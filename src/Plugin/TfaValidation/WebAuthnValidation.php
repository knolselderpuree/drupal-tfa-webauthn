<?php

namespace Drupal\webauthn\Plugin\TfaValidation;

use BadMethodCallException;
use Drupal\Core\Config\Config;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Http\RequestStack;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\webauthn\Entity\WebAuthn;
use Exception;
use Firehed\U2F\AttestationCertificate;
use Firehed\U2F\ECPublicKey;
use Firehed\U2F\InvalidDataException;
use Firehed\U2F\Registration;
use Firehed\U2F\RegistrationInterface;
use Firehed\U2F\Server;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\tfa\Plugin\TfaBasePlugin;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\user\UserDataInterface;
use Firehed\U2F\WebAuthn\LoginResponse;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * WebAuthn validation class for performing WebAuthn validation
 *
 * @TfaValidation(
 *   id = "tfa_webauthn",
 *   label = @Translation("TFA WebAuthn Setup"),
 *   description = @Translation("TFA WebAuthn Setup Plugin"),
 *   setupPluginId = "tfa_webauthn_setup",
 * )
 */
class WebAuthnValidation extends TfaBasePlugin implements TfaValidationInterface, ContainerFactoryPluginInterface
{
  use StringTranslationTrait;
  public Server $server;
  public string $token;
  public string $appRoot;
  public AccountProxyInterface $currentUser;
  public EntityStorageInterface $webauthnStorage;
  public RequestStack $requestStack;

  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    UserDataInterface $user_data,
    EncryptionProfileManagerInterface $encryption_profile_manager,
    EncryptServiceInterface $encrypt_service,
    EntityStorageInterface $webauthnStorage,
    string $appRoot,
    AccountProxyInterface $current_user,
    RequestStack $requestStack
  )
  {
    parent::__construct($configuration,
      $plugin_id,
      $plugin_definition,
      $user_data,
      $encryption_profile_manager,
      $encrypt_service
    );
    $this->webauthnStorage = $webauthnStorage;
    $this->appRoot = $appRoot;
    $this->requestStack = $requestStack;

    $this->server = new Server();
    $this->server->disableCAVerification();
    $this->server->setAppId($requestStack->getMainRequest()->getHost());
    $this->token = $this->generateToken($this->getJWTConfiguration());
    $this->currentUser = $current_user;
  }

  /**
   * {@inheritdoc}
   */
  public function ready(): bool
  {
    return !empty($this->webauthnStorage->loadMultiple());
  }

  /**
   * {@inheritdoc}
   */
  public function getForm(array $form, FormStateInterface $form_state): array
  {
    $form['#id'] = 'WebAuthnValidation';
    $form['step'] = [
      '#type' => 'hidden',
      '#attributes' => ['id' => 'step']
    ];
    $form['sign_request'] = [
      '#type' => 'hidden',
      '#attributes' => ['id' => 'sign_request']
    ];
    $form['response'] = [
      '#type' => 'hidden',
      '#attributes' => ['id' => 'response', 'maxlength' => 20000]
    ];
    $form['select_name'] = [
      '#type' => 'select',
      '#empty_option' => '- Select a device -',
      '#title' => $this->t('Available devices'),
      '#options' => $this->getDeviceNamesFromUser(),
      '#attributes' => ['class' => ['select_name']],
      '#ajax' => [
        'event' => 'change',
        'callback' => [$this, 'getSelectedSignReqs'],
        'wrapper' => 'sign_request',
        'progress' => [
          'type' => 'throbber',
          'message' => $this->t('Gathering data...'),
        ],
      ],
    ];
    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = [
      '#type' => 'submit',
      '#button_type' => 'primary',
      '#value' => $this->t('Verify'),
    ];
    return $form;
  }

  /**
   * @param array $form
   * @param FormStateInterface $form_state
   * @return array
   */
  public function getSelectedSignReqs(array $form, FormStateInterface $form_state): array
  {
    // Ajax callback to get the sign request for the selected device.
    $selectedId = $form_state->getValue('select_name');
    if ($selectedId == "" || !$this->verifyUserDeviceAccess($selectedId)) {
      $form['sign_request']['#value'] = '';
      return $form['sign_request'];
    }
    $registrations = $this->getRegistrationsFromUserWithDevice($form_state->getValue('select_name'));
    $signReqs = $this->server->generateSignRequests($registrations);
    $this->ChangeChallengeSignReqs($signReqs, $this->token);
    $form['sign_request']['#value'] = json_encode([
      'challenge' => $signReqs[0]->getChallenge(),
      'keyHandles' => $this->getKeyHandlesWeb($signReqs)
    ]);
    return $form['sign_request'];
  }

  /**
   * @param Config $config
   * @param array $state
   * @return array
   */
  public function buildConfigurationForm(Config $config, array $state = []): array
  {
    return [];
  }

  /**
   * {@inheritdoc}
   * @throws Exception
   */
  public function validateForm(array $form, FormStateInterface $form_state): bool
  {
    $selectedId = $form_state->getValue('select_name');
    $response = $form_state->getValue('response');
    if ($form_state->getValue('step') === '0' && isset($selectedId) && !isset($response)) {
      return true;
    } elseif ($form_state->getValue('step') === '1' && isset($selectedId) && isset($response)) {
      if ($this->verifyUserDeviceAccess($selectedId)) {
        $submittedSignReq = json_decode($form_state->getValue('sign_request'), true, 512, JSON_THROW_ON_ERROR);
        if (!$this->validateChallenge($submittedSignReq['challenge'])) {
          return false;
        }
        $data = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        $response = LoginResponse::fromDecodedJson($data);

        $registrations = $this->getRegistrationsFromUserWithDevice($selectedId);
        $signReqs = $this->server->generateSignRequests($registrations);
        $this->changeChallengeSignReqs($signReqs, $submittedSignReq['challenge']);
        $this->server->setRegistrations($registrations);
        $this->server->setSignRequests($signReqs);

        try {
          $registration = $this->server->authenticate($response);
        } catch (BadMethodCallException $ex) {
          $this->errorMessages['code'] = $this->t($ex);
          return false;
        }
        $this->updateRegistration($registration);
        return true;
      }
    }
    $this->errorMessages['code'] = $this->t('Something went wrong. Please try again.');
    return false;
  }

  /**
   * {@inheritdoc}
   */
  public function validateRequest(): bool
  {
    return false;
  }

  /**
   * @param int $selected
   * @return bool
   */
  public function verifyUserDeviceAccess(int $selected): bool
  {
    // Verify that the user has access to the selected device for security.
    $authnData = $this->getWebAuthnDataFromUser($this->uid);
    foreach ($authnData as $item) {
      if ($item->getId() === $selected) {
        return true;
      }
    }
    return false;
  }

  /**
   * @param array $signRequests
   * @param string $token
   */
  private function changeChallengeSignReqs(array $signRequests, string $token)
  {
    // Change the Webauthn sign request challenge to the JWT token.
    foreach ($signRequests as $signReq) {
      $signReq->setChallenge($token);
    }
  }

  /**
   * @param array $signRequest
   * @return array
   */
  private function getKeyHandlesWeb(array $signRequest): array
  {
    // Get the key handles (web format) for the given sign request.
    // Used for navigator.credentials.get method in WebAuthnValidation.js.
    $keyHandlesWeb = [];
    foreach ($signRequest as $item) {
      $keyHandlesWeb[] = $item->getKeyHandleWeb();
    }
    return $keyHandlesWeb;
  }

  /**
   * @param int $selectedId
   * @return array
   * @throws InvalidDataException
   */
  private function getRegistrationsFromUserWithDevice(int $selectedId): array
  {
    // Get registration object dependent on the selected device.
    // Used to set the sign request for the U2F server.
    /** @var RegistrationInterface[] $registrations */
    $registrations = [];
    $authnData = $this->getWebAuthnDataFromUser($this->uid);
    foreach ($authnData as $item) {
      if ($item->getId() === $selectedId) {
        $registrations[] = $this->createRegistration($item);
      }
    }
    return $registrations;
  }

  /**
   * @return array
   */
  private function getDeviceNamesFromUser(): array
  {
    // Get a list of the devices the user can use for WebAuthn validation.
    $names = [];
    $authnData = $this->getWebAuthnDataFromUser($this->uid);
    foreach ($authnData as $item) {
      $names[$item->getId()] = $item->getName();
    }
    return $names;
  }

  /**
   * @param WebAuthn $regData
   * @return RegistrationInterface
   * @throws InvalidDataException
   */
  private function createRegistration(WebAuthn $regData): RegistrationInterface
  {
    // Object used for U2F server to create sign requests.
    $reg = new Registration();
    $reg->setCounter($regData->getCounter());
    $reg->setKeyHandle(base64_decode($regData->getKeyHandle()));
    $reg->setPublicKey(new ECPublicKey(base64_decode($regData->getPublicKey())));
    $reg->setAttestationCertificate(new AttestationCertificate(base64_decode($regData->getAttestationCertificate())));
    return $reg;
  }

  /**
   * @param int $ownerId
   * @throws EntityStorageException
   */
  public function deleteWebAuthnDataFromUser(int $ownerId)
  {
    // Delete all WebAuthn data for given user.
    $delete = $this->getWebAuthnDataFromUser($ownerId);
    if (isset($delete)) {
      foreach ($delete as $deleted) {
        $this->webauthnStorage->load($deleted->id())->delete();
      }
    }
  }

  /**
   * @param int $ownerId
   * @return array
   */
  public function getWebAuthnDataFromUser(int $ownerId): array
  {
    // Retrieve all WebAuthn data for given user.
    return $this->webauthnStorage->loadByProperties(['owner_user_id' => $ownerId]);
  }

  /**
   * @param RegistrationInterface $registration
   * @throws EntityStorageException
   */
  private function updateRegistration(RegistrationInterface $registration)
  {
    // Update the registration after valid sign in to prevent token cloning attacks.
    $entities = $this->webauthnStorage->loadByProperties(['user_id' => $this->uid, 'key_handle' => base64_encode($registration->getKeyHandleBinary())]);
    if (!empty($entities)) {
      reset($entities)->setCounter($registration->getCounter());
      reset($entities)->save();
    }
  }

  /**
   * @param Configuration $config
   * @return string
   * @throws Exception
   */
  public function generateToken(Configuration $config): string
  {
    // Generate a JWT token for security.
    $now = new \DateTimeImmutable();
    $modifiedNow = $now->modify('+30 minute');
    return $config->builder()
      ->identifiedBy($this->uid)
      ->permittedFor($this->uid)
      ->issuedBy('atlas.groupflights.com')
      ->issuedAt($now)
      ->expiresAt($modifiedNow)
      ->getToken($config->signer(), $config->signingKey())->toString();
  }

  /**
   * @param string $token
   * @param Configuration $config
   * @return Token
   */
  private function parseToken(string $token, Configuration $config): Token
  {
    // Parse a string to a valid JWT token.
    return $config->parser()->parse($token);
  }

  /**
   * @param string $token
   * @return bool
   * @throws Exception
   */
  public function validateChallenge(string $token): bool
  {
    // Validation of a JWT token
    $config = $this->getJWTConfiguration();
    $parsedToken = $this->parseToken($token, $config);
    $now = new FrozenClock(new \DateTimeImmutable());
    $config->setValidationConstraints(new Constraint\IdentifiedBy($this->uid));
    $config->setValidationConstraints(new Constraint\IssuedBy('atlas.groupflights.com'));
    $config->setValidationConstraints(new Constraint\PermittedFor($this->uid));
    $config->setValidationConstraints(new Constraint\SignedWith($config->signer(), $config->signingKey()));
    $config->setValidationConstraints(new Constraint\ValidAt($now));
    $constraint = $config->validationConstraints();
    return $config->validator()->validate($parsedToken, ...$constraint);
  }

  /**
   * @return Configuration
   */
  public function getJWTConfiguration(): Configuration
  {
    // Retrieve the JWT configuration.
    return Configuration::forAsymmetricSigner(
      new Sha256(),
      InMemory::file($this->appRoot . '/private.pem'),
      InMemory::file($this->appRoot . '/public.pem'),
      );
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition)
  {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('user.data'),
      $container->get('encrypt.encryption_profile.manager'),
      $container->get('encryption'),
      $container->get('entity_type.manager')->getStorage('webauthn'),
      $container->get('app.root'),
      $container->get('current_user'),
      $container->get('request_stack')
    );
  }
}
