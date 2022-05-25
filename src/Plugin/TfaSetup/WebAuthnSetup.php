<?php

namespace Drupal\webauthn\Plugin\TfaSetup;

use BadMethodCallException;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Http\RequestStack;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Url;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\tfa\Plugin\TfaSetupInterface;
use Drupal\user\UserDataInterface;
use Drupal\webauthn\Plugin\TfaValidation\WebAuthnValidation;
use Exception;
use Firehed\U2F\RegisterRequest;
use Firehed\U2F\RegistrationInterface;
use Firehed\U2F\WebAuthn\RegistrationResponse;

/**
 * WebAuthn setup class to setup WebAuthn validation
 *
 * @TfaSetup(
 *   id = "tfa_webauthn_setup",
 *   label = @Translation("TFA WebAuthn Setup"),
 *   description = @Translation("TFA WebAuthn Setup Plugin"),
 *   setupMessages = {
 *    "saved" = @Translation("WebAuthn saved."),
 *    "skipped" = @Translation("WebAuthn not saved.")
 *   }
 * )
 */
class WebAuthnSetup extends WebAuthnValidation implements TfaSetupInterface
{
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
    parent::__construct(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $user_data,
      $encryption_profile_manager,
      $encrypt_service,
      $webauthnStorage,
      $appRoot,
      $current_user,
      $requestStack
    );
  }

  /**
   * {@inheritdoc}
   */
  public function ready(): bool
  {
    return true;
  }

  /**
   * {@inheritdoc}
   */
  public function getSetupForm(array $form, FormStateInterface $form_state): array
  {
    $regReq = $this->initializeWebAuthnRegistration();

    $form['#id'] = 'WebAuthnSetup';
    $form['webauthn'] = [
      '#title' => $this->t('WebAuthn')
    ];
    $form['description'] = [
      '#type' => 'html_tag',
      '#tag' => 'p',
      '#value' => $this->t('Insert your hardware key, wait for the popup and press the button.'),
      '#disabled' => TRUE,
    ];
    $form['challenge'] = [
      '#type' => 'hidden',
      '#value' => $regReq->getChallenge(),
      '#disabled' => TRUE,
      '#attributes' => ['id' => 'challenge'],
    ];
    $form['username'] = [
      '#type' => 'hidden',
      '#value' => $this->currentUser->getDisplayName(),
      '#attributes' => ['id' => 'username'],
    ];
    $form['email'] = [
      '#type' => 'hidden',
      '#value' => $this->currentUser->getEmail(),
      '#attributes' => ['id' => 'email'],
    ];
    $form['response'] = [
      '#type' => 'hidden',
      '#attributes' => ['id' => 'response', 'maxlength' => 20000, 'readonly' => 'readonly'],
    ];
    $form['hostname'] = [
      '#type' => 'hidden',
      '#attributes' => ['id' => 'hostname'],
    ];
    $form['name'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Give your device a name'),
      '#attributes' => ['id' => 'device_name'],
    ];
    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = [
      '#type' => 'submit',
      '#button_type' => 'primary',
      '#value' => $this->t('Verify and save'),
    ];
    return $form;
  }

  /**
   * {@inheritDoc}
   * @throws Exception
   */
  public function validateSetupForm(array $form, FormStateInterface $form_state): bool
  {
    if (empty($form_state->getValue('challenge')) || empty($form_state->getValue('name')) || empty($form_state->getValue('response'))) {
      $this->errorMessages['code'] = $this->t('No token or device (name) was given. Please try again.');
      return false;
    }
    if (!$this->validateChallenge($form_state->getValue('challenge'))) {
      $this->errorMessages['code'] = $this->t('Invalid token. Please try again.');
      return false;
    }
    $regReq = $this->initializeWebAuthnRegistration();
    $regReq->setChallenge($form_state->getValue('challenge'));
    if (!$this->isNameUniqueForUser($form_state->getValue('name'))) {
      $this->errorMessages['code'] = $this->t('You already have a device with that name.');
      return false;
    }

    $data = json_decode($form_state->getValue('response'), true, 512, JSON_THROW_ON_ERROR);
    $response = RegistrationResponse::fromDecodedJson($data);
    $this->server->setRegisterRequest($regReq);

    try {
      $registration = $this->server->register($response);
    } catch (BadMethodCallException $ex) {
      $this->errorMessages['code'] = $this->t($ex);
      return false;
    }
    $this->storeRegistration($registration, $form_state->getValue('name'));
    return true;
  }

  /**
   * {@inheritDoc}
   */
  public function submitSetupForm(array $form, FormStateInterface $form_state): bool
  {
    return true;
  }

  /**
   * @param RegistrationInterface $registration
   * @param string $name
   * @throws EntityStorageException
   */
  public function storeRegistration(RegistrationInterface $registration, string $name)
  {
    // Save WebAuthn registration in dbs after setup is completed
    $this->webauthnStorage->create([
      'name' => $name,
      'user_id' => $this->uid,
      'owner_user_id' => $this->uid,
      'counter' => $registration->getCounter(),
      'key_handle' => base64_encode($registration->getKeyHandleBinary()),
      'public_key' => base64_encode($registration->getPublicKey()->getBinary()),
      'attestation_certificate' => base64_encode($registration->getAttestationCertificate()->getBinary())
    ])->save();
  }

  /**
   * {@inheritdoc}
   */
  public function getHelpLinks(): string
  {
    return '';
  }

  /**
   * {@inheritdoc}
   */
  public function getSetupMessages(): string
  {
    return '';
  }

  /**
   * {@inheritdoc}
   */
  public function getOverview(array $params): array
  {
    $output = [
      'heading' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('WebAuthn'),
      ],
      'description' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('Enable WebAuthn for your user account.'),
      ],
      'setup' => [
        '#theme' => 'links',
        '#links' => [
          'reset' => [
            'title' => $this->t('Add a device'),
            'url' => Url::fromRoute('tfa.validation.setup', [
              'user' => $params['account']->id(),
              'method' => $params['plugin_id'],
            ]),
          ],
        ],
      ]
    ];
    return $output;
  }

  /**
   * @return RegisterRequest
   */
  public function initializeWebAuthnRegistration(): RegisterRequest
  {
    // Generate register request with JWT token.
    $initializing = $this->server->generateRegisterRequest();
    $initializing->setChallenge($this->token);
    return $initializing;
  }

  /**
   * @param string $name
   * @return bool
   */
  private function isNameUniqueForUser(string $name): bool
  {
    return empty($this->webauthnStorage->loadByProperties(['owner_user_id' => $this->uid, 'name' => $name]));
  }
}
