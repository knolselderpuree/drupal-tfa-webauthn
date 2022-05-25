<?php


namespace Drupal\Tests\webauthn\FunctionalJavascript;

use Behat\Mink\Exception\ExpectationException;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\encrypt\Entity\EncryptionProfile;
use Drupal\FunctionalJavascriptTests\WebDriverTestBase;
use Drupal\FunctionalJavascriptTests\WebDriverWebAssert;
use Drupal\key\Entity\Key;
use Drupal\user\Entity\User;
use Drupal\webauthn\Plugin\TfaSetup\WebAuthnSetup;

/**
 *
 * Class WebAuthnSetupTest
 * @group webauthn
 *
 */
//turn off verify in Guzzle Client to run tests
class WebAuthnSetupTest extends WebDriverTestBase
{
  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * @var User
   */
  protected User $userAccount;

  /**
   * @var string
   */
  protected string $validationPluginId = 'tfa_webauthn';

  /**
   * @var WebAuthnSetup
   */
  protected WebAuthnSetup $setupPlugin;

  /**
   * @var EntityInterface
   */
  protected EntityInterface $testKey;

  /**
   * @var EntityInterface
   */
  protected EntityInterface $encryptionProfile;

  protected static $modules = [
    'tfa_test_plugins',
    'tfa',
    'encrypt',
    'encrypt_test',
    'key',
    'webauthn',
  ];

  /**
   * {@inheritdoc}
   * @throws EntityStorageException
   * @throws ExpectationException
   */
  public function setUp(): void
  {
    parent::setUp();
    $this->tfaSetUp();
    $this->canEnableValidationPlugin($this->validationPluginId);
    $this->userAccount = $this->drupalCreateUser(['setup own tfa', 'disable own tfa']);
    $this->setupPlugin = \Drupal::service('plugin.manager.tfa.setup')->createInstance($this->validationPluginId . '_setup', ['uid' => $this->userAccount->id()]);
    $this->drupalLogin($this->userAccount);
  }

  /**
   * Clear flood and access_token database after every test
   *
   */
  public function tearDown(): void
  {
    $tables = [
      'webauthn_token_registration',
      'users_field_data',
      'users_data',
      'users',
      'user__roles',
      'sessions',
      'sequences',
      'semaphore',
      'router',
      'path_alias_revision',
      'path_alias',
      'menu_tree',
      'key_value_expire',
      'key_value',
      'config',
      'cachetags',
      'cache_page',
      'cache_render',
      'cache_entity',
      'cache_dynamic_page_cache',
      'cache_discovery',
      'cache_default',
      'cache_data',
      'cache_container',
      'cache_config',
      'cache_bootstrap',
    ];
    $connection = \Drupal::database();
    $schema = $connection->schema();
    foreach($tables as $table) {
      $schema->dropTable($table);
    }
  }

  public function testTfaOverviewExists()
  {
    $this->drupalGet('user/' . $this->userAccount->id() . '/security/tfa');
    $page = $this->getSession()->getPage();
    $this->assertNotEmpty($page->findLink('Add a device'));
  }

  public function testWebAuthnFlow()
  {
    $this->drupalGet('user/' . $this->userAccount->id() . '/security/tfa/' . $this->validationPluginId);
    $webDriver = new WebDriverWebAssert($this->getSession());

    $page = $this->getSession()->getPage();
    $webDriver->pageTextContains('Enter your current password');
    $this->assertEmpty($page->findField('field_current_pass'));
    $this->drupalPostForm(NULL, ['current_pass' => $this->userAccount->passRaw], 'Confirm');

    $webDriver->pageTextContains('Give your device a name');
    $webDriver->hiddenFieldExists('challenge');
    $webDriver->hiddenFieldExists('username');
    $webDriver->hiddenFieldExists('email');

    $result = $this->xpath('//input[@name="challenge"]');
    if (empty($result)) {
      $this->fail('No challenge set. Aborting test.');
      return;
    }
    $this->drupalPostForm(NULL, ['name' => 'test-webauthn-setup'], 'Verify and save');
    $webDriver->pageTextContains('No token or device (name) was given. Please try again.');

    // TODO: create virtual authenticator.
  }

  /**
   * Reusable test for enabling a validation plugin on the configuration form.
   *
   * @param string $validation_plugin_id
   *   A validation plugin id.
   * @throws ExpectationException
   */
  public function canEnableValidationPlugin($validation_plugin_id) {
    $assert = $this->assertSession();
    $adminUser = $this->drupalCreateUser(['admin tfa settings']);
    $this->drupalLogin($adminUser);

    $this->drupalGet('admin/config/people/tfa');
    $assert->pageTextContains('TFA Settings');

    $edit = [
      'tfa_enabled' => TRUE,
      'tfa_validate' => $validation_plugin_id,
      "tfa_allowed_validation_plugins[{$validation_plugin_id}]" => $validation_plugin_id,
      'encryption_profile' => $this->encryptionProfile->id(),
    ];

    $this->submitForm($edit, 'Save configuration');
    $assert->pageTextContains('The configuration options have been saved.');
    $select_field_id = 'edit-tfa-validate';
    $option_field = $assert->optionExists($select_field_id, $validation_plugin_id);
    $result = $option_field->hasAttribute('selected');
    $assert->assert($result, "Option {$validation_plugin_id} for field {$select_field_id} is selected.");
  }

  public function tfaSetUp()
  {
    $user = $this->drupalCreateUser([
      'access administration pages',
      'administer encrypt',
      'administer keys',
    ]);
    $this->drupalLogin($user);
    $this->generateEncryptionKey();
    $this->generateEncryptionProfile();
  }

  /**
   * Generates an encryption key.
   */
  public function generateEncryptionKey() {
    $key = Key::create([
      'id' => 'testing_key_128',
      'label' => 'Testing Key 128 bit',
      'key_type' => 'encryption',
      'key_type_settings' => ['key_size' => '128'],
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'mustbesixteenbit'],
    ]);
    $key->save();
    $this->testKey = $key;
  }

  /**
   * Generates an Encryption profile.
   */
  public function generateEncryptionProfile() {
    $encryption_profile = EncryptionProfile::create([
      'id' => 'test_encryption_profile',
      'label' => 'Test encryption profile',
      'encryption_method' => 'test_encryption_method',
      'encryption_key' => $this->testKey->id(),
    ]);
    $encryption_profile->save();
    $this->encryptionProfile = $encryption_profile;
  }
}
