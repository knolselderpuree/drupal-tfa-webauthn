<?php

namespace Drupal\webauthn\Entity;

use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;

/**
 * Defines the WebAuthn entity.
 *
 * @ingroup webauthn
 *
 * @ContentEntityType(
 *   id = "webauthn",
 *   label = @Translation("WebAuthn"),
 *   base_table = "webauthn_token_registration",
 *   entity_keys = {
 *    "id" = "id",
 *   }
 * )
 */
class WebAuthn extends ContentEntityBase
{
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type)
  {
    $fields['id'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('ID'))
      ->setDescription(t('The ID of the WebAuthn entity.'))
      ->setReadOnly(true);

    $fields['name'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Name'))
      ->setDescription(t('The name of the WebAuthn device'));

    $fields['user_id'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('Creator'))
      ->setDescription(t('The user ID of author of the WebAuthn entity, the user who creates the entity.'))
      ->setRevisionable(false)
      ->setSetting('target_type', 'user')
      ->setSetting('handler', 'default')
      ->setDefaultValueCallback('Drupal\webauthn\Entity\WebAuthn::getCurrentUserId')
      ->setTranslatable(false);

    $fields['owner_user_id'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('User'))
      ->setDescription(t('The user ID of the user this webauthn is authenticating, the user who owns the entity.'))
      ->setRevisionable(false)
      ->setSetting('target_type', 'user')
      ->setSetting('handler', 'default')
      ->setDefaultValueCallback('Drupal\webauthn\Entity\WebAuthn::getCurrentUserId')
      ->setTranslatable(false)
      ->setCardinality(1);

    $fields['counter'] = BaseFieldDefinition::create('integer')
      ->setLabel(t('Counter'))
      ->setLabel(t('The counter of the WebAuthn entity.'));

    $fields['key_handle'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Key Handle'))
      ->setDescription('The key handler of the WebAuthn entity.');

    $fields['public_key'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Public Key'))
      ->setDescription(t('The public key of the WebAuthn entity.'));

    $fields['attestation_certificate'] = BaseFieldDefinition::create('string')
      ->setLabel(t('Attestation Certificate'))
      ->setDescription(t('The attestation certificate of the WebAuthn entity.'))
      ->setSettings([
        'max_length' => 500
      ]);

    return $fields;
  }

  public function getId(): int
  {
    return $this->get('id')->value;
  }

  public function getName(): string
  {
    return $this->get('name')->value;
  }

  public function getUserId(): int
  {
    return $this->get('user_id')->target_id;
  }

  public function getOwnerId(): int
  {
    return $this->get('owner_user_id')->target_id;
  }

  public function getCounter(): int
  {
    return $this->get('counter')->value;
  }

  public function setCounter(int $count)
  {
    $this->set('counter', $count);
  }

  public function getKeyHandle(): string
  {
    return $this->get('key_handle')->value;
  }

  public function getPublicKey(): string
  {
    return $this->get('public_key')->value;
  }

  public function getAttestationCertificate(): string
  {
    return $this->get('attestation_certificate')->value;
  }

  public static function getCurrentUserId(): int
  {
    return \Drupal::currentUser()->id();
  }
}
