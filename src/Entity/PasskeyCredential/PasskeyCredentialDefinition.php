<?php declare(strict_types=1);

namespace Actualize\Passkey\Entity\PasskeyCredential;

use Shopware\Core\Checkout\Customer\CustomerDefinition;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\EntityProtection\EntityProtectionCollection;
use Shopware\Core\Framework\DataAbstractionLayer\EntityProtection\WriteProtection;
use Shopware\Core\Framework\DataAbstractionLayer\Field\BlobField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\DateTimeField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IntField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\JsonField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;
use Shopware\Core\System\User\UserDefinition;

class PasskeyCredentialDefinition extends EntityDefinition
{
    public const ENTITY_NAME = 'act_passkey_credential';

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getEntityClass(): string
    {
        return PasskeyCredentialEntity::class;
    }

    public function getCollectionClass(): string
    {
        return PasskeyCredentialCollection::class;
    }

    /**
     * A row here IS an authentication factor: an insert with a foreign userId and an
     * attacker-held public key is a silent passkey enrollment that bypasses every check
     * in the manage controllers. The generic /api CRUD routes exist for every registered
     * definition, so the write path must be closed at the definition — same reasoning as
     * core's UserDefinition. Writes therefore only pass in system scope; see
     * CredentialRepository, which is the only place that may open it.
     */
    protected function defineProtections(): EntityProtectionCollection
    {
        return new EntityProtectionCollection([new WriteProtection(Context::SYSTEM_SCOPE)]);
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new PrimaryKey(), new Required()),

            (new StringField('realm', 'realm'))->addFlags(new Required()),

            (new FkField('user_id', 'userId', UserDefinition::class)),
            new ManyToOneAssociationField('user', 'user_id', UserDefinition::class, 'id', false),

            (new FkField('customer_id', 'customerId', CustomerDefinition::class)),
            new ManyToOneAssociationField('customer', 'customer_id', CustomerDefinition::class, 'id', false),

            (new BlobField('credential_id', 'credentialId'))->addFlags(new Required()),
            (new BlobField('public_key', 'publicKey'))->addFlags(new Required()),
            (new IntField('sign_count', 'signCount'))->addFlags(new Required()),
            (new BlobField('user_handle', 'userHandle'))->addFlags(new Required()),

            new StringField('aaguid', 'aaguid'),
            new JsonField('transports', 'transports'),
            new StringField('name', 'name'),
            new DateTimeField('last_used_at', 'lastUsedAt'),

            new CreatedAtField(),
            new UpdatedAtField(),
        ]);
    }
}
