<?php declare(strict_types=1);

namespace Actualize\Passkey\Entity\PasskeyUserHandle;

use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\BlobField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

class PasskeyUserHandleDefinition extends EntityDefinition
{
    public const ENTITY_NAME = 'act_passkey_user_handle';

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getEntityClass(): string
    {
        return PasskeyUserHandleEntity::class;
    }

    public function getCollectionClass(): string
    {
        return PasskeyUserHandleCollection::class;
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new PrimaryKey(), new Required()),

            (new StringField('realm', 'realm'))->addFlags(new Required()),

            // No FK: account_id is polymorphic (references either an admin user or a customer).
            (new StringField('account_id', 'accountId'))->addFlags(new Required()),

            (new BlobField('user_handle', 'userHandle'))->addFlags(new Required()),

            new CreatedAtField(),
            new UpdatedAtField(),
        ]);
    }
}
