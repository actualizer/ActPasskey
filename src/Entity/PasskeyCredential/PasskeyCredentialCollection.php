<?php declare(strict_types=1);

namespace Actualize\Passkey\Entity\PasskeyCredential;

use Shopware\Core\Framework\DataAbstractionLayer\EntityCollection;

/**
 * @extends EntityCollection<PasskeyCredentialEntity>
 *
 * @method void                        add(PasskeyCredentialEntity $entity)
 * @method void                        set(string $key, PasskeyCredentialEntity $entity)
 * @method PasskeyCredentialEntity[]    getIterator()
 * @method PasskeyCredentialEntity[]    getElements()
 * @method PasskeyCredentialEntity|null get(string $key)
 * @method PasskeyCredentialEntity|null first()
 * @method PasskeyCredentialEntity|null last()
 */
class PasskeyCredentialCollection extends EntityCollection
{
    protected function getExpectedClass(): string
    {
        return PasskeyCredentialEntity::class;
    }
}
