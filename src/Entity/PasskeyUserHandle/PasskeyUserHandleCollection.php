<?php declare(strict_types=1);

namespace Actualize\Passkey\Entity\PasskeyUserHandle;

use Shopware\Core\Framework\DataAbstractionLayer\EntityCollection;

/**
 * @extends EntityCollection<PasskeyUserHandleEntity>
 *
 * @method void                          add(PasskeyUserHandleEntity $entity)
 * @method void                          set(string $key, PasskeyUserHandleEntity $entity)
 * @method PasskeyUserHandleEntity[]     getIterator()
 * @method PasskeyUserHandleEntity[]     getElements()
 * @method PasskeyUserHandleEntity|null  get(string $key)
 * @method PasskeyUserHandleEntity|null  first()
 * @method PasskeyUserHandleEntity|null  last()
 */
class PasskeyUserHandleCollection extends EntityCollection
{
    protected function getExpectedClass(): string
    {
        return PasskeyUserHandleEntity::class;
    }
}
