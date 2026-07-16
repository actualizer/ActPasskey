<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Credential;

use Actualize\Passkey\Entity\PasskeyUserHandle\PasskeyUserHandleCollection;
use Actualize\Passkey\Entity\PasskeyUserHandle\PasskeyUserHandleEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Uuid\Uuid;

final class UserHandleProvider
{
    /**
     * @param EntityRepository<PasskeyUserHandleCollection> $userHandleRepository
     */
    public function __construct(private readonly EntityRepository $userHandleRepository)
    {
    }

    public function getOrCreate(Realm $realm, string $accountId, Context $context): string
    {
        $existing = $this->find($realm, 'accountId', $accountId, $context);
        if ($existing !== null) {
            return $existing->getUserHandle();
        }

        $handle = random_bytes(32);
        $this->userHandleRepository->create([[
            'id' => Uuid::randomHex(),
            'realm' => $realm->value,
            'accountId' => $accountId,
            'userHandle' => $handle,
        ]], $context);

        return $handle;
    }

    public function resolveAccountId(Realm $realm, string $rawUserHandle, Context $context): ?string
    {
        $entity = $this->find($realm, 'userHandle', $rawUserHandle, $context);

        return $entity?->getAccountId();
    }

    private function find(Realm $realm, string $field, string $value, Context $context): ?PasskeyUserHandleEntity
    {
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('realm', $realm->value))
            ->addFilter(new EqualsFilter($field, $value))
            ->setLimit(1);

        /** @var PasskeyUserHandleEntity|null $entity */
        $entity = $this->userHandleRepository->search($criteria, $context)->first();

        return $entity;
    }
}
