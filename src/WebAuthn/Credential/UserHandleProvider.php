<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Credential;

use Actualize\Passkey\Entity\PasskeyUserHandle\PasskeyUserHandleCollection;
use Actualize\Passkey\Entity\PasskeyUserHandle\PasskeyUserHandleEntity;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
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

        try {
            // The definition denies writes outside system scope; this is the only sanctioned way in.
            $context->scope(Context::SYSTEM_SCOPE, fn (Context $systemContext) => $this->userHandleRepository->create([[
                'id' => Uuid::randomHex(),
                'realm' => $realm->value,
                'accountId' => $accountId,
                'userHandle' => $handle,
            ]], $systemContext));
        } catch (UniqueConstraintViolationException $exception) {
            // A concurrent request of the same account inserted its handle between
            // find() and create(). The unique key kept exactly one — use that one.
            $existing = $this->find($realm, 'accountId', $accountId, $context);
            if ($existing === null) {
                throw $exception;
            }

            return $existing->getUserHandle();
        }

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
        $entity = $this->userHandleRepository->search($criteria, $context)->getEntities()->first();

        return $entity;
    }
}
