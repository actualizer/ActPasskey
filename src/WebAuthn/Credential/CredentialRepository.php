<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Credential;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialCollection;
use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;

final class CredentialRepository
{
    /**
     * @param EntityRepository<PasskeyCredentialCollection> $credentialRepository
     */
    public function __construct(private readonly EntityRepository $credentialRepository)
    {
    }

    public function findOneByCredentialId(string $rawCredentialId, Realm $realm): ?PasskeyCredentialEntity
    {
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('credentialId', $rawCredentialId))
            ->addFilter(new EqualsFilter('realm', $realm->value))
            ->setLimit(1);

        $entity = $this->credentialRepository->search($criteria, Context::createDefaultContext())->first();

        return $entity instanceof PasskeyCredentialEntity ? $entity : null;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function save(array $data, Context $context): void
    {
        $this->credentialRepository->upsert([$data], $context);
    }

    public function updateSignCount(string $id, int $signCount, Context $context): void
    {
        $this->credentialRepository->update([['id' => $id, 'signCount' => $signCount]], $context);
    }

    public function deleteOwned(string $id, Realm $realm, string $accountId, Context $context): bool
    {
        $ownerField = $realm === Realm::Admin ? 'userId' : 'customerId';

        // The combined id + realm + owner filter IS the IDOR defense: a row is only
        // deletable when all three match. Do not weaken this to id-only.
        $criteria = (new Criteria([$id]))
            ->addFilter(new EqualsFilter('realm', $realm->value))
            ->addFilter(new EqualsFilter($ownerField, $accountId))
            ->setLimit(1);

        if ($this->credentialRepository->searchIds($criteria, $context)->getTotal() === 0) {
            // Not owned or not found — identical outcome, no existence oracle for attackers.
            return false;
        }

        $this->credentialRepository->delete([['id' => $id]], $context);

        return true;
    }

    public function listOwned(Realm $realm, string $accountId, Context $context): PasskeyCredentialCollection
    {
        $ownerField = $realm === Realm::Admin ? 'userId' : 'customerId';

        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('realm', $realm->value))
            ->addFilter(new EqualsFilter($ownerField, $accountId));

        /** @var PasskeyCredentialCollection $collection */
        $collection = $this->credentialRepository->search($criteria, $context)->getEntities();

        return $collection;
    }
}
