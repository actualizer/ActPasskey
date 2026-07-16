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

    public function findOneByCredentialId(string $rawCredentialId, Realm $realm, Context $context): ?PasskeyCredentialEntity
    {
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('credentialId', $rawCredentialId))
            ->addFilter(new EqualsFilter('realm', $realm->value))
            ->setLimit(1);

        $entity = $this->credentialRepository->search($criteria, $context)->first();

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

    /**
     * The combined id + realm + owner filter IS the IDOR defense for every mutation
     * below: a row is only touchable when all three match. Never weaken this to
     * id-only, and never inline a second copy — one owner check cannot drift.
     */
    private function assertOwned(string $id, Realm $realm, string $accountId, Context $context): bool
    {
        $ownerField = $realm === Realm::Admin ? 'userId' : 'customerId';

        $criteria = (new Criteria([$id]))
            ->addFilter(new EqualsFilter('realm', $realm->value))
            ->addFilter(new EqualsFilter($ownerField, $accountId))
            ->setLimit(1);

        // Not owned or not found — identical outcome, no existence oracle for attackers.
        return $this->credentialRepository->searchIds($criteria, $context)->getTotal() > 0;
    }

    public function deleteOwned(string $id, Realm $realm, string $accountId, Context $context): bool
    {
        if (!$this->assertOwned($id, $realm, $accountId, $context)) {
            return false;
        }

        $this->credentialRepository->delete([['id' => $id]], $context);

        return true;
    }

    public function renameOwned(string $id, Realm $realm, string $accountId, string $name, Context $context): bool
    {
        if (!$this->assertOwned($id, $realm, $accountId, $context)) {
            return false;
        }

        $this->credentialRepository->update([['id' => $id, 'name' => $name]], $context);

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
