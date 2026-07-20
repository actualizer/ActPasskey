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
     * The definition denies writes outside system scope so the generic /api CRUD routes
     * cannot enroll a credential. This class is the only sanctioned way in — every write
     * below therefore opens the scope, and must only be reached after the caller has
     * established ownership.
     *
     * @param array<string, mixed> $data
     */
    public function save(array $data, Context $context): void
    {
        $context->scope(
            Context::SYSTEM_SCOPE,
            fn (Context $systemContext) => $this->credentialRepository->upsert([$data], $systemContext)
        );
    }

    public function updateSignCount(
        string $id,
        int $signCount,
        Context $context,
        ?\DateTimeInterface $lastUsedAt = null
    ): void {
        $payload = ['id' => $id, 'signCount' => $signCount];
        if ($lastUsedAt !== null) {
            $payload['lastUsedAt'] = $lastUsedAt;
        }

        $context->scope(
            Context::SYSTEM_SCOPE,
            fn (Context $systemContext) => $this->credentialRepository->update([$payload], $systemContext)
        );
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

        $context->scope(
            Context::SYSTEM_SCOPE,
            fn (Context $systemContext) => $this->credentialRepository->delete([['id' => $id]], $systemContext)
        );

        return true;
    }

    public function renameOwned(string $id, Realm $realm, string $accountId, string $name, Context $context): bool
    {
        if (!$this->assertOwned($id, $realm, $accountId, $context)) {
            return false;
        }

        $context->scope(
            Context::SYSTEM_SCOPE,
            fn (Context $systemContext) => $this->credentialRepository->update(
                [['id' => $id, 'name' => $name]],
                $systemContext
            )
        );

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
