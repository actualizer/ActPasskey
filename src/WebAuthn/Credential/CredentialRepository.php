<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Credential;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialCollection;
use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\MultiFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\NotEqualsAnyFilter;

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

    /**
     * `$rpId` filters the list to the current channel. Rows without a stored rp id
     * stay visible — filtering is display logic and must never hide a credential the
     * owner still needs to manage. `$reachableRpIds` is the set the resolver can still
     * return on some active domain; a row whose rp id is not in it is orphaned (its
     * domain was retired or the broaden parent changed) and is surfaced everywhere so
     * it does not become unmanageable.
     *
     * @param list<string> $reachableRpIds
     */
    public function listOwned(
        Realm $realm,
        string $accountId,
        Context $context,
        ?string $rpId = null,
        array $reachableRpIds = []
    ): PasskeyCredentialCollection {
        $ownerField = $realm === Realm::Admin ? 'userId' : 'customerId';

        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('realm', $realm->value))
            ->addFilter(new EqualsFilter($ownerField, $accountId));

        if ($rpId !== null) {
            $branches = [
                new EqualsFilter('rpId', $rpId),
                new EqualsFilter('rpId', null),
            ];

            // Only add the orphan branch when the reachable set is known; NOT IN ()
            // would otherwise match every row and defeat the channel filter.
            if ($reachableRpIds !== []) {
                $branches[] = new NotEqualsAnyFilter('rpId', $reachableRpIds);
            }

            $criteria->addFilter(new MultiFilter(MultiFilter::CONNECTION_OR, $branches));
        }

        /** @var PasskeyCredentialCollection $collection */
        $collection = $this->credentialRepository->search($criteria, $context)->getEntities();

        return $collection;
    }
}
