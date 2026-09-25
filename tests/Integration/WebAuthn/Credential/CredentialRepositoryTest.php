<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Credential;

use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;

final class CredentialRepositoryTest extends TestCase
{
    use IntegrationTestBehaviour;

    /**
     * `customer_id` on act_passkey_credential has a real FK to `customer`, so
     * owner ids used in fixtures must be actual customer rows, not bare UUIDs.
     */
    private function createCustomer(): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();

        /** @var EntityRepository $customerRepository */
        $customerRepository = $this->getContainer()->get('customer.repository');
        $customerRepository->create([[
            'id' => $customerId,
            'salesChannelId' => TestDefaults::SALES_CHANNEL,
            'defaultShippingAddress' => [
                'id' => $addressId,
                'firstName' => 'Max',
                'lastName' => 'Mustermann',
                'street' => 'Musterstraße 1',
                'city' => 'Schöppingen',
                'zipcode' => '12345',
                'salutationId' => $this->getValidSalutationId(),
                'countryId' => $this->getValidCountryId(),
            ],
            'defaultBillingAddressId' => $addressId,
            'groupId' => TestDefaults::FALLBACK_CUSTOMER_GROUP,
            'email' => Uuid::randomHex() . '@example.test',
            'password' => TestDefaults::HASHED_PASSWORD,
            'firstName' => 'Max',
            'lastName' => 'Mustermann',
            'salutationId' => $this->getValidSalutationId(),
            'customerNumber' => Uuid::randomHex(),
        ]], Context::createDefaultContext());

        return $customerId;
    }

    /**
     * `user_id` on act_passkey_credential has a real FK to `user`, so owner ids
     * used in fixtures must be actual user rows, not bare UUIDs.
     */
    private function createAdminUser(): string
    {
        $userId = Uuid::randomHex();

        /** @var EntityRepository $userRepository */
        $userRepository = $this->getContainer()->get('user.repository');
        $userRepository->create([[
            'id' => $userId,
            'localeId' => $this->getLocaleIdOfSystemLanguage(),
            'username' => Uuid::randomHex(),
            'password' => TestDefaults::HASHED_PASSWORD,
            'firstName' => 'Max',
            'lastName' => 'Mustermann',
            'email' => Uuid::randomHex() . '@example.test',
            'admin' => true,
        ]], Context::createDefaultContext());

        return $userId;
    }

    private function seed(string $realm, ?string $userId, ?string $customerId, string $rawCredId): void
    {
        /** @var EntityRepository $raw */
        $raw = $this->getContainer()->get('act_passkey_credential.repository');
        $raw->create([[
            'id' => Uuid::randomHex(),
            'realm' => $realm,
            'userId' => $userId,
            'customerId' => $customerId,
            'credentialId' => $rawCredId,
            'publicKey' => 'k',
            'signCount' => 0,
            'userHandle' => Uuid::randomBytes(),
            'aaguid' => Uuid::randomHex(),
            'transports' => ['internal'],
            'name' => 'n',
        ]], Context::createDefaultContext());
    }

    public function testCustomerCredentialInvisibleToAdminRealm(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $cred = Uuid::randomBytes();
        $this->seed('customer', null, $this->createCustomer(), $cred);

        self::assertNull($sut->findOneByCredentialId($cred, Realm::Admin, $ctx), 'realm boundary: not visible to admin');
        self::assertNotNull($sut->findOneByCredentialId($cred, Realm::Customer, $ctx), 'visible in its own realm');
    }

    public function testDeleteOwnedRejectsForeignOwner(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createCustomer();
        $attackerB = Uuid::randomHex();
        $cred = Uuid::randomBytes();
        $this->seed('customer', null, $ownerA, $cred);

        $row = $sut->findOneByCredentialId($cred, Realm::Customer, $ctx);
        self::assertNotNull($row);

        self::assertFalse($sut->deleteOwned($row->getId(), Realm::Customer, $attackerB, $ctx), 'B cannot delete A key');
        self::assertNotNull($sut->findOneByCredentialId($cred, Realm::Customer, $ctx), 'A key survives foreign delete attempt');

        self::assertTrue($sut->deleteOwned($row->getId(), Realm::Customer, $ownerA, $ctx), 'owner can delete own key');
        self::assertNull($sut->findOneByCredentialId($cred, Realm::Customer, $ctx), 'key gone after owner delete');
    }

    public function testAdminRealmDeleteOwnedRejectsForeignOwner(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createAdminUser();
        $attackerB = $this->createAdminUser();
        $cred = Uuid::randomBytes();
        $this->seed('admin', $ownerA, null, $cred);

        self::assertNull($sut->findOneByCredentialId($cred, Realm::Customer, $ctx), 'realm boundary: not visible to customer');

        $row = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($row);

        self::assertFalse($sut->deleteOwned($row->getId(), Realm::Admin, $attackerB, $ctx), 'B cannot delete A key');
        self::assertNotNull($sut->findOneByCredentialId($cred, Realm::Admin, $ctx), 'A key survives foreign delete attempt');

        self::assertTrue($sut->deleteOwned($row->getId(), Realm::Admin, $ownerA, $ctx), 'owner can delete own key');
        self::assertNull($sut->findOneByCredentialId($cred, Realm::Admin, $ctx), 'key gone after owner delete');
    }

    public function testListOwnedIsScopedToOwner(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createCustomer();
        $ownerB = $this->createCustomer();
        $this->seed('customer', null, $ownerA, Uuid::randomBytes());
        $this->seed('customer', null, $ownerA, Uuid::randomBytes());
        $this->seed('customer', null, $ownerB, Uuid::randomBytes());

        self::assertSame(2, $sut->listOwned(Realm::Customer, $ownerA, $ctx)->count());
        self::assertSame(1, $sut->listOwned(Realm::Customer, $ownerB, $ctx)->count());
    }

    public function testRenameOwnedUpdatesTheNameForTheOwner(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createAdminUser();
        $cred = Uuid::randomBytes();
        $this->seed('admin', $ownerA, null, $cred);

        $row = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($row);

        self::assertTrue($sut->renameOwned($row->getId(), Realm::Admin, $ownerA, 'New name', $ctx));

        $entity = $sut->listOwned(Realm::Admin, $ownerA, $ctx)->first();
        self::assertNotNull($entity);
        self::assertSame('New name', $entity->getName());
    }

    public function testRenameOwnedRejectsAnOverlongName(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createAdminUser();
        $cred = Uuid::randomBytes();
        $this->seed('admin', $ownerA, null, $cred);

        $row = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($row);

        $overlong = str_repeat('a', CredentialRepository::MAX_NAME_LENGTH + 1);
        self::assertFalse($sut->renameOwned($row->getId(), Realm::Admin, $ownerA, $overlong, $ctx));

        // The rejected rename leaves the stored name untouched.
        $entity = $sut->listOwned(Realm::Admin, $ownerA, $ctx)->first();
        self::assertNotNull($entity);
        self::assertSame('n', $entity->getName());
    }

    public function testRenameOwnedIsANoOpForAForeignOwner(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createAdminUser();
        $attackerB = $this->createAdminUser();
        $cred = Uuid::randomBytes();
        $this->seed('admin', $ownerA, null, $cred);

        $row = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($row);

        self::assertFalse($sut->renameOwned($row->getId(), Realm::Admin, $attackerB, 'Hacked', $ctx));

        $entity = $sut->listOwned(Realm::Admin, $ownerA, $ctx)->first();
        self::assertNotNull($entity);
        self::assertSame('n', $entity->getName());
    }

    public function testRenameOwnedIsANoOpAcrossRealms(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createAdminUser();
        $cred = Uuid::randomBytes();
        $this->seed('admin', $ownerA, null, $cred);

        $row = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($row);

        self::assertFalse($sut->renameOwned($row->getId(), Realm::Customer, $ownerA, 'Hacked', $ctx));

        $entity = $sut->listOwned(Realm::Admin, $ownerA, $ctx)->first();
        self::assertNotNull($entity);
        self::assertSame('n', $entity->getName());
    }

    public function testMarkUsedStampsLastUsedAt(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createAdminUser();
        $cred = Uuid::randomBytes();
        $this->seed('admin', $ownerA, null, $cred);

        $row = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($row);
        self::assertNull($row->getLastUsedAt(), 'freshly seeded credential has no last-used stamp');

        $stamp = new \DateTimeImmutable('2024-06-01T12:00:00+00:00');
        $sut->markUsed($row->getId(), $ctx, $stamp);

        $updated = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($updated);
        self::assertNotNull($updated->getLastUsedAt());
        self::assertSame($stamp->getTimestamp(), $updated->getLastUsedAt()->getTimestamp());
    }

    public function testUpdateSignCountLeavesLastUsedAtUntouched(): void
    {
        $sut = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $ownerA = $this->createAdminUser();
        $cred = Uuid::randomBytes();
        $this->seed('admin', $ownerA, null, $cred);

        $row = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($row);

        $stamp = new \DateTimeImmutable('2024-06-01T12:00:00+00:00');
        $sut->markUsed($row->getId(), $ctx, $stamp);
        $sut->updateSignCount($row->getId(), 4, $ctx);

        $unchanged = $sut->findOneByCredentialId($cred, Realm::Admin, $ctx);
        self::assertNotNull($unchanged);
        self::assertSame(4, $unchanged->getSignCount());
        self::assertNotNull($unchanged->getLastUsedAt());
        self::assertSame($stamp->getTimestamp(), $unchanged->getLastUsedAt()->getTimestamp());
    }
}
