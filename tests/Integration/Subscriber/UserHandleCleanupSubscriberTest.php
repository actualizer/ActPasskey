<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Subscriber;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Credential\UserHandleProvider;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;

/**
 * Credentials leave with their account through the FK cascade; the user handle has no
 * FK (its account id is polymorphic by realm), so it is removed on the delete event.
 *
 * @internal
 */
final class UserHandleCleanupSubscriberTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testDeletingAUserRemovesOnlyItsHandle(): void
    {
        $deleted = $this->createAdminUser();
        $kept = $this->createAdminUser();
        $this->handles()->getOrCreate(Realm::Admin, $deleted, Context::createDefaultContext());
        $this->handles()->getOrCreate(Realm::Admin, $kept, Context::createDefaultContext());

        $this->repository('user.repository')->delete([['id' => $deleted]], Context::createDefaultContext());

        self::assertSame(0, $this->handleCount(Realm::Admin, $deleted));
        self::assertSame(1, $this->handleCount(Realm::Admin, $kept));
    }

    public function testDeletingSeveralCustomersAtOnceRemovesEveryHandle(): void
    {
        $first = $this->createCustomer();
        $second = $this->createCustomer();
        $this->handles()->getOrCreate(Realm::Customer, $first, Context::createDefaultContext());
        $this->handles()->getOrCreate(Realm::Customer, $second, Context::createDefaultContext());

        $this->repository('customer.repository')->delete([['id' => $first], ['id' => $second]], Context::createDefaultContext());

        self::assertSame(0, $this->handleCount(Realm::Customer, $first));
        self::assertSame(0, $this->handleCount(Realm::Customer, $second));
    }

    /**
     * Unlikely in practice (ids are random UUIDs), but it proves the cleanup is scoped
     * to the realm of the deleted entity rather than matching on the id alone.
     */
    public function testTheOtherRealmsHandleWithTheSameIdStays(): void
    {
        $userId = $this->createAdminUser();
        $this->handles()->getOrCreate(Realm::Admin, $userId, Context::createDefaultContext());
        $this->handles()->getOrCreate(Realm::Customer, $userId, Context::createDefaultContext());

        $this->repository('user.repository')->delete([['id' => $userId]], Context::createDefaultContext());

        self::assertSame(0, $this->handleCount(Realm::Admin, $userId));
        self::assertSame(1, $this->handleCount(Realm::Customer, $userId));
    }

    public function testDeletingAnAccountWithoutAHandleIsANoOp(): void
    {
        $userId = $this->createAdminUser();

        $this->repository('user.repository')->delete([['id' => $userId]], Context::createDefaultContext());

        self::assertSame(0, $this->handleCount(Realm::Admin, $userId));
    }

    private function handleCount(Realm $realm, string $accountId): int
    {
        $connection = $this->getContainer()->get(Connection::class);
        self::assertInstanceOf(Connection::class, $connection);

        return (int) $connection->fetchOne(
            'SELECT COUNT(*) FROM `act_passkey_user_handle` WHERE `realm` = :realm AND `account_id` = :accountId',
            ['realm' => $realm->value, 'accountId' => $accountId]
        );
    }

    private function handles(): UserHandleProvider
    {
        $service = $this->getContainer()->get(UserHandleProvider::class);
        self::assertInstanceOf(UserHandleProvider::class, $service);

        return $service;
    }

    private function repository(string $id): EntityRepository
    {
        $repository = $this->getContainer()->get($id);
        self::assertInstanceOf(EntityRepository::class, $repository);

        return $repository;
    }

    private function createAdminUser(): string
    {
        $userId = Uuid::randomHex();
        $this->repository('user.repository')->create([[
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

    private function createCustomer(): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();

        $this->repository('customer.repository')->create([[
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
}
