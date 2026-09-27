<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Migration;

use Actualize\Passkey\Migration\Migration1790467200PasskeyOrphanedUserHandles;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;

/**
 * Handles of accounts deleted before the cleanup subscriber existed are removed once.
 * Plain DELETE, no DDL, so the transaction wrapper of IntegrationTestBehaviour is fine.
 *
 * @internal
 */
final class Migration1790467200PasskeyOrphanedUserHandlesTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testDeletesOrphansAndKeepsLiveHandles(): void
    {
        $userId = $this->createAdminUser();

        $live = $this->insertHandle('admin', $userId);
        $orphan = $this->insertHandle('admin', Uuid::randomHex());
        // The live user's id in the customer realm: no customer has it, so it is an orphan.
        $otherRealm = $this->insertHandle('customer', $userId);

        $migration = new Migration1790467200PasskeyOrphanedUserHandles();
        $migration->update($this->connection());
        $migration->update($this->connection());

        self::assertTrue($this->exists($live), 'a handle of an existing account must stay');
        self::assertFalse($this->exists($orphan), 'a handle of a deleted account must go');
        self::assertFalse($this->exists($otherRealm), 'the account must exist in the handle\'s own realm');
    }

    private function insertHandle(string $realm, string $accountId): string
    {
        $id = Uuid::randomBytes();
        $this->connection()->insert('act_passkey_user_handle', [
            'id' => $id,
            'realm' => $realm,
            'account_id' => $accountId,
            'user_handle' => random_bytes(32),
            'created_at' => (new \DateTimeImmutable())->format(Defaults::STORAGE_DATE_TIME_FORMAT),
        ]);

        return $id;
    }

    private function exists(string $id): bool
    {
        return (bool) $this->connection()->fetchOne(
            'SELECT 1 FROM `act_passkey_user_handle` WHERE `id` = :id',
            ['id' => $id]
        );
    }

    private function connection(): Connection
    {
        $connection = $this->getContainer()->get(Connection::class);
        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }

    private function createAdminUser(): string
    {
        $repository = $this->getContainer()->get('user.repository');
        self::assertInstanceOf(EntityRepository::class, $repository);

        $userId = Uuid::randomHex();
        $repository->create([[
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
}
