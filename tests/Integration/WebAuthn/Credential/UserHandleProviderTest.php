<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Credential;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Credential\UserHandleProvider;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\EventDispatcherBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;

final class UserHandleProviderTest extends TestCase
{
    use EventDispatcherBehaviour;
    use IntegrationTestBehaviour;

    public function testCreateOnceReuseAndReverseLookup(): void
    {
        $sut = $this->getContainer()->get(UserHandleProvider::class);
        $ctx = Context::createDefaultContext();
        $acc = Uuid::randomHex();

        $h1 = $sut->getOrCreate(Realm::Admin, $acc, $ctx);
        $h2 = $sut->getOrCreate(Realm::Admin, $acc, $ctx);

        self::assertSame($h1, $h2, 'handle must be reused');
        self::assertSame(32, \strlen($h1));
        self::assertSame($acc, $sut->resolveAccountId(Realm::Admin, $h1, $ctx));
        self::assertNull($sut->resolveAccountId(Realm::Customer, $h1, $ctx), 'realm-scoped reverse lookup');
    }

    public function testAHandleCreatedConcurrentlyIsReturnedInsteadOfFailing(): void
    {
        $sut = $this->getContainer()->get(UserHandleProvider::class);
        $ctx = Context::createDefaultContext();
        $acc = Uuid::randomHex();
        $rivalHandle = random_bytes(32);
        $connection = $this->getContainer()->get(Connection::class);
        $inserted = false;

        // Stands in for a second request of the same account: its row appears after
        // find() has read "no handle", but before create() writes one. The id-search
        // event fires even for an empty result, unlike the entity search event.
        $this->addEventListener(
            $this->getContainer()->get('event_dispatcher'),
            'act_passkey_user_handle.id.search.result.loaded',
            function () use (&$inserted, $connection, $acc, $rivalHandle): void {
                if ($inserted) {
                    return;
                }
                $inserted = true;
                $connection->insert('act_passkey_user_handle', [
                    'id' => Uuid::randomBytes(),
                    'realm' => Realm::Admin->value,
                    'account_id' => $acc,
                    'user_handle' => $rivalHandle,
                    'created_at' => (new \DateTimeImmutable())->format(Defaults::STORAGE_DATE_TIME_FORMAT),
                ]);
            }
        );

        self::assertSame($rivalHandle, $sut->getOrCreate(Realm::Admin, $acc, $ctx), 'the stored winner, not a locally minted handle');
        self::assertTrue($inserted, 'the race was actually simulated');
    }
}
