<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Credential;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Credential\UserHandleProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;

final class UserHandleProviderTest extends TestCase
{
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
}
