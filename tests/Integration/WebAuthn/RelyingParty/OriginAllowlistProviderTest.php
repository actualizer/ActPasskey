<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\RelyingParty;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\OriginAllowlistProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;

final class OriginAllowlistProviderTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testIncludesAppUrlOriginAndNoDuplicates(): void
    {
        $container = $this->getContainer();
        $sut = $container->get(OriginAllowlistProvider::class);
        $origins = $sut->origins(Realm::Customer, Context::createDefaultContext());

        // Derive the expected app-url origin from the same %APP_URL% parameter the
        // service is wired with, instead of hard-coding a host: the test kernel
        // (APP_ENV=test) resolves APP_URL from the project's .env, not .env.local,
        // so the value differs from the ddev site URL used outside tests.
        $appUrlParts = parse_url((string) $container->getParameter('APP_URL'));
        self::assertIsArray($appUrlParts);
        $expectedAppOrigin = $appUrlParts['scheme'] . '://' . $appUrlParts['host']
            . (isset($appUrlParts['port']) ? ':' . $appUrlParts['port'] : '');

        self::assertContains($expectedAppOrigin, $origins);
        self::assertSame(array_values(array_unique($origins)), $origins, 'no duplicates');
        foreach ($origins as $o) {
            self::assertMatchesRegularExpression('#^https?://#', $o, 'origins are scheme+host');
        }
    }

    public function testAdminAllowlistHoldsOnlyTheAppUrlOrigin(): void
    {
        $provider = static::getContainer()->get(OriginAllowlistProvider::class);
        static::assertInstanceOf(OriginAllowlistProvider::class, $provider);

        $appUrl = rtrim((string) static::getContainer()->getParameter('APP_URL'), '/');

        // Customer ceremonies now run on arbitrary storefront domains, so the admin
        // must not inherit that widened list.
        static::assertSame([$appUrl], $provider->origins(Realm::Admin, Context::createCLIContext()));
    }
}
