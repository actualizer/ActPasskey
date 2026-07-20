<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\RelyingParty;

use Actualize\Passkey\WebAuthn\RelyingParty\SalesChannelDomainProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;

/**
 * @internal
 */
final class SalesChannelDomainProviderFilterTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testHeadlessPlaceholderDomainsAreExcluded(): void
    {
        $provider = static::getContainer()->get(SalesChannelDomainProvider::class);
        static::assertInstanceOf(SalesChannelDomainProvider::class, $provider);

        $hosts = $provider->hosts(Context::createCLIContext());

        // Headless channels ship "default.headless0" style placeholders.
        foreach ($hosts as $host) {
            static::assertStringNotContainsString('headless', $host);
        }
    }

    public function testStorefrontDomainIsIncluded(): void
    {
        $provider = static::getContainer()->get(SalesChannelDomainProvider::class);
        static::assertInstanceOf(SalesChannelDomainProvider::class, $provider);

        $appUrl = (string) static::getContainer()->getParameter('APP_URL');
        $appHost = strtolower((string) parse_url($appUrl, PHP_URL_HOST));

        static::assertContains($appHost, $provider->hosts(Context::createCLIContext()));
    }
}
