<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Unit\WebAuthn\RelyingParty;

use Actualize\Passkey\WebAuthn\RelyingParty\SalesChannelDomainProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainCollection;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainEntity;
use Shopware\Core\Test\Stub\DataAbstractionLayer\StaticEntityRepository;

final class SalesChannelDomainProviderTest extends TestCase
{
    public function testPathLanguageDomainsCollapseToOneHost(): void
    {
        // Shopware stores one row per language; both mean the same host, and
        // WebAuthn knows no paths.
        $provider = $this->providerFor(['https://domain.de/de', 'https://domain.de/en']);

        self::assertSame(['domain.de'], $provider->hosts(Context::createCLIContext()));
    }

    public function testDistinctHostsAreKept(): void
    {
        $provider = $this->providerFor(['https://shopa.de', 'https://shopb.de']);

        self::assertSame(['shopa.de', 'shopb.de'], $provider->hosts(Context::createCLIContext()));
    }

    public function testHostsAreLowercased(): void
    {
        $provider = $this->providerFor(['https://SHOPA.de']);

        self::assertSame(['shopa.de'], $provider->hosts(Context::createCLIContext()));
    }

    public function testOriginsKeepSchemeAndPort(): void
    {
        $provider = $this->providerFor(['https://shopa.de:8443/de', 'http://shopb.de']);

        self::assertSame(
            ['https://shopa.de:8443', 'http://shopb.de'],
            $provider->origins(Context::createCLIContext())
        );
    }

    public function testUnparsableUrlIsSkipped(): void
    {
        $provider = $this->providerFor(['not-a-url', 'https://shopa.de']);

        self::assertSame(['shopa.de'], $provider->hosts(Context::createCLIContext()));
    }

    /**
     * @param list<string> $urls
     */
    private function providerFor(array $urls): SalesChannelDomainProvider
    {
        $entities = [];
        foreach ($urls as $i => $url) {
            $domain = new SalesChannelDomainEntity();
            $domain->setUniqueIdentifier('domain-' . $i);
            $domain->setUrl($url);
            $entities[] = $domain;
        }

        /** @var StaticEntityRepository<SalesChannelDomainCollection> $repository */
        $repository = new StaticEntityRepository([
            new SalesChannelDomainCollection($entities),
            new SalesChannelDomainCollection($entities),
        ]);

        return new SalesChannelDomainProvider($repository);
    }
}
