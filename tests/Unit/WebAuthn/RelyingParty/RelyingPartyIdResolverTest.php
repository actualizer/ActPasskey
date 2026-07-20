<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Unit\WebAuthn\RelyingParty;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Actualize\Passkey\WebAuthn\RelyingParty\SalesChannelDomainProvider;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainCollection;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainEntity;
use Shopware\Core\Test\Stub\DataAbstractionLayer\StaticEntityRepository;
use Shopware\Core\Test\Stub\SystemConfigService\StaticSystemConfigService;

final class RelyingPartyIdResolverTest extends TestCase
{
    private function context(): Context
    {
        return Context::createCLIContext();
    }

    /**
     * @param list<string> $storefrontUrls
     */
    private function resolver(string $appUrl, array $storefrontUrls = [], string $broadenParent = ''): RelyingPartyIdResolver
    {
        $entities = [];
        foreach ($storefrontUrls as $i => $url) {
            $domain = new SalesChannelDomainEntity();
            $domain->setUniqueIdentifier('domain-' . $i);
            $domain->setUrl($url);
            $entities[] = $domain;
        }

        // A single resolve() call reaches the sales-channel lookup at most once,
        // so at most one search() call needs a canned result.
        /** @var StaticEntityRepository<SalesChannelDomainCollection> $repository */
        $repository = new StaticEntityRepository([
            new SalesChannelDomainCollection($entities),
        ]);

        return new RelyingPartyIdResolver(
            $appUrl,
            new SalesChannelDomainProvider($repository),
            new StaticSystemConfigService(['ActPasskey.config.broadenParentDomain' => $broadenParent]),
        );
    }

    public function testCustomerGetsAppHostForAppUrlItself(): void
    {
        $sut = $this->resolver('https://shopa.de');

        self::assertSame('shopa.de', $sut->resolve(Realm::Customer, 'shopa.de', $this->context()));
    }

    public function testAppHostSubdomainStillBroadensToAppHost(): void
    {
        $sut = $this->resolver('https://example.com');

        self::assertSame('example.com', $sut->resolve(Realm::Customer, 'shop.example.com', $this->context()));
    }

    public function testCustomerGetsSecondStorefrontDomainAsItsOwnRpId(): void
    {
        $sut = $this->resolver('https://shopa.de', ['https://shopb.de']);

        self::assertSame('shopb.de', $sut->resolve(Realm::Customer, 'shopb.de', $this->context()));
    }

    public function testAdminRejectsAKnownStorefrontDomain(): void
    {
        // The realm boundary: a legitimate customer domain must never become an
        // admin relying party id.
        $sut = $this->resolver('https://shopa.de', ['https://shopb.de']);

        $this->expectException(UnsupportedHostException::class);
        $sut->resolve(Realm::Admin, 'shopb.de', $this->context());
    }

    public function testAdminIgnoresTheConfiguredBroadenParent(): void
    {
        $sut = $this->resolver('https://www.example.com', [], 'example.com');

        self::assertSame('www.example.com', $sut->resolve(Realm::Admin, 'www.example.com', $this->context()));
    }

    public function testCustomerUsesBroadenParentForASiblingSubdomain(): void
    {
        $sut = $this->resolver('https://www.example.com', [], 'example.com');

        self::assertSame('example.com', $sut->resolve(Realm::Customer, 'en.example.com', $this->context()));
    }

    public function testBroadenParentAppliesEvenWhenHostEqualsAppUrlItself(): void
    {
        // Pins rule 1 before rule 2: the host equals the APP_URL host itself.
        // Under a swapped order rule 2 would match first and return
        // 'www.example.com' instead, splitting its credentials from its siblings.
        $sut = $this->resolver('https://www.example.com', [], 'example.com');

        self::assertSame('example.com', $sut->resolve(Realm::Customer, 'www.example.com', $this->context()));
    }

    public function testAppUrlWinsWhenItIsAlsoAStorefrontDomain(): void
    {
        // An APP_URL host that is also a registered storefront domain still
        // resolves to the app host.
        $sut = $this->resolver('https://shopa.de', ['https://shopa.de', 'https://shopb.de']);

        self::assertSame('shopa.de', $sut->resolve(Realm::Customer, 'shopa.de', $this->context()));
    }

    public function testAppUrlSubdomainOutranksAMatchingStorefrontDomain(): void
    {
        // Pins rule 2 before rule 3: the host is itself a registered storefront
        // domain AND a subdomain of APP_URL. Under a swapped order rule 3 would
        // match first and return 'shop.example.com' instead.
        $sut = $this->resolver('https://example.com', ['https://shop.example.com']);

        self::assertSame('example.com', $sut->resolve(Realm::Customer, 'shop.example.com', $this->context()));
    }

    public function testBroadenParentNotCoveringAppUrlIsIgnored(): void
    {
        // Misconfiguration must not produce an rp id no realm can be reached from.
        $sut = $this->resolver('https://shopa.de', [], 'example.org');

        $this->expectException(UnsupportedHostException::class);
        $sut->resolve(Realm::Customer, 'en.example.org', $this->context());
    }

    public function testMalformedAppUrlFailsClosedOnTrailingDotHost(): void
    {
        // A scheme-less APP_URL leaves appHost '' internally; an empty suffix must
        // not match anything, or any trailing-dot host would resolve to '' instead
        // of throwing.
        $sut = $this->resolver('shop.example.com');

        $this->expectException(UnsupportedHostException::class);
        $sut->resolve(Realm::Customer, 'evil.test.', $this->context());
    }

    public function testProductionDefaultWithoutTheConfigKeyStillResolvesAppUrl(): void
    {
        // The setting is not written to system_config on install, so an untouched
        // shop must go through broadenParent()'s !is_string() branch, not a seeded ''.
        /** @var StaticEntityRepository<SalesChannelDomainCollection> $repository */
        $repository = new StaticEntityRepository([new SalesChannelDomainCollection()]);
        $sut = new RelyingPartyIdResolver(
            'https://shopa.de',
            new SalesChannelDomainProvider($repository),
            new StaticSystemConfigService([]),
        );

        self::assertSame('shopa.de', $sut->resolve(Realm::Customer, 'shopa.de', $this->context()));
    }

    public function testUnknownHostRejectedForCustomer(): void
    {
        $sut = $this->resolver('https://shopa.de', ['https://shopb.de']);

        $this->expectException(UnsupportedHostException::class);
        $sut->resolve(Realm::Customer, 'evil.attacker.test', $this->context());
    }

    public function testReachableRpIdsCoversAppHostAndStorefrontDomains(): void
    {
        $sut = $this->resolver('https://shopa.de', ['https://shopb.de']);

        self::assertEqualsCanonicalizing(
            ['shopa.de', 'shopb.de'],
            $sut->reachableRpIds($this->context())
        );
    }

    public function testBroadenParentCollapsesTheAppHostSubdomainOutOfTheReachableSet(): void
    {
        // With a broaden parent, resolve() returns the parent for the app host, so
        // the bare app-host subdomain is no longer reachable: a credential created
        // before the parent was configured is now orphaned.
        $sut = $this->resolver('https://www.example.com', [], 'example.com');

        self::assertSame(['example.com'], $sut->reachableRpIds($this->context()));
    }

    public function testReachableRpIdsSkipsAnUnparsableAppHost(): void
    {
        // A scheme-less APP_URL yields an empty app host; it must contribute nothing
        // rather than an empty-string rp id.
        $sut = $this->resolver('shopa.de', ['https://shopb.de']);

        self::assertSame(['shopb.de'], $sut->reachableRpIds($this->context()));
    }
}
