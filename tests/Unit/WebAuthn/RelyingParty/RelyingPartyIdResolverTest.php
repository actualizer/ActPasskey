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

        // One canned result per possible search() call in a single test.
        /** @var StaticEntityRepository<SalesChannelDomainCollection> $repository */
        $repository = new StaticEntityRepository([
            new SalesChannelDomainCollection($entities),
            new SalesChannelDomainCollection($entities),
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

    public function testAppUrlWinsWhenItIsAlsoAStorefrontDomain(): void
    {
        // Rule 2 before rule 3, otherwise the rp id would flip with the data.
        $sut = $this->resolver('https://shopa.de', ['https://shopa.de', 'https://shopb.de']);

        self::assertSame('shopa.de', $sut->resolve(Realm::Customer, 'shopa.de', $this->context()));
    }

    public function testBroadenParentNotCoveringAppUrlIsIgnored(): void
    {
        // Misconfiguration must not produce an rp id no realm can be reached from.
        $sut = $this->resolver('https://shopa.de', [], 'example.org');

        $this->expectException(UnsupportedHostException::class);
        $sut->resolve(Realm::Customer, 'en.example.org', $this->context());
    }

    public function testUnknownHostRejectedForCustomer(): void
    {
        $sut = $this->resolver('https://shopa.de', ['https://shopb.de']);

        $this->expectException(UnsupportedHostException::class);
        $sut->resolve(Realm::Customer, 'evil.attacker.test', $this->context());
    }
}
