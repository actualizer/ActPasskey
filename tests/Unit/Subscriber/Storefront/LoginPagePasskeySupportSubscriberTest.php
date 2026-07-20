<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Unit\Subscriber\Storefront;

use Actualize\Passkey\Subscriber\Storefront\LoginPagePasskeySupportSubscriber;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Actualize\Passkey\WebAuthn\RelyingParty\SalesChannelDomainProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainCollection;
use Shopware\Core\Test\Generator;
use Shopware\Core\Test\Stub\DataAbstractionLayer\StaticEntityRepository;
use Shopware\Core\Test\Stub\SystemConfigService\StaticSystemConfigService;
use Shopware\Storefront\Page\Account\Login\AccountLoginPage;
use Shopware\Storefront\Page\Account\Login\AccountLoginPageLoadedEvent;
use Symfony\Component\HttpFoundation\Request;

final class LoginPagePasskeySupportSubscriberTest extends TestCase
{
    // A real resolver, built exactly like RelyingPartyIdResolverTest::resolver() —
    // it is final and cannot be mocked.
    private function resolver(string $appUrl): RelyingPartyIdResolver
    {
        /** @var StaticEntityRepository<SalesChannelDomainCollection> $repository */
        $repository = new StaticEntityRepository([new SalesChannelDomainCollection()]);

        return new RelyingPartyIdResolver(
            $appUrl,
            new SalesChannelDomainProvider($repository),
            new StaticSystemConfigService([]),
        );
    }

    private function dispatch(RelyingPartyIdResolver $resolver, string $host): AccountLoginPage
    {
        $page = new AccountLoginPage();
        $event = new AccountLoginPageLoadedEvent(
            $page,
            Generator::generateSalesChannelContext(),
            Request::create('https://' . $host . '/account/login'),
        );

        (new LoginPagePasskeySupportSubscriber($resolver))->onLoginPageLoaded($event);

        return $page;
    }

    public function testHostCoveredByResolverIsMarkedSupported(): void
    {
        $page = $this->dispatch($this->resolver('https://shopa.de'), 'shopa.de');

        $extension = $page->getExtension('actPasskeySupported');
        self::assertInstanceOf(ArrayStruct::class, $extension);
        self::assertTrue($extension->get('supported'));
    }

    public function testHostNotCoveredByResolverIsMarkedUnsupported(): void
    {
        $page = $this->dispatch($this->resolver('https://shopa.de'), 'evil.attacker.test');

        $extension = $page->getExtension('actPasskeySupported');
        self::assertInstanceOf(ArrayStruct::class, $extension);
        self::assertFalse($extension->get('supported'));
    }
}
