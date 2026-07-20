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
use Shopware\Storefront\Page\Checkout\Register\CheckoutRegisterPage;
use Shopware\Storefront\Page\Checkout\Register\CheckoutRegisterPageLoadedEvent;
use Symfony\Component\EventDispatcher\EventDispatcher;
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

    // Goes through the real event dispatcher (not a direct method call) so a
    // getSubscribedEvents() mapping that drops this event is actually caught:
    // the checkout/register page sw_extends the same login component template.
    private function dispatchCheckoutRegister(RelyingPartyIdResolver $resolver, string $host): CheckoutRegisterPage
    {
        $page = new CheckoutRegisterPage();
        $event = new CheckoutRegisterPageLoadedEvent(
            $page,
            Generator::generateSalesChannelContext(),
            Request::create('https://' . $host . '/checkout/register'),
        );

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new LoginPagePasskeySupportSubscriber($resolver));
        $dispatcher->dispatch($event);

        return $page;
    }

    public function testCheckoutRegisterHostCoveredByResolverIsMarkedSupported(): void
    {
        $page = $this->dispatchCheckoutRegister($this->resolver('https://shopa.de'), 'shopa.de');

        $extension = $page->getExtension('actPasskeySupported');
        self::assertInstanceOf(ArrayStruct::class, $extension);
        self::assertTrue($extension->get('supported'));
    }

    public function testCheckoutRegisterHostNotCoveredByResolverIsMarkedUnsupported(): void
    {
        $page = $this->dispatchCheckoutRegister($this->resolver('https://shopa.de'), 'evil.attacker.test');

        $extension = $page->getExtension('actPasskeySupported');
        self::assertInstanceOf(ArrayStruct::class, $extension);
        self::assertFalse($extension->get('supported'));
    }

    public function testSubscribesToBothLoginAndCheckoutRegisterPageLoadedEvents(): void
    {
        $events = LoginPagePasskeySupportSubscriber::getSubscribedEvents();

        // Pin the handler names too: a swapped mapping is only caught indirectly,
        // via the TypeError the strictly typed handlers raise when dispatched.
        self::assertSame('onLoginPageLoaded', $events[AccountLoginPageLoadedEvent::class] ?? null);
        self::assertSame('onCheckoutRegisterPageLoaded', $events[CheckoutRegisterPageLoadedEvent::class] ?? null);
    }
}
