<?php declare(strict_types=1);

namespace Actualize\Passkey\Subscriber\Storefront;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Storefront\Page\Account\Login\AccountLoginPageLoadedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Tells the login template whether this domain can run a passkey ceremony at all,
 * so an uncovered domain falls back to password login instead of offering a button
 * that can only fail.
 */
final class LoginPagePasskeySupportSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly RelyingPartyIdResolver $rpIdResolver)
    {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            AccountLoginPageLoadedEvent::class => 'onLoginPageLoaded',
        ];
    }

    public function onLoginPageLoaded(AccountLoginPageLoadedEvent $event): void
    {
        try {
            $this->rpIdResolver->resolve(
                Realm::Customer,
                $event->getRequest()->getHost(),
                $event->getContext()
            );
            $supported = true;
        } catch (UnsupportedHostException) {
            $supported = false;
        }

        $event->getPage()->addExtension('actPasskeySupported', new ArrayStruct(['supported' => $supported]));
    }
}
