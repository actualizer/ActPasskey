<?php declare(strict_types=1);

namespace Actualize\Passkey\Subscriber\Storefront;

use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerEligibilityGuard;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Storefront\Page\Account\Profile\AccountProfilePageLoadedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Adds the logged-in customer's own passkeys to the account profile page so the
 * passkeys card (block `page_account_profile_passkeys`) can render the list
 * server-side. Every mutation redirects back to this page, so the list is
 * always current.
 */
final class AccountProfilePasskeysSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly CredentialRepository $credentials,
        private readonly CustomerEligibilityGuard $guard,
        private readonly RelyingPartyIdResolver $rpIdResolver,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            AccountProfilePageLoadedEvent::class => 'onProfileLoaded',
        ];
    }

    public function onProfileLoaded(AccountProfilePageLoadedEvent $event): void
    {
        $customer = $event->getSalesChannelContext()->getCustomer();
        if ($customer === null) {
            // The page route is `_loginRequired`; defensive guard only.
            return;
        }

        try {
            $this->guard->assertEligible($customer);
            $credentials = $this->credentials->listOwned(
                Realm::Customer,
                $customer->getId(),
                $event->getContext(),
                $this->currentRpId($event->getRequest()->getHost(), $event->getContext()),
            );
        } catch (\Throwable) {
            // A session can outlive eligibility (e.g. the account is deactivated
            // after login). That must never take down the whole profile page; the
            // template treats a missing extension as an empty list.
            return;
        }

        $event->getPage()->addExtension('actPasskeyCredentials', new ArrayStruct(['credentials' => $credentials]));
    }

    /**
     * An unresolvable host must not hide the list: the customer would lose access to
     * credentials they may still need to delete.
     */
    private function currentRpId(string $host, Context $context): ?string
    {
        try {
            return $this->rpIdResolver->resolve(Realm::Customer, $host, $context);
        } catch (UnsupportedHostException) {
            return null;
        }
    }
}
