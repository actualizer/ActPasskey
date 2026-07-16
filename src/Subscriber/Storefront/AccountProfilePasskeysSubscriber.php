<?php declare(strict_types=1);

namespace Actualize\Passkey\Subscriber\Storefront;

use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerEligibilityGuard;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Storefront\Page\Account\Profile\AccountProfilePageLoadedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Adds the logged-in customer's own passkeys to the account profile page so
 * the passkeys card (block `page_account_profile_passkeys`) can render the
 * list server-side on every page load — no dedicated list route, no AJAX
 * round-trip, and every mutation (register/rename/delete) already redirects
 * back to this page, so the list is always current.
 *
 * Reuses the exact same services PasskeyManageStoreApiController::list() uses
 * (CredentialRepository, CustomerEligibilityGuard) rather than re-querying via
 * a JSON round-trip through that controller — this keeps the entities typed
 * (real DateTimeInterface columns for the twig date filters) and does not
 * duplicate the ownership query.
 */
final class AccountProfilePasskeysSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly CredentialRepository $credentials,
        private readonly CustomerEligibilityGuard $guard,
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
            // The page route is `_loginRequired`, so this should never happen
            // in production — defensive guard only, never a reason to fail
            // rendering the rest of the profile page.
            return;
        }

        try {
            $this->guard->assertEligible($customer);
            $credentials = $this->credentials->listOwned(Realm::Customer, $customer->getId(), $event->getContext());
        } catch (\Throwable) {
            // A session can outlive eligibility (e.g. an admin deactivates the
            // account after login). The guard throwing here must never take
            // down the WHOLE profile page — the twig template already treats
            // a missing extension as an empty list via the `?? []` fallback.
            return;
        }

        $event->getPage()->addExtension('actPasskeyCredentials', new ArrayStruct(['credentials' => $credentials]));
    }
}
