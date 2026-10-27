<?php declare(strict_types=1);

namespace Actualize\Passkey\Subscriber\Storefront;

use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerEligibilityGuard;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Shopware\Storefront\Page\Account\Overview\AccountOverviewPageLoadedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Decides whether the account overview invites the customer to add a passkey.
 * The extension `actPasskeyEnrollmentPrompt` exists only when the prompt may show.
 */
final class AccountOverviewEnrollmentPromptSubscriber implements EventSubscriberInterface
{
    private const CONFIG_KEY = 'ActPasskey.config.enrollmentPrompt';

    public function __construct(
        private readonly CredentialRepository $credentials,
        private readonly CustomerEligibilityGuard $guard,
        private readonly RelyingPartyIdResolver $rpIdResolver,
        private readonly SystemConfigService $systemConfig,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            AccountOverviewPageLoadedEvent::class => 'onOverviewLoaded',
        ];
    }

    public function onOverviewLoaded(AccountOverviewPageLoadedEvent $event): void
    {
        $context = $event->getSalesChannelContext();

        // Not getBool(): config.xml defaults are not written on plugin update, so an
        // unsaved key must read as "on".
        $enabled = $this->systemConfig->get(self::CONFIG_KEY, $context->getSalesChannelId());
        if ($enabled !== null && !$enabled) {
            return;
        }

        $customer = $context->getCustomer();
        if ($customer === null || $customer->getGuest()) {
            return;
        }

        if ($context->getImitatingUserId() !== null) {
            return;
        }

        try {
            $this->guard->assertEligible($customer);
        } catch (\Throwable) {
            return;
        }

        try {
            $rpId = $this->rpIdResolver->resolve(Realm::Customer, $event->getRequest()->getHost(), $event->getContext());
        } catch (UnsupportedHostException) {
            return;
        }

        if ($this->credentials->listOwned(Realm::Customer, $customer->getId(), $event->getContext(), $rpId)->count() > 0) {
            return;
        }

        $event->getPage()->addExtension('actPasskeyEnrollmentPrompt', new ArrayStruct([
            'dismissKey' => 'act-passkey-enrollment-prompt-'
                . substr(hash('sha256', 'act-passkey|' . $customer->getId()), 0, 16),
        ]));
    }
}
