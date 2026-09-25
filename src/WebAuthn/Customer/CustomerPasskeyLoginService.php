<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Customer;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Psr\Log\LoggerInterface;
use Shopware\Core\Checkout\Customer\CustomerCollection;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\SalesChannel\AccountService;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * Verifies a customer assertion and opens a session. Shared by the store-api
 * route and the storefront controller so the account checks cannot drift apart.
 */
final class CustomerPasskeyLoginService
{
    /**
     * @param EntityRepository<CustomerCollection> $customerRepository
     */
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly CustomerEligibilityGuard $guard,
        private readonly AccountService $accountService,
        private readonly EntityRepository $customerRepository,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function login(string $rawResponseJson, string $challengeId, string $host, SalesChannelContext $context): string
    {
        try {
            // Bound to the context token that fetched the challenge: a cross-site
            // POST arrives without the Lax session cookie, gets a fresh context and
            // is rejected, so nobody can be logged into someone else's account.
            $customerId = $this->authenticationCeremony->verify(
                Realm::Customer,
                $rawResponseJson,
                $challengeId,
                $host,
                $context->getContext(),
                $context->getToken()
            );
        } catch (\Throwable $exception) {
            // Catch broadly, incl. Webauthn CounterException (does not extend the
            // verification exception in webauthn-lib 5.3.5) — never leak a 500 for
            // a failed authentication attempt. NOTICE, not warning: this is a public
            // endpoint that fails routinely (wrong key, bots), so it must not flood
            // the error log — yet stays diagnosable once the level is lowered.
            $this->logger->notice('Passkey authentication failed', ['exception' => $exception]);
            throw new UnauthorizedHttpException('', 'Passkey authentication failed');
        }

        $customer = $this->customerRepository
            ->search(new Criteria([$customerId]), $context->getContext())
            ->first();

        if (!$customer instanceof CustomerEntity) {
            throw new UnauthorizedHttpException('', 'Passkey authentication failed');
        }

        // The credential is valid — but the account may not be allowed to log in.
        $this->guard->assertEligible($customer);

        return $this->accountService->loginById($customerId, $context);
    }
}
