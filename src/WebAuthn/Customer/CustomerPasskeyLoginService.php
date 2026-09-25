<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Customer;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
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
        private readonly CredentialRepository $credentials,
    ) {
    }

    public function login(string $rawResponseJson, string $challengeId, string $host, SalesChannelContext $context): string
    {
        try {
            // Redeemable only in the context that fetched the challenge; an attacker
            // cannot obtain a challenge bound to the victim's context token.
            $result = $this->authenticationCeremony->verify(
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
            ->search(new Criteria([$result->accountId]), $context->getContext())
            ->getEntities()
            ->first();

        if (!$customer instanceof CustomerEntity) {
            throw new UnauthorizedHttpException('', 'Passkey authentication failed');
        }

        // The credential is valid — but the account may not be allowed to log in.
        $this->guard->assertEligible($customer);

        $token = $this->accountService->loginById($result->accountId, $context);

        // Stamped only once the session exists: a refused login must not look like a
        // recent use. The stamp is cosmetic, so a failing write must not turn the
        // accepted login into an error.
        try {
            $this->credentials->markUsed($result->credentialEntityId, $context->getContext(), new \DateTimeImmutable());
        } catch (\Throwable $exception) {
            $this->logger->warning('Passkey last-used stamp failed', ['exception' => $exception]);
        }

        return $token;
    }
}
