<?php declare(strict_types=1);

namespace Actualize\Passkey\Session;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\OAuth\AuthCodeRepository;
use Shopware\Core\Framework\Api\OAuth\RefreshTokenRepository;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextPersister;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\Request;

/**
 * Ends sessions after a passkey was removed. A failure never changes the caller's
 * response: it is logged once and reported as `false`.
 */
class SessionRevoker
{
    public function __construct(
        private readonly SalesChannelContextPersister $contextPersister,
        private readonly RefreshTokenRepository $refreshTokens,
        private readonly AuthCodeRepository $authCodes,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Ends every storefront/store-api session of the customer.
     */
    public function endCustomerSessions(string $customerId, string $credentialId): bool
    {
        try {
            $this->contextPersister->revokeAllCustomerTokens($customerId);

            return true;
        } catch (\Throwable $exception) {
            $this->logFailure(Realm::Customer, $customerId, $credentialId, $exception);

            return false;
        }
    }

    /**
     * Ends all other sessions of the context's customer; the caller moves to a rotated token.
     */
    public function endOtherCustomerSessions(SalesChannelContext $context, Request $request, string $credentialId): bool
    {
        $customerId = (string) $context->getCustomerId();

        try {
            $newToken = $this->contextPersister->replace($context->getToken(), $context);

            if ($request->hasSession(true)) {
                $session = $request->getSession();
                $session->migrate();
                $session->set('sessionId', $session->getId());
                $session->set(PlatformRequest::HEADER_CONTEXT_TOKEN, $newToken);
                // Sales-channel-bound customers are read back from this per-channel key.
                $channelKey = PlatformRequest::HEADER_CONTEXT_TOKEN . '-' . $context->getSalesChannelId();
                if ($session->has($channelKey)) {
                    $session->set($channelKey, $newToken);
                }
            }
            $request->headers->set(PlatformRequest::HEADER_CONTEXT_TOKEN, $newToken);

            $this->contextPersister->revokeAllCustomerTokens($customerId, $newToken);

            return true;
        } catch (\Throwable $exception) {
            $this->logFailure(Realm::Customer, $customerId, $credentialId, $exception);

            return false;
        }
    }

    /**
     * Revokes refresh tokens and auth codes; issued access tokens run out on their own.
     */
    public function endUserSessions(string $userId, string $credentialId): bool
    {
        try {
            $this->refreshTokens->revokeRefreshTokensForUser($userId);
            $this->authCodes->revokeAuthCodesForUser($userId);

            return true;
        } catch (\Throwable $exception) {
            $this->logFailure(Realm::Admin, $userId, $credentialId, $exception);

            return false;
        }
    }

    private function logFailure(Realm $realm, string $ownerId, string $credentialId, \Throwable $exception): void
    {
        $this->logger->warning('Passkey removed but sessions could not be ended', [
            'realm' => $realm->value,
            'ownerId' => $ownerId,
            'credentialId' => $credentialId,
            'exception' => $exception,
        ]);
    }
}
