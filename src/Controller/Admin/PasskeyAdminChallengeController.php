<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Admin;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\RateLimiter\Exception\RateLimitExceededException;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Public (unauthenticated) admin login-challenge endpoint: hands out a
 * usernameless WebAuthn request-options payload + challengeId for the
 * `grant_type=passkey` OAuth grant (see PasskeyGrant).
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class PasskeyAdminChallengeController
{
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    #[Route(
        path: '/api/_action/act-passkey/admin/login-challenge',
        name: 'api.action.act_passkey.admin.login_challenge',
        defaults: ['auth_required' => false],
        methods: ['POST'],
    )]
    public function loginChallenge(Request $request, Context $context): JsonResponse
    {
        try {
            $this->rateLimiter->ensureAccepted('act_passkey_challenge', (string) $request->getClientIp());
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        $host = $request->getHost();

        try {
            $result = $this->authenticationCeremony->createOptions(Realm::Admin, $host, $context);
        } catch (UnsupportedHostException) {
            return new JsonResponse(['error' => 'unsupported_host'], 400);
        }

        return new JsonResponse([
            'options' => json_decode($result['options'], true),
            'challengeId' => $result['challengeId'],
        ]);
    }
}
