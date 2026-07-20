<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Store;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerPasskeyLoginService;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Shopware\Core\Framework\RateLimiter\Exception\RateLimitExceededException;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Store-api passkey login: hands out a usernameless challenge and verifies the
 * assertion at the CUSTOMER realm via CustomerPasskeyLoginService. No password
 * check is involved, but eligibility still is — the service guards it before
 * opening a session.
 *
 * Both routes are pre-login, which is expressed by NOT setting `_loginRequired`.
 * `auth_required` is a different axis — it gates the sales-channel access-key
 * check, and switching it off makes SalesChannelAuthenticationListener return
 * before it sets the sales-channel id, leaving `SalesChannelContext` unresolvable.
 */
#[Route(defaults: ['_routeScope' => ['store-api']])]
class PasskeyStoreApiController
{
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly CustomerPasskeyLoginService $loginService,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    #[Route(path: '/store-api/act-passkey/challenge', name: 'store-api.act-passkey.challenge', methods: ['POST'])]
    public function challenge(Request $request, SalesChannelContext $context): JsonResponse
    {
        try {
            $this->rateLimiter->ensureAccepted('act_passkey_challenge', (string) $request->getClientIp());
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        try {
            $result = $this->authenticationCeremony->createOptions(Realm::Customer, $request->getHost(), $context->getContext());
        } catch (UnsupportedHostException) {
            return new JsonResponse(['error' => 'unsupported_host'], Response::HTTP_BAD_REQUEST);
        }

        return new JsonResponse(['options' => json_decode($result['options'], true), 'challengeId' => $result['challengeId']]);
    }

    #[Route(path: '/store-api/act-passkey/login', name: 'store-api.act-passkey.login', methods: ['POST'])]
    public function login(Request $request, RequestDataBag $data, SalesChannelContext $context): ContextTokenResponse|JsonResponse
    {
        // Throttle before the body check, so a malformed flood is capped too.
        $rateLimitKey = (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_login', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        $response = $data->get('passkey_response');
        $challengeId = $data->get('passkey_challenge_id');
        if (!is_string($response) || $response === '' || !is_string($challengeId) || $challengeId === '') {
            throw new UnauthorizedHttpException('', 'Passkey authentication failed');
        }

        try {
            $token = $this->loginService->login($response, $challengeId, $request->getHost(), $context);
        } catch (UnsupportedHostException) {
            return new JsonResponse(['error' => 'unsupported_host'], Response::HTTP_BAD_REQUEST);
        }

        // login() throws on every failed attempt, so reset() is reached only on a
        // real success — a reset that ran unconditionally would leave this inert.
        $this->rateLimiter->reset('act_passkey_login', $rateLimitKey);

        return new ContextTokenResponse($token);
    }
}
