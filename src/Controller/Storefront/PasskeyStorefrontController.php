<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Storefront;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerPasskeyLoginService;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Shopware\Core\Framework\RateLimiter\Exception\RateLimitExceededException;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Storefront passkey login: hands out a usernameless challenge and verifies the
 * assertion at the CUSTOMER realm. No password check — the assertion IS the
 * credential. The session is opened via CustomerPasskeyLoginService, shared with
 * PasskeyStoreApiController so the eligibility checks cannot drift apart.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class PasskeyStorefrontController extends StorefrontController
{
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly CustomerPasskeyLoginService $loginService,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    #[Route(path: '/account/login/passkey/challenge', name: 'frontend.account.login.passkey.challenge', defaults: ['XmlHttpRequest' => true], methods: ['POST'])]
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

    #[Route(path: '/account/login/passkey', name: 'frontend.account.login.passkey', methods: ['POST'])]
    public function login(Request $request, SalesChannelContext $context): Response
    {
        // Throttle before the body check, so a malformed flood is capped too.
        $rateLimitKey = (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_login', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        $response = $request->request->get('passkey_response');
        $challengeId = $request->request->get('passkey_challenge_id');
        if (!is_string($response) || $response === '' || !is_string($challengeId) || $challengeId === '') {
            return $this->forwardToRoute('frontend.account.login.page', ['loginError' => true], []);
        }

        try {
            $this->loginService->login($response, $challengeId, $request->getHost(), $context);
            // Inside the try: a failed login throws, so only a success resets.
            $this->rateLimiter->reset('act_passkey_login', $rateLimitKey);
        } catch (\Throwable) {
            // Catch broadly, incl. a rejected CustomerEligibilityGuard check
            // (e.g. unconfirmed double opt-in) — never leak a 500 for a failed
            // or disallowed login attempt.
            return $this->forwardToRoute('frontend.account.login.page', ['loginError' => true], []);
        }

        // createActionResponse() falls back to an EMPTY Response when neither
        // redirectTo nor forwardTo is present, hence the explicit account-home
        // redirect below.
        if ($request->request->has('redirectTo') || $request->query->has('redirectTo')) {
            return $this->createActionResponse($request);
        }

        return $this->redirectToRoute('frontend.account.home.page');
    }
}
