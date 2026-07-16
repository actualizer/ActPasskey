<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Storefront;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerPasskeyLoginService;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Storefront passkey login: hands out a usernameless WebAuthn request-options
 * payload (challenge) and, after the browser responds, verifies the assertion
 * at the CUSTOMER realm and establishes the session via
 * CustomerPasskeyLoginService (no password check — the passkey assertion IS
 * the credential), same-origin, so the login page can redirect straight into
 * the account area. Shares the login service with PasskeyStoreApiController
 * so the account eligibility checks cannot drift apart between the two entry
 * points.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class PasskeyStorefrontController extends StorefrontController
{
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly CustomerPasskeyLoginService $loginService,
    ) {
    }

    #[Route(path: '/account/login/passkey/challenge', name: 'frontend.account.login.passkey.challenge', defaults: ['XmlHttpRequest' => true], methods: ['POST'])]
    public function challenge(Request $request, SalesChannelContext $context): JsonResponse
    {
        $result = $this->authenticationCeremony->createOptions(Realm::Customer, $request->getHost(), $context->getContext());

        return new JsonResponse(['options' => json_decode($result['options'], true), 'challengeId' => $result['challengeId']]);
    }

    #[Route(path: '/account/login/passkey', name: 'frontend.account.login.passkey', methods: ['POST'])]
    public function login(Request $request, SalesChannelContext $context): Response
    {
        $response = $request->request->get('passkey_response');
        $challengeId = $request->request->get('passkey_challenge_id');
        if (!is_string($response) || $response === '' || !is_string($challengeId) || $challengeId === '') {
            return $this->forwardToRoute('frontend.account.login.page', ['loginError' => true], []);
        }

        try {
            $this->loginService->login($response, $challengeId, $request->getHost(), $context);
        } catch (\Throwable) {
            // Catch broadly, incl. a rejected CustomerEligibilityGuard check
            // (e.g. unconfirmed double opt-in) — never leak a 500 for a failed
            // or disallowed login attempt.
            return $this->forwardToRoute('frontend.account.login.page', ['loginError' => true], []);
        }

        // Mirrors AuthController::login: honors the redirectTo/redirectParameters
        // carried over from the surrounding login form (checkout guest-login,
        // product-review login card, ...) instead of always bouncing to the
        // account home page. createActionResponse() falls back to an empty
        // Response when neither redirectTo nor forwardTo is present on the
        // request, so keep the account-home redirect as an explicit fallback
        // for that case.
        if ($request->request->has('redirectTo') || $request->query->has('redirectTo')) {
            return $this->createActionResponse($request);
        }

        return $this->redirectToRoute('frontend.account.home.page');
    }
}
