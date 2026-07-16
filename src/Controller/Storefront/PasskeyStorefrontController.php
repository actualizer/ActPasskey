<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Storefront;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Shopware\Core\Checkout\Customer\SalesChannel\AccountService;
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
 * AccountService::loginById (no password check — the passkey assertion IS
 * the credential), same-origin, so the login page can redirect straight into
 * the account area. Mirrors PasskeyStoreApiController's verify step directly
 * (no controller-to-controller call) rather than sharing a service.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class PasskeyStorefrontController extends StorefrontController
{
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly AccountService $accountService,
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
            $customerId = $this->authenticationCeremony->verify(
                Realm::Customer,
                $response,
                $challengeId,
                $request->getHost(),
                $context->getContext()
            );
            $this->accountService->loginById($customerId, $context);
        } catch (\Throwable) {
            // Catch broadly, incl. Webauthn CounterException (does not extend the
            // verification exception in webauthn-lib 5.3.5) — never leak a 500 for
            // a failed authentication attempt.
            return $this->forwardToRoute('frontend.account.login.page', ['loginError' => true], []);
        }

        return $this->redirectToRoute('frontend.account.home.page');
    }
}
