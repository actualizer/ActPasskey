<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Store;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Shopware\Core\Checkout\Customer\SalesChannel\AccountService;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Store-api passkey login: hands out a usernameless WebAuthn request-options
 * payload (challenge) and, after the browser responds, verifies the
 * assertion at the CUSTOMER realm and establishes the customer session via
 * AccountService::loginById (no password check — the passkey assertion IS
 * the credential). Both routes are pre-login (auth_required=false).
 */
#[Route(defaults: ['_routeScope' => ['store-api'], 'auth_required' => false])]
class PasskeyStoreApiController
{
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly AccountService $accountService,
    ) {
    }

    #[Route(path: '/store-api/act-passkey/challenge', name: 'store-api.act-passkey.challenge', methods: ['POST'])]
    public function challenge(Request $request, SalesChannelContext $context): JsonResponse
    {
        $result = $this->authenticationCeremony->createOptions(Realm::Customer, $request->getHost(), $context->getContext());

        return new JsonResponse(['options' => json_decode($result['options'], true), 'challengeId' => $result['challengeId']]);
    }

    #[Route(path: '/store-api/act-passkey/login', name: 'store-api.act-passkey.login', methods: ['POST'])]
    public function login(Request $request, RequestDataBag $data, SalesChannelContext $context): ContextTokenResponse
    {
        $response = $data->get('passkey_response');
        $challengeId = $data->get('passkey_challenge_id');
        if (!is_string($response) || $response === '' || !is_string($challengeId) || $challengeId === '') {
            throw new UnauthorizedHttpException('', 'Passkey authentication failed');
        }

        try {
            $customerId = $this->authenticationCeremony->verify(
                Realm::Customer,
                $response,
                $challengeId,
                $request->getHost(),
                $context->getContext()
            );
        } catch (\Throwable) {
            // Catch broadly, incl. Webauthn CounterException (does not extend the
            // verification exception in webauthn-lib 5.3.5) — never leak a 500 for
            // a failed authentication attempt.
            throw new UnauthorizedHttpException('', 'Passkey authentication failed');
        }

        $token = $this->accountService->loginById($customerId, $context);

        return new ContextTokenResponse($token);
    }
}
