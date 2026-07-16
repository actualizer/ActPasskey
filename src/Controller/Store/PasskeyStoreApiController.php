<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Store;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerPasskeyLoginService;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Store-api passkey login: hands out a usernameless challenge and verifies the
 * assertion at the CUSTOMER realm via CustomerPasskeyLoginService. No password
 * check is involved, but eligibility still is — the service guards it before
 * opening a session. Both routes are pre-login (auth_required=false).
 */
#[Route(defaults: ['_routeScope' => ['store-api'], 'auth_required' => false])]
class PasskeyStoreApiController
{
    public function __construct(
        private readonly AuthenticationCeremony $authenticationCeremony,
        private readonly CustomerPasskeyLoginService $loginService,
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

        $token = $this->loginService->login($response, $challengeId, $request->getHost(), $context);

        return new ContextTokenResponse($token);
    }
}
