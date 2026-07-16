<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Admin;

use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Shopware\Core\Framework\Context;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Public (unauthenticated) admin login-challenge endpoint: hands out a
 * usernameless WebAuthn request-options payload + challengeId for the
 * `grant_type=passkey` OAuth grant (see PasskeyGrant).
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class PasskeyAdminChallengeController
{
    public function __construct(private readonly AuthenticationCeremony $authenticationCeremony)
    {
    }

    #[Route(
        path: '/api/_action/act-passkey/admin/login-challenge',
        name: 'api.action.act_passkey.admin.login_challenge',
        defaults: ['auth_required' => false],
        methods: ['POST'],
    )]
    public function loginChallenge(Request $request, Context $context): JsonResponse
    {
        $host = $request->getHost();
        $result = $this->authenticationCeremony->createOptions(Realm::Admin, $host, $context);

        return new JsonResponse([
            'options' => json_decode($result['options'], true),
            'challengeId' => $result['challengeId'],
        ]);
    }
}
