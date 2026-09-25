<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Admin;

use Actualize\Passkey\Controller\CredentialListPayload;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\RateLimiter\Exception\RateLimitExceededException;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Operator revocation of OTHER accounts' passkeys. Delete only: there is deliberately no
 * route that creates or renames a credential for someone else — enrollment stays
 * self-service, and the entity's write protection keeps the generic API closed as well.
 *
 * The owner comes from the URL here, since the operator acts on someone else's account.
 * CredentialRepository's id + realm + owner filter is therefore what keeps the customer
 * routes from touching an admin credential and vice versa.
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class PasskeyGovernanceController
{
    private const HEX_ID = '[0-9a-f]{32}';

    public function __construct(
        private readonly CredentialRepository $credentials,
        private readonly RateLimiter $rateLimiter,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route(
        path: '/api/_action/act-passkey/governance/user/{userId}/credentials',
        name: 'api.action.act_passkey.governance.user.list',
        defaults: ['_acl' => ['user:read', 'act_passkey.revoke_user']],
        requirements: ['userId' => self::HEX_ID],
        methods: ['POST'],
    )]
    public function listUser(string $userId, Context $context): JsonResponse
    {
        return $this->list(Realm::Admin, $userId, $context);
    }

    #[Route(
        path: '/api/_action/act-passkey/governance/user/{userId}/credentials/{id}',
        name: 'api.action.act_passkey.governance.user.revoke',
        defaults: ['_acl' => ['user:read', 'act_passkey.revoke_user']],
        requirements: ['userId' => self::HEX_ID, 'id' => self::HEX_ID],
        methods: ['DELETE'],
    )]
    public function revokeUser(string $userId, string $id, Request $request, Context $context): Response
    {
        // Core demands a fresh password confirmation for every change in Users &
        // permissions; removing another admin's authentication factor is no less.
        UserVerifiedScopeGuard::assert($request);

        return $this->revoke(Realm::Admin, $userId, $id, $request, $context);
    }

    #[Route(
        path: '/api/_action/act-passkey/governance/customer/{customerId}/credentials',
        name: 'api.action.act_passkey.governance.customer.list',
        defaults: ['_acl' => ['customer:read', 'act_passkey.revoke_customer']],
        requirements: ['customerId' => self::HEX_ID],
        methods: ['POST'],
    )]
    public function listCustomer(string $customerId, Context $context): JsonResponse
    {
        return $this->list(Realm::Customer, $customerId, $context);
    }

    #[Route(
        path: '/api/_action/act-passkey/governance/customer/{customerId}/credentials/{id}',
        name: 'api.action.act_passkey.governance.customer.revoke',
        defaults: ['_acl' => ['customer:read', 'act_passkey.revoke_customer']],
        requirements: ['customerId' => self::HEX_ID, 'id' => self::HEX_ID],
        methods: ['DELETE'],
    )]
    public function revokeCustomer(string $customerId, string $id, Request $request, Context $context): Response
    {
        // No step-up: core edits customers in the administration without one either.
        return $this->revoke(Realm::Customer, $customerId, $id, $request, $context);
    }

    private function list(Realm $realm, string $ownerId, Context $context): JsonResponse
    {
        $this->actorId($context);

        // No rp id filter: an operator must see every credential that can still authenticate.
        return new JsonResponse([
            'credentials' => CredentialListPayload::fromCollection(
                $this->credentials->listOwned($realm, $ownerId, $context)
            ),
        ]);
    }

    private function revoke(Realm $realm, string $ownerId, string $id, Request $request, Context $context): Response
    {
        $actorId = $this->actorId($context);
        $rateLimitKey = $actorId . '-' . (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_delete', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        // No reset() on success: deleteOwned() has no throwing path, so a reset would run
        // on every call and the bucket could never fill — the throttle would be inert.
        if ($this->credentials->deleteOwned($id, $realm, $ownerId, $context)) {
            // WARNING, not NOTICE: this is the audit record of an operator removing someone
            // else's authentication factor, so it must survive a production log level.
            $this->logger->warning('Passkey revoked by operator', [
                'actorUserId' => $actorId,
                'realm' => $realm->value,
                'ownerId' => $ownerId,
                'credentialId' => $id,
            ]);
        }

        // Always 204: "not this owner", "other realm" and "does not exist" look the same.
        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    /**
     * An admin integration passes every ACL check, so the actor must be checked on its
     * own: only a real user may revoke, and the audit record needs who it was.
     */
    private function actorId(Context $context): string
    {
        return AdminActor::userId($context, 'Passkey governance');
    }
}
