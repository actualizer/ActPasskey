<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Admin;

use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\RateLimiter\Exception\RateLimitExceededException;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Admin passkey self-service. Every route derives ownership from the access
 * token (AdminApiSource::getUserId()), never from the request body — combined
 * with CredentialRepository's id+realm+owner filter this is the IDOR defense.
 *
 * Mutations additionally require the `user-verified` scope (fresh password
 * confirmation), mirroring core's UserController::validateScope(). Listing is
 * deliberately NOT gated: it only reads the caller's own rows and carries no
 * secrets, and gating it would force a password prompt just to render the
 * overview a passkey-logged-in admin needs in order to reach the step-up.
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class PasskeyAdminManageController
{
    public function __construct(
        private readonly RegistrationCeremony $registrationCeremony,
        private readonly CredentialRepository $credentials,
        private readonly RateLimiter $rateLimiter,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route(
        path: '/api/_action/act-passkey/admin/credentials',
        name: 'api.action.act_passkey.admin.credentials.list',
        methods: ['POST'],
    )]
    public function list(Context $context): JsonResponse
    {
        $userId = $this->userId($context);

        return new JsonResponse([
            'credentials' => CredentialListPayload::fromCollection(
                $this->credentials->listOwned(Realm::Admin, $userId, $context)
            ),
        ]);
    }

    #[Route(
        path: '/api/_action/act-passkey/admin/register-challenge',
        name: 'api.action.act_passkey.admin.register_challenge',
        methods: ['POST'],
    )]
    public function registerChallenge(Request $request, Context $context): JsonResponse
    {
        UserVerifiedScopeGuard::assert($request);
        $userId = $this->userId($context);

        try {
            $result = $this->registrationCeremony->createOptions(
                Realm::Admin,
                $userId,
                $request->getHost(),
                $context,
                $this->displayName($request),
                $this->userName($request),
            );
        } catch (UnsupportedHostException) {
            return new JsonResponse(['error' => 'unsupported_host'], Response::HTTP_BAD_REQUEST);
        }

        return new JsonResponse([
            'options' => json_decode($result['options'], true),
            'challengeId' => $result['challengeId'],
        ]);
    }

    #[Route(
        path: '/api/_action/act-passkey/admin/register',
        name: 'api.action.act_passkey.admin.register',
        methods: ['POST'],
    )]
    public function register(Request $request, Context $context): Response
    {
        UserVerifiedScopeGuard::assert($request);
        $userId = $this->userId($context);
        $rateLimitKey = $userId . '-' . (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_register', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        $response = $request->request->get('passkey_response');
        $challengeId = $request->request->get('passkey_challenge_id');
        $name = $request->request->get('name');
        if (!is_string($response) || $response === '' || !is_string($challengeId) || $challengeId === '') {
            throw new AccessDeniedHttpException('Passkey registration failed');
        }

        // displayName/userName only label the credential in the browser's
        // passkey manager; they are not part of what the assertion signs, so
        // they cannot affect whether verification succeeds.
        try {
            $this->registrationCeremony->verify(
                Realm::Admin,
                $userId,
                $response,
                $challengeId,
                $request->getHost(),
                is_string($name) && $name !== '' ? $name : 'Passkey',
                $context,
                $this->displayName($request),
                $this->userName($request),
            );
        } catch (\Throwable $exception) {
            // \Throwable, not the library's verification exception: webauthn-lib's
            // CounterException does not extend it, so a narrower catch would leak a 500.
            // WARNING: enrollment runs after a password step-up, so a failure here is
            // unexpected rather than routine login noise.
            $this->logger->warning('Passkey admin enrollment failed', ['exception' => $exception]);
            throw new AccessDeniedHttpException('Passkey registration failed', $exception);
        }

        // reset() is correct here (unlike delete): verify() throws on every failure
        // path, so this line is only reached after a genuinely successful enrollment.
        $this->rateLimiter->reset('act_passkey_register', $rateLimitKey);

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    #[Route(
        path: '/api/_action/act-passkey/admin/credentials/{id}',
        name: 'api.action.act_passkey.admin.credentials.rename',
        methods: ['PATCH'],
        requirements: ['id' => '[0-9a-f]{32}'],
    )]
    public function rename(string $id, Request $request, Context $context): Response
    {
        UserVerifiedScopeGuard::assert($request);
        $name = $request->request->get('name');
        if (!is_string($name) || $name === '') {
            throw new AccessDeniedHttpException('Passkey rename failed');
        }

        // Return value intentionally ignored: "not yours" and "does not exist"
        // must be indistinguishable to the caller.
        $this->credentials->renameOwned($id, Realm::Admin, $this->userId($context), $name, $context);

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    #[Route(
        path: '/api/_action/act-passkey/admin/credentials/{id}',
        name: 'api.action.act_passkey.admin.credentials.delete',
        methods: ['DELETE'],
        requirements: ['id' => '[0-9a-f]{32}'],
    )]
    public function delete(string $id, Request $request, Context $context): Response
    {
        UserVerifiedScopeGuard::assert($request);
        $userId = $this->userId($context);
        $rateLimitKey = $userId . '-' . (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_delete', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        // Same as rename: no existence oracle, so the result is not surfaced.
        $this->credentials->deleteOwned($id, Realm::Admin, $userId, $context);

        // Deliberately NO reset() here, unlike register(): deleteOwned() has no
        // throwing path (foreign/missing rows both just return false), so a reset
        // would run unconditionally on every call and the bucket could never
        // accumulate — the throttle against mass-revocation would be inert. Let
        // it decay on its configured interval instead.

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    private function userId(Context $context): string
    {
        $source = $context->getSource();
        if (!$source instanceof AdminApiSource) {
            throw new AccessDeniedHttpException('Passkey self-service requires an admin session.');
        }

        $userId = $source->getUserId();
        if ($userId === null || $userId === '') {
            // Integration (app/system) tokens have no user — they own no passkeys.
            throw new AccessDeniedHttpException('Passkey self-service requires a user session.');
        }

        return $userId;
    }

    private function displayName(Request $request): string
    {
        $value = $request->request->get('displayName');

        return is_string($value) ? $value : '';
    }

    private function userName(Request $request): string
    {
        $value = $request->request->get('userName');

        return is_string($value) ? $value : '';
    }
}
