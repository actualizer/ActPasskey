<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Store;

use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerEligibilityGuard;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\Validation\Constraint\CustomerPasswordMatches;
use Shopware\Core\Framework\RateLimiter\Exception\RateLimitExceededException;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\Framework\Validation\DataValidationDefinition;
use Shopware\Core\Framework\Validation\DataValidator;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Validator\Constraints\NotBlank;

/**
 * Customer passkey self-service. `_loginRequired` + the CustomerEntity parameter
 * are self-enforcing (CustomerValueResolver rejects the route outright if the
 * attribute is ever dropped, and SalesChannelRequestContextResolver::validateLogin()
 * rejects both an anonymous session and — because `_loginRequiredAllowGuest` is
 * deliberately NOT set — a guest one). assertEligible() additionally re-applies the
 * active/double-opt-in checks that AccountService::loginById() skips, so a passkey
 * can never be enrolled by an account that may not log in with a password.
 *
 * Ownership always comes from the session customer, never from the request — that,
 * combined with CredentialRepository's id + realm + owner filter, is the IDOR defense.
 *
 * Password step-up (CustomerPasswordMatches, the same constraint core's
 * ChangePasswordRoute uses) guards every route that adds or removes an
 * authentication factor: register-challenge, register and delete. Listing and
 * renaming stay step-up free — a label change is not an auth-factor change, and
 * gating the list would force a password prompt just to render the overview.
 */
#[Route(defaults: [
    '_routeScope' => ['store-api'],
    PlatformRequest::ATTRIBUTE_CONTEXT_TOKEN_REQUIRED => true,
])]
class PasskeyManageStoreApiController
{
    public function __construct(
        private readonly RegistrationCeremony $registrationCeremony,
        private readonly CredentialRepository $credentials,
        private readonly CustomerEligibilityGuard $guard,
        private readonly DataValidator $validator,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    #[Route(
        path: '/store-api/act-passkey/credentials',
        name: 'store-api.act-passkey.credentials.list',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['POST'],
    )]
    public function list(SalesChannelContext $context, CustomerEntity $customer): JsonResponse
    {
        $this->guard->assertEligible($customer);

        $credentials = [];
        foreach ($this->credentials->listOwned(Realm::Customer, $customer->getId(), $context->getContext()) as $credential) {
            $credentials[] = [
                'id' => $credential->getId(),
                'name' => $credential->getName(),
                'aaguid' => $credential->getAaguid(),
                'transports' => $credential->getTransports(),
                'createdAt' => $credential->getCreatedAt()?->format(\DATE_ATOM),
                'lastUsedAt' => $credential->getLastUsedAt()?->format(\DATE_ATOM),
            ];
        }

        return new JsonResponse(['credentials' => $credentials]);
    }

    #[Route(
        path: '/store-api/act-passkey/register-challenge',
        name: 'store-api.act-passkey.register_challenge',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['POST'],
    )]
    public function registerChallenge(
        Request $request,
        RequestDataBag $data,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): JsonResponse {
        $this->guard->assertEligible($customer);

        // ensureAccepted() before validatePassword(): see register() for why the
        // password check must never run unthrottled.
        $rateLimitKey = $customer->getId() . '-' . (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_register', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        $this->validatePassword($data, $context);

        // Deliberately NO reset() here, unlike register(): createOptions() has no
        // throwing failure path (UnsupportedHostException aside, which is not an
        // auth-oracle result), so a reset would run unconditionally on every call
        // and the bucket could never accumulate — the throttle would be inert.
        try {
            $result = $this->registrationCeremony->createOptions(
                Realm::Customer,
                $customer->getId(),
                $request->getHost(),
                $context->getContext(),
                $this->displayNameFor($customer),
                (string) $customer->getEmail(),
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
        path: '/store-api/act-passkey/register',
        name: 'store-api.act-passkey.register',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['POST'],
    )]
    public function register(
        Request $request,
        RequestDataBag $data,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): Response {
        $this->guard->assertEligible($customer);

        // ensureAccepted() before validatePassword(): the password check is a
        // pass/fail oracle, so it must be rate-limited before it runs, not after —
        // otherwise a hijacked context token lets an attacker guess the account
        // password with no throttle at all.
        $rateLimitKey = $customer->getId() . '-' . (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_register', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        $this->validatePassword($data, $context);

        $response = $data->get('passkey_response');
        $challengeId = $data->get('passkey_challenge_id');
        $name = $data->get('name');
        if (!is_string($response) || $response === '' || !is_string($challengeId) || $challengeId === '') {
            throw new AccessDeniedHttpException('Passkey registration failed');
        }

        // displayName/userName are derived server-side and are purely cosmetic (the
        // label the browser's passkey manager shows). They are NOT part of what the
        // authenticator signs, so they are never accepted from the request body.
        try {
            $this->registrationCeremony->verify(
                Realm::Customer,
                $customer->getId(),
                $response,
                $challengeId,
                $request->getHost(),
                is_string($name) && $name !== '' ? $name : 'Passkey',
                $context->getContext(),
                $this->displayNameFor($customer),
                (string) $customer->getEmail(),
            );
        } catch (\Throwable $exception) {
            // \Throwable, not the library's verification exception: webauthn-lib's
            // CounterException does not extend it, so a narrower catch would leak a 500.
            throw new AccessDeniedHttpException('Passkey registration failed', $exception);
        }

        // reset() is correct here (unlike delete): verify() throws on every failure
        // path, so this line is only reached after a genuinely successful enrollment.
        $this->rateLimiter->reset('act_passkey_register', $rateLimitKey);

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    #[Route(
        path: '/store-api/act-passkey/credentials/{id}',
        name: 'store-api.act-passkey.credentials.rename',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['PATCH'],
        requirements: ['id' => '[0-9a-f]{32}'],
    )]
    public function rename(
        string $id,
        RequestDataBag $data,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): Response {
        $this->guard->assertEligible($customer);

        $name = $data->get('name');
        if (!is_string($name) || $name === '') {
            throw new AccessDeniedHttpException('Passkey rename failed');
        }

        // Return value intentionally ignored: "not yours" and "does not exist"
        // must be indistinguishable to the caller.
        $this->credentials->renameOwned($id, Realm::Customer, $customer->getId(), $name, $context->getContext());

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    #[Route(
        path: '/store-api/act-passkey/credentials/{id}',
        name: 'store-api.act-passkey.credentials.delete',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true],
        methods: ['DELETE'],
        requirements: ['id' => '[0-9a-f]{32}'],
    )]
    public function delete(
        string $id,
        Request $request,
        RequestDataBag $data,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): Response {
        $this->guard->assertEligible($customer);

        // ensureAccepted() before validatePassword(): see register() for why the
        // password check must never run unthrottled.
        $rateLimitKey = $customer->getId() . '-' . (string) $request->getClientIp();

        try {
            $this->rateLimiter->ensureAccepted('act_passkey_delete', $rateLimitKey);
        } catch (RateLimitExceededException $exception) {
            throw new TooManyRequestsHttpException($exception->getWaitTime(), '', $exception);
        }

        $this->validatePassword($data, $context);

        // Same as rename: no existence oracle, so the result is not surfaced.
        $this->credentials->deleteOwned($id, Realm::Customer, $customer->getId(), $context->getContext());

        // Deliberately NO reset() here, unlike register(): deleteOwned() has no
        // throwing path (foreign/missing rows both just return false), so a reset
        // would run unconditionally on every call and the bucket could never
        // accumulate — the throttle against mass-revocation would be inert. Let
        // it decay on its configured interval instead.

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    /**
     * Same contract as core's ChangePasswordRoute::validatePasswordFields(): an
     * authentication factor may only be added or removed after a fresh password
     * confirmation. Never hand-roll the comparison — CustomerPasswordMatches goes
     * through AccountService and keeps the account checks in one place.
     */
    private function validatePassword(RequestDataBag $data, SalesChannelContext $context): void
    {
        $definition = new DataValidationDefinition('act_passkey.step_up');
        $definition->add('password', new NotBlank(), new CustomerPasswordMatches(salesChannelContext: $context));

        $this->validator->validate(['password' => $data->get('password')], $definition);
    }

    private function displayNameFor(CustomerEntity $customer): string
    {
        // The `?? ''` guards stay: they are belt-and-braces against a future
        // signature change to `?string` (the getters are currently natively typed
        // `string`, so PHPStan sees the coalesce as dead code today, hence the
        // ignore), and this value is only a cosmetic label — it must never be the
        // reason a request blows up.
        /** @phpstan-ignore nullCoalesce.expr, nullCoalesce.expr */
        return trim(($customer->getFirstName() ?? '') . ' ' . ($customer->getLastName() ?? ''));
    }
}
