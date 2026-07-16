<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\OAuth;

use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\KernelLifecycleManager;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;

/**
 * End-to-end proof of Phase 2: a public admin challenge route hands out a
 * WebAuthn assertion challenge, and the real `/api/oauth/token` endpoint
 * accepts `grant_type=passkey` for a registered admin passkey, issuing a
 * genuine admin access token.
 */
final class AdminPasskeyLoginFlowTest extends TestCase
{
    use IntegrationTestBehaviour;

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        // In APP_ENV=test, %APP_URL% = http://127.0.0.1:8000 (host 127.0.0.1).
        $appUrl = (string) $this->getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    public function testPasskeyGrantIssuesValidAdminToken(): void
    {
        $ctx = Context::createDefaultContext();
        $adminUserId = $this->createAdminUser();

        // register an admin passkey (Phase-1 ceremony + software authenticator)
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $create = $reg->createOptions(Realm::Admin, $adminUserId, $this->host, $ctx);
        $reg->verify(
            Realm::Admin,
            $adminUserId,
            SoftwareAuthenticator::respondToCreate($create['options'], $this->origin),
            $create['challengeId'],
            $this->host,
            'Test Key',
            $ctx
        );

        // issue a login challenge + build the assertion
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        // POST to the real token endpoint with grant_type=passkey via an
        // UNauthenticated browser. HTTP_HOST must line up with the rpId
        // ('127.0.0.1') resolved at registration time, since the grant
        // derives its host from $request->getUri()->getHost().
        $response = $this->requestToken([
            'grant_type' => 'passkey',
            'client_id' => 'administration',
            'scope' => 'write',
            'passkey_response' => $assertion,
            'passkey_challenge_id' => $req['challengeId'],
        ]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertArrayHasKey('access_token', $data);
        self::assertNotEmpty($data['access_token']);
    }

    public function testLoginChallengeRouteReturnsOptionsAndChallengeId(): void
    {
        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->request('POST', '/api/_action/act-passkey/admin/login-challenge');

        $response = $browser->getResponse();
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertArrayHasKey('options', $data);
        self::assertArrayHasKey('challengeId', $data);
        self::assertNotEmpty($data['challengeId']);
    }

    public function testBogusChallengeIdIsRejected(): void
    {
        $ctx = Context::createDefaultContext();
        $adminUserId = $this->createAdminUser();

        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $create = $reg->createOptions(Realm::Admin, $adminUserId, $this->host, $ctx);
        $reg->verify(
            Realm::Admin,
            $adminUserId,
            SoftwareAuthenticator::respondToCreate($create['options'], $this->origin),
            $create['challengeId'],
            $this->host,
            'Test Key',
            $ctx
        );

        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        $response = $this->requestToken([
            'grant_type' => 'passkey',
            'client_id' => 'administration',
            'scope' => 'write',
            'passkey_response' => $assertion,
            'passkey_challenge_id' => Uuid::randomHex(),
        ]);

        $this->assertInvalidGrant($response);
    }

    public function testCustomerCredentialRejectedAtAdminTokenEndpoint(): void
    {
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer();

        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $create = $reg->createOptions(Realm::Customer, $customerId, $this->host, $ctx);
        $reg->verify(
            Realm::Customer,
            $customerId,
            SoftwareAuthenticator::respondToCreate($create['options'], $this->origin),
            $create['challengeId'],
            $this->host,
            'Test Key',
            $ctx
        );

        // The login challenge is still requested at the ADMIN realm — a
        // customer credential must not resolve there (realm boundary).
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        $response = $this->requestToken([
            'grant_type' => 'passkey',
            'client_id' => 'administration',
            'scope' => 'write',
            'passkey_response' => $assertion,
            'passkey_challenge_id' => $req['challengeId'],
        ]);

        $this->assertInvalidGrant($response);
    }

    /**
     * Shopware's ErrorResponseFactory converts OAuthServerException into its own
     * JSON:API-style `errors[]` envelope (not the raw OAuth2 `{error: "..."}`
     * shape), so assert on the wrapped `code` (OAuthServerException::invalidGrant()
     * uses code 10) rather than a top-level `error` key.
     */
    private function assertInvalidGrant(\Symfony\Component\HttpFoundation\Response $response): void
    {
        self::assertSame(400, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertSame('10', $data['errors'][0]['code'] ?? null, (string) $response->getContent());
    }

    /**
     * @param array<string, mixed> $params
     */
    private function requestToken(array $params): \Symfony\Component\HttpFoundation\Response
    {
        $kernel = KernelLifecycleManager::getKernel();
        $browser = KernelLifecycleManager::createBrowser($kernel);
        // Align HTTP_HOST with the rpId ('127.0.0.1') resolved at registration
        // time — the grant reads $request->getUri()->getHost(), and a mismatch
        // (e.g. default 'localhost') would fail the rpIdHash check.
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->request('POST', '/api/oauth/token', $params);

        return $browser->getResponse();
    }

    /**
     * `customer_id` has a real FK to `customer`, so owner ids must be real rows.
     */
    private function createCustomer(): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();

        /** @var EntityRepository $customerRepository */
        $customerRepository = $this->getContainer()->get('customer.repository');
        $customerRepository->create([[
            'id' => $customerId,
            'salesChannelId' => TestDefaults::SALES_CHANNEL,
            'defaultShippingAddress' => [
                'id' => $addressId,
                'firstName' => 'Max',
                'lastName' => 'Mustermann',
                'street' => 'Musterstraße 1',
                'city' => 'Schöppingen',
                'zipcode' => '12345',
                'salutationId' => $this->getValidSalutationId(),
                'countryId' => $this->getValidCountryId(),
            ],
            'defaultBillingAddressId' => $addressId,
            'groupId' => TestDefaults::FALLBACK_CUSTOMER_GROUP,
            'email' => Uuid::randomHex() . '@example.test',
            'password' => TestDefaults::HASHED_PASSWORD,
            'firstName' => 'Max',
            'lastName' => 'Mustermann',
            'salutationId' => $this->getValidSalutationId(),
            'customerNumber' => Uuid::randomHex(),
        ]], Context::createDefaultContext());

        return $customerId;
    }

    /**
     * `user_id` has a real FK to `user`, so owner ids must be real rows.
     */
    private function createAdminUser(): string
    {
        /** @var EntityRepository $userRepository */
        $userRepository = $this->getContainer()->get('user.repository');

        // The default admin user always exists (see task brief) — reuse it
        // rather than creating another one where not needed for isolation.
        $userId = Uuid::randomHex();
        $userRepository->create([[
            'id' => $userId,
            'localeId' => $this->getLocaleIdOfSystemLanguage(),
            'username' => Uuid::randomHex(),
            'password' => TestDefaults::HASHED_PASSWORD,
            'firstName' => 'Max',
            'lastName' => 'Mustermann',
            'email' => Uuid::randomHex() . '@example.test',
            'admin' => true,
        ]], Context::createDefaultContext());

        return $userId;
    }
}
