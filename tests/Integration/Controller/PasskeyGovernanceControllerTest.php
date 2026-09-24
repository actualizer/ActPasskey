<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Controller;

use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\ApiException;
use Shopware\Core\Framework\Api\Exception\MissingPrivilegeException;
use Shopware\Core\Framework\Api\OAuth\Scope\UserVerifiedScope;
use Shopware\Core\Framework\Api\Util\AccessKeyHelper;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\KernelLifecycleManager;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Response;

/**
 * Operator revocation over real HTTP with real tokens: ACL-gated, delete only, a
 * password step-up for admin users only, and bounded by id + realm + the owner in the URL.
 *
 * @internal
 */
final class PasskeyGovernanceControllerTest extends TestCase
{
    use IntegrationTestBehaviour;

    private const PLAIN_PASSWORD = 'shopware';

    private const BASE = '/api/_action/act-passkey/governance';

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

    public function testFullAdminListsAnotherUsersPasskeysWithoutKeyMaterial(): void
    {
        $operator = $this->createUser();
        $owner = $this->createUser();
        $this->enroll(Realm::Admin, $owner['id'], 'Owner Key');

        $response = $this->apiRequest('POST', self::BASE . '/user/' . $owner['id'] . '/credentials', $this->token($operator, 'write'));

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertSame(['Owner Key'], array_column($data['credentials'], 'name'));
        self::assertSame(
            ['id', 'name', 'aaguid', 'transports', 'createdAt', 'lastUsedAt'],
            array_keys($data['credentials'][0])
        );
    }

    public function testFullAdminRevokesAnotherUsersPasskeyAfterStepUp(): void
    {
        $operator = $this->createUser();
        $owner = $this->createUser();
        $id = $this->enroll(Realm::Admin, $owner['id'], 'Owner Key');

        $response = $this->apiRequest(
            'DELETE',
            self::BASE . '/user/' . $owner['id'] . '/credentials/' . $id,
            $this->token($operator, 'user-verified')
        );

        self::assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode(), (string) $response->getContent());
        self::assertFalse($this->exists($id));
    }

    public function testUserRevokeWithoutStepUpIsRejected(): void
    {
        $operator = $this->createUser();
        $owner = $this->createUser();
        $id = $this->enroll(Realm::Admin, $owner['id'], 'Owner Key');

        $response = $this->apiRequest(
            'DELETE',
            self::BASE . '/user/' . $owner['id'] . '/credentials/' . $id,
            $this->token($operator, 'write')
        );

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertSame(ApiException::API_INVALID_SCOPE_ACCESS_TOKEN, $data['errors'][0]['code'] ?? null);
        self::assertStringContainsString(UserVerifiedScope::IDENTIFIER, (string) json_encode($data['errors'][0] ?? []));
        self::assertTrue($this->exists($id));
    }

    public function testFullAdminRevokesACustomerPasskeyWithoutStepUp(): void
    {
        $operator = $this->createUser();
        $customerId = $this->createCustomer();
        $id = $this->enroll(Realm::Customer, $customerId, 'Customer Key');

        $response = $this->apiRequest(
            'DELETE',
            self::BASE . '/customer/' . $customerId . '/credentials/' . $id,
            $this->token($operator, 'write')
        );

        self::assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode(), (string) $response->getContent());
        self::assertFalse($this->exists($id));
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function privilegedRouteProvider(): iterable
    {
        // [method, realm path segment, privilege the rejection must name]
        yield 'user list' => ['POST', 'user', 'act_passkey.revoke_user'];
        yield 'user revoke' => ['DELETE', 'user', 'act_passkey.revoke_user'];
        yield 'customer list' => ['POST', 'customer', 'act_passkey.revoke_customer'];
        yield 'customer revoke' => ['DELETE', 'customer', 'act_passkey.revoke_customer'];
    }

    #[DataProvider('privilegedRouteProvider')]
    public function testRestrictedRoleWithoutThePrivilegeIsRejected(string $method, string $realm, string $privilege): void
    {
        // Viewer rights on both account types, but not the revoke privilege.
        $operator = $this->createUser(['user:read', 'customer:read']);
        [$ownerId, $id] = $this->enrollFor($realm);
        $uri = self::BASE . '/' . $realm . '/' . $ownerId . '/credentials' . ($method === 'DELETE' ? '/' . $id : '');

        // user-verified, so a rejection on the user route cannot come from the step-up instead.
        $response = $this->apiRequest($method, $uri, $this->token($operator, 'user-verified'));

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertSame(MissingPrivilegeException::MISSING_PRIVILEGE_ERROR, $data['errors'][0]['code'] ?? null);
        self::assertStringContainsString($privilege, (string) json_encode($data['errors'][0] ?? []));
        self::assertTrue($this->exists($id));
    }

    public function testRestrictedRoleWithThePrivilegesMayRevoke(): void
    {
        $operator = $this->createUser([
            'user:read',
            'act_passkey.revoke_user',
            'customer:read',
            'act_passkey.revoke_customer',
        ]);
        $token = $this->token($operator, 'user-verified');
        [$userId, $userCredential] = $this->enrollFor('user');
        [$customerId, $customerCredential] = $this->enrollFor('customer');

        $userResponse = $this->apiRequest('DELETE', self::BASE . '/user/' . $userId . '/credentials/' . $userCredential, $token);
        $customerResponse = $this->apiRequest('DELETE', self::BASE . '/customer/' . $customerId . '/credentials/' . $customerCredential, $token);

        self::assertSame(Response::HTTP_NO_CONTENT, $userResponse->getStatusCode(), (string) $userResponse->getContent());
        self::assertSame(Response::HTTP_NO_CONTENT, $customerResponse->getStatusCode(), (string) $customerResponse->getContent());
        self::assertFalse($this->exists($userCredential));
        self::assertFalse($this->exists($customerCredential));
    }

    public function testIdsOutsideTheUrlOwnerOrRealmAreSilentNoOps(): void
    {
        $token = $this->token($this->createUser(), 'user-verified');
        $adminOwner = $this->createUser();
        $adminCredential = $this->enroll(Realm::Admin, $adminOwner['id'], 'Admin Key');
        $customerA = $this->createCustomer();
        $customerB = $this->createCustomer();
        $credentialOfB = $this->enroll(Realm::Customer, $customerB, 'B Key');

        $attempts = [
            // An admin credential through the customer route.
            self::BASE . '/customer/' . $customerA . '/credentials/' . $adminCredential,
            // A customer credential through the user route.
            self::BASE . '/user/' . $adminOwner['id'] . '/credentials/' . $credentialOfB,
            // Customer B's credential under customer A's URL.
            self::BASE . '/customer/' . $customerA . '/credentials/' . $credentialOfB,
        ];

        foreach ($attempts as $uri) {
            $response = $this->apiRequest('DELETE', $uri, $token);
            // Identical to a real deletion: no existence oracle across accounts or realms.
            self::assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode(), $uri);
        }

        self::assertTrue($this->exists($adminCredential));
        self::assertTrue($this->exists($credentialOfB));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function nonDeleteMethodProvider(): iterable
    {
        yield 'POST' => ['POST'];
        yield 'PUT' => ['PUT'];
        yield 'PATCH' => ['PATCH'];
    }

    #[DataProvider('nonDeleteMethodProvider')]
    public function testTheCredentialPathOffersNoWriteMethodBesidesDelete(string $method): void
    {
        $token = $this->token($this->createUser(), 'user-verified');
        $customerId = $this->createCustomer();
        $id = $this->enroll(Realm::Customer, $customerId, 'Key');

        $response = $this->apiRequest(
            $method,
            self::BASE . '/customer/' . $customerId . '/credentials/' . $id,
            $token,
            ['name' => 'Hijacked', 'passkey_response' => '{}']
        );

        // No route handles it: 405 (path known, method not) or 404 — never a 2xx.
        self::assertContains($response->getStatusCode(), [404, 405], (string) $response->getContent());
        $owned = $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext());
        self::assertSame(['Key'], array_values(array_map(static fn ($c) => $c->getName(), $owned->getElements())));
    }

    public function testIntegrationTokenIsRejected(): void
    {
        $customerId = $this->createCustomer();
        $id = $this->enroll(Realm::Customer, $customerId, 'Key');

        $response = $this->apiRequest(
            'DELETE',
            self::BASE . '/customer/' . $customerId . '/credentials/' . $id,
            $this->integrationToken()
        );

        // An admin integration passes every ACL check — only the actor check stops it.
        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), (string) $response->getContent());
        self::assertStringContainsString('user session', (string) $response->getContent());
        self::assertTrue($this->exists($id));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function listRouteProvider(): iterable
    {
        yield 'user list' => ['user'];
        yield 'customer list' => ['customer'];
    }

    #[DataProvider('listRouteProvider')]
    public function testIntegrationTokenIsRejectedOnTheListRoute(string $realm): void
    {
        // The actor check runs before anything else in list(), so the owner does not
        // need to exist for this to be the assertion that fails.
        $ownerId = Uuid::randomHex();

        $response = $this->apiRequest(
            'POST',
            self::BASE . '/' . $realm . '/' . $ownerId . '/credentials',
            $this->integrationToken()
        );

        // An admin integration passes every ACL check — only the actor check stops it.
        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), (string) $response->getContent());
        self::assertStringContainsString('user session', (string) $response->getContent());
    }

    public function testUnknownOwnerListsNothingAndRevokesNothing(): void
    {
        $token = $this->token($this->createUser(), 'write');
        $unknown = Uuid::randomHex();

        $list = $this->apiRequest('POST', self::BASE . '/customer/' . $unknown . '/credentials', $token);
        $revoke = $this->apiRequest('DELETE', self::BASE . '/customer/' . $unknown . '/credentials/' . Uuid::randomHex(), $token);

        self::assertSame(200, $list->getStatusCode(), (string) $list->getContent());
        self::assertSame(['credentials' => []], json_decode((string) $list->getContent(), true));
        self::assertSame(Response::HTTP_NO_CONTENT, $revoke->getStatusCode(), (string) $revoke->getContent());
    }

    public function testMalformedIdsDoNotRoute(): void
    {
        $token = $this->token($this->createUser(), 'write');

        $notAUuid = $this->apiRequest('DELETE', self::BASE . '/customer/not-a-uuid/credentials/' . Uuid::randomHex(), $token);
        $upperCase = $this->apiRequest('DELETE', self::BASE . '/customer/' . strtoupper(Uuid::randomHex()) . '/credentials/' . Uuid::randomHex(), $token);

        self::assertSame(404, $notAUuid->getStatusCode(), (string) $notAUuid->getContent());
        self::assertSame(404, $upperCase->getStatusCode(), (string) $upperCase->getContent());
    }

    private function credentials(): CredentialRepository
    {
        $service = $this->getContainer()->get(CredentialRepository::class);
        self::assertInstanceOf(CredentialRepository::class, $service);

        return $service;
    }

    private function exists(string $credentialId): bool
    {
        /** @var EntityRepository $repository */
        $repository = $this->getContainer()->get('act_passkey_credential.repository');

        return $repository->searchIds(new Criteria([$credentialId]), Context::createDefaultContext())->getTotal() > 0;
    }

    private function enroll(Realm $realm, string $accountId, string $name): string
    {
        $context = Context::createDefaultContext();
        $ceremony = $this->getContainer()->get(RegistrationCeremony::class);
        self::assertInstanceOf(RegistrationCeremony::class, $ceremony);

        $create = $ceremony->createOptions($realm, $accountId, $this->host, $context);
        $ceremony->verify(
            $realm,
            $accountId,
            SoftwareAuthenticator::respondToCreate($create['options'], $this->origin),
            $create['challengeId'],
            $this->host,
            $name,
            $context
        );

        foreach ($this->credentials()->listOwned($realm, $accountId, $context) as $credential) {
            if ($credential->getName() === $name) {
                return $credential->getId();
            }
        }

        self::fail('enrolled credential not found');
    }

    /**
     * @return array{0: string, 1: string} [owner id, credential id]
     */
    private function enrollFor(string $realm): array
    {
        if ($realm === 'user') {
            $owner = $this->createUser()['id'];

            return [$owner, $this->enroll(Realm::Admin, $owner, 'Owner Key')];
        }

        $owner = $this->createCustomer();

        return [$owner, $this->enroll(Realm::Customer, $owner, 'Owner Key')];
    }

    /**
     * @param array{id: string, username: string} $user
     */
    private function token(array $user, string $scope): string
    {
        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->setServerParameter('HTTP_AUTHORIZATION', '');
        $browser->request('POST', '/api/oauth/token', [
            'grant_type' => 'password',
            'client_id' => 'administration',
            'username' => $user['username'],
            'password' => self::PLAIN_PASSWORD,
            'scope' => $scope,
        ]);

        $response = $browser->getResponse();
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertIsString($data['access_token'] ?? null);

        return $data['access_token'];
    }

    private function integrationToken(): string
    {
        $accessKey = AccessKeyHelper::generateAccessKey('integration');
        $secret = AccessKeyHelper::generateSecretAccessKey();

        /** @var EntityRepository $integrationRepository */
        $integrationRepository = $this->getContainer()->get('integration.repository');
        // `admin` is write-protected outside the system scope.
        Context::createDefaultContext()->scope(
            Context::SYSTEM_SCOPE,
            static fn (Context $systemContext) => $integrationRepository->create([[
                'label' => 'Passkey governance test',
                'accessKey' => $accessKey,
                'secretAccessKey' => $secret,
                'admin' => true,
            ]], $systemContext)
        );

        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->setServerParameter('HTTP_AUTHORIZATION', '');
        $browser->request('POST', '/api/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $accessKey,
            'client_secret' => $secret,
        ]);

        $response = $browser->getResponse();
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertIsString($data['access_token'] ?? null);

        return $data['access_token'];
    }

    /**
     * @param array<string, mixed> $params
     */
    private function apiRequest(string $method, string $uri, string $token, array $params = []): Response
    {
        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->setServerParameter('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $browser->request($method, $uri, $params);

        return $browser->getResponse();
    }

    /**
     * A full administrator when `$privileges` is null, otherwise a restricted user
     * (`admin = false`) whose only role grants exactly `$privileges`.
     *
     * @param list<string>|null $privileges
     *
     * @return array{id: string, username: string}
     */
    private function createUser(?array $privileges = null): array
    {
        /** @var EntityRepository $userRepository */
        $userRepository = $this->getContainer()->get('user.repository');

        $userId = Uuid::randomHex();
        $username = 'governance-' . Uuid::randomHex();
        $user = [
            'id' => $userId,
            'localeId' => $this->getLocaleIdOfSystemLanguage(),
            'username' => $username,
            'password' => TestDefaults::HASHED_PASSWORD,
            'firstName' => 'Max',
            'lastName' => 'Mustermann',
            'email' => Uuid::randomHex() . '@example.test',
            'admin' => $privileges === null,
        ];
        if ($privileges !== null) {
            $user['aclRoles'] = [[
                'id' => Uuid::randomHex(),
                'name' => 'governance-role-' . Uuid::randomHex(),
                'privileges' => $privileges,
            ]];
        }

        $userRepository->create([$user], Context::createDefaultContext());

        return ['id' => $userId, 'username' => $username];
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
}
