<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Controller;

use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\ApiException;
use Shopware\Core\Framework\Api\OAuth\Scope\UserVerifiedScope;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\RateLimiter\DisableRateLimiterCompilerPass;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\KernelLifecycleManager;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Response;

/**
 * Proves the admin self-service API: ownership is derived from the access token
 * (never from the body), foreign rows are untouchable and indistinguishable from
 * missing ones, and every mutation demands the `user-verified` scope.
 *
 * @internal
 */
final class PasskeyAdminManageControllerTest extends TestCase
{
    use IntegrationTestBehaviour;

    private const PLAIN_PASSWORD = 'shopware';

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

    public function testListReturnsOnlyOwnCredentials(): void
    {
        $userA = $this->createAdminUser();
        $userB = $this->createAdminUser();

        $credentialA = $this->enrollPasskey($userA['id'], 'A Key');
        $this->enrollPasskey($userB['id'], 'B Key');

        $response = $this->apiRequest(
            'POST',
            '/api/_action/act-passkey/admin/credentials',
            $this->token($userA, 'write')
        );

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertIsArray($data['credentials'] ?? null);
        self::assertCount(1, $data['credentials']);
        self::assertSame($credentialA, $data['credentials'][0]['id']);
        self::assertSame('A Key', $data['credentials'][0]['name']);
    }

    protected function tearDown(): void
    {
        DisableRateLimiterCompilerPass::enableNoLimit();
    }

    /**
     * The administration can only name the wait time if the 429 carries it. The API's
     * error envelope drops response headers, so it has to be core's own exception,
     * whose body states the seconds.
     */
    public function testThrottledDeleteAnswers429WithTheWaitTime(): void
    {
        $user = $this->createAdminUser();
        $token = $this->token($user, 'user-verified');
        DisableRateLimiterCompilerPass::disableNoLimit();

        for ($i = 1; $i <= 5; ++$i) {
            $response = $this->apiRequest('DELETE', '/api/_action/act-passkey/admin/credentials/' . Uuid::randomHex(), $token);
            self::assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode(), (string) $response->getContent());
        }

        $response = $this->apiRequest('DELETE', '/api/_action/act-passkey/admin/credentials/' . Uuid::randomHex(), $token);

        self::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        $seconds = $data['errors'][0]['meta']['parameters']['seconds'] ?? null;
        self::assertIsInt($seconds, (string) $response->getContent());
        self::assertGreaterThan(0, $seconds);
    }

    /**
     * Every register challenge writes a cache entry, and the route has no password of its
     * own to throttle (its step-up is the token scope). It therefore shares the challenge
     * bucket with the customer route, keyed by user and IP: a flood is capped, and another
     * administrator behind the same address is not affected.
     */
    public function testRegisterChallengeIsThrottledPerUser(): void
    {
        $user = $this->createAdminUser();
        $other = $this->createAdminUser();
        // Tokens first: minting one runs through core's own oauth limiter.
        $token = $this->token($user, 'user-verified');
        $otherToken = $this->token($other, 'user-verified');
        $limit = $this->challengeLimit();
        DisableRateLimiterCompilerPass::disableNoLimit();

        for ($i = 1; $i <= $limit; ++$i) {
            $response = $this->apiRequest('POST', '/api/_action/act-passkey/admin/register-challenge', $token);
            self::assertSame(Response::HTTP_OK, $response->getStatusCode(), "attempt {$i}: " . $response->getContent());
        }

        $response = $this->apiRequest('POST', '/api/_action/act-passkey/admin/register-challenge', $token);

        self::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        $seconds = $data['errors'][0]['meta']['parameters']['seconds'] ?? null;
        self::assertIsInt($seconds, (string) $response->getContent());
        self::assertGreaterThan(0, $seconds);

        $response = $this->apiRequest('POST', '/api/_action/act-passkey/admin/register-challenge', $otherToken);
        self::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
    }

    public function testListShowsWhenAPasskeyMayBeCloned(): void
    {
        $user = $this->createAdminUser();
        $credential = $this->enrollPasskey($user['id'], 'Copied Key');
        $detectedAt = new \DateTimeImmutable('2026-09-27T10:00:00+00:00');
        $this->credentials()->markPossiblyCloned($credential, Context::createDefaultContext(), $detectedAt);

        $response = $this->apiRequest('POST', '/api/_action/act-passkey/admin/credentials', $this->token($user, 'write'));

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        $stamp = $data['credentials'][0]['cloneWarningAt'] ?? null;
        self::assertIsString($stamp, (string) $response->getContent());
        self::assertSame($detectedAt->getTimestamp(), (new \DateTimeImmutable($stamp))->getTimestamp());
    }

    public function testRegisterPersistsTheCredentialForTheTokenOwner(): void
    {
        $userA = $this->createAdminUser();
        $token = $this->token($userA, 'user-verified');

        $challengeResponse = $this->apiRequest(
            'POST',
            '/api/_action/act-passkey/admin/register-challenge',
            $token
        );
        self::assertSame(200, $challengeResponse->getStatusCode(), (string) $challengeResponse->getContent());

        $challenge = json_decode((string) $challengeResponse->getContent(), true);
        self::assertIsArray($challenge);
        self::assertIsArray($challenge['options'] ?? null);
        self::assertNotEmpty($challenge['challengeId'] ?? null);

        $attestation = SoftwareAuthenticator::respondToCreate(
            (string) json_encode($challenge['options']),
            $this->origin
        );

        $registerResponse = $this->apiRequest(
            'POST',
            '/api/_action/act-passkey/admin/register',
            $token,
            [
                'passkey_response' => $attestation,
                'passkey_challenge_id' => $challenge['challengeId'],
                'name' => 'My Laptop',
            ]
        );

        self::assertSame(
            Response::HTTP_NO_CONTENT,
            $registerResponse->getStatusCode(),
            (string) $registerResponse->getContent()
        );

        $owned = $this->credentials()->listOwned(Realm::Admin, $userA['id'], Context::createDefaultContext());
        self::assertCount(1, $owned);
        self::assertSame('My Laptop', $owned->first()?->getName());
    }

    public function testDeleteOfAForeignCredentialIsANoOp(): void
    {
        $userA = $this->createAdminUser();
        $userB = $this->createAdminUser();
        $credentialB = $this->enrollPasskey($userB['id'], 'B Key');

        $token = $this->token($userA, 'user-verified');

        $foreign = $this->apiRequest('DELETE', '/api/_action/act-passkey/admin/credentials/' . $credentialB, $token);
        $missing = $this->apiRequest('DELETE', '/api/_action/act-passkey/admin/credentials/' . Uuid::randomHex(), $token);

        // No existence oracle: "not yours" and "does not exist" must look identical.
        self::assertSame(Response::HTTP_NO_CONTENT, $foreign->getStatusCode(), (string) $foreign->getContent());
        self::assertSame($missing->getStatusCode(), $foreign->getStatusCode());
        self::assertSame((string) $missing->getContent(), (string) $foreign->getContent());

        $ownedByB = $this->credentials()->listOwned(Realm::Admin, $userB['id'], Context::createDefaultContext());
        self::assertCount(1, $ownedByB);
        self::assertSame($credentialB, $ownedByB->first()?->getId());
    }

    public function testRenameOfAForeignCredentialIsANoOp(): void
    {
        $userA = $this->createAdminUser();
        $userB = $this->createAdminUser();
        $credentialB = $this->enrollPasskey($userB['id'], 'B Key');

        $token = $this->token($userA, 'user-verified');

        $foreign = $this->apiRequest(
            'PATCH',
            '/api/_action/act-passkey/admin/credentials/' . $credentialB,
            $token,
            ['name' => 'Hijacked']
        );
        $missing = $this->apiRequest(
            'PATCH',
            '/api/_action/act-passkey/admin/credentials/' . Uuid::randomHex(),
            $token,
            ['name' => 'Hijacked']
        );

        self::assertSame(Response::HTTP_NO_CONTENT, $foreign->getStatusCode(), (string) $foreign->getContent());
        self::assertSame($missing->getStatusCode(), $foreign->getStatusCode());
        self::assertSame((string) $missing->getContent(), (string) $foreign->getContent());

        $ownedByB = $this->credentials()->listOwned(Realm::Admin, $userB['id'], Context::createDefaultContext());
        self::assertSame('B Key', $ownedByB->first()?->getName());
    }

    public function testWhitespaceOnlyRenameIsRejectedAndKeepsTheName(): void
    {
        $user = $this->createAdminUser();
        $credential = $this->enrollPasskey($user['id'], 'Old Key');

        $response = $this->apiRequest(
            'PATCH',
            '/api/_action/act-passkey/admin/credentials/' . $credential,
            $this->token($user, 'user-verified'),
            ['name' => " \u{00A0}\t "]
        );

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), (string) $response->getContent());
        $owned = $this->credentials()->listOwned(Realm::Admin, $user['id'], Context::createDefaultContext());
        self::assertSame('Old Key', $owned->first()?->getName());
    }

    public function testRenameTrimsSurroundingWhitespace(): void
    {
        $user = $this->createAdminUser();
        $credential = $this->enrollPasskey($user['id'], 'Old Key');

        $response = $this->apiRequest(
            'PATCH',
            '/api/_action/act-passkey/admin/credentials/' . $credential,
            $this->token($user, 'user-verified'),
            ['name' => "  New Key\u{00A0} "]
        );

        self::assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode(), (string) $response->getContent());
        $owned = $this->credentials()->listOwned(Realm::Admin, $user['id'], Context::createDefaultContext());
        self::assertSame('New Key', $owned->first()?->getName());
    }

    public function testOverLongRenameIsRejectedAndKeepsTheName(): void
    {
        $user = $this->createAdminUser();
        $credential = $this->enrollPasskey($user['id'], 'Old Key');
        $token = $this->token($user, 'user-verified');

        $response = $this->apiRequest(
            'PATCH',
            '/api/_action/act-passkey/admin/credentials/' . $credential,
            $token,
            ['name' => str_repeat('a', CredentialRepository::MAX_NAME_LENGTH + 1)]
        );

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), (string) $response->getContent());

        $owned = $this->credentials()->listOwned(Realm::Admin, $user['id'], Context::createDefaultContext());
        self::assertSame('Old Key', $owned->first()?->getName());
    }

    public function testRenameAtTheLimitWithMultibyteCharactersIsAccepted(): void
    {
        $user = $this->createAdminUser();
        $credential = $this->enrollPasskey($user['id'], 'Old Key');
        $token = $this->token($user, 'user-verified');

        // 128 characters, 256 bytes: the limit counts characters, not bytes.
        $name = str_repeat('ä', CredentialRepository::MAX_NAME_LENGTH);

        $response = $this->apiRequest(
            'PATCH',
            '/api/_action/act-passkey/admin/credentials/' . $credential,
            $token,
            ['name' => $name]
        );

        self::assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode(), (string) $response->getContent());

        $owned = $this->credentials()->listOwned(Realm::Admin, $user['id'], Context::createDefaultContext());
        self::assertSame($name, $owned->first()?->getName());
    }

    /**
     * Covers all four mutating routes (register-challenge, register, rename,
     * delete) so a dropped assertUserVerified() call on any single one of them
     * fails this test, not just the route where it happened to be tested before.
     *
     * @return iterable<string, array{0: string, 1: string, 2: array<string, mixed>}>
     */
    public static function mutatingRouteProvider(): iterable
    {
        yield 'register-challenge' => ['POST', '/api/_action/act-passkey/admin/register-challenge', []];
        yield 'register' => ['POST', '/api/_action/act-passkey/admin/register', [
            'passkey_response' => '{}',
            'passkey_challenge_id' => Uuid::randomHex(),
            'name' => 'Should not be created',
        ]];
        yield 'rename' => [
            'PATCH',
            '/api/_action/act-passkey/admin/credentials/' . Uuid::randomHex(),
            ['name' => 'Hijacked'],
        ];
        yield 'delete' => ['DELETE', '/api/_action/act-passkey/admin/credentials/' . Uuid::randomHex(), []];
    }

    /**
     * @param array<string, mixed> $params
     */
    #[DataProvider('mutatingRouteProvider')]
    public function testMutationWithoutUserVerifiedScopeIsRejected(string $method, string $uri, array $params): void
    {
        $userA = $this->createAdminUser();

        // A REAL admin token, just without the password step-up scope — exactly
        // what a passkey-issued token looks like.
        $response = $this->apiRequest($method, $uri, $this->token($userA, 'write'), $params);

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertSame(
            ApiException::API_INVALID_SCOPE_ACCESS_TOKEN,
            $data['errors'][0]['code'] ?? null,
            (string) $response->getContent()
        );
        self::assertStringContainsString(
            UserVerifiedScope::IDENTIFIER,
            (string) json_encode($data['errors'][0] ?? []),
            (string) $response->getContent()
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function registerNameProvider(): iterable
    {
        yield 'surrounding whitespace is removed' => ["  My Key\u{00A0} ", 'My Key'];
        yield 'whitespace only falls back to the default' => [" \u{00A0}\t ", 'Passkey'];
    }

    #[DataProvider('registerNameProvider')]
    public function testRegisterNormalisesTheName(string $name, string $expected): void
    {
        $user = $this->createAdminUser();
        $token = $this->token($user, 'user-verified');

        $challenge = json_decode(
            (string) $this->apiRequest('POST', '/api/_action/act-passkey/admin/register-challenge', $token)->getContent(),
            true
        );
        self::assertIsArray($challenge);

        $response = $this->apiRequest('POST', '/api/_action/act-passkey/admin/register', $token, [
            'passkey_response' => SoftwareAuthenticator::respondToCreate((string) json_encode($challenge['options']), $this->origin),
            'passkey_challenge_id' => $challenge['challengeId'],
            'name' => $name,
        ]);
        self::assertSame(Response::HTTP_NO_CONTENT, $response->getStatusCode(), (string) $response->getContent());

        $owned = $this->credentials()->listOwned(Realm::Admin, $user['id'], Context::createDefaultContext());
        self::assertSame($expected, $owned->first()?->getName());
    }

    public function testRegisterChallengeRequiresAnAuthenticatedSession(): void
    {
        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->setServerParameter('HTTP_AUTHORIZATION', '');
        $browser->request('POST', '/api/_action/act-passkey/admin/register-challenge');

        self::assertSame(
            Response::HTTP_UNAUTHORIZED,
            $browser->getResponse()->getStatusCode(),
            (string) $browser->getResponse()->getContent()
        );
    }

    private function challengeLimit(): int
    {
        $config = $this->getContainer()->getParameter('shopware.api.rate_limiter');
        self::assertIsArray($config);
        $limit = $config['act_passkey_challenge']['limit'] ?? null;
        self::assertIsInt($limit);

        return $limit;
    }

    private function credentials(): CredentialRepository
    {
        $service = $this->getContainer()->get(CredentialRepository::class);
        self::assertInstanceOf(CredentialRepository::class, $service);

        return $service;
    }

    /**
     * Enrolls a passkey straight through the ceremony (no HTTP), so list/rename/
     * delete tests start from a real, fully valid credential row.
     */
    private function enrollPasskey(string $adminUserId, string $name): string
    {
        $context = Context::createDefaultContext();

        $ceremony = $this->getContainer()->get(RegistrationCeremony::class);
        self::assertInstanceOf(RegistrationCeremony::class, $ceremony);

        $create = $ceremony->createOptions(Realm::Admin, $adminUserId, $this->host, $context);
        $ceremony->verify(
            Realm::Admin,
            $adminUserId,
            SoftwareAuthenticator::respondToCreate($create['options'], $this->origin),
            $create['challengeId'],
            $this->host,
            $name,
            $context
        );

        $credential = $this->credentials()->listOwned(Realm::Admin, $adminUserId, $context)->first();
        self::assertNotNull($credential);

        return $credential->getId();
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

    /**
     * @param array<string, mixed> $params
     */
    private function apiRequest(string $method, string $uri, string $token, array $params = []): Response
    {
        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        // HTTP_HOST must line up with the rpId ('127.0.0.1') the ceremony resolves.
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->setServerParameter('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $browser->request($method, $uri, $params);

        return $browser->getResponse();
    }

    /**
     * `user_id` has a real FK to `user`, so owner ids must be real rows. The
     * password must be a known plaintext so the OAuth password grant can mint a
     * real token for this user.
     *
     * @return array{id: string, username: string}
     */
    private function createAdminUser(): array
    {
        /** @var EntityRepository $userRepository */
        $userRepository = $this->getContainer()->get('user.repository');

        $userId = Uuid::randomHex();
        $username = 'passkey-' . Uuid::randomHex();
        $userRepository->create([[
            'id' => $userId,
            'localeId' => $this->getLocaleIdOfSystemLanguage(),
            'username' => $username,
            'password' => TestDefaults::HASHED_PASSWORD,
            'firstName' => 'Max',
            'lastName' => 'Mustermann',
            'email' => Uuid::randomHex() . '@example.test',
            'admin' => true,
        ]], Context::createDefaultContext());

        return ['id' => $userId, 'username' => $username];
    }
}
