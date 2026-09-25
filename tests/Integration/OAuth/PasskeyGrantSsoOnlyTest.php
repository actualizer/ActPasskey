<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\OAuth;

use Actualize\Passkey\OAuth\AdminLoginPolicy;
use Actualize\Passkey\OAuth\PasskeyGrant;
use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Doctrine\DBAL\Connection;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Api\OAuth\RefreshTokenRepository;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;

/**
 * Core refuses the password grant when the shop is SSO-only (`admin_login.use_default:
 * false`); the passkey grant must follow. The container parameter is frozen after compile,
 * so each test builds the grant with an explicit policy and drives the REAL shared
 * AuthorizationServer directly. Going around the HTTP kernel matters: its REQUEST
 * subscriber would swap the container's own grant back in. The control test proves the
 * identical setup succeeds with the default config, so the policy is the only variable.
 */
final class PasskeyGrantSsoOnlyTest extends TestCase
{
    use IntegrationTestBehaviour;

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        $appUrl = (string) $this->getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    public function testDefaultLoginConfigIssuesToken(): void
    {
        $response = $this->respondWithPolicy(new AdminLoginPolicy([]));

        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getBody(), true);
        self::assertIsArray($data);
        self::assertNotEmpty($data['access_token'] ?? null);
    }

    public function testSsoOnlyShopRejectsPasskeyGrant(): void
    {
        try {
            $this->respondWithPolicy(new AdminLoginPolicy(['use_default' => false]));
            self::fail('An SSO-only shop must not issue a token for a passkey login.');
        } catch (OAuthServerException $exception) {
            self::assertSame('invalid_grant', $exception->getErrorType());
        }
    }

    public function testAFailedLastUsedStampDoesNotFailAnAcceptedLogin(): void
    {
        // Same harness, only the stamp's write fails: every refusal has already passed,
        // so the token must still be issued rather than a 500.
        $failingRepository = $this->createMock(EntityRepository::class);
        $failingRepository->method('update')->willThrowException(new \RuntimeException('database unavailable'));

        $response = $this->respondWithPolicy(new AdminLoginPolicy([]), new CredentialRepository($failingRepository));

        self::assertSame(200, $response->getStatusCode());
    }

    private function respondWithPolicy(AdminLoginPolicy $policy, ?CredentialRepository $credentials = null): ResponseInterface
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

        $grant = new PasskeyGrant(
            $this->getContainer()->get(RefreshTokenRepository::class),
            $auth,
            new NullLogger(),
            $policy,
            $this->getContainer()->get(Connection::class),
            $credentials ?? $this->getContainer()->get(CredentialRepository::class),
        );
        // Normally set by PasskeyGrantSubscriber, which this test deliberately bypasses.
        $grant->setRefreshTokenTTL(new \DateInterval('P1W'));

        $server = $this->getContainer()->get('shopware.api.authorization_server');
        self::assertInstanceOf(AuthorizationServer::class, $server);
        $server->enableGrantType($grant, new \DateInterval('PT10M'));

        // The grant derives its host from the request URI, which must match the rp id.
        $request = (new ServerRequest('POST', 'http://' . $this->host . ':8000/api/oauth/token'))
            ->withParsedBody([
                'grant_type' => 'passkey',
                'client_id' => 'administration',
                'scope' => 'write',
                'passkey_response' => $assertion,
                'passkey_challenge_id' => $req['challengeId'],
            ]);

        return $server->respondToAccessTokenRequest($request, new Response());
    }

    /**
     * `user_id` has a real FK to `user`, so owner ids must be real rows.
     */
    private function createAdminUser(): string
    {
        /** @var EntityRepository $userRepository */
        $userRepository = $this->getContainer()->get('user.repository');

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
