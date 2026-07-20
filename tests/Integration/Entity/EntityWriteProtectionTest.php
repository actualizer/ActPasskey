<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Entity;

use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Credential\UserHandleProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\KernelLifecycleManager;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Response;

/**
 * Registering an entity definition makes core mint generic /api CRUD routes for it.
 * For these two tables an insert IS an enrollment, so the manage controllers'
 * ownership and step-up checks are worthless if that route stays open. These tests
 * pin the definition-level WriteProtection shut and prove the sanctioned path
 * through the ceremony still writes.
 *
 * @internal
 */
final class EntityWriteProtectionTest extends TestCase
{
    use IntegrationTestBehaviour;

    private const PLAIN_PASSWORD = 'shopware';

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        $appUrl = (string) $this->getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    /**
     * The escalation this closes: a principal holding act_passkey_credential:create
     * inserts a row carrying the victim's userId and its own public key, then logs
     * in as the victim via grant_type=passkey. No password step-up ever happens.
     */
    public function testGenericApiCannotEnrollACredentialForAnotherUser(): void
    {
        $victim = $this->createAdminUser();
        $attacker = $this->createAdminUser();

        $response = $this->apiRequest(
            'POST',
            '/api/act-passkey-credential',
            $this->token($attacker),
            [
                'id' => Uuid::randomHex(),
                'realm' => Realm::Admin->value,
                'userId' => $victim['id'],
                'credentialId' => base64_encode(random_bytes(32)),
                'publicKey' => base64_encode(random_bytes(64)),
                'signCount' => 0,
                'userHandle' => base64_encode(random_bytes(32)),
                'name' => 'Attacker Key',
            ]
        );

        $this->assertDeniedByWriteProtection($response, 'act_passkey_credential');
        self::assertCount(0, $this->credentials()->listOwned(Realm::Admin, $victim['id'], Context::createDefaultContext()));
    }

    public function testGenericApiCannotDeleteAForeignCredential(): void
    {
        $victim = $this->createAdminUser();
        $attacker = $this->createAdminUser();
        $credentialId = $this->enrollPasskey($victim['id'], 'Victim Key');

        // Locking a victim out of their own account is the mirror image of the
        // enrollment attack and must be closed by the same protection.
        $response = $this->apiRequest(
            'DELETE',
            '/api/act-passkey-credential/' . $credentialId,
            $this->token($attacker)
        );

        $this->assertDeniedByWriteProtection($response, 'act_passkey_credential');

        $owned = $this->credentials()->listOwned(Realm::Admin, $victim['id'], Context::createDefaultContext());
        self::assertCount(1, $owned);
        self::assertSame($credentialId, $owned->first()?->getId());
    }

    /**
     * Repointing a handle reassigns every credential bound to it, so this table
     * needs the same lock as the credential table.
     */
    public function testGenericApiCannotWriteAUserHandle(): void
    {
        $attacker = $this->createAdminUser();

        $response = $this->apiRequest(
            'POST',
            '/api/act-passkey-user-handle',
            $this->token($attacker),
            [
                'id' => Uuid::randomHex(),
                'realm' => Realm::Admin->value,
                'accountId' => $this->createAdminUser()['id'],
                'userHandle' => base64_encode(random_bytes(32)),
            ]
        );

        $this->assertDeniedByWriteProtection($response, 'act_passkey_user_handle');
    }

    /**
     * A protection that also blocked the plugin's own writes would be caught here
     * rather than in production, where it would break every enrollment and, via
     * updateSignCount, every login.
     */
    public function testSanctionedCeremonyPathStillWrites(): void
    {
        $user = $this->createAdminUser();
        $context = Context::createDefaultContext();

        $credentialId = $this->enrollPasskey($user['id'], 'My Laptop');

        $owned = $this->credentials()->listOwned(Realm::Admin, $user['id'], $context);
        self::assertCount(1, $owned);
        self::assertSame('My Laptop', $owned->first()?->getName());

        self::assertTrue($this->credentials()->renameOwned($credentialId, Realm::Admin, $user['id'], 'Renamed', $context));
        $this->credentials()->updateSignCount($credentialId, 42, $context);

        $reloaded = $this->credentials()->listOwned(Realm::Admin, $user['id'], $context)->first();
        self::assertSame('Renamed', $reloaded?->getName());
        self::assertSame(42, $reloaded?->getSignCount());

        self::assertTrue($this->credentials()->deleteOwned($credentialId, Realm::Admin, $user['id'], $context));
        self::assertCount(0, $this->credentials()->listOwned(Realm::Admin, $user['id'], $context));
    }

    public function testSanctionedUserHandleCreationStillWrites(): void
    {
        $user = $this->createAdminUser();
        $context = Context::createDefaultContext();

        $provider = $this->getContainer()->get(UserHandleProvider::class);
        self::assertInstanceOf(UserHandleProvider::class, $provider);

        $handle = $provider->getOrCreate(Realm::Admin, $user['id'], $context);

        self::assertSame(32, \strlen($handle));
        self::assertSame($user['id'], $provider->resolveAccountId(Realm::Admin, $handle, $context));
        // Second call must reuse the row, not mint a competing handle.
        self::assertSame($handle, $provider->getOrCreate(Realm::Admin, $user['id'], $context));

        /** @var EntityRepository $repository */
        $repository = $this->getContainer()->get('act_passkey_user_handle.repository');
        $criteria = (new Criteria())->addFilter(new EqualsFilter('accountId', $user['id']));
        self::assertSame(1, $repository->searchIds($criteria, $context)->getTotal());
    }

    /**
     * A bare 403 is not enough evidence. The attacker is a full admin with write scope,
     * so today the only thing that can refuse is the definition's WriteProtection — but
     * a later scope or ACL regression would produce its own 403 and keep these tests
     * green over a wide-open hole. Pin the refusal to the protection itself.
     *
     * For /api requests the refusal comes from EntityProtectionValidator::validateEntityPath(),
     * which runs while ApiController builds the entity path — earlier than the
     * PreWriteValidationEvent check that guards internal DAL writes.
     */
    private function assertDeniedByWriteProtection(Response $response, string $entity): void
    {
        $body = (string) $response->getContent();

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), $body);

        $decoded = json_decode($body, true);
        self::assertIsArray($decoded, $body);
        self::assertIsArray($decoded['errors'][0] ?? null, $body);
        self::assertSame(
            \sprintf('API access for entity "%s" not allowed.', $entity),
            $decoded['errors'][0]['detail'] ?? null,
            $body
        );
    }

    private function credentials(): CredentialRepository
    {
        $service = $this->getContainer()->get(CredentialRepository::class);
        self::assertInstanceOf(CredentialRepository::class, $service);

        return $service;
    }

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
     * A full admin token with write scope: ACL cannot be what rejects these calls
     * (AclWriteValidator returns early for admins), so a pass here would mean the
     * protection is genuinely absent.
     *
     * @param array{id: string, username: string} $user
     */
    private function token(array $user): string
    {
        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->setServerParameter('HTTP_AUTHORIZATION', '');
        $browser->request('POST', '/api/oauth/token', [
            'grant_type' => 'password',
            'client_id' => 'administration',
            'username' => $user['username'],
            'password' => self::PLAIN_PASSWORD,
            'scope' => 'write',
        ]);

        $response = $browser->getResponse();
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());

        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertIsString($data['access_token'] ?? null);

        return $data['access_token'];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function apiRequest(string $method, string $uri, string $token, array $payload = []): Response
    {
        $browser = KernelLifecycleManager::createBrowser(KernelLifecycleManager::getKernel());
        $browser->setServerParameter('HTTP_HOST', $this->host . ':8000');
        $browser->setServerParameter('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $browser->request(
            $method,
            $uri,
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json'],
            $payload === [] ? null : (string) json_encode($payload)
        );

        return $browser->getResponse();
    }

    /**
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
