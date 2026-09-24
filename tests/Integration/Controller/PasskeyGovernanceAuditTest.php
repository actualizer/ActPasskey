<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Controller;

use Actualize\Passkey\Controller\Admin\PasskeyGovernanceController;
use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Shopware\Core\Framework\RateLimiter\RateLimiterFactory;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * The audit record and the throttle of operator revocation. The controller is called
 * directly (ACL and routing are covered over HTTP in PasskeyGovernanceControllerTest):
 * only the logger and the limiter are swapped, everything else is the real container.
 *
 * @internal
 */
final class PasskeyGovernanceAuditTest extends TestCase
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

    public function testARealRevocationLeavesOneWarningWithTheAuditFields(): void
    {
        $spy = $this->spyLogger();
        $controller = $this->controller($spy, $this->containerLimiter());
        $actorId = Uuid::randomHex();
        $customerId = $this->createCustomer();
        $credentialId = $this->enrollCustomerPasskey($customerId);

        $controller->revokeCustomer($customerId, $credentialId, $this->request(), $this->operatorContext($actorId));

        self::assertCount(1, $spy->records);
        self::assertSame(LogLevel::WARNING, $spy->records[0]['level']);
        self::assertSame('Passkey revoked by operator', $spy->records[0]['message']);
        self::assertSame([
            'actorUserId' => $actorId,
            'realm' => 'customer',
            'ownerId' => $customerId,
            'credentialId' => $credentialId,
        ], $spy->records[0]['context']);
    }

    public function testANoOpRevocationIsNotAudited(): void
    {
        $spy = $this->spyLogger();
        $controller = $this->controller($spy, $this->containerLimiter());

        $controller->revokeCustomer(
            $this->createCustomer(),
            Uuid::randomHex(),
            $this->request(),
            $this->operatorContext(Uuid::randomHex())
        );

        self::assertSame([], $spy->records);
    }

    public function testRevocationsConsumeTheDeleteBucket(): void
    {
        $config = static::getContainer()->getParameter('shopware.api.rate_limiter');
        static::assertIsArray($config);
        $bucket = $config['act_passkey_delete'];
        static::assertIsArray($bucket);
        static::assertSame('time_backoff', $bucket['policy']);
        $burst = $bucket['limits'][0]['limit'];
        static::assertIsInt($burst);

        // APP_ENV=test wraps container limiters in NoLimiter — build a real one over the
        // plugin's shipped bucket config, backed by process-local storage.
        $rateLimiter = new RateLimiter();
        $rateLimiter->registerLimiterFactory('act_passkey_delete', new RateLimiterFactory(
            $bucket + ['id' => 'act_passkey_delete'],
            new InMemoryStorage(),
            static::getContainer()->get(SystemConfigService::class),
            static::getContainer()->get(ClockInterface::class),
        ));

        $controller = $this->controller($this->spyLogger(), $rateLimiter);
        $context = $this->operatorContext(Uuid::randomHex());
        $customerId = $this->createCustomer();

        // No-op revocations still count: the throttle runs before the delete.
        for ($i = 1; $i <= $burst; ++$i) {
            $controller->revokeCustomer($customerId, Uuid::randomHex(), $this->request(), $context);
        }

        $this->expectException(TooManyRequestsHttpException::class);
        $controller->revokeCustomer($customerId, Uuid::randomHex(), $this->request(), $context);
    }

    private function controller(AbstractLogger $logger, RateLimiter $rateLimiter): PasskeyGovernanceController
    {
        $credentials = $this->getContainer()->get(CredentialRepository::class);
        self::assertInstanceOf(CredentialRepository::class, $credentials);

        return new PasskeyGovernanceController($credentials, $rateLimiter, $logger);
    }

    private function containerLimiter(): RateLimiter
    {
        $limiter = $this->getContainer()->get(RateLimiter::class);
        self::assertInstanceOf(RateLimiter::class, $limiter);

        return $limiter;
    }

    /**
     * @return AbstractLogger&object{records: list<array{level: mixed, message: string, context: array<mixed>}>}
     */
    private function spyLogger(): AbstractLogger
    {
        return new class extends AbstractLogger {
            /** @var list<array{level: mixed, message: string, context: array<mixed>}> */
            public array $records = [];

            public function log($level, $message, array $context = []): void
            {
                $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
            }
        };
    }

    private function operatorContext(string $actorId): Context
    {
        return new Context(new AdminApiSource($actorId));
    }

    private function request(): Request
    {
        $request = new Request();
        $request->server->set('REMOTE_ADDR', '203.0.113.21');

        return $request;
    }

    private function enrollCustomerPasskey(string $customerId): string
    {
        $context = Context::createDefaultContext();
        $ceremony = $this->getContainer()->get(RegistrationCeremony::class);
        self::assertInstanceOf(RegistrationCeremony::class, $ceremony);

        $create = $ceremony->createOptions(Realm::Customer, $customerId, $this->host, $context);
        $ceremony->verify(
            Realm::Customer,
            $customerId,
            SoftwareAuthenticator::respondToCreate($create['options'], $this->origin),
            $create['challengeId'],
            $this->host,
            'Key',
            $context
        );

        $credentials = $this->getContainer()->get(CredentialRepository::class);
        self::assertInstanceOf(CredentialRepository::class, $credentials);
        $credential = $credentials->listOwned(Realm::Customer, $customerId, $context)->first();
        self::assertNotNull($credential);

        return $credential->getId();
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
