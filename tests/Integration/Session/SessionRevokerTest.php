<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Session;

use Actualize\Passkey\Session\SessionRevoker;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Api\OAuth\AuthCodeRepository;
use Shopware\Core\Framework\Api\OAuth\RefreshTokenRepository;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\BasicTestDataBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\SalesChannelApiTestBehaviour;
use Shopware\Core\Framework\Util\Random;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\Context\AbstractSalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextPersister;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextService;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * Session end is proven against the real core tables: only the targeted owner's rows change.
 *
 * @internal
 */
final class SessionRevokerTest extends TestCase
{
    use BasicTestDataBehaviour;
    use IntegrationTestBehaviour;
    use SalesChannelApiTestBehaviour;

    public function testEndOtherCustomerSessionsRotatesTheCallersToken(): void
    {
        $customerId = $this->createCustomerId();
        $caller = Random::getAlphanumericString(32);
        $other = Random::getAlphanumericString(32);
        $this->persist($caller, $customerId);
        $this->persist($other, $customerId, $this->secondSalesChannelId());
        $context = $this->contextFor($caller, $customerId);

        $result = $this->revoker()->endOtherCustomerSessions($context, new Request(), Uuid::randomHex());

        self::assertTrue($result);
        $newToken = $context->getToken();
        self::assertNotSame($caller, $newToken);
        self::assertSame(0, $this->tokenRowCount($caller));
        self::assertSame($customerId, $this->customerIdOf($newToken));
        self::assertNull($this->customerIdOf($other));
    }

    public function testEndOtherCustomerSessionsMovesAStartedSessionToTheNewToken(): void
    {
        $customerId = $this->createCustomerId();
        $caller = Random::getAlphanumericString(32);
        $this->persist($caller, $customerId);
        $context = $this->contextFor($caller, $customerId);
        $session = new Session(new MockArraySessionStorage());
        $session->start();
        $oldSessionId = $session->getId();
        $request = new Request();
        $request->setSession($session);

        self::assertTrue($this->revoker()->endOtherCustomerSessions($context, $request, Uuid::randomHex()));

        $newToken = $context->getToken();
        self::assertSame($newToken, $session->get(PlatformRequest::HEADER_CONTEXT_TOKEN));
        self::assertSame($newToken, $request->headers->get(PlatformRequest::HEADER_CONTEXT_TOKEN));
        self::assertNotSame($oldSessionId, $session->getId());
        self::assertSame($session->getId(), $session->get('sessionId'));
    }

    public function testEndOtherCustomerSessionsMovesThePerChannelSessionKeyToo(): void
    {
        $customerId = $this->createCustomerId();
        $caller = Random::getAlphanumericString(32);
        $this->persist($caller, $customerId);
        $context = $this->contextFor($caller, $customerId);
        $channelKey = PlatformRequest::HEADER_CONTEXT_TOKEN . '-' . $context->getSalesChannelId();
        $session = new Session(new MockArraySessionStorage());
        $session->start();
        $session->set($channelKey, $caller);
        $request = new Request();
        $request->setSession($session);

        self::assertTrue($this->revoker()->endOtherCustomerSessions($context, $request, Uuid::randomHex()));

        self::assertSame($context->getToken(), $session->get($channelKey));
        self::assertNotSame($caller, $session->get($channelKey));
    }

    public function testEndOtherCustomerSessionsDoesNotCreateAPerChannelSessionKey(): void
    {
        $customerId = $this->createCustomerId();
        $caller = Random::getAlphanumericString(32);
        $this->persist($caller, $customerId);
        $context = $this->contextFor($caller, $customerId);
        $session = new Session(new MockArraySessionStorage());
        $session->start();
        $request = new Request();
        $request->setSession($session);

        self::assertTrue($this->revoker()->endOtherCustomerSessions($context, $request, Uuid::randomHex()));

        self::assertFalse($session->has(PlatformRequest::HEADER_CONTEXT_TOKEN . '-' . $context->getSalesChannelId()));
    }

    public function testEndCustomerSessionsWithoutPreservedTokenEndsAll(): void
    {
        $customerId = $this->createCustomerId();
        $tokenA = Random::getAlphanumericString(32);
        $tokenB = Random::getAlphanumericString(32);
        $this->persist($tokenA, $customerId);
        $this->persist($tokenB, $customerId, $this->secondSalesChannelId());

        self::assertTrue($this->revoker()->endCustomerSessions($customerId, Uuid::randomHex()));

        self::assertNull($this->customerIdOf($tokenA));
        self::assertNull($this->customerIdOf($tokenB));
    }

    public function testEndCustomerSessionsLeavesOtherCustomersAlone(): void
    {
        $customerId = $this->createCustomerId();
        $otherId = $this->createCustomerId();
        $own = Random::getAlphanumericString(32);
        $foreign = Random::getAlphanumericString(32);
        $this->persist($own, $customerId);
        $this->persist($foreign, $otherId);

        self::assertTrue($this->revoker()->endCustomerSessions($customerId, Uuid::randomHex()));

        self::assertNull($this->customerIdOf($own));
        self::assertSame($otherId, $this->customerIdOf($foreign));
    }

    public function testEndUserSessionsRemovesTheUsersRefreshTokens(): void
    {
        $userA = Uuid::randomHex();
        $userB = Uuid::randomHex();
        $this->insertRefreshToken($userA);
        $this->insertRefreshToken($userA);
        $this->insertRefreshToken($userB);

        self::assertTrue($this->revoker()->endUserSessions($userA, Uuid::randomHex()));

        self::assertSame(0, $this->refreshTokenCount($userA));
        self::assertSame(1, $this->refreshTokenCount($userB));
    }

    public function testAFailureIsLoggedAndReportedAsNotEnded(): void
    {
        $persister = $this->createMock(SalesChannelContextPersister::class);
        $persister->method('revokeAllCustomerTokens')->willThrowException(new \RuntimeException('db down'));
        $spy = $this->spyLogger();
        $revoker = new SessionRevoker(
            $persister,
            $this->getContainer()->get(RefreshTokenRepository::class),
            $this->getContainer()->get(AuthCodeRepository::class),
            $spy,
        );
        $customerId = Uuid::randomHex();
        $credentialId = Uuid::randomHex();

        self::assertFalse($revoker->endCustomerSessions($customerId, $credentialId));

        self::assertCount(1, $spy->records);
        self::assertSame(LogLevel::WARNING, $spy->records[0]['level']);
        self::assertSame('Passkey removed but sessions could not be ended', $spy->records[0]['message']);
        self::assertSame('customer', $spy->records[0]['context']['realm']);
        self::assertSame($customerId, $spy->records[0]['context']['ownerId']);
        self::assertSame($credentialId, $spy->records[0]['context']['credentialId']);
    }

    public function testAFailureWhileRotatingTheCallersTokenIsLoggedAndReportedAsNotEnded(): void
    {
        $persister = $this->createMock(SalesChannelContextPersister::class);
        $persister->method('replace')->willThrowException(new \RuntimeException('db down'));
        $spy = $this->spyLogger();
        $revoker = new SessionRevoker(
            $persister,
            $this->getContainer()->get(RefreshTokenRepository::class),
            $this->getContainer()->get(AuthCodeRepository::class),
            $spy,
        );
        $customerId = $this->createCustomerId();
        $credentialId = Uuid::randomHex();
        $context = $this->contextFor(Random::getAlphanumericString(32), $customerId);

        self::assertFalse($revoker->endOtherCustomerSessions($context, new Request(), $credentialId));

        self::assertCount(1, $spy->records);
        self::assertSame(LogLevel::WARNING, $spy->records[0]['level']);
        self::assertSame('Passkey removed but sessions could not be ended', $spy->records[0]['message']);
        self::assertSame('customer', $spy->records[0]['context']['realm']);
        self::assertSame($customerId, $spy->records[0]['context']['ownerId']);
        self::assertSame($credentialId, $spy->records[0]['context']['credentialId']);
    }

    public function testAnAdminFailureIsLoggedWithTheAdminRealm(): void
    {
        $refreshTokens = $this->createMock(RefreshTokenRepository::class);
        $refreshTokens->method('revokeRefreshTokensForUser')->willThrowException(new \RuntimeException('db down'));
        $spy = $this->spyLogger();
        $revoker = new SessionRevoker(
            $this->getContainer()->get(SalesChannelContextPersister::class),
            $refreshTokens,
            $this->getContainer()->get(AuthCodeRepository::class),
            $spy,
        );
        $userId = Uuid::randomHex();
        $credentialId = Uuid::randomHex();

        self::assertFalse($revoker->endUserSessions($userId, $credentialId));

        self::assertCount(1, $spy->records);
        self::assertSame(LogLevel::WARNING, $spy->records[0]['level']);
        self::assertSame('Passkey removed but sessions could not be ended', $spy->records[0]['message']);
        self::assertSame('admin', $spy->records[0]['context']['realm']);
        self::assertSame($userId, $spy->records[0]['context']['ownerId']);
        self::assertSame($credentialId, $spy->records[0]['context']['credentialId']);
    }

    private function revoker(): SessionRevoker
    {
        return new SessionRevoker(
            $this->getContainer()->get(SalesChannelContextPersister::class),
            $this->getContainer()->get(RefreshTokenRepository::class),
            $this->getContainer()->get(AuthCodeRepository::class),
            new NullLogger(),
        );
    }

    private function createCustomerId(): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();
        $this->getContainer()->get('customer.repository')->create([[
            'id' => $customerId,
            'active' => true,
            'salesChannelId' => TestDefaults::SALES_CHANNEL,
            'defaultShippingAddress' => [
                'id' => $addressId,
                'firstName' => 'Max',
                'lastName' => 'Mustermann',
                'street' => 'Musterstrasse 1',
                'city' => 'Schoeppingen',
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
     * The table is unique per (sales channel, customer), so a customer's second
     * concurrent session can only live in another sales channel.
     */
    private function secondSalesChannelId(): string
    {
        return $this->createSalesChannel()['id'];
    }

    private function contextFor(string $token, string $customerId): SalesChannelContext
    {
        $factory = $this->getContainer()->get(SalesChannelContextFactory::class);
        self::assertInstanceOf(AbstractSalesChannelContextFactory::class, $factory);

        return $factory->create($token, TestDefaults::SALES_CHANNEL, [
            SalesChannelContextService::CUSTOMER_ID => $customerId,
        ]);
    }

    private function tokenRowCount(string $token): int
    {
        return (int) $this->connection()->fetchOne(
            'SELECT COUNT(*) FROM sales_channel_api_context WHERE token = :token',
            ['token' => $token]
        );
    }

    private function persist(string $token, string $customerId, string $salesChannelId = TestDefaults::SALES_CHANNEL): void
    {
        $this->getContainer()->get(SalesChannelContextPersister::class)
            ->save($token, [], $salesChannelId, $customerId);
    }

    private function customerIdOf(string $token): ?string
    {
        $value = $this->connection()->fetchOne(
            'SELECT LOWER(HEX(customer_id)) FROM sales_channel_api_context WHERE token = :token',
            ['token' => $token]
        );
        self::assertNotFalse($value, 'token row must exist');

        return $value === null ? null : (string) $value;
    }

    private function insertRefreshToken(string $userId): void
    {
        $this->connection()->insert('refresh_token', [
            'id' => Uuid::randomBytes(),
            'user_id' => Uuid::fromHexToBytes($userId),
            'token_id' => Uuid::randomHex(),
            'family_id' => Uuid::randomBytes(),
            'issued_at' => '2026-01-01 00:00:00.000',
            'expires_at' => '2099-01-01 00:00:00.000',
        ]);
    }

    private function refreshTokenCount(string $userId): int
    {
        return (int) $this->connection()->fetchOne(
            'SELECT COUNT(*) FROM refresh_token WHERE user_id = :id',
            ['id' => Uuid::fromHexToBytes($userId)]
        );
    }

    private function connection(): Connection
    {
        return $this->getContainer()->get(Connection::class);
    }

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
}
