<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Store;

use Actualize\Passkey\Controller\Store\PasskeyStoreApiController;
use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Customer\CustomerEligibilityGuard;
use Actualize\Passkey\WebAuthn\Customer\CustomerPasskeyLoginService;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Shopware\Core\Checkout\Customer\CustomerException;
use Shopware\Core\Checkout\Customer\SalesChannel\AccountService;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * Behavioural proof of storefront passkey login: a real ACTIVE customer
 * registers a passkey, authenticates with it against the store-api login
 * route, and receives a genuine ContextTokenResponse (customer session
 * established via AccountService::loginById — no password involved).
 *
 * Also proves the realm boundary (an ADMIN credential must not resolve at
 * the customer login route) and rejects a bogus challenge id.
 */
final class CustomerPasskeyLoginRouteTest extends TestCase
{
    use IntegrationTestBehaviour;

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        // In APP_ENV=test, %APP_URL% = http://127.0.0.1:8000 (host 127.0.0.1).
        // Derive host + origin from the container parameter so the test stays
        // robust against env changes, and so it lines up with the credential's
        // rpId resolved at registration time.
        $appUrl = (string) $this->getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    public function testCustomerCanLoginWithRegisteredPasskey(): void
    {
        $controller = $this->getContainer()->get(PasskeyStoreApiController::class);
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer();

        $this->registerPasskey(Realm::Customer, $customerId, $ctx);

        $salesChannelContext = $this->createStorefrontContext();
        $requestDataBag = $this->buildLoginRequestDataBag(Realm::Customer, $ctx);
        $request = $this->buildHostRequest();

        $response = $controller->login($request, $requestDataBag, $salesChannelContext);

        self::assertInstanceOf(ContextTokenResponse::class, $response);
        self::assertNotSame('', $response->getToken());
    }

    public function testAdminCredentialIsRejectedAtCustomerLoginRoute(): void
    {
        $controller = $this->getContainer()->get(PasskeyStoreApiController::class);
        $ctx = Context::createDefaultContext();
        $adminUserId = $this->createAdminUser();

        // Register an ADMIN-realm credential, then present its assertion at
        // the CUSTOMER login route — the realm-scoped lookup must reject it.
        $this->registerPasskey(Realm::Admin, $adminUserId, $ctx);

        $salesChannelContext = $this->createStorefrontContext();
        $requestDataBag = $this->buildLoginRequestDataBag(Realm::Admin, $ctx);
        $request = $this->buildHostRequest();

        $this->expectException(UnauthorizedHttpException::class);
        $controller->login($request, $requestDataBag, $salesChannelContext);
    }

    public function testUnconfirmedDoubleOptInCustomerCannotLoginWithPasskey(): void
    {
        $controller = $this->getContainer()->get(PasskeyStoreApiController::class);
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer([
            'doubleOptInRegistration' => true,
            'doubleOptInConfirmDate' => null,
        ]);

        $this->registerPasskey(Realm::Customer, $customerId, $ctx);

        $salesChannelContext = $this->createStorefrontContext();
        $requestDataBag = $this->buildLoginRequestDataBag(Realm::Customer, $ctx);
        $request = $this->buildHostRequest();

        // On the store-api route, the eligibility guard's CustomerException
        // propagates unwrapped (same as a rejected password login) — only the
        // storefront controller catches it and turns it into a loginError forward.
        $this->expectException(CustomerException::class);
        $controller->login($request, $requestDataBag, $salesChannelContext);
    }

    public function testInactiveCustomerCannotLoginWithPasskey(): void
    {
        $controller = $this->getContainer()->get(PasskeyStoreApiController::class);
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer(['active' => false]);

        $this->registerPasskey(Realm::Customer, $customerId, $ctx);

        $salesChannelContext = $this->createStorefrontContext();
        $requestDataBag = $this->buildLoginRequestDataBag(Realm::Customer, $ctx);
        $request = $this->buildHostRequest();

        $this->expectException(CustomerException::class);
        $controller->login($request, $requestDataBag, $salesChannelContext);
    }

    public function testBogusChallengeIdIsRejected(): void
    {
        $controller = $this->getContainer()->get(PasskeyStoreApiController::class);
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer();

        $this->registerPasskey(Realm::Customer, $customerId, $ctx);

        // Build a valid assertion, but pair it with a challenge id that was
        // never issued by the ChallengeStore.
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $req = $auth->createOptions(Realm::Customer, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        $requestDataBag = new RequestDataBag([
            'passkey_response' => $assertion,
            'passkey_challenge_id' => Uuid::randomHex(),
        ]);

        $salesChannelContext = $this->createStorefrontContext();
        $request = $this->buildHostRequest();

        $this->expectException(UnauthorizedHttpException::class);
        $controller->login($request, $requestDataBag, $salesChannelContext);
    }

    public function testFailedLoginIsRecordedOnThePasskeyChannel(): void
    {
        $spy = new class extends AbstractLogger {
            /** @var list<array{level: mixed, message: string}> */
            public array $records = [];

            public function log($level, $message, array $context = []): void
            {
                $this->records[] = ['level' => $level, 'message' => (string) $message];
            }
        };

        // Real collaborators from the container, only the logger swapped for a spy —
        // AuthenticationCeremony is final and cannot be mocked (see PasskeyGrantIdentifierTest).
        $service = new CustomerPasskeyLoginService(
            $this->getContainer()->get(AuthenticationCeremony::class),
            $this->getContainer()->get(CustomerEligibilityGuard::class),
            $this->getContainer()->get(AccountService::class),
            $this->getContainer()->get('customer.repository'),
            $spy,
        );

        // A challenge id that was never issued makes the ceremony throw, which the
        // service catches: the public response stays a generic 401, but the failure
        // must now be recorded internally for diagnosis.
        try {
            $service->login('not-a-valid-assertion', Uuid::randomHex(), $this->host, $this->createStorefrontContext());
            self::fail('expected the failed login to throw UnauthorizedHttpException');
        } catch (UnauthorizedHttpException) {
            // expected — the generic public response is unchanged.
        }

        self::assertCount(1, $spy->records, 'a failed login must leave exactly one internal record');
        self::assertSame('Passkey authentication failed', $spy->records[0]['message']);
        self::assertSame(LogLevel::NOTICE, $spy->records[0]['level'], 'public auth failures log at NOTICE, not warning');
    }

    private function registerPasskey(Realm $realm, string $accountId, Context $ctx): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $create = $reg->createOptions($realm, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify($realm, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);
    }

    private function buildLoginRequestDataBag(Realm $realm, Context $ctx): RequestDataBag
    {
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $req = $auth->createOptions($realm, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        return new RequestDataBag([
            'passkey_response' => $assertion,
            'passkey_challenge_id' => $req['challengeId'],
        ]);
    }

    private function buildHostRequest(): Request
    {
        return Request::create('/store-api/act-passkey/login', 'POST', [], [], [], [
            'HTTP_HOST' => $this->host . ':8000',
        ]);
    }

    private function createStorefrontContext(): SalesChannelContext
    {
        return $this->getContainer()->get(SalesChannelContextFactory::class)
            ->create(Uuid::randomHex(), TestDefaults::SALES_CHANNEL);
    }

    /**
     * `customer_id` has a real FK to `customer`, so owner ids must be real
     * rows. Mirrors CeremonyRoundTripTest::createCustomer(), but explicitly
     * `active` (required for AccountService::loginById -> fetchCustomer to
     * accept it) and `boundSalesChannelId=null` (unbound, so it resolves
     * under the storefront sales-channel context built for the login call).
     *
     * @param array<string, mixed> $overrides merged over the default row,
     *     e.g. `['active' => false]` or the double-opt-in columns, so
     *     eligibility-guard tests can build a non-eligible customer.
     */
    private function createCustomer(array $overrides = []): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();

        /** @var EntityRepository $customerRepository */
        $customerRepository = $this->getContainer()->get('customer.repository');
        $customerRepository->create([array_merge([
            'id' => $customerId,
            'active' => true,
            'boundSalesChannelId' => null,
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
        ], $overrides)], Context::createDefaultContext());

        return $customerId;
    }

    /**
     * `user_id` has a real FK to `user`, so owner ids must be real rows.
     */
    private function createAdminUser(): string
    {
        $userId = Uuid::randomHex();

        /** @var EntityRepository $userRepository */
        $userRepository = $this->getContainer()->get('user.repository');
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
