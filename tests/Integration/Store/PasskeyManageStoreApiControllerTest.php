<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Store;

use Actualize\Passkey\Controller\Store\PasskeyManageStoreApiController;
use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\Customer\CustomerCollection;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\Exception\CustomerNotFoundByIdException;
use Shopware\Core\Checkout\Customer\Exception\CustomerOptinNotCompletedException;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\Routing\RoutingException;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\SalesChannelApiTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\System\SalesChannel\Context\AbstractSalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextService;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Proves the customer self-service store-api: enrollment is only possible for an
 * active, opt-in-confirmed, logged-in (non-guest) customer, ownership always comes
 * from the session customer, and foreign rows are untouchable and indistinguishable
 * from missing ones.
 *
 * @internal
 */
final class PasskeyManageStoreApiControllerTest extends TestCase
{
    use IntegrationTestBehaviour;
    use SalesChannelApiTestBehaviour;

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

    /**
     * The `_loginRequired` route default is only enforced by the real request
     * pipeline, so this case goes through the kernel: a genuine guest session
     * (registered via the core's own guest registration) must never reach the
     * controller at all.
     */
    public function testGuestSessionCannotEnroll(): void
    {
        $browser = $this->getSalesChannelBrowser();
        $browser->request('POST', '/store-api/account/register', $this->guestRegistrationPayload());
        self::assertSame(
            Response::HTTP_OK,
            $browser->getResponse()->getStatusCode(),
            (string) $browser->getResponse()->getContent()
        );

        $contextToken = $browser->getResponse()->headers->get('sw-context-token');
        self::assertIsString($contextToken);
        $browser->setServerParameter('HTTP_SW_CONTEXT_TOKEN', $contextToken);

        $browser->request('POST', '/store-api/act-passkey/register-challenge', ['password' => self::PLAIN_PASSWORD]);

        $response = $browser->getResponse();
        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode(), (string) $response->getContent());

        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertSame(
            RoutingException::CUSTOMER_NOT_LOGGED_IN_CODE,
            $data['errors'][0]['code'] ?? null,
            (string) $response->getContent()
        );
    }

    /**
     * THE hard Phase-4 requirement: AccountService::loginById() does not re-check
     * double opt-in, so a session may exist for an unconfirmed account. Enrollment
     * must still be refused — and refused by the eligibility guard, not by some
     * incidental ceremony failure, hence the specific exception assertion.
     *
     * NOTE: this is a valid end-to-end negative, but NOT a regression lock on the
     * guard specifically — registerChallenge() also runs the password step-up
     * (CustomerPasswordMatches -> AccountService::getCustomerByLogin()), which
     * throws the identical CustomerOptinNotCompletedException for the same
     * unconfirmed account. This test supplies the correct password and would still
     * pass if CustomerEligibilityGuard::assertEligible() were deleted entirely. The
     * guard-specific regression locks are testUnconfirmedDoubleOptInCustomerCannotList
     * and testUnconfirmedDoubleOptInCustomerCannotRename below, on routes with no
     * step-up where the guard is the sole defense.
     */
    public function testUnconfirmedDoubleOptInCustomerCannotEnroll(): void
    {
        $customerId = $this->createCustomerRow([
            'doubleOptInRegistration' => true,
            'doubleOptInConfirmDate' => null,
        ]);
        $context = $this->createCustomerContext($customerId);

        $this->expectException(CustomerOptinNotCompletedException::class);
        $this->controller()->registerChallenge(
            $this->buildHostRequest(),
            new RequestDataBag(['password' => self::PLAIN_PASSWORD]),
            $context,
            $this->customerOf($context)
        );
    }

    /**
     * Regression lock on the guard itself: list() has no password step-up, so
     * assertEligible() is the ONLY thing that can produce this exception here.
     */
    public function testUnconfirmedDoubleOptInCustomerCannotList(): void
    {
        $customerId = $this->createCustomerRow([
            'doubleOptInRegistration' => true,
            'doubleOptInConfirmDate' => null,
        ]);
        $context = $this->createCustomerContext($customerId);

        $this->expectException(CustomerOptinNotCompletedException::class);
        $this->controller()->list($this->buildHostRequest(), $context, $this->customerOf($context));
    }

    /**
     * Regression lock on the guard itself: rename() has no password step-up, so
     * assertEligible() is the ONLY thing that can produce this exception here.
     */
    public function testUnconfirmedDoubleOptInCustomerCannotRename(): void
    {
        $customerId = $this->createCustomerRow([
            'doubleOptInRegistration' => true,
            'doubleOptInConfirmDate' => null,
        ]);
        $context = $this->createCustomerContext($customerId);

        $this->expectException(CustomerOptinNotCompletedException::class);
        $this->controller()->rename(
            Uuid::randomHex(),
            new RequestDataBag(['name' => 'Should not matter']),
            $context,
            $this->customerOf($context)
        );
    }

    /**
     * Regression lock on the guard's other branch: list() has no password step-up
     * and nothing else in the route checks `active`, so assertEligible() is the
     * ONLY thing that can produce this exception here.
     *
     * Note: SalesChannelContextFactory::loadCustomer() itself drops an inactive
     * customer (returns null instead of the entity), so createCustomerContext() +
     * customerOf() can't be used to obtain the CustomerEntity here — that path
     * would never reach the controller at all in production. This test targets the
     * guard specifically, so the CustomerEntity is loaded directly, exactly like
     * CustomerValueResolver would hand it to the controller.
     */
    public function testInactiveCustomerCannotList(): void
    {
        $customerId = $this->createCustomerRow(['active' => false]);
        $context = $this->createCustomerContext($customerId);

        $this->expectException(CustomerNotFoundByIdException::class);
        $this->controller()->list($this->buildHostRequest(), $context, $this->customerById($customerId));
    }

    public function testRegisterWithoutPasswordIsRejected(): void
    {
        $customerId = $this->createCustomerRow();
        $context = $this->createCustomerContext($customerId);

        $this->expectException(ConstraintViolationException::class);
        $this->controller()->register(
            $this->buildHostRequest(),
            new RequestDataBag([
                'passkey_response' => '{}',
                'passkey_challenge_id' => Uuid::randomHex(),
                'name' => 'Should not be created',
            ]),
            $context,
            $this->customerOf($context)
        );
    }

    public function testRegisterWithWrongPasswordIsRejected(): void
    {
        $customerId = $this->createCustomerRow();
        $context = $this->createCustomerContext($customerId);

        try {
            $this->controller()->register(
                $this->buildHostRequest(),
                new RequestDataBag([
                    'password' => 'definitely-not-the-password',
                    'passkey_response' => '{}',
                    'passkey_challenge_id' => Uuid::randomHex(),
                    'name' => 'Should not be created',
                ]),
                $context,
                $this->customerOf($context)
            );
            self::fail('Expected a ConstraintViolationException for a wrong step-up password.');
        } catch (ConstraintViolationException $exception) {
            $codes = [];
            foreach ($exception->getViolations() as $violation) {
                $codes[] = $violation->getCode();
            }

            // The specific code matters: a NotBlank violation would also satisfy a
            // bare ConstraintViolationException assertion. The DataValidator maps the
            // raw uuid code to the constraint's error NAME before it surfaces.
            self::assertContains(
                'VIOLATION::CUSTOMER_PASSWORD_NOT_CORRECT',
                $codes,
                (string) json_encode($codes)
            );
        }

        self::assertCount(0, $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext()));
    }

    public function testRegisterPersistsCredentialForTheSessionCustomer(): void
    {
        $customerId = $this->createCustomerRow();
        $context = $this->createCustomerContext($customerId);
        $customer = $this->customerOf($context);
        $controller = $this->controller();

        $challengeResponse = $controller->registerChallenge(
            $this->buildHostRequest(),
            new RequestDataBag(['password' => self::PLAIN_PASSWORD]),
            $context,
            $customer
        );
        self::assertSame(Response::HTTP_OK, $challengeResponse->getStatusCode(), (string) $challengeResponse->getContent());

        $challenge = json_decode((string) $challengeResponse->getContent(), true);
        self::assertIsArray($challenge);
        self::assertIsArray($challenge['options'] ?? null);
        self::assertIsString($challenge['challengeId'] ?? null);

        $attestation = SoftwareAuthenticator::respondToCreate((string) json_encode($challenge['options']), $this->origin);

        $registerResponse = $controller->register(
            $this->buildHostRequest(),
            new RequestDataBag([
                'password' => self::PLAIN_PASSWORD,
                'passkey_response' => $attestation,
                'passkey_challenge_id' => $challenge['challengeId'],
                'name' => 'My Phone',
            ]),
            $context,
            $customer
        );

        self::assertSame(Response::HTTP_NO_CONTENT, $registerResponse->getStatusCode());

        $owned = $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext());
        self::assertCount(1, $owned);
        self::assertSame('My Phone', $owned->first()?->getName());
    }

    public function testListReturnsOnlyOwnCredentials(): void
    {
        $customerA = $this->createCustomerRow();
        $customerB = $this->createCustomerRow();

        $credentialA = $this->enrollPasskey($customerA, 'A Key');
        $this->enrollPasskey($customerB, 'B Key');

        $context = $this->createCustomerContext($customerA);
        $response = $this->controller()->list($this->buildHostRequest(), $context, $this->customerOf($context));

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertIsArray($data['credentials'] ?? null);
        self::assertCount(1, $data['credentials']);
        self::assertSame($credentialA, $data['credentials'][0]['id']);
        self::assertSame('A Key', $data['credentials'][0]['name']);
        // Never used yet — the account page renders this as "never".
        self::assertNull($data['credentials'][0]['lastUsedAt']);
    }

    public function testDeleteOfAForeignCredentialIsANoOp(): void
    {
        $customerA = $this->createCustomerRow();
        $customerB = $this->createCustomerRow();
        $credentialB = $this->enrollPasskey($customerB, 'B Key');

        $context = $this->createCustomerContext($customerA);
        $customer = $this->customerOf($context);
        $controller = $this->controller();

        $foreign = $controller->delete(
            $credentialB,
            $this->buildHostRequest(),
            new RequestDataBag(['password' => self::PLAIN_PASSWORD]),
            $context,
            $customer
        );
        $missing = $controller->delete(
            Uuid::randomHex(),
            $this->buildHostRequest(),
            new RequestDataBag(['password' => self::PLAIN_PASSWORD]),
            $context,
            $customer
        );

        // No existence oracle: "not yours" and "does not exist" must look identical.
        self::assertSame(Response::HTTP_NO_CONTENT, $foreign->getStatusCode());
        self::assertSame($missing->getStatusCode(), $foreign->getStatusCode());
        self::assertSame((string) $missing->getContent(), (string) $foreign->getContent());

        $ownedByB = $this->credentials()->listOwned(Realm::Customer, $customerB, Context::createDefaultContext());
        self::assertCount(1, $ownedByB);
        self::assertSame($credentialB, $ownedByB->first()?->getId());
    }

    public function testRenameOfAForeignCredentialIsANoOp(): void
    {
        $customerA = $this->createCustomerRow();
        $customerB = $this->createCustomerRow();
        $credentialB = $this->enrollPasskey($customerB, 'B Key');

        $context = $this->createCustomerContext($customerA);
        $customer = $this->customerOf($context);
        $controller = $this->controller();

        $foreign = $controller->rename($credentialB, new RequestDataBag(['name' => 'Hijacked']), $context, $customer);
        $missing = $controller->rename(Uuid::randomHex(), new RequestDataBag(['name' => 'Hijacked']), $context, $customer);

        self::assertSame(Response::HTTP_NO_CONTENT, $foreign->getStatusCode());
        self::assertSame($missing->getStatusCode(), $foreign->getStatusCode());
        self::assertSame((string) $missing->getContent(), (string) $foreign->getContent());

        $ownedByB = $this->credentials()->listOwned(Realm::Customer, $customerB, Context::createDefaultContext());
        self::assertSame('B Key', $ownedByB->first()?->getName());
    }

    private function controller(): PasskeyManageStoreApiController
    {
        $controller = $this->getContainer()->get(PasskeyManageStoreApiController::class);
        self::assertInstanceOf(PasskeyManageStoreApiController::class, $controller);

        return $controller;
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
    private function enrollPasskey(string $customerId, string $name): string
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
            $name,
            $context
        );

        $credential = $this->credentials()->listOwned(Realm::Customer, $customerId, $context)->first();
        self::assertNotNull($credential);

        return $credential->getId();
    }

    /**
     * The controller's `CustomerEntity $customer` argument is what
     * CustomerValueResolver yields at runtime: the context's customer.
     */
    private function customerOf(SalesChannelContext $context): CustomerEntity
    {
        $customer = $context->getCustomer();
        self::assertInstanceOf(CustomerEntity::class, $customer);

        return $customer;
    }

    /**
     * Loads the CustomerEntity directly by id, bypassing
     * SalesChannelContextFactory::loadCustomer() — which silently drops an
     * inactive customer instead of returning it. Only used where the test
     * targets the eligibility guard for a customer the context factory itself
     * would never resolve.
     */
    private function customerById(string $customerId): CustomerEntity
    {
        /** @var EntityRepository<CustomerCollection> $customerRepository */
        $customerRepository = $this->getContainer()->get('customer.repository');
        $customer = $customerRepository->search(new Criteria([$customerId]), Context::createDefaultContext())
            ->getEntities()
            ->first();
        self::assertInstanceOf(CustomerEntity::class, $customer);

        return $customer;
    }

    private function createCustomerContext(string $customerId): SalesChannelContext
    {
        // The `SalesChannelContextFactory` id is an alias for the cached decorator,
        // so assert against the abstract base rather than the concrete class.
        $factory = $this->getContainer()->get(SalesChannelContextFactory::class);
        self::assertInstanceOf(AbstractSalesChannelContextFactory::class, $factory);

        return $factory->create(Uuid::randomHex(), TestDefaults::SALES_CHANNEL, [
            SalesChannelContextService::CUSTOMER_ID => $customerId,
        ]);
    }

    private function buildHostRequest(): Request
    {
        return Request::create('/store-api/act-passkey/register', 'POST', [], [], [], [
            'HTTP_HOST' => $this->host . ':8000',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function guestRegistrationPayload(): array
    {
        return [
            'guest' => true,
            'salutationId' => $this->getValidSalutationId(),
            'firstName' => 'Gast',
            'lastName' => 'Nutzer',
            'email' => Uuid::randomHex() . '@example.test',
            'storefrontUrl' => 'http://localhost',
            'billingAddress' => [
                'countryId' => $this->getValidCountryId(),
                'street' => 'Musterstraße 1',
                'zipcode' => '12345',
                'city' => 'Schöppingen',
            ],
        ];
    }

    /**
     * `customer_id` has a real FK to `customer`, so owner ids must be real rows.
     * Explicitly `active` and `boundSalesChannelId=null` so the customer resolves
     * under the storefront sales-channel context built for the controller calls.
     *
     * @param array<string, mixed> $overrides merged over the default row, e.g. the
     *     double-opt-in columns, so eligibility-guard tests can build a
     *     non-eligible customer.
     */
    private function createCustomerRow(array $overrides = []): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();

        /** @var EntityRepository<CustomerCollection> $customerRepository */
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
}
