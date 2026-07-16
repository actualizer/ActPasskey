<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Storefront;

use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;
use Shopware\Storefront\Test\Controller\StorefrontControllerTestBehaviour;

/**
 * Behavioural proof of the storefront passkey login controller. Unlike Task 1's
 * CustomerPasskeyLoginRouteTest (direct controller call), this exercises the
 * REAL HTTP/routing layer: requests go through the kernel via a KernelBrowser
 * (StorefrontControllerTestBehaviour::request()), resolving the actual
 * storefront sales channel by domain (http://127.0.0.1:8000) and carrying a
 * real PHP session/cookie jar across requests, so login state genuinely
 * persists the way a browser session would.
 *
 * The storefront domain's sales channel differs from TestDefaults::SALES_CHANNEL
 * (a headless one) — the test customer is created UNBOUND
 * (boundSalesChannelId=null), which AccountService::fetchCustomer() accepts
 * for any sales channel context, so login succeeds against the real
 * domain-resolved storefront channel.
 */
final class PasskeyStorefrontControllerTest extends TestCase
{
    use IntegrationTestBehaviour;
    use StorefrontControllerTestBehaviour;

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        // In APP_ENV=test, %APP_URL% = http://127.0.0.1:8000 (host 127.0.0.1),
        // which also matches the storefront sales_channel_domain row's url —
        // required for both rpId resolution and real HTTP domain routing.
        $appUrl = (string) $this->getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    public function testChallengeRouteReturnsOptionsAndChallengeId(): void
    {
        $response = $this->request('POST', 'account/login/passkey/challenge', []);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsArray($data);
        self::assertArrayHasKey('options', $data);
        self::assertArrayHasKey('challengeId', $data);
        self::assertNotEmpty($data['challengeId']);
    }

    public function testCustomerCanLoginWithRegisteredPasskeyAndSessionPersists(): void
    {
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer();
        $this->registerPasskey($customerId, $ctx);

        [$assertion, $challengeId] = $this->buildAssertion($ctx);

        $loginResponse = $this->request('POST', 'account/login/passkey', [
            'passkey_response' => $assertion,
            'passkey_challenge_id' => $challengeId,
        ]);

        self::assertSame(302, $loginResponse->getStatusCode(), (string) $loginResponse->getContent());
        self::assertStringContainsString('/account', (string) $loginResponse->headers->get('Location'));

        // Same browser instance (test.client is a container singleton) carries
        // the session cookie forward. /account is _loginRequired — reaching it
        // with 200 (no further redirect to the login page) proves the login
        // actually stuck in the session, not just that the controller replied 302.
        $accountResponse = $this->request('GET', 'account', []);
        self::assertSame(200, $accountResponse->getStatusCode(), (string) $accountResponse->getContent());
    }

    /**
     * Mirrors the stock component/account/login.html.twig hidden `redirectTo`
     * field: a passkey login triggered from checkout/product-review must
     * return the user to that redirectTo target instead of always bouncing
     * to the account home page (PasskeyStorefrontController::login() now
     * delegates to createActionResponse(), same as AuthController::login()).
     */
    public function testCustomerCanLoginWithRedirectToTargetIsHonored(): void
    {
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer();
        $this->registerPasskey($customerId, $ctx);

        [$assertion, $challengeId] = $this->buildAssertion($ctx);

        $loginResponse = $this->request('POST', 'account/login/passkey', [
            'passkey_response' => $assertion,
            'passkey_challenge_id' => $challengeId,
            'redirectTo' => 'frontend.account.profile.page',
        ]);

        self::assertSame(302, $loginResponse->getStatusCode(), (string) $loginResponse->getContent());
        self::assertStringContainsString('/account/profile', (string) $loginResponse->headers->get('Location'));
    }

    public function testBogusChallengeIdForwardsToLoginPageWithoutLoggingIn(): void
    {
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer();
        $this->registerPasskey($customerId, $ctx);

        [$assertion, ] = $this->buildAssertion($ctx);

        $loginResponse = $this->request('POST', 'account/login/passkey', [
            'passkey_response' => $assertion,
            'passkey_challenge_id' => Uuid::randomHex(),
        ]);

        // forwardToRoute() renders the login page in-process; it must NOT be
        // the redirect the success path returns.
        self::assertNotSame(302, $loginResponse->getStatusCode());

        // No session was established — a login-required page must still
        // bounce to the login page.
        $accountResponse = $this->request('GET', 'account', []);
        self::assertSame(302, $accountResponse->getStatusCode());
        self::assertStringContainsString('/account/login', (string) $accountResponse->headers->get('Location'));
    }

    /**
     * @return array{0: string, 1: string} assertion JSON + challengeId
     */
    private function buildAssertion(Context $ctx): array
    {
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $req = $auth->createOptions(Realm::Customer, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        return [$assertion, $req['challengeId']];
    }

    private function registerPasskey(string $customerId, Context $ctx): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $create = $reg->createOptions(Realm::Customer, $customerId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Customer, $customerId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);
    }

    /**
     * `customer_id` has a real FK to `customer`, so owner ids must be real
     * rows. Mirrors CustomerPasskeyLoginRouteTest::createCustomer(): explicitly
     * `active` (required for AccountService::loginById -> fetchCustomer to
     * accept it) and `boundSalesChannelId=null` (unbound, so it resolves under
     * the REAL storefront sales-channel context the domain-routed HTTP request
     * resolves — which is not TestDefaults::SALES_CHANNEL).
     */
    private function createCustomer(): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();

        /** @var EntityRepository $customerRepository */
        $customerRepository = $this->getContainer()->get('customer.repository');
        $customerRepository->create([[
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
        ]], Context::createDefaultContext());

        return $customerId;
    }
}
