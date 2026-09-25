<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Storefront;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialEntity;
use Actualize\Passkey\Subscriber\Storefront\AccountProfilePasskeysSubscriber;
use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SalesChannel\Context\AbstractSalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextService;
use Shopware\Core\Test\TestDefaults;
use Shopware\Storefront\Page\Account\Profile\AccountProfilePage;
use Shopware\Storefront\Page\Account\Profile\AccountProfilePageLoadedEvent;
use Shopware\Storefront\Test\Controller\StorefrontControllerTestBehaviour;
use Symfony\Component\HttpFoundation\Request;
use Twig\Environment;

/**
 * Behavioural proof of the customer-facing passkey management card: a real
 * KernelBrowser session (established the same way PasskeyStorefrontControllerTest
 * does — via a throwaway passkey login, so no parallel login helper is invented)
 * registers a SECOND passkey through the new frontend.account.passkey.register
 * route and lands back on the profile page with the expected flash.
 */
final class PasskeyManageStorefrontControllerTest extends TestCase
{
    use IntegrationTestBehaviour;
    use StorefrontControllerTestBehaviour;

    private const PLAIN_PASSWORD = 'shopware';

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        // In APP_ENV=test, %APP_URL% = http://127.0.0.1:8000 (host 127.0.0.1),
        // matching the storefront sales_channel_domain row's url.
        $appUrl = (string) $this->getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    public function testCustomerCanRegisterPasskeyAndGetsRedirectedWithSuccessFlash(): void
    {
        $customerId = $this->createLoggedInCustomer();

        $ceremony = $this->getContainer()->get(RegistrationCeremony::class);
        self::assertInstanceOf(RegistrationCeremony::class, $ceremony);

        $create = $ceremony->createOptions(Realm::Customer, $customerId, $this->host, Context::createDefaultContext());
        $attestation = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);

        $response = $this->request('POST', 'account/passkey/register', [
            'password' => self::PLAIN_PASSWORD,
            'passkey_response' => $attestation,
            'passkey_challenge_id' => $create['challengeId'],
            'name' => 'My Laptop',
        ]);

        self::assertSame(302, $response->getStatusCode(), (string) $response->getContent());
        self::assertStringContainsString('/account/profile', (string) $response->headers->get('Location'));

        // Registering the LOGIN passkey during setUp() plus this one means two
        // rows exist in total; the one under test is identified by name.
        $owned = $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext());
        $names = [];
        foreach ($owned as $credential) {
            $names[] = $credential->getName();
        }
        self::assertContains('My Laptop', $names);

        // The test storefront domain resolves the en_GB storefront snippet set.
        $profileResponse = $this->request('GET', 'account/profile', []);
        self::assertSame(200, $profileResponse->getStatusCode());
        self::assertStringContainsString('Passkey registered', (string) $profileResponse->getContent());
    }

    public function testWrongPasswordProducesErrorFlashAndNoCredential(): void
    {
        $customerId = $this->createLoggedInCustomer();
        $beforeCount = $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext())->count();

        $response = $this->request('POST', 'account/passkey/register', [
            'password' => 'definitely-not-the-password',
            'passkey_response' => '{}',
            'passkey_challenge_id' => Uuid::randomHex(),
            'name' => 'Should not be created',
        ]);

        self::assertSame(302, $response->getStatusCode(), (string) $response->getContent());
        self::assertStringContainsString('/account/profile', (string) $response->headers->get('Location'));

        // No new row: the wrong password must be rejected before any WebAuthn
        // verification is even attempted.
        self::assertSame(
            $beforeCount,
            $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext())->count()
        );

        // The test storefront domain resolves the en_GB storefront snippet set.
        $profileResponse = $this->request('GET', 'account/profile', []);
        self::assertSame(200, $profileResponse->getStatusCode());
        self::assertStringContainsString('could not be completed', (string) $profileResponse->getContent());
    }

    public function testOverLongRenameShowsAnErrorFlashAndKeepsTheName(): void
    {
        $customerId = $this->createLoggedInCustomer();
        $credential = $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext())->first();
        self::assertNotNull($credential);

        $response = $this->request('POST', 'account/passkey/' . $credential->getId() . '/rename', [
            'name' => str_repeat('a', CredentialRepository::MAX_NAME_LENGTH + 1),
        ]);

        self::assertSame(302, $response->getStatusCode(), (string) $response->getContent());
        self::assertStringContainsString('/account/profile', (string) $response->headers->get('Location'));

        $stored = $this->credentials()->listOwned(Realm::Customer, $customerId, Context::createDefaultContext())->first();
        self::assertSame('Login Key', $stored?->getName());

        // The test storefront domain resolves the en_GB storefront snippet set.
        $profile = (string) $this->request('GET', 'account/profile', [])->getContent();
        self::assertStringContainsString('could not be completed', $profile);
        self::assertStringNotContainsString('Passkey renamed.', $profile);
    }

    public function testOrphanedCredentialShowsTheNoteOnTheProfilePage(): void
    {
        $customerId = $this->createLoggedInCustomer();

        $this->insertCredentialRow($customerId, 'retired.invalid', 'Old device');

        $profileResponse = $this->request('GET', 'account/profile', []);
        self::assertSame(200, $profileResponse->getStatusCode());

        $body = (string) $profileResponse->getContent();
        self::assertStringContainsString('Old device', $body);
        // The en-GB orphaned note (the test storefront resolves the en_GB snippet set).
        self::assertStringContainsString('no longer active', $body);
    }

    public function testRegisterBlockIsPresentOnASupportedHost(): void
    {
        $this->createLoggedInCustomer();

        $profileResponse = $this->request('GET', 'account/profile', []);
        self::assertSame(200, $profileResponse->getStatusCode());

        // The test storefront runs on the APP_URL host, which resolves, so the add
        // control must be rendered (server-side hidden; the JS reveals it).
        self::assertStringContainsString('data-act-passkey-manage-register', (string) $profileResponse->getContent());
    }

    /**
     * The harness re-derives HTTP_HOST from the fully-qualified APP_URL URI, so an
     * unsupported host cannot be observed over HTTP; asserted at subscriber level instead.
     */
    public function testRegisterBlockIsHiddenOnAnUnsupportedHostButTheListRemains(): void
    {
        $customerId = $this->createCustomerRow();

        $subscriber = $this->getContainer()->get(AccountProfilePasskeysSubscriber::class);
        self::assertInstanceOf(AccountProfilePasskeysSubscriber::class, $subscriber);

        $factory = $this->getContainer()->get(SalesChannelContextFactory::class);
        self::assertInstanceOf(AbstractSalesChannelContextFactory::class, $factory);
        $context = $factory->create(Uuid::randomHex(), TestDefaults::SALES_CHANNEL, [
            SalesChannelContextService::CUSTOMER_ID => $customerId,
        ]);

        $request = Request::create('/account/profile', 'GET', [], [], [], ['HTTP_HOST' => 'unresolvable.invalid']);
        $page = new AccountProfilePage();
        $event = new AccountProfilePageLoadedEvent($page, $context, $request);

        $subscriber->onProfileLoaded($event);

        $supported = $page->getExtension('actPasskeySupported');
        self::assertInstanceOf(ArrayStruct::class, $supported);
        self::assertFalse($supported->get('supported'));
    }

    /**
     * Renders the real profile card block directly through Twig, the only way to
     * observe the unsupported-host direction (the HTTP harness always resolves the
     * APP_URL host to supported=true). Proves the {% if supported %} gate is not a
     * silent no-op: the add block appears only when supported is true.
     */
    public function testRegisterBlockRendersOnlyWhenSupported(): void
    {
        $supportedHtml = $this->renderPasskeyCard(true);
        $unsupportedHtml = $this->renderPasskeyCard(false);

        self::assertStringContainsString('data-act-passkey-manage-register', $supportedHtml);
        self::assertStringNotContainsString('data-act-passkey-manage-register', $unsupportedHtml);

        // The list (and its per-row delete form) survives in BOTH cases, so an
        // unsupported host never makes an existing credential unmanageable.
        self::assertStringContainsString('data-act-passkey-delete-form', $supportedHtml);
        self::assertStringContainsString('data-act-passkey-delete-form', $unsupportedHtml);
    }

    private function renderPasskeyCard(bool $supported): string
    {
        $twig = $this->getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);

        $credential = new PasskeyCredentialEntity();
        $credential->setId(Uuid::randomHex());
        $credential->setName('Kept device');
        $credential->setLastUsedAt(null);

        $page = new AccountProfilePage();
        $page->addExtension('actPasskeyCredentials', new ArrayStruct([
            'credentials' => [$credential],
            'orphanedIds' => [],
        ]));
        $page->addExtension('actPasskeySupported', new ArrayStruct([
            'supported' => $supported,
        ]));

        return $twig->load('@ActPasskey/storefront/page/account/profile/index.html.twig')
            ->renderBlock('page_account_profile_passkeys', ['page' => $page]);
    }

    private function insertCredentialRow(string $customerId, string $rpId, string $name): void
    {
        $repository = $this->getContainer()->get('act_passkey_credential.repository');
        self::assertInstanceOf(EntityRepository::class, $repository);

        Context::createDefaultContext()->scope(
            Context::SYSTEM_SCOPE,
            function (Context $systemContext) use ($repository, $customerId, $rpId, $name): void {
                $repository->create([[
                    'id' => Uuid::randomHex(),
                    'realm' => Realm::Customer->value,
                    'rpId' => $rpId,
                    'customerId' => $customerId,
                    'credentialId' => random_bytes(32),
                    'publicKey' => random_bytes(64),
                    'signCount' => 0,
                    'userHandle' => random_bytes(32),
                    'name' => $name,
                ]], $systemContext);
            }
        );
    }

    private function credentials(): CredentialRepository
    {
        $service = $this->getContainer()->get(CredentialRepository::class);
        self::assertInstanceOf(CredentialRepository::class, $service);

        return $service;
    }

    /**
     * Creates a customer and establishes a REAL browser session via the
     * storefront passkey login (same mechanism PasskeyStorefrontControllerTest
     * uses), so `_loginRequired` on the routes under test is satisfied by an
     * actual session cookie, not a bypassed context.
     */
    private function createLoggedInCustomer(): string
    {
        $customerId = $this->createCustomerRow();
        $ctx = Context::createDefaultContext();

        $registration = $this->getContainer()->get(RegistrationCeremony::class);
        self::assertInstanceOf(RegistrationCeremony::class, $registration);
        $create = $registration->createOptions(Realm::Customer, $customerId, $this->host, $ctx);
        $attestation = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $registration->verify(Realm::Customer, $customerId, $attestation, $create['challengeId'], $this->host, 'Login Key', $ctx);

        // Through the real challenge route: the challenge is bound to this browser
        // session's context token, which the login POST then carries.
        $challenge = $this->request('POST', 'account/login/passkey/challenge', []);
        self::assertSame(200, $challenge->getStatusCode(), (string) $challenge->getContent());
        $data = json_decode((string) $challenge->getContent(), true);
        self::assertIsArray($data);
        self::assertIsArray($data['options'] ?? null);
        self::assertIsString($data['challengeId'] ?? null);
        $assertion = SoftwareAuthenticator::respondToGet(json_encode($data['options'], JSON_THROW_ON_ERROR), $this->origin);

        $loginResponse = $this->request('POST', 'account/login/passkey', [
            'passkey_response' => $assertion,
            'passkey_challenge_id' => $data['challengeId'],
        ]);
        self::assertSame(302, $loginResponse->getStatusCode(), (string) $loginResponse->getContent());

        return $customerId;
    }

    /**
     * `customer_id` has a real FK to `customer`, so owner ids must be real
     * rows. Explicitly `active` and `boundSalesChannelId=null` so the customer
     * resolves under the real, domain-routed storefront sales-channel context.
     */
    private function createCustomerRow(): string
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
