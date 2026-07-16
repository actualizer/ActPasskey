<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Storefront;

use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;
use Shopware\Storefront\Test\Controller\StorefrontControllerTestBehaviour;

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

        $authentication = $this->getContainer()->get(AuthenticationCeremony::class);
        self::assertInstanceOf(AuthenticationCeremony::class, $authentication);
        $request = $authentication->createOptions(Realm::Customer, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($request['options'], $this->origin);

        $loginResponse = $this->request('POST', 'account/login/passkey', [
            'passkey_response' => $assertion,
            'passkey_challenge_id' => $request['challengeId'],
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
