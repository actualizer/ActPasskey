<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialCollection;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;

/**
 * @internal
 */
final class RegistrationStoresRpIdTest extends TestCase
{
    use IntegrationTestBehaviour;

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        $appUrl = (string) static::getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    public function testRegisteredCredentialCarriesTheRelyingPartyId(): void
    {
        $context = Context::createCLIContext();
        $customerId = $this->createCustomer();

        $this->registerPasskey($customerId, $context);

        /** @var EntityRepository<PasskeyCredentialCollection> $repository */
        $repository = static::getContainer()->get('act_passkey_credential.repository');
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('realm', Realm::Customer->value))
            ->addFilter(new EqualsFilter('customerId', $customerId));

        $credential = $repository->search($criteria, $context)->first();

        static::assertNotNull($credential);
        static::assertSame(strtolower($this->host), $credential->getRpId());
    }

    private function registerPasskey(string $customerId, Context $ctx): void
    {
        $reg = static::getContainer()->get(RegistrationCeremony::class);
        static::assertInstanceOf(RegistrationCeremony::class, $reg);

        $create = $reg->createOptions(Realm::Customer, $customerId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Customer, $customerId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);
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
}
