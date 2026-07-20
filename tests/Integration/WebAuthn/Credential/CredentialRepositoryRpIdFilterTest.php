<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Credential;

use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;

/**
 * @internal
 */
final class CredentialRepositoryRpIdFilterTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testListHidesCredentialsOfAnotherChannelButKeepsLegacyRows(): void
    {
        $context = Context::createCLIContext();
        $customerId = $this->createCustomer();
        $repository = static::getContainer()->get(CredentialRepository::class);
        static::assertInstanceOf(CredentialRepository::class, $repository);

        $this->insertCredential($customerId, 'shopa.de', 'A');
        $this->insertCredential($customerId, 'shopb.de', 'B');
        $this->insertCredential($customerId, null, 'legacy');

        $names = [];
        foreach ($repository->listOwned(Realm::Customer, $customerId, $context, 'shopa.de') as $credential) {
            $names[] = $credential->getName();
        }
        sort($names);

        // The legacy row stays visible: filtering is display logic, and must never
        // make a credential unmanageable.
        static::assertSame(['A', 'legacy'], $names);
    }

    public function testWithoutAnRpIdEverythingIsListed(): void
    {
        $context = Context::createCLIContext();
        $customerId = $this->createCustomer();
        $repository = static::getContainer()->get(CredentialRepository::class);
        static::assertInstanceOf(CredentialRepository::class, $repository);

        $this->insertCredential($customerId, 'shopa.de', 'A');
        $this->insertCredential($customerId, 'shopb.de', 'B');

        static::assertCount(2, $repository->listOwned(Realm::Customer, $customerId, $context));
    }

    private function insertCredential(string $customerId, ?string $rpId, string $name): void
    {
        /** @var EntityRepository<\Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialCollection> $repository */
        $repository = static::getContainer()->get('act_passkey_credential.repository');

        Context::createCLIContext()->scope(Context::SYSTEM_SCOPE, function (Context $systemContext) use ($repository, $customerId, $rpId, $name): void {
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
        });
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
