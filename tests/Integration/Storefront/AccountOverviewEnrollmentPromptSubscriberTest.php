<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Storefront;

use Actualize\Passkey\Subscriber\Storefront\AccountOverviewEnrollmentPromptSubscriber;
use Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony\SoftwareAuthenticator;
use Actualize\Passkey\WebAuthn\Ceremony\RegistrationCeremony;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\Customer\CustomerCollection;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SalesChannel\Context\AbstractSalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextService;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Shopware\Core\Test\TestDefaults;
use Shopware\Storefront\Page\Account\Overview\AccountOverviewPage;
use Shopware\Storefront\Page\Account\Overview\AccountOverviewPageLoadedEvent;
use Symfony\Component\HttpFoundation\Request;

/**
 * @internal
 */
final class AccountOverviewEnrollmentPromptSubscriberTest extends TestCase
{
    use IntegrationTestBehaviour;

    private const KEY = 'ActPasskey.config.enrollmentPrompt';

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        $appUrl = (string) static::getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');
    }

    public function testShownWhenAllConditionsHold(): void
    {
        $customerId = $this->createCustomerRow();

        $extension = $this->decide($this->contextFor($customerId));

        static::assertNotNull($extension);
        $key = $extension->get('dismissKey');
        static::assertIsString($key);
        static::assertMatchesRegularExpression('/^act-passkey-enrollment-prompt-[0-9a-f]{16}$/', $key);
        static::assertStringNotContainsString($customerId, $key);
    }

    public function testShownWhenTheSettingWasNeverSaved(): void
    {
        $config = $this->config();
        $config->delete(self::KEY);
        $config->delete(self::KEY, TestDefaults::SALES_CHANNEL);

        static::assertNull($config->get(self::KEY, TestDefaults::SALES_CHANNEL));
        static::assertNotNull($this->decide($this->contextFor($this->createCustomerRow())));
    }

    public function testHiddenWhenSwitchedOffForTheSalesChannel(): void
    {
        $this->config()->set(self::KEY, false, TestDefaults::SALES_CHANNEL);

        static::assertNull($this->decide($this->contextFor($this->createCustomerRow())));
    }

    public function testHiddenWhenTheCustomerHasAPasskeyHere(): void
    {
        $customerId = $this->createCustomerRow();
        $this->enrollPasskey($customerId);

        static::assertNull($this->decide($this->contextFor($customerId)));
    }

    public function testShownWhenTheOnlyPasskeyIsBoundToAnotherDomain(): void
    {
        $customerId = $this->createCustomerRow();
        $this->insertCredentialRow($customerId, 'retired.example');

        static::assertNotNull($this->decide($this->contextFor($customerId)));
    }

    public function testHiddenOnAnUncoveredHost(): void
    {
        $context = $this->contextFor($this->createCustomerRow());

        static::assertNull($this->decide($context, 'unknown.invalid'));
    }

    public function testHiddenWhileAnOperatorImitatesTheCustomer(): void
    {
        $context = $this->contextFor($this->createCustomerRow(), [
            SalesChannelContextService::IMITATING_USER_ID => Uuid::randomHex(),
        ]);

        static::assertNull($this->decide($context));
    }

    public function testHiddenForGuests(): void
    {
        $customerId = $this->createCustomerRow(['guest' => true]);

        static::assertNull($this->decide($this->contextFor($customerId)));
    }

    public function testHiddenForAnUnconfirmedDoubleOptInCustomer(): void
    {
        $customerId = $this->createCustomerRow([
            'doubleOptInRegistration' => true,
            'doubleOptInConfirmDate' => null,
        ]);

        static::assertNull($this->decide($this->contextFor($customerId)));
    }

    private function decide(SalesChannelContext $context, ?string $host = null): ?ArrayStruct
    {
        $subscriber = static::getContainer()->get(AccountOverviewEnrollmentPromptSubscriber::class);
        static::assertInstanceOf(AccountOverviewEnrollmentPromptSubscriber::class, $subscriber);

        $request = Request::create('/account', 'GET', [], [], [], ['HTTP_HOST' => ($host ?? $this->host) . ':8000']);
        $page = new AccountOverviewPage();
        $subscriber->onOverviewLoaded(new AccountOverviewPageLoadedEvent($page, $context, $request));

        $extension = $page->getExtension('actPasskeyEnrollmentPrompt');
        if ($extension === null) {
            return null;
        }
        static::assertInstanceOf(ArrayStruct::class, $extension);

        return $extension;
    }

    private function config(): SystemConfigService
    {
        $config = static::getContainer()->get(SystemConfigService::class);
        static::assertInstanceOf(SystemConfigService::class, $config);

        return $config;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function contextFor(string $customerId, array $options = []): SalesChannelContext
    {
        $factory = static::getContainer()->get(SalesChannelContextFactory::class);
        static::assertInstanceOf(AbstractSalesChannelContextFactory::class, $factory);

        return $factory->create(Uuid::randomHex(), TestDefaults::SALES_CHANNEL, array_merge([
            SalesChannelContextService::CUSTOMER_ID => $customerId,
        ], $options));
    }

    private function enrollPasskey(string $customerId): void
    {
        $context = Context::createDefaultContext();
        $ceremony = static::getContainer()->get(RegistrationCeremony::class);
        static::assertInstanceOf(RegistrationCeremony::class, $ceremony);

        $create = $ceremony->createOptions(Realm::Customer, $customerId, $this->host, $context);
        $ceremony->verify(
            Realm::Customer,
            $customerId,
            SoftwareAuthenticator::respondToCreate($create['options'], $this->origin),
            $create['challengeId'],
            $this->host,
            'Test Key',
            $context
        );
    }

    private function insertCredentialRow(string $customerId, string $rpId): void
    {
        $repository = static::getContainer()->get('act_passkey_credential.repository');
        static::assertInstanceOf(EntityRepository::class, $repository);

        Context::createDefaultContext()->scope(
            Context::SYSTEM_SCOPE,
            function (Context $systemContext) use ($repository, $customerId, $rpId): void {
                $repository->create([[
                    'id' => Uuid::randomHex(),
                    'realm' => Realm::Customer->value,
                    'rpId' => $rpId,
                    'customerId' => $customerId,
                    'credentialId' => random_bytes(32),
                    'publicKey' => random_bytes(64),
                    'signCount' => 0,
                    'userHandle' => random_bytes(32),
                    'name' => 'Retired',
                ]], $systemContext);
            }
        );
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function createCustomerRow(array $overrides = []): string
    {
        $customerId = Uuid::randomHex();
        $addressId = Uuid::randomHex();

        /** @var EntityRepository<CustomerCollection> $customerRepository */
        $customerRepository = static::getContainer()->get('customer.repository');
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
