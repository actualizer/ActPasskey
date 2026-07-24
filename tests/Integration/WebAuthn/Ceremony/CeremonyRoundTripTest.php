<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony;

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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CounterException;

final class CeremonyRoundTripTest extends TestCase
{
    use IntegrationTestBehaviour;

    private string $host;

    private string $origin;

    protected function setUp(): void
    {
        SoftwareAuthenticator::reset();

        // In APP_ENV=test, %APP_URL% = http://127.0.0.1:8000 (host 127.0.0.1).
        // Derive host + origin from the container parameter so the test stays
        // robust against env changes.
        $appUrl = (string) $this->getContainer()->getParameter('APP_URL');
        $this->host = (string) parse_url($appUrl, PHP_URL_HOST);
        $this->origin = rtrim($appUrl, '/');

        // ChallengeStore is session-bound; push a request carrying a session.
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        $this->getContainer()->get('request_stack')->push($request);
    }

    public function testRegisterThenAuthenticateResolvesSameAccount(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $create = $reg->createOptions(Realm::Admin, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Admin, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asgJson = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);
        $resolved = $auth->verify(Realm::Admin, $asgJson, $req['challengeId'], $this->host, $ctx);

        self::assertSame($accountId, $resolved);
    }

    public function testCustomerRealmRoundTrip(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createCustomer();

        $create = $reg->createOptions(Realm::Customer, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Customer, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        $req = $auth->createOptions(Realm::Customer, $this->host, $ctx);
        $asgJson = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);
        $resolved = $auth->verify(Realm::Customer, $asgJson, $req['challengeId'], $this->host, $ctx);

        self::assertSame($accountId, $resolved);
    }

    public function testCustomerCredentialRejectedAtAdminRealm(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $ctx = Context::createDefaultContext();
        $customerId = $this->createCustomer();

        $create = $reg->createOptions(Realm::Customer, $customerId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Customer, $customerId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        // Present the CUSTOMER credential's assertion at the ADMIN realm. The
        // realm-scoped lookup returns null, so verification must abort.
        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asgJson = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        $this->expectException(\RuntimeException::class);
        $auth->verify(Realm::Admin, $asgJson, $req['challengeId'], $this->host, $ctx);
    }

    public function testCredentialBoundToForeignRpIdIsRejected(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $credentials = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $create = $reg->createOptions(Realm::Admin, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Admin, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        // Rebind the stored credential to a DIFFERENT relying party, standing in
        // for a key enrolled on another sales-channel domain of the same install.
        // The authenticator still signs for the host's own rp id, so the library's
        // rpIdHash check passes — only the stored-vs-resolved binding can catch it.
        $enrolled = $credentials->listOwned(Realm::Admin, $accountId, $ctx)->first();
        self::assertNotNull($enrolled);
        $this->setStoredRpId($enrolled->getId(), 'foreign.example');

        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asgJson = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('bound to a different relying party');
        $auth->verify(Realm::Admin, $asgJson, $req['challengeId'], $this->host, $ctx);
    }

    public function testLegacyCredentialWithoutStoredRpIdStillAuthenticates(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $credentials = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $create = $reg->createOptions(Realm::Admin, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Admin, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        // A pre-Migration1752624300 row carries no stored rp id; the binding check
        // must skip NULL so those users are not locked out of their passkey.
        $enrolled = $credentials->listOwned(Realm::Admin, $accountId, $ctx)->first();
        self::assertNotNull($enrolled);
        $this->setStoredRpId($enrolled->getId(), null);

        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asgJson = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);

        self::assertSame($accountId, $auth->verify(Realm::Admin, $asgJson, $req['challengeId'], $this->host, $ctx));
    }

    public function testCounterRegressionRejected(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $create = $reg->createOptions(Realm::Admin, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Admin, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        // First auth advances the stored counter to 5.
        $req1 = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asg1 = SoftwareAuthenticator::respondToGet($req1['options'], $this->origin, 5);
        self::assertSame($accountId, $auth->verify(Realm::Admin, $asg1, $req1['challengeId'], $this->host, $ctx));

        // Replay with a non-increasing counter -> library CheckCounter throws.
        $req2 = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asg2 = SoftwareAuthenticator::respondToGet($req2['options'], $this->origin, 5);

        $this->expectException(CounterException::class);
        $auth->verify(Realm::Admin, $asg2, $req2['challengeId'], $this->host, $ctx);
    }

    public function testWrongOriginRejected(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $create = $reg->createOptions(Realm::Admin, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Admin, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asgJson = SoftwareAuthenticator::respondToGet($req['options'], 'https://evil.test');

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $auth->verify(Realm::Admin, $asgJson, $req['challengeId'], $this->host, $ctx);
    }

    public function testAssertionCanTargetAnEarlierEnrolledCredential(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $first = $this->enrollAndReturnCredentialId($reg, $ctx, $accountId, 'First key');
        $this->enrollAndReturnCredentialId($reg, $ctx, $accountId, 'Second key');

        $request = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $assertion = SoftwareAuthenticator::respondToGet($request['options'], $this->origin, 1, $first);

        $resolved = $auth->verify(
            Realm::Admin,
            $assertion,
            $request['challengeId'],
            $this->host,
            $ctx
        );

        self::assertSame($accountId, $resolved);

        /** @var array{id: string} $decodedAssertion */
        $decodedAssertion = json_decode($assertion, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame($first, $decodedAssertion['id']);
    }

    public function testCreateOptionsCarriesTheHumanReadableDisplayName(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $create = $reg->createOptions(
            Realm::Admin,
            $accountId,
            $this->host,
            $ctx,
            'Ada Lovelace',
            'ada@example.com'
        );

        $options = json_decode($create['options'], true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('ada@example.com', $options['user']['name']);
        self::assertSame('Ada Lovelace', $options['user']['displayName']);
        // The user handle must stay opaque random bytes — never the email/name.
        self::assertNotSame('ada@example.com', $options['user']['id']);
    }

    public function testSuccessfulAssertionStampsLastUsedAt(): void
    {
        $reg = $this->getContainer()->get(RegistrationCeremony::class);
        $auth = $this->getContainer()->get(AuthenticationCeremony::class);
        $credentials = $this->getContainer()->get(CredentialRepository::class);
        $ctx = Context::createDefaultContext();
        $accountId = $this->createAdminUser();

        $create = $reg->createOptions(Realm::Admin, $accountId, $this->host, $ctx);
        $attJson = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Admin, $accountId, $attJson, $create['challengeId'], $this->host, 'Test Key', $ctx);

        $enrolled = $credentials->listOwned(Realm::Admin, $accountId, $ctx)->first();
        self::assertNotNull($enrolled);
        self::assertNull($enrolled->getLastUsedAt(), 'registration must not stamp last_used_at');

        $req = $auth->createOptions(Realm::Admin, $this->host, $ctx);
        $asgJson = SoftwareAuthenticator::respondToGet($req['options'], $this->origin);
        $auth->verify(Realm::Admin, $asgJson, $req['challengeId'], $this->host, $ctx);

        $afterAssertion = $credentials->listOwned(Realm::Admin, $accountId, $ctx)->first();
        self::assertNotNull($afterAssertion);
        self::assertNotNull($afterAssertion->getLastUsedAt(), 'successful assertion must stamp last_used_at');
    }

    /**
     * Enrolls a credential for the given account via a real create+verify round
     * trip and returns its base64url credential id, so a later assertion can
     * target this specific key instead of whichever one was enrolled last.
     */
    private function enrollAndReturnCredentialId(
        RegistrationCeremony $reg,
        Context $ctx,
        string $accountId,
        string $name
    ): string {
        $create = $reg->createOptions(Realm::Admin, $accountId, $this->host, $ctx);
        $attestation = SoftwareAuthenticator::respondToCreate($create['options'], $this->origin);
        $reg->verify(Realm::Admin, $accountId, $attestation, $create['challengeId'], $this->host, $name, $ctx);

        return SoftwareAuthenticator::lastCredentialId();
    }

    /**
     * Directly rewrites the stored rp id of a credential, standing in for a key
     * enrolled on a different domain (foreign value) or before the rp-id
     * migration (null). Writes open the system scope — the definition denies
     * rp-id writes on the plain /api scope.
     */
    private function setStoredRpId(string $id, ?string $rpId): void
    {
        /** @var EntityRepository<\Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialCollection> $repository */
        $repository = $this->getContainer()->get('act_passkey_credential.repository');

        Context::createCLIContext()->scope(Context::SYSTEM_SCOPE, function (Context $systemContext) use ($repository, $id, $rpId): void {
            $repository->update([['id' => $id, 'rpId' => $rpId]], $systemContext);
        });
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
