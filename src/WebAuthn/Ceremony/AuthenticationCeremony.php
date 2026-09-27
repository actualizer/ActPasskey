<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialEntity;
use Actualize\Passkey\WebAuthn\Challenge\ChallengePurpose;
use Actualize\Passkey\WebAuthn\Challenge\ChallengeStore;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Shopware\Core\Framework\Context;
use Symfony\Component\Uid\Uuid as SymfonyUuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CredentialRecord;
use Webauthn\Exception\CounterException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Authentication ("assertion") ceremony: builds usernameless request options and
 * verifies the returned assertion.
 *
 * Realm boundary: the credential lookup is realm-scoped and the resolved account
 * id comes from the STORED row's owner — never from the userHandle carried in
 * the assertion. A credential from one realm is unusable in another.
 */
final class AuthenticationCeremony
{
    private const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000';

    public function __construct(
        private readonly CeremonyFactory $ceremonyFactory,
        private readonly ChallengeStore $challengeStore,
        private readonly CredentialRepository $credentials,
        private readonly RelyingPartyIdResolver $rpIdResolver,
        private readonly WebauthnSerializer $serializer,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * `$binding` (the customer's sales-channel context token) ties the challenge to
     * the context that requested it; verify() must then be called with the same
     * value. The admin realm passes none: its token endpoint is stateless.
     *
     * @return array{options: string, challengeId: string}
     */
    public function createOptions(Realm $realm, string $host, Context $context, ?string $binding = null): array
    {
        $challenge = random_bytes(32);
        $challengeId = $this->challengeStore->issue(
            $challenge,
            ChallengePurpose::Authentication,
            $realm,
            binding: $binding
        );
        $options = $this->buildOptions($realm, $host, $challenge, $context);

        return [
            'options' => $this->serializer->serializeOptions($options),
            'challengeId' => $challengeId,
        ];
    }

    /**
     * Writes the sign count (clone detection must not wait for the caller) but never
     * `lastUsedAt`: the caller stamps that via CredentialRepository::markUsed() once
     * it has accepted the account.
     */
    public function verify(
        Realm $realm,
        string $rawResponseJson,
        string $challengeId,
        string $host,
        Context $context,
        ?string $binding = null
    ): AuthenticationResult {
        $challenge = $this->challengeStore->consume($challengeId, ChallengePurpose::Authentication, $realm, $binding);
        if ($challenge === null) {
            throw new RuntimeException('Invalid or expired authentication challenge.');
        }

        $options = $this->buildOptions($realm, $host, $challenge, $context);

        $credential = $this->serializer->deserializeCredential($rawResponseJson);
        $response = $credential->response;
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new RuntimeException('The response is not an assertion response.');
        }

        $entity = $this->credentials->findOneByCredentialId($credential->rawId, $realm, $context);
        if ($entity === null) {
            throw new RuntimeException('Unknown credential for this realm.');
        }

        // A credential is bound to the relying party it was registered for. The
        // library validates the assertion's rpIdHash against the rp id of the
        // options, not the STORED one — so on a multi-domain install a key enrolled
        // for one sales-channel domain could otherwise authenticate on another if an
        // authenticator is induced to sign for that rp id. Compared against
        // `$options->rpId`: exactly the value the assertion is checked against. NULL
        // is a pre-Migration1752624300 legacy row with no stored binding and stays
        // usable so those owners are not locked out.
        if ($entity->getRpId() !== null && $entity->getRpId() !== $options->rpId) {
            throw new RuntimeException('Credential is bound to a different relying party.');
        }

        $record = $this->toCredentialRecord($entity);

        $validator = AuthenticatorAssertionResponseValidator::create(
            $this->ceremonyFactory->request($realm, $context)
        );
        // Last argument is the expected user handle: the validator enforces that
        // the assertion's own userHandle matches the stored one.
        try {
            $validator->check($record, $response, $options, $host, $entity->getUserHandle());
        } catch (CounterException $exception) {
            $this->markPossiblyCloned($entity, $context);

            throw $exception;
        }

        $this->credentials->updateSignCount(
            $entity->getId(),
            $response->authenticatorData->signCount,
            $context
        );

        $accountId = $this->ownerId($entity);
        if ($accountId === null) {
            throw new RuntimeException('Stored credential has no owner for its realm.');
        }

        return new AuthenticationResult($accountId, $entity->getId());
    }

    /**
     * A signature counter that did not go up means another copy of the key may be
     * signing too. The login stays refused (the exception is rethrown); the credential
     * is only marked, not disabled — some authenticators reset their counter, so the
     * owner or an operator decides whether to remove it.
     *
     * WARNING although this is a public route: webauthn-lib checks the signature before
     * the counter, so only a genuinely signed assertion of a stored key gets here and
     * bots cannot flood it. Logged before stamping, so the signal survives a failed write.
     */
    private function markPossiblyCloned(PasskeyCredentialEntity $entity, Context $context): void
    {
        $this->logger->warning('Passkey signature counter did not increase; the passkey may be cloned', [
            'credentialId' => $entity->getId(),
            'realm' => $entity->getRealm(),
            'ownerId' => $this->ownerId($entity),
        ]);

        $this->credentials->markPossiblyCloned($entity->getId(), $context, new \DateTimeImmutable());
    }

    private function ownerId(PasskeyCredentialEntity $entity): ?string
    {
        return $entity->getRealm() === Realm::Admin->value
            ? $entity->getUserId()
            : $entity->getCustomerId();
    }

    private function buildOptions(
        Realm $realm,
        string $host,
        string $challenge,
        Context $context
    ): PublicKeyCredentialRequestOptions {
        return PublicKeyCredentialRequestOptions::create(
            $challenge,
            $this->rpIdResolver->resolve($realm, $host, $context),
            [],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        );
    }

    private function toCredentialRecord(PasskeyCredentialEntity $entity): CredentialRecord
    {
        return CredentialRecord::create(
            $entity->getCredentialId(),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $entity->getTransports() ?? [],
            'none',
            EmptyTrustPath::create(),
            SymfonyUuid::fromString($entity->getAaguid() ?? self::ZERO_AAGUID),
            $entity->getPublicKey(),
            $entity->getUserHandle(),
            $entity->getSignCount(),
        );
    }
}
