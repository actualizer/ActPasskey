<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialEntity;
use Actualize\Passkey\WebAuthn\Challenge\ChallengePurpose;
use Actualize\Passkey\WebAuthn\Challenge\ChallengeStore;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use RuntimeException;
use Shopware\Core\Framework\Context;
use Symfony\Component\Uid\Uuid as SymfonyUuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CredentialRecord;
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
        // library validates the assertion's rpIdHash against the CURRENTLY
        // resolved rp id, not the STORED one — so on a multi-domain install a key
        // enrolled for one sales-channel domain could otherwise authenticate on
        // another if an authenticator is induced to sign for that rp id. NULL is a
        // pre-Migration1752624300 legacy row with no stored binding and stays
        // usable so those owners are not locked out.
        $resolvedRpId = $this->rpIdResolver->resolve($realm, $host, $context);
        if ($entity->getRpId() !== null && $entity->getRpId() !== $resolvedRpId) {
            throw new RuntimeException('Credential is bound to a different relying party.');
        }

        $record = $this->toCredentialRecord($entity);

        $validator = AuthenticatorAssertionResponseValidator::create(
            $this->ceremonyFactory->request($realm, $context)
        );
        // Last argument is the expected user handle: the validator enforces that
        // the assertion's own userHandle matches the stored one.
        $validator->check($record, $response, $options, $host, $entity->getUserHandle());

        $this->credentials->updateSignCount(
            $entity->getId(),
            $response->authenticatorData->signCount,
            $context
        );

        $accountId = $entity->getRealm() === Realm::Admin->value
            ? $entity->getUserId()
            : $entity->getCustomerId();
        if ($accountId === null) {
            throw new RuntimeException('Stored credential has no owner for its realm.');
        }

        return new AuthenticationResult($accountId, $entity->getId());
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
