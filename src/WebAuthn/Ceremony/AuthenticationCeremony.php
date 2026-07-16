<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialEntity;
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
     * @return array{options: string, challengeId: string}
     */
    public function createOptions(Realm $realm, string $host, Context $context): array
    {
        $challenge = random_bytes(32);
        $challengeId = $this->challengeStore->issue($challenge);
        $options = $this->buildOptions($host, $challenge);

        return [
            'options' => $this->serializer->serializeOptions($options),
            'challengeId' => $challengeId,
        ];
    }

    /**
     * @return string the resolved account id (admin user id or customer id)
     */
    public function verify(
        Realm $realm,
        string $rawResponseJson,
        string $challengeId,
        string $host,
        Context $context
    ): string {
        $challenge = $this->challengeStore->consume($challengeId);
        if ($challenge === null) {
            throw new RuntimeException('Invalid or expired authentication challenge.');
        }

        $options = $this->buildOptions($host, $challenge);

        $credential = $this->serializer->deserializeCredential($rawResponseJson);
        $response = $credential->response;
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new RuntimeException('The response is not an assertion response.');
        }

        $entity = $this->credentials->findOneByCredentialId($credential->rawId, $realm, $context);
        if ($entity === null) {
            throw new RuntimeException('Unknown credential for this realm.');
        }

        $record = $this->toCredentialRecord($entity);

        $validator = AuthenticatorAssertionResponseValidator::create(
            $this->ceremonyFactory->request($context)
        );
        // Last argument is the expected user handle: the validator enforces that
        // the assertion's own userHandle matches the stored one.
        $validator->check($record, $response, $options, $host, $entity->getUserHandle());

        $this->credentials->updateSignCount(
            $entity->getId(),
            $response->authenticatorData->signCount,
            $context,
            new \DateTimeImmutable()
        );

        $accountId = $entity->getRealm() === Realm::Admin->value
            ? $entity->getUserId()
            : $entity->getCustomerId();
        if ($accountId === null) {
            throw new RuntimeException('Stored credential has no owner for its realm.');
        }

        return $accountId;
    }

    private function buildOptions(string $host, string $challenge): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(
            $challenge,
            $this->rpIdResolver->resolve($host),
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
