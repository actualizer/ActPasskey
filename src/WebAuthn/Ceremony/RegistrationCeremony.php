<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Actualize\Passkey\WebAuthn\Challenge\ChallengeStore;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\Credential\UserHandleProvider;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Cose\Algorithms;
use RuntimeException;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Registration ("attestation") ceremony: builds the creation options for the
 * browser and verifies the returned attestation against the real webauthn-lib
 * validator before persisting the credential.
 */
final class RegistrationCeremony
{
    public function __construct(
        private readonly CeremonyFactory $ceremonyFactory,
        private readonly ChallengeStore $challengeStore,
        private readonly CredentialRepository $credentials,
        private readonly UserHandleProvider $userHandles,
        private readonly RelyingPartyIdResolver $rpIdResolver,
        private readonly WebauthnSerializer $serializer,
    ) {
    }

    /**
     * @return array{options: string, challengeId: string}
     */
    public function createOptions(Realm $realm, string $accountId, string $host, Context $context): array
    {
        $challenge = random_bytes(32);
        $challengeId = $this->challengeStore->issue($challenge);
        $options = $this->buildOptions($realm, $accountId, $host, $challenge, $context);

        return [
            'options' => $this->serializer->serializeOptions($options),
            'challengeId' => $challengeId,
        ];
    }

    public function verify(
        Realm $realm,
        string $accountId,
        string $rawResponseJson,
        string $challengeId,
        string $host,
        string $name,
        Context $context
    ): void {
        $challenge = $this->challengeStore->consume($challengeId);
        if ($challenge === null) {
            throw new RuntimeException('Invalid or expired registration challenge.');
        }

        // Reconstruct the options with the SAME challenge that was issued and
        // just consumed, so CheckChallenge compares against the exact value.
        $options = $this->buildOptions($realm, $accountId, $host, $challenge, $context);

        $credential = $this->serializer->deserializeCredential($rawResponseJson);
        $response = $credential->response;
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw new RuntimeException('The response is not an attestation response.');
        }

        $validator = AuthenticatorAttestationResponseValidator::create(
            $this->ceremonyFactory->creation($context)
        );
        $record = $validator->check($response, $options, $host);

        $this->credentials->save([
            'id' => Uuid::randomHex(),
            'realm' => $realm->value,
            'userId' => $realm === Realm::Admin ? $accountId : null,
            'customerId' => $realm === Realm::Customer ? $accountId : null,
            'credentialId' => $record->publicKeyCredentialId,
            'publicKey' => $record->credentialPublicKey,
            'signCount' => $record->counter,
            'userHandle' => $options->user->id,
            'aaguid' => $record->aaguid->toRfc4122(),
            'transports' => $record->transports,
            'name' => $name,
        ], $context);
    }

    private function buildOptions(
        Realm $realm,
        string $accountId,
        string $host,
        string $challenge,
        Context $context
    ): PublicKeyCredentialCreationOptions {
        $rpId = $this->rpIdResolver->resolve($host);
        $userHandle = $this->userHandles->getOrCreate($realm, $accountId, $context);

        return PublicKeyCredentialCreationOptions::create(
            new PublicKeyCredentialRpEntity($rpId, $rpId),
            PublicKeyCredentialUserEntity::create($accountId, $userHandle, $accountId),
            $challenge,
            [
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256),
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_RS256),
            ],
            new AuthenticatorSelectionCriteria(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        );
    }
}
