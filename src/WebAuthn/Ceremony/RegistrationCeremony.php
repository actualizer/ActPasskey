<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Actualize\Passkey\WebAuthn\Challenge\ChallengePurpose;
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
 * Registration ("attestation") ceremony: builds the creation options and
 * verifies the returned attestation before persisting the credential.
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
    public function createOptions(
        Realm $realm,
        string $accountId,
        string $host,
        Context $context,
        string $displayName = '',
        string $userName = ''
    ): array {
        $challenge = random_bytes(32);
        $challengeId = $this->challengeStore->issue($challenge, ChallengePurpose::Registration, $realm);
        $options = $this->buildOptions($realm, $accountId, $host, $challenge, $context, $displayName, $userName);

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
        Context $context,
        string $displayName = '',
        string $userName = ''
    ): void {
        $challenge = $this->challengeStore->consume($challengeId, ChallengePurpose::Registration, $realm);
        if ($challenge === null) {
            throw new RuntimeException('Invalid or expired registration challenge.');
        }

        // Rebuild the options with the SAME challenge that was just consumed, so
        // CheckChallenge compares against the exact issued value.
        $options = $this->buildOptions($realm, $accountId, $host, $challenge, $context, $displayName, $userName);

        $credential = $this->serializer->deserializeCredential($rawResponseJson);
        $response = $credential->response;
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw new RuntimeException('The response is not an attestation response.');
        }

        $validator = AuthenticatorAttestationResponseValidator::create(
            $this->ceremonyFactory->creation($realm, $context)
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
        Context $context,
        string $displayName = '',
        string $userName = ''
    ): PublicKeyCredentialCreationOptions {
        $rpId = $this->rpIdResolver->resolve($realm, $host, $context);
        $userHandle = $this->userHandles->getOrCreate($realm, $accountId, $context);

        // Cosmetic only: the label the browser's passkey manager shows. The user
        // handle stays random bytes and must never carry these values.
        $userName = $userName !== '' ? $userName : $accountId;
        $displayName = $displayName !== '' ? $displayName : $accountId;

        return PublicKeyCredentialCreationOptions::create(
            new PublicKeyCredentialRpEntity($rpId, $rpId),
            PublicKeyCredentialUserEntity::create($userName, $userHandle, $displayName),
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
