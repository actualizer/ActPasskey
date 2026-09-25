<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * Minimal in-process ES256 (P-256) software authenticator for the ceremony
 * round-trip and security negative tests. It produces attestation/assertion
 * responses in the exact wire format the REAL webauthn-lib serializer +
 * validators consume: CBOR attestation objects, COSE_ES256 public keys, and
 * DER-encoded ECDSA signatures over `authenticatorData || sha256(clientDataJSON)`.
 *
 * The private key + credential id are kept in a static registry keyed by the
 * base64url credential id, so respondToGet() can sign with the key minted during
 * respondToCreate(). Nothing here bypasses crypto: the signatures are genuine and
 * only verify because the key pair is consistent between create and get.
 */
final class SoftwareAuthenticator
{
    /** @var array<string, array{pem: string, userHandle: string}> */
    private static array $registry = [];

    private static string $lastCredentialId = '';

    /**
     * @return string JSON of the browser PublicKeyCredential (attestation)
     */
    public static function respondToCreate(
        string $optionsJson,
        string $origin,
        int $credentialIdLength = 32,
        string $attestationFormat = 'none'
    ): string
    {
        /** @var array{challenge: string, rp: array{id: string}, user: array{id: string}} $options */
        $options = json_decode($optionsJson, true, 512, JSON_THROW_ON_ERROR);

        $challenge = self::b64uDecode($options['challenge']);
        $rpId = $options['rp']['id'];
        $userHandle = self::b64uDecode($options['user']['id']);

        $keyPair = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if (!$keyPair instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Unable to generate EC key pair.');
        }

        $details = openssl_pkey_get_details($keyPair);
        if ($details === false || !isset($details['ec']['x'], $details['ec']['y'])) {
            throw new RuntimeException('Unable to read EC key details.');
        }
        openssl_pkey_export($keyPair, $pem);

        $credentialId = random_bytes($credentialIdLength);
        $cosePublicKey = self::coseEs256Key($details['ec']['x'], $details['ec']['y']);

        $flags = 0x01 | 0x04 | 0x40; // UP | UV | AT
        $authData = hash('sha256', $rpId, true)
            . chr($flags)
            . pack('N', 0)
            . self::attestedCredentialData($credentialId, $cosePublicKey);

        $clientDataJson = self::clientDataJson('webauthn.create', $challenge, $origin);

        $attestationObject = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create($attestationFormat === 'none' ? 'none' : 'packed'))
            ->add(TextStringObject::create('attStmt'), self::attestationStatement($attestationFormat, $authData, $clientDataJson, $keyPair))
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        self::$lastCredentialId = self::b64uEncode($credentialId);
        self::$registry[self::$lastCredentialId] = [
            'pem' => (string) $pem,
            'userHandle' => $userHandle,
        ];

        return json_encode([
            'id' => self::b64uEncode($credentialId),
            'rawId' => self::b64uEncode($credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::b64uEncode($clientDataJson),
                'attestationObject' => self::b64uEncode((string) $attestationObject),
            ],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * @return string JSON of the browser PublicKeyCredential (assertion)
     */
    public static function respondToGet(
        string $optionsJson,
        string $origin,
        int $signCount = 1,
        ?string $credentialId = null
    ): string {
        /** @var array{challenge: string, rpId: string} $options */
        $options = json_decode($optionsJson, true, 512, JSON_THROW_ON_ERROR);

        $challenge = self::b64uDecode($options['challenge']);
        $rpId = $options['rpId'];

        // Default to the newest credential so existing single-credential callers are
        // unaffected; an explicit id lets multi-credential tests pick a specific key.
        $handle = $credentialId ?? array_key_last(self::$registry);
        if ($handle === null || !isset(self::$registry[$handle])) {
            throw new RuntimeException('Unknown credential id for assertion.');
        }
        $credentialIdB64u = $handle;
        $entry = self::$registry[$credentialIdB64u];

        $flags = 0x01 | 0x04; // UP | UV
        $authData = hash('sha256', $rpId, true)
            . chr($flags)
            . pack('N', $signCount);

        $clientDataJson = self::clientDataJson('webauthn.get', $challenge, $origin);

        $privateKey = openssl_pkey_get_private($entry['pem']);
        if (!$privateKey instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Unable to load private key.');
        }
        $signedData = $authData . hash('sha256', $clientDataJson, true);
        openssl_sign($signedData, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        return json_encode([
            'id' => $credentialIdB64u,
            'rawId' => $credentialIdB64u,
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::b64uEncode($clientDataJson),
                'authenticatorData' => self::b64uEncode($authData),
                'signature' => self::b64uEncode((string) $signature),
                'userHandle' => self::b64uEncode($entry['userHandle']),
            ],
        ], JSON_THROW_ON_ERROR);
    }

    public static function lastCredentialId(): string
    {
        if (self::$lastCredentialId === '') {
            throw new RuntimeException('No credential has been created yet.');
        }

        return self::$lastCredentialId;
    }

    public static function reset(): void
    {
        self::$registry = [];
        self::$lastCredentialId = '';
    }

    /**
     * `packed` is a self-attestation: signed with the credential's own key over
     * `authData || sha256(clientDataJSON)`, without a certificate. `packed-invalid`
     * signs different bytes, so a verifier that really checks the signature refuses it.
     */
    private static function attestationStatement(
        string $format,
        string $authData,
        string $clientDataJson,
        OpenSSLAsymmetricKey $key
    ): MapObject {
        if ($format === 'none') {
            return MapObject::create();
        }
        if ($format !== 'packed' && $format !== 'packed-invalid') {
            throw new RuntimeException(sprintf('Unsupported attestation format "%s".', $format));
        }

        $signedData = $authData . hash('sha256', $clientDataJson, true);
        if ($format === 'packed-invalid') {
            $signedData .= "\0";
        }
        openssl_sign($signedData, $signature, $key, OPENSSL_ALGO_SHA256);

        return MapObject::create()
            ->add(TextStringObject::create('alg'), NegativeIntegerObject::create(-7)) // ES256
            ->add(TextStringObject::create('sig'), ByteStringObject::create((string) $signature));
    }

    private static function attestedCredentialData(string $credentialId, string $cosePublicKey): string
    {
        return str_repeat("\0", 16) // AAGUID = all zero
            . pack('n', strlen($credentialId))
            . $credentialId
            . $cosePublicKey;
    }

    private static function coseEs256Key(string $x, string $y): string
    {
        $x = str_pad($x, 32, "\0", STR_PAD_LEFT);
        $y = str_pad($y, 32, "\0", STR_PAD_LEFT);

        // COSE_Key: kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y
        $key = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($x))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($y));

        return (string) $key;
    }

    private static function clientDataJson(string $type, string $challenge, string $origin): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => self::b64uEncode($challenge),
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);
    }

    private static function b64uEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function b64uDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64url input.');
        }

        return $decoded;
    }
}
