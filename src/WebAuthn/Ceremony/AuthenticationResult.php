<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

/**
 * A verified assertion. `credentialEntityId` is the stored row's id (not the raw
 * WebAuthn credential id), so a caller can stamp the credential once it has
 * accepted the login.
 */
final readonly class AuthenticationResult
{
    public function __construct(
        public string $accountId,
        public string $credentialEntityId,
    ) {
    }
}
