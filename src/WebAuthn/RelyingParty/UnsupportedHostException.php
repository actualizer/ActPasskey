<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\RelyingParty;

final class UnsupportedHostException extends \RuntimeException
{
    public function __construct(string $host)
    {
        parent::__construct(sprintf('Host "%s" is not covered by the configured relying party id.', $host));
    }
}
