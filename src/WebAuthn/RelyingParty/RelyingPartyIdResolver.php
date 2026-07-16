<?php declare(strict_types=1);
namespace Actualize\Passkey\WebAuthn\RelyingParty;

final class RelyingPartyIdResolver {
    private readonly string $appHost;
    public function __construct(string $appUrl, private readonly ?string $broadenParent) {
        $this->appHost = (string) parse_url($appUrl, PHP_URL_HOST);
    }
    public function resolve(string $host): string {
        $host = strtolower(trim($host));
        if ($this->broadenParent !== null && $this->isWithin($host, $this->broadenParent)) {
            return $this->broadenParent;
        }
        if ($this->isWithin($host, $this->appHost)) {
            return $this->appHost;
        }
        throw new UnsupportedHostException($host);
    }
    private function isWithin(string $host, string $suffix): bool {
        return $host === $suffix || str_ends_with($host, '.' . $suffix);
    }
}
