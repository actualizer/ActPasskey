<?php declare(strict_types=1);

namespace Actualize\Passkey\OAuth;

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * Mirrors core's SSO-only switch (`shopware.admin_login.use_default`). Core refuses the
 * password grant when it is false; a passkey is a non-SSO login as well, so it must obey
 * the same switch — otherwise a user offboarded at the identity provider keeps access.
 */
final class AdminLoginPolicy
{
    private const PARAMETER = 'shopware.admin_login';

    /**
     * @param array<mixed> $adminLoginConfig
     */
    public function __construct(private readonly array $adminLoginConfig)
    {
    }

    public static function fromParameters(ParameterBagInterface $parameters): self
    {
        // Read defensively instead of injecting %shopware.admin_login%: the plugin supports
        // every 6.7 minor, and a missing parameter would break the container compile there.
        $config = $parameters->has(self::PARAMETER) ? $parameters->get(self::PARAMETER) : [];

        return new self(\is_array($config) ? $config : []);
    }

    public function allowsNonSsoLogin(): bool
    {
        // Same semantics as core: only an explicit `false` disables the default login.
        return ($this->adminLoginConfig['use_default'] ?? true) !== false;
    }
}
