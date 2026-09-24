<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Unit\OAuth;

use Actualize\Passkey\OAuth\AdminLoginPolicy;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;

final class AdminLoginPolicyTest extends TestCase
{
    public function testSsoOnlyConfigDisallowsNonSsoLogin(): void
    {
        $parameters = new ParameterBag(['shopware.admin_login' => ['use_default' => false]]);

        self::assertFalse(AdminLoginPolicy::fromParameters($parameters)->allowsNonSsoLogin());
    }

    public function testCoreDefaultAllowsNonSsoLogin(): void
    {
        $parameters = new ParameterBag(['shopware.admin_login' => ['use_default' => true]]);

        self::assertTrue(AdminLoginPolicy::fromParameters($parameters)->allowsNonSsoLogin());
    }

    /**
     * 6.7 minors without the admin SSO feature have no such parameter at all.
     */
    public function testMissingParameterAllowsNonSsoLogin(): void
    {
        self::assertTrue(AdminLoginPolicy::fromParameters(new ParameterBag())->allowsNonSsoLogin());
    }
}
