<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Admin;

use Shopware\Core\Framework\Api\ApiException;
use Shopware\Core\Framework\Api\OAuth\Scope\UserVerifiedScope;
use Shopware\Core\PlatformRequest;
use Symfony\Component\HttpFoundation\Request;

/**
 * Same contract as core's UserController::validateScope(): a token without a fresh
 * password confirmation must not change authentication factors. Unlike core we do not
 * exempt non-`administration` clients — integration tokens own no passkeys and are
 * rejected by every caller before a mutation runs.
 */
final class UserVerifiedScopeGuard
{
    public static function assert(Request $request): void
    {
        $scopes = $request->attributes->get(PlatformRequest::ATTRIBUTE_OAUTH_SCOPES);
        if (!is_array($scopes) || !in_array(UserVerifiedScope::IDENTIFIER, $scopes, true)) {
            throw ApiException::invalidScopeAccessToken(UserVerifiedScope::IDENTIFIER);
        }
    }
}
