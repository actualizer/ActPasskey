<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Admin;

use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * The one check that an admin API request acts for a real user. An integration
 * token passes every ACL check but owns no passkeys and is no accountable actor,
 * so every passkey route refuses it here.
 */
final class AdminActor
{
    /**
     * @param string $feature names the refusing feature in the error message
     */
    public static function userId(Context $context, string $feature): string
    {
        $source = $context->getSource();
        if (!$source instanceof AdminApiSource) {
            throw new AccessDeniedHttpException($feature . ' requires an admin session.');
        }

        $userId = $source->getUserId();
        if ($userId === null || $userId === '') {
            throw new AccessDeniedHttpException($feature . ' requires a user session.');
        }

        return $userId;
    }
}
