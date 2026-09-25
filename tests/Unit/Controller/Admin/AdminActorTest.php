<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Unit\Controller\Admin;

use Actualize\Passkey\Controller\Admin\AdminActor;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Api\Context\SystemSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

final class AdminActorTest extends TestCase
{
    public function testReturnsTheUserOfAnAdminSession(): void
    {
        $userId = Uuid::randomHex();

        self::assertSame($userId, AdminActor::userId(new Context(new AdminApiSource($userId)), 'Feature'));
    }

    public function testRejectsAnIntegrationToken(): void
    {
        $this->expectException(AccessDeniedHttpException::class);
        $this->expectExceptionMessage('Feature requires a user session.');

        AdminActor::userId(new Context(new AdminApiSource(null, Uuid::randomHex())), 'Feature');
    }

    public function testRejectsANonAdminSource(): void
    {
        $this->expectException(AccessDeniedHttpException::class);
        $this->expectExceptionMessage('Feature requires an admin session.');

        AdminActor::userId(new Context(new SystemSource()), 'Feature');
    }
}
