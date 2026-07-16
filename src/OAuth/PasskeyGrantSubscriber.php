<?php declare(strict_types=1);

namespace Actualize\Passkey\OAuth;

use League\OAuth2\Server\AuthorizationServer;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Registers the `passkey` grant on the shared (per-request) AuthorizationServer.
 * Mirrors core's ApiAuthenticationListener::setupOAuth() — runs on
 * KernelEvents::REQUEST at the same priority, and re-enabling per request is
 * expected since league keys grants by identifier (idempotent, no guard needed).
 */
class PasskeyGrantSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly AuthorizationServer $authorizationServer,
        private readonly PasskeyGrant $passkeyGrant,
        private readonly string $accessTokenTtl,
        private readonly string $refreshTokenTtl,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => ['enablePasskeyGrant', 128]];
    }

    public function enablePasskeyGrant(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $this->passkeyGrant->setRefreshTokenTTL(new \DateInterval($this->refreshTokenTtl));
        $this->authorizationServer->enableGrantType($this->passkeyGrant, new \DateInterval($this->accessTokenTtl));
    }
}
