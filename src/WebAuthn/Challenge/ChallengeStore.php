<?php declare(strict_types=1);
namespace Actualize\Passkey\WebAuthn\Challenge;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Clock\ClockInterface;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Cache-backed, single-use, TTL-expiring store for WebAuthn challenges.
 *
 * Backed by our OWN pool (`act_passkey.challenge_pool`, see
 * Resources/config/packages/framework.yaml) rather than the session, so it also
 * works on the stateless admin `/api` endpoint — and deliberately NOT by
 * `cache.app`: Shopware maps that to `cache.adapter.array` in the dev
 * environment, which only lives for a single request. Every passkey flow spans
 * two requests (issue the challenge, then redeem the signed response), so on
 * `cache.app` they all fail in dev with "Invalid or expired challenge" while
 * silently working in prod. The pool pins a persistent adapter in every
 * environment.
 *
 * A challenge is deleted from the cache as soon as it is looked up in
 * `consume()`, before the expiry check runs. This guarantees single-use
 * semantics even when the subsequent expiry (or any later validation) fails:
 * an attacker cannot retry a challenge that was rejected once.
 */
final class ChallengeStore {
    private const KEY_PREFIX = 'act_passkey_challenge.';
    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly ClockInterface $clock,
    ) {}

    public function issue(string $rawChallenge, int $ttlSeconds = 120): string {
        $id = Uuid::randomHex();
        $item = $this->cache->getItem(self::KEY_PREFIX . $id);
        $item->set([
            'challenge' => base64_encode($rawChallenge),
            'expires' => $this->clock->now()->getTimestamp() + $ttlSeconds,
        ]);
        $item->expiresAfter($ttlSeconds + 5); // backstop; primary check below
        $this->cache->save($item);
        return $id;
    }

    public function consume(string $challengeId): ?string {
        $key = self::KEY_PREFIX . $challengeId;
        $item = $this->cache->getItem($key);
        if (!$item->isHit()) {
            return null;
        }
        $this->cache->deleteItem($key); // delete first — single use even on later failure
        $data = $item->get();
        if (!is_array($data) || ($data['expires'] ?? 0) < $this->clock->now()->getTimestamp()) {
            return null;
        }
        $encoded = $data['challenge'] ?? null;
        $raw = is_string($encoded) ? base64_decode($encoded, true) : false;
        return $raw === false ? null : $raw;
    }
}
