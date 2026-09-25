<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Challenge;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Clock\ClockInterface;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\Lock\LockFactory;

/**
 * Cache-backed, single-use, TTL-expiring store for WebAuthn challenges.
 *
 * Backed by our own pool (`act_passkey.challenge_pool`), never `cache.app`:
 * Shopware maps that to the array adapter in dev, which lives for one request
 * only, while every passkey flow spans two (issue, then redeem).
 */
final class ChallengeStore
{
    private const KEY_PREFIX = 'act_passkey_challenge.';
    private const LOCK_PREFIX = 'act_passkey_challenge_consume.';

    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly ClockInterface $clock,
        private readonly LockFactory $lockFactory,
    ) {
    }

    /**
     * `$binding` ties the challenge to the context it was handed out to (the
     * customer's sales-channel context token). Only its hash is stored.
     */
    public function issue(
        string $rawChallenge,
        ChallengePurpose $purpose,
        Realm $realm,
        int $ttlSeconds = 120,
        ?string $binding = null
    ): string {
        $id = Uuid::randomHex();
        $item = $this->cache->getItem(self::KEY_PREFIX . $id);
        $item->set([
            'challenge' => base64_encode($rawChallenge),
            'purpose' => $purpose->value,
            'realm' => $realm->value,
            'binding' => $binding === null ? null : hash('sha256', $binding),
            'expires' => $this->clock->now()->getTimestamp() + $ttlSeconds,
        ]);
        $item->expiresAfter($ttlSeconds + 5); // backstop; primary check below
        $this->cache->save($item);
        return $id;
    }

    public function consume(
        string $challengeId,
        ChallengePurpose $purpose,
        Realm $realm,
        ?string $binding = null
    ): ?string {
        $key = self::KEY_PREFIX . $challengeId;

        // getItem-then-deleteItem is not atomic on a PSR-6 pool: two near-simultaneous
        // requests could both observe the hit before either deletes, and both redeem
        // the same challenge. A synced passkey often keeps signCount at 0 permanently,
        // so the later counter check cannot catch that replay. Serialize the critical
        // section per challenge id; a rival already holding it means a concurrent
        // consume is in flight, so treat this one as already spent.
        $lock = $this->lockFactory->createLock(self::LOCK_PREFIX . $challengeId);
        if (!$lock->acquire()) {
            return null;
        }

        try {
            $item = $this->cache->getItem($key);
            if (!$item->isHit()) {
                return null;
            }
            $this->cache->deleteItem($key); // delete first — single use even on later failure
            $data = $item->get();
            if (!is_array($data) || ($data['expires'] ?? 0) < $this->clock->now()->getTimestamp()) {
                return null;
            }
            // A challenge is only valid for the ceremony and realm it was issued for:
            // one handed out at a customer endpoint must not redeem an admin login.
            if (($data['purpose'] ?? null) !== $purpose->value || ($data['realm'] ?? null) !== $realm->value) {
                return null;
            }
            // Exact match: a bound challenge only redeems in its own context, an unbound
            // one only without one — otherwise a cross-site POST could log a victim
            // into the attacker's account.
            $stored = $data['binding'] ?? null;
            $matches = $binding === null
                ? $stored === null
                : is_string($stored) && hash_equals($stored, hash('sha256', $binding));
            if (!$matches) {
                return null;
            }
            $encoded = $data['challenge'] ?? null;
            $raw = is_string($encoded) ? base64_decode($encoded, true) : false;
            return $raw === false ? null : $raw;
        } finally {
            $lock->release();
        }
    }
}
