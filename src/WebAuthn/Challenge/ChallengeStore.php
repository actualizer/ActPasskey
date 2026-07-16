<?php declare(strict_types=1);
namespace Actualize\Passkey\WebAuthn\Challenge;
use Psr\Clock\ClockInterface;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Session-bound, single-use, TTL-expiring store for WebAuthn challenges.
 *
 * A challenge is deleted from the session as soon as it is looked up in
 * `consume()`, before the expiry check runs. This guarantees single-use
 * semantics even when the subsequent expiry (or any later validation)
 * fails: an attacker cannot retry a challenge that was rejected once.
 */
final class ChallengeStore {
    private const SESSION_KEY = 'act_passkey_challenges';
    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly ClockInterface $clock,
    ) {}

    public function issue(string $rawChallenge, int $ttlSeconds = 120): string {
        $id = Uuid::randomHex();
        $bag = $this->bag();
        $bag[$id] = [
            'challenge' => base64_encode($rawChallenge),
            'expires' => $this->clock->now()->getTimestamp() + $ttlSeconds,
        ];
        $this->save($bag);
        return $id;
    }

    public function consume(string $challengeId): ?string {
        $bag = $this->bag();
        $entry = $bag[$challengeId] ?? null;
        if ($entry === null) { return null; }
        unset($bag[$challengeId]);
        $this->save($bag); // delete first — single use even if later checks fail
        if (($entry['expires'] ?? 0) < $this->clock->now()->getTimestamp()) {
            return null;
        }
        $decoded = base64_decode($entry['challenge'], true);
        return $decoded === false ? null : $decoded;
    }

    /** @return array<string, array{challenge:string, expires:int}> */
    private function bag(): array {
        return $this->requestStack->getSession()->get(self::SESSION_KEY, []);
    }
    /** @param array<string, array{challenge:string, expires:int}> $bag */
    private function save(array $bag): void {
        $this->requestStack->getSession()->set(self::SESSION_KEY, $bag);
    }
}
