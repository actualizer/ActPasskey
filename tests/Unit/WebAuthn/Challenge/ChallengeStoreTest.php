<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Unit\WebAuthn\Challenge;
use Actualize\Passkey\WebAuthn\Challenge\ChallengePurpose;
use Actualize\Passkey\WebAuthn\Challenge\ChallengeStore;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;
final class ChallengeStoreTest extends TestCase {
    private function makeStore(MockClock $clock, ?LockFactory $lockFactory = null): ChallengeStore {
        // storeSerialized=false keeps raw values across get/save in-process
        return new ChallengeStore(new ArrayAdapter(0, false), $clock, $lockFactory ?? new LockFactory(new InMemoryStore()));
    }
    public function testConsumeReturnsChallengeOnce(): void {
        $store = $this->makeStore(new MockClock());
        $raw = random_bytes(32);
        $id = $store->issue($raw, ChallengePurpose::Authentication, Realm::Admin, 120);
        self::assertSame($raw, $store->consume($id, ChallengePurpose::Authentication, Realm::Admin));
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Admin), 'single-use');
    }
    public function testConcurrentConsumeIsRejectedWhileLockHeld(): void {
        $lockFactory = new LockFactory(new InMemoryStore());
        $store = $this->makeStore(new MockClock(), $lockFactory);
        $id = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Admin);

        // Simulate a concurrent request that is mid-consume by holding the exact
        // per-challenge lock (name must match ChallengeStore::LOCK_PREFIX).
        $rival = $lockFactory->createLock('act_passkey_challenge_consume.' . $id);
        self::assertTrue($rival->acquire());

        // While the rival holds the critical section, consume must not hand out the
        // challenge — otherwise both requests redeem the same one.
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Admin));

        // Once the rival is done the challenge is untouched, so it is redeemable
        // exactly once — proving the rejection above did not consume or corrupt it.
        $rival->release();
        self::assertNotNull($store->consume($id, ChallengePurpose::Authentication, Realm::Admin));
        self::assertNull(
            $store->consume($id, ChallengePurpose::Authentication, Realm::Admin),
            'single-use still holds after a lock-contended consume'
        );
    }

    public function testExpiredChallengeIsNull(): void {
        $clock = new MockClock();
        $store = $this->makeStore($clock);
        $id = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Admin, 120);
        $clock->sleep(121);
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Admin));
    }
    public function testUnknownIdIsNull(): void {
        self::assertNull(
            $this->makeStore(new MockClock())->consume('nope', ChallengePurpose::Authentication, Realm::Admin)
        );
    }
    public function testTwoChallengesAreIndependent(): void {
        $store = $this->makeStore(new MockClock());
        $a = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Admin);
        $b = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Admin);
        self::assertNotNull($store->consume($a, ChallengePurpose::Authentication, Realm::Admin));
        self::assertNotNull($store->consume($b, ChallengePurpose::Authentication, Realm::Admin));
    }
    public function testChallengeIssuedForAnotherRealmIsRejected(): void {
        $store = $this->makeStore(new MockClock());
        $id = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Customer);
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Admin));
    }
    public function testChallengeIssuedForAnotherPurposeIsRejected(): void {
        $store = $this->makeStore(new MockClock());
        $id = $store->issue(random_bytes(32), ChallengePurpose::Registration, Realm::Admin);
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Admin));
    }
    public function testARejectedMismatchStillBurnsTheChallenge(): void {
        $store = $this->makeStore(new MockClock());
        $id = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Customer);
        $store->consume($id, ChallengePurpose::Authentication, Realm::Admin);
        self::assertNull(
            $store->consume($id, ChallengePurpose::Authentication, Realm::Customer),
            'a mismatched attempt must not leave the challenge replayable'
        );
    }
    public function testBoundChallengeRedeemsInItsOwnContext(): void {
        $store = $this->makeStore(new MockClock());
        $raw = random_bytes(32);
        $id = $store->issue($raw, ChallengePurpose::Authentication, Realm::Customer, binding: 'token-a');
        self::assertSame($raw, $store->consume($id, ChallengePurpose::Authentication, Realm::Customer, 'token-a'));
    }
    public function testBoundChallengeIsRejectedInAnotherContextAndBurned(): void {
        $store = $this->makeStore(new MockClock());
        $id = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Customer, binding: 'token-a');
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Customer, 'token-b'));
        self::assertNull(
            $store->consume($id, ChallengePurpose::Authentication, Realm::Customer, 'token-a'),
            'a mismatched attempt must not leave the challenge replayable'
        );
    }
    public function testBoundChallengeIsRejectedWithoutAContext(): void {
        $store = $this->makeStore(new MockClock());
        $id = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Customer, binding: 'token-a');
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Customer));
    }
    public function testUnboundChallengeIsRejectedInAContext(): void {
        $store = $this->makeStore(new MockClock());
        $id = $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Customer);
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Customer, 'token-a'));
    }
    public function testTheBindingIsStoredOnlyAsAHash(): void {
        $cache = new ArrayAdapter(0, false);
        $store = new ChallengeStore($cache, new MockClock(), new LockFactory(new InMemoryStore()));
        $store->issue(random_bytes(32), ChallengePurpose::Authentication, Realm::Customer, binding: 'token-a');
        self::assertStringNotContainsString('token-a', serialize($cache->getValues()));
    }
}
