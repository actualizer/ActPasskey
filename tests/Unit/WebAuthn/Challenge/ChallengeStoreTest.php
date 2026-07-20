<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Unit\WebAuthn\Challenge;
use Actualize\Passkey\WebAuthn\Challenge\ChallengePurpose;
use Actualize\Passkey\WebAuthn\Challenge\ChallengeStore;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;
final class ChallengeStoreTest extends TestCase {
    private function makeStore(MockClock $clock): ChallengeStore {
        // storeSerialized=false keeps raw values across get/save in-process
        return new ChallengeStore(new ArrayAdapter(0, false), $clock);
    }
    public function testConsumeReturnsChallengeOnce(): void {
        $store = $this->makeStore(new MockClock());
        $raw = random_bytes(32);
        $id = $store->issue($raw, ChallengePurpose::Authentication, Realm::Admin, 120);
        self::assertSame($raw, $store->consume($id, ChallengePurpose::Authentication, Realm::Admin));
        self::assertNull($store->consume($id, ChallengePurpose::Authentication, Realm::Admin), 'single-use');
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
}
