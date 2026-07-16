<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Unit\WebAuthn\Challenge;
use Actualize\Passkey\WebAuthn\Challenge\ChallengeStore;
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
        $id = $store->issue($raw, 120);
        self::assertSame($raw, $store->consume($id));
        self::assertNull($store->consume($id), 'single-use');
    }
    public function testExpiredChallengeIsNull(): void {
        $clock = new MockClock();
        $store = $this->makeStore($clock);
        $id = $store->issue(random_bytes(32), 120);
        $clock->sleep(121);
        self::assertNull($store->consume($id));
    }
    public function testUnknownIdIsNull(): void {
        self::assertNull($this->makeStore(new MockClock())->consume('nope'));
    }
    public function testTwoChallengesAreIndependent(): void {
        $store = $this->makeStore(new MockClock());
        $a = $store->issue(random_bytes(32)); $b = $store->issue(random_bytes(32));
        self::assertNotNull($store->consume($a));
        self::assertNotNull($store->consume($b));
    }
}
