<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Unit\WebAuthn\Challenge;
use Actualize\Passkey\WebAuthn\Challenge\ChallengeStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
final class ChallengeStoreTest extends TestCase {
    private function makeStore(MockClock $clock): ChallengeStore {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        $stack = new RequestStack();
        $stack->push($request);
        return new ChallengeStore($stack, $clock);
    }
    public function testConsumeReturnsChallengeOnce(): void {
        $clock = new MockClock();
        $store = $this->makeStore($clock);
        $raw = random_bytes(32);
        $id = $store->issue($raw, 120);
        self::assertSame($raw, $store->consume($id), 'first consume returns it');
        self::assertNull($store->consume($id), 'second consume is null (single-use)');
    }
    public function testExpiredChallengeIsNull(): void {
        $clock = new MockClock();
        $store = $this->makeStore($clock);
        $id = $store->issue(random_bytes(32), 120);
        $clock->sleep(121);
        self::assertNull($store->consume($id), 'expired challenge rejected');
    }
    public function testUnknownIdIsNull(): void {
        $store = $this->makeStore(new MockClock());
        self::assertNull($store->consume('does-not-exist'));
    }
}
