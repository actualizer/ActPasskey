<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Store;

use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\SalesChannelApiTestBehaviour;
use Symfony\Component\HttpFoundation\Response;

/**
 * Drives the store-api routes through the REAL kernel, which every other test
 * around them skips by calling the controller with a hand-built context.
 *
 * That gap hid a routing defect: `auth_required => false` makes
 * SalesChannelAuthenticationListener return before it sets the sales-channel id,
 * so the resolver had nothing to build a SalesChannelContext from and every
 * request died with a TypeError on the controller's own signature.
 *
 * @internal
 */
final class PasskeyStoreApiRoutingTest extends TestCase
{
    use IntegrationTestBehaviour;
    use SalesChannelApiTestBehaviour;

    public function testChallengeRouteResolvesASalesChannelContext(): void
    {
        $browser = $this->getSalesChannelBrowser();
        // The browser defaults to host "localhost", which no relying party id
        // covers — drive it at the APP_URL host the rp id is derived from.
        $browser->setServerParameter('HTTP_HOST', $this->appUrlHost());
        $browser->request('POST', '/store-api/act-passkey/challenge');
        $response = $browser->getResponse();

        self::assertSame(
            Response::HTTP_OK,
            $response->getStatusCode(),
            'store-api challenge must serve over real HTTP: ' . (string) $response->getContent()
        );

        $payload = json_decode((string) $response->getContent(), true);
        self::assertIsArray($payload);
        self::assertArrayHasKey('challengeId', $payload);
        self::assertArrayHasKey('options', $payload);
    }

    public function testLoginRouteRejectsAnEmptyBodyInsteadOfFailingToBoot(): void
    {
        $browser = $this->getSalesChannelBrowser();
        $browser->request('POST', '/store-api/act-passkey/login');
        $response = $browser->getResponse();

        // The point is that it reaches our own auth check rather than dying in
        // the argument resolver — a 500 here means the route never booted.
        self::assertSame(
            Response::HTTP_UNAUTHORIZED,
            $response->getStatusCode(),
            'store-api login must reject, not crash: ' . (string) $response->getContent()
        );
    }

    public function testChallengeAnswers400ForAnUnsupportedHost(): void
    {
        $browser = $this->getSalesChannelBrowser();
        $browser->setServerParameter('HTTP_HOST', 'unknown.invalid');
        $browser->request('POST', '/store-api/act-passkey/challenge');

        // Must be a clean rejection, never a 500 — this route used to blow up here.
        self::assertSame(400, $browser->getResponse()->getStatusCode());
    }

    private function appUrlHost(): string
    {
        $appUrl = (string) static::getContainer()->getParameter('APP_URL');

        return (string) parse_url($appUrl, PHP_URL_HOST);
    }
}
