<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Storefront;

use PHPUnit\Framework\TestCase;
use Shopware\Core\Content\Test\Product\ProductBuilder;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Test\Stub\Framework\IdsCollection;
use Shopware\Storefront\Test\Controller\StorefrontControllerTestBehaviour;

/**
 * Pins the regression: /checkout/register sw_extends the same login component
 * template as /account/login, so it must receive the same actPasskeySupported
 * page extension from LoginPagePasskeySupportSubscriber. Before the fix,
 * CheckoutRegisterPageLoadedEvent was not covered and the whole passkey button
 * container never rendered there.
 */
final class CheckoutRegisterPasskeyButtonTest extends TestCase
{
    use IntegrationTestBehaviour;
    use StorefrontControllerTestBehaviour;

    public function testPasskeyButtonContainerIsPresentOnCheckoutRegisterPage(): void
    {
        // checkoutRegisterPage() redirects to the cart page for an empty cart,
        // so a product must be added first via the real storefront route.
        $ids = new IdsCollection();
        (new ProductBuilder($ids, 'p1'))
            ->price(10)
            ->visibility($this->getSalesChannelId())
            ->write($this->getContainer());
        $productId = $ids->get('p1');

        $addResponse = $this->request('POST', 'checkout/line-item/add', [
            'lineItems' => [
                'p1' => [
                    'id' => $productId,
                    'referencedId' => $productId,
                    'type' => 'product',
                    'quantity' => 1,
                ],
            ],
        ]);
        self::assertNotSame(500, $addResponse->getStatusCode(), (string) $addResponse->getContent());

        $response = $this->request('GET', 'checkout/register', []);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        self::assertStringContainsString('data-act-passkey-login', (string) $response->getContent());
    }
}
