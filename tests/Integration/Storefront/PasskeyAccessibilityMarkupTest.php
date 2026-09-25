<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Storefront;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialEntity;
use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use DOMDocument;
use DOMElement;
use DOMXPath;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Struct\ArrayStruct;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Storefront\Page\Account\Login\AccountLoginPage;
use Shopware\Storefront\Page\Account\Profile\AccountProfilePage;
use Twig\Environment;

/**
 * The passkey controls are operated by keyboard and screen reader, which the
 * data-act-passkey-* assertions elsewhere cannot see: those stay green while the
 * ARIA wiring rots. Every reference here is checked against the id it points at,
 * so a renamed id fails instead of a still-present attribute passing.
 */
final class PasskeyAccessibilityMarkupTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testToggleControlsPointAtTheFormsTheyOpen(): void
    {
        $xpath = $this->xpathFor($this->renderPasskeyCard());

        foreach (['rename', 'delete'] as $action) {
            $toggle = $this->single($xpath, "//button[@data-act-passkey-{$action}-toggle]");

            self::assertSame('false', $toggle->getAttribute('aria-expanded'), "{$action} toggle starts collapsed");

            $controls = $toggle->getAttribute('aria-controls');
            self::assertNotSame('', $controls, "{$action} toggle references a form");
            self::assertSame(
                1,
                $xpath->query("//form[@id='{$controls}']")?->length,
                "aria-controls of the {$action} toggle resolves to exactly one form"
            );
        }
    }

    public function testRepeatedActionsCarryThePasskeyNameInTheirAccessibleName(): void
    {
        $xpath = $this->xpathFor($this->renderPasskeyCard('Kept device'));

        // Visible text is the same on every row, so the name has to come from the label.
        $rename = $this->single($xpath, '//button[@data-act-passkey-rename-toggle]');
        $delete = $this->single($xpath, '//button[@data-act-passkey-delete-toggle]');

        self::assertStringContainsString('Kept device', $rename->getAttribute('aria-label'));
        self::assertStringContainsString('Kept device', $delete->getAttribute('aria-label'));
        self::assertNotSame($rename->getAttribute('aria-label'), $delete->getAttribute('aria-label'));
    }

    public function testEveryPasskeyInputHasANonVisualLabel(): void
    {
        $xpath = $this->xpathFor($this->renderPasskeyCard());

        $inputs = $xpath->query('//input[@type="text" or @type="password"]');
        self::assertNotFalse($inputs);
        self::assertGreaterThan(0, $inputs->length, 'the card renders inputs at all');

        foreach ($inputs as $input) {
            self::assertInstanceOf(DOMElement::class, $input);
            $id = $input->getAttribute('id');
            self::assertNotSame('', $id, 'input is addressable by a label');

            $label = $this->single($xpath, "//label[@for='{$id}']");
            self::assertStringContainsString(
                'visually-hidden',
                $label->getAttribute('class'),
                "the label for {$id} stays off-screen"
            );
            self::assertNotSame('', trim((string) $label->textContent), "the label for {$id} carries text");
        }
    }

    public function testRenameInputIsCappedAtTheNameLimit(): void
    {
        $xpath = $this->xpathFor($this->renderPasskeyCard());

        $input = $this->single($xpath, "//form[@data-act-passkey-rename-form]//input[@name='name']");

        self::assertSame((string) CredentialRepository::MAX_NAME_LENGTH, $input->getAttribute('maxlength'));
    }

    public function testPasswordFieldsReferenceTheirHint(): void
    {
        $xpath = $this->xpathFor($this->renderPasskeyCard());

        $fields = $xpath->query('//input[@type="password"]');
        self::assertNotFalse($fields);
        self::assertGreaterThan(0, $fields->length);

        foreach ($fields as $field) {
            self::assertInstanceOf(DOMElement::class, $field);
            $describedBy = $field->getAttribute('aria-describedby');
            self::assertNotSame('', $describedBy, 'password field points at its hint');
            self::assertSame(
                1,
                $xpath->query("//*[@id='{$describedBy}']")?->length,
                "aria-describedby '{$describedBy}' resolves to exactly one element"
            );
        }
    }

    /**
     * Both plugins write their message into a region that is revealed first, which
     * only announces if the region is a live region to begin with.
     */
    public function testErrorRegionsAreLiveRegions(): void
    {
        $card = $this->xpathFor($this->renderPasskeyCard());
        self::assertSame(
            'alert',
            $this->single($card, '//*[@data-act-passkey-manage-error]')->getAttribute('role')
        );

        $login = $this->xpathFor($this->renderLoginSubmit());
        self::assertSame(
            'alert',
            $this->single($login, '//*[@data-act-passkey-login-error]')->getAttribute('role')
        );
    }

    private function renderPasskeyCard(string $credentialName = 'Kept device'): string
    {
        $credential = new PasskeyCredentialEntity();
        $credential->setId(Uuid::randomHex());
        $credential->setName($credentialName);
        $credential->setLastUsedAt(null);

        $page = new AccountProfilePage();
        $page->addExtension('actPasskeyCredentials', new ArrayStruct([
            'credentials' => [$credential],
            'orphanedIds' => [],
        ]));
        $page->addExtension('actPasskeySupported', new ArrayStruct(['supported' => true]));

        return $this->twig()
            ->load('@ActPasskey/storefront/page/account/profile/index.html.twig')
            ->renderBlock('page_account_profile_passkeys', ['page' => $page]);
    }

    private function renderLoginSubmit(): string
    {
        $page = new AccountLoginPage();
        $page->addExtension('actPasskeySupported', new ArrayStruct(['supported' => true]));

        return $this->twig()
            ->load('@ActPasskey/storefront/component/account/login.html.twig')
            ->renderBlock('component_account_login_submit', ['page' => $page]);
    }

    private function twig(): Environment
    {
        $twig = $this->getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);

        return $twig;
    }

    private function xpathFor(string $html): DOMXPath
    {
        $document = new DOMDocument();
        // The blocks are fragments, and the storefront markup is not valid XML.
        $loaded = @$document->loadHTML(
            '<?xml encoding="utf-8" ?><div>' . $html . '</div>',
            LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
        );
        self::assertTrue($loaded, 'rendered block parses as HTML');

        return new DOMXPath($document);
    }

    private function single(DOMXPath $xpath, string $query): DOMElement
    {
        $nodes = $xpath->query($query);
        self::assertNotFalse($nodes, "query {$query} is valid");
        self::assertSame(1, $nodes->length, "query {$query} matches exactly one element");

        $node = $nodes->item(0);
        self::assertInstanceOf(DOMElement::class, $node);

        return $node;
    }
}
