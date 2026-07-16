<?php declare(strict_types=1);

namespace Actualize\Passkey\Twig;

use Symfony\Component\HttpKernel\KernelInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Exposes this plugin's built administration entry point to Twig so the login
 * screen can load it.
 *
 * The administration discovers plugin bundles through `/api/_info/config`, which
 * has no `auth_required => false` and answers 401 while nobody is logged in —
 * plugin admin bundles are therefore injected only AFTER a successful login. A
 * passkey button on the login screen cannot be delivered that way; it has to
 * come from the server-rendered `index.html.twig`, which needs no API auth.
 *
 * The hashed file name must never be hard-coded, since Vite renames the bundle
 * on every build. It is read from the entry point manifest that our own build
 * writes — our file, in our own bundle. The asset prefix is deliberately NOT
 * applied here: the template pipes the paths through Twig's `asset()`, so CDN
 * and sub-folder installations keep working.
 */
class AdministrationLoginScriptsExtension extends AbstractExtension
{
    private const BUNDLE_NAME = 'ActPasskey';

    /**
     * Entry name as configured in this plugin's vite.config.js. It also has to
     * match the technical bundle name the administration derives for us, which
     * is why it is spelled with a dash.
     */
    private const ENTRY_NAME = 'act-passkey';

    private const MANIFEST_PATH = '/Resources/public/administration/.vite/entrypoints.json';

    public function __construct(private readonly KernelInterface $kernel)
    {
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('act_passkey_admin_scripts', $this->getScripts(...)),
        ];
    }

    /**
     * @return list<string> Asset paths of this plugin's administration entry point
     */
    public function getScripts(): array
    {
        $manifest = $this->kernel->getBundle(self::BUNDLE_NAME)->getPath() . self::MANIFEST_PATH;

        // Absent before the first administration build — the login screen has to
        // stay usable, so a missing manifest simply means "no passkey button".
        if (!is_file($manifest)) {
            return [];
        }

        $content = file_get_contents($manifest);
        if ($content === false) {
            return [];
        }

        try {
            $data = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return [];
        }

        if (!\is_array($data)) {
            return [];
        }

        $entryPoints = $data['entryPoints'] ?? null;
        if (!\is_array($entryPoints)) {
            return [];
        }

        $entryPoint = $entryPoints[self::ENTRY_NAME] ?? null;
        if (!\is_array($entryPoint)) {
            return [];
        }

        $scripts = $entryPoint['js'] ?? null;
        if (!\is_array($scripts)) {
            return [];
        }

        return array_values(array_filter($scripts, \is_string(...)));
    }
}
