<?php declare(strict_types=1);

namespace Actualize\Passkey\Twig;

use Symfony\Component\HttpKernel\KernelInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Exposes the built administration entry point to the login template.
 *
 * The administration loads plugin bundles from `/api/_info/config`, which is 401
 * while logged out, so on the login screen the bundle has to come from the
 * server-rendered template instead. Paths are read from the manifest because
 * Vite rehashes the file on every build; the asset prefix is left to the
 * template's `asset()`.
 */
class AdministrationLoginScriptsExtension extends AbstractExtension
{
    private const BUNDLE_NAME = 'ActPasskey';

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

        // Missing until the administration has been built once.
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
