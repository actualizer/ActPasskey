# ActPasskey - Shopware Plugin

A Shopware 6 plugin that adds Passkey / WebAuthn login for both the storefront and the administration. This is currently a scaffold — the plugin installs and activates cleanly, but no login functionality has been implemented yet.

## Planned Features

- Passwordless, phishing-resistant login via Passkeys (WebAuthn) for storefront customers
- Passwordless login via Passkeys (WebAuthn) for administration users
- Registration and management of Passkeys per account

## Requirements

- Shopware 6.7.x
- PHP 8.4 or higher

## Installation

### Via Composer (recommended)

```bash
composer require actualizer/passkey
bin/console plugin:refresh
bin/console plugin:install --activate ActPasskey
bin/console cache:clear
```

### Manual

1. Download or clone this plugin into your `custom/plugins/` directory
2. Install and activate the plugin via CLI:
   ```bash
   bin/console plugin:refresh
   bin/console plugin:install --activate ActPasskey
   bin/console cache:clear
   ```

## Compatibility

- **Shopware Version**: 6.7.x
- **PHP Version**: 8.4+

## Support

For questions or support, contact Actualize at https://actualize.de

## License

This plugin is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Credits

Developed by Actualize
