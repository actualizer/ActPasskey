# ActPasskey - Shopware Plugin

A Shopware 6 plugin that adds Passkey / WebAuthn login for both the storefront and the administration.

Passkeys are additive: the password login keeps working for every account. Anyone without a passkey, without WebAuthn support, or on a domain the shop does not cover simply sees the normal password form.

## Features

- Passwordless, phishing-resistant login via Passkeys (WebAuthn) for storefront customers
- Passwordless login via Passkeys (WebAuthn) for administration users
- Usernameless sign-in (discoverable credentials): the browser offers the matching passkey, no username needed
- Self-service management: register, rename and revoke your own passkeys from the admin profile page or the customer account
- Admin and customer passkeys are strictly separated: a customer passkey can never authenticate an administrator
- Multi-domain aware: on a shop serving several storefront domains, each passkey is bound to the domain it was created on, so every domain issues and accepts its own domain-correct passkeys

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

## Known limitations

### Administration SSO

Registering, renaming or revoking a passkey requires confirming the account password. Shopware only issues the required `user-verified` scope through the password grant, so this step-up is unavailable to administrators who sign in via SSO — on shops where the **administration** login is delegated to an identity provider, the admin self-service routes return HTTP 403.

The passkey **login** itself and the entire storefront side are unaffected.

This fails closed by design. Shopware core skips its own step-up under SSO, but core uses that check to guard profile edits, whereas this plugin uses it to guard the enrollment of an authentication factor. A passkey enrolled locally would keep working after the account is deprovisioned in the central identity provider — bypassing the very control SSO exists for. Proper support means requiring a fresh SSO re-authentication instead of a password prompt; that is a separate feature, not a configuration toggle.

### Domain coverage

A passkey is bound to the shop's domain (that is what makes it phishing-resistant). Trusted origins are derived from `APP_URL` and the configured sales channel domains — never from the request host. On a domain that is not covered, the browser will not offer the passkey, and both the login button and the account "add a passkey" control stay hidden; the password login remains available.

If a covered domain is later retired, or the shared parent domain is changed, a passkey created for it can no longer run a login ceremony. Such a passkey is not silently dropped: it stays listed in the customer account with a note that its domain is no longer active, so it remains renameable and deletable and never becomes stranded.

### Multi-node / clustered setups

A passkey ceremony spans two requests: one issues a challenge, a second redeems it. By default the challenge lives in a dedicated **filesystem** cache pool (`act_passkey.challenge_pool`) and its single-use guarantee is serialized with a `flock` lock — both node-local. The pool is pinned to the filesystem adapter deliberately: Shopware maps `cache.app` to an in-memory adapter in the dev environment, which would break every ceremony locally, so the pool does not follow the global cache configuration.

On a single application server this is correct. Behind a load balancer with more than one node it is not: a challenge issued on node A is absent when the redeem request lands on node B (surfacing as "Invalid or expired challenge"), and the single-use lock only serializes redemptions within one node.

For a clustered deployment, point both at shared backends:

- Override the challenge pool with a shared adapter (for example Redis) via `framework.cache.pools.act_passkey.challenge_pool.adapter` in your own config. Because of the pinning above, the plugin will **not** switch automatically when you move the rest of Shopware to a shared cache.
- Ensure the application lock uses a shared store (`LOCK_DSN`, for example Redis or a database) instead of the default `flock`. A shop already running multiple nodes normally has this configured for Shopware core anyway.

## Compatibility

- **Shopware Version**: 6.7.x
- **PHP Version**: 8.4+

## Support

For questions or support, contact Actualize at https://actualize.de

## License

This plugin is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Credits

Developed by Actualize
