# Security Policy

## Supported versions

Security fixes are released for the latest version only. Please check that the issue still occurs on the latest release before reporting it.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report it privately via GitHub instead: [Report a vulnerability](https://github.com/actualizer/ActPasskey/security/advisories/new). Only you and the maintainers can see the report. If you cannot use GitHub, send an email to plugin@actualize.de.

Please include:

- the plugin version and Shopware version
- whether the Storefront or the Administration is affected
- the steps to reproduce
- what an attacker gains

## What to expect

- An acknowledgement within 7 days.
- Once confirmed, a fix is released as a new version. The advisory is published after that release, crediting you unless you prefer otherwise.

## Scope

In scope, for both the Storefront and the Administration:

- Signing in as another account, or signing in without a valid passkey.
- Reusing a challenge, or using a passkey on a domain it was not created for.
- Listing, registering, renaming or revoking passkeys of another account without being allowed to.
- Registering, renaming or revoking a passkey without the password confirmation the Administration requires.
- WebAuthn payloads or credential data written to logs or exposed in responses.

Out of scope:

- The behaviour described under "Known limitations" in the README, such as the Administration SSO restriction or multi-node setups without a shared cache and lock store.
- Weaknesses of a browser, an operating system or an authenticator.
- Vulnerabilities in Shopware itself. Please report those to Shopware: <https://github.com/shopware/shopware/security/policy>.
