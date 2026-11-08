# 1.3.1

- Fixed: version 1.3.0 did not start on Shopware 6.7.0 to 6.7.14 because it required a class that only exists from 6.7.15 on. Shops on those versions should update to 1.3.1. Below 6.7.15 Shopware issues no admin authorization codes, so ending sessions after a passkey removal works as before.
- Tested with Shopware 6.7.16.0.
- Added a changelog in English and German.

Earlier versions: see the [tags on GitHub](https://github.com/actualizer/ActPasskey/tags).
