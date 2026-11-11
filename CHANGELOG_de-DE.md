# 1.3.2

- Behoben: Unter Shopware 6.7.0 bis 6.7.2 schlug die Passwort-Bestätigung im Kundenkonto fehl, unter 6.7.0 außerdem das Laden der Passkeys eines Verkaufskanals, weil das Plugin Shopware-Schnittstellen nutzte, die es erst in späteren 6.7-Versionen gibt.

# 1.3.1

- Behoben: Version 1.3.0 startete unter Shopware 6.7.0 bis 6.7.14 nicht, weil sie eine Klasse voraussetzte, die es erst ab 6.7.15 gibt. Shops auf diesen Versionen sollten auf 1.3.1 aktualisieren. Unter 6.7.15 vergibt Shopware keine Admin-Autorisierungscodes, daher funktioniert das Beenden der Sitzungen nach dem Entfernen eines Passkeys wie bisher.
- Getestet mit Shopware 6.7.16.0.
- Changelog auf Englisch und Deutsch ergänzt.

Frühere Versionen: siehe [Tags auf GitHub](https://github.com/actualizer/ActPasskey/tags).
