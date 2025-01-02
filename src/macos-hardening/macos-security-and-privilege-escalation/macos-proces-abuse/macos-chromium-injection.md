# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Przeglądarki oparte na Chromium, takie jak Google Chrome, Microsoft Edge, Brave i inne. Te przeglądarki są zbudowane na projekcie open-source Chromium, co oznacza, że dzielą wspólną bazę i mają podobne funkcjonalności oraz opcje dewelopera.

#### Flaga `--load-extension`

Flaga `--load-extension` jest używana podczas uruchamiania przeglądarki opartej na Chromium z linii poleceń lub skryptu. Ta flaga pozwala na **automatyczne załadowanie jednego lub więcej rozszerzeń** do przeglądarki przy starcie.

#### Flaga `--use-fake-ui-for-media-stream`

Flaga `--use-fake-ui-for-media-stream` to kolejna opcja wiersza poleceń, która może być używana do uruchamiania przeglądarek opartych na Chromium. Ta flaga jest zaprojektowana, aby **ominąć normalne monity użytkownika, które proszą o pozwolenie na dostęp do strumieni mediów z kamery i mikrofonu**. Gdy ta flaga jest używana, przeglądarka automatycznie przyznaje pozwolenie każdej stronie internetowej lub aplikacji, która prosi o dostęp do kamery lub mikrofonu.

### Narzędzia

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Przykład
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Znajdź więcej przykładów w linkach narzędzi

## Odniesienia

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
