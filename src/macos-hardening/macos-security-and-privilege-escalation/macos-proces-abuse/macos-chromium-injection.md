# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Grundinformationen

Chromium-basierte Browser wie Google Chrome, Microsoft Edge, Brave und andere. Diese Browser basieren auf dem Chromium-Open-Source-Projekt, was bedeutet, dass sie eine gemeinsame Basis teilen und daher ähnliche Funktionen und Entwickleroptionen haben.

#### `--load-extension` Flag

Das `--load-extension` Flag wird verwendet, wenn ein Chromium-basierter Browser über die Befehlszeile oder ein Skript gestartet wird. Dieses Flag ermöglicht es, **eine oder mehrere Erweiterungen automatisch** beim Start in den Browser zu laden.

#### `--use-fake-ui-for-media-stream` Flag

Das `--use-fake-ui-for-media-stream` Flag ist eine weitere Befehlszeilenoption, die verwendet werden kann, um Chromium-basierte Browser zu starten. Dieses Flag ist dafür ausgelegt, **die normalen Benutzeraufforderungen zu umgehen, die um Erlaubnis bitten, auf Medienströme von der Kamera und dem Mikrofon zuzugreifen**. Wenn dieses Flag verwendet wird, gewährt der Browser automatisch die Erlaubnis für jede Website oder Anwendung, die Zugriff auf die Kamera oder das Mikrofon anfordert.

### Werkzeuge

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Beispiel
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Finde weitere Beispiele in den Tool-Links

## Referenzen

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
