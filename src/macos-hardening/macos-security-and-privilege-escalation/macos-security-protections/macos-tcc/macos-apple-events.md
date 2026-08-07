# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**Apple Events** sind eine Funktion in Apples macOS, die es Anwendungen ermöglicht, miteinander zu kommunizieren. Sie sind Bestandteil des **Apple Event Manager**, einer Komponente des macOS-Betriebssystems, die für die Interprozesskommunikation zuständig ist. Dieses System ermöglicht es einer Anwendung, einer anderen Anwendung eine Nachricht zu senden und sie aufzufordern, eine bestimmte Operation auszuführen, etwa eine Datei zu öffnen, Daten abzurufen oder einen Befehl auszuführen.

Der zentrale daemon ist `/System/Library/CoreServices/appleeventsd`, der den Service `com.apple.coreservices.appleevents` registriert.

Jede Anwendung, die Events empfangen kann, registriert sich bei diesem daemon und übergibt dabei ihren Apple Event Mach Port. Wenn eine Anwendung ein Event an sie senden möchte, fordert sie diesen Port beim daemon an.

Sandboxed applications benötigen Privileges wie `allow appleevent-send` und `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`, um Events senden zu können. Beachte, dass Entitlements wie `com.apple.security.temporary-exception.apple-events` einschränken können, wer Zugriff zum Senden von Events hat, wofür möglicherweise Entitlements wie `com.apple.private.appleevents` erforderlich sind.

> [!TIP]
> Es ist möglich, die env variable **`AEDebugSends`** zu verwenden, um Informationen über die gesendete Nachricht zu protokollieren:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
