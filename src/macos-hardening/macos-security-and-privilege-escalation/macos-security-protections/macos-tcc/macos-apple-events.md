# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Grundinformationen

**Apple Events** sind eine Funktion in Apples macOS, die es Anwendungen ermöglicht, miteinander zu kommunizieren. Sie sind Teil des **Apple Event Manager**, der ein Bestandteil des macOS-Betriebssystems ist und für die Verarbeitung der interprozessualen Kommunikation verantwortlich ist. Dieses System ermöglicht es einer Anwendung, einer anderen Anwendung eine Nachricht zu senden, um zu verlangen, dass sie eine bestimmte Operation ausführt, wie das Öffnen einer Datei, das Abrufen von Daten oder das Ausführen eines Befehls.

Der mina-Daemon ist `/System/Library/CoreServices/appleeventsd`, der den Dienst `com.apple.coreservices.appleevents` registriert.

Jede Anwendung, die Ereignisse empfangen kann, wird mit diesem Daemon überprüfen, indem sie ihren Apple Event Mach Port bereitstellt. Und wenn eine App ein Ereignis an ihn senden möchte, wird die App diesen Port vom Daemon anfordern.

Sandboxed-Anwendungen benötigen Berechtigungen wie `allow appleevent-send` und `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`, um in der Lage zu sein, Ereignisse zu senden. Beachten Sie, dass Berechtigungen wie `com.apple.security.temporary-exception.apple-events` einschränken können, wer Zugriff auf das Senden von Ereignissen hat, was Berechtigungen wie `com.apple.private.appleevents` erfordert.

> [!TIP]
> Es ist möglich, die Umgebungsvariable **`AEDebugSends`** zu verwenden, um Informationen über die gesendete Nachricht zu protokollieren:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
