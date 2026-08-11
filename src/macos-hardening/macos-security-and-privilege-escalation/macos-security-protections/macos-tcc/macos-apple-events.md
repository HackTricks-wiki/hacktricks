# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**Apple events** sind strukturierte Interprozessnachrichten, die Anwendungen verwenden, um Operationen oder Daten von anderen Anwendungen anzufordern. Der **Apple Event Manager** stellt APIs zum Erstellen, Senden, Empfangen und Beantworten dieser Nachrichten bereit.<sup>[[1]](#references)</sup>

Unter macOS ist der zentrale Broker `/System/Library/CoreServices/appleeventsd`, der den Mach-Service `com.apple.coreservices.appleevents` registriert. Anwendungen, die Events empfangen, registrieren bei diesem Service einen Apple-Event-Mach-Port; Sender beziehen darüber den Zielport.<sup>[[3]](#references)</sup>

Sandbox-Regeln und Entitlements beschränken diese Kommunikation. Ein Sandbox-Profil benötigt die Berechtigung, Apple events zu senden und den Mach-Service des Brokers nachzuschlagen. Das Entitlement `com.apple.security.temporary-exception.apple-events` kann eine sandboxed Anwendung zusätzlich auf benannte Ziel-Bundle-Identifier beschränken.<sup>[[2]](#references)</sup>

> [!TIP]
> Setze die Umgebungsvariable **`AEDebugSends`**, um Informationen über die von einem Prozess gesendeten Apple events zu protokollieren:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple-Entwicklerdokumentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple-Entwicklerdokumentation - Temporäre Ausnahme-Entitlements für die App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Umgebungsvariablen zur Fehlersuche bei Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
