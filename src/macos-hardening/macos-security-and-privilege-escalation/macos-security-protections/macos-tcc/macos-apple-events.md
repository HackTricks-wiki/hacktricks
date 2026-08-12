# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**Apple events** sind strukturierte Interprozessnachrichten, die Anwendungen verwenden, um Operationen oder Daten von anderen Anwendungen anzufordern. Der **Apple Event Manager** stellt APIs zum Erstellen, Senden, Empfangen und Beantworten dieser Nachrichten bereit.<sup>[[1]](#references)</sup>

Unter macOS ist der wichtigste Broker `/System/Library/CoreServices/appleeventsd`, der den Mach-Service `com.apple.coreservices.appleevents` registriert. Anwendungen, die Events empfangen, registrieren bei diesem Service einen Apple-event-Mach-Port; Sender erhalten darüber den Zielport.<sup>[[3]](#references)</sup>

Sandbox-Regeln und Entitlements beschränken diese Kommunikation. Ein Sandbox-Profil formuliert die erforderlichen Operationen üblicherweise als `allow appleevent-send` sowie als Mach-Lookup für `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Die öffentliche `com.apple.security.temporary-exception.apple-events`-Berechtigung kann eine sandboxed Anwendung auf benannte Ziel-Bundle-Identifiers beschränken. Bei der Analyse von Apple-signierten Komponenten sollte auch die private `com.apple.private.appleevents`-Berechtigung geprüft werden; private Apple-Berechtigungen sind für Anwendungen von Drittanbietern normalerweise nicht verfügbar.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Setze die Umgebungsvariable **`AEDebugSends`**, um Informationen über die von einem Prozess gesendeten Apple events zu protokollieren:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - Temporäre Ausnahmeberechtigungen für die App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Umgebungsvariablen für das Apple-event-Debugging](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
