# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**Apple-Events** sind strukturierte Interprozessnachrichten, mit denen Anwendungen Operationen oder Daten von anderen Anwendungen anfordern. Der **Apple Event Manager** stellt die APIs zum Erstellen, Senden, Empfangen und Beantworten dieser Nachrichten bereit.<sup>[[1]](#references)</sup>

Unter macOS ist der wichtigste Vermittler `/System/Library/CoreServices/appleeventsd`, der den Mach-Dienst `com.apple.coreservices.appleevents` registriert. Anwendungen, die Ereignisse empfangen, registrieren bei diesem Dienst einen Apple-Event-Mach-Port; Sender erhalten darüber den Ziel-Port.<sup>[[3]](#references)</sup>

Sandbox-Regeln und Entitlements beschränken diese Kommunikation. Ein Sandbox-Profil legt die erforderlichen Operationen üblicherweise mit `allow appleevent-send` und einer Mach-Abfrage für `com.apple.coreservices.appleevents` fest:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Die öffentliche `com.apple.security.temporary-exception.apple-events`-Berechtigung kann eine sandboxed Anwendung auf benannte Bundle-IDs als Ziele beschränken. Prüfen Sie bei der Analyse von Apple-signierten Komponenten auch die private Berechtigung `com.apple.private.appleevents`; private Apple-Berechtigungen stehen Drittanbieteranwendungen normalerweise nicht zur Verfügung.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Setzen Sie die Umgebungsvariable **`AEDebugSends`**, um Informationen zu den von einem Prozess gesendeten Apple events zu protokollieren:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Um eine Automation-Berechtigung ihrem Sender und Empfänger zuzuordnen, siehe [TCC-Berechtigungen für Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Apple-Entwicklerdokumentation – Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple-Entwicklerdokumentation – Berechtigungen für temporäre Ausnahmen der App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X und iOS Internals – Umgebungsvariablen zur Fehlerbehebung bei Apple Events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
