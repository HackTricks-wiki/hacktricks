# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informacje podstawowe

**Apple events** to ustrukturyzowane komunikaty międzyprocesowe, których aplikacje używają do żądania wykonania operacji lub pobrania danych z innych aplikacji. **Apple Event Manager** udostępnia API do tworzenia, wysyłania, odbierania i obsługi tych komunikatów.<sup>[[1]](#references)</sup>

W systemie macOS głównym brokerem jest `/System/Library/CoreServices/appleeventsd`, który rejestruje usługę Mach `com.apple.coreservices.appleevents`. Aplikacje odbierające zdarzenia rejestrują port Mach Apple event w tej usłudze, a nadawcy uzyskują za jej pośrednictwem port docelowy.<sup>[[3]](#references)</sup>

Reguły sandboxa i entitlements ograniczają tę komunikację. Profil sandboxa często określa wymagane operacje jako `allow appleevent-send` oraz wyszukiwanie Mach dla `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Publiczne entitlement `com.apple.security.temporary-exception.apple-events` może ograniczyć aplikację działającą w sandboxie do nazwanych identyfikatorów bundle miejsc docelowych. Podczas analizowania komponentów podpisanych przez Apple sprawdź również prywatne entitlement `com.apple.private.appleevents`; prywatne entitlementy Apple zwykle nie są dostępne dla aplikacji firm trzecich.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Ustaw zmienną środowiskową **`AEDebugSends`**, aby rejestrować informacje o Apple events wysyłanych przez proces:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Dokumentacja Apple dla deweloperów - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Dokumentacja Apple dla deweloperów - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - zmienne środowiskowe debugowania Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
