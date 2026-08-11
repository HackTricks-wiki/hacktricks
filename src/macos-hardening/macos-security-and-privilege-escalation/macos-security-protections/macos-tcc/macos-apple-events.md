# Apple events w macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**Apple events** to ustrukturyzowane komunikaty międzyprocesowe, których aplikacje używają do żądania wykonania operacji lub pobrania danych z innych aplikacji. **Apple Event Manager** udostępnia interfejsy API do tworzenia, wysyłania, odbierania i obsługi tych komunikatów.<sup>[[1]](#references)</sup>

W systemie macOS głównym brokerem jest `/System/Library/CoreServices/appleeventsd`, który rejestruje usługę Mach `com.apple.coreservices.appleevents`. Aplikacje odbierające zdarzenia rejestrują port Mach Apple event w tej usłudze, a nadawcy uzyskują za jej pośrednictwem port docelowy.<sup>[[3]](#references)</sup>

Reguły sandboxa i uprawnienia ograniczają tę komunikację. Profil sandboxa musi zezwalać na wysyłanie Apple events i wyszukiwanie usługi Mach brokera. Uprawnienie `com.apple.security.temporary-exception.apple-events` może dodatkowo ograniczyć aplikację działającą w sandboxie do określonych identyfikatorów bundle aplikacji docelowych.<sup>[[2]](#references)</sup>

> [!TIP]
> Ustaw zmienną środowiskową **`AEDebugSends`**, aby rejestrować informacje o Apple events wysyłanych przez proces:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Dokumentacja Apple Developer - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Dokumentacja Apple Developer - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
