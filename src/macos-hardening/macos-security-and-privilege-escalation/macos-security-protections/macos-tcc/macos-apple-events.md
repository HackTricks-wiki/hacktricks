# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informacje podstawowe

**Apple events** to ustrukturyzowane komunikaty międzyprocesowe, których aplikacje używają do żądania wykonania operacji lub udostępnienia danych przez inne aplikacje. **Apple Event Manager** udostępnia interfejsy API do tworzenia, wysyłania, odbierania i obsługi tych komunikatów.<sup>[[1]](#references)</sup>

W systemie macOS głównym brokerem jest `/System/Library/CoreServices/appleeventsd`, który rejestruje usługę Mach `com.apple.coreservices.appleevents`. Aplikacje odbierające zdarzenia rejestrują port Mach dla zdarzeń Apple w tej usłudze; nadawcy uzyskują za jej pośrednictwem port docelowy.<sup>[[3]](#references)</sup>

Reguły sandboxa i entitlements ograniczają tę komunikację. Profil sandboxa zwykle określa wymagane operacje za pomocą `allow appleevent-send` oraz wyszukiwania Mach dla `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Publiczne uprawnienie `com.apple.security.temporary-exception.apple-events` może ograniczyć aplikację działającą w sandboxie do wskazanych identyfikatorów pakietów docelowych. Podczas analizowania komponentów podpisanych przez Apple sprawdź również prywatne uprawnienie `com.apple.private.appleevents`; prywatne uprawnienia Apple zwykle nie są dostępne dla aplikacji innych firm.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Ustaw zmienną środowiskową **`AEDebugSends`**, aby rejestrować informacje o zdarzeniach Apple wysyłanych przez proces:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Aby przypisać uprawnienie Automation do nadawcy i odbiorcy, zobacz [uprawnienia TCC Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Dokumentacja Apple dla deweloperów - Menedżer Apple Event](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Dokumentacja Apple dla deweloperów - Uprawnienia tymczasowych wyjątków App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Wewnętrzne mechanizmy Mac OS X i iOS - Zmienne środowiskowe debugowania Apple-event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
