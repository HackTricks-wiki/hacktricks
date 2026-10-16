# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

**Apple događaji** su strukturirane međuprocesne poruke koje aplikacije koriste da bi od drugih aplikacija zatražile operacije ili podatke. **Apple Event Manager** pruža API-je za kreiranje, slanje, primanje i obradu ovih poruka.<sup>[[1]](#references)</sup>

Na macOS-u je glavni posrednik `/System/Library/CoreServices/appleeventsd`, koji registruje Mach servis `com.apple.coreservices.appleevents`. Aplikacije koje primaju događaje registruju Apple-event Mach port kod ovog servisa; pošiljaoci preko njega dobijaju odredišni port.<sup>[[3]](#references)</sup>

Sandbox pravila i ovlašćenja ograničavaju ovu komunikaciju. Sandbox profil obično definiše potrebne operacije pomoću `allow appleevent-send` i Mach lookup-a za `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Javno ovlašćenje `com.apple.security.temporary-exception.apple-events` može da ograniči sandboxed aplikaciju na imenovane identifikatore odredišnih paketa. Pri analizi komponenti koje je potpisao Apple, proverite i privatno ovlašćenje `com.apple.private.appleevents`; privatna Apple ovlašćenja obično nisu dostupna aplikacijama trećih strana.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Podesite promenljivu okruženja **`AEDebugSends`** da biste beležili informacije o Apple događajima koje proces šalje:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Da biste povezali Automation dozvolu sa pošiljaocem i primaocem, pogledajte [TCC dozvole za Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Apple Developer Documentation - Menadžer Apple događaja](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - Privremena izuzeća iz App Sandbox ovlašćenja](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X i iOS Internals - Promenljive okruženja za otklanjanje grešaka u Apple događajima](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
