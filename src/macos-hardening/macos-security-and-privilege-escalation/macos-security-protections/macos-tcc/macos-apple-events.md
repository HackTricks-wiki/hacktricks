# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

**Apple events** su strukturirane međuprocesne poruke koje aplikacije koriste za zahtevanje operacija ili podataka od drugih aplikacija. **Apple Event Manager** obezbeđuje API-je za kreiranje, slanje, prijem i odgovaranje na ove poruke.<sup>[[1]](#references)</sup>

Na macOS-u, glavni broker je `/System/Library/CoreServices/appleeventsd`, koji registruje Mach servis `com.apple.coreservices.appleevents`. Aplikacije koje primaju events registruju Apple-event Mach port kod ovog servisa; pošiljaoci preko njega dobijaju odredišni port.<sup>[[3]](#references)</sup>

Sandbox pravila i entitlements ograničavaju ovu komunikaciju. Sandbox profil obično izražava potrebne operacije kao `allow appleevent-send` i Mach lookup za `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Javni entitlement `com.apple.security.temporary-exception.apple-events` može da ograniči aplikaciju u sandboxu na imenovane bundle identifikatore odredišta. Kada analizirate komponente potpisane od strane Apple-a, proverite i privatni entitlement `com.apple.private.appleevents`; privatni Apple entitlements obično nisu dostupni aplikacijama trećih strana.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Podesite promenljivu okruženja **`AEDebugSends`** da biste beležili informacije o Apple events koje proces šalje:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple dokumentacija za developere - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple dokumentacija za developere - Privremeni exception entitlements za App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Debug promenljive okruženja za Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
