# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

**Apple events** su strukturirane međuprocesne poruke koje aplikacije koriste za zahtevanje operacija ili podataka od drugih aplikacija. **Apple Event Manager** obezbeđuje API-je za kreiranje, slanje, primanje i odgovaranje na ove poruke.<sup>[[1]](#references)</sup>

Na macOS-u je glavni broker `/System/Library/CoreServices/appleeventsd`, koji registruje `com.apple.coreservices.appleevents` Mach servis. Aplikacije koje primaju događaje registruju Apple-event Mach port kod ovog servisa; pošiljaoci preko njega dobijaju odredišni port.<sup>[[3]](#references)</sup>

Sandbox pravila i entitlements ograničavaju ovu komunikaciju. sandbox profil zahteva dozvolu za slanje Apple events i pronalaženje brokerovog Mach servisa. `com.apple.security.temporary-exception.apple-events` entitlement može dodatno ograničiti sandboxed aplikaciju na imenovane destination bundle identifiers.<sup>[[2]](#references)</sup>

> [!TIP]
> Postavite promenljivu okruženja **`AEDebugSends`** da biste beležili informacije o Apple events koje proces šalje:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
