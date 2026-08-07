# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**Apple Events** ni kipengele katika Apple's macOS kinachoruhusu applications kuwasiliana. Ni sehemu ya **Apple Event Manager**, ambayo ni component ya macOS operating system inayohusika na kushughulikia interprocess communication. Mfumo huu huwezesha application moja kutuma message kwa application nyingine ili iombe ifanye operation fulani, kama vile kufungua file, kupata data, au kutekeleza command.

Daemon kuu ni `/System/Library/CoreServices/appleeventsd`, ambayo husajili service `com.apple.coreservices.appleevents`.

Kila application inayoweza kupokea events huwasiliana na daemon hii na kutoa Apple Event Mach Port yake. Na application inapotaka kutuma event kwake, application hiyo huomba port hii kutoka kwa daemon.

Sandboxed applications zinahitaji privileges kama `allow appleevent-send` na `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` ili ziweze kutuma events. Kumbuka kuwa entitlements kama `com.apple.security.temporary-exception.apple-events` zinaweza kuzuia ni nani anayeweza kutuma events, jambo ambalo litahitaji entitlements kama `com.apple.private.appleevents`.

> [!TIP]
> Inawezekana kutumia env variable **`AEDebugSends`** ili kurekodi taarifa kuhusu message iliyotumwa:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
