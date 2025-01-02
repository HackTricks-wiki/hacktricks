# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple Events** ni kipengele katika macOS ya Apple kinachowezesha programu kuwasiliana na kila mmoja. Ni sehemu ya **Meneja wa Matukio ya Apple**, ambao ni kipengele cha mfumo wa uendeshaji wa macOS kinachohusika na kushughulikia mawasiliano kati ya michakato. Mfumo huu unaruhusu programu moja kutuma ujumbe kwa programu nyingine kuomba ifanye operesheni fulani, kama kufungua faili, kupata data, au kutekeleza amri.

Daemoni ya mina ni `/System/Library/CoreServices/appleeventsd` ambayo inasajili huduma `com.apple.coreservices.appleevents`.

Kila programu inayoweza kupokea matukio itakuwa ikikagua na daemoni hii ikitoa Apple Event Mach Port yake. Na wakati programu inataka kutuma tukio kwake, programu hiyo itahitaji port hii kutoka kwa daemoni.

Programu zilizowekwa kwenye sandbox zinahitaji ruhusa kama `allow appleevent-send` na `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` ili kuweza kutuma matukio. Kumbuka kwamba ruhusa kama `com.apple.security.temporary-exception.apple-events` zinaweza kuzuia nani anayeweza kutuma matukio ambayo yatahitaji ruhusa kama `com.apple.private.appleevents`.

> [!TIP]
> Inawezekana kutumia variable ya env **`AEDebugSends`** ili kurekodi taarifa kuhusu ujumbe uliopelekwa:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
