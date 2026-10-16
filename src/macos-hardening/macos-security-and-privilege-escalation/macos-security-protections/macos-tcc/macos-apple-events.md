# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**Apple events** ni ujumbe wa interprocess wenye muundo maalum ambao programu hutumia kuomba shughuli au data kutoka kwa programu nyingine. **Apple Event Manager** hutoa API za kuunda, kutuma, kupokea na kujibu ujumbe huu.<sup>[[1]](#references)</sup>

Kwenye macOS, broker mkuu ni `/System/Library/CoreServices/appleeventsd`, ambayo husajili huduma ya Mach `com.apple.coreservices.appleevents`. Programu zinazopokea matukio husajili port ya Mach ya Apple event kupitia huduma hii; watumaji hupata port ya lengwa kupitia huduma hiyo.<sup>[[3]](#references)</sup>

Sheria za sandbox na entitlements hudhibiti mawasiliano haya. Wasifu wa sandbox mara nyingi huonyesha shughuli zinazohitajika kama `allow appleevent-send` na utafutaji wa Mach wa `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Entitlement ya umma `com.apple.security.temporary-exception.apple-events` inaweza kuzuia programu iliyo kwenye sandbox kutuma matukio kwa bundle identifiers maalum za wapokeaji. Unapochanganua vipengele vilivyotiwa saini na Apple, angalia pia entitlement ya faragha `com.apple.private.appleevents`; kwa kawaida, entitlement za faragha za Apple hazipatikani kwa programu za watu wengine.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Weka kigezo cha mazingira **`AEDebugSends`** ili kurekodi taarifa kuhusu matukio ya Apple yanayotumwa na mchakato:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Ili kuhusisha ruhusa ya Automation na mtumaji na mpokeaji wake, angalia [TCC Apple Events grants](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Nyaraka za Wasanidi wa Apple - Meneja wa Matukio ya Apple](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Nyaraka za Wasanidi wa Apple - Ruhusa za Vighairi vya Muda vya App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Ndani ya Mac OS X na iOS - Vigezo vya mazingira vya utatuzi wa Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
