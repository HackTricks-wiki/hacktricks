# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript ni lugha ya automation inayoweza kutuma Apple Events kwa applications zinazoweza kuandikiwa scripts. Ikiwa malware imepewa grants husika, inaweza kuingiza JavaScript kwenye kichupo cha scriptable browser au kutumia System Events/Accessibility kubofya permission dialog. Apple Events na Accessibility ni TCC services tofauti na kwa kawaida huhitaji approvals zao kutoka kwa mtumiaji.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
The `abbeycode/AppleScripts` repository ina mifano ya automation.<sup>[[7]](#references)</sup>\
Pata maelezo zaidi kuhusu malware inayotumia applescripts [**hapa**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation / TCC quirks

Idhini za Apple Events zina **mwelekeo**: prompt inalenga jozi ya **source process -> target process**. Baada ya mtumiaji kubofya **Allow**, maombi yajayo kutoka kwa source hiyo hiyo kwenda kwa target hiyo hiyo yanaruhusiwa hadi ingizo hilo liwekwe upya. Wakati wa testing, kutoa `Terminal -> Finder` au `Terminal -> System Events` mara moja kunatosha kutumia tena ruhusa hiyo baadaye bila popup nyingine.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Hili ni muhimu hasa wakati **target** ni **Finder**, kwa sababu Finder huwa na **Full Disk Access** kila wakati hata kama haionekani kwenye FDA UI. Kwa hiyo, host yoyote ambayo tayari ina Automation kupitia Finder inaweza kutumika kama proxy ya AppleScript/JXA kufikia faili zilizolindwa na TCC.<sup>[[1]](#references)</sup> Payloads za jumla za Finder na System Events tayari zimeandikwa katika [ukurasa mkuu wa TCC](../README.md) na katika [ukurasa wa Apple Events](../macos-apple-events.md).

### Mbinu za kisasa za offensive tradecraft

`/usr/bin/osascript` ni entry point inayoonekana zaidi pekee. AppleScript na JXA pia zinaweza kutekelezwa kutoka kwenye **Mach-O binaries** kupitia **`NSAppleScript`** / **`OSAScript`**, jambo ambalo ni muhimu kwa evasion na pia kwa kufanya kazi ndani ya host ambayo tayari ina TCC grants zenye manufaa.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ukitengeneza helper maalum inayotuma Apple Events moja kwa moja, kuipa **utambulisho halisi wa app** hufanya testing na operations ziwe zenye kutegemeka zaidi. Kwa kawaida hii inamaanisha ku-embed `Info.plist` yenye `CFBundleIdentifier` na `NSAppleEventsUsageDescription`, kusaini binary, na kutoa entitlement ya `com.apple.security.automation.apple-events`. Vinginevyo, prompt ya Apple Events mara nyingi huhusishwa na **parent host** (kwa mfano `Terminal`) au utekelezaji wa `NSAppleScript` hushindwa tu na errors zinazoleta mkanganyiko za `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

AppleScripts zinaweza kuhifadhiwa katika compiled form na kwa kawaida zika-decompile kwa `osadecompile`.

Hata hivyo, scripts hizi pia zinaweza **ku-exportiwa kama "Read only"** (kupitia chaguo la "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Katika hali hiyo, `osadecompile` hukataa kurejesha source ya kawaida, lakini bytecode na istilahi za Apple Event bado zinaweza kuchanganuliwa.

Utafiti wa SentinelOne kuhusu run-only unaeleza jinsi ya kurejesha muundo licha ya kizuizi hicho. `applescript-disassembler` na `aevt_decompile` husaidia kukagua script iliyocompile na data ya Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Kukwepa Ulinzi wa Faragha wa Mtumiaji wa macOS TCC kwa Bahati Mbaya na kwa Makusudi](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Kufanya AppleScript Ifanye Kazi katika Zana za CLI za macOS: Sehemu Zisizoandikwa](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Jinsi Wahusika Wenye Nia Mbaya Wanavyotumia AppleScript Kushambulia macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Matukio ya Reverse Engineering ya AppleScripts Hasidi za Run-Only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [Mifano ya AppleScripts ya abbeycode](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
