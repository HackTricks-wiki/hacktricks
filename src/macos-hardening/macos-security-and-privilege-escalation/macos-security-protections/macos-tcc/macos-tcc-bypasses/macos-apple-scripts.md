# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Ni lugha ya scripting inayotumika kwa automation ya kazi kwa **kuingiliana na remote processes**. Hurahisisha sana **kuomba processes zingine zitekeleze actions fulani**. **Malware** inaweza kutumia vibaya vipengele hivi ili kutumia vibaya functions zinazotolewa na processes zingine.\
Kwa mfano, malware inaweza **ku-inject arbitrary JS code kwenye pages zilizofunguliwa kwenye browser**. Au **kubofya kiotomatiki** baadhi ya allow permissions zinazoombwa kutoka kwa mtumiaji;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hapa kuna baadhi ya mifano: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Pata maelezo zaidi kuhusu malware inayotumia applescripts [**hapa**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation / TCC quirks

Vibali vya Apple Events ni **vya mwelekeo**: kidokezo kinahusu jozi ya **mchakato chanzo -> mchakato lengwa**. Mtumiaji akibofya **Allow**, maombi yajayo kutoka chanzo hicho hicho kwenda lengwa hilo hilo yanaruhusiwa hadi ingizo hilo liwekwe upya. Wakati wa majaribio, kutoa ruhusa ya `Terminal -> Finder` au `Terminal -> System Events` mara moja kunatosha kutumia tena ruhusa hiyo baadaye bila kidokezo kingine.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Hili ni muhimu hasa wakati **target** ni **Finder**, kwa sababu Finder huwa na **Full Disk Access** kila wakati hata kama haionekani kwenye FDA UI. Kwa hiyo, host yoyote ambayo tayari ina **Automation** juu ya Finder inaweza kutumika kama proxy ya AppleScript/JXA kufikia faili zinazolindwa na TCC.<sup>[[1]](#references)</sup> Payloads za jumla za Finder na System Events tayari zimeandikwa kwenye [ukurasa mkuu wa TCC](../README.md) na kwenye [ukurasa wa Apple Events](../macos-apple-events.md).

### Mbinu za kisasa za offensive tradecraft

`/usr/bin/osascript` ndiyo entry point inayoonekana zaidi. AppleScript na JXA pia zinaweza kutekelezwa kutoka kwenye **Mach-O binaries** kupitia **`NSAppleScript`** / **`OSAScript`**, jambo ambalo ni muhimu kwa evasion na pia kwa kuishi ndani ya host ambayo tayari ina TCC grants zenye manufaa.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ukijenga custom helper inayotuma Apple Events moja kwa moja, kuipa **real app identity** hufanya testing na operations kuwa za kuaminika zaidi. Kwa vitendo, hii inamaanisha ku-embed `Info.plist` yenye `CFBundleIdentifier` na `NSAppleEventsUsageDescription`, kusaini binary, na kutoa entitlement ya `com.apple.security.automation.apple-events`. Vinginevyo, Apple Events prompt mara nyingi huhusishwa na **parent host** (kwa mfano `Terminal`) au utekelezaji wa `NSAppleScript` hushindwa tu kwa errors zinazochanganya za `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Apple scripts zinaweza kwa urahisi "**compiled**". Matoleo haya yanaweza kwa urahisi "**decompiled**" kwa kutumia `osadecompile`

Hata hivyo, scripts hizi pia zinaweza **exported as "Read only"** (kupitia chaguo la "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
na katika hali hii maudhui hayawezi kufanyiwa decompile hata kwa kutumia `osadecompile`

Hata hivyo, bado kuna baadhi ya tools zinazoweza kutumika kuelewa aina hii ya executables, [**soma research hii kwa maelezo zaidi**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) pamoja na [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) zitakuwa muhimu sana kuelewa jinsi script inavyofanya kazi.

## Marejeo

- [1] [Kupita kwa bahati mbaya na kwa kubuniwa ulinzi wa Faragha ya Mtumiaji wa macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Kufanya AppleScript ifanye kazi katika macOS CLI Tools: Sehemu ambazo hazijaandikwa kwenye nyaraka](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Jinsi Wavamizi Hutumia AppleScript Kushambulia macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Matukio ya Kuchanganua AppleScripts Hasidi za Run-Only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
