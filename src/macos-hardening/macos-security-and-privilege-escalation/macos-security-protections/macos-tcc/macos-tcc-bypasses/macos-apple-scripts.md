# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Ni lugha ya scripting inayotumika kwa automation ya kazi **ikiingiliana na remote processes**. Hurahisisha sana **kuomba processes nyingine zitekeleze vitendo fulani**. **Malware** inaweza kutumia vibaya vipengele hivi ili kutumia vibaya functions zinazotolewa na processes nyingine.\
Kwa mfano, malware inaweza **kuingiza arbitrary JS code kwenye kurasa zilizofunguliwa za browser**. Au **kubofya kiotomatiki** baadhi ya allow permissions zinazoombwa kutoka kwa mtumiaji;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hapa kuna baadhi ya mifano: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Pata maelezo zaidi kuhusu malware inayotumia applescripts [**hapa**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Idhini za Apple Events ni **za mwelekeo**: prompt huonyeshwa kwa jozi ya **source process -> target process**. Mtumiaji akibofya **Allow**, maombi yajayo kutoka source hiyo hiyo kwenda target hiyo hiyo yataruhusiwa hadi ingizo hilo liwekwe upya. Wakati wa majaribio, kutoa ruhusa ya `Terminal -> Finder` au `Terminal -> System Events` mara moja kunatosha kutumia tena ruhusa hiyo baadaye bila popup nyingine.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Hili ni muhimu hasa wakati **target** ni **Finder**, kwa sababu Finder huwa na **Full Disk Access** kila wakati hata kama haionekani kwenye FDA UI. Kwa hiyo, host yoyote ambayo tayari ina Automation kupitia Finder inaweza kutumika kama proxy ya AppleScript/JXA kufikia faili zilizolindwa na TCC.<sup>[[1]](#references)</sup> Finder na System Events payloads za jumla tayari zimeandikwa kwenye [ukurasa mkuu wa TCC](../README.md) na kwenye [ukurasa wa Apple Events](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` ni entry point inayoonekana zaidi pekee. AppleScript na JXA zinaweza pia kutekelezwa kutoka kwenye **Mach-O binaries** kupitia **`NSAppleScript`** / **`OSAScript`**, jambo ambalo ni muhimu kwa evasion na pia kwa kuendesha ndani ya host ambayo tayari ina TCC grants za kuvutia.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ukitengeneza helper maalum inayotuma Apple Events moja kwa moja, kuipa **utambulisho halisi wa app** hufanya testing na operations ziwe za kuaminika zaidi. Kwa vitendo, hii inamaanisha ku-embed `Info.plist` yenye `CFBundleIdentifier` na `NSAppleEventsUsageDescription`, kusaini binary, na kuipa entitlement ya `com.apple.security.automation.apple-events`. Vinginevyo, prompt ya Apple Events mara nyingi huhusishwa na **parent host** (kwa mfano `Terminal`), au utekelezaji wa `NSAppleScript` hushindwa tu ukiwa na errors zinazochanganya za `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Apple scripts zinaweza "**compiled**" kwa urahisi. Versions hizi zinaweza "**decompiled**" kwa urahisi kwa kutumia `osadecompile`

Hata hivyo, scripts hizi pia zinaweza **exported as "Read only"** (kupitia option ya "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
na katika hali hii maudhui hayawezi ku-decompile hata kwa kutumia `osadecompile`

Hata hivyo, bado kuna tools kadhaa zinazoweza kutumika kuelewa aina hii ya executables, [**soma utafiti huu kwa maelezo zaidi**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) pamoja na [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) zitakuwa muhimu sana kuelewa jinsi script inavyofanya kazi.

## Marejeleo

- [1] [Kukwepa Protections za macOS TCC za Faragha ya Mtumiaji kwa Bahati Mbaya na kwa Makusudi](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Kufanya AppleScript Ifanye Kazi katika macOS CLI Tools: Sehemu Zisizoandikwa](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Jinsi Offensive Actors Wanavyotumia AppleScript Kushambulia macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Matukio ya Reverse Engineering ya Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
