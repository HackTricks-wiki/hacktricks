# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Ni lugha ya scripting inayotumika kwa automation ya task **ikiingiliana na remote processes**. Hurahisisha sana **kuomba processes nyingine zitekeleze actions fulani**. **Malware** inaweza kutumia vibaya vipengele hivi ili kutumia vibaya functions zilizo-exportiwa na processes nyingine.\
Kwa mfano, malware inaweza **ku-inject JS code kiholela kwenye kurasa zilizofunguliwa kwenye browser**. Au **kubofya kiotomatiki** baadhi ya ruhusa za Allow zinazoombwa kwa mtumiaji;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hapa una baadhi ya mifano: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Pata maelezo zaidi kuhusu malware inayotumia applescripts [**hapa**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Uidhinishaji wa Apple Events ni **wa mwelekeo**: prompt ni ya jozi ya **source process -> target process**. Mtumiaji akibofya **Allow**, maombi yajayo kutoka kwa source ileile kwenda kwa target ileile yataruhusiwa hadi ingizo hilo liwekwe upya. Wakati wa testing, kutoa ruhusa kwa `Terminal -> Finder` au `Terminal -> System Events` mara moja kunatosha kutumia tena ruhusa hiyo baadaye bila popup nyingine.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Hili ni muhimu hasa wakati **target** ni **Finder**, kwa sababu Finder daima ina **Full Disk Access** hata kama haionekani kwenye FDA UI. Kwa hiyo, host yoyote ambayo tayari ina Automation juu ya Finder inaweza kutumika kama proxy ya AppleScript/JXA kufikia faili zinazolindwa na TCC.<sup>[1]</sup> Payloads za kawaida za Finder na System Events tayari zimeandikwa kwenye [ukurasa mkuu wa TCC](../README.md) na kwenye [ukurasa wa Apple Events](../macos-apple-events.md).

### Mbinu za kisasa za offensive tradecraft

`/usr/bin/osascript` ni entry point inayoonekana zaidi pekee. AppleScript na JXA pia zinaweza kutekelezwa kutoka kwenye **Mach-O binaries** kupitia **`NSAppleScript`** / **`OSAScript`**, jambo ambalo ni muhimu kwa evasion na pia kwa kuishi ndani ya host ambayo tayari ina TCC grants zenye manufaa.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ukitengeneza custom helper inayotuma Apple Events moja kwa moja, kuipa **real app identity** hufanya testing na operations ziwe za kuaminika zaidi. Kwa vitendo, hii inamaanisha ku-embed `Info.plist` yenye `CFBundleIdentifier` na `NSAppleEventsUsageDescription`, kusaini binary, na kutoa entitlement ya `com.apple.security/automation.apple-events`. Vinginevyo, prompt ya Apple Events mara nyingi huhusishwa na **parent host** (kwa mfano `Terminal`), au execution ya `NSAppleScript` hushindwa tu ikiwa na errors zinazochanganya za `-1750` / `errOSASystemError`.<sup>[2]</sup>

Apple scripts zinaweza kwa urahisi kuwa "**compiled**". Versions hizi zinaweza kwa urahisi kuwa "**decompiled**" kwa kutumia `osadecompile`

Hata hivyo, scripts hizi pia zinaweza **ku-exportiwa kama "Read only"** (kupitia option ya **"Export..."**):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
na katika hali hii maudhui hayawezi ku-decompile hata kwa kutumia `osadecompile`

Hata hivyo, bado kuna tools kadhaa zinazoweza kutumika kuelewa aina hii ya executables, [**soma research hii kwa maelezo zaidi**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) pamoja na [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) zitakuwa muhimu sana kuelewa jinsi script inavyofanya kazi.

## Marejeo

- [1] [Kukwepa macOS TCC User Privacy Protections kwa bahati mbaya na kwa makusudi](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Kufanya AppleScript ifanye kazi katika macOS CLI Tools: Sehemu ambazo hazijaandikwa rasmi](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Jinsi Offensive Actors wanavyotumia AppleScript kushambulia macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures katika ku-reverse Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
