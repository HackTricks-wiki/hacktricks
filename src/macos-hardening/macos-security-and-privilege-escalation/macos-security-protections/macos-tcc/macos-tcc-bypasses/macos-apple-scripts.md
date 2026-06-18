# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Ni lugha ya scripting inayotumiwa kwa uendeshaji wa kazi kiotomatiki **ikishirikiana na remote processes**. Inaifanya kuwa rahisi sana ku **uliza processes nyingine zitekeleze baadhi ya actions**. **Malware** inaweza kutumia vibaya vipengele hivi ili kutumia functions zilizotolewa na processes nyingine.\
Kwa mfano, malware inaweza **kuingiza arbitrary JS code katika kurasa za browser zilizofunguliwa**. Au **kufanya auto click** baadhi ya allow permissions zilizoombwa kwa mtumiaji;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Find more info about malware using applescripts [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Apple Events approvals are **directional**: the prompt is for a **source process -> target process** pair. Once the user clicks **Allow**, future requests from the same source to the same target are allowed until the entry is reset. During testing, granting `Terminal -> Finder` or `Terminal -> System Events` once is enough to reuse the permission later without another popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Hili ni muhimu hasa wakati **target** ni **Finder**, kwa sababu Finder daima ina **Full Disk Access** hata kama haionekani kwenye UI ya FDA. Kwa hivyo, host yoyote ambayo tayari ina Automation juu ya Finder inaweza kutumika kama AppleScript/JXA proxy ili kufikia files zinazolindwa na TCC. Payloads za kawaida za Finder na System Events tayari zimeandikwa katika [the main TCC page](../README.md) na katika [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` ni tu entry point inayoonekana zaidi. AppleScript na JXA pia zinaweza ku-execute kutoka **Mach-O binaries** kupitia **`NSAppleScript`** / **`OSAScript`**, ambayo ni muhimu kwa evasion na pia kwa kuishi ndani ya host ambayo tayari ina TCC grants za kuvutia.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
If you build a custom helper that sends Apple Events directly, giving it a **real app identity** makes testing and operations much more reliable. In practice this means embedding an `Info.plist` with `CFBundleIdentifier` and `NSAppleEventsUsageDescription`, signing the binary, and granting the `com.apple.security.automation.apple-events` entitlement. Otherwise the Apple Events prompt is frequently attributed to the **parent host** (for example `Terminal`) or the `NSAppleScript` execution just fails with confusing `-1750` / `errOSASystemError` errors.

Apple scripts zinaweza ku**compiled** kwa urahisi. Matoleo haya yanaweza pia ku**decompiled** kwa urahisi na `osadecompile`

Hata hivyo, scripts hizi pia zinaweza ku**exported as "Read only"** (kupitia chaguo la "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
na katika kesi hii maudhui hayawezi ku-decompile hata kwa `osadecompile`

Hata hivyo, bado kuna baadhi ya tools zinazoweza kutumika kuelewa aina hii ya executables, [**soma utafiti huu kwa maelezo zaidi**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) pamoja na [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) itakuwa muhimu sana ili kuelewa jinsi script inavyofanya kazi.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
