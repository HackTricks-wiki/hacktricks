# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Dit is 'n scripting-taal wat vir taakoutomatisering gebruik word en met **remote processes** interaksie het. Dit maak dit redelik maklik om **ander prosesse te vra om sekere aksies uit te voer**. **Malware** kan hierdie funksies misbruik om funksies wat deur ander prosesse uitgevoer word, te misbruik.\
Byvoorbeeld, malware kan **arbitrêre JS-kode in bladsye wat in 'n browser oopgemaak is, inject**. Of **outomaties klik** op sekere toestemmingversoeke wat aan die gebruiker vertoon word;<sup>[[3]](#references)</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier is ’n paar voorbeelde: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Vind meer inligting oor malware wat AppleScripts gebruik [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC-eienaardighede

Apple Events-goedkeurings is **rigtingafhanklik**: die prompt is vir ’n **source process -> target process**-paar. Sodra die gebruiker **Allow** klik, word toekomstige versoeke vanaf dieselfde bron na dieselfde teiken toegelaat totdat die inskrywing teruggestel word. Tydens toetsing is dit genoeg om een keer toestemming vir `Terminal -> Finder` of `Terminal -> System Events` te verleen om die permission later weer te gebruik sonder nog ’n popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dit is veral relevant wanneer die **target** **Finder** is, omdat Finder altyd **Full Disk Access** het, selfs al verskyn dit nie in die FDA UI nie. Daarom kan enige host wat reeds **Automation** oor Finder het, as ’n AppleScript/JXA-proxy gebruik word om toegang tot TCC-beskermde lêers te verkry.<sup>[[1]](#references)</sup> Die generiese Finder- en System Events-payloads is reeds in [die hoof-TCC-bladsy](../README.md) en op [die Apple Events-bladsy](../macos-apple-events.md) gedokumenteer.

### Moderne offensiewe tradecraft

`/usr/bin/osascript` is slegs die mees sigbare toegangspunt. AppleScript en JXA kan ook vanaf **Mach-O binaries** via **`NSAppleScript`** / **`OSAScript`** uitgevoer word, wat nuttig is vir beide ontduiking en om binne ’n host te bly wat reeds interessante TCC-toestemmings het.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
As jy 'n pasgemaakte helper bou wat Apple Events direk stuur, maak dit toetsing en bedrywighede baie meer betroubaar om dit 'n **werklike app-identiteit** te gee. In die praktyk beteken dit dat 'n `Info.plist` met `CFBundleIdentifier` en `NSAppleEventsUsageDescription` ingebed moet word, die binary onderteken moet word, en die `com.apple.security.automation.apple-events` entitlement toegestaan moet word. Andersins word die Apple Events-prompt dikwels aan die **ouer-host** (byvoorbeeld `Terminal`) toegeskryf, of die `NSAppleScript`-uitvoering misluk eenvoudig met verwarrende `-1750` / `errOSASystemError`-foute.<sup>[[2]](#references)</sup>

Apple scripts kan maklik "**compiled**" word. Hierdie weergawes kan maklik met `osadecompile` "**decompiled**" word.

Hierdie scripts kan egter ook as **"Read only"** (via die "Export..."-opsie) **uitgevoer** word:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
en in hierdie geval kan die inhoud nie eens met `osadecompile` gedekomileer word nie

Daar is egter steeds sommige tools wat gebruik kan word om hierdie soort uitvoerbare lêers te verstaan, [**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Die tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) saam met [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) sal baie nuttig wees om te verstaan hoe die script werk.

## Verwysings

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
