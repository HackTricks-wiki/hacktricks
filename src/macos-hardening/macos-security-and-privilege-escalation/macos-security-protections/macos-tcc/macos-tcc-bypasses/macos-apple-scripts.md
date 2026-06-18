# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Dit is 'n skriptaal wat gebruik word vir taakoutomatisering **wat met afgeleë prosesse interaksie het**. Dit maak dit redelik maklik om **ander prosesse te vra om sekere aksies uit te voer**. **Malware** kan hierdie kenmerke misbruik om funksies te misbruik wat deur ander prosesse uitgevoer word.\
Byvoorbeeld, malware kan **willekeurige JS-kode in oop bladsye in die browser inspuit**. Of **outo-kliek** op sekere laat-toestemming-versoeke wat aan die gebruiker vertoon word;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier het jy ’n paar voorbeelde: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Vind meer inligting oor malware wat AppleScripts gebruik [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC eienaardighede

Apple Events-goedkeurings is **rigtinggebonde**: die prompt is vir ’n **source process -> target process**-paar. Sodra die gebruiker **Allow** klik, word toekomstige versoeke van dieselfde source na dieselfde target toegelaat totdat die entry teruggestel word. Tydens toetsing is dit genoeg om `Terminal -> Finder` of `Terminal -> System Events` een keer toe te staan om die permission later weer te gebruik sonder ’n ander popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dit is veral relevant wanneer die **teiken** **Finder** is, omdat Finder altyd **Full Disk Access** het, selfs al verskyn dit nie in die FDA UI nie. Daarom kan enige host wat reeds Automation oor Finder het, gebruik word as 'n AppleScript/JXA-proxy om toegang te verkry tot TCC-beskermde files. Die generiese Finder- en System Events-payloads is reeds gedokumenteer in [the main TCC page](../README.md) en in [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` is slegs die mees sigbare entry point. AppleScript en JXA kan ook vanaf **Mach-O binaries** uitgevoer word via **`NSAppleScript`** / **`OSAScript`**, wat nuttig is vir beide evasion en om binne 'n host te bly wat reeds interessante TCC grants het.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
As jy ’n pasgemaakte helper bou wat Apple Events direk stuur, maak dit toetsing en operasies baie meer betroubaar as jy dit ’n **regte app-identiteit** gee. In die praktyk beteken dit om ’n `Info.plist` met `CFBundleIdentifier` en `NSAppleEventsUsageDescription` in te sluit, die binary te teken, en die `com.apple.security.automation.apple-events` entitlement toe te ken. Andersins word die Apple Events-prompt dikwels aan die **parent host** toegeskryf (byvoorbeeld `Terminal`) of die `NSAppleScript`-uitvoering misluk net met verwarrende `-1750` / `errOSASystemError`-foute.

Apple scripts kan maklik "**compiled**" word. Hierdie weergawes kan maklik met `osadecompile` "**decompiled**" word

Hierdie scripts kan egter ook as "**Read only**" uitgevoer word (via die "Export..."-opsie):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
en in hierdie geval kan die inhoud nie gedekompileer word nie, selfs met `osadecompile`

Daar is egter steeds sommige tools wat gebruik kan word om hierdie soort uitvoerbare lêers te verstaan, [**lees hierdie navorsing vir meer inligting**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Die tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) met [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) sal baie nuttig wees om te verstaan hoe die script werk.

## Verwysings

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
