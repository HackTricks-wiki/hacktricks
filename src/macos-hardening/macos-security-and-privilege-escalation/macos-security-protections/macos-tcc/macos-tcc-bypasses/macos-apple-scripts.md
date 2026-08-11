# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript is ’n automation language wat Apple Events na scriptable applications kan stuur. Met die relevante grants kan malware JavaScript in ’n scriptable browser-tab injecteer of System Events/Accessibility gebruik om op ’n permission dialog te klik. Apple Events en Accessibility is afsonderlike TCC-services en vereis gewoonlik hul onderskeie user approvals.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Die `abbeycode/AppleScripts`-repository bevat voorbeelde van automation.<sup>[[7]](#references)</sup>\
Vind [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) meer inligting oor malware wat AppleScripts gebruik.<sup>[[3]](#references)</sup>

### Automation / TCC-eienaardighede

Apple Events-goedkeurings is **rigtinggewend**: die prompt is vir ’n **source process -> target process**-paar. Sodra die gebruiker **Allow** klik, word toekomstige versoeke van dieselfde bron na dieselfde teiken toegelaat totdat die entry teruggestel word. Tydens testing is dit genoeg om `Terminal -> Finder` of `Terminal -> System Events` een keer toe te laat, sodat die permission later hergebruik kan word sonder nog ’n popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dit is veral relevant wanneer die **target** **Finder** is, omdat Finder altyd **Full Disk Access** het, selfs al verskyn dit nie in die FDA UI nie. Daarom kan enige host wat reeds **Automation** oor Finder het, as ’n AppleScript/JXA-proxy gebruik word om toegang tot TCC-protected files te verkry.<sup>[[1]](#references)</sup> Die generiese Finder- en System Events-payloads is reeds in [the main TCC page](../README.md) en in [the Apple Events page](../macos-apple-events.md) gedokumenteer.

### Moderne offensive tradecraft

`/usr/bin/osascript` is slegs die sigbaarste entry point. AppleScript en JXA kan ook vanaf **Mach-O binaries** via **`NSAppleScript`** / **`OSAScript`** uitgevoer word, wat nuttig is vir beide evasion en om binne ’n host te bly wat reeds interessante TCC grants het.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
As jy ’n pasgemaakte helper bou wat Apple Events direk stuur, maak die gebruik van ’n **werklike app-identiteit** toetsing en bedrywighede baie meer betroubaar. In die praktyk beteken dit dat jy ’n `Info.plist` met `CFBundleIdentifier` en `NSAppleEventsUsageDescription` insluit, die binary onderteken en die `com.apple.security.automation.apple-events` entitlement toestaan. Andersins word die Apple Events-prompt dikwels aan die **ouer-host** (byvoorbeeld `Terminal`) toegeskryf, of die `NSAppleScript`-uitvoering misluk bloot met verwarrende `-1750` / `errOSASystemError`-foute.<sup>[[2]](#references)</sup>

AppleScripts kan in compiled vorm gestoor word en normaalweg met `osadecompile` gedecompileer word.

Hierdie scripts kan egter ook as **"Read only"** uitgevoer word (via die **"Export..."**-opsie):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
In daardie geval weier `osadecompile` om normale bronkode te herstel, maar die bytecode en Apple Event-terminologie kan steeds ontleed word.

SentinelOne se run-only-navorsing beskryf hoe om die struktuur ondanks daardie beperking te herstel. `applescript-disassembler` en `aevt_decompile` help om die gekompileerde script en Apple Event-data te inspekteer.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Om macOS TCC User Privacy Protections per ongeluk en volgens ontwerp te omseil](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Om AppleScript in macOS CLI Tools te laat werk: Die ongedokumenteerde dele](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Hoe Offensive Actors AppleScript gebruik om macOS aan te val](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Avonture in die reverse engineering van kwaadwillige run-only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts-voorbeelde](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
