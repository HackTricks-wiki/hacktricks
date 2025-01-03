# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Ovo je baza podataka svih instaliranih aplikacija u macOS-u koja se može pretraživati da bi se dobile informacije o svakoj instaliranoj aplikaciji, kao što su URL sheme koje podržava i MIME tipovi.

Moguće je izvući ovu bazu podataka sa:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ili korišćenjem alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je mozak baze podataka. Pruža **several XPC services** kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, i još mnogo toga. Ali takođe **zahteva neka ovlašćenja** za aplikacije da bi mogle da koriste izložene XPC funkcionalnosti, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler` za promenu podrazumevanih aplikacija za mime tipove ili url sheme i druge.

**`/System/Library/CoreServices/launchservicesd`** zahteva uslugu `com.apple.coreservices.launchservicesd` i može se upititi da bi se dobile informacije o pokrenutim aplikacijama. Može se upititi pomoću sistemskog alata /**`usr/bin/lsappinfo`** ili sa [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Rukovaoci aplikacijama za ekstenzije datoteka i URL sheme

Sledeća linija može biti korisna za pronalaženje aplikacija koje mogu otvoriti datoteke u zavisnosti od ekstenzije:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ili koristite nešto poput [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Možete takođe proveriti ekstenzije koje podržava aplikacija tako što ćete:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
{{#include ../../banners/hacktricks-training.md}}
