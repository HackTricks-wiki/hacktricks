# macOS ekstenzije datoteka i handleri URL scheme-ova

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices baza podataka

Ovo je baza podataka svih instaliranih aplikacija u macOS-u koja se može upitati kako bi se dobile informacije o svakoj instaliranoj aplikaciji, kao što su podržani **URL scheme-ovi**, **tipovi dokumenata**, **UTI-jevi** i podrazumevani handleri.

Ovu bazu podataka moguće je izvući pomoću:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ili koristeći alat [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je mozak baze podataka. Obezbeđuje **nekoliko XPC servisa** kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i drugi. Međutim, takođe **zahteva određene entitlements** od aplikacija kako bi mogle da koriste izložene XPC funkcionalnosti, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler` za promenu podrazumevanih aplikacija za MIME tipove ili URL scheme-ove, kao i druge.

**`/System/Library/CoreServices/launchservicesd`** registruje servis `com.apple.coreservices.launchservicesd` i može se upititi radi dobijanja informacija o pokrenutim aplikacijama. Može se upitati sistemskim alatom **`/usr/bin/lsappinfo`** ili pomoću [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Iz perspektive operatera, imajte na umu da obično postoje **dva korisna prikaza**:

- **Registration database** kojom upravljaju LaunchServices / `lsd` (uz podršku `.csstore` datoteka).
- **Per-user effective defaults** sačuvane u `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, unutar niza `LSHandlers`.

Ova razlika je važna: aplikacija može biti **registrovana** kao aplikacija koja može da obrađuje određeni tip ili scheme, ali **trenutni podrazumevani izbor** i dalje može biti drugi bundle ID.

## Rukovaoci aplikacija za ekstenzije datoteka i URL scheme-ove

Sledeća linija može biti korisna za pronalaženje aplikacija koje mogu da otvaraju datoteke u zavisnosti od ekstenzije:
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
Možete proveriti i ekstenzije koje aplikacija podržava pomoću:
```bash
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
## Enumerisanje efektivnih handler-a

Najkorisnija datoteka za **podrazumevane postavke trenutnog korisnika** obično je:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Za izlistavanje rukovalaca za **URL scheme** iz njega:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Za izlistavanje **content-type / UTI** handlera:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Za razrešavanje UTI stabla uzorka datoteke:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Ako želite prijatniji CLI za upite ili promenu podrazumevanih vrednosti:
```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```
## Zanimljivi ključevi u Info.plist datoteci

Prilikom triage-a application bundle-a, sledeći ključevi su najvažniji:

- **`CFBundleDocumentTypes`**: grupe dokumenata za koje bundle tvrdi da može da ih otvara.
- **`LSItemContentTypes`**: **moderniji / preporučeni** način povezivanja tipova dokumenata sa UTI-jevima.
- **`LSHandlerRank`**: rangiranje koje koristi LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: prilagođene URI scheme koje application implementira.
- **`UTExportedTypeDeclarations`**: UTI-jevi koje application **poseduje**.
- **`UTImportedTypeDeclarations`**: UTI-jevi koje application ne poseduje, ali želi da ih sistem prepoznaje.

Korisna komanda za brzi triage je:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Suptilan, ali važan detalj: ako je **`LSItemContentTypes`** prisutan, stariji ključevi kao što su **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`** praktično predstavljaju legacy compatibility podatke. Za stvarno određivanje handlera, prvo se fokusirajte na UTI putanju.

## Offensive notes

Aplikacije ne moraju biti izvršene da bi postale interesantne. Ostavljen ili kloniran `.app` bundle može biti **automatski parsiran od strane `lsd` čim se upiše na disk**, a njegovi deklarisani tipovi dokumenata / URL scheme-ovi mogu biti registrovani bez toga da korisnik ikada pokrene bundle.

Ovo je korisno kako za **persistence / hijacking research**, tako i za **initial-access chains**:

- Malicious app može preuzeti **retku ekstenziju** ili **custom UTI** i čekati da žrtva otvori lure fajl.
- Malicious app može registrovati **custom URL scheme** do kog se može doći iz browsera, Electron aplikacije, office dokumenta, chat klijenta ili druge helper aplikacije.<sup>[[1]](#references)</sup>
- Ako izmenite app bundle nakon buildovanja, možete naterati LaunchServices da ga ponovo parsira pomoću:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Prilikom testiranja sumnjivih bundle-ova, obratite posebnu pažnju na:

- **`LSHandlerRank=Owner`** kod neuobičajenih tipova.
- Široke nizove **`CFBundleDocumentTypes`** koji tvrde da podržavaju mnoge ekstenzije.
- **Helper / wrapper apps** čije se jedino zanimljivo ponašanje nalazi iza document ili URI handler-a.
- Datoteke nalik prečicama (`.webloc`, `.inetloc`, `.fileloc`) koje na kraju prosleđuju izvršavanje u LaunchServices. Za trikove u stilu `.fileloc` i povezane Gatekeeper pristupe, pogledajte [ovu drugu stranicu](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ako vam je cilj pasivno izvršavanje koda samim pregledanjem fascikle ili izborom datoteke, pogledajte i posebnu stranicu za [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), pošto je to drugačija, ali blisko povezana površina za file handler-e.

## Reference


- [1] [Objective-See - Udaljena eksploatacija Mac-a putem prilagođenih URL šema](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Zaobilaženje Gate-a: Detaljniji pregled propusta u Gatekeeper-u na macOS-u](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
