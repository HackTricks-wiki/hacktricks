# macOS rukovaoci aplikacija za ekstenzije fajlova i URL scheme

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Ovo je baza podataka svih instaliranih aplikacija u macOS-u koja može da se upita da bi se dobile informacije o svakoj instaliranoj aplikaciji, kao što su podržani **URL schemes**, **document types**, **UTIs** i default rukovaoci.

Moguće je izbaciti ovu bazu podataka sa:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ili koristeći alat [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je mozak baze podataka. Pruža **više XPC servisa** kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, i druge. Ali takođe **zahteva određene entitlements** od aplikacija da bi mogle da koriste izložene XPC funkcionalnosti, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler` za promenu podrazumevanih aplikacija za MIME tipove ili URL scheme i druge.

**`/System/Library/CoreServices/launchservicesd`** registruje servis `com.apple.coreservices.launchservicesd` i može mu se postaviti upit da bi se dobile informacije o aplikacijama koje su pokrenute. Može mu se postaviti upit pomoću sistemskog alata **`/usr/bin/lsappinfo`** ili pomoću [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Iz perspektive operatora, imajte na umu da obično postoje **dva korisna prikaza**:

- **Registraciona baza podataka** kojom upravlja LaunchServices / `lsd` (podržana `.csstore` fajlovima).
- **Efektivni podrazumevani izbori po korisniku** sačuvani u `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` unutar niza `LSHandlers`.

Ova razlika je važna: aplikacija može biti **registrovana** kao sposobna da obrađuje tip ili scheme, ali **trenutni podrazumevani** i dalje može biti drugi bundle ID.

## File Extension & URL scheme app handlers

Sledeća linija može biti korisna za pronalaženje aplikacija koje mogu da otvaraju fajlove u zavisnosti od ekstenzije:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ili upotrebite nešto poput [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Možete takođe proveriti ekstenzije koje podržava aplikacija tako što ćete uraditi:
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
## Nabrajanje efektivnih handlera

Najkorisnija datoteka za **podrazumevane postavke trenutnog korisnika** je obično:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Za dump **URL scheme** handler-a iz njega:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Za dump **content-type / UTI** handlera:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Da biste rešili UTI stablo uzorka fajla:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Ako želite prijateljskiji CLI za upit ili izmenu podrazumevanih podešavanja:
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
## Zanimljivi Info.plist ključevi

Prilikom analize application bundle-a, ovi ključevi su najvažniji:

- **`CFBundleDocumentTypes`**: grupe dokumenata koje bundle tvrdi da može da otvori.
- **`LSItemContentTypes`**: **moderni / preferirani** način za povezivanje tipova dokumenata sa UTI-jevima.
- **`LSHandlerRank`**: rang koji koristi LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemovi koje implementira aplikacija.
- **`UTExportedTypeDeclarations`**: UTI-jevi koje aplikacija **poseduje**.
- **`UTImportedTypeDeclarations`**: UTI-jevi koje aplikacija ne poseduje, ali želi da sistem prepozna.

Korisna brza komanda za analizu je:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Suptilan, ali važan detalj: ako je prisutan **`LSItemContentTypes`**, stariji ključevi kao što su **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`** su efektivno legacy compatibility data. Za stvarno rešavanje handler-a, prvo se fokusiraj na UTI putanju.

## Offensive notes

Aplikacije ne moraju biti izvršene da bi postale zanimljive. Ispušten ili kloniran `.app` bundle može biti **parsed automatically by `lsd` as soon as it is written to disk**, a njegovi deklarisani document types / URL schemes mogu biti registrovani bez da korisnik ikada pokrene bundle.

Ovo je korisno i za istraživanje **persistence / hijacking** i za **initial-access chains**:

- Malicious app može da preuzme **rare extension** ili **custom UTI** i sačeka da žrtva otvori lure file.
- Malicious app može da registruje **custom URL scheme** kojem se može pristupiti iz browser-a, Electron app, office document-a, chat client-a ili druge helper app.
- Ako izmeniš app bundle nakon build-a, možeš naterati LaunchServices da ga ponovo parsira sa:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Kada testirate sumnjive bundles, obratite posebnu pažnju na:

- **`LSHandlerRank=Owner`** na neuobičajenim tipovima.
- **Široke `CFBundleDocumentTypes`** nizove koji tvrde da podržavaju mnogo ekstenzija.
- **Helper / wrapper apps** kod kojih je jedino zanimljivo ponašanje iza document ili URI handler-a.
- **Shortcut-like fajlove** (`.webloc`, `.inetloc`, `.fileloc`) koji na kraju prosleđuju izvršavanje u LaunchServices. Za `.fileloc`-style trikove i povezane Gatekeeper uglove, pogledajte [ovu drugu stranicu](macos-security-protections/macos-fs-tricks/README.md).

Ako vam je cilj pasivno code-execution samo otvaranjem foldera ili selektovanjem fajla, pogledajte i posebnu stranicu za [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), jer je to drugačija, ali blisko povezana surface za file-handler.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
