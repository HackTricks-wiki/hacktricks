# macOS rukovaoci ekstenzija datoteka i URL scheme-ova

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices baza podataka

Ovo je baza podataka svih instaliranih aplikacija u macOS-u koja se može upitati kako bi se dobile informacije o svakoj instaliranoj aplikaciji, kao što su podržani **URL scheme-ovi**, **tipovi dokumenata**, **UTI-jevi** i podrazumevani rukovaoci.

Ovu bazu podataka moguće je izvesti pomoću:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ili koristeći alat [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** predstavlja jezgro baze podataka. On pruža **nekoliko XPC servisa**, kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i drugi. Međutim, takođe **zahteva određene entitlements** od aplikacija kako bi mogle da koriste izložene XPC funkcionalnosti, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler`, za promenu podrazumevanih aplikacija za MIME tipove ili URL šeme, kao i druge.

**`/System/Library/CoreServices/launchservicesd`** registruje servis `com.apple.coreservices.launchservicesd` i može mu se uputiti upit radi dobijanja informacija o pokrenutim aplikacijama. Upit mu se može uputiti pomoću sistemskog alata **`/usr/bin/lsappinfo`** ili pomoću alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Iz perspektive operatera, imajte na umu da obično postoje **dva korisna prikaza**:

- **Baza podataka registracija** kojom upravljaju LaunchServices / `lsd` (zasnovana na `.csstore` datotekama).
- **Efektivna podrazumevana podešavanja po korisniku**, sačuvana u `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, unutar niza `LSHandlers`.

Ova razlika je važna: aplikacija može biti **registrovana** kao aplikacija koja može da obrađuje određeni tip ili šemu, ali **trenutna podrazumevana aplikacija** i dalje može biti drugi bundle ID.

## Rukovaoci aplikacija za ekstenzije datoteka i URL šeme

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
Takođe možete proveriti ekstenzije koje aplikacija podržava tako što ćete:
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

Najkorisniji fajl za **podrazumevane postavke trenutnog korisnika** obično je:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Za izlistavanje **URL scheme** handlera iz njega:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Za dump **content-type / UTI** handler-a:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Da biste razrešili UTI stablo uzorka datoteke:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Ako želite jednostavniji CLI za pregled ili izmenu podrazumevanih vrednosti:
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

- **`CFBundleDocumentTypes`**: grupe dokumenata za koje bundle navodi da može da ih otvara.
- **`LSItemContentTypes`**: **moderni / preporučeni** način povezivanja tipova dokumenata sa UTI-jevima.
- **`LSHandlerRank`**: rangiranje koje koristi LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: prilagođene URI šeme koje aplikacija implementira.
- **`UTExportedTypeDeclarations`**: UTI-jevi čiji je **vlasnik** aplikacija.
- **`UTImportedTypeDeclarations`**: UTI-jevi čiji vlasnik nije aplikacija, ali želi da ih sistem prepoznaje.

Korisna komanda za brzu analizu je:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Suptilan, ali važan detalj: ako je **`LSItemContentTypes`** prisutan, stariji ključevi kao što su **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`** praktično predstavljaju legacy compatibility data. Za stvarnu rezoluciju handlera, prvo se fokusirajte na UTI putanju.

## Ofanzivne napomene

Aplikacije ne moraju biti izvršene da bi postale zanimljive. Odbačeni ili klonirani `.app` bundle može biti **automatski parsiran od strane `lsd` čim se upiše na disk**, a njegovi deklarisani tipovi dokumenata / URL schemes mogu biti registrovani, a da korisnik nikada ne pokrene bundle.

Ovo je korisno i za istraživanje **persistence / hijacking** tehnika i za **initial-access chains**:

- Malicious app može preuzeti **retku ekstenziju** ili **custom UTI** i čekati da žrtva otvori lure fajl.
- Malicious app može registrovati **custom URL scheme** dostupan iz browsera, Electron aplikacije, office dokumenta, chat klijenta ili druge helper aplikacije.<sup>[1]</sup>
- Ako izmenite app bundle nakon buildovanja, možete primorati LaunchServices da ga ponovo parsira pomoću:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Prilikom testiranja sumnjivih paketa, obratite posebnu pažnju na:

- **`LSHandlerRank=Owner`** kod neuobičajenih tipova.
- Široke nizove **`CFBundleDocumentTypes`** koji navode mnoge ekstenzije.
- Helper / wrapper aplikacije čije je jedino zanimljivo ponašanje dostupno preko handlera dokumenata ili URI-ja.
- Datoteke nalik prečicama (`.webloc`, `.inetloc`, `.fileloc`) koje na kraju prosleđuju obradu u LaunchServices. Za trikove u stilu `.fileloc` i povezane Gatekeeper uglove, pogledajte [ovu drugu stranicu](macos-security-protections/macos-fs-tricks/README.md).<sup>[2]</sup>

Ako vam je cilj pasivno izvršavanje koda samim pregledanjem fascikle ili izborom datoteke, pogledajte i posebnu stranicu o [Quick Look generatorima](macos-proces-abuse/macos-quicklook-generators.md), jer je to drugačija, ali blisko povezana površina za obradu datoteka.

## Reference

- [1] [Objective-See - Daljinska eksploatacija Mac računara putem prilagođenih URL šema](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Zaobilaženje kapije: Detaljniji pogled na propuste Gatekeeper-a u macOS-u](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
