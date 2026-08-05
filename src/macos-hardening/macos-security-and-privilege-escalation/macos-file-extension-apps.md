# macOS rukovaoci ekstenzijama datoteka i URL scheme-ama

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Ovo je baza podataka svih instaliranih aplikacija u macOS-u koja se može upitati da bi se dobile informacije o svakoj instaliranoj aplikaciji, kao što su podržane **URL schemes**, **document types**, **UTIs** i podrazumevani rukovaoci.

Ovu bazu podataka moguće je dump-ovati pomoću:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ili korišćenjem alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je mozak baze podataka. Obezbeđuje **nekoliko XPC servisa**, kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i drugi. Međutim, takođe **zahteva određene entitlements** od aplikacija kako bi mogle da koriste izložene XPC funkcionalnosti, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler`, za promenu podrazumevanih aplikacija za MIME types ili URL schemes, kao i druge.

**`/System/Library/CoreServices/launchservicesd`** preuzima servis `com.apple.coreservices.launchservicesd` i može se upitati radi dobijanja informacija o pokrenutim aplikacijama. Može se upitati sistemskim alatom **`/usr/bin/lsappinfo`** ili pomoću alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Iz perspektive operatora, imajte na umu da obično postoje **dva korisna prikaza**:

- **registration database** kojom upravljaju LaunchServices / `lsd` (podržana `.csstore` datotekama).
- **per-user effective defaults** sačuvani u `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, unutar niza `LSHandlers`.

Ova razlika je važna: aplikacija može biti **registrovana** kao aplikacija koja može da obrađuje određeni tip ili scheme, ali **trenutna podrazumevana vrednost** i dalje može biti drugi bundle ID.

## Handleri aplikacija za ekstenzije datoteka i URL schemes

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
Takođe možete proveriti ekstenzije koje aplikacija podržava pomoću:
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
## Enumerisanje efektivnih handlera

Najkorisniji fajl za **podrazumevane vrednosti trenutnog korisnika** obično je:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Da iz njega izvučete handlere za **URL scheme**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Za ispisivanje handlera za **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Da biste razrešili UTI stablo ogledne datoteke:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Ako želite jednostavniji CLI za upite ili promenu podrazumevanih vrednosti:
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
- **`LSItemContentTypes`**: **moderan / preporučen** način povezivanja tipova dokumenata sa UTI-jima.
- **`LSHandlerRank`**: rang koji koristi LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: prilagođene URI šeme koje aplikacija implementira.
- **`UTExportedTypeDeclarations`**: UTI-ji čiji je aplikacija **vlasnik**.
- **`UTImportedTypeDeclarations`**: UTI-ji čiji aplikacija nije vlasnik, ali želi da ih sistem prepoznaje.

Korisna komanda za brzu analizu je:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Suptilan, ali važan detalj: ako je **`LSItemContentTypes`** prisutan, stariji ključevi kao što su **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`** praktično predstavljaju legacy compatibility podatke. Za stvarno određivanje handlera, najpre se fokusirajte na UTI putanju.

## Offensive notes

Aplikacije ne moraju da budu izvršene da bi postale interesantne. Odbačeni ili klonirani `.app` bundle može biti **automatski parsiran od strane `lsd` čim se upiše na disk**, a njegovi deklarisani tipovi dokumenata / URL schemes mogu biti registrovani čak i ako korisnik nikada ne pokrene bundle.

Ovo je korisno i za **persistence / hijacking research** i za **initial-access chains**:

- Malicious app može da preuzme **retku ekstenziju** ili **custom UTI** i sačeka da žrtva otvori lure fajl.
- Malicious app može da registruje **custom URL scheme** kojem se može pristupiti iz browsera, Electron app-a, office dokumenta, chat klijenta ili druge helper aplikacije.<sup>[[1]](#references)</sup>
- Ako izmenite app bundle nakon buildovanja, možete naterati LaunchServices da ga ponovo parsira pomoću:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Prilikom testiranja sumnjivih bundle-ova, obratite posebnu pažnju na:

- **`LSHandlerRank=Owner`** kod neuobičajenih tipova.
- Široke nizove **`CFBundleDocumentTypes`** koji navode mnoge ekstenzije.
- **Helper / wrapper apps** čije se jedino zanimljivo ponašanje nalazi iza document ili URI handler-a.
- Fajlove nalik prečicama (`.webloc`, `.inetloc`, `.fileloc`) koji se na kraju prosleđuju u LaunchServices. Za trikove u stilu `.fileloc` i povezane Gatekeeper uglove, pogledajte [ovu drugu stranicu](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ako je vaš cilj pasivno izvršavanje koda samo pregledanjem fascikle ili izborom fajla, pogledajte i posebnu stranicu o [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), pošto je to drugačija, ali blisko povezana površina za file-handler-e.

## Reference

- [1] [Objective-See - Daljinska eksploatacija Mac računara putem prilagođenih URL šema](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Zaobilaženje kapije: detaljniji pogled na propuste Gatekeeper-a u macOS-u](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
