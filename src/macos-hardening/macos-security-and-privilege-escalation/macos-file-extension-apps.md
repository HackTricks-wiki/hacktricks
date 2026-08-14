# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Ovo je baza podataka svih instaliranih aplikacija u macOS-u koja se može upitom koristiti za dobijanje informacija o svakoj instaliranoj aplikaciji, kao što su podržane **URL schemes**, **document types**, **UTIs** i podrazumevani handleri.

Ovu bazu podataka je moguće dump-ovati pomoću:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ili korišćenjem alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je mozak baze podataka. Obezbeđuje **nekoliko XPC servisa**, kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i drugi. Međutim, takođe **zahteva određene entitlements** od aplikacija kako bi mogle da koriste izložene XPC funkcionalnosti, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler` za promenu podrazumevanih aplikacija za MIME tipove ili URL šeme, kao i druge.

**`/System/Library/CoreServices/launchservicesd`** obezbeđuje servis `com.apple.coreservices.launchservicesd` i može mu se postaviti upit radi dobijanja informacija o pokrenutim aplikacijama. Upit se može poslati sistemskim alatom **`/usr/bin/lsappinfo`** ili pomoću alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Iz perspektive operatora, imajte na umu da obično postoje **dva korisna prikaza**:

- **Registraciona baza** kojom upravljaju LaunchServices / `lsd` (koju podržavaju `.csstore` datoteke).
- **Efektivna podrazumevana podešavanja po korisniku**, sačuvana u `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, unutar niza `LSHandlers`.

Ova razlika je važna: aplikacija može biti **registrovana** kao sposobna da obrađuje određeni tip ili šemu, ali **trenutna podrazumevana vrednost** i dalje može biti drugi bundle ID.

Na novijim izdanjima macOS-a, otkrivanje registracija nije ograničeno samo na `/Applications`: aplikacije u drugim folderima vidljivim Spotlight-u i dostupnim folderima, kao i na montiranim/deljenim volumenima, mogu ući u registar. Zato tokom triage-a sačuvajte informacije o `path`-u i volumenu iz izlaza komande `lsregister -dump` i nemojte pretpostaviti da je odregistracija aplikacije trajna dok je bundle i dalje moguće otkriti.<sup>[[4]](#references)</sup>

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
## Nabrajanje efektivnih rukovalaca

Najkorisnija datoteka za **podrazumevane postavke trenutnog korisnika** obično je:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Za dumpovanje **URL scheme** handlera iz njega:
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
### `Open With` overrides po datoteci

Rezolucija handlera takođe ima sloj **specifičan za datoteku**. Pre nego što se vrati na UTI datoteke i korisnički globalni podrazumevani izbor, LaunchServices proverava prošireni atribut `com.apple.LaunchServices.OpenWith`. Finder ga kreira kada se za jednu datoteku izabere **Always Open With**; njegova vrednost je binarna property lista koja sadrži putanju aplikacije, bundle identifier i selektor verzije.<sup>[[3]](#references)</sup>

Pregledajte ga i dekodirajte bez oslanjanja na ekstenziju naziva datoteke:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Ovo je korisno kada jedan mamac otvori neočekivanu aplikaciju iako `duti`, `dutix` ili `LSHandlers` prijavljuje bezazlenu globalnu podrazumevanu vrednost. U kontrolisanom lab okruženju, tačna neprozirna vrednost može se kopirati iz datoteke konfigurisane kroz Finder; njenim brisanjem se obnavlja uobičajeno razrešavanje na osnovu tipa:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Zanimljivi Info.plist ključevi

Prilikom analize application bundle-a, ovi ključevi su najvažniji:

- **`CFBundleDocumentTypes`**: grupe dokumenata za koje bundle tvrdi da može da ih otvara.
- **`LSItemContentTypes`**: **moderan / preporučen** način povezivanja tipova dokumenata sa UTI-jevima.
- **`LSHandlerRank`**: rangiranje koje koristi LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: prilagođene URI šeme koje application implementira.
- **`UTExportedTypeDeclarations`**: UTI-jevi čiji je app **vlasnik**.
- **`UTImportedTypeDeclarations`**: UTI-jevi čiji app nije vlasnik, ali želi da ih sistem prepoznaje.

Koristan brzi triage command je:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Suptilan, ali važan detalj: ako je **`LSItemContentTypes`** prisutan, stariji ključevi kao što su **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`** praktično predstavljaju legacy podatke za kompatibilnost. Za stvarno određivanje handlera, prvo se fokusirajte na UTI putanju.

## Offensive notes

Aplikacije ne moraju biti izvršene da bi postale interesantne. Odbačeni ili klonirani `.app` bundle može biti **automatski parsiran pomoću `lsd` čim se upiše na disk**, a njegovi deklarisani tipovi dokumenata / URL scheme-ovi mogu biti registrovani čak i ako korisnik nikada ne pokrene bundle.

Ovo je korisno i za istraživanje **persistence / hijacking** tehnika i za **initial-access chain-ove**:

- Malicious app može preuzeti **retku ekstenziju** ili **custom UTI** i čekati da žrtva otvori lure fajl.
- Malicious app može registrovati **custom URL scheme** kojem se može pristupiti iz browsera, Electron aplikacije, office dokumenta, chat klijenta ili druge helper aplikacije.<sup>[[1]](#references)</sup>
- Da biste razdvojili normalno podrazumevano određivanje od testiranja određenog candidate handlera, pozovite scheme kroz LaunchServices pomoću `open 'targetscheme://host/path?value=test'`, a zatim usmerite poziv na određeni registrovani bundle pomoću `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Ovo je korisno za proveru načina na koji receiving app validira i dekodira URL komponente pod kontrolom napadača.<sup>[[1]](#references)</sup>
- Ako izmenite app bundle nakon buildovanja, možete naterati LaunchServices da ga ponovo parsira pomoću:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Kada testirate sumnjive bundles, obratite posebnu pažnju na:

- **`LSHandlerRank=Owner`** kod neuobičajenih tipova.
- **Široke `CFBundleDocumentTypes`** nizove koji polažu pravo na mnoge ekstenzije.
- **Helper / wrapper apps** čije se jedino zanimljivo ponašanje nalazi iza document ili URI handler-a.
- **Datoteke nalik prečicama** (`.webloc`, `.inetloc`, `.fileloc`) koje na kraju prosleđuju izvršavanje u LaunchServices. Za trikove u stilu `.fileloc` i povezane Gatekeeper uglove, pogledajte [ovu drugu stranicu](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ako je vaš cilj pasivni code-execution samim pregledanjem foldera ili izborom datoteke, pogledajte i posebnu stranicu o [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), jer je to drugačija, ali usko povezana površina za file-handler.

## References

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Detaljniji pogled na Gatekeeper propuste na macOS-u](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Kako macOS otvara datoteku u odgovarajućoj aplikaciji](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kontrolisanje LaunchServices-a u macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
