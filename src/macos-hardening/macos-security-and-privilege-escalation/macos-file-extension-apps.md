# macOS aplikacije za rukovanje ekstenzijama datoteka i URL scheme-ovima

{{#include ../../banners/hacktricks-training.md}}

## Baza podataka LaunchServices

Ova baza podataka sadrži sve instalirane aplikacije u macOS-u i može se pretraživati da bi se dobile informacije o svakoj instaliranoj aplikaciji, kao što su podržani **URL scheme-ovi**, **tipovi dokumenata**, **UTI-jevi** i podrazumevani rukovaoci.

Ovu bazu podataka je moguće izlistati pomoću:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ili pomoću alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je mozak baze podataka. Pruža **nekoliko XPC servisa** kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i drugi. Međutim, za korišćenje izloženih XPC funkcionalnosti aplikacijama su potrebna i **određena prava (entitlements)**, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler`, za promenu podrazumevanih aplikacija za MIME tipove ili URL šeme, i druga.

**`/System/Library/CoreServices/launchservicesd`** pruža servis `com.apple.coreservices.launchservicesd`, koji se može upitati za informacije o pokrenutim aplikacijama. Može se upitati pomoću sistemskog alata **`/usr/bin/lsappinfo`** ili alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Iz perspektive operatera, imajte na umu da obično postoje **dva korisna prikaza**:

- **Baza podataka o registracijama** kojom upravlja LaunchServices / `lsd` (čuvana u `.csstore` datotekama).
- **Efektivne podrazumevane vrednosti za korisnika** sačuvane u `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, unutar niza `LSHandlers`.

Ova razlika je važna: aplikacija može biti **registrovana** kao sposobna da obrađuje određeni tip ili šemu, ali **trenutna podrazumevana aplikacija** i dalje može biti neki drugi bundle ID.

U novijim izdanjima macOS-a, otkrivanje registracija nije ograničeno na `/Applications`: aplikacije u drugim dostupnim fasciklama vidljivim Spotlight-u, kao i na montiranim/deljenim volumenima, mogu biti dodate u registar. Zato tokom trijaže sačuvajte podatke o `path`-u i volumenu iz izlaza komande `lsregister -dump` i nemojte pretpostavljati da je odregistracija aplikacije trajna dok paket aplikacije i dalje može biti otkriven.<sup>[[4]](#references)</sup>

## Rukovaoci aplikacija za ekstenzije datoteka i URL šeme

Sledeća komanda može biti korisna za pronalaženje aplikacija koje mogu da otvore datoteke na osnovu ekstenzije:

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

Podržane ekstenzije aplikacije možete proveriti i pomoću:

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

## Enumerisanje aktivnih rukovalaca

Najkorisnija datoteka za **podrazumevane postavke trenutnog korisnika** obično je:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Da biste iz njega dumpovali rukovaoce za **URL scheme**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Za izlistavanje rukovalaca za **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Da biste razrešili UTI stablo ogledne datoteke:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Ako želite jednostavniji CLI za postavljanje upita ili promenu podrazumevanih vrednosti:

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

### Zamene `Open With` za pojedinačne fajlove

Rezolucija rukovaoca ima i sloj specifičan za **pojedinačni fajl**. Pre nego što se osloni na UTI fajla i podrazumevanu aplikaciju korisnika, LaunchServices proverava prošireni atribut `com.apple.LaunchServices.OpenWith`. Finder ga kreira kada se za jedan fajl izabere **Always Open With**; njegova vrednost je binarna property lista koja sadrži putanju do aplikacije, identifikator paketa i selektor verzije.<sup>[[3]](#references)</sup>

Pregledajte je i dekodirajte bez oslanjanja na ekstenziju fajla:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Ovo je korisno kada jedan mamac otvori neočekivanu aplikaciju, iako `duti`, `dutix` ili `LSHandlers` prikazuju bezazlenu globalnu podrazumevanu vrednost. U kontrolisanom laboratorijskom okruženju, tačna neprozirna vrednost može da se kopira iz datoteke konfigurisane kroz Finder; njenim brisanjem ponovo se uspostavlja uobičajeno razrešavanje na osnovu tipa:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Zanimljivi ključevi Info.plist

Prilikom trijaže paketa aplikacije, ovi ključevi su najvažniji:

- **`CFBundleDocumentTypes`**: grupe dokumenata za koje paket tvrdi da može da ih otvara.
- **`LSItemContentTypes`**: **savremeniji / preporučeni** način povezivanja tipova dokumenata sa UTI-jima.
- **`LSHandlerRank`**: rang koji koristi LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: prilagođene URI šeme koje aplikacija implementira.
- **`UTExportedTypeDeclarations`**: UTI-ji koje aplikacija **poseduje**.
- **`UTImportedTypeDeclarations`**: UTI-ji koje aplikacija ne poseduje, ali želi da ih sistem prepoznaje.

Korisna komanda za brzu trijažu je:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Suptilan, ali važan detalj: ako je prisutan **`LSItemContentTypes`**, stariji ključevi kao što su **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`** praktično predstavljaju zastarele podatke radi kompatibilnosti. Za stvarno razrešavanje handlera najpre se fokusirajte na UTI putanju.

## Ofanzivne napomene

Aplikacije ne moraju da se pokrenu da bi postale zanimljive. `lsd` može **automatski da obradi odbačeni ili klonirani `.app` bundle čim se upiše na disk**, a deklarisani tipovi dokumenata / URL sheme mogu biti registrovani čak i ako korisnik nikada ne pokrene bundle.

Ovo je korisno i za istraživanje **persistence / hijacking** tehnika i za **initial-access lance**:

- Zlonamerna aplikacija može da preuzme **retku ekstenziju** ili **prilagođeni UTI** i sačeka da žrtva otvori mamac.
- Zlonamerna aplikacija može da registruje **prilagođenu URL shemu** kojoj se može pristupiti iz pregledača, Electron aplikacije, kancelarijskog dokumenta, chat klijenta ili druge pomoćne aplikacije.<sup>[[1]](#references)</sup>
- Da biste odvojili uobičajeno razrešavanje podrazumevanog handlera od testiranja određenog kandidata, pozovite shemu kroz LaunchServices pomoću `open 'targetscheme://host/path?value=test'`, a zatim navedite konkretan registrovani bundle pomoću `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Ovo je korisno za proveru načina na koji aplikacija koja prima zahtev proverava i dekodira URL komponente koje kontroliše napadač.<sup>[[1]](#references)</sup>
- Ako izmenite app bundle nakon njegovog pravljenja, LaunchServices možete naterati da ga ponovo obradi pomoću:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Prilikom testiranja sumnjivih bundle-ova, obratite posebnu pažnju na:

- **`LSHandlerRank=Owner`** kod neuobičajenih tipova.
- **Široke nizove `CFBundleDocumentTypes`** koji navode mnogo ekstenzija.
- **Pomoćne / wrapper aplikacije** čije se jedino zanimljivo ponašanje aktivira preko document ili URI handlera.
- **Fajlove nalik prečicama** (`.webloc`, `.inetloc`, `.fileloc`) koji na kraju pokreću LaunchServices. Za trikove u stilu `.fileloc` i srodne Gatekeeper vektore, pogledajte [ovu drugu stranicu](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Ako vam je cilj pasivno izvršavanje koda samim pregledanjem fascikle ili izborom fajla, pogledajte i posebnu stranicu o [Quick Look generatorima](macos-proces-abuse/macos-quicklook-generators.md), jer je to druga, ali blisko povezana površina za rukovanje fajlovima.



## References

- [1] [Objective-See - Daljinska eksploatacija Mac računara pomoću prilagođenih URL šema](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Zaobilaženje kapije: bliži pogled na propuste Gatekeeper-a u macOS-u](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Kako macOS otvara fajl u odgovarajućoj aplikaciji](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Upravljanje LaunchServices-om u macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
