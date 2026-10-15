# macOS aplikacije za rukovanje ekstenzijama datoteka i URL scheme-ovima

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices baza podataka

Ovo je baza podataka svih instaliranih aplikacija u macOS-u, koju je moguće upitati za informacije o svakoj instaliranoj aplikaciji, kao što su podržani **URL scheme-ovi**, **tipovi dokumenata**, **UTI-jevi** i podrazumevani handler-i.

Ovu bazu podataka moguće je izbaciti pomoću:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ili pomoću alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je jezgro baze podataka. Pruža **nekoliko XPC servisa**, kao što su `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i drugi. Međutim, aplikacijama su potrebna i **određena ovlašćenja** da bi mogle da koriste izložene XPC funkcionalnosti, kao što su `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler` za promenu podrazumevanih aplikacija za MIME tipove ili URL šeme, kao i druga ovlašćenja.

**`/System/Library/CoreServices/launchservicesd`** pruža servis `com.apple.coreservices.launchservicesd` i može mu se uputiti upit za informacije o pokrenutim aplikacijama. Upit se može uputiti pomoću sistemskog alata **`/usr/bin/lsappinfo`** ili alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Iz perspektive operatera, imajte na umu da obično postoje **dva korisna prikaza**:

- **Registraciona baza podataka** kojom upravlja LaunchServices / `lsd` (čuvana u `.csstore` datotekama).
- **Delotvorne podrazumevane vrednosti za svakog korisnika**, sačuvane u nizu `LSHandlers` u datoteci `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`.

Ova razlika je važna: aplikacija može biti **registrovana** kao aplikacija koja može da obrađuje određeni tip ili šemu, dok je **trenutno podrazumevana** aplikacija i dalje neki drugi bundle ID.

U novijim izdanjima macOS-a, pronalaženje registrovanih aplikacija nije ograničeno na `/Applications`: aplikacije u drugim dostupnim fasciklama koje su vidljive Spotlight-u, kao i na montiranim ili deljenim volumenima, mogu biti dodate u registar. Zato tokom trijaže sačuvajte informacije o `path`-u i volumenu iz izlaza komande `lsregister -dump` i nemojte pretpostavljati da će uklanjanje registracije aplikacije trajati dok je bundle i dalje moguće pronaći.<sup>[[4]](#references)</sup>

## Rukovaoci aplikacijama za ekstenzije datoteka i URL šeme

Sledeća linija može biti korisna za pronalaženje aplikacija koje mogu da otvaraju datoteke u zavisnosti od ekstenzije:

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

Možete proveriti i ekstenzije koje aplikacija podržava tako što ćete izvršiti:

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

## Popisivanje efektivnih rukovalaca

Najkorisnija datoteka za **podrazumevane postavke trenutnog korisnika** obično je:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Da biste iz njega izlistali rukovaoce za **URL scheme**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Za dumpovanje **content-type / UTI** handlera:

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

### Per-file `Open With` overrides

Razrešavanje handlera ima i sloj specifičan za **pojedinačnu datoteku**. Pre nego što se osloni na UTI datoteke i podrazumevanu aplikaciju korisnika, LaunchServices proverava prošireni atribut `com.apple.LaunchServices.OpenWith`. Finder ga kreira kada se za jednu datoteku izabere **Always Open With**; njegova vrednost je binarna lista svojstava koja sadrži putanju do aplikacije, identifikator paketa i selektor verzije.<sup>[[3]](#references)</sup>

Pregledajte ga i dekodirajte bez oslanjanja na ekstenziju naziva datoteke:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Ovo je korisno kada se jedan mamac otvori u neočekivanoj aplikaciji, iako `duti`, `dutix` ili `LSHandlers` prijavljuje bezbednu globalnu podrazumevanu vrednost. U kontrolisanom laboratorijskom okruženju, tačna neprozirna vrednost može da se kopira iz datoteke konfigurisane kroz Finder; njenim brisanjem vraća se uobičajeno razrešavanje na osnovu tipa:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Zanimljivi ključevi Info.plist

Pri trijaži paketa aplikacije najvažniji su sledeći ključevi:

- **`CFBundleDocumentTypes`**: grupe dokumenata za koje paket tvrdi da može da ih otvara.
- **`LSItemContentTypes`**: **savremeniji / preporučeni** način povezivanja tipova dokumenata sa UTI-jevima.
- **`LSHandlerRank`**: rang koji koristi LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: prilagođene URI sheme koje aplikacija implementira.
- **`UTExportedTypeDeclarations`**: UTI-jevi koje aplikacija **poseduje**.
- **`UTImportedTypeDeclarations`**: UTI-jevi koje aplikacija ne poseduje, ali želi da ih sistem prepoznaje.

Korisna komanda za brzu trijažu je:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Suptilan, ali važan detalj: ako je prisutan **`LSItemContentTypes`**, stariji ključevi kao što su **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`** u suštini predstavljaju zastarele podatke radi kompatibilnosti. Pri stvarnom određivanju handlera, prvo se usredsredite na UTI putanju.

## Ofanzivne napomene

Aplikacije ne moraju da se pokrenu da bi njihove registracije za obradu postale zanimljive, ali **samo upisivanje `.app` bundle-a ne garantuje da će odmah biti registrovan**. Finder može da registruje aplikaciju kada je otkrije, uključujući i slučaj kada korisnik pregleda njen folder; registracija može da se desi i pri pokretanju sistema ili prijavljivanju korisnika, kao i putem eksplicitnog poziva za registraciju. Pre testiranja registracije proverite izlaz komande `lsregister -dump`. Sama registracija ne pokreće aplikaciju niti je postavlja kao efektivnu podrazumevanu aplikaciju.<sup>[[5]](#references)</sup> Za preduslove za persistence pogledajte [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Ovo je korisno i za **istraživanje persistence / hijacking tehnika** i za **lance početnog pristupa**:

- Zlonamerna aplikacija može da registruje **retku ekstenziju** ili **prilagođeni UTI** i sačeka da žrtva otvori fajl-mamac.
- Zlonamerna aplikacija može da registruje **prilagođenu URL šemu** kojoj se može pristupiti iz browser-a, Electron aplikacije, office dokumenta, chat klijenta ili druge pomoćne aplikacije.<sup>[[1]](#references)</sup>
- Da biste razdvojili uobičajeno razrešavanje podrazumevane aplikacije od testiranja određenog kandidata za handler, pozovite šemu preko LaunchServices komandom `open 'targetscheme://host/path?value=test'`, a zatim usmerite poziv na određeni registrovani bundle komandom `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Ovo je korisno za proveru načina na koji aplikacija koja prima poziv validira i dekodira URL komponente pod kontrolom napadača.<sup>[[1]](#references)</sup>
- Ako izmenite app bundle nakon izrade, možete naterati LaunchServices da ga ponovo parsira komandom:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Prilikom testiranja sumnjivih bundle-ova, obratite posebnu pažnju na:

- **`LSHandlerRank=Owner`** za neuobičajene tipove.
- **Široke nizove `CFBundleDocumentTypes`** koji obuhvataju mnogo ekstenzija.
- **Helper / wrapper aplikacije** čije se jedino zanimljivo ponašanje aktivira preko handlera za dokumente ili URI-jeve.
- **Fajlove nalik prečicama** (`.webloc`, `.inetloc`, `.fileloc`) koji na kraju pokreću LaunchServices. Za trikove tipa `.fileloc` i povezane Gatekeeper uglove, pogledajte [ovu drugu stranicu](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### URL parametri prosleđeni u nizvodne opcije

Potvrda pregledača za spoljašnji protokol odobrava samo otvaranje handlera; ona ne znači da su URL parametri pouzdani. Pratite URL parser aplikacije koja prima URL kroz sve biblioteke, medijske mehanizme, pomoćne procese i opcije za upisivanje datoteka. Potražite prefiks ključa upita koji pretvara polja URL-a u nazive nizvodnih opcija. Testirajte i doslovne i percent-kodirane separatore pomoću bezopasnog markera u privremenom nalogu.<sup>[[6]](#references)</sup>

Proverite **konačnu opciju koju prihvata nizvodna komponenta**, a ne samo početno parsiranje aplikacije. Jedan handler je dozvoljavao da ključevi upita sa prefiksom stignu do mpv ulaznih komandi; blokiranje te opcije ipak je ostavljalo putanju za upisivanje datoteke. Testirajte dostupnu klasu opcija, a ne samo jedan poznati opasan ključ.<sup>[[7]](#references)</sup>

### Ugrađeni `applescript://` handler

URL handler `applescript://com.apple.scripteditor` prihvata `action=new` i URL-kodirani parametar `script`. Zato veza u pregledaču može da otvori Script Editor sa AppleScript-om pod kontrolom napadača već unetim u editor, bez koraka lepljenja u Terminal. Ovo **ne pokreće skriptu automatski**: pregledač može da zatraži dozvolu za otvaranje Script Editor-a, a korisnik mora da pokrene skriptu.<sup>[[8]](#references)</sup>

Novije verzije macOS-a mogu da prikažu upozorenje za skriptni dokument, dok XProtect skenira AppleScript prilikom izvršavanja.<sup>[[8]](#references)[[9]](#references)</sup>

Koristite bezopasnu lokalnu probu da biste proverili handler i upite na verziji macOS-a koja se procenjuje; ona treba samo da popuni editor dok se ne klikne na **Run**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Ako vam je cilj pasivno izvršavanje koda samo pregledanjem fascikle ili izborom datoteke, pogledajte i posebnu stranicu o [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), jer je to drugačija, ali usko povezana površina za rukovanje datotekama.



## References

- [1] [Objective-See - Daljinsko iskorišćavanje Mac računara putem prilagođenih URL šema](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Zaobilaženje kapije: Bliži pogled na propuste Gatekeeper-a u macOS-u](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Kako macOS otvara datoteku u odgovarajućoj aplikaciji](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Upravljanje LaunchServices-om u macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Koncepti Launch Services-a](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Istraživanje izvršavanja komandi putem IINA URL šeme](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Nebezbedno rukovanje mpv opcijama u URL šemi](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - Tehnika ClickFix koristi Script Editor umesto Terminal-a](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Zaštita Terminal-a i skripti](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
