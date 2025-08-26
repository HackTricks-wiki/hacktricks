# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB odnosi se na zloupotrebu Interface Builder fajlova (.xib/.nib) unutar potpisanog macOS app bundla da bi se izvršila logika kojom kontroliše napadač unutar ciljnog procesa, čime se nasleđuju njegova entitlements i TCC permisije. Ovu tehniku je izvorno dokumentovao xpn (MDSec), a kasnije ju je generalizovao i značajno proširio Sector7, koji je takođe obradio Apple‑ove mitigacije u macOS 13 Ventura i macOS 14 Sonoma. Za pozadinu i dubinske analize, pogledajte reference na kraju.

> TL;DR
> • Before macOS 13 Ventura: replacing a bundle’s MainMenu.nib (or another nib loaded at startup) could reliably achieve process injection and often privilege escalation.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, and the new TCC “App Management” permission largely prevent post‑launch nib tampering by unrelated apps. Attacks may still be feasible in niche cases (e.g., same‑developer tooling modifying own apps, or terminals granted App Management/Full Disk Access by the user).

## What are NIB/XIB files

Nib (skraćeno od NeXT Interface Builder) fajlovi su serijalizovani UI object graph‑ovi koje koriste AppKit aplikacije. Moderni Xcode čuva uređive XML .xib fajlove koji se pri build‑u kompajliraju u .nib. Tipična aplikacija učitava svoj glavni UI preko `NSApplicationMain()` koji čita `NSMainNibFile` ključ iz app‑ovog Info.plist i instancira object graph u runtime‑u.

Ključne tačke koje omogućavaju napad:
- NIB loading instantiates arbitrary Objective‑C classes without requiring them to conform to NSSecureCoding (Apple’s nib loader falls back to `init`/`initWithFrame:` when `initWithCoder:` is not available).
- Cocoa Bindings can be abused to call methods as nibs are instantiated, including chained calls that require no user interaction.

## Dirty NIB injection process (iz perspektive napadača)

The classic pre‑Ventura flow:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Use bindings to set a menu item’s target/selector and then invoke the private `_corePerformAction` method so the action fires automatically when the nib loads. This removes the need for a user to click a button.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
Ovo omogućava izvršavanje proizvoljnog AppleScript-a u ciljnom procesu pri učitavanju nib-a.  

Napredni lanci mogu:
- Instancirati proizvoljne AppKit klase (npr. `NSTask`) i pozivati metode bez argumenata poput `-launch`.
- Pozvati proizvoljne selektore sa objekt-argumentima pomoću gore pomenutog binding trika.
- Učitati AppleScriptObjC.framework da bi se napravio bridge ka Objective‑C i čak pozivali izabrani C API-ji.
- Na starijim sistemima koji još uključuju Python.framework, napraviti bridge ka Pythonu i onda koristiti `ctypes` za pozivanje proizvoljnih C funkcija (Sector7’s research).

3) Zameniti nib aplikacije
- Kopirajte `target.app` na mesto gde je moguće pisati, zamenite, npr., `Contents/Resources/MainMenu.nib` zlonamernim nib-om i pokrenite `target.app`. Pre‑Ventura, nakon jednokratne Gatekeeper procene, kasnija pokretanja su obavljala samo plitke provere potpisa, pa non‑executable resursi (kao .nib) nisu bili ponovo verifikovani.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS zaštite (Ventura/Monterey/Sonoma/Sequoia)

Apple je uveo nekoliko sistemskih mitigacija koje dramatično smanjuju izvodljivost Dirty NIB na modernim macOS sistemima:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- Pri prvom pokretanju bilo koje aplikacije (quarantined ili ne), dubinska provera potpisa pokriva sve resurse bundle‑a. Nakon toga, bundle postaje zaštićen: samo aplikacije istog developera (ili eksplicitno dozvoljene od strane aplikacije) mogu menjati njegov sadržaj. Druge aplikacije zahtevaju novu TCC “App Management” dozvolu za pisanje u bundle druge aplikacije.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps can’t be copied elsewhere and launched; ovo ubija pristup „copy to /tmp, patch, run” za OS aplikacije.
- Improvements in macOS 14 Sonoma
- Apple je ojačao App Management i ispravio poznate bypass‑eve (npr. CVE‑2023‑40450) koje je prikazao Sector7. Python.framework je uklonjen ranije (macOS 12.3), što je prekinulo neke lance za eskalaciju privilegija.
- Gatekeeper/Quarantine changes
- Za širu diskusiju o izmenama Gatekeeper‑a, porekla i procene koje su uticale na ovu tehniku, pogledajte stranicu navedenu ispod.

> Practical implication
> • Na Ventura+ generalno ne možete izmeniti .nib treće strane aplikacije osim ako vaš proces nema App Management ili nije potpisan istim Team ID kao cilj (npr. developer tooling).
> • Dodeljivanje App Management ili Full Disk Access shell‑ovima/terminalima efektivno ponovo otvara ovu površinu napada za sve što može izvršavati kod unutar konteksta tog terminala.

### Rešavanje Launch Constraints

Launch Constraints sprečavaju pokretanje mnogih Apple aplikacija iz ne‑podrazumevanih lokacija počevši od Ventura. Ako ste se oslanjali na pre‑Ventura radne tokove kao što su kopiranje Apple aplikacije u privremeni direktorijum, modifikovanje `MainMenu.nib` i njeno pokretanje, očekujte da to neće raditi na verzijama >= 13.0.


## Enumerisanje ciljeva i nib‑ova (korisno za istraživanje / legacy sisteme)

- Pronađite aplikacije čiji je UI nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Pronađi moguće nib resurse unutar bundle-a:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Validirajte potpise koda dubinski (neće uspeti ako ste menjali resurse i niste ponovo potpisali):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Napomena: Na modernim macOS verzijama bićete blokirani i od strane bundle protection/TCC kada pokušate da upišete u bundle druge aplikacije bez odgovarajuće autorizacije.


## Detection and DFIR tips

- Praćenje integriteta fajlova nad resursima bundle‑a
- Pratiti promene mtime/ctime za `Contents/Resources/*.nib` i druge ne‑izvršne resurse u instaliranim aplikacijama.
- Unified logs i ponašanje procesa
- Pratiti neočekivano izvršavanje AppleScript‑a unutar GUI aplikacija i procese koji učitavaju AppleScriptObjC ili Python.framework. Primer:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktivne procene
- Povremeno pokrenuti `codesign --verify --deep` na kritičnim aplikacijama da biste osigurali da resursi ostaju netaknuti.
- Kontekst privilegija
- Auditirati ko/šta ima TCC “App Management” ili Full Disk Access (posebno terminali i management agents). Uklanjanje ovih iz alata opšte namene sprečava trivijalno ponovno omogućavanje Dirty NIB‑style manipulacija.


## Defensive hardening (developers and defenders)

- Preferirajte programatski UI ili ograničite šta se instancira iz nib‑ova. Izbegavajte uključivanje moćnih klasa (npr. `NSTask`) u nib grafove i izbegavajte bindings koji indirektno pozivaju selektore na proizvoljnim objektima.
- Koristite hardened runtime sa Library Validation (već standard za moderne aplikacije). Iako ovo samo po sebi ne zaustavlja nib injection, blokira lako učitavanje native koda i primorava napadače na scripting‑only payload‑e.
- Ne tražite i ne oslanjajte se na široke App Management dozvole u alatima opšte namene. Ako MDM zahteva App Management, odvojite taj kontekst od shell‑ova pokretanih od strane korisnika.
- Redovno verifikujte integritet vašeg app bundle‑a i učinite da mehanizmi ažuriranja automatski popravljaju resurse bundle‑a.


## Related reading in HackTricks

Saznajte više o Gatekeeper, quarantine i provenance promenama koje utiču na ovu tehniku:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (original write‑up with Pages example): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
