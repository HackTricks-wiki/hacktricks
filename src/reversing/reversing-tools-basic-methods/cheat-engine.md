# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojima su važne vrednosti sačuvane u memoriji pokrenute igre i njihovu izmenu.\
Kada ga preuzmete i pokrenete, biće vam prikazan **tutorial** o tome kako da koristite alat. Ako želite da naučite kako se alat koristi, veoma je preporučljivo da ga završite.

## Šta pretražujete?

![Cheat Engine - Šta pretražujete?: Šta pretražujete?](<../../images/image (762).png>)

Ovaj alat je veoma koristan za pronalaženje **mesta na kojem je neka vrednost** (obično broj) **sačuvana u memoriji** programa.\
**Brojevi** se **obično čuvaju** u obliku **4bytes**, ali ih možete pronaći i u formatima **double** ili **float**, ili možda želite da tražite nešto što **nije broj**. Zbog toga morate biti sigurni da ste **izabrali** ono što želite da **pretražujete**:

![Cheat Engine - Šta pretražujete?: Brojevi se obično čuvaju u obliku 4bytes, ali ih možete pronaći i u formatima double ili float, ili možda želite da tražite nešto...](<../../images/image (324).png>)

Takođe možete naznačiti **različite tipove** **pretraga**:

![Cheat Engine - Šta pretražujete?: Takođe možete naznačiti različite tipove pretraga](<../../images/image (311).png>)

Možete označiti i polje za **zaustavljanje igre tokom skeniranja memorije**:

![Cheat Engine - Šta pretražujete?: Možete označiti i polje za zaustavljanje igre tokom skeniranja memorije](<../../images/image (1052).png>)

### Hotkeys

U _**Edit --> Settings --> Hotkeys**_ možete podesiti različite **hotkeys** za različite namene, kao što je **zaustavljanje** **igre** (što je veoma korisno ako u nekom trenutku želite da skenirate memoriju). Dostupne su i druge opcije:

![Šta pretražujete? - Hotkeys: U Edit -- Settings -- Hotkeys možete podesiti različite hotkeys za različite namene, kao što je zaustavljanje igre (što je veoma korisno ako u nekom trenutku...](<../../images/image (864).png>)

## Izmena vrednosti

Kada **pronađete** gde se nalazi **vrednost** koju **tražite** (više o tome u narednim koracima), možete je **izmeniti** tako što ćete dvaput kliknuti na nju, a zatim dvaput kliknuti na njenu vrednost:

![Hotkeys - Izmena vrednosti: Kada pronađete gde se nalazi vrednost koju tražite (više o tome u narednim koracima), možete je izmeniti tako što ćete dvaput kliknuti na nju, a zatim dvaput kliknuti...](<../../images/image (563).png>)

Na kraju **označite polje** da bi izmena bila izvršena u memoriji:

![Hotkeys - Izmena vrednosti: Na kraju označite polje da bi izmena bila izvršena u memoriji](<../../images/image (385).png>)

**Izmena** u **memoriji** biće odmah **primenjena** (imajte na umu da vrednost **neće biti ažurirana u igri** sve dok je igra ponovo ne upotrebi).

## Pretraživanje vrednosti

Pretpostavimo da postoji važna vrednost (kao što je život vašeg korisnika) koju želite da poboljšate i da tražite tu vrednost u memoriji.

### Putem poznate promene

Pretpostavimo da tražite vrednost 100. **Pokrenete skeniranje** za tu vrednost i pronađete mnogo podudaranja:

![Pretraživanje vrednosti - Putem poznate promene: Pretpostavimo da tražite vrednost 100, pokrenete skeniranje za tu vrednost i pronađete mnogo podudaranja](<../../images/image (108).png>)

Zatim uradite nešto zbog čega se **vrednost promeni**, **zaustavite** igru i **pokrenete** **naredno skeniranje**:

![Pretraživanje vrednosti - Putem poznate promene: Zatim uradite nešto zbog čega se vrednost promeni, zaustavite igru i pokrenete naredno skeniranje](<../../images/image (684).png>)

Cheat Engine će tražiti **vrednosti** koje su **prešle sa 100 na novu vrednost**. Čestitamo, **pronašli ste** **adresu** vrednosti koju ste tražili i sada možete da je izmenite.\
_Ako i dalje imate više vrednosti, ponovo uradite nešto što će izmeniti tu vrednost i pokrenite još jedno „naredno skeniranje“ da biste filtrirali adrese._

### Nepoznata vrednost, poznata promena

U scenariju u kojem **ne znate vrednost**, ali znate **kako da je promenite** (pa čak i za koliko će se promeniti), možete da tražite svoj broj.

Zato za početak pokrenite skeniranje tipa „**Unknown initial value**“:

![Putem poznate promene - Nepoznata vrednost, poznata promena: Zato za početak pokrenite skeniranje tipa " Unknown initial value "](<../../images/image (890).png>)

Zatim promenite vrednost, navedite **kako** se **vrednost** **promenila** (u mom slučaju smanjena je za 1) i pokrenite **naredno skeniranje**:

![Putem poznate promene - Nepoznata vrednost, poznata promena: Zatim promenite vrednost, navedite kako se vrednost promenila (u mom slučaju smanjena je za 1) i pokrenite naredno skeniranje](<../../images/image (371).png>)

Biće vam prikazane **sve vrednosti koje su izmenjene na izabrani način**:

![Putem poznate promene - Nepoznata vrednost, poznata promena: Biće vam prikazane sve vrednosti koje su izmenjene na izabrani način](<../../images/image (569).png>)

Kada pronađete svoju vrednost, možete da je izmenite.

Imajte na umu da postoji **mnogo mogućih promena** i da ove **korake** možete ponavljati **koliko god želite** da biste filtrirali rezultate:

![Putem poznate promene - Nepoznata vrednost, poznata promena: Imajte na umu da postoji mnogo mogućih promena i da ove korake možete ponavljati koliko god želite da biste filtrirali rezultate](<../../images/image (574).png>)

### Nasumična adresa memorije - Pronalaženje koda

Do sada smo naučili kako da pronađemo adresu na kojoj se čuva neka vrednost, ali je veoma verovatno da se **ta adresa nalazi na drugom mestu u memoriji tokom različitih pokretanja igre**. Zato hajde da vidimo kako da tu adresu uvek pronađemo.

Koristeći neke od prethodno navedenih trikova, pronađite adresu na kojoj trenutna igra čuva važnu vrednost. Zatim (po želji zaustavite igru) kliknite **desnim tasterom** na pronađenu **adresu** i izaberite „**Find out what accesses this address**“ ili „**Find out what writes to this address**“:

![Nepoznata vrednost, poznata promena - Nasumična adresa memorije - Pronalaženje koda: Koristeći neke od prethodno navedenih trikova, pronađite adresu na kojoj trenutna igra čuva važnu vrednost. Zatim...](<../../images/image (1067).png>)

**Prva opcija** je korisna za utvrđivanje koji **delovi** **koda** **koriste** ovu **adresu** (što je korisno i za druge stvari, kao što je **utvrđivanje gde možete izmeniti kod** igre).\
**Druga opcija** je **specifičnija** i u ovom slučaju će biti korisnija, jer želimo da saznamo **odakle se ova vrednost upisuje**.

Kada izaberete jednu od tih opcija, **debugger** će biti **prikačen** za program i pojaviće se novi **prazan prozor**. Sada **igrajte** **igru** i **izmenite** tu **vrednost** (bez ponovnog pokretanja igre). **Prozor** bi trebalo da se **popuni** **adresama** koje **menjaju** **vrednost**:

![Nepoznata vrednost, poznata promena - Nasumična adresa memorije - Pronalaženje koda: Kada izaberete jednu od tih opcija, debugger će biti prikačen za program i pojaviće se novi prazan prozor. Zatim...](<../../images/image (91).png>)

Sada kada ste pronašli adresu koja menja vrednost, možete **izmeniti kod po želji** (Cheat Engine omogućava veoma brzo menjanje u NOPs):

![Nepoznata vrednost, poznata promena - Nasumična adresa memorije - Pronalaženje koda: Sada kada ste pronašli adresu koja menja vrednost, možete izmeniti kod po želji (Cheat Engine...](<../../images/image (1057).png>)

Sada možete da je izmenite tako da kod ne utiče na vaš broj ili da na njega uvek utiče na pozitivan način.

### Nasumična adresa memorije - Pronalaženje pointera

Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim pomoću opcije „**Find out what writes to this address**“ saznajte koja adresa upisuje ovu vrednost i dvaput kliknite na nju da biste dobili prikaz disassembly-ja:

![Nasumična adresa memorije - Pronalaženje koda - Nasumična adresa memorije - Pronalaženje pointera: Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim pomoću opcije " Find out...](<../../images/image (1039).png>)

Zatim pokrenite novo skeniranje i **pretražite hex vrednost između "\[]"** (vrednost registra $edx u ovom slučaju):

![Nasumična adresa memorije - Pronalaženje koda - Nasumična adresa memorije - Pronalaženje pointera: Zatim pokrenite novo skeniranje i pretražite hex vrednost između " ()" (vrednost registra $edx u ovom slučaju)](<../../images/image (994).png>)

(_Ako se pojavi više rezultata, obično vam je potrebna adresa sa najmanjom vrednošću_)\
Sada smo **pronašli pointer koji će menjati vrednost koja nas zanima**.

Kliknite na „**Add Address Manually**“:

![Nasumična adresa memorije - Pronalaženje koda - Nasumična adresa memorije - Pronalaženje pointera: Kliknite na " Add Address Manually "](<../../images/image (990).png>)

Sada kliknite na polje „Pointer“ i dodajte pronađenu adresu u tekstualno polje (u ovom scenariju, pronađena adresa na prethodnoj slici bila je „Tutorial-i386.exe“+2426B0):

![Nasumična adresa memorije - Pronalaženje koda - Nasumična adresa memorije - Pronalaženje pointera: Sada kliknite na polje "Pointer" i dodajte pronađenu adresu u tekstualno polje (u ovom scenariju,...](<../../images/image (392).png>)

(Imajte na umu da se prvi „Address“ automatski popunjava na osnovu adrese pointera koju unesete)

Kliknite na OK i biće kreiran novi pointer:

![Nasumična adresa memorije - Pronalaženje koda - Nasumična adresa memorije - Pronalaženje pointera: Kliknite na OK i biće kreiran novi pointer](<../../images/image (308).png>)

Sada svaki put kada izmenite tu vrednost, **menjate važnu vrednost čak i ako se adresa memorije na kojoj se vrednost nalazi promeni.**

### Code Injection

Code injection je tehnika u kojoj ubacujete deo koda u ciljni proces, a zatim preusmeravate izvršavanje koda tako da prolazi kroz vaš kod (na primer, dobijate poene umesto da ih gubite).

Pretpostavimo da ste pronašli adresu koja oduzima 1 od života vašeg igrača:

![Nasumična adresa memorije - Pronalaženje pointera - Code Injection: Pretpostavimo da ste pronašli adresu koja oduzima 1 od života vašeg igrača](<../../images/image (203).png>)

Kliknite na Show disassembler da biste dobili **disassemble kod**.\
Zatim kliknite **CTRL+a** da biste otvorili prozor Auto assemble i izaberite _**Template --> Code Injection**_

![Nasumična adresa memorije - Pronalaženje pointera - Code Injection: Zatim kliknite CTRL+a da biste otvorili prozor Auto assemble i izaberite Template -- Code Injection](<../../images/image (902).png>)

Unesite **adresu instrukcije koju želite da izmenite** (ona se obično automatski popunjava):

![Nasumična adresa memorije - Pronalaženje pointera - Code Injection: Unesite adresu instrukcije koju želite da izmenite (ona se obično automatski popunjava)](<../../images/image (744).png>)

Biće generisan template:

![Nasumična adresa memorije - Pronalaženje pointera - Code Injection: Biće generisan template](<../../images/image (944).png>)

Zato unesite svoj novi assembly kod u odeljak „**newmem**“ i uklonite originalni kod iz odeljka „**originalcode**“ ako ne želite da se izvršava**.** U ovom primeru, ubačeni kod će dodati 2 poena umesto da oduzme 1:

![Nasumična adresa memorije - Pronalaženje pointera - Code Injection: Zato unesite svoj novi assembly kod u odeljak " newmem " i uklonite originalni kod iz odeljka " originalcode " ako...](<../../images/image (521).png>)

**Kliknite na execute i ostalo, pa bi vaš kod trebalo da bude ubačen u program i da promeni ponašanje funkcionalnosti!**

## Napredne funkcije u Cheat Engine 7.x (2023-2025)

Cheat Engine je nastavio da se razvija od verzije 7.0 i dodato je nekoliko funkcija za kvalitetniji rad i *offensive-reversing* koje su izuzetno korisne pri analizi modernog software-a (i ne samo igara!). U nastavku je **veoma sažet vodič** kroz dodatke koje ćete najverovatnije koristiti tokom red-team/CTF rada.<sup>[[1]](#references)</sup>

### Poboljšanja Pointer Scanner 2
* Opcije `Pointers must end with specific offsets` i novi klizač **Deviation** (≥7.4) značajno smanjuju broj lažno pozitivnih rezultata kada ponovo skenirate nakon ažuriranja. Koristite ih zajedno sa poređenjem više mapa (`.PTR` → *Compare results with other saved pointer map*) da biste za samo nekoliko minuta dobili **jedan otporan base-pointer**.
* Prečica za grupno filtriranje: nakon prvog skeniranja pritisnite `Ctrl+A → Space` da biste označili sve, a zatim `Ctrl+I` (invert) da biste poništili izbor adresa koje nisu prošle ponovno skeniranje.

### Ultimap 3 – Intel PT tracing
*Od verzije 7.5 stari Ultimap je ponovo implementiran na osnovu **Intel Processor-Trace (IPT)**.* To znači da sada možete da snimite *svaki branch koji cilj izvrši* **bez single-stepping-a** (samo u user-mode-u; to neće aktivirati većinu anti-debug gadgeta).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Posle nekoliko sekundi zaustavite snimanje i **desnim klikom → Save execution list to file**. Kombinujte adrese grana sa sesijom `Find out what addresses this instruction accesses` da biste izuzetno brzo pronašli hotspots sa visokom frekvencijom u game-logic kodu.

### 1-byte `jmp` / auto-patch templates
Verzija 7.5 uvela je *one-byte* JMP stub (0xEB) koji instalira SEH handler i postavlja INT3 na originalnu lokaciju. Automatski se generiše kada koristite **Auto Assembler → Template → Code Injection** na instrukcijama koje ne mogu da se patch-uju 5-byte relativnim skokom. Ovo omogućava „tight“ hooks unutar packed ili size-constrained rutina.<sup>[[1]](#references)</sup>

### Kernel-level stealth sa DBVM (AMD & Intel)
*DBVM* je CE-ov ugrađeni Type-2 hypervisor. Novije verzije su konačno dodale **AMD-V/SVM support**, tako da možete pokrenuti `Driver → Load DBVM` na Ryzen/EPYC hostovima. DBVM vam omogućava da:
1. Kreirate hardware breakpoints nevidljive Ring-3/anti-debug proverama.
2. Čitate/pišete pageable ili zaštićene kernel memory regione čak i kada je user-mode driver onemogućen.
3. Izvršavate VM-EXIT-less timing-attack bypasses (npr. da iz hypervisor-a upitate `rdtsc`).

**Savet:** DBVM neće moći da se učita kada je HVCI/Memory-Integrity omogućen na Windows 11 → isključite ga ili pokrenite namenski VM-host.

### Remote / cross-platform debugging sa **ceserver**
CE sada dolazi sa potpunim rewrite-om *ceserver*-a i može da se poveže preko TCP-a sa **Linux, Android, macOS & iOS** targetima. Popularni fork integriše *Frida* kako bi kombinovao dynamic instrumentation sa CE GUI-jem – idealno kada treba da patch-ujete Unity ili Unreal igre koje rade na telefonu:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Za Frida bridge pogledajte `bb33bb/frida-ceserver` na GitHub-u.<sup>[[1]](#references)[[2]](#references)</sup>

### Još korisnih funkcija
* **Patch Scanner** (MemView → Tools) – otkriva neočekivane izmene koda u izvršnim sekcijama; koristan za analizu malware-a.
* **Structure Dissector 2** – prevucite adresu → `Ctrl+D`, zatim izaberite *Guess fields* za automatsku procenu C-structures.
* **.NET & Mono Dissector** – poboljšana podrška za Unity igre; metode možete pozivati direktno iz CE Lua konzole.
* **Big-Endian custom types** – skeniranje/izmena obrnutog redosleda bajtova (korisno za emulatore konzola i baferе mrežnih paketa).
* **Autosave & tabs** za AutoAssembler/Lua prozore, kao i `reassemble()` za izmenu instrukcija u više linija.<sup>[[1]](#references)</sup>

### Napomene o instalaciji i OPSEC-u (2024-2025)
* Zvanični installer je upakovan sa **ad-offers** (`RAV` itd.). **Uvek kliknite *Decline*** *ili kompajlirajte iz source-a* da biste izbegli PUP-ove. AV-ovi će i dalje označavati `cheatengine.exe` kao *HackTool*, što je očekivano.
* Moderni anti-cheat driveri (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) otkrivaju CE-ovu klasu prozora čak i kada je preimenovana. Svoju kopiju za reversing pokrećite **unutar disposable VM-a** ili nakon onemogućavanja network play-a.
* Ako vam je potreban samo pristup u user-mode-u, izaberite **`Settings → Extra → Kernel mode debug = off`** da biste izbegli učitavanje CE-ovog unsigned driver-a, koji može izazvati BSOD na Windows 11 24H2 Secure-Boot-u.

---

## Reference

- [1] [Cheat Engine 7.5 beleške o izdanju (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
