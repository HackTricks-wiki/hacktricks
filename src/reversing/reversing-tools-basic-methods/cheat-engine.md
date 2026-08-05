# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojem su važne vrednosti sačuvane u memoriji pokrenute igre i njihovu izmenu.\
Kada ga preuzmete i pokrenete, biće vam **prikazan** **tutorial** o korišćenju ovog alata. Ako želite da naučite kako se alat koristi, veoma se preporučuje da ga završite.<sup>[[3]](#references)</sup>

## Šta tražite?

![Cheat Engine - Šta tražite?: Šta tražite?](<../../images/image (762).png>)

Ovaj alat je veoma koristan za pronalaženje **mesta na kojem je neka vrednost** (obično broj) **sačuvana u memoriji** programa.\
**Brojevi se obično** čuvaju u formatu **4bytes**, ali ih možete pronaći i u formatima **double** ili **float**, ili možda želite da tražite nešto što **nije broj**. Zato morate biti sigurni da ste **izabrali** ono što želite da **tražite**:

![Cheat Engine - Šta tražite?: Brojevi se obično čuvaju u formatu 4bytes, ali ih možete pronaći i u formatima double ili float, ili možda želite da tražite nešto...](<../../images/image (324).png>)

Takođe možete navesti **različite** tipove **pretrage**:

![Cheat Engine - Šta tražite?: Takođe možete navesti različite tipove pretrage](<../../images/image (311).png>)

Možete označiti i polje za **zaustavljanje igre tokom skeniranja memorije**:

![Cheat Engine - Šta tražite?: Možete označiti i polje za zaustavljanje igre tokom skeniranja memorije](<../../images/image (1052).png>)

### Prečice

U _**Edit --> Settings --> Hotkeys**_ možete podesiti različite **prečice** za različite namene, kao što je **zaustavljanje** **igre** (što je veoma korisno ako u nekom trenutku želite da skenirate memoriju). Dostupne su i druge opcije:

![Šta tražite? - Prečice: U Edit -- Settings -- Hotkeys možete podesiti različite prečice za različite namene, kao što je zaustavljanje igre (što je veoma korisno ako u nekom trenutku...](<../../images/image (864).png>)

## Izmena vrednosti

Kada **pronađete** gde se nalazi **vrednost** koju **tražite** (više o tome u narednim koracima), možete je **izmeniti** tako što ćete dvaput kliknuti na nju, a zatim dvaput kliknuti na njenu vrednost:

![Prečice - Izmena vrednosti: Kada pronađete gde se nalazi vrednost koju tražite (više o tome u narednim koracima), možete je izmeniti tako što ćete dvaput kliknuti na nju, a zatim dvaput kliknuti...](<../../images/image (563).png>)

Na kraju **označite polje** da bi izmena bila izvršena u memoriji:

![Prečice - Izmena vrednosti: Na kraju označite polje da bi izmena bila izvršena u memoriji](<../../images/image (385).png>)

**Izmena** u **memoriji** biće odmah **primenjena** (imajte na umu da vrednost **neće biti ažurirana u igri** dok je igra ponovo ne upotrebi).

## Pretraga vrednosti

Pretpostavimo da postoji važna vrednost (kao što je život vašeg korisnika) koju želite da povećate i da tu vrednost tražite u memoriji.

### Putem poznate promene

Pretpostavimo da tražite vrednost 100. **Pokrenete skeniranje** za tu vrednost i pronađete mnogo podudaranja:

![Pretraga vrednosti - Putem poznate promene: Pretpostavimo da tražite vrednost 100, pokrenete skeniranje za tu vrednost i pronađete mnogo podudaranja](<../../images/image (108).png>)

Zatim uradite nešto zbog čega se **vrednost promeni**, **zaustavite** igru i **pokrenete** **naredno skeniranje**:

![Pretraga vrednosti - Putem poznate promene: Zatim uradite nešto zbog čega se vrednost promeni, zaustavite igru i pokrenete naredno skeniranje](<../../images/image (684).png>)

Cheat Engine će potražiti **vrednosti** koje su **prešle sa 100 na novu vrednost**. Čestitamo, **pronašli** ste **adresu** vrednosti koju ste tražili i sada je možete izmeniti.\
_Ako i dalje imate više vrednosti, ponovo uradite nešto što će izmeniti tu vrednost i pokrenite još jedno „naredno skeniranje“ da biste filtrirali adrese._

### Nepoznata vrednost, poznata promena

U scenariju u kojem **ne znate vrednost**, ali znate **kako da je promenite** (pa čak i za koliko će se promeniti), možete potražiti svoj broj.

Započnite skeniranjem tipa "**Unknown initial value**":

![Putem poznate promene - Nepoznata vrednost, poznata promena: Započnite skeniranjem tipa „Unknown initial value“](<../../images/image (890).png>)

Zatim promenite vrednost, navedite **kako** se **vrednost** promenila (u mom slučaju smanjena je za 1) i pokrenite **naredno skeniranje**:

![Putem poznate promene - Nepoznata vrednost, poznata promena: Zatim promenite vrednost, navedite kako se vrednost promenila (u mom slučaju smanjena je za 1) i pokrenite naredno skeniranje](<../../images/image (371).png>)

Biće vam prikazane **sve vrednosti koje su izmenjene na izabrani način**:

![Putem poznate promene - Nepoznata vrednost, poznata promena: Biće vam prikazane sve vrednosti koje su izmenjene na izabrani način](<../../images/image (569).png>)

Kada pronađete svoju vrednost, možete je izmeniti.

Imajte na umu da postoji **mnogo mogućih promena** i da ove **korake možete ponavljati koliko god želite** da biste filtrirali rezultate:

![Putem poznate promene - Nepoznata vrednost, poznata promena: Imajte na umu da postoji mnogo mogućih promena i da ove korake možete ponavljati koliko god želite da biste filtrirali rezultate](<../../images/image (574).png>)

### Nasumična memorijska adresa - Pronalaženje koda

Do sada smo naučili kako da pronađemo adresu na kojoj se čuva neka vrednost, ali je veoma verovatno da se **ta adresa nalazi na različitim mestima u memoriji tokom različitih pokretanja igre**. Zato ćemo videti kako da tu adresu uvek pronađemo.

Koristeći neke od pomenutih trikova, pronađite adresu na kojoj vaša trenutna igra čuva važnu vrednost. Zatim (zaustavljajući igru ako želite) kliknite **desnim klikom** na pronađenu **adresu** i izaberite "**Find out what accesses this address**" ili "**Find out what writes to this address**":

![Nepoznata vrednost, poznata promena - Nasumična memorijska adresa - Pronalaženje koda: Koristeći neke od pomenutih trikova, pronađite adresu na kojoj vaša trenutna igra čuva važnu vrednost. Zatim...](<../../images/image (1067).png>)

**Prva opcija** je korisna za utvrđivanje koji **delovi** **koda** **koriste** ovu **adresu** (što je korisno i za druge stvari, kao što je **utvrđivanje mesta na kojem možete izmeniti kod** igre).\
**Druga opcija** je **specifičnija** i u ovom slučaju će biti korisnija, jer želimo da saznamo **odakle se ova vrednost upisuje**.

Kada izaberete jednu od tih opcija, **debugger** će biti **prikačen** programu i pojaviće se novi **prazan prozor**. Sada **igrajte** **igru** i **izmenite** tu **vrednost** (bez ponovnog pokretanja igre). **Prozor** bi trebalo da se **popuni** **adresama** koje **menjaju** **vrednost**:

![Nepoznata vrednost, poznata promena - Nasumična memorijska adresa - Pronalaženje koda: Kada izaberete jednu od tih opcija, debugger će biti prikačen programu i pojaviće se novi prazan prozor...](<../../images/image (91).png>)

Sada kada ste pronašli adresu koja menja vrednost, možete **menjati kod po želji** (Cheat Engine omogućava veoma brzu izmenu u NOPs):

![Nepoznata vrednost, poznata promena - Nasumična memorijska adresa - Pronalaženje koda: Sada kada ste pronašli adresu koja menja vrednost, možete menjati kod po želji (Cheat Engine...](<../../images/image (1057).png>)

Sada je možete izmeniti tako da kod ne utiče na vaš broj ili da uvek utiče na pozitivan način.

### Nasumična memorijska adresa - Pronalaženje pointera

Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim pomoću opcije "**Find out what writes to this address**" saznajte koja adresa upisuje tu vrednost i dvaput kliknite na nju da biste dobili prikaz disassembly-ja:

![Nasumična memorijska adresa - Pronalaženje koda - Nasumična memorijska adresa - Pronalaženje pointera: Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim pomoću opcije „Find out...](<../../images/image (1039).png>)

Zatim pokrenite novo skeniranje **tražeći hex vrednost između "\[]"** (vrednost od $edx u ovom slučaju):

![Nasumična memorijska adresa - Pronalaženje koda - Nasumična memorijska adresa - Pronalaženje pointera: Zatim pokrenite novo skeniranje tražeći hex vrednost između „\[]“ (vrednost od $edx u ovom slučaju)](<../../images/image (994).png>)

(_Ako se pojavi više rezultata, obično vam je potrebna adresa sa najmanjom vrednošću_)\
Sada smo **pronašli pointer koji će menjati vrednost koja nas zanima**.

Kliknite na "**Add Address Manually**":

![Nasumična memorijska adresa - Pronalaženje koda - Nasumična memorijska adresa - Pronalaženje pointera: Kliknite na „Add Address Manually“](<../../images/image (990).png>)

Sada kliknite na polje za potvrdu "Pointer" i dodajte pronađenu adresu u tekstualno polje (u ovom scenariju, pronađena adresa na prethodnoj slici bila je "Tutorial-i386.exe"+2426B0):

![Nasumična memorijska adresa - Pronalaženje koda - Nasumična memorijska adresa - Pronalaženje pointera: Sada kliknite na polje za potvrdu „Pointer“ i dodajte pronađenu adresu u tekstualno polje (u ovom scenariju,...](<../../images/image (392).png>)

(Imajte na umu da se prvi "Address" automatski popunjava na osnovu adrese pointera koju unesete)

Kliknite na OK i biće kreiran novi pointer:

![Nasumična memorijska adresa - Pronalaženje koda - Nasumična memorijska adresa - Pronalaženje pointera: Kliknite na OK i biće kreiran novi pointer](<../../images/image (308).png>)

Sada, svaki put kada izmenite tu vrednost, **menjate važnu vrednost čak i ako se memorijska adresa na kojoj se vrednost nalazi razlikuje.**

### Code Injection

Code injection je tehnika u kojoj ubacujete deo koda u ciljni proces, a zatim preusmeravate izvršavanje koda tako da prolazi kroz vaš kod (na primer, dobijate poene umesto da ih gubite).

Pretpostavimo da ste pronašli adresu koja igraču oduzima 1 život:

![Nasumična memorijska adresa - Pronalaženje pointera - Code Injection: Pretpostavimo da ste pronašli adresu koja igraču oduzima 1 život](<../../images/image (203).png>)

Kliknite na Show disassembler da biste dobili **disassemble code**.\
Zatim pritisnite **CTRL+a** da biste otvorili prozor Auto assemble i izaberite _**Template --> Code Injection**_

![Nasumična memorijska adresa - Pronalaženje pointera - Code Injection: Zatim pritisnite CTRL+a da biste otvorili prozor Auto assemble i izaberite Template -- Code Injection](<../../images/image (902).png>)

Unesite **adresu instrukcije koju želite da izmenite** (ona se obično automatski popunjava):

![Nasumična memorijska adresa - Pronalaženje pointera - Code Injection: Unesite adresu instrukcije koju želite da izmenite (ona se obično automatski popunjava)](<../../images/image (744).png>)

Biće generisan template:

![Nasumična memorijska adresa - Pronalaženje pointera - Code Injection: Biće generisan template](<../../images/image (944).png>)

Zato ubacite svoj novi assembly kod u odeljak "**newmem**" i uklonite originalni kod iz odeljka "**originalcode**" ako ne želite da se izvršava**.** U ovom primeru, ubačeni kod će dodati 2 poena umesto da oduzme 1:

![Nasumična memorijska adresa - Pronalaženje pointera - Code Injection: Zato ubacite svoj novi assembly kod u odeljak „newmem“ i uklonite originalni kod iz odeljka „originalcode“ ako...](<../../images/image (521).png>)

**Kliknite na execute i tako dalje, pa bi vaš kod trebalo da bude ubačen u program i promeni ponašanje funkcionalnosti!**

## Napredne funkcije u Cheat Engine 7.x (2023-2025)

Cheat Engine je nastavio da se razvija od verzije 7.0 i dodato je nekoliko funkcija za lakši rad i *offensive-reversing* koje su izuzetno korisne pri analizi modernog software-a (a ne samo igara!). U nastavku je **veoma sažet terenski vodič** za dodatke koje ćete najverovatnije koristiti tokom red-team/CTF rada.<sup>[[1]](#references)</sup>

### Poboljšanja Pointer Scanner 2
* `Pointers must end with specific offsets` i novi klizač **Deviation** (≥7.4) značajno smanjuju broj lažno pozitivnih rezultata kada ponovo skenirate nakon update-a. Koristite ga zajedno sa poređenjem više mapa (`.PTR` → *Compare results with other saved pointer map*) da biste za samo nekoliko minuta dobili **jedan otporan bazni pointer**.
* Prečica za grupno filtriranje: nakon prvog skeniranja pritisnite `Ctrl+A → Space` da biste označili sve, a zatim `Ctrl+I` (invert) da biste poništili izbor adresa koje nisu prošle ponovno skeniranje.

### Ultimap 3 – Intel PT tracing
*Od verzije 7.5 stari Ultimap je ponovo implementiran na osnovu tehnologije **Intel Processor-Trace (IPT)**.* To znači da sada možete snimiti *svaki branch koji cilj izvrši* **bez single-stepping-a** (samo u user-mode-u; ovo neće aktivirati većinu anti-debug mehanizama).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Nakon nekoliko sekundi zaustavite capture i **kliknite desnim tasterom miša → Save execution list to file**. Kombinujte branch addresses sa sesijom `Find out what addresses this instruction accesses` da biste izuzetno brzo locirali game-logic hotspots sa visokom učestalošću.

### 1-byte `jmp` / auto-patch templates
Verzija 7.5 uvela je *one-byte* JMP stub (0xEB) koji instalira SEH handler i postavlja INT3 na originalnu lokaciju. Automatski se generiše kada koristite **Auto Assembler → Template → Code Injection** na instrukcijama koje ne mogu biti patch-ovane relativnim jump-om od 5 bajtova. Ovo omogućava „tight“ hooks unutar packed ili size-constrained rutina.

### Kernel-level stealth sa DBVM (AMD i Intel)
*DBVM* je CE-ov ugrađeni Type-2 hypervisor. Novije verzije su konačno dodale **AMD-V/SVM support**, tako da možete pokrenuti `Driver → Load DBVM` na Ryzen/EPYC hostovima. DBVM vam omogućava da:
1. Kreirate hardware breakpoints nevidljive Ring-3/anti-debug proverama.
2. Čitate/upisujete pageable ili zaštićene kernel memory regione čak i kada je user-mode driver onemogućen.
3. Izvršavate VM-EXIT-less zaobilaženja timing-attack mehanizama, npr. da iz hypervisor-a upitate `rdtsc`.

**Savet:** DBVM će odbiti učitavanje kada je HVCI/Memory-Integrity omogućen na Windowsu 11 → isključite ga ili pokrenite namenski VM-host.

### Remote / cross-platform debugging sa **ceserver**
CE sada dolazi sa potpunim rewrite-om alata *ceserver* i može da se poveže preko TCP-a sa **Linux, Android, macOS & iOS** targetima. Popularni fork integriše *Frida* kako bi kombinovao dynamic instrumentation sa CE GUI-jem – idealno kada treba da patch-ujete Unity ili Unreal igre koje rade na telefonu:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Za Frida bridge pogledajte `bb33bb/frida-ceserver` na GitHubu.<sup>[[2]](#references)</sup>

### Ostale značajne mogućnosti
* **Patch Scanner** (MemView → Tools) – otkriva neočekivane izmene koda u izvršnim sekcijama; korisno za malware analysis.
* **Structure Dissector 2** – prevucite adresu → `Ctrl+D`, zatim izaberite *Guess fields* da biste automatski procenili C-structures.
* **.NET & Mono Dissector** – poboljšana podrška za Unity igre; pozivajte metode direktno iz CE Lua konzole.
* **Big-Endian custom types** – skeniranje/uređivanje obrnutog redosleda bajtova (korisno za emulatore konzola i buffere mrežnih paketa).
* **Autosave & tabs** za AutoAssembler/Lua prozore, kao i `reassemble()` za višelinijsko prepisivanje instrukcija.

### Napomene o instalaciji i OPSEC-u (2024-2025)
* Zvanični installer je upakovan sa InnoSetup **ad-offers** (`RAV` itd.). **Uvek kliknite *Decline*** *ili kompajlirajte iz izvornog koda* da biste izbegli PUPs. AV-ovi će i dalje označavati `cheatengine.exe` kao *HackTool*, što je očekivano.
* Moderni anti-cheat driveri (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) detektuju CE window class čak i kada je preimenovan. Pokrenite svoju kopiju za reversing **unutar disposable VM-a** ili nakon onemogućavanja network play-a.
* Ako vam je potreban samo user-mode pristup, izaberite **`Settings → Extra → Kernel mode debug = off`** da biste izbegli učitavanje CE unsigned driver-a, koji može izazvati BSOD na Windowsu 11 24H2 sa Secure-Boot-om.

---

## Reference

- [1] [Beleške o izdanju Cheat Engine 7.5 (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial, završite ga da biste naučili kako da započnete rad sa Cheat Engine-om

{{#include ../../banners/hacktricks-training.md}}
