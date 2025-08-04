# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje gde su važni podaci sačuvani unutar memorije pokrenute igre i njihovu promenu.\
Kada ga preuzmete i pokrenete, **prikazuje** vam se **tutorijal** o tome kako koristiti alat. Ako želite da naučite kako da koristite alat, toplo se preporučuje da ga završite.

## Šta tražite?

![](<../../images/image (762).png>)

Ovaj alat je veoma koristan za pronalaženje **gde je neki podatak** (obično broj) **sačuvan u memoriji** programa.\
**Obično se brojevi** čuvaju u **4bajtnoj** formi, ali ih možete pronaći i u **double** ili **float** formatima, ili možda želite da tražite nešto **drugačije od broja**. Iz tog razloga, morate biti sigurni da **izaberete** ono što želite da **tražite**:

![](<../../images/image (324).png>)

Takođe možete označiti **različite** tipove **pretraga**:

![](<../../images/image (311).png>)

Možete takođe označiti opciju da **zaustavite igru dok skenirate memoriju**:

![](<../../images/image (1052).png>)

### Prečice

U _**Edit --> Settings --> Hotkeys**_ možete postaviti različite **prečice** za različite svrhe kao što su **zaustavljanje** **igre** (što je veoma korisno ako u nekom trenutku želite da skenirate memoriju). Druge opcije su dostupne:

![](<../../images/image (864).png>)

## Modifikovanje vrednosti

Kada **pronađete** gde je **vrednost** koju tražite (više o tome u sledećim koracima), možete je **modifikovati** dvostrukim klikom na nju, a zatim dvostrukim klikom na njenu vrednost:

![](<../../images/image (563).png>)

I konačno **označite** kvačicu da biste izvršili modifikaciju u memoriji:

![](<../../images/image (385).png>)

**Promena** u **memoriji** će odmah biti **primenjena** (imajte na umu da dok igra ne koristi ovu vrednost ponovo, vrednost **neće biti ažurirana u igri**).

## Traženje vrednosti

Dakle, pretpostavićemo da postoji važna vrednost (kao što je život vašeg korisnika) koju želite da poboljšate, i tražite ovu vrednost u memoriji)

### Kroz poznatu promenu

Pretpostavljajući da tražite vrednost 100, **izvršite skeniranje** tražeći tu vrednost i pronađite mnogo podudaranja:

![](<../../images/image (108).png>)

Zatim, uradite nešto tako da **vrednost promeni**, i **zaustavite** igru i **izvršite** **sledeće skeniranje**:

![](<../../images/image (684).png>)

Cheat Engine će tražiti **vrednosti** koje su **prešle sa 100 na novu vrednost**. Čestitam, **pronašli ste** **adresu** vrednosti koju ste tražili, sada je možete modifikovati.\
_Ako još uvek imate nekoliko vrednosti, uradite nešto da ponovo modifikujete tu vrednost, i izvršite još jedno "sledeće skeniranje" da filtrirate adrese._

### Nepoznata vrednost, poznata promena

U scenariju kada **ne znate vrednost** ali znate **kako da je promenite** (i čak vrednost promene) možete tražiti svoj broj.

Dakle, počnite tako što ćete izvršiti skeniranje tipa "**Nepoznata početna vrednost**":

![](<../../images/image (890).png>)

Zatim, promenite vrednost, navedite **kako** se **vrednost** **promenila** (u mom slučaju je smanjena za 1) i izvršite **sledeće skeniranje**:

![](<../../images/image (371).png>)

Bićete prikazani **sve vrednosti koje su modifikovane na odabrani način**:

![](<../../images/image (569).png>)

Kada pronađete svoju vrednost, možete je modifikovati.

Imajte na umu da postoji **mnogo mogućih promena** i možete ponavljati ove **korake koliko god želite** da filtrirate rezultate:

![](<../../images/image (574).png>)

### Nasumična adresa u memoriji - Pronalaženje koda

Do sada smo naučili kako da pronađemo adresu koja čuva vrednost, ali je veoma verovatno da će u **različitim izvršavanjima igre ta adresa biti na različitim mestima u memoriji**. Dakle, hajde da saznamo kako da uvek pronađemo tu adresu.

Koristeći neke od pomenutih trikova, pronađite adresu gde vaša trenutna igra čuva važnu vrednost. Zatim (zaustavljajući igru ako želite) uradite **desni klik** na pronađenu **adresu** i izaberite "**Find out what accesses this address**" ili "**Find out what writes to this address**":

![](<../../images/image (1067).png>)

**Prva opcija** je korisna da saznate koje **delove** **koda** koriste ovu **adresu** (što je korisno za više stvari kao što je **znanje gde možete modifikovati kod** igre).\
**Druga opcija** je više **specifična**, i biće korisnija u ovom slučaju jer nas zanima da saznamo **odakle se ova vrednost piše**.

Kada odaberete jednu od tih opcija, **debugger** će biti **priključen** na program i novi **prazan prozor** će se pojaviti. Sada, **igrajte** **igru** i **modifikujte** tu **vrednost** (bez ponovnog pokretanja igre). **Prozor** bi trebao biti **ispunjen** sa **adresama** koje **modifikuju** **vrednost**:

![](<../../images/image (91).png>)

Sada kada ste pronašli adresu koja modifikuje vrednost, možete **modifikovati kod po svojoj želji** (Cheat Engine vam omogućava da ga brzo modifikujete za NOPs):

![](<../../images/image (1057).png>)

Dakle, sada možete modifikovati tako da kod ne utiče na vaš broj, ili će uvek pozitivno uticati.

### Nasumična adresa u memoriji - Pronalaženje pokazivača

Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim, koristeći "**Find out what writes to this address**" saznajte koja adresa piše ovu vrednost i dvostruko kliknite na nju da biste dobili prikaz disasembly-a:

![](<../../images/image (1039).png>)

Zatim, izvršite novo skeniranje **tražeći heksadecimalnu vrednost između "\[]"** (vrednost $edx u ovom slučaju):

![](<../../images/image (994).png>)

(_Ako se pojavi više njih, obično vam je potrebna najmanja adresa_)\
Sada smo **pronašli pokazivač koji će modifikovati vrednost koja nas zanima**.

Kliknite na "**Add Address Manually**":

![](<../../images/image (990).png>)

Sada, kliknite na kvačicu "Pointer" i dodajte pronađenu adresu u tekstualno polje (u ovom scenariju, pronađena adresa na prethodnoj slici je bila "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Imajte na umu kako je prva "Adresa" automatski popunjena iz adrese pokazivača koju ste uneli)

Kliknite na OK i biće kreiran novi pokazivač:

![](<../../images/image (308).png>)

Sada, svaki put kada modifikujete tu vrednost, **modifikujete važnu vrednost čak i ako je adresa u memoriji gde se vrednost nalazi drugačija.**

### Injekcija koda

Injekcija koda je tehnika gde injektujete deo koda u ciljni proces, a zatim preusmeravate izvršenje koda da ide kroz vaš vlastiti napisani kod (kao što je davanje poena umesto oduzimanja).

Dakle, zamislite da ste pronašli adresu koja oduzima 1 od života vašeg igrača:

![](<../../images/image (203).png>)

Kliknite na Prikaži disassembler da biste dobili **disassemble kod**.\
Zatim, kliknite **CTRL+a** da pozovete prozor Auto assemble i izaberite _**Template --> Code Injection**_

![](<../../images/image (902).png>)

Popunite **adresu instrukcije koju želite da modifikujete** (ovo se obično automatski popunjava):

![](<../../images/image (744).png>)

Generisaće se šablon:

![](<../../images/image (944).png>)

Dakle, umetnite svoj novi assembly kod u sekciju "**newmem**" i uklonite originalni kod iz "**originalcode**" ako ne želite da se izvršava. U ovom primeru, injektovani kod će dodati 2 poena umesto oduzimanja 1:

![](<../../images/image (521).png>)

**Kliknite na izvrši i tako dalje i vaš kod bi trebao biti injektovan u program menjajući ponašanje funkcionalnosti!**

## Napredne funkcije u Cheat Engine 7.x (2023-2025)

Cheat Engine je nastavio da se razvija od verzije 7.0 i nekoliko funkcija za poboljšanje kvaliteta života i *ofanzivnog obrnute inženjeringa* je dodato što je izuzetno korisno prilikom analize modernog softvera (i ne samo igara!). Ispod je **veoma sažet vodič** za dodatke koje ćete najverovatnije koristiti tokom red-team/CTF rada.

### Poboljšanja Pointer Scanner 2
* `Pokazivači moraju završavati sa specifičnim ofsetima` i novi **Deviation** klizač (≥7.4) značajno smanjuje lažne pozitivne rezultate kada ponovo skenirate nakon ažuriranja. Koristite ga zajedno sa višekratnom mapom poređenja (`.PTR` → *Poredi rezultate sa drugim sačuvanim mapama pokazivača*) da dobijete **jedan otporan osnovni pokazivač** za samo nekoliko minuta.
* Prečica za filtriranje u grupi: nakon prvog skeniranja pritisnite `Ctrl+A → Space` da označite sve, zatim `Ctrl+I` (invert) da poništite selekciju adresa koje nisu prošle ponovo skeniranje.

### Ultimap 3 – Intel PT praćenje
*Od 7.5 stari Ultimap je ponovo implementiran na osnovu **Intel Processor-Trace (IPT)***. To znači da sada možete snimiti *svaku* granu koju cilj preuzima **bez pojedinačnog koraka** (samo korisnički režim, neće aktivirati većinu anti-debug uređaja).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Nakon nekoliko sekundi, zaustavite snimanje i **desni klik → Sačuvaj listu izvršenja u datoteku**. Kombinujte adrese grana sa sesijom `Find out what addresses this instruction accesses` da biste veoma brzo locirali visoko-frekventne tačke logike igre.

### 1-bajtni `jmp` / auto-patch šabloni
Verzija 7.5 je uvela *jedan-bajtni* JMP stub (0xEB) koji instalira SEH handler i postavlja INT3 na originalnu lokaciju. Automatski se generiše kada koristite **Auto Assembler → Template → Code Injection** na instrukcijama koje ne mogu biti patch-ovane sa 5-bajtni relativnim skokom. Ovo omogućava “uske” hook-ove unutar pakovanih ili veličinski ograničenih rutina.

### Kernel-level stealth sa DBVM (AMD & Intel)
*DBVM* je ugrađeni Type-2 hipervizor CE-a. Nedavne verzije konačno su dodale **AMD-V/SVM podršku** tako da možete pokrenuti `Driver → Load DBVM` na Ryzen/EPYC hostovima. DBVM vam omogućava:
1. Kreiranje hardverskih breakpoint-a nevidljivih za Ring-3/anti-debug provere.
2. Čitanje/pisanje paginabilnih ili zaštićenih kernel memorijskih regiona čak i kada je drajver u korisničkom režimu onemogućen.
3. Izvođenje VM-EXIT-less zaobilaženja napada na vreme (npr. upit `rdtsc` iz hipervizora).

**Savjet:** DBVM će odbiti da se učita kada je HVCI/Memory-Integrity omogućen na Windows 11 → isključite ga ili pokrenite posvećen VM-host. 

### Daljinsko / cross-platform debagovanje sa **ceserver**
CE sada isporučuje potpuno prepisanu verziju *ceserver* i može se povezati preko TCP sa **Linux, Android, macOS & iOS** ciljevima. Popularni fork integriše *Frida* da kombinuje dinamičku instrumentaciju sa CE-ovim GUI-jem – idealno kada treba da patch-ujete Unity ili Unreal igre koje se pokreću na telefonu:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Za Frida most pogledajte `bb33bb/frida-ceserver` na GitHub-u.

### Ostali značajni alati
* **Patch Scanner** (MemView → Tools) – detektuje neočekivane promene koda u izvršnim sekcijama; koristan za analizu malvera.
* **Structure Dissector 2** – prevucite-adresu → `Ctrl+D`, zatim *Guess fields* za automatsku evaluaciju C-struktura.
* **.NET & Mono Dissector** – poboljšana podrška za Unity igre; pozivajte metode direktno iz CE Lua konzole.
* **Big-Endian prilagođeni tipovi** – obrnuti redosled bajtova skeniranje/uređivanje (korisno za emulatora konzola i mrežne pakete).
* **Autosave & tabs** za AutoAssembler/Lua prozore, plus `reassemble()` za prepisivanje višelinijskih instrukcija.

### Instalacija & OPSEC napomene (2024-2025)
* Zvanični instalater je obavijen InnoSetup **oglasima** (`RAV` itd.). **Uvek kliknite *Decline*** *ili kompajlirajte iz izvora* da izbegnete PUP-ove. AV-ovi će i dalje označiti `cheatengine.exe` kao *HackTool*, što je očekivano.
* Moderni anti-cheat drajveri (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) detektuju CE-ovu klasu prozora čak i kada je preimenovana. Pokrenite svoju verziju za obrnuto inženjerstvo **unutar jednokratne VM** ili nakon onemogućavanja mrežne igre.
* Ako vam je potrebna samo pristup korisničkom režimu izaberite **`Settings → Extra → Kernel mode debug = off`** da izbegnete učitavanje CE-ovog nepodpisanog drajvera koji može izazvati BSOD na Windows 11 24H2 Secure-Boot.

---

## **Reference**

- [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Cheat Engine tutorial, complete it to learn how to start with Cheat Engine**

{{#include ../../banners/hacktricks-training.md}}
