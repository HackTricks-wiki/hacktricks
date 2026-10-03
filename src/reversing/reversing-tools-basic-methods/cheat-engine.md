# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje mesta na kojima su važne vrednosti sačuvane u memoriji pokrenute igre i njihovu izmenu.\
Kada ga preuzmete i pokrenete, biće vam **prikazan** **tutorial** o tome kako da koristite alat. Ako želite da naučite kako da koristite alat, preporučuje se da ga završite.

## Šta tražite?

![Cheat Engine - What are you searching?: Šta tražite?](<../../images/image (762).png>)

Ovaj alat je veoma koristan za pronalaženje **mesta na kojem je neka vrednost** (obično broj) **sačuvana u memoriji** programa.\
**Brojevi** se **obično** čuvaju u obliku **4bytes**, ali možete ih pronaći i u formatima **double** ili **float**, ili možda želite da tražite nešto **što nije broj**. Zato morate biti sigurni da ste **izabrali** ono što želite da **tražite**:

![Cheat Engine - What are you searching?: Brojevi se obično čuvaju u obliku 4bytes, ali možete ih pronaći i u formatima double ili float, ili možda želite da tražite nešto...](<../../images/image (324).png>)

Takođe možete navesti **različite** tipove **pretrage**:

![Cheat Engine - What are you searching?: Takođe možete navesti različite tipove pretrage](<../../images/image (311).png>)

Možete označiti i polje za **zaustavljanje igre tokom skeniranja memorije**:

![Cheat Engine - What are you searching?: Možete označiti i polje za zaustavljanje igre tokom skeniranja memorije](<../../images/image (1052).png>)

### Prečice

U _**Edit --> Settings --> Hotkeys**_ možete podesiti različite **prečice** za različite namene, kao što je **zaustavljanje** **igre** (što je veoma korisno ako u nekom trenutku želite da skenirate memoriju). Dostupne su i druge opcije:

![What are you searching? - Hotkeys: U meniju Edit -- Settings -- Hotkeys možete podesiti različite prečice za različite namene, kao što je zaustavljanje igre (što je veoma korisno ako u nekom trenutku...](<../../images/image (864).png>)

## Izmena vrednosti

Kada **pronađete** gde se nalazi **vrednost** koju **tražite** (više o tome u sledećim koracima), možete je **izmeniti** tako što ćete dvaput kliknuti na nju, a zatim dvaput kliknuti na njenu vrednost:

![Hotkeys - Modifying the value: Kada pronađete gde se nalazi vrednost koju tražite (više o tome u sledećim koracima), možete je izmeniti tako što ćete dvaput kliknuti na nju, a zatim dvaput kliknuti...](<../../images/image (563).png>)

Na kraju **označite polje** da bi izmena bila izvršena u memoriji:

![Hotkeys - Modifying the value: Na kraju označite polje da bi izmena bila izvršena u memoriji](<../../images/image (385).png>)

**Izmena** u **memoriji** biće odmah **primenjena** (imajte na umu da se vrednost **neće ažurirati u igri** sve dok je igra ponovo ne upotrebi).

## Pretraga vrednosti

Pretpostavimo da postoji važna vrednost (kao što je život vašeg korisnika) koju želite da povećate i da tražite tu vrednost u memoriji.

### Na osnovu poznate promene

Pretpostavimo da tražite vrednost 100. **Izvršite skeniranje** tražeći tu vrednost i pronaći ćete mnogo podudaranja:

![Searching the value - Through a known change: Pretpostavimo da tražite vrednost 100, izvršite skeniranje tražeći tu vrednost i pronaći ćete mnogo podudaranja](<../../images/image (108).png>)

Zatim uradite nešto zbog čega će se **vrednost promeniti**, **zaustavite** igru i **izvršite** **sledeće skeniranje**:

![Searching the value - Through a known change: Zatim uradite nešto zbog čega će se vrednost promeniti, zaustavite igru i izvršite sledeće skeniranje](<../../images/image (684).png>)

Cheat Engine će tražiti **vrednosti** koje su se promenile **sa 100 na novu vrednost**. Čestitamo, **pronašli ste** **adresu** vrednosti koju ste tražili i sada možete da je izmenite.\
_Ako i dalje imate nekoliko vrednosti, ponovo uradite nešto što će izmeniti tu vrednost i izvršite još jedno „next scan“ skeniranje da biste filtrirali adrese._

### Nepoznata vrednost, poznata promena

U situaciji u kojoj **ne znate vrednost**, ali znate **kako da je promenite** (pa čak i za koliko će se promeniti), možete da pronađete svoj broj.

Započnite izvršavanjem skeniranja tipa „**Unknown initial value**“:

![Through a known change - Unknown Value, known change: Započnite izvršavanjem skeniranja tipa „Unknown initial value“](<../../images/image (890).png>)

Zatim promenite vrednost, navedite **kako** se **vrednost** **promenila** (u mom slučaju smanjena je za 1) i izvršite **sledeće skeniranje**:

![Through a known change - Unknown Value, known change: Zatim promenite vrednost, navedite kako se vrednost promenila (u mom slučaju smanjena je za 1) i izvršite sledeće skeniranje](<../../images/image (371).png>)

Biće vam prikazane **sve vrednosti koje su izmenjene na izabrani način**:

![Through a known change - Unknown Value, known change: Biće vam prikazane sve vrednosti koje su izmenjene na izabrani način](<../../images/image (569).png>)

Kada pronađete svoju vrednost, možete je izmeniti.

Imajte na umu da postoji **mnogo mogućih promena** i da ove **korake možete ponavljati koliko god želite** da biste filtrirali rezultate:

![Through a known change - Unknown Value, known change: Imajte na umu da postoji mnogo mogućih promena i da ove korake možete ponavljati koliko god želite da biste filtrirali rezultate](<../../images/image (574).png>)

### Nasumična adresa memorije - pronalaženje koda

Do sada smo naučili kako da pronađemo adresu na kojoj se čuva vrednost, ali je veoma verovatno da se **ta adresa nalazi na različitim mestima u memoriji tokom različitih pokretanja igre**. Zato pogledajmo kako da tu adresu uvek pronađemo.

Koristeći neke od prethodno pomenutih trikova, pronađite adresu na kojoj trenutna igra čuva važnu vrednost. Zatim (po želji zaustavite igru) kliknite **desnim tasterom miša** na pronađenu **adresu** i izaberite „**Find out what accesses this address**“ ili „**Find out what writes to this address**“:

![Unknown Value, known change - Random Memory Address - Finding the code: Koristeći neke od prethodno pomenutih trikova, pronađite adresu na kojoj trenutna igra čuva važnu vrednost. Zatim...](<../../images/image (1067).png>)

**Prva opcija** je korisna za utvrđivanje koji **delovi** **koda** **koriste** ovu **adresu** (što je korisno i za druge stvari, kao što je **utvrđivanje gde možete izmeniti kod** igre).\
**Druga opcija** je **konkretnija** i u ovom slučaju će biti korisnija jer želimo da saznamo **odakle se ova vrednost upisuje**.

Kada izaberete jednu od tih opcija, **debugger** će biti **prikačen** za program i pojaviće se novi **prazan prozor**. Sada **igrajte** igru i **izmenite** tu **vrednost** (bez ponovnog pokretanja igre). **Prozor** bi trebalo da se **popuni** **adresama** koje **menjaju** **vrednost**:

![Unknown Value, known change - Random Memory Address - Finding the code: Kada izaberete jednu od tih opcija, debugger će biti prikačen za program i pojaviće se novi prazan prozor...](<../../images/image (91).png>)

Sada kada ste pronašli adresu koja menja vrednost, možete **menjati kod po želji** (Cheat Engine omogućava veoma brzu izmenu u NOPs):

![Unknown Value, known change - Random Memory Address - Finding the code: Sada kada ste pronašli adresu koja menja vrednost, možete menjati kod po želji (Cheat Engine omogućava veoma brzu izmenu u NOPs...](<../../images/image (1057).png>)

Sada možete da ga izmenite tako da kod ne utiče na vaš broj ili da uvek utiče na pozitivan način.

### Nasumična adresa memorije - pronalaženje pointera

Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim, pomoću opcije „**Find out what writes to this address**“, saznajte koja adresa upisuje ovu vrednost i dvaput kliknite na nju da biste dobili prikaz disassembly-ja:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim, pomoću opcije „Find out...](<../../images/image (1039).png>)

Zatim izvršite novo skeniranje **tražeći hex vrednost između „\[]“** (vrednost od $edx u ovom slučaju):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Zatim izvršite novo skeniranje tražeći hex vrednost između „ ()“ (vrednost od $edx u ovom slučaju)](<../../images/image (994).png>)

(_Ako se pojavi više rezultata, obično vam je potrebna adresa sa najmanjom vrednošću_)\
Sada smo **pronašli pointer koji će menjati vrednost koja nas zanima**.

Kliknite na „**Add Address Manually**“:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Kliknite na „Add Address Manually“](<../../images/image (990).png>)

Sada kliknite na polje „Pointer“ i dodajte pronađenu adresu u tekstualno polje (u ovom slučaju, pronađena adresa na prethodnoj slici bila je „Tutorial-i386.exe“+2426B0):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Sada kliknite na polje „Pointer“ i dodajte pronađenu adresu u tekstualno polje (u ovom slučaju,...](<../../images/image (392).png>)

(Imajte na umu da se prvi „Address“ automatski popunjava na osnovu adrese pointera koju unesete)

Kliknite na OK i biće kreiran novi pointer:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Kliknite na OK i biće kreiran novi pointer](<../../images/image (308).png>)

Sada, svaki put kada izmenite tu vrednost, **menjaćete važnu vrednost čak i ako se adresa memorije na kojoj se vrednost nalazi promeni.**

### Code Injection

Code injection je tehnika u kojoj ubacujete deo koda u ciljani proces, a zatim preusmeravate izvršavanje koda tako da prolazi kroz vaš kod (na primer, da vam dodeli poene umesto da ih oduzme).

Pretpostavimo da ste pronašli adresu koja životu vašeg igrača oduzima 1:

![Random Memory Address - Finding the pointer - Code Injection: Pretpostavimo da ste pronašli adresu koja životu vašeg igrača oduzima 1](<../../images/image (203).png>)

Kliknite na Show disassembler da biste dobili **disassembled code**.\
Zatim pritisnite **CTRL+a** da biste otvorili prozor Auto assemble i izaberite _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Zatim pritisnite CTRL+a da biste otvorili prozor Auto assemble i izaberite Template -- Code Injection](<../../images/image (902).png>)

Unesite **adresu instrukcije koju želite da izmenite** (ona se obično automatski popunjava):

![Random Memory Address - Finding the pointer - Code Injection: Unesite adresu instrukcije koju želite da izmenite (ona se obično automatski popunjava)](<../../images/image (744).png>)

Biće generisan template:

![Random Memory Address - Finding the pointer - Code Injection: Biće generisan template](<../../images/image (944).png>)

Sada unesite novi assembly kod u odeljak „**newmem**“ i uklonite originalni kod iz odeljka „**originalcode**“ ako ne želite da se izvršava**.** U ovom primeru, injected code će dodati 2 poena umesto da oduzme 1:

![Random Memory Address - Finding the pointer - Code Injection: Sada unesite novi assembly kod u odeljak „newmem“ i uklonite originalni kod iz odeljka „originalcode“ ako...](<../../images/image (521).png>)

**Kliknite na execute i tako dalje, pa bi vaš kod trebalo da bude injected u program i promeni ponašanje funkcionalnosti!**

## Code Injection bez problema sa relocacijom pomoću AOB signatures

Script koji hook-uje `game.exe+123456` može prestati da radi nakon ASLR-a ili ažuriranja software-a. **Array of Bytes (AOB) signature** umesto toga pronalazi instrukciju na osnovu okolnog machine code-a. Koristite `aobscanmodule` da biste pretragu ograničili na jedan module. Neka signature bude dovoljno dugačka da vrati jedno podudaranje. Koristite wildcard za relocation bytes, adrese i druge bytes koji se mogu promeniti. Nemojte koristiti wildcard za celu instrukciju koju treba da vratite.<sup>[[4]](#references)</sup>

U Memory View-u izaberite instrukciju i koristite **Tools → Auto Assemble → Template → AOB Injection**. Generisani `[DISABLE]` blok je važan. On mora da vrati svaki overwritten byte i oslobodi alokaciju.<sup>[[4]](#references)</sup>

<details>
<summary>Minimalni x64 AOB injection skeleton</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Pre omogućavanja skripte proverite sledeće:

1. AOB vraća **jednu** adresu. Ako vraća više adresa, dodajte stabilne instrukcije sa obe strane.
2. Skok zamenjuje kompletne instrukcije. Nikada nemojte deliti instrukciju.
3. Alocirani cave je dostižan generisanim skokom. Na x64, udaljena alokacija može zahtevati skok od 14 bajtova.
4. Injected code čuva registre, flags i poravnanje stack-a koje originalna funkcija očekuje.
5. Blok za onemogućavanje vraća tačne originalne bajtove. Testirajte omogućavanje i onemogućavanje više puta pre čuvanja tabele.

## Pouzdan workflow za pointer-e

Pointer pronađen u jednom pokretanju samo je kandidat. Napravite pointer mape u nekoliko novih izvršavanja i ponovite skeniranje u odnosu na sva izvršavanja. Ponovo pokrenite target između snimanja kako bi se ASLR i heap alokacije promenili. Dajte prednost putanjama čija je baza modul ili drugi stabilan simbol. Odbacite putanje koje rade samo sa jednim save-om, nivoom ili instancom objekta.

Filter **pointer must end with specific offsets** i njegova opcija za devijaciju mogu zadržati korisne putanje kada se obližnje polje pomeri između build-ova. Izdanje 7.5 takođe je dodalo ovu kontrolu devijacije. To je filter, a ne dokaz da je pointer chain stabilan.<sup>[[1]](#references)</sup>

Kada se struktura prečesto pomera za pointer scanning, hook-ujte instrukciju koja joj pristupa. Sačuvajte živi pointer objekta iz registra u alocirani simbol. Ovo je često pouzdanije za liste entiteta i managed objekte.

## Praćenje koda umesto skeniranja vrednosti

Koristite **Find out what writes to this address** kada se vrednost direktno menja. Koristite **Find out what accesses this address** kada vam je potreban objekat koji je vlasnik ili kada se upis obavlja preko kopiranih podataka. U target-u pokrenite samo jednu radnju. Zatim uporedite broj pogodaka i stanje registara.

**Ultimap 2** koristi Intel Processor Trace na podržanim Intel CPU-ovima. Beleži izvršeni control flow uz manje prekida nego pri izvršavanju svake instrukcije korak po korak. Filtrirajte kod koji je izvršen tokom zanimljive radnje i uklonite kod koji je takođe izvršen tokom idle snimanja. Intel PT nije stealth funkcija. Target i dalje može otkriti tracing, promene u vremenu izvršavanja ili sam Cheat Engine.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 je takođe dodao Intel PT interfejs koji obezbeđuje Windows. Stariji Ultimap režim zasnovan na DBVM-u i Intel PT režim imaju različite hardverske i OS zahteve. Nemojte pretpostaviti da CPU koji podržava DBVM podržava i Intel PT.<sup>[[1]](#references)</sup>

## Izbor debugger-a i breakpoint-a

Izaberite najmanje invazivan debugger koji funkcioniše:

- **Windows debugger** je jednostavan, ali kreira uobičajene debug događaje. Anti-debugging provere mogu da ga otkriju.
- **VEH debugger** obrađuje breakpoint-e kroz vectored exception handler. Zaobilazi neke osnovne provere debugger-a, ali nije nevidljiv.
- **Hardware breakpoints** ne menjaju bajtove instrukcija, ali x86/x64 pruža samo mali broj slotova u debug registrima.
- **Software breakpoints** zamenjuju jedan bajt sa `INT3`. Lako ih je otkriti i mogu biti u konfliktu sa integrity proverama.
- **DBVM debugger** premešta neke operacije ispod guest OS-a. Ima mnogo veće privilegije i može srušiti host ako je pogrešno konfigurisan.

Cheat Engine 7.5 može koristiti skok od jednog bajta zasnovan na exception handler-u i `INT3` kada nema dovoljno prostora za normalan relativni skok. Tretirajte ga kao software breakpoint. Proverite tok exception-a i nemojte pretpostaviti da zaobilazi anti-tamper provere.<sup>[[1]](#references)</sup>

DBVM je hypervisor, a ne opšti prekidač za nevidljivost. Koristite ga samo u disposable lab-u. Nemojte izlagati njegov control interfejs nepouzdanom kodu. Kernel anti-cheat i endpoint proizvodi i dalje mogu otkriti driver, stanje hypervisor-a ili izmenjenu memoriju.

## Managed runtime-i i novije funkcije 7.6/7.7

Za Mono, IL2CPP, .NET i Java target-e, kada je dostupno, dajte prednost runtime metadata podacima u odnosu na slepe scan-ove. Otvorite **Mono → Activate mono features** ili odgovarajući prozor sa runtime informacijama. Najpre pronađite klasu, polje ili metodu. Zatim koristite native disassembly kada se managed metoda JIT-kompajlira.

Linija 7.6 dodala je `AOBSCANEX` za signature-e ograničene na executable memoriju, `gdbserver` debugger interfejs, inspekciju Java metadata podataka, bržu IL2CPP enumeraciju i opciju pointer scan-a koja ignoriše gornji bajt pointer-a koji koristi ARM memory tagging. Linija 7.7 dodala je native Linux build-ove, `HOOK`/`UNHOOK`, `aobscanfunction`, bolji lookup generičkih Mono metoda, poboljšanu podršku za PDB strukture i osnovnu disekciju Unreal Engine struktura.<sup>[[3]](#references)</sup>

Ove dopune omogućavaju koristan workflow:

1. Razrešite managed metodu ili static field iz metadata podataka.
2. Pratite ili disasemblirajte native kod generisan za tu metodu.
3. Koristite `AOBSCANEX` ili `aobscanfunction` da pronađete stabilan executable signature.
4. Generišite reverzibilni hook. Sačuvajte originalne instrukcije i proverite putanju za onemogućavanje.
5. Ponovo proverite signature nakon svakog update-a target-a. Uspešno poklapanje ne garantuje da okolna logika i dalje ima isto značenje.

## Remote target-i sa `ceserver`

`ceserver` Cheat Engine GUI-ju izlaže enumeraciju procesa, pristup memoriji i debugging. Zvanični build-ovi pokrivaju Linux i Android. Pokrenite odgovarajuću arhitekturu na target-u i povežite se kroz karticu **Network**. Na Android-u, prosleđivanje podrazumevanog porta sprečava njegovo izlaganje na mreži:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Treća strana `frida-ceserver` bridge može da obezbedi interfejs kompatibilan sa Cheat Engine-om za iOS targets. To nije zvanični `ceserver`, a podržane operacije mogu da se razlikuju.<sup>[[2]](#references)</sup>

Pretpostavite da protokol omogućava pristup na nivou debugger-a. Vežite ga za loopback ili ga postavite iza SSH/ADB tunela. Nikada ne izlažite TCP 52736 mreži kojoj se ne može verovati. Zaustavite server kada se sesija završi.

## Bezbednost pri radu

Povezujte se samo sa softverom koji posedujete ili za čije testiranje imate ovlašćenje. Nemojte pokretati Cheat Engine pored online igre ili produkcionog endpoint-a. Memory writes, injected code, drivers i DBVM mogu da sruše ili oštete target.<sup>[[3]](#references)</sup>

Preuzimajte builds sa zvaničnog sajta ili kompajlirajte objavljeni source. Security products često klasifikuju memory editors, debuggers i njihove drivers kao hack tools. Nemojte globalno onemogućavati zaštitu hosta. Koristite namenski VM ili lab host i proverite artifact pre pokretanja.<sup>[[3]](#references)</sup>



## References

- [1] [Beleške o izdanju Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver bridge za remote targets](https://github.com/gmh5225/frida-ceserver)
- [3] [Zvanične vesti o izdanjima Cheat Engine-a](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
