# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca pokrenutog izvršnog programa, međutim procesi ne izvršavaju kod, to su niti. Stoga **procesi su samo kontejneri za pokretne niti** koji obezbeđuju memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su započinjani unutar drugih procesa (osim PID 1) pozivanjem **`fork`** koji bi napravio tačnu kopiju trenutnog procesa, a zatim bi **dečiji proces** obično pozvao **`execve`** da učita novi izvršni program i pokrene ga. Zatim je **`vfork`** uveden da ubrza ovaj proces bez kopiranja memorije.\
Zatim je **`posix_spawn`** uveden kombinujući **`vfork`** i **`execve`** u jednom pozivu i prihvatajući zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuj efektivne id-ove na stvarne id-ove
- `POSIX_SPAWN_SETPGROUP`: Postavi pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavi podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavi masku signala
- `POSIX_SPAWN_SETEXEC`: Izvrši u istom procesu (kao `execve` sa više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Započni suspendovano
- `_POSIX_SPAWN_DISABLE_ASLR`: Započni bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc-ov Nano alokator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoli `rwx` na segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Zatvori sve opise datoteka na exec(2) po defaultu
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizuj visoke bitove ASLR klizanja

Pored toga, `posix_spawn` omogućava da se specificira niz **`posix_spawnattr`** koji kontroliše neke aspekte pokrenutog procesa, i **`posix_spawn_file_actions`** za modifikaciju stanja deskriptora.

Kada proces umre, šalje **kod povratka roditeljskom procesu** (ako je roditelj umro, novi roditelj je PID 1) sa signalom `SIGCHLD`. Roditelj treba da dobije ovu vrednost pozivajući `wait4()` ili `waitid()` i dok se to ne desi, dečak ostaje u zombiju stanju gde je još uvek naveden, ali ne troši resurse.

### PIDs

PIDs, identifikatori procesa, identifikuju jedinstveni proces. U XNU **PIDs** su **64bita** i rastu monotonno i **nikada se ne preklapaju** (da bi se izbegle zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** mogu biti smešteni u **grupe** kako bi ih bilo lakše obraditi. Na primer, komande u shell skripti će biti u istoj grupi procesa, tako da je moguće **signalizovati ih zajedno** koristeći kill, na primer.\
Takođe je moguće **grupisati procese u sesije**. Kada proces započne sesiju (`setsid(2)`), dečiji procesi se postavljaju unutar sesije, osim ako ne započnu svoju sesiju.

Koalicija je još jedan način grupisanja procesa u Darwinu. Proces koji se pridružuje koaliciji omogućava mu pristup resursima bazena, deljenje knjigovodstva ili suočavanje sa Jetsam-om. Koalicije imaju različite uloge: Vođa, XPC usluga, Ekstenzija.

### Akreditivi i personae

Svaki proces ima **akreditive** koji **identifikuju njegove privilegije** u sistemu. Svaki proces će imati jedan primarni `uid` i jedan primarni `gid` (iako može pripadati više grupa).\
Takođe je moguće promeniti korisnički i grupni id ako binarni fajl ima `setuid/setgid` bit.\
Postoji nekoliko funkcija za **postavljanje novih uids/gids**.

Syscall **`persona`** pruža **alternativni** skup **akreditiva**. Usvajanje persone pretpostavlja njen uid, gid i članstva u grupama **odjednom**. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Osnovne informacije o nitima

1. **POSIX niti (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za niti za C/C++. Implementacija pthreads u macOS-u se nalazi u `/usr/lib/system/libsystem_pthread.dylib`, koja dolazi iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža potrebne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` se koristi za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, što je sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kojem se zasniva macOS). Ovaj sistemski poziv uzima različite zastavice izvedene iz `pthread_attr` (atributi) koje specificiraju ponašanje niti, uključujući politike raspoređivanja i veličinu steka.
- **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB, što je dovoljno za tipične operacije, ali se može prilagoditi putem atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` je ključna tokom postavljanja niti, koristeći argument `env[]` za parsiranje promenljivih okruženja koje mogu uključivati detalje o lokaciji i veličini steka.

#### Prekid niti u macOS-u

1. **Izlazak iz niti:** Niti se obično prekidaju pozivanjem `pthread_exit()`. Ova funkcija omogućava niti da se čisto završi, obavljajući potrebne čišćenje i omogućavajući niti da pošalje povratnu vrednost bilo kojim pridruženim nitima.
2. **Čišćenje niti:** Nakon pozivanja `pthread_exit()`, funkcija `pthread_terminate()` se poziva, koja se bavi uklanjanjem svih povezanih struktura niti. Ona deokupira Mach portove niti (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture na nivou kernela povezane sa niti.

#### Mehanizmi sinhronizacije

Da bi se upravljalo pristupom deljenim resursima i izbegle trke, macOS pruža nekoliko sinhronizacionih primitiva. Ovi su kritični u višedretvenim okruženjima kako bi se osigurala integritet podataka i stabilnost sistema:

1. **Mutexi:**
- **Obični mutex (Potpis: 0x4D555458):** Standardni mutex sa memorijskim otiskom od 60 bajtova (56 bajtova za mutex i 4 bajta za potpis).
- **Brzi mutex (Potpis: 0x4d55545A):** Sličan običnom mutexu, ali optimizovan za brže operacije, takođe 60 bajtova veličine.
2. **Uslovni varijable:**
- Koriste se za čekanje na određene uslove, sa veličinom od 44 bajta (40 bajtova plus 4-bajtni potpis).
- **Atributi uslovnih varijabli (Potpis: 0x434e4441):** Konfiguracijski atributi za uslovne varijable, veličine 12 bajtova.
3. **Jednom varijabla (Potpis: 0x4f4e4345):**
- Osigurava da se deo inicijalizacionog koda izvrši samo jednom. Njena veličina je 12 bajtova.
4. **Read-Write zaključavanja:**
- Omogućava više čitaoca ili jednog pisca u isto vreme, olakšavajući efikasan pristup deljenim podacima.
- **Read Write Lock (Potpis: 0x52574c4b):** Veličine 196 bajtova.
- **Atributi Read Write Lock (Potpis: 0x52574c41):** Atributi za read-write zaključavanja, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata se koriste za detekciju prelivanja.

### Lokalne varijable niti (TLV)

**Lokalne varijable niti (TLV)** u kontekstu Mach-O datoteka (format za izvršne datoteke u macOS-u) koriste se za deklarisanje varijabli koje su specifične za **svaku nit** u višedretvenoj aplikaciji. Ovo osigurava da svaka nit ima svoju odvojenu instancu varijable, pružajući način da se izbegnu konflikti i održi integritet podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije poput mutexa.

U C i srodnim jezicima, možete deklarisati lokalnu varijablu niti koristeći **`__thread`** ključnu reč. Evo kako to funkcioniše u vašem primeru:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ovaj deo definiše `tlv_var` kao promenljivu lokalnu za nit. Svaka nit koja izvršava ovaj kod ima svoju `tlv_var`, a promene koje jedna nit napravi na `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnom formatu, podaci vezani za promenljive lokalne za nit organizovani su u specifične sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o promenljivama lokalnim za nit, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za promenljive lokalne za nit koje nisu eksplicitno inicijalizovane. To je deo memorije rezervisan za podatke koji su inicijalizovani na nulu.

Mach-O takođe pruža specifičan API pod nazivom **`tlv_atexit`** za upravljanje promenljivama lokalnim za nit kada nit izlazi. Ovaj API omogućava **registraciju destruktora**—specijalnih funkcija koje čiste podatke lokalne za nit kada nit završi.

### Prioriteti niti

Razumevanje prioriteta niti uključuje razmatranje kako operativni sistem odlučuje koje niti da pokrene i kada. Ova odluka je pod uticajem nivoa prioriteta dodeljenog svakoj niti. U macOS-u i Unix-sličnim sistemima, ovo se rešava korišćenjem koncepata kao što su `nice`, `renice` i klase kvaliteta usluge (QoS).

#### Nice i Renice

1. **Nice:**
- `nice` vrednost procesa je broj koji utiče na njegov prioritet. Svaki proces ima nice vrednost u opsegu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana nice vrednost kada se proces kreira obično je 0.
- Niža nice vrednost (bliža -20) čini proces "samoživijim", dajući mu više CPU vremena u poređenju sa drugim procesima sa višim nice vrednostima.
2. **Renice:**
- `renice` je komanda koja se koristi za promenu nice vrednosti već pokrenutog procesa. Ovo se može koristiti za dinamičko podešavanje prioriteta procesa, bilo povećanjem ili smanjenjem njihove alokacije CPU vremena na osnovu novih nice vrednosti.
- Na primer, ako procesu privremeno treba više CPU resursa, možete smanjiti njegovu nice vrednost koristeći `renice`.

#### Klase kvaliteta usluge (QoS)

QoS klase su moderniji pristup upravljanju prioritetima niti, posebno u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. QoS klase omogućavaju programerima da **kategorizuju** rad u različite nivoe na osnovu njihove važnosti ili hitnosti. macOS automatski upravlja prioritetizacijom niti na osnovu ovih QoS klasa:

1. **Interaktivni korisnik:**
- Ova klasa je za zadatke koji trenutno interaguju sa korisnikom ili zahtevaju trenutne rezultate kako bi se obezbedilo dobro korisničko iskustvo. Ovi zadaci imaju najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **Inicirani od strane korisnika:**
- Zadaci koje korisnik inicira i očekuje trenutne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva proračune. Ovi su visoki prioritet, ali ispod interaktivnih korisničkih zadataka.
3. **Korisnička usluga:**
- Ovi zadaci su dugotrajni i obično prikazuju indikator napretka (npr. preuzimanje datoteka, uvoz podataka). Oni su niži u prioritetu od zadataka iniciranih od strane korisnika i ne moraju se završiti odmah.
4. **Pozadina:**
- Ova klasa je za zadatke koji rade u pozadini i nisu vidljivi korisniku. To mogu biti zadaci kao što su indeksiranje, sinhronizacija ili pravljenje rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem QoS klasa, programeri ne moraju upravljati tačnim brojevima prioriteta, već se fokusiraju na prirodu zadatka, a sistem optimizuje CPU resurse u skladu s tim.

Pored toga, postoje različite **politike zakazivanja niti** koje definišu skup parametara zakazivanja koje zakazivač uzima u obzir. Ovo se može uraditi korišćenjem `thread_policy_[set/get]`. Ovo može biti korisno u napadima na uslove trke.

## Zloupotreba procesa na MacOS-u

MacOS, kao i svaki drugi operativni sistem, pruža razne metode i mehanizme za **interakciju, komunikaciju i deljenje podataka između procesa**. Dok su ove tehnike esencijalne za efikasno funkcionisanje sistema, mogu ih takođe zloupotrebiti pretnje da **izvrše zlonamerne aktivnosti**.

### Ubrizgavanje biblioteka

Ubrizgavanje biblioteka je tehnika u kojoj napadač **prisiljava proces da učita zlonamernu biblioteku**. Kada se ubrizga, biblioteka se izvršava u kontekstu ciljnog procesa, pružajući napadaču iste dozvole i pristup kao proces.

{{#ref}}
macos-library-injection/
{{#endref}}

### Hooking funkcija

Hooking funkcija uključuje **presretanje poziva funkcija** ili poruka unutar softverskog koda. Presretanjem funkcija, napadač može **modifikovati ponašanje** procesa, posmatrati osetljive podatke ili čak preuzeti kontrolu nad tokom izvršenja.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### Komunikacija između procesa

Komunikacija između procesa (IPC) se odnosi na različite metode putem kojih odvojeni procesi **dele i razmenjuju podatke**. Dok je IPC fundamentalna za mnoge legitimne aplikacije, može se takođe zloupotrebiti za potkopavanje izolacije procesa, curenje osetljivih informacija ili izvršavanje neovlašćenih radnji.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Ubrizgavanje Electron aplikacija

Electron aplikacije izvršene sa specifičnim env varijablama mogu biti podložne ubrizgavanju procesa:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Ubrizgavanje Chromium-a

Moguće je koristiti zastavice `--load-extension` i `--use-fake-ui-for-media-stream` za izvršenje **napada "čovek u pretraživaču"** koji omogućava krađu pritisaka tastera, saobraćaja, kolačića, ubrizgavanje skripti u stranice...:

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Prljavi NIB

NIB datoteke **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, one mogu **izvršavati proizvoljne komande** i **Gatekeeper ne zaustavlja** već izvršenu aplikaciju od ponovnog izvršavanja ako je **NIB datoteka izmenjena**. Stoga se mogu koristiti za izvršavanje proizvoljnih komandi:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Ubrizgavanje Java aplikacija

Moguće je zloupotrebiti određene java mogućnosti (kao što je **`_JAVA_OPTS`** env varijabla) da bi se Java aplikacija izvršila **proizvoljnim kodom/komandama**.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Ubrizgavanje .Net aplikacija

Moguće je ubrizgati kod u .Net aplikacije zloupotrebom **.Net funkcionalnosti za debagovanje** (koja nije zaštićena macOS zaštitama kao što je hardening u vreme izvršenja).

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Ubrizgavanje Perla

Proverite različite opcije za izvršavanje Perl skripta proizvoljnim kodom u:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ubrizgavanje Ruby-a

Takođe je moguće zloupotrebiti ruby env varijable da bi se proizvoljni skripti izvršili proizvoljnim kodom:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Ubrizgavanje Pythona

Ako je env varijabla **`PYTHONINSPECT`** postavljena, Python proces će preći u Python CLI kada završi. Takođe je moguće koristiti **`PYTHONSTARTUP`** da označite Python skript koji će se izvršiti na početku interaktivne sesije.\
Međutim, imajte na umu da **`PYTHONSTARTUP`** skript neće biti izvršen kada **`PYTHONINSPECT`** kreira interaktivnu sesiju.

Druge env varijable kao što su **`PYTHONPATH`** i **`PYTHONHOME`** takođe mogu biti korisne za izvršavanje proizvoljnog koda Python komandom.

Napomena da izvršni programi kompajlirani sa **`pyinstaller`** neće koristiti ove varijable okruženja čak i ako se izvršavaju koristeći ugrađeni Python.

> [!CAUTION]
> U celini, nisam mogao pronaći način da se Python izvrši proizvoljnim kodom zloupotrebom varijabli okruženja.\
> Međutim, većina ljudi instalira Python koristeći **Homebrew**, koji će instalirati Python na **pisivo mesto** za podrazumevanog admin korisnika. Možete ga preuzeti sa nečim poput:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Dodatni kod za preuzimanje
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Čak će i **root** izvršiti ovaj kod kada pokrene Python.

## Detekcija

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) je aplikacija otvorenog koda koja može **detektovati i blokirati akcije ubrizgavanja procesa**:

- Korišćenjem **varijabli okruženja**: Pratiće prisustvo bilo koje od sledećih varijabli okruženja: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** i **`ELECTRON_RUN_AS_NODE`**
- Korišćenjem poziva **`task_for_pid`**: Da bi saznali kada jedan proces želi da dobije **task port drugog** koji omogućava ubrizgavanje koda u proces.
- **Parametri Electron aplikacija**: Neko može koristiti **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`** argumente komandne linije da pokrene Electron aplikaciju u režimu debagovanja, i tako ubrizga kod u nju.
- Korišćenjem **simboličkih linkova** ili **hardlinkova**: Obično je najčešća zloupotreba **postavljanje linka sa našim korisničkim privilegijama**, i **usmeravanje na lokaciju sa višim privilegijama**. Detekcija je vrlo jednostavna za hardlink i simboličke linkove. Ako proces koji kreira link ima **drugi nivo privilegija** od ciljne datoteke, kreiramo **uzbunu**. Nažalost, u slučaju simboličkih linkova blokiranje nije moguće, jer nemamo informacije o odredištu linka pre kreiranja. Ovo je ograničenje Apple-ovog EndpointSecurity okvira.

### Pozivi koje prave drugi procesi

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako je moguće koristiti funkciju **`task_name_for_pid`** da dobijete informacije o drugim **procesima koji ubrizgavaju kod u proces** i zatim dobijete informacije o tom drugom procesu.

Napomena da da biste pozvali tu funkciju morate biti **isti uid** kao onaj koji pokreće proces ili **root** (i vraća informacije o procesu, ne način za ubrizgavanje koda).

## Reference

- [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
- [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{{#include ../../../banners/hacktricks-training.md}}
