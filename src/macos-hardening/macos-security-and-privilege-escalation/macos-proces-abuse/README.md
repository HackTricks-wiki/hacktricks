# Zloupotreba macOS procesa

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog fajla koji se izvršava; međutim, procesi ne izvršavaju code, već niti. Zato su **procesi samo kontejneri za niti koje se izvršavaju**, obezbeđujući memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su pokretani unutar drugih procesa (osim PID-a 1) pozivanjem funkcije **`fork`**, koja bi kreirala identičnu kopiju trenutnog procesa, nakon čega bi **child process** uglavnom pozvao **`execve`** da učita novi izvršni fajl i pokrene ga. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao bez kopiranja memorije.\
Nakon toga je uveden **`posix_spawn`**, koji kombinuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne id-jeve na stvarne id-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
- `POSIX_SPAWN_SETEXEC`: Izvršava u istom procesu (kao `execve`, uz više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće suspendovano
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi Nano allocator biblioteke libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` nad segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve deskriptore fajlova pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizuje visoke bitove ASLR pomeraja

Pored toga, `posix_spawn` omogućava navođenje niza **`posix_spawnattr`** struktura koje kontrolišu određene aspekte pokrenutog procesa, kao i **`posix_spawn_file_actions`** za izmenu stanja deskriptora.

Kada proces završi, on šalje **povratni code roditeljskom procesu** (ako je roditelj završio, novi roditelj je PID 1) pomoću signala `SIGCHLD`. Roditelj mora da preuzme ovu vrednost pozivanjem `wait4()` ili `waitid()`, a dok se to ne dogodi, child ostaje u zombie stanju, u kom je i dalje naveden, ali ne troši resurse.

### PID-ovi

PID-ovi, odnosno identifikatori procesa, identifikuju jedinstveni proces. U XNU-u **PID-ovi** su 64-bitni, monotono rastu i **nikada se ne vraćaju na početak** (kako bi se sprečile zloupotrebe).

### Grupe procesa, sesije i Coalations

**Procesi** mogu biti smešteni u **grupe** kako bi se njima lakše upravljalo. Na primer, komande u shell skripti biće u istoj grupi procesa, pa ih je moguće **signalizirati zajedno**, na primer pomoću komande kill.\
Takođe je moguće **grupisati procese u sesije**. Kada proces pokrene sesiju (`setsid(2)`), child procesi se smeštaju u tu sesiju, osim ako ne pokrenu sopstvenu sesiju.

Coalition predstavlja drugi način grupisanja procesa u sistemu Darwin. Pridruživanje procesa coalition-u omogućava mu pristup resursima pool-a, deljenje ledger-a ili izlaganje Jetsam-u. Coalitions imaju različite uloge: Leader, XPC service, Extension.

### Kredencijali i personae

Svaki proces poseduje **kredencijale** koji **identifikuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (iako može pripadati većem broju grupa).\
Takođe je moguće promeniti korisnički i grupni id ako binarni fajl ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** obezbeđuje alternativni skup **kredencijala**. Usvajanje personae podrazumeva istovremeno preuzimanje njenog uid-a, gid-a i članstva u grupama. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:
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
## Osnovne informacije o thread-ovima

1. **POSIX Threads (pthreads):** macOS podržava POSIX thread-ove (`pthreads`), koji su deo standardnog threading API-ja za C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koji potiče iz javno dostupnog `libpthread` projekta. Ova biblioteka pruža neophodne funkcije za kreiranje i upravljanje thread-ovima.
2. **Kreiranje thread-ova:** Funkcija `pthread_create()` koristi se za kreiranje novih thread-ova. Interno, ova funkcija poziva `bsdthread_create()`, što je system call nižeg nivoa specifičan za XNU kernel (kernel na kojem je macOS zasnovan). Ovaj system call prima različite flag-ove izvedene iz `pthread_attr` (atributa), koji definišu ponašanje thread-a, uključujući scheduling policies i veličinu stack-a.
- **Podrazumevana veličina stack-a:** Podrazumevana veličina stack-a za nove thread-ove je 512 KB, što je dovoljno za tipične operacije, ali se može podesiti pomoću atributa thread-a ako je potrebno više ili manje prostora.
3. **Inicijalizacija thread-a:** Funkcija `__pthread_init()` je ključna tokom podešavanja thread-a i koristi argument `env[]` za parsiranje environment variables koje mogu sadržati informacije o lokaciji i veličini stack-a.

#### Terminacija thread-ova u macOS-u

1. **Izlazak iz thread-ova:** Thread-ovi se obično terminiraju pozivanjem `pthread_exit()`. Ova funkcija omogućava thread-u da se pravilno završi, obavi neophodno čišćenje i pošalje return value thread-ovima koji čekaju na njegovo završavanje.
2. **Čišćenje thread-a:** Nakon pozivanja `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture thread-a. Ona dealocira Mach thread port-ove (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, syscall koji uklanja strukture na nivou kernela povezane sa thread-om.

#### Mehanizmi za sinhronizaciju

Za upravljanje pristupom shared resources-ima i izbegavanje race conditions-a, macOS pruža nekoliko synchronization primitives-a. One su ključne u multi-threading okruženjima kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
- **Regular Mutex (Signature: 0x4D555458):** Standardni mutex sa memorijskim otiskom od 60 bajtova (56 bajtova za mutex i 4 bajta za signature).
- **Fast Mutex (Signature: 0x4d55545A):** Sličan regularnom mutex-u, ali optimizovan za brže operacije; takođe je veličine 60 bajtova.
2. **Condition Variables:**
- Koriste se za čekanje da se ispune određeni uslovi, a veličine su 44 bajta (40 bajtova plus 4-bajtni signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes za condition variables, veličine 12 bajtova.
3. **Once Variable (Signature: 0x4f4e4345):**
- Obezbeđuje da se deo initialization code-a izvrši samo jednom. Njegova veličina je 12 bajtova.
4. **Read-Write Locks:**
- Omogućavaju više čitalaca ili jednog writer-a istovremeno, čime se omogućava efikasan pristup shared data-u.
- **Read Write Lock (Signature: 0x52574c4b):** Veličine 196 bajtova.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes za read-write locks, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata koriste se za detektovanje overflow-a.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** u kontekstu Mach-O fajlova (formata za executable fajlove u macOS-u) koriste se za deklarisanje promenljivih koje su specifične za **svaki thread** u multi-threaded aplikaciji. To obezbeđuje da svaki thread ima svoju zasebnu instancu promenljive, čime se omogućava izbegavanje conflicts-a i očuvanje integriteta podataka bez potrebe za eksplicitnim synchronization mechanisms-ima kao što su mutex-i.

U C-u i srodnim jezicima, thread-local promenljivu možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ovaj isečak definiše `tlv_var` kao thread-local promenljivu. Svaka nit koja izvršava ovaj kod ima sopstvenu promenljivu `tlv_var`, a izmene koje jedna nit napravi nad promenljivom `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnom fajlu, podaci povezani sa thread-local promenljivama organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o thread-local promenljivama, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za thread-local promenljive koje nisu eksplicitno inicijalizovane. Ona predstavlja deo memorije rezervisan za podatke inicijalizovane nulama.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje thread-local promenljivama prilikom završetka niti. Ovaj API omogućava **registrovanje destruktora** — posebnih funkcija koje čiste thread-local podatke kada se nit završi.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva posmatranje načina na koji operativni sistem odlučuje koje niti će pokrenuti i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS i Unix-like sistemima, ovo se rešava korišćenjem koncepata kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
- Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima nice vrednost u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana nice vrednost prilikom kreiranja procesa obično je 0.
- Niža nice vrednost (bliža -20) čini proces „sebičnijim“, dajući mu više CPU vremena u poređenju sa drugim procesima sa višim nice vrednostima.
2. **Renice:**
- `renice` je komanda koja se koristi za promenu nice vrednosti već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, odnosno povećanje ili smanjenje dodeljenog CPU vremena na osnovu novih nice vrednosti.
- Na primer, ako je procesu privremeno potrebno više CPU resursa, njegova nice vrednost može se smanjiti pomoću `renice`.

#### Quality of Service (QoS) klase

QoS klase predstavljaju moderniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. QoS klase omogućavaju developerima da **kategoriyu** rad prema različitim nivoima, na osnovu njegove važnosti ili hitnosti. macOS automatski upravlja određivanjem prioriteta niti na osnovu ovih QoS klasa:

1. **User Interactive:**
- Ova klasa je namenjena zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju neposredne rezultate radi pružanja dobrog korisničkog iskustva. Ovim zadacima se dodeljuje najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
- Zadaci koje korisnik pokrene i za koje očekuje neposredne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva izračunavanja. Imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
- Ovi zadaci dugo traju i obično prikazuju indikator napretka (npr. preuzimanje fajlova ili uvoz podataka). Imaju niži prioritet od zadataka koje je pokrenuo korisnik i ne moraju se odmah završiti.
4. **Background:**
- Ova klasa je namenjena zadacima koji rade u pozadini i nisu vidljivi korisniku. To mogu biti zadaci poput indeksiranja, sinhronizacije ili pravljenja rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem QoS klasa, developeri ne moraju da upravljaju konkretnim brojevima prioriteta, već se mogu usredsrediti na prirodu zadatka, dok sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **thread scheduling policies** koje omogućavaju specificiranje skupa parametara raspoređivanja koje će scheduler uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u napadima koji iskorišćavaju race condition.

## MacOS Process Abuse

MacOS, kao i svaki drugi operativni sistem, pruža različite metode i mehanizme za **interakciju, komunikaciju i deljenje podataka između procesa**. Iako su ove tehnike neophodne za efikasno funkcionisanje sistema, threat actors ih mogu zloupotrebiti za **izvršavanje malicious aktivnosti**.

### Library Injection

Library Injection je tehnika u kojoj attacker **prisiljava proces da učita malicious biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, dajući attacker-u iste dozvole i pristup koje ima taj proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking funkcija omogućava attacker-u da **izmeni ponašanje** procesa, posmatra osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) odnosi se na različite metode pomoću kojih odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC osnova mnogih legitimnih aplikacija, može se zloupotrebiti za narušavanje izolacije procesa, curenje osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije pokrenute sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti flagove `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **man in the browser attack** napada, što omogućava krađu pritisnutih tastera, saobraćaja i cookies, kao i injection skripti u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršavati proizvoljne komande**, a **Gatekeeper ne sprečava** već pokrenutu aplikaciju da se izvrši ako je **NIB fajl izmenjen**. Zato se mogu koristiti za pokretanje proizvoljnih programa koji izvršavaju proizvoljne komande:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je zloupotrebiti određene java mogućnosti (kao što je env promenljiva **`_JAVA_OPTS`**) kako bi java aplikacija izvršila **proizvoljan code/commands**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je inject-ovati code u .Net aplikacije **zloupotrebom .Net debugging funkcionalnosti** (koju ne štite macOS zaštite kao što je runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Pogledajte različite opcije za izvršavanje proizvoljnog code-a u Perl skripti na:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Takođe je moguće zloupotrebiti ruby env promenljive kako bi proizvoljne skripte izvršavale proizvoljan code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Ako je env promenljiva **`PYTHONINSPECT`** podešena, python proces će nakon završetka preći u python cli. Takođe je moguće koristiti **`PYTHONSTARTUP`** za navođenje python skripte koja će se izvršiti na početku interaktivne sesije.\
Međutim, imajte na umu da se **`PYTHONSTARTUP`** skripta neće izvršiti kada **`PYTHONINSPECT`** kreira interaktivnu sesiju.

Druge env promenljive, kao što su **`PYTHONPATH`** i **`PYTHONHOME`**, takođe mogu biti korisne za izvršavanje proizvoljnog koda pomoću python komande.

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** neće koristiti ove environmental promenljive, čak i kada rade koristeći embedded python.

> [!CAUTION]
> Uopšteno, nisam uspeo da pronađem način da python izvrši proizvoljan code zloupotrebom env promenljivih.\
> Međutim, većina ljudi instalira pyhton koristeći **Hombrew**, koji će instalirati pyhton na **writable lokaciju** za podrazumevanog admin korisnika. Možete ga hijack-ovati nečim poput:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Čak će i **root** izvršiti ovaj code prilikom pokretanja python-a.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je open source aplikacija zasnovana na **EndpointSecurity** koja otkriva i blokira process injection. Predstavlja dobru referencu za signale koji su zaista vidljivi iz ES-a, pošto upozorava na:<sup>[[1]](#references)</sup>

- **Injection env promenljive** prilikom izvršavanja procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u njega.
- **Electron debugging argumente** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u debug režimu i omogućavaju bilo kome da se poveže i izvršava code u njoj.
- **Kreiranje symlink/hardlink veza između nivoa privilegija** — klasični primitive „postavi link kao normalan korisnik i usmeri ga na privilegovanu lokaciju“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne izlaže odredište linka pre kreiranja.

### Pozivi koje prave drugi procesi

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako je moguće koristiti funkciju **`task_name_for_pid`** za dobijanje informacija o drugim **procesima koji inject-uju code u proces**, a zatim i informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje ove funkcije morate imati **isti uid** kao proces koji je pokrenuo proces ili biti **root** (a ona vraća informacije o procesu, ne predstavlja način za injection koda).

## Reference

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
