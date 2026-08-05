# Zloupotreba macOS procesa

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog fajla koji se izvršava, međutim procese ne izvršavaju kod, već niti. Zato su **procesi samo kontejneri za niti koje se izvršavaju**, obezbeđujući memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivanjem funkcije **`fork`**, koja bi kreirala identičnu kopiju trenutnog procesa, nakon čega bi **child process** uglavnom pozvao **`execve`** da učita novi izvršni fajl i pokrene ga. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao bez kopiranja memorije.\
Nakon toga je uveden **`posix_spawn`**, koji kombinuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
- `POSIX_SPAWN_SETEXEC`: Izvršava u istom procesu (poput `execve`, sa više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće suspendovano
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi Nano allocator biblioteke libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` na segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve deskriptore fajlova pri izvršavanju exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizuje visoke bitove ASLR pomaka

Pored toga, `posix_spawn` omogućava navođenje niza **`posix_spawnattr`** koji kontroliše neke aspekte pokrenutog procesa, kao i **`posix_spawn_file_actions`** za izmenu stanja deskriptora.

Kada proces umre, on šalje **povratni kod roditeljskom procesu** (ako je roditelj umro, novi roditelj je PID 1) signalom `SIGCHLD`. Roditelj mora da preuzme ovu vrednost pozivanjem funkcije `wait4()` ili `waitid()`, a dok se to ne dogodi, child ostaje u zombie stanju, u kom je i dalje naveden, ali ne troši resurse.

### PID-ovi

PID-ovi, odnosno identifikatori procesa, identifikuju jedinstven proces. U XNU-u **PID-ovi** imaju **64 bita**, monotono se uvećavaju i **nikada ne prelaze granicu** (kako bi se izbegle zloupotrebe).

### Grupe procesa, sesije i Coalition-i

**Procesi** se mogu ubaciti u **grupe** kako bi se njima lakše upravljalo. Na primer, komande u shell skripti biće u istoj grupi procesa, pa je moguće **signalizirati ih zajedno**, na primer korišćenjem funkcije kill.\
Procesi se takođe mogu **grupisati u sesije**. Kada proces pokrene sesiju (`setsid(2)`), child procesi se smeštaju u tu sesiju, osim ako pokrenu sopstvenu sesiju.

Coalition je još jedan način grupisanja procesa u Darwinu. Proces koji se pridruži coalition-u može da pristupi resursima pool-a, deli ledger ili bude podvrgnut Jetsam-u. Coalition-i imaju različite uloge: Leader, XPC service, Extension.

### Kredencijali i personae

Svaki proces poseduje **kredencijale** koji **identifikuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (iako može pripadati većem broju grupa).\
Takođe je moguće promeniti ID korisnika i grupe ako binarni fajl ima bit **`setuid/setgid`**.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** obezbeđuje alternativni skup **kredencijala**. Usvajanje personae istovremeno preuzima njen uid, gid i članstva u grupama. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:
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

1. **POSIX Threads (pthreads):** macOS podržava POSIX thread-ove (`pthreads`), koji su deo standardnog API-ja za thread-ove za C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, a potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža neophodne funkcije za kreiranje i upravljanje thread-ovima.
2. **Kreiranje thread-ova:** Funkcija `pthread_create()` koristi se za kreiranje novih thread-ova. Interno, ova funkcija poziva `bsdthread_create()`, system call nižeg nivoa specifičan za XNU kernel (kernel na kojem je macOS zasnovan). Ovaj system call prihvata različite flag-ove izvedene iz `pthread_attr` (atributa), koji određuju ponašanje thread-a, uključujući politike raspoređivanja i veličinu stack-a.
- **Podrazumevana veličina stack-a:** Podrazumevana veličina stack-a za nove thread-ove je 512 KB, što je dovoljno za uobičajene operacije, ali se može promeniti pomoću atributa thread-a ako je potrebno više ili manje prostora.
3. **Inicijalizacija thread-a:** Funkcija `__pthread_init()` ključna je tokom podešavanja thread-a i koristi argument `env[]` za parsiranje environment varijabli koje mogu sadržati podatke o lokaciji i veličini stack-a.

#### Terminacija thread-ova u macOS-u

1. **Izlazak iz thread-ova:** Thread-ovi se obično terminiraju pozivanjem funkcije `pthread_exit()`. Ova funkcija omogućava thread-u da se uredno završi, izvršavajući neophodno čišćenje i omogućavajući thread-u da pošalje povratnu vrednost svim thread-ovima koji ga čekaju.
2. **Čišćenje thread-a:** Nakon pozivanja funkcije `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja upravlja uklanjanjem svih povezanih struktura thread-a. Ona dealocira Mach port-ove thread-a (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, syscall koji uklanja strukture na nivou kernela povezane sa thread-om.

#### Mehanizmi za sinhronizaciju

Za upravljanje pristupom deljenim resursima i izbegavanje race condition-a, macOS pruža nekoliko primitiva za sinhronizaciju. Oni su ključni u multi-threading okruženjima kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
- **Regular Mutex (Signature: 0x4D555458):** Standardni mutex sa memorijskim footprint-om od 60 bajtova (56 bajtova za mutex i 4 bajta za signature).
- **Fast Mutex (Signature: 0x4d55545A):** Sličan regularnom mutex-u, ali optimizovan za brže operacije; njegova veličina je takođe 60 bajtova.
2. **Condition Variables:**
- Koriste se za čekanje da se ispune određeni uslovi, a njihova veličina je 44 bajta (40 bajtova plus 4-bajtni signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Konfiguracioni atributi za condition variables, veličine 12 bajtova.
3. **Once Variable (Signature: 0x4f4e4345):**
- Obezbeđuje da se deo inicijalizacionog koda izvrši samo jednom. Njegova veličina je 12 bajtova.
4. **Read-Write Locks:**
- Omogućava više čitača ili jednog writer-a u datom trenutku, čime se omogućava efikasan pristup deljenim podacima.
- **Read Write Lock (Signature: 0x52574c4b):** Veličine 196 bajtova.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Atributi za read-write lock-ove, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata koriste se za detekciju overflow-a.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** u kontekstu Mach-O fajlova (format izvršnih fajlova u macOS-u) koriste se za deklarisanje varijabli koje su specifične za **svaki thread** u multi-threaded aplikaciji. Ovo obezbeđuje da svaki thread ima sopstvenu, zasebnu instancu varijable, čime se omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije, kao što su mutex-i.

U C-u i srodnim jezicima, thread-local varijablu možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ovaj isečak definiše `tlv_var` kao thread-local promenljivu. Svaka nit koja izvršava ovaj kod ima sopstvenu `tlv_var` promenljivu, a izmene koje jedna nit napravi nad promenljivom `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnom fajlu, podaci povezani sa thread local promenljivama organizovani su u određene sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metadata podatke o thread-local promenljivama, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za thread-local promenljive koje nisu eksplicitno inicijalizovane. Ona predstavlja deo memorije rezervisan za podatke inicijalizovane nulom.

Mach-O takođe pruža specifičan API pod nazivom **`tlv_atexit`** za upravljanje thread-local promenljivama kada se nit završi. Ovaj API omogućava **registrovanje destruktora** — posebnih funkcija koje čiste thread-local podatke kada se nit terminira.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva posmatranje načina na koji operativni sistem odlučuje koje niti će se izvršavati i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS i Unix-like sistemima, ovo se obavlja korišćenjem koncepata kao što su `nice`, `renice` i Quality of Service (QoS) klase.

#### Nice i Renice

1. **Nice:**
- `nice` vrednost procesa je broj koji utiče na njegov prioritet. Svaki proces ima nice vrednost u opsegu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana nice vrednost prilikom kreiranja procesa obično je 0.
- Niža nice vrednost (bliža vrednosti -20) čini proces "sebičnijim", dajući mu više CPU vremena u odnosu na druge procese sa višim nice vrednostima.
2. **Renice:**
- `renice` je komanda koja se koristi za promenu nice vrednosti već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, povećavanjem ili smanjivanjem dodeljenog CPU vremena na osnovu novih nice vrednosti.
- Na primer, ako je procesu privremeno potrebno više CPU resursa, njegova nice vrednost može se smanjiti korišćenjem komande `renice`.

#### Quality of Service (QoS) klase

QoS klase predstavljaju moderniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. QoS klase omogućavaju developerima da **kategorizuju** rad u različite nivoe na osnovu njegove važnosti ili hitnosti. macOS automatski upravlja određivanjem prioriteta niti na osnovu ovih QoS klasa:

1. **User Interactive:**
- Ova klasa je namenjena zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju trenutne rezultate radi pružanja dobrog korisničkog iskustva. Ovim zadacima se dodeljuje najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
- Zadaci koje korisnik pokrene i za koje očekuje trenutne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva izračunavanja. Oni imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
- Ovi zadaci dugo traju i obično prikazuju indikator napretka (npr. preuzimanje fajlova ili importovanje podataka). Imaju niži prioritet od zadataka koje je pokrenuo korisnik i ne moraju da se završe odmah.
4. **Background:**
- Ova klasa je namenjena zadacima koji rade u pozadini i nisu vidljivi korisniku. To mogu biti zadaci kao što su indeksiranje, sinhronizacija ili backup. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem QoS klasa, developeri ne moraju da upravljaju preciznim brojevima prioriteta, već se mogu fokusirati na prirodu zadatka, dok sistem u skladu sa tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje definišu skup parametara raspoređivanja koje će scheduler uzeti u obzir. Ovo se može obaviti korišćenjem `thread_policy_[set/get]`. To može biti korisno u race condition napadima.

## Zloupotreba MacOS procesa

MacOS, kao i svaki drugi operativni sistem, pruža različite metode i mehanizme za **interakciju, komunikaciju i deljenje podataka između procesa**. Iako su ove tehnike ključne za efikasan rad sistema, threat actors ih mogu zloupotrebiti za **izvršavanje zlonamernih aktivnosti**.

### Library Injection

Library Injection je tehnika u kojoj napadač **primorava proces da učita zlonamernu biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, dajući napadaču iste dozvole i pristup kao i sam proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar programskog koda. Hooking funkcija napadaču može omogućiti da **izmeni ponašanje** procesa, posmatra osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) odnosi se na različite metode pomoću kojih odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC osnova mnogih legitimnih aplikacija, može se zloupotrebiti i za narušavanje izolacije procesa, leak osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije pokrenute sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti flagove `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **man in the browser attack** napada, koji omogućava krađu pritisnutih tastera, saobraćaja i cookies-a, kao i injection scriptova u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršavati proizvoljne komande**, a **Gatekeeper ne sprečava** već pokrenutu aplikaciju da se izvrši ako je **NIB fajl izmenjen**. Zato se mogu koristiti za izvršavanje proizvoljnih komandi pomoću proizvoljnih programa:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je zloupotrebiti određene java mogućnosti (kao što je env promenljiva **`_JAVA_OPTS`**) kako bi java aplikacija izvršila **proizvoljan code/commands**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je ubaciti code u .Net aplikacije **zloupotrebom .Net debugging funkcionalnosti** (koju ne štite macOS mehanizmi kao što je runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Pogledajte različite opcije za omogućavanje izvršavanja proizvoljnog koda u Perl skripti na sledećoj adresi:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Takođe je moguće zloupotrebiti ruby env promenljive kako bi proizvoljne skripte izvršavale proizvoljan code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Ako je env promenljiva **`PYTHONINSPECT`** postavljena, python proces će nakon završetka preći u python cli. Takođe je moguće koristiti **`PYTHONSTARTUP`** za navođenje python skripte koju treba izvršiti na početku interaktivne sesije.\
Međutim, imajte na umu da **`PYTHONSTARTUP`** skripta neće biti izvršena kada **`PYTHONINSPECT`** kreira interaktivnu sesiju.

Druge env promenljive, kao što su **`PYTHONPATH`** i **`PYTHONHOME`**, takođe mogu biti korisne za omogućavanje python komandi da izvrši proizvoljan code.

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** neće koristiti ove environmental promenljive čak i kada se izvršavaju pomoću ugrađenog python-a.

> [!CAUTION]
> Sve u svemu, nisam uspeo da pronađem način da python izvrši proizvoljan code zloupotrebom environment promenljivih.\
> Međutim, većina ljudi instalira pyhton pomoću **Hombrew-a**, koji će instalirati pyhton na **writable lokaciju** za podrazumevanog admin korisnika. Možete ga hijack-ovati na sledeći način:
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

[**Shield**](https://github.com/theevilbit/Shield) je open source aplikacija zasnovana na **EndpointSecurity**-ju koja detektuje i blokira process injection. Ona je dobar izvor za proveru toga koji su signali zaista vidljivi iz ES-a, jer upozorava na:<sup>[1]</sup>

- **Injection environment promenljive** prilikom exec procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u njega.
- **Electron debugging argumente** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u debug režimu i omogućavaju bilo kome da se poveže na nju i izvrši code.
- **Kreiranje symlink/hardlink veza između nivoa privilegija** — klasičan primitive "postavi link kao normalan korisnik i usmeri ga na privilegovanu lokaciju". Imajte na umu da se na **symlink veze može upozoriti, ali se ne mogu blokirati**: EndpointSecurity ne izlaže odredište linka pre njegovog kreiranja.

### Pozivi koje prave drugi procesi

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako je moguće koristiti funkciju **`task_name_for_pid`** za dobijanje informacija o drugim **procesima koji ubacuju code u proces**, a zatim i informacija o tom drugom procesu.<sup>[4]</sup>

Imajte na umu da za pozivanje ove funkcije morate imati **isti uid** kao proces koji je pokrenut ili biti **root** korisnik (a funkcija vraća informacije o procesu, ne način za injection koda).

## Reference

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
