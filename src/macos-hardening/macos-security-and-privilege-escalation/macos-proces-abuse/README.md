# Zloupotreba macOS procesa

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog fajla koji se izvršava; međutim, procesi ne izvršavaju kod, već to rade niti. Dakle, **procesi su samo kontejneri za niti koje se izvršavaju**, a obezbeđuju memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su pokretani unutar drugih procesa (osim PID-a 1) pozivanjem funkcije **`fork`**, koja bi kreirala identičnu kopiju trenutnog procesa, nakon čega bi **child process** uglavnom pozvao **`execve`** da učita novi izvršni fajl i pokrene ga. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao bez kopiranja memorije.\
Nakon toga je uveden **`posix_spawn`**, koji kombinuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
- `POSIX_SPAWN_SETEXEC`: Izvršava u istom procesu (kao `execve`, ali sa više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće suspendovano
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` nad segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve deskriptore fajlova pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično raspoređuje visoke bitove ASLR pomeraja

Pored toga, `posix_spawn` omogućava navođenje niza **`posix_spawnattr`** elemenata koji kontrolišu određene aspekte pokrenutog procesa, kao i **`posix_spawn_file_actions`** za izmenu stanja deskriptora.

Kada proces umre, on šalje **povratni kod roditeljskom procesu** (ako je roditeljski proces umro, novi roditelj je PID 1) signalom `SIGCHLD`. Roditelj mora da preuzme ovu vrednost pozivanjem funkcije `wait4()` ili `waitid()`, a dok se to ne dogodi, child ostaje u zombie stanju, u kom je i dalje naveden, ali ne zauzima resurse.

### PID-ovi

PID-ovi, odnosno identifikatori procesa, identifikuju jedinstven proces. U XNU-u, **PID-ovi** su 64-bitni, monotono rastu i **nikada se ne vraćaju na početak** (kako bi se sprečile zloupotrebe).

### Grupe procesa, sesije i Coalations

**Procesi** mogu biti ubačeni u **grupe** kako bi se njima lakše upravljalo. Na primer, komande u shell skripti biće u istoj grupi procesa, pa ih je moguće **signalizirati zajedno**, na primer korišćenjem funkcije kill.\
Takođe je moguće **grupisati procese u sesije**. Kada proces pokrene sesiju (`setsid(2)`), child procesi se postavljaju unutar te sesije, osim ako ne pokrenu sopstvenu sesiju.

Coalition je još jedan način grupisanja procesa u Darwinu. Proces koji se pridruži coalition-u može da pristupi zajedničkim resursima, deli ledger ili bude obuhvaćen Jetsam-om. Coalations imaju različite uloge: Leader, XPC service, Extension.

### Kredencijali i Personae

Svaki proces poseduje **kredencijale** koji **identifikuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (iako može pripadati većem broju grupa).\
Takođe je moguće promeniti korisnički i grupni ID ako binarni fajl ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** obezbeđuje alternativni skup **kredencijala**. Usvajanje persone podrazumeva istovremeno preuzimanje njenog uid-a, gid-a i članstva u grupama. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:
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

1. **POSIX Threads (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog threading API-ja za C/C++. Implementacija pthreads u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, a potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža neophodne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, što je sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kom je macOS zasnovan). Ovaj sistemski poziv prihvata različite flagove izvedene iz `pthread_attr` (atributa), koji određuju ponašanje niti, uključujući politike raspoređivanja i veličinu steka.
- **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti iznosi 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi pomoću atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` ključna je tokom podešavanja niti i koristi argument `env[]` za parsiranje promenljivih okruženja koje mogu sadržati informacije o lokaciji i veličini steka.

#### Prekid niti u macOS-u

1. **Izlazak iz niti:** Niti se obično prekidaju pozivanjem funkcije `pthread_exit()`. Ova funkcija omogućava niti da se pravilno završi, obavljajući neophodno čišćenje i omogućavajući niti da pošalje povratnu vrednost svim nitima koje čekaju na njen završetak.
2. **Čišćenje niti:** Nakon pozivanja funkcije `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja upravlja uklanjanjem svih povezanih struktura niti. Ona dealocira Mach portove niti (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, syscall koji uklanja strukture na nivou kernela povezane sa niti.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i izbegavanje race conditions, macOS pruža nekoliko primitiva za sinhronizaciju. Oni su ključni u okruženjima sa više niti kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standardni mutex sa memorijskim otiskom od 60 bajtova (56 bajtova za mutex i 4 bajta za signature).
- **Fast Mutex (Signature: 0x4d55545A):** Sličan standardnom mutexu, ali optimizovan za brže operacije; takođe zauzima 60 bajtova.
2. **Condition Variables:**
- Koriste se za čekanje da nastupe određeni uslovi, a veličina im je 44 bajta (40 bajtova plus 4-bajtni signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Konfiguracioni atributi za condition variables, veličine 12 bajtova.
3. **Once Variable (Signature: 0x4f4e4345):**
- Obezbeđuje da se deo inicijalizacionog koda izvrši samo jednom. Njegova veličina je 12 bajtova.
4. **Read-Write Locks:**
- Omogućavaju više čitalaca ili jednog pisca istovremeno, čime se omogućava efikasan pristup deljenim podacima.
- **Read Write Lock (Signature: 0x52574c4b):** Veličine 196 bajtova.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Atributi za read-write locks, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata koriste se za otkrivanje prelivanja.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** u kontekstu Mach-O datoteka (formata za izvršne datoteke u macOS-u) koriste se za deklarisanje promenljivih koje su specifične za **svaku nit** u aplikaciji sa više niti. Ovo obezbeđuje da svaka nit ima sopstvenu odvojenu instancu promenljive, čime se omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije kao što su mutexes.

U C-u i srodnim jezicima, thread-local promenljivu možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ovaj isečak definiše `tlv_var` kao thread-local promenljivu. Svaka nit koja izvršava ovaj kod ima sopstvenu `tlv_var` promenljivu, a izmene koje jedna nit napravi u `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnom fajlu podaci povezani sa thread-local promenljivama organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o thread-local promenljivama, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za thread-local promenljive koje nisu eksplicitno inicijalizovane. Ona predstavlja deo memorije rezervisan za podatke inicijalizovane nulama.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje thread-local promenljivama prilikom završetka niti. Ovaj API omogućava **registrovanje destruktora** — posebnih funkcija koje čiste thread-local podatke kada se nit završi.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva analizu načina na koji operativni sistem odlučuje koje niti treba pokrenuti i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS i Unix-like sistemima to se rešava korišćenjem koncepata kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
- Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima `nice` vrednost u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana `nice` vrednost prilikom kreiranja procesa obično je 0.
- Niža `nice` vrednost (bliža -20) čini proces „sebičnijim“, dajući mu više CPU vremena u odnosu na druge procese sa višim `nice` vrednostima.
2. **Renice:**
- `renice` je komanda koja se koristi za promenu `nice` vrednosti već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, odnosno povećanje ili smanjenje dodeljenog CPU vremena na osnovu novih `nice` vrednosti.
- Na primer, ako je procesu privremeno potrebno više CPU resursa, njegova `nice` vrednost može se smanjiti pomoću `renice`.

#### Quality of Service (QoS) klase

QoS klase predstavljaju moderniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. QoS klase omogućavaju developerima da **kategorizuju** posao u različite nivoe na osnovu njegove važnosti ili hitnosti. macOS automatski upravlja prioritetima niti na osnovu ovih QoS klasa:

1. **User Interactive:**
- Ova klasa namenjena je zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju trenutne rezultate kako bi se obezbedilo dobro korisničko iskustvo. Ovim zadacima se dodeljuje najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
- Zadaci koje korisnik pokrene i za koje očekuje trenutne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva izračunavanja. Imaju visok prioritet, ali niži od klase user interactive.
3. **Utility:**
- Ovi zadaci dugo traju i obično prikazuju indikator napretka (npr. preuzimanje fajlova ili uvoz podataka). Imaju niži prioritet od zadataka koje je pokrenuo korisnik i ne moraju se odmah završiti.
4. **Background:**
- Ova klasa namenjena je zadacima koji rade u pozadini i nisu vidljivi korisniku. To mogu biti indeksiranje, sinhronizacija ili backup. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem QoS klasa, developeri ne moraju da upravljaju preciznim brojevima prioriteta, već mogu da se usredsrede na prirodu zadatka, dok sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje omogućavaju specificiranje skupa parametara raspoređivanja koje će scheduler uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u race condition napadima.

## Zloupotreba macOS procesa

macOS, kao i svaki drugi operativni sistem, pruža različite metode i mehanizme za **interakciju, komunikaciju i deljenje podataka između procesa**. Iako su ove tehnike neophodne za efikasan rad sistema, threat actor-i ih mogu zloupotrebiti za **izvršavanje malicioznih aktivnosti**.

### Library Injection

Library Injection je tehnika u kojoj napadač **primorava proces da učita malicioznu biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, dajući napadaču iste dozvole i pristup kao i sam proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking funkcija napadaču omogućava da **izmeni ponašanje** procesa, posmatra osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) odnosi se na različite metode kojima odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC osnovni deo mnogih legitimnih aplikacija, može se zloupotrebiti za narušavanje izolacije procesa, leak osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije pokrenute sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti flagove `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **man in the browser attack** napada, koji omogućava krađu pritisnutih tastera, saobraćaja i cookies-a, kao i injection skripti u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršavati proizvoljne komande**, a **Gatekeeper neće sprečiti** već pokrenutu aplikaciju da se ponovo izvrši ako je **NIB fajl izmenjen**. Zbog toga se mogu koristiti za pokretanje proizvoljnih programa koji izvršavaju proizvoljne komande:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je zloupotrebiti određene Java mogućnosti (kao što je env promenljiva **`_JAVA_OPTS`**) kako bi Java aplikacija izvršila **proizvoljan kod/komande**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je ubaciti kod u .Net aplikacije **zloupotrebom funkcionalnosti za .Net debugging** (koju ne štite macOS zaštite kao što je runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Proverite različite opcije za navođenje Perl skripte da izvrši proizvoljan kod u:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Takođe je moguće zloupotrebiti Ruby env promenljive kako bi proizvoljne skripte izvršile proizvoljan kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Ako je env promenljiva **`PYTHONINSPECT`** podešena, Python proces će nakon završetka preći u Python CLI. Takođe je moguće koristiti **`PYTHONSTARTUP`** za navođenje Python skripte koja će se izvršiti na početku interaktivne sesije.\
Međutim, imajte na umu da se skripta **`PYTHONSTARTUP`** neće izvršiti kada **`PYTHONINSPECT`** kreira interaktivnu sesiju.

Druge env promenljive, kao što su **`PYTHONPATH`** i **`PYTHONHOME`**, takođe mogu biti korisne za navođenje Python komande da izvrši proizvoljan kod.

Imajte na umu da izvršni fajlovi kompajlirani pomoću **`pyinstaller`** neće koristiti ove environmental promenljive, čak i kada se izvršavaju pomoću embedded Python-a.

> [!CAUTION]
> Sve u svemu, nisam uspeo da pronađem način da navedem Python da izvrši proizvoljan kod zloupotrebom env promenljivih.\
> Međutim, većina ljudi instalira Python pomoću **Hombrew-a**, koji će instalirati Python na **writable lokaciju** za podrazumevanog admin korisnika. Možete ga hijack-ovati nečim poput:
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
> Čak će i **root** izvršiti ovaj kod prilikom pokretanja Python-a.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je open source aplikacija zasnovana na **EndpointSecurity** koja detektuje i blokira process injection. Predstavlja dobru referencu za signale koji su zaista vidljivi iz ES-a, jer generiše upozorenja za:<sup>[[1]](#references)[[2]](#references)</sup>

- **Injection env promenljive** prilikom exec procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u njega.
- **Electron debugging argumente** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u debug režimu i omogućavaju bilo kome da se poveže i izvrši kod u njoj.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza između različitih nivoa privilegija** — klasični primitive „postavi link kao običan korisnik i usmeri ga na privilegovanu lokaciju“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne izlaže odredište linka pre njegovog kreiranja.

### Pozivi drugih procesa

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako je moguće koristiti funkciju **`task_name_for_pid`** za dobijanje informacija o drugim **procesima koji ubacuju kod u proces**, a zatim i informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje ove funkcije morate imati **isti uid** kao proces koji je pokrenut ili biti **root** (funkcija vraća informacije o procesu, ali ne i način za injection koda).

## Reference

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
