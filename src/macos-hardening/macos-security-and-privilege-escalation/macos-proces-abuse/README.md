# Zloupotreba macOS procesa

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog programa koji se izvršava, međutim, procesi ne izvršavaju kôd, već to rade thread-ovi. Zato su **procesi samo kontejneri za thread-ove koji se izvršavaju**, a obezbeđuju memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivanjem funkcije **`fork`**, koja bi kreirala identičnu kopiju trenutnog procesa, nakon čega bi **child process** uglavnom pozvao **`execve`** da učita novi izvršni program i pokrene ga. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao bez kopiranja memorije.\
Nakon toga je uveden **`posix_spawn`**, koji kombinuje **`vfork`** i **`execve`** u jednom pozivu i prihvata flags:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne id-jeve na stvarne id-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost process group-u
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja signal masku
- `POSIX_SPAWN_SETEXEC`: Izvršava u istom procesu (kao `execve`, sa više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće suspendovano
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc-ov Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` nad segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve file description-e prilikom exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizuje visoke bitove ASLR slide-a

Pored toga, `posix_spawn` prihvata podešavanja **`posix_spawnattr`**, koja kontrolišu aspekte pokrenutog procesa, kao i stavke **`posix_spawn_file_actions`**, koje menjaju file descriptor-e.

Kada proces umre, on šalje **return code parent process-u** (ako je parent umro, novi parent je PID 1) pomoću signala `SIGCHLD`. Parent mora da preuzme ovu vrednost pozivanjem `wait4()` ili `waitid()`, a do tada child ostaje u zombie stanju, u kojem je i dalje naveden, ali ne troši resurse.

### PIDs

PIDs, odnosno identifikatori procesa, identifikuju jedinstveni proces. U XNU-u, **PIDs** su veličine **64 bita**, povećavaju se monotono i **nikada se ne vraćaju na početnu vrednost** (kako bi se sprečile zloupotrebe).

### Process Groups, Sessions & Coalations

**Procesi** se mogu ubaciti u **groups** kako bi se njima lakše upravljalo. Na primer, komande u shell script-u biće u istoj process group, pa ih je moguće **signalizirati zajedno**, na primer pomoću kill-a.\
Procesi se takođe mogu **grupisati u sessions**. Kada proces pokrene session (`setsid(2)`), child procesi se smeštaju u tu session, osim ako ne pokrenu sopstvenu session.

Coalition je još jedan način grupisanja procesa u Darwin-u. Pridruživanje procesa coalition-u omogućava mu pristup pool resursima, deljenje ledger-a ili izlaganje Jetsam-u. Coalitions imaju različite uloge: Leader, XPC service, Extension.

### Credentials & Personae

Svaki proces poseduje **credentials** koje **identifikuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (iako može pripadati većem broju grupa).\
Takođe je moguće promeniti user i group id ako binary ima `setuid/setgid` bit.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Syscall **`persona`** obezbeđuje alternativni skup **credentials**. Usvajanje personae podrazumeva istovremeno preuzimanje njenog uid-a, gid-a i članstva u grupama. U [**source code-u**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:
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

1. **POSIX Threads (pthreads):** macOS podržava POSIX thread-ove (`pthreads`), koji su deo standardnog threading API-ja za C/C++. Implementacija pthread-ova u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koja potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža neophodne funkcije za kreiranje i upravljanje thread-ovima.
2. **Kreiranje thread-ova:** Funkcija `pthread_create()` koristi se za kreiranje novih thread-ova. Interno, ova funkcija poziva `bsdthread_create()`, što je system call nižeg nivoa specifičan za XNU kernel (kernel na kojem je macOS zasnovan). Ovaj system call prima različite flag-ove izvedene iz `pthread_attr` (atributa), koji određuju ponašanje thread-a, uključujući scheduling policies i veličinu stack-a.
- **Podrazumevana veličina stack-a:** Podrazumevana veličina stack-a za nove thread-ove iznosi 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi putem atributa thread-a ako je potrebno više ili manje prostora.
3. **Inicijalizacija thread-a:** Funkcija `__pthread_init()` ključna je tokom podešavanja thread-a i koristi argument `env[]` za parsiranje environment varijabli koje mogu sadržati informacije o lokaciji i veličini stack-a.

#### Terminacija thread-ova u macOS-u

1. **Izlazak iz thread-ova:** Thread-ovi se obično terminiraju pozivanjem funkcije `pthread_exit()`. Ova funkcija omogućava thread-u da se pravilno završi, izvršavajući neophodno čišćenje i omogućavajući thread-u da pošalje povratnu vrednost bilo kom thread-u koji ga čeka.
2. **Čišćenje thread-a:** Nakon pozivanja funkcije `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja upravlja uklanjanjem svih povezanih struktura thread-a. Ona dealocira Mach thread port-ove (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, syscall koji uklanja strukture na nivou kernela povezane sa thread-om.

#### Mehanizmi za synchronization

Za upravljanje pristupom shared resursima i sprečavanje race condition-a, macOS pruža nekoliko synchronization primitive-a. One su ključne u multi-threading okruženjima kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
- **Regular Mutex (Signature: 0x4D555458):** Standardni mutex sa memorijskim otiskom od 60 bajtova (56 bajtova za mutex i 4 bajta za signature).
- **Fast Mutex (Signature: 0x4d55545A):** Sličan regularnom mutex-u, ali optimizovan za brže operacije; takođe je veličine 60 bajtova.
2. **Condition Variables:**
- Koriste se za čekanje da se ispune određeni uslovi, a veličine su 44 bajta (40 bajtova plus 4-bajtni signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Konfiguracioni atributi za condition variables, veličine 12 bajtova.
3. **Once Variable (Signature: 0x4f4e4345):**
- Obezbeđuje da se deo initialization koda izvrši samo jednom. Njegova veličina je 12 bajtova.
4. **Read-Write Locks:**
- Omogućavaju više čitalaca ili jednog writer-a istovremeno, čime se omogućava efikasan pristup shared podacima.
- **Read Write Lock (Signature: 0x52574c4b):** Veličine 196 bajtova.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Atributi za read-write lock-ove, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata koriste se za otkrivanje overflow-a.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** u kontekstu Mach-O fajlova (formata za executable fajlove u macOS-u) koriste se za deklarisanje varijabli koje su specifične za **svaki thread** u multi-threaded aplikaciji. Ovo obezbeđuje da svaki thread ima svoju zasebnu instancu varijable, pružajući način za izbegavanje konflikata i održavanje integriteta podataka bez potrebe za eksplicitnim synchronization mehanizmima kao što su mutex-i.

U C-u i srodnim jezicima, thread-local varijablu možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ovaj isečak definiše `tlv_var` kao thread-local promenljivu. Svaka nit koja izvršava ovaj kod ima sopstvenu promenljivu `tlv_var`, a izmene koje jedna nit napravi nad `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnom fajlu podaci povezani sa thread-local promenljivama organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o thread-local promenljivama, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za thread-local promenljive koje nisu eksplicitno inicijalizovane. Ona predstavlja deo memorije rezervisan za podatke inicijalizovane nulom.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje thread-local promenljivama kada se nit završi. Ovaj API omogućava **registrovanje destruktora** — posebnih funkcija koje čiste thread-local podatke kada se nit terminira.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva posmatranje načina na koji operativni sistem odlučuje koje niti će pokretati i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS i Unix-like sistemima ovo se rešava korišćenjem koncepata kao što su `nice`, `renice` i Quality of Service (QoS) klase.

#### Nice i Renice

1. **Nice:**
- Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima `nice` vrednost u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana `nice` vrednost pri kreiranju procesa obično je 0.
- Niža `nice` vrednost (bliža -20) čini proces „sebičnijim“, dajući mu više CPU vremena u poređenju sa drugim procesima koji imaju više `nice` vrednosti.
2. **Renice:**
- `renice` je komanda koja se koristi za promenu `nice` vrednosti već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, odnosno povećanje ili smanjenje dodeljenog CPU vremena na osnovu novih `nice` vrednosti.
- Na primer, ako je procesu privremeno potrebno više CPU resursa, njegova `nice` vrednost može se smanjiti pomoću `renice`.

#### Quality of Service (QoS) klase

QoS klase predstavljaju moderniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. QoS klase omogućavaju developerima da **kategorizuju** posao prema različitim nivoima na osnovu njegove važnosti ili hitnosti. macOS automatski upravlja određivanjem prioriteta niti na osnovu ovih QoS klasa:

1. **User Interactive:**
- Ova klasa je namenjena zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju trenutne rezultate radi dobrog korisničkog iskustva. Ovi zadaci dobijaju najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
- Zadaci koje korisnik pokrene i za koje očekuje trenutne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva izračunavanja. Imaju visok prioritet, ali niži od klase user interactive.
3. **Utility:**
- Ovi zadaci dugo traju i obično prikazuju indikator napretka (npr. preuzimanje fajlova ili uvoz podataka). Imaju niži prioritet od user-initiated zadataka i ne moraju se odmah završiti.
4. **Background:**
- Ova klasa je namenjena zadacima koji rade u pozadini i nisu vidljivi korisniku. To mogu biti indeksiranje, sinhronizacija ili backup. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem QoS klasa, developeri ne moraju da upravljaju tačnim brojevima prioriteta, već se mogu fokusirati na prirodu zadatka, dok sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje omogućavaju specificiranje skupa parametara raspoređivanja koje će scheduler uzeti u obzir. Ovo se može uraditi pomoću `thread_policy_[set/get]`. To može biti korisno u napadima zasnovanim na race condition-u.

## macOS Process Abuse

macOS pruža mnoge mehanizme za **interakciju, komunikaciju i deljenje podataka između procesa**. Iako su ovi mehanizmi neophodni za normalan rad sistema, napadači ih mogu zloupotrebiti za injection, code execution ili pristup podacima.

### Library Injection

Library Injection je tehnika kojom napadač **primorava proces da učita malicioznu biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, dajući napadaču iste dozvole i pristup koje ima taj proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking funkcija napadaču omogućava da **izmeni ponašanje** procesa, posmatra osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) odnosi se na različite metode kojima odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC osnova mnogih legitimnih aplikacija, može se zloupotrebiti za zaobilaženje izolacije procesa, leak-ovanje osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije pokrenute sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti flag-ove `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **man in the browser attack** napada, koji omogućava krađu pritisnutih tastera, saobraćaja i cookies-a, kao i injection script-ova u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršavati proizvoljne komande**, a **Gatekeeper ne sprečava** već pokrenutu aplikaciju da se izvrši ako je **NIB fajl izmenjen**. Zato se mogu koristiti za izvršavanje proizvoljnih komandi pomoću proizvoljnih programa:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je ubaciti JVM opcije pomoću **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ili **`JDK_JAVA_OPTIONS`** i učitati Java ili native agent pre pokretanja aplikacije.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** preload-uje attacker JavaScript putem `--require` (fajl) ili `--import data:text/javascript,…` (fileless, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** učitava modul u interaktivni REPL, a **`ELECTRON_RUN_AS_NODE`** ponovo omogućava sve navedeno na Electron binarnim fajlovima.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je ubaciti kod u .NET aplikacije pomoću **`DOTNET_STARTUP_HOOKS`** pre funkcije `Main`, ili zloupotrebom .NET debugging funkcionalnosti kada su ispunjeni njeni preduslovi.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Neinteraktivni Bash čita **`BASH_ENV`**; interaktivni POSIX shell-ovi čitaju **`ENV`**; zsh čita **`$ZDOTDIR/.zshenv`**; a fish čita konfiguraciju ispod **`XDG_CONFIG_HOME`** ili **`XDG_DATA_DIRS`**. Svaki od njih može izvršiti kontrolisani startup fajl pre predviđene komande. Bash takođe izvršava command substitution postavljen u **`PS4`** svaki put kada je xtrace omogućen (npr. nasleđivanjem **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** ili **`PHP_INI_SCAN_DIR`** mogu učitati kontrolisanu PHP konfiguraciju čiji **`auto_prepend_file`** se izvršava pre ciljne skripte.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samostalni Lua interpreter izvršava kod ili `@file` iz promenljive **`LUA_INIT`** (ili njene varijante specifične za verziju) pre obrade ciljne skripte.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** preusmeravaju startup profile koji sadrže R kod. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, zajedno sa putanjom R biblioteke, mogu umesto toga automatski učitati instalirani paket.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** preusmerava depot čiji se `config/startup.jl` automatski izvršava.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ili **`ERL_ZFLAGS`** mogu ubaciti Erlang VM **`-eval`** izraz bez potrebe za payload fajlom; Elixir workload-i obično pokreću isti VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** preusmeravaju Octave startup skripte.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` je cross-platform .NET aplikacija, pa nekoliko env promenljivih omogućava izvršavanje pre komande: **`XDG_CONFIG_HOME`** preusmerava profile skripte koje se pokreću pri startup-u, **`PSModulePath`** omogućava hijacking automatskog učitavanja modula (postavljeni `.psm1` se izvršava pri import-u i može sakriti ugrađene cmdlet-e), a .NET promenljive **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** učitavaju attacker kod u proces pre funkcije `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Proverite različite opcije pomoću kojih Perl skripta može izvršiti proizvoljan kod u:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Moguće je i zloupotrebiti Ruby env promenljive (**`RUBYOPT`**, **`RUBYLIB`**) kako bi proizvoljne skripte izvršile proizvoljan kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Standard-library chain **`PYTHONWARNINGS`** i **`BROWSER`** može izvršiti komandu tokom parsiranja warning filter-a. Alternativa zasnovana na fajlu postavlja `sitecustomize.py` na **`PYTHONPATH`**, tako da ga normalna `site` inicijalizacija importuje pre ciljne skripte. **`PYTHONBREAKPOINT`** pokreće izabrani callable/module kada kod dođe do `breakpoint()`. Interaktivne promenljive kao što je **`PYTHONSTARTUP`** imaju užu primenljivost.

Imajte na umu da izvršni fajlovi kompajlirani pomoću **`pyinstaller`** neće koristiti ove env promenljive čak i kada rade koristeći embedded Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (i njegov `EXINIT` fallback) izvršavaju se kao Ex komande pri normalnom startup-u, pa `:!cmd` / `:call system(...)` omogućavaju code execution kada žrtva otvori Vim/Neovim sa kontrolisanim okruženjem:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Odvojeno od toga, Homebrew često instalira Python ispod `/opt/homebrew`, gde članovi lokalne `admin` grupe možda mogu da zamene launcher. To je hijacking writable binary fajla, a ne injection putem env promenljive; proverite vlasništvo i ACL-ove pre nego što ga smatrate exploitable.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je open-source aplikacija zasnovana na **EndpointSecurity** koja detektuje i blokira process injection. Predstavlja dobru referencu za signale koji su vidljivi kroz Endpoint Security, jer upozorava na:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection env promenljive** pri exec-u procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** pozive — jedan proces traži task port drugog procesa, što je preduslov za injection u njega.
- **Electron debugging argumente** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u debug modu i omogućavaju bilo kome da se poveže i izvršava kod u njoj.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza između nivoa privilegija** — klasični primitive „postavi link kao normalan korisnik i usmeri ga na privilegovanu lokaciju“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne izlaže odredište linka pre njegovog kreiranja.

### Pozivi koje izvršavaju drugi procesi

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako je moguće koristiti funkciju **`task_name_for_pid`** za dobijanje informacija o drugim **procesima koji ubacuju kod u proces**, a zatim i informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje ove funkcije morate imati **isti uid** kao proces koji je pokrenuo proces ili morate biti **root** (funkcija vraća informacije o procesu, a ne način za ubacivanje koda).

## References

- [1] [Shield — open-source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Zašto Electron aplikacije ne mogu poverljivo čuvati vaše secrets: --inspect opcija](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detektovanje izmena task-a](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
