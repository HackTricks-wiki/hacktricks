# Zloupotreba procesa u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršne datoteke koja je pokrenuta, ali procesi ne izvršavaju kod — to rade niti. Zato su **procesi samo kontejneri za niti koje se izvršavaju**, a obezbeđuju im memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivom **`fork`**, koji bi napravio tačnu kopiju trenutnog procesa, a zatim bi **podređeni proces** uglavnom pozvao **`execve`** da učita novu izvršnu datoteku i pokrene je. Zatim je uveden **`vfork`** kako bi se ovaj postupak ubrzao bez kopiranja memorije.\
Potom je uveden **`posix_spawn`**, koji objedinjuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Poništi efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavi pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavi podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavi masku signala
- `POSIX_SPAWN_SETEXEC`: Izvrši u istom procesu (kao `execve`, ali sa više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreni obustavljen
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreni bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc Nano alokator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoli `rwx` na segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvori sve opise datoteka pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično odredi više bitove ASLR pomeraja

Pored toga, `posix_spawn` prihvata podešavanja **`posix_spawnattr`**, koja kontrolišu aspekte pokrenutog procesa, i stavke **`posix_spawn_file_actions`**, koje menjaju deskriptore datoteka.

Kada proces završi, šalje **povratni kod nadređenom procesu** (ako je nadređeni proces završio, novi nadređeni proces je PID 1) signalom `SIGCHLD`. Nadređeni proces mora da preuzme ovu vrednost pozivom funkcije `wait4()` ili `waitid()`. Do tada, podređeni proces ostaje u zombi stanju: i dalje je na listi, ali ne troši resurse.

### PID-jevi

PID-jevi, odnosno identifikatori procesa, identifikuju jedinstven proces. U XNU-u, **PID-jevi** su **64-bitni**, monotono se povećavaju i **nikada se ne vraćaju na početak** (kako bi se sprečile zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** mogu da se grupišu radi lakšeg upravljanja. Na primer, komande u skripti ljuske pripadaju istoj grupi procesa, pa ih je moguće **signalizirati zajedno**, na primer pomoću komande kill.\
Procesi se mogu grupisati i **u sesije**. Kada proces pokrene sesiju (`setsid(2)`), podređeni procesi se smeštaju u tu sesiju, osim ako ne pokrenu sopstvenu sesiju.

Koalicija je još jedan način grupisanja procesa u Darwinu. Kada se proces pridruži koaliciji, može da pristupi zajedničkim resursima, deli knjigu evidencije ili bude podložan sistemu Jetsam. Koalicije imaju različite uloge: vođa, XPC usluga, proširenje.

### Akreditivi i persone

Svaki proces poseduje **akreditive** koji **određuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (mada može da pripada većem broju grupa).\
Moguće je promeniti i korisnički i grupni ID ako izvršna datoteka ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** obezbeđuje alternativni skup **akreditiva**. Usvajanjem persone preuzimaju se njen uid, gid i članstva u grupama **istovremeno**. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:

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

1. **POSIX niti (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za rad sa nitima u C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koji potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža potrebne funkcije za kreiranje niti i upravljanje njima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kojem je zasnovan macOS). Ovaj sistemski poziv prima različite zastavice izvedene iz `pthread_attr` (atributa), koje određuju ponašanje niti, uključujući pravila raspoređivanja i veličinu steka.
   - **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB, što je dovoljno za tipične operacije, ali se može podesiti pomoću atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` ključna je tokom podešavanja niti; koristi argument `env[]` za obradu promenljivih okruženja koje mogu sadržati detalje o lokaciji i veličini steka.

#### Završetak niti u macOS-u

1. **Izlazak iz niti:** Niti se obično završavaju pozivom funkcije `pthread_exit()`. Ova funkcija omogućava niti da se uredno završi, obavi potrebno čišćenje i vrati vrednost nitima koje čekaju na njen završetak.
2. **Čišćenje niti:** Nakon poziva funkcije `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture niti. Ona oslobađa Mach portove niti (Mach je podsistem za komunikaciju u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture niti na nivou kernela.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i sprečavanje race condition-a, macOS pruža nekoliko primitiva za sinhronizaciju. One su ključne u okruženjima sa više niti kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
   - **Regularni mutex (potpis: 0x4D555458):** Standardni mutex, zauzima 60 bajtova memorije (56 bajtova za mutex i 4 bajta za potpis).
   - **Brzi mutex (potpis: 0x4d55545A):** Sličan je regularnom mutex-u, ali je optimizovan za brže operacije; takođe zauzima 60 bajtova.
2. **Uslovne promenljive:**
   - Koriste se za čekanje da se ispune određeni uslovi; zauzimaju 44 bajta (40 bajtova plus potpis od 4 bajta).
   - **Atributi uslovnih promenljivih (potpis: 0x434e4441):** Atributi za podešavanje uslovnih promenljivih, zauzimaju 12 bajtova.
3. **Once promenljiva (potpis: 0x4f4e4345):**
   - Obezbeđuje da se određeni kod za inicijalizaciju izvrši samo jednom. Zauzima 12 bajtova.
4. **Brave za čitanje i upisivanje:**
   - Omogućavaju više čitalaca ili jednog upisivača istovremeno, čime se olakšava efikasan pristup deljenim podacima.
   - **Brava za čitanje i upisivanje (potpis: 0x52574c4b):** Zauzima 196 bajtova.
   - **Atributi brave za čitanje i upisivanje (potpis: 0x52574c41):** Atributi za brave za čitanje i upisivanje; zauzimaju 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata koriste se za otkrivanje prekoračenja.

### Lokalne promenljive niti (TLV)

**Lokalne promenljive niti (TLV)** u kontekstu Mach-O datoteka (format izvršnih datoteka u macOS-u) koriste se za deklarisanje promenljivih koje su specifične za **svaku nit** u aplikaciji sa više niti. Time se obezbeđuje da svaka nit ima sopstvenu zasebnu instancu promenljive, što omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije kao što su mutex-i.

U jeziku C i srodnim jezicima, lokalnu promenljivu niti možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ovaj isečak definiše `tlv_var` kao promenljivu lokalnu za nit. Svaka nit koja izvršava ovaj kod imaće sopstvenu promenljivu `tlv_var`, a izmene koje jedna nit napravi u promenljivoj `tlv_var` neće uticati na promenljivu `tlv_var` u drugoj niti.

U Mach-O binarnoj datoteci, podaci povezani sa promenljivama lokalnim za nit organizovani su u određene odeljke:

- **`__DATA.__thread_vars`**: Ovaj odeljak sadrži metapodatke o promenljivama lokalnim za nit, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ovaj odeljak koristi se za promenljive lokalne za nit koje nisu eksplicitno inicijalizovane. To je deo memorije namenjen podacima inicijalizovanim nulom.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje promenljivama lokalnim za nit kada se nit završi. Ovaj API omogućava da **registrujete destruktore** — posebne funkcije koje čiste podatke lokalne za nit kada se nit prekine.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva razmatranje načina na koji operativni sistem odlučuje koje niti će pokretati i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS-u i sistemima sličnim Unixu, za to se koriste koncepti kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima vrednost `nice` u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana vrednost `nice` pri kreiranju procesa obično je 0.
   - Niža vrednost `nice` (bliža vrednosti -20) čini proces „sebičnijim“, dajući mu više CPU vremena u poređenju s drugim procesima koji imaju više vrednosti `nice`.
2. **Renice:**
   - `renice` je komanda koja se koristi za promenu vrednosti `nice` već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, odnosno za povećanje ili smanjenje dodeljenog CPU vremena u zavisnosti od novih vrednosti `nice`.
   - Na primer, ako procesu privremeno treba više CPU resursa, možete smanjiti njegovu vrednost `nice` pomoću komande `renice`.

#### Klase Quality of Service (QoS)

Klase QoS predstavljaju savremeniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržava **Grand Central Dispatch (GCD)**. Klase QoS omogućavaju programerima da **kategorizuju** zadatke prema njihovoj važnosti ili hitnosti. macOS automatski upravlja prioritetima niti na osnovu ovih klasa QoS:

1. **User Interactive:**
   - Ova klasa namenjena je zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju neposredne rezultate radi dobrog korisničkog iskustva. Ovi zadaci imaju najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
   - Zadaci koje pokreće korisnik i za koje očekuje neposredne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva proračune. Imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
   - Ovi zadaci traju duže i obično prikazuju indikator napretka (npr. preuzimanje datoteka, uvoz podataka). Imaju niži prioritet od zadataka koje pokreće korisnik i ne moraju odmah da se završe.
4. **Background:**
   - Ova klasa namenjena je zadacima koji se izvršavaju u pozadini i nisu vidljivi korisniku. To mogu biti zadaci poput indeksiranja, sinhronizacije ili pravljenja rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Koristeći klase QoS, programeri ne moraju da upravljaju konkretnim brojevima prioriteta, već mogu da se usredsrede na prirodu zadatka, dok sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje omogućavaju navođenje skupa parametara raspoređivanja koje će raspoređivač uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u napadima zasnovanim na uslovima trke.

## Zloupotreba procesa u macOS-u

macOS pruža brojne mehanizme pomoću kojih **procesi mogu da međusobno komuniciraju i dele podatke**. Iako su ovi mehanizmi neophodni za uobičajen rad sistema, napadači mogu da ih zloupotrebe za injection, izvršavanje koda ili pristup podacima.

### Library Injection

Library Injection je tehnika kojom napadač **primorava proces da učita zlonamernu biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, čime napadač dobija iste dozvole i pristup kao taj proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking funkcija napadaču omogućava da **izmeni ponašanje** procesa, nadgleda osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ova stranica obrađuje ARM64 metapodatke za unwind, ograničenja PAC-a u arm64e i sintetičke lance poziva.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) obuhvata različite metode pomoću kojih odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC ključan za mnoge legitimne aplikacije, može se i zloupotrebiti za narušavanje izolacije procesa, otkrivanje osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije pokrenute sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Za izvođenje **man in the browser attack** napada koji omogućava krađu pritisaka na tastere, saobraćaja i kolačića, kao i injection skripti u stranice, moguće je koristiti zastavice `--load-extension` i `--use-fake-ui-for-media-stream`:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB datoteke **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, mogu da **izvršavaju proizvoljne komande**, a **Gatekeeper ne sprečava** ponovno izvršavanje već pokrenute aplikacije ako se **NIB datoteka izmeni**. Zato se mogu koristiti za pokretanje proizvoljnih komandi iz proizvoljnih programa:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je injection-om ubaciti JVM opcije pomoću **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ili **`JDK_JAVA_OPTIONS`** i učitati Java ili native agent pre pokretanja aplikacije.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** unapred učitava JavaScript napadača preko opcije `--require` (datoteka) ili `--import data:text/javascript,…` (bez datoteke, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** učitava modul u interaktivni REPL, a **`ELECTRON_RUN_AS_NODE`** ponovo omogućava sve ovo u Electron binarnim datotekama.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je injection-om ubaciti kod u .NET aplikacije pomoću **`DOTNET_STARTUP_HOOKS`** pre funkcije `Main`, ili zloupotrebom .NET funkcionalnosti za debagovanje kada su ispunjeni preduslovi.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Neinteraktivni Bash čita **`BASH_ENV`**; interaktivne POSIX ljuske čitaju **`ENV`**; zsh čita **`$ZDOTDIR/.zshenv`**; a fish čita konfiguraciju ispod **`XDG_CONFIG_HOME`** ili **`XDG_DATA_DIRS`**. Svaka od njih može da izvrši kontrolisanu startup datoteku pre predviđene komande. Bash takođe izvršava command substitution postavljen u **`PS4`** svaki put kada je xtrace omogućen (npr. preko nasleđene vrednosti **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Pokretanjem `/bin/zsh -s` shell čita program sa standardnog ulaza. Zato downloader koji kopira nepouzdan strukturirani dokument u stdin child procesa, a da ga prethodno ne parsira, pretvara ceo dokument u izvorni kod shell-a. Jedan uočeni loader prosleđivao je javno dostupnu iCalendar datoteku kroz anonimni pipe, red po red. Metapodaci kalendara nisu bili ispravne komande, ali zsh je nastavio sa izvršavanjem dok nije naišao na izvršive redove postavljene posle `DESCRIPTION:`. Ti redovi su preuzimali i pokretali sledeći application bundle. Očekivani tip sadržaja i pouzdani hosting nisu učinili ovaj postupak bezbednim; opasnost je nastala prosleđivanjem bajtova interpreteru.<sup>[[5]](#references)</sup>

Povezane faze obrađene su u odeljcima [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) i [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ili **`PHP_INI_SCAN_DIR`** mogu da učitaju kontrolisanu PHP konfiguraciju čiji **`auto_prepend_file`** izvršava kod pre ciljne skripte.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Samostalni Lua interpreter izvršava kod ili `@file` iz **`LUA_INIT`** (ili njegove verzijski specifične varijante) pre obrade ciljne skripte.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** preusmeravaju na startup profile koji sadrže R kod. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** uz putanju do R biblioteke mogu umesto toga automatski da učitaju instalirani paket.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** preusmerava na depot čija se datoteka `config/startup.jl` automatski izvršava.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ili **`ERL_ZFLAGS`** mogu da injection-om ubace Erlang VM izraz **`-eval`** bez potrebe za payload datotekom; Elixir workloads obično pokreću istu VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** preusmeravaju na Octave startup skripte.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` je višeplatformska .NET aplikacija, pa nekoliko env promenljivih omogućava izvršavanje pre komande: **`XDG_CONFIG_HOME`** preusmerava na profile skripti koje se pokreću pri startup-u, **`PSModulePath`** omogućava hijacking automatskog učitavanja modula (postavljena `.psm1` datoteka izvršava se pri uvozu i može da zameni ugrađene cmdlet-e), a .NET promenljive **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** učitavaju kod napadača u proces pre funkcije `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Pogledajte različite opcije pomoću kojih Perl skripta može da izvršava proizvoljan kod u:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Moguće je i zloupotrebiti ruby env promenljive (**`RUBYOPT`**, **`RUBYLIB`**) kako bi proizvoljne skripte izvršavale proizvoljan kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Lanac **`PYTHONWARNINGS`** i **`BROWSER`** iz standardne biblioteke može da izvrši komandu tokom parsiranja filtera upozorenja. Alternativa zasnovana na datoteci postavlja `sitecustomize.py` u **`PYTHONPATH`**, tako da ga uobičajena `site` inicijalizacija uveze pre ciljne skripte. **`PYTHONBREAKPOINT`** pokreće izabrani callable/modul kada kod dođe do `breakpoint()`. Promenljive namenjene isključivo interaktivnoj upotrebi, kao što je **`PYTHONSTARTUP`**, imaju užu primenu.

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** neće koristiti ove env promenljive, čak ni kada se izvršavaju pomoću ugrađenog Python-a.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (i njegova zamena `EXINIT`) izvršavaju se kao Ex komande pri uobičajenom pokretanju, pa `:!cmd` / `:call system(...)` omogućavaju izvršavanje koda kada žrtva otvori Vim/Neovim sa kontrolisanim okruženjem:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Odvojeno od toga, Homebrew obično instalira Python ispod `/opt/homebrew`, gde članovi lokalne grupe `admin` možda mogu da zamene launcher. To je hijacking binarne datoteke koja se može pisati, a ne injection preko env promenljive; pre nego što to smatrate iskoristivim, proverite vlasništvo i ACL-ove.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je aplikacija otvorenog koda zasnovana na **EndpointSecurity** koja otkriva i blokira process injection. Dobar je primer signala koji su vidljivi preko Endpoint Security-ja, jer upozorava na sledeće:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection env promenljive** pri izvršavanju procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u taj proces.
- **Electron debugging argumente** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u režimu debagovanja i omogućavaju bilo kome da se poveže s njom i izvršava kod u njoj.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza između nivoa privilegija** — klasičan postupak „postavi vezu kao običan korisnik i usmeri je ka privilegovanoj lokaciji“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne izlaže odredište veze pre njenog kreiranja.

### Pozivi drugih procesa

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći opis upotrebe funkcije **`task_name_for_pid`** za dobijanje informacija o drugim **procesima koji injection-om ubacuju kod u proces**, a zatim i informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje te funkcije morate imati **isti uid** kao proces ili biti **root** (ona vraća informacije o procesu, ali ne pruža način za injection koda).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — detekcija process injection-a u macOS-u otvorenog koda (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Zašto Electron aplikacije ne mogu da čuvaju vaše tajne kao poverljive: opcija --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Otkrivanje izmena task-ova](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Nova verzija MacSync macOS stealera cilja entuzijaste kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
