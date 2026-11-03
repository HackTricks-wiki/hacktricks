# Zloupotreba procesa u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršne datoteke koja se pokreće, ali procesi ne izvršavaju kod — to rade thread-ovi. Dakle, **procesi su samo kontejneri za pokrenute thread-ove** koji obezbeđuju memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivom funkcije **`fork`**, koja bi napravila tačnu kopiju trenutnog procesa, a zatim bi **child process** uglavnom pozvao **`execve`** da učita novu izvršnu datoteku i pokrene je. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao bez kopiranja memorije.\
Potom je uveden **`posix_spawn`**, koji objedinjuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
- `POSIX_SPAWN_SETEXEC`: Izvršava program u istom procesu (kao `execve`, ali sa više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće proces u suspendovanom stanju
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće proces bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc-ov Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` na segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve deskriptore datoteka pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično menja više bitove ASLR pomeraja

Pored toga, `posix_spawn` prihvata podešavanja **`posix_spawnattr`**, koja kontrolišu aspekte pokrenutog procesa, kao i stavke **`posix_spawn_file_actions`**, koje menjaju deskriptore datoteka.

Kada proces završi, šalje **povratni kod roditeljskom procesu** (ako je roditeljski proces završio, novi roditelj je PID 1) signalom `SIGCHLD`. Roditeljski proces mora da preuzme ovu vrednost pozivom funkcije `wait4()` ili `waitid()`. Dok se to ne dogodi, child ostaje u zombi stanju: i dalje se prikazuje na listi, ali ne troši resurse.

### PID-ovi

PID-ovi, odnosno identifikatori procesa, identifikuju jedinstven proces. U XNU-u, **PID-ovi** su dugački **64 bita**, monotono se uvećavaju i **nikada se ne vraćaju na početak** (kako bi se sprečile zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** mogu da se organizuju u **grupe** kako bi se njima lakše upravljalo. Na primer, komande u shell skripti pripadaju istoj grupi procesa, pa je moguće **slati im signal zajedno**, na primer pomoću komande kill.\
Procesi mogu da se **organizuju i u sesije**. Kada proces pokrene sesiju (`setsid(2)`), njegovi child procesi se pridružuju toj sesiji, osim ako sami ne pokrenu sopstvenu sesiju.

Koalicija je još jedan način grupisanja procesa u Darwinu. Kada se proces pridruži koaliciji, može da pristupa zajedničkim resursima, deli ledger ili bude podložan mehanizmu Jetsam. Koalicije imaju različite uloge: Leader, XPC service, Extension.

### Akreditivi i personae

Svaki proces poseduje **akreditive** koji **određuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (mada može da pripada većem broju grupa).\
Takođe je moguće promeniti korisnički i grupni ID ako binarna datoteka ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** obezbeđuje alternativni skup **akreditiva**. Usvajanjem persone istovremeno se preuzimaju njen uid, gid i članstva u grupama. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) može se pronaći struktura:

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

1. **POSIX Threads (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za niti u C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib` i potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža potrebne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kojem je zasnovan macOS). Ovaj sistemski poziv prima različite oznake izvedene iz `pthread_attr` (atributa), koje određuju ponašanje niti, uključujući pravila raspoređivanja i veličinu steka.
   - **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi pomoću atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` je ključna tokom podešavanja niti; koristi argument `env[]` za analizu promenljivih okruženja koje mogu sadržati detalje o lokaciji i veličini steka.

#### Završavanje niti u macOS-u

1. **Izlazak iz niti:** Niti se obično završavaju pozivom funkcije `pthread_exit()`. Ova funkcija omogućava niti da se čisto završi, obavi potrebno čišćenje i prosledi povratnu vrednost nitima koje je čekaju.
2. **Čišćenje niti:** Pozivom funkcije `pthread_exit()` poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture niti. Ona oslobađa Mach portove niti (Mach je podsistem za komunikaciju u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture niti na nivou kernela.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i sprečavanje race condition-a, macOS pruža nekoliko primitiva za sinhronizaciju. One su ključne u okruženjima sa više niti kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
   - **Običan mutex (potpis: 0x4D555458):** Standardni mutex memorijskog otiska od 60 bajtova (56 bajtova za mutex i 4 bajta za potpis).
   - **Brzi mutex (potpis: 0x4d55545A):** Sličan običnom mutex-u, ali optimizovan za brže operacije; takođe je veličine 60 bajtova.
2. **Uslovne promenljive:**
   - Koriste se za čekanje da nastupe određeni uslovi; veličine su 44 bajta (40 bajtova plus potpis od 4 bajta).
   - **Atributi uslovnih promenljivih (potpis: 0x434e4441):** Atributi za podešavanje uslovnih promenljivih, veličine 12 bajtova.
3. **Once promenljiva (potpis: 0x4f4e4345):**
   - Obezbeđuje da se deo inicijalizacionog koda izvrši samo jednom. Veličine je 12 bajtova.
4. **Read-Write Locks:**
   - Omogućavaju više čitalaca ili jednog pisca istovremeno, čime se omogućava efikasan pristup deljenim podacima.
   - **Read Write Lock (potpis: 0x52574c4b):** Veličine je 196 bajtova.
   - **Atributi Read Write Lock-a (potpis: 0x52574c41):** Atributi za read-write lock-ove, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata koriste se za otkrivanje prekoračenja.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** se u kontekstu Mach-O datoteka (format izvršnih datoteka u macOS-u) koriste za deklarisanje promenljivih koje su specifične za **svaku nit** u aplikaciji sa više niti. Time se obezbeđuje da svaka nit ima zasebnu instancu promenljive, što omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije kao što su mutex-i.

U C-u i srodnim jezicima možete deklarisati lokalnu promenljivu niti pomoću ključne reči **`__thread`**. Ovako to funkcioniše u vašem primeru:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ovaj isečak definiše `tlv_var` kao thread-local promenljivu. Svaka nit koja izvršava ovaj kod imaće sopstvenu promenljivu `tlv_var`, a izmene koje jedna nit napravi u svojoj promenljivoj `tlv_var` neće uticati na promenljivu `tlv_var` u drugim nitima.

U Mach-O binarnoj datoteci, podaci povezani sa thread-local promenljivama organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o thread-local promenljivama, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za thread-local promenljive koje nisu izričito inicijalizovane. To je deo memorije rezervisan za podatke inicijalizovane nulom.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje thread-local promenljivama pri izlasku niti. Ovaj API omogućava **registrovanje destruktora** — posebnih funkcija koje čiste thread-local podatke kada se nit završi.

### Prioriteti niti

Da bismo razumeli prioritete niti, treba da pogledamo kako operativni sistem odlučuje koje će niti pokrenuti i kada. Na tu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS-u i sistemima sličnim Unixu, za to se koriste koncepti kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima vrednost `nice` u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana vrednost `nice` pri kreiranju procesa obično je 0.
   - Niža vrednost `nice` (bliža -20) čini proces „sebičnijim“, pa mu dodeljuje više CPU vremena u poređenju sa procesima čije su vrednosti `nice` veće.
2. **Renice:**
   - `renice` je komanda koja se koristi za promenu vrednosti `nice` već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, povećavanjem ili smanjivanjem dodeljenog CPU vremena u skladu sa novim vrednostima `nice`.
   - Na primer, ako je procesu privremeno potrebno više CPU resursa, vrednost `nice` možete smanjiti pomoću `renice`.

#### Klase Quality of Service (QoS)

Klase QoS predstavljaju savremeniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. Klase QoS omogućavaju programerima da **kategorizuju** posao prema različitim nivoima važnosti ili hitnosti. macOS automatski upravlja prioritetima niti na osnovu tih klasa QoS:

1. **User Interactive:**
   - Ova klasa namenjena je zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju neposredne rezultate radi dobrog korisničkog iskustva. Tim zadacima dodeljuje se najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
   - Zadaci koje korisnik pokreće i za koje očekuje neposredne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva proračune. Imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
   - Ovi zadaci traju duže i obično prikazuju indikator napretka (npr. preuzimanje datoteka ili uvoz podataka). Imaju niži prioritet od zadataka koje je pokrenuo korisnik i ne moraju odmah da se završe.
4. **Background:**
   - Ova klasa namenjena je zadacima koji se izvršavaju u pozadini i nisu vidljivi korisniku. To mogu biti zadaci poput indeksiranja, sinhronizacije ili pravljenja rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem klasa QoS, programeri ne moraju da upravljaju konkretnim vrednostima prioriteta, već mogu da se usredsrede na prirodu zadatka, dok sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje tokovima omogućavaju da navedu skup parametara raspoređivanja koje će raspoređivač uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u napadima zasnovanim na race condition.

## Zloupotreba macOS procesa

macOS pruža brojne mehanizme koji omogućavaju **procesima da međusobno komuniciraju i dele podatke**. Iako su ti mehanizmi neophodni za uobičajen rad sistema, napadači mogu da ih zloupotrebe za injection, izvršavanje koda ili pristup podacima.

### Library Injection

Library Injection je tehnika kojom napadač **primorava proces da učita zlonamernu biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, pa napadač dobija iste dozvole i pristup kao taj proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking funkcija omogućava napadaču da **izmeni ponašanje** procesa, nadgleda osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ova stranica obrađuje ARM64 unwind metapodatke, arm64e PAC ograničenja i sintetičke lance poziva.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) obuhvata različite metode kojima odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC ključan za mnoge legitimne aplikacije, može se zloupotrebiti i za zaobilaženje izolacije procesa, leak osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection u Electron aplikacije

Electron aplikacije pokrenute sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti zastavice `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **man in the browser napada**, čime se mogu ukrasti pritisci tastera, saobraćaj i kolačići, ubacivati skripte na stranice i slično:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB datoteke **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije u okviru aplikacije. Međutim, mogu i da **izvršavaju proizvoljne komande**, a **Gatekeeper ne sprečava** ponovno izvršavanje već pokrenute aplikacije ako je **NIB datoteka izmenjena**. Zato bi se mogle koristiti za pokretanje proizvoljnih komandi iz proizvoljnih programa:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection u Java aplikacije

Moguće je ubaciti JVM opcije pomoću **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ili **`JDK_JAVA_OPTIONS`** i učitati Java ili nativnog agenta pre pokretanja aplikacije.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** unapred učitava napadačev JavaScript preko `--require` (datoteka) ili `--import data:text/javascript,…` (bez datoteke, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** učitava modul u interaktivni REPL, a **`ELECTRON_RUN_AS_NODE`** ponovo omogućava sve ovo na Electron binarnim datotekama.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection u .Net aplikacije

Moguće je ubaciti kod u .NET aplikacije pomoću **`DOTNET_STARTUP_HOOKS`** pre funkcije `Main` ili zloupotrebom funkcionalnosti za otklanjanje grešaka u .NET-u kada su ispunjeni neophodni preduslovi.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Neinteraktivni Bash čita **`BASH_ENV`**; interaktivne POSIX ljuske čitaju **`ENV`**; zsh čita **`$ZDOTDIR/.zshenv`**; a fish čita konfiguraciju iz **`XDG_CONFIG_HOME`** ili **`XDG_DATA_DIRS`**. Svaka od njih može da izvrši kontrolisanu startup datoteku pre predviđene komande. Bash takođe izvršava zamenu komande smeštenu u **`PS4`** svaki put kada je xtrace omogućen (npr. nasleđenim **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Ubacivanje komandi preko standardnog ulaza ljuske

Pokretanje komande `/bin/zsh -s` navodi ljusku da čita program sa standardnog ulaza. Zato downloader koji kopira nepouzdan strukturirani dokument u standardni ulaz podređenog procesa, a da ga prethodno ne parsira, pretvara ceo dokument u izvorni kod ljuske. Jedan zabeleženi loader prosleđivao je javnu iCalendar datoteku kroz anonimni pipe, red po red. Metapodaci kalendara nisu mogli da se izvrše kao komande, ali je zsh nastavio sa čitanjem dok nije naišao na izvršive redove postavljene nakon `DESCRIPTION:`. Ti redovi su preuzeli i pokrenuli sledeći application bundle. Očekivani tip sadržaja i pouzdani hosting nisu činili ovo bezbednim; opasnost je nastala prosleđivanjem bajtova interpreteru.<sup>[[5]](#references)</sup>

Povezane faze obrađene su u odeljcima [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) i [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ili **`PHP_INI_SCAN_DIR`** mogu da učitaju kontrolisanu PHP konfiguraciju čiji **`auto_prepend_file`** izvršava kod pre ciljne skripte.

[PHP konfiguracija i injection pri pokretanju preko `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Samostalni Lua interpreter izvršava kod ili datoteku `@file` iz **`LUA_INIT`** (ili njegove varijante specifične za verziju) pre obrade ciljne skripte.

[Lua `LUA_INIT` injection pri pokretanju (datoteka i umetnuti kod)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** preusmeravaju na startup profile koji sadrže R kod. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** u kombinaciji sa putanjom R biblioteke mogu umesto toga automatski da učitaju instalirani paket.

[R startup profili i učitavanje paketa](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** preusmerava na depot čija se datoteka `config/startup.jl` automatski izvršava.

[Julia injection preko `JULIA_DEPOT_PATH` i `startup.jl`](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang i Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ili **`ERL_ZFLAGS`** mogu da ubace Erlang VM izraz **`-eval`** bez potrebe za payload datotekom; Elixir workload-i obično pokreću isti VM.

[Erlang/Elixir injection preko VM zastavica](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** preusmeravaju na Octave startup skripte.

[Injection preko GNU Octave startup datoteka](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` je .NET aplikacija koja radi na više platformi, pa nekoliko env promenljivih omogućava izvršavanje pre komande: **`XDG_CONFIG_HOME`** preusmerava na profile skripte koje se pokreću pri pokretanju, **`PSModulePath`** otima automatsko učitavanje modula (postavljeni `.psm1` se pokreće pri uvozu i može da zaseni ugrađene cmdlet-e), a .NET promenljive **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** učitavaju napadačev kod u proces pre funkcije `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Proverite različite opcije za navođenje Perl skripte da izvrši proizvoljan kod u:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Moguće je i zloupotrebiti Ruby env promenljive (**`RUBYOPT`**, **`RUBYLIB`**) kako bi se proizvoljne skripte navele da izvrše proizvoljan kod:


[Opcije Ruby loader-a `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Lanac **`PYTHONWARNINGS`** i standardne biblioteke **`BROWSER`** može da izvrši komandu tokom parsiranja filtera upozorenja. Alternativno, datoteka `sitecustomize.py` može se postaviti na **`PYTHONPATH`**, pa će je uobičajena inicijalizacija `site` uvesti pre ciljne skripte. **`PYTHONBREAKPOINT`** pokreće izabranu funkciju ili modul kada kod dođe do `breakpoint()`. Promenljive namenjene samo interaktivnom režimu, kao što je **`PYTHONSTARTUP`**, imaju užu primenu.

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** ne koriste ove env promenljive, čak ni kada se izvršavaju pomoću ugrađenog Python interpretera.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (i njegova rezervna opcija `EXINIT`) izvršavaju se kao Ex komande pri uobičajenom pokretanju, pa `:!cmd` / `:call system(...)` omogućavaju izvršavanje koda kada žrtva otvori Vim/Neovim u kontrolisanom okruženju:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Odvojeno od toga, Homebrew često instalira Python ispod `/opt/homebrew`, gde članovi lokalne grupe `admin` možda mogu da zamene launcher. To je otmica binarne datoteke sa mogućnošću upisa, a ne injection preko env promenljivih; proverite vlasništvo i ACL-ove pre nego što je smatrate ranjivošću.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je aplikacija otvorenog koda zasnovana na **EndpointSecurity** koja detektuje i blokira process injection. Dobar je izvor za razumevanje signala vidljivih preko Endpoint Security-ja, jer upozorava na:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Env promenljive za injection** pri izvršavanju procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u taj proces.
- **Electron argumente za otklanjanje grešaka** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u režimu za otklanjanje grešaka i omogućavaju bilo kome da se poveže na nju i izvršava kod u njoj.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza između nivoa privilegija** — klasičnu primitivu „postavi vezu kao običan korisnik, pa je usmeri ka privilegovanoj lokaciji“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne otkriva odredište veze pre njenog kreiranja.

### Pozivi drugih procesa

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete saznati kako se funkcija **`task_name_for_pid`** može koristiti za dobijanje informacija o drugim **procesima koji ubacuju kod u proces**, a zatim i informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za poziv ove funkcije morate imati **isti uid** kao proces ili biti **root** (funkcija vraća informacije o procesu, a ne način za injection koda).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — detekcija macOS process injection-a otvorenog koda (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Zašto Electron aplikacije ne mogu poverljivo da čuvaju vaše tajne: opcija --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detektovanje izmena task-a](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Nova verzija MacSync macOS kradljivca cilja ljubitelje kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
