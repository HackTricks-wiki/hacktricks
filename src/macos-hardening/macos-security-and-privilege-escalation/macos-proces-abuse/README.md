# Zloupotreba procesa u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog fajla koji se pokreće, ali procesi ne izvršavaju kod — to rade niti. Zato su **procesi samo kontejneri za pokrenute niti** koji obezbeđuju memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivom **`fork`**, koji bi stvorio tačnu kopiju trenutnog procesa, a zatim bi **podređeni proces** obično pozvao **`execve`** da učita novi izvršni fajl i pokrene ga. Zatim je uveden **`vfork`** da bi se ovaj proces ubrzao bez kopiranja memorije.\
Potom je uveden **`posix_spawn`**, koji objedinjuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetovanje efektivnih ID-jeva na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavljanje pripadnosti grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavljanje podrazumevanog ponašanja signala
- `POSIX_SPAWN_SETSIGMASK`: Postavljanje maske signala
- `POSIX_SPAWN_SETEXEC`: Izvršavanje u istom procesu (kao `execve`, uz više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokretanje u suspendovanom stanju
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokretanje bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Korišćenje libmalloc-ovog Nano alokatora
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljavanje `rwx` prava nad segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvaranje svih opisa fajlova pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumična promena viših bitova ASLR pomeraja

Pored toga, `posix_spawn` prihvata podešavanja **`posix_spawnattr`** koja kontrolišu aspekte pokrenutog procesa i stavke **`posix_spawn_file_actions`** koje menjaju deskriptore fajlova.

Kada proces prestane da radi, šalje **povratni kod nadređenom procesu** (ako je nadređeni proces prestao da radi, novi nadređeni proces je PID 1) signalom `SIGCHLD`. Nadređeni proces mora da preuzme ovu vrednost pozivom `wait4()` ili `waitid()`, a do tada podređeni proces ostaje u zombi stanju — i dalje je naveden, ali ne troši resurse.

### PID-ovi

PID-ovi, odnosno identifikatori procesa, identifikuju jedinstven proces. U XNU-u **PID-ovi** su **64-bitni**, monotono rastu i **nikada se ne prelivaju** (da bi se izbegle zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** se mogu organizovati u **grupe** radi lakšeg upravljanja. Na primer, komande u shell skripti biće u istoj grupi procesa, pa ih je moguće **signalizirati zajedno**, na primer pomoću kill.\
Procesi se takođe mogu **organizovati u sesije**. Kada proces pokrene sesiju (`setsid(2)`), njegovi podređeni procesi smeštaju se u tu sesiju, osim ako ne pokrenu sopstvenu sesiju.

Koalicija je još jedan način grupisanja procesa u Darwinu. Proces koji se pridruži koaliciji može da pristupi zajedničkim resursima, deli knjigu evidencije ili bude podvrgnut usluzi Jetsam. Koalicije imaju različite uloge: Leader, XPC service, Extension.

### Kredencijali i persone

Svaki proces poseduje **kredencijale** koji **određuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (mada može da pripada većem broju grupa).\
Korisnički i grupni ID mogu se promeniti i ako izvršni fajl ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih UID-jeva/GID-jeva**.

Sistemski poziv **`persona`** pruža **alternativni** skup **kredencijala**. Usvajanjem persone istovremeno se preuzimaju njen UID, GID i članstva u grupama. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) može se pronaći struktura:

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

1. **POSIX niti (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za niti u C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koja potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka obezbeđuje neophodne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kom se macOS zasniva). Ovaj sistemski poziv prima različite zastavice izvedene iz `pthread_attr` (atributa), koje određuju ponašanje niti, uključujući pravila raspoređivanja i veličinu steka.
   - **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi pomoću atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` ključna je tokom podešavanja niti. Ona koristi argument `env[]` za obradu promenljivih okruženja, koje mogu da sadrže detalje o lokaciji i veličini steka.

#### Završavanje niti u macOS-u

1. **Izlazak iz niti:** Niti se obično završavaju pozivanjem funkcije `pthread_exit()`. Ova funkcija omogućava niti da se uredno završi, obavi neophodno čišćenje i pošalje povratnu vrednost nitima koje čekaju na njen završetak.
2. **Čišćenje niti:** Nakon poziva funkcije `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture niti. Ona oslobađa Mach portove niti (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture na nivou kernela povezane sa niti.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i sprečavanje race condition-a, macOS obezbeđuje nekoliko primitiva za sinhronizaciju. One su ključne u okruženjima sa više niti kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
   - **Običan mutex (potpis: 0x4D555458):** Standardni mutex sa memorijskim otiskom od 60 bajtova (56 bajtova za mutex i 4 bajta za potpis).
   - **Brzi mutex (potpis: 0x4d55545A):** Sličan običnom mutex-u, ali optimizovan za brže operacije; takođe zauzima 60 bajtova.
2. **Uslovne promenljive:**
   - Koriste se za čekanje da se ispune određeni uslovi i zauzimaju 44 bajta (40 bajtova plus potpis od 4 bajta).
   - **Atributi uslovne promenljive (potpis: 0x434e4441):** Konfiguracioni atributi za uslovne promenljive, veličine 12 bajtova.
3. **Promenljiva Once (potpis: 0x4f4e4345):**
   - Obezbeđuje da se deo inicijalizacionog koda izvrši samo jednom. Zauzima 12 bajtova.
4. **Read-write locks:**
   - Omogućavaju istovremeni pristup većem broju čitalaca ili jednom piscu, čime se omogućava efikasan pristup deljenim podacima.
   - **Read-write lock (potpis: 0x52574c4b):** Zauzima 196 bajtova.
   - **Atributi read-write lock-a (potpis: 0x52574c41):** Atributi za read-write lock-ove, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta tih objekata koriste se za otkrivanje prekoračenja.

### Lokalne promenljive niti (TLV)

**Lokalne promenljive niti (TLV)** u kontekstu Mach-O fajlova (formata izvršnih fajlova u macOS-u) koriste se za deklarisanje promenljivih specifičnih za **svaku nit** u aplikaciji sa više niti. Time se obezbeđuje da svaka nit ima sopstvenu zasebnu instancu promenljive, što omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije, kao što su mutex-i.

U C-u i srodnim jezicima možete deklarisati lokalnu promenljivu niti pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ovaj isečak definiše `tlv_var` kao promenljivu lokalnu za nit. Svaka nit koja izvršava ovaj kod imaće sopstvenu promenljivu `tlv_var`, a izmene koje jedna nit napravi u svojoj promenljivoj `tlv_var` neće uticati na promenljivu `tlv_var` u drugoj niti.

U Mach-O binarnom fajlu, podaci povezani sa promenljivama lokalnim za nit organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o promenljivama lokalnim za nit, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za promenljive lokalne za nit koje nisu eksplicitno inicijalizovane. Ona je deo memorije rezervisan za podatke inicijalizovane nulom.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje promenljivama lokalnim za nit pri završetku niti. Ovaj API omogućava da **registrujete destruktore** — posebne funkcije koje čiste podatke lokalne za nit kada se nit završi.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva razmatranje načina na koji operativni sistem odlučuje koje niti će se izvršavati i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS-u i sistemima sličnim Unix-u, za to se koriste koncepti kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima vrednost `nice` u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana vrednost `nice` pri kreiranju procesa obično je 0.
   - Niža vrednost `nice` (bliža -20) čini proces „sebičnijim“, dajući mu više CPU vremena u odnosu na druge procese sa višim vrednostima `nice`.
2. **Renice:**
   - `renice` je komanda koja se koristi za promenu vrednosti `nice` već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, povećavajući ili smanjujući dodeljeno CPU vreme na osnovu novih vrednosti `nice`.
   - Na primer, ako procesu privremeno treba više CPU resursa, možete sniziti njegovu vrednost `nice` pomoću komande `renice`.

#### Klase Quality of Service (QoS)

Klase QoS predstavljaju moderniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. Klase QoS omogućavaju programerima da **kategorizuju** zadatke u različite nivoe na osnovu njihove važnosti ili hitnosti. macOS automatski upravlja prioritetima niti na osnovu ovih klasa QoS:

1. **User Interactive:**
   - Ova klasa namenjena je zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju trenutne rezultate radi dobrog korisničkog iskustva. Ovi zadaci dobijaju najviši prioritet kako bi interfejs ostao odzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
   - Zadaci koje korisnik pokreće i za koje očekuje trenutne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva računanje. Ovi zadaci imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
   - Ovi zadaci traju duže i obično prikazuju indikator napretka (npr. preuzimanje fajlova ili uvoz podataka). Imaju niži prioritet od zadataka koje je pokrenuo korisnik i ne moraju odmah da se završe.
4. **Background:**
   - Ova klasa namenjena je zadacima koji se izvršavaju u pozadini i nisu vidljivi korisniku. To mogu biti zadaci poput indeksiranja, sinhronizacije ili pravljenja rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem klasa QoS, programeri ne moraju da upravljaju konkretnim brojevima prioriteta, već mogu da se fokusiraju na prirodu zadatka, a sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje određuju skup parametara za raspoređivanje koje će planer uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u napadima zasnovanim na race condition.

## Zloupotreba macOS procesa

macOS pruža brojne mehanizme koji omogućavaju **procesima da međusobno komuniciraju i dele podatke**. Iako su ovi mehanizmi neophodni za uobičajen rad sistema, napadači ih mogu zloupotrebiti za injection, izvršavanje koda ili pristup podacima.

### Library Injection

Library Injection je tehnika kojom napadač **primorava proces da učita zlonamernu biblioteku**. Nakon ubacivanja, biblioteka se izvršava u kontekstu ciljnog procesa, dajući napadaču iste dozvole i pristup kao i samom procesu.


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

Ova stranica obrađuje ARM64 unwind metapodatke, ograničenja PAC-a za arm64e i sintetičke lance poziva.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) obuhvata različite načine na koje odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC ključan za mnoge legitimne aplikacije, može se zloupotrebiti i za zaobilaženje izolacije procesa, leak osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije pokrenute sa određenim promenljivama okruženja mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Za izvođenje **man in the browser napada** moguće je upotrebiti zastavice `--load-extension` i `--use-fake-ui-for-media-stream`, što omogućava krađu pritisaka na tastere, saobraćaja i kolačića, kao i ubacivanje skripti u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršavati proizvoljne komande**, a **Gatekeeper ne sprečava** ponovno pokretanje već pokrenute aplikacije ako je **NIB fajl izmenjen**. Zato se mogu koristiti za pokretanje proizvoljnih komandi u proizvoljnim programima:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je ubaciti JVM opcije pomoću **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ili **`JDK_JAVA_OPTIONS`** i učitati Java ili nativni agent pre pokretanja aplikacije.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** unapred učitava JavaScript napadača pomoću `--require` (fajl) ili `--import data:text/javascript,…` (bez fajla, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** učitava modul u interaktivni REPL, a **`ELECTRON_RUN_AS_NODE`** ponovo omogućava sve ovo u Electron binarnim fajlovima.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je ubaciti kod u .NET aplikacije pomoću **`DOTNET_STARTUP_HOOKS`** pre funkcije `Main` ili zloupotrebom .NET funkcionalnosti za otklanjanje grešaka kada su ispunjeni preduslovi.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Neinteraktivni Bash čita **`BASH_ENV`**; interaktivne POSIX ljuske čitaju **`ENV`**; zsh čita **`$ZDOTDIR/.zshenv`**; a fish čita konfiguraciju ispod **`XDG_CONFIG_HOME`** ili **`XDG_DATA_DIRS`**. Svaka od njih može da izvrši kontrolisani startup fajl pre predviđene komande. Bash takođe izvršava zamenu komande postavljenu u **`PS4`** svaki put kada je xtrace omogućen (npr. nasleđeni **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Ubacivanje komandi kroz stdin ljuske

Pokretanje `/bin/zsh -s` nalaže ljusci da čita program sa standardnog ulaza. Zato downloader koji kopira nepouzdani strukturirani dokument u stdin svog procesa-podređenog bez prethodnog parsiranja pretvara ceo dokument u izvorni kod ljuske. Jedan uočeni loader prosleđivao je javni iCalendar fajl liniju po liniju kroz anonimni pipe. Metapodaci kalendara nisu bili validne komande, ali je zsh nastavio sa izvršavanjem sve dok nije naišao na izvršive linije postavljene posle `DESCRIPTION:`. Te linije su preuzele i pokrenule sledeći application bundle. Očekivani tip sadržaja i pouzdan hosting nisu učinili ovaj postupak bezbednim; opasna granica nastala je prosleđivanjem njegovih bajtova interpreteru.<sup>[[5]](#references)</sup>

Povezane faze obrađene su u člancima [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper i quarantine](../macos-security-protections/macos-gatekeeper.md) i [macOS lokacije za automatsko pokretanje](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ili **`PHP_INI_SCAN_DIR`** mogu učitati kontrolisanu PHP konfiguraciju čiji **`auto_prepend_file`** izvršava kod pre ciljne skripte.

[PHP konfiguracija i injection pri pokretanju preko `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Samostalni Lua interpreter izvršava kod ili `@file` iz **`LUA_INIT`** (ili njegove verzijski specifične varijante) pre obrade ciljne skripte.

[Lua injection pri pokretanju preko `LUA_INIT` (fajl i inline kod)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** preusmeravaju na startup profile koji sadrže R kod. Umesto toga, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, zajedno sa putanjom do R biblioteke, mogu automatski da učitaju instalirani paket.

[R startup profili i učitavanje paketa](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** preusmerava na depot čiji se `config/startup.jl` automatski izvršava.

[Julia injection preko `JULIA_DEPOT_PATH` i `startup.jl`](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ili **`ERL_ZFLAGS`** mogu ubaciti Erlang VM izraz **`-eval`** bez potrebe za payload fajlom; Elixir workload-ovi često pokreću isti VM.

[Ubacivanje Erlang/Elixir VM zastavica](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** preusmeravaju na Octave startup skripte.

[Ubacivanje GNU Octave startup fajlova](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` je multiplatformska .NET aplikacija, pa nekoliko promenljivih okruženja omogućava izvršavanje pre komande: **`XDG_CONFIG_HOME`** preusmerava na profile koji se izvršavaju pri pokretanju, **`PSModulePath`** omogućava otmicu automatskog učitavanja modula (postavljeni `.psm1` se izvršava pri uvozu i može da zaseni ugrađene cmdlet-e), a .NET promenljive **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** učitavaju kod napadača u proces pre funkcije `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Proverite različite opcije pomoću kojih Perl skripta može da izvrši proizvoljan kod:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Moguće je zloupotrebiti i Ruby promenljive okruženja (**`RUBYOPT`**, **`RUBYLIB`**) kako bi proizvoljne skripte izvršavale proizvoljan kod:


[Opcije Ruby loader-a `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Lanac **`PYTHONWARNINGS`** i **`BROWSER`** iz standardne biblioteke može da izvrši komandu tokom parsiranja filtera upozorenja. Alternativa koja koristi fajl postavlja `sitecustomize.py` na **`PYTHONPATH`**, tako da ga uobičajena inicijalizacija `site` uveze pre ciljne skripte. **`PYTHONBREAKPOINT`** pokreće izabranu callable funkciju/modul kada kod stigne do `breakpoint()`.

Na CPython 3.13 i novijim verzijama, **`PYTHONINSPECT`** može da pokrene i fajl **`PYTHONSTARTUP`** nakon skripte, kada se njegov PyREPL pokrene u terminalu.<sup>[[6]](#references)</sup>

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** neće koristiti ove promenljive okruženja, čak ni kada se izvršavaju pomoću ugrađenog Python-a.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (i njegova zamena `EXINIT`) izvršavaju se kao Ex komande pri uobičajenom pokretanju, pa `:!cmd` / `:call system(...)` omogućavaju izvršavanje koda kada žrtva pokrene Vim/Neovim u kontrolisanom okruženju:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Odvojeno od toga, Homebrew često instalira Python ispod `/opt/homebrew`, gde članovi lokalne grupe `admin` mogu da zamene launcher. To je otmica upisivog binarnog fajla, a ne injection preko promenljive okruženja; pre nego što to smatrate iskoristivim, proverite vlasništvo i ACL-ove.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je aplikacija otvorenog koda zasnovana na **EndpointSecurity** koja detektuje i blokira process injection. Predstavlja dobar primer signala koji se mogu uočiti pomoću Endpoint Security-ja, jer upozorava na sledeće:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection promenljive okruženja** pri pokretanju procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- **Pozive `task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u taj proces.
- **Electron argumente za otklanjanje grešaka** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u režimu za otklanjanje grešaka i omogućavaju bilo kome da se poveže na nju i izvršava kod u njoj.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza preko nivoa privilegija** — klasičan postupak „postavi vezu kao običan korisnik, a zatim je usmeri na privilegovanu lokaciju“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne otkriva odredište veze pre njenog kreiranja.

### Pozivi drugih procesa

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako se funkcija **`task_name_for_pid`** može upotrebiti za dobijanje informacija o drugim **procesima koji ubacuju kod u proces**, a zatim i za dobijanje informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje ove funkcije morate imati **isti uid** kao proces ili biti **root** (a ona vraća informacije o procesu, ne omogućava injection koda).



## References

- [1] [Shield — detekcija ubacivanja u macOS procese otvorenog koda (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — Zašto Electron aplikacije ne mogu poverljivo da čuvaju vaše tajne: opcija --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — Detektovanje izmena taskova](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist — Nova verzija macOS kradljivca MacSync cilja ljubitelje kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
- [6] [Python komandna linija i okruženje — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
