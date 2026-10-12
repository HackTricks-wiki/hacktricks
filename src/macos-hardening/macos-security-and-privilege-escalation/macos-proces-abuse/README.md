# Zloupotreba macOS procesa

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog fajla koji se pokreće, ali procesi ne izvršavaju kod — to rade niti. Zato su **procesi samo kontejneri za niti koje se izvršavaju** i obezbeđuju im memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivom funkcije **`fork`**, koja bi napravila tačnu kopiju trenutnog procesa, a zatim bi **podređeni proces** obično pozvao **`execve`** da učita novi izvršni fajl i pokrene ga. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao bez kopiranja memorije.\
Potom je uveden **`posix_spawn`**, koji objedinjuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
- `POSIX_SPAWN_SETEXEC`: Izvršava u istom procesu (poput `execve`, uz više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće obustavljen proces
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc-ov Nano alokator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` nad segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve opise fajlova pri pozivu exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično određuje visoke bitove ASLR pomeraja

Pored toga, `posix_spawn` prihvata podešavanja **`posix_spawnattr`** koja kontrolišu aspekte pokrenutog procesa, kao i stavke **`posix_spawn_file_actions`** koje menjaju deskriptore fajlova.

Kada proces završi, šalje **povratni kod roditeljskom procesu** (ako je roditelj završio, novi roditelj je PID 1) pomoću signala `SIGCHLD`. Roditelj mora da preuzme ovu vrednost pozivom funkcije `wait4()` ili `waitid()`. Do tada podređeni proces ostaje u zombi stanju: i dalje se prikazuje na listi, ali ne troši resurse.

### PID-jevi

PID-jevi (identifikatori procesa) identifikuju jedinstven proces. U XNU-u su **PID-jevi** dugi **64 bita**, rastu monotono i **nikada se ne vraćaju na početnu vrednost** (kako bi se sprečile zloupotrebe).

### Grupe procesa, sesije i Coalition-i

**Procesi** mogu biti raspoređeni u **grupe** kako bi se njima lakše upravljalo. Na primer, komande u shell skripti pripadaju istoj grupi procesa, pa ih je moguće **signalizirati zajedno**, na primer pomoću komande kill.\
Moguće je i **grupisati procese u sesije**. Kada proces pokrene sesiju (`setsid(2)`), podređeni procesi se smeštaju u tu sesiju, osim ako ne pokrenu sopstvenu sesiju.

Coalition je još jedan način grupisanja procesa u Darwinu. Proces koji se pridruži Coalition-u može da pristupi zajedničkim resursima, deli ledger ili bude podložan mehanizmu Jetsam. Coalition-i imaju različite uloge: Leader, XPC service, Extension.

### Akreditivi i Personae

Svaki proces poseduje **akreditive** koji **određuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (mada može pripadati većem broju grupa).\
Moguće je i promeniti ID korisnika i grupe ako binarni fajl ima bit `setuid/setgid`.\
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

1. **POSIX Threads (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za rad sa nitima u C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib` i potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža potrebne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kom je zasnovan macOS). Ovaj sistemski poziv prima različite zastavice izvedene iz `pthread_attr` (atributa), koje određuju ponašanje niti, uključujući pravila raspoređivanja i veličinu steka.
   - **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB. To je dovoljno za uobičajene operacije, ali se može prilagoditi pomoću atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` ključna je tokom podešavanja niti; koristi argument `env[]` za obradu promenljivih okruženja koje mogu sadržati podatke o lokaciji i veličini steka.

#### Završetak niti u macOS-u

1. **Izlazak iz niti:** Niti se obično završavaju pozivom funkcije `pthread_exit()`. Ona omogućava niti da se uredno završi, obavi neophodno čišćenje i vrati povratnu vrednost nitima koje čekaju njen završetak.
2. **Čišćenje niti:** Kada se pozove `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture niti. Ona oslobađa Mach portove niti (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture niti na nivou kernela.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i sprečavanje race condition-a, macOS pruža nekoliko primitiva za sinhronizaciju. One su ključne u okruženjima sa više niti kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
   - **Običan mutex (potpis: 0x4D555458):** Standardni mutex, veličine 60 bajtova (56 bajtova za mutex i 4 bajta za potpis).
   - **Brzi mutex (potpis: 0x4d55545A):** Sličan običnom mutex-u, ali optimizovan za brži rad; takođe je veličine 60 bajtova.
2. **Uslovne promenljive:**
   - Koriste se za čekanje da se ispune određeni uslovi; veličine su 44 bajta (40 bajtova plus potpis od 4 bajta).
   - **Atributi uslovnih promenljivih (potpis: 0x434e4441):** Atributi za podešavanje uslovnih promenljivih, veličine 12 bajtova.
3. **Once promenljiva (potpis: 0x4f4e4345):**
   - Obezbeđuje da se deo inicijalizacionog koda izvrši samo jednom. Veličine je 12 bajtova.
4. **Read-Write Locks:**
   - Omogućavaju više čitalaca ili jednog pisca istovremeno, čime se omogućava efikasan pristup deljenim podacima.
   - **Read Write Lock (potpis: 0x52574c4b):** Veličine 196 bajtova.
   - **Atributi za Read Write Lock (potpis: 0x52574c41):** Atributi za read-write locks, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta tih objekata koriste se za otkrivanje prekoračenja.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** se u kontekstu Mach-O datoteka (formata izvršnih datoteka u macOS-u) koriste za deklarisanje promenljivih specifičnih za **svaku nit** u aplikaciji sa više niti. Tako svaka nit dobija sopstvenu instancu promenljive, što omogućava izbegavanje sukoba i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije kao što su mutex-i.

U jeziku C i srodnim jezicima, promenljivu lokalnu za nit možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ovaj isečak definiše `tlv_var` kao thread-local promenljivu. Svaka nit koja izvršava ovaj kod imaće sopstvenu promenljivu `tlv_var`, a izmene koje jedna nit napravi u svojoj promenljivoj `tlv_var` neće uticati na promenljivu `tlv_var` u drugoj niti.

U Mach-O binarnom fajlu, podaci povezani sa thread-local promenljivama organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o thread-local promenljivama, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za thread-local promenljive koje nisu eksplicitno inicijalizovane. To je deo memorije rezervisan za podatke inicijalizovane nulom.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje thread-local promenljivama kada se nit završi. Ovaj API omogućava da se **registruju destruktori** — posebne funkcije koje čiste thread-local podatke kada se nit završi.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva razmatranje načina na koji operativni sistem odlučuje koje će niti pokretati i kada. Na tu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS-u i sistemima sličnim Unix-u, za to se koriste koncepti kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima vrednost `nice` u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana vrednost `nice` pri kreiranju procesa obično je 0.
   - Niža vrednost `nice` (bliža -20) čini proces „sebičnijim“ i daje mu više CPU vremena u poređenju sa drugim procesima sa višim vrednostima `nice`.
2. **Renice:**
   - `renice` je komanda koja se koristi za promenu vrednosti `nice` već pokrenutog procesa. Njome se prioritet procesa može dinamički prilagoditi, povećavajući ili smanjujući dodeljeno CPU vreme u skladu sa novim vrednostima `nice`.
   - Na primer, ako je procesu privremeno potrebno više CPU resursa, možete mu smanjiti vrednost `nice` pomoću komande `renice`.

#### Klase Quality of Service (QoS)

Klase QoS predstavljaju savremeniji pristup upravljanju prioritetima niti, naročito u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. Klase QoS omogućavaju programerima da **kategorizuju** zadatke u različite nivoe prema njihovoj važnosti ili hitnosti. macOS automatski upravlja prioritetima niti na osnovu ovih klasa QoS:

1. **User Interactive:**
   - Ova klasa je namenjena zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju neposredne rezultate radi dobrog korisničkog iskustva. Ovi zadaci dobijaju najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
   - Zadaci koje korisnik pokreće i za koje očekuje neposredne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje pokreće izračunavanja. Imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
   - Ovi zadaci dugo traju i obično prikazuju indikator napretka (npr. preuzimanje datoteka, uvoz podataka). Imaju niži prioritet od zadataka koje pokreće korisnik i ne moraju odmah da se završe.
4. **Background:**
   - Ova klasa je namenjena zadacima koji se izvršavaju u pozadini i nisu vidljivi korisniku. To mogu biti zadaci kao što su indeksiranje, sinhronizacija ili pravljenje rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem klasa QoS, programeri ne moraju da upravljaju tačnim vrednostima prioriteta, već mogu da se usredsrede na prirodu zadatka, dok sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje omogućavaju definisanje skupa parametara raspoređivanja koje će planer uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u napadima zasnovanim na race condition.

## Zloupotreba macOS procesa

macOS pruža brojne mehanizme koji omogućavaju **procesima da međusobno komuniciraju i dele podatke**. Iako su ovi mehanizmi neophodni za uobičajeni rad sistema, napadači mogu da ih zloupotrebe za injection, izvršavanje koda ili pristup podacima.

### Library Injection

Library Injection je tehnika kojom napadač **primorava proces da učita zlonamernu biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, čime napadač dobija ista ovlašćenja i pristup kao taj proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking-om funkcija napadač može da **izmeni ponašanje** procesa, nadgleda osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ova stranica obrađuje ARM64 unwind metapodatke, arm64e PAC ograničenja i sintetičke lance poziva.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) označava različite načine na koje odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC ključan za mnoge legitimne aplikacije, može se zloupotrebiti za narušavanje izolacije procesa, leak osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije pokrenute sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti zastavice `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje napada **man in the browser**, koji omogućava krađu pritisaka na tastere, saobraćaja i kolačića, kao i injection skripti u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB datoteke **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije u okviru aplikacije. Međutim, mogu da **izvršavaju proizvoljne komande**, a **Gatekeeper ne sprečava** ponovno pokretanje već pokrenute aplikacije ako je **NIB datoteka izmenjena**. Zato se mogu koristiti za pokretanje proizvoljnih komandi iz proizvoljnih programa:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je ubaciti JVM opcije pomoću **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ili **`JDK_JAVA_OPTIONS`** i učitati Java ili native agent pre pokretanja aplikacije.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** unapred učitava JavaScript napadača putem `--require` (datoteka) ili `--import data:text/javascript,…` (bez datoteke, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** učitava modul u interaktivni REPL, a **`ELECTRON_RUN_AS_NODE`** ponovo omogućava sve ovo u Electron binarnim fajlovima.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je ubaciti kod u .NET aplikacije pomoću **`DOTNET_STARTUP_HOOKS`** pre funkcije `Main` ili zloupotrebom .NET funkcionalnosti za otklanjanje grešaka kada su ispunjeni neophodni preduslovi.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Neinteraktivni Bash čita **`BASH_ENV`**; interaktivne POSIX ljuske čitaju **`ENV`**; zsh čita **`$ZDOTDIR/.zshenv`**; a fish čita konfiguraciju iz **`XDG_CONFIG_HOME`** ili **`XDG_DATA_DIRS`**. Svaka od njih može da izvrši kontrolisanu startup datoteku pre predviđene komande. Bash takođe izvršava zamenu komande postavljenu u **`PS4`** svaki put kada je xtrace omogućen (npr. nasleđenom vrednošću **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** ili **`PHP_INI_SCAN_DIR`** mogu da učitaju kontrolisanu PHP konfiguraciju čiji **`auto_prepend_file`** izvršava kod pre ciljne skripte.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samostalni Lua interpreter izvršava kod ili datoteku navedenu pomoću `@file` iz promenljive **`LUA_INIT`** (ili njene verzijski specifične varijante) pre obrade ciljne skripte.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** preusmeravaju na startup profile koji sadrže R kod. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** i putanja do R biblioteke mogu umesto toga automatski da učitaju instalirani paket.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** preusmerava na depot čija se datoteka `config/startup.jl` automatski izvršava.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ili **`ERL_ZFLAGS`** mogu da ubace Erlang VM izraz **`-eval`** bez potrebe za datotekom sa payload-om; Elixir radna opterećenja obično pokreću istu VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** preusmeravaju na startup skripte za Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` je višeplatformska .NET aplikacija, pa nekoliko env promenljivih omogućava izvršavanje pre komande: **`XDG_CONFIG_HOME`** preusmerava na profile skripte koje se pokreću pri pokretanju; **`PSModulePath`** omogućava hijacking automatskog učitavanja modula (postavljena `.psm1` datoteka izvršava se pri uvozu i može da zameni ugrađene cmdlet-ove); a .NET promenljive **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** učitavaju kod napadača u proces pre funkcije `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Pogledajte razne opcije pomoću kojih Perl skripta može da izvršava proizvoljan kod u:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Moguće je i zloupotrebiti Ruby env promenljive (**`RUBYOPT`**, **`RUBYLIB`**) da bi proizvoljne skripte izvršavale proizvoljan kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Lanac standardnih biblioteka **`PYTHONWARNINGS`** i **`BROWSER`** može da izvrši komandu tokom parsiranja filtera upozorenja. Alternativa koja koristi datoteku postavlja `sitecustomize.py` na putanju **`PYTHONPATH`**, tako da je standardna inicijalizacija `site` uveze pre ciljne skripte. **`PYTHONBREAKPOINT`** pokreće izabranu funkciju/modul kada kod dođe do `breakpoint()`. Promenljive koje važe samo za interaktivni režim, kao što je **`PYTHONSTARTUP`**, imaju užu primenu.

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** neće koristiti ove env promenljive, čak ni kada se pokreću sa ugrađenim Python-om.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (i njegova rezervna opcija `EXINIT`) izvršavaju se kao Ex komande pri uobičajenom pokretanju, pa `:!cmd` / `:call system(...)` omogućavaju izvršavanje koda kada žrtva otvori Vim/Neovim u kontrolisanom okruženju:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Odvojeno od toga, Homebrew obično instalira Python ispod putanje `/opt/homebrew`, gde članovi lokalne grupe `admin` možda mogu da zamene pokretač. To je hijacking upisive binarne datoteke, a ne injection putem env promenljivih; proverite vlasništvo i ACL-ove pre nego što to smatrate iskoristivim.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je aplikacija otvorenog koda zasnovana na **EndpointSecurity** koja otkriva i blokira process injection. Dobar je primer signala koji su vidljivi kroz Endpoint Security, jer upozorava na:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection env promenljive** pri izvršavanju procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u njega.
- **Electron argumente za otklanjanje grešaka** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u režimu za otklanjanje grešaka i omogućavaju bilo kome da se poveže s njom i izvršava kod.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza između različitih nivoa privilegija** — klasičnu primitivu „postavi vezu kao običan korisnik i usmeri je na privilegovanu lokaciju“. Imajte na umu da se na **symlink veze može upozoriti, ali se ne mogu blokirati**: EndpointSecurity ne otkriva odredište veze pre njenog kreiranja.

### Pozivi drugih procesa

U [**ovoj objavi na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete saznati kako se funkcija **`task_name_for_pid`** može koristiti za dobijanje informacija o drugim **procesima koji ubacuju kod u neki proces**, a zatim i za dobijanje informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje te funkcije morate imati **isti uid** kao proces ili biti **root** (funkcija vraća informacije o procesu, a ne omogućava injection koda).

## References

- [1] [Shield — otkrivanje process injection-a u macOS-u pomoću softvera otvorenog koda (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity okvir](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — Zašto Electron aplikacije ne mogu poverljivo da čuvaju vaše tajne: opcija --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — Otkrivanje izmena task-ova](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
