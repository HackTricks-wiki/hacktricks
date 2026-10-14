# Zloupotreba procesa u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog fajla koji se izvršava, ali procesi ne izvršavaju kod — to rade niti. Zato su **procesi samo kontejneri za niti koje se izvršavaju** i obezbeđuju im memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivanjem funkcije **`fork`**, koja bi napravila tačnu kopiju trenutnog procesa, a zatim bi **podređeni proces** obično pozvao **`execve`** da učita novi izvršni fajl i pokrene ga. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao izbegavanjem kopiranja memorije.\
Potom je uveden **`posix_spawn`**, koji objedinjuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
- `POSIX_SPAWN_SETEXEC`: Izvršava u istom procesu (kao `execve`, uz više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće suspendovan proces
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi Nano alokator iz libmalloc-a
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` nad segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve opise fajlova pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično menja visoke bitove ASLR pomeraja

Pored toga, `posix_spawn` prihvata postavke **`posix_spawnattr`**, koje kontrolišu aspekte pokrenutog procesa, kao i stavke **`posix_spawn_file_actions`**, koje menjaju deskriptore fajlova.

Kada proces završi, šalje **povratni kod roditeljskom procesu** (ako je roditeljski proces završio, novi roditelj je PID 1) pomoću signala `SIGCHLD`. Roditelj treba da preuzme ovu vrednost pozivom funkcije `wait4()` ili `waitid()`. Do tada podređeni proces ostaje u stanju zombija — i dalje je naveden, ali ne troši resurse.

### PID-jevi

PID-jevi, odnosno identifikatori procesa, identifikuju jedinstven proces. U XNU-u **PID-jevi** su **64-bitni**, monotono rastu i **nikada se ne prelivaju** (kako bi se sprečile zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** mogu da se organizuju u **grupe** kako bi se njima lakše upravljalo. Na primer, komande u shell skripti pripadaće istoj grupi procesa, pa je moguće **poslati im signal istovremeno**, na primer pomoću komande kill.\
Moguće je i **grupisati procese u sesije**. Kada proces pokrene sesiju (`setsid(2)`), njegovi podređeni procesi pripadaju toj sesiji, osim ako ne pokrenu sopstvenu sesiju.

Koalicija je još jedan način grupisanja procesa u Darwinu. Proces koji se pridruži koaliciji može da pristupi zajedničkim resursima pool-a, deli ledger ili bude podložan sistemu Jetsam. Koalicije imaju različite uloge: vođa, XPC servis, ekstenzija.

### Akreditivi i personae

Svaki proces poseduje **akreditive** koji **određuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (mada može pripadati većem broju grupa).\
Takođe je moguće promeniti ID korisnika i grupe ako binarni fajl ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** pruža alternativni skup **akreditiva**. Preuzimanjem personae istovremeno se preuzimaju njen uid, gid i članstva u grupama. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:

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

1. **POSIX Threads (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za niti za C/C++. Implementacija pthreads u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koja potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža funkcije potrebne za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kom je zasnovan macOS). Ovaj sistemski poziv prima različite zastavice izvedene iz `pthread_attr` (atributa), koje određuju ponašanje niti, uključujući pravila raspoređivanja i veličinu steka.
   - **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi pomoću atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` je ključna tokom podešavanja niti i koristi argument `env[]` za analizu promenljivih okruženja koje mogu da sadrže detalje o lokaciji i veličini steka.

#### Završetak niti u macOS-u

1. **Izlazak iz niti:** Niti se obično završavaju pozivanjem funkcije `pthread_exit()`. Ova funkcija omogućava niti da se uredno završi, obavi potrebno čišćenje i vrati vrednost svim nitima koje je čekaju.
2. **Čišćenje niti:** Nakon poziva funkcije `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture niti. Ona oslobađa Mach portove niti (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture na nivou kernela povezane s niti.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i sprečavanje race condition-a, macOS pruža nekoliko primitiva za sinhronizaciju. One su ključne u okruženjima sa više niti jer obezbeđuju integritet podataka i stabilnost sistema:

1. **Mutex-i:**
   - **Običan mutex (potpis: 0x4D555458):** Standardni mutex memorijskog otiska od 60 bajtova (56 bajtova za mutex i 4 bajta za potpis).
   - **Brzi mutex (potpis: 0x4d55545A):** Sličan običnom mutex-u, ali optimizovan za brže operacije; takođe je veličine 60 bajtova.
2. **Promenljive uslova:**
   - Koriste se za čekanje da se ispune određeni uslovi, a veličine su 44 bajta (40 bajtova plus potpis od 4 bajta).
   - **Atributi promenljivih uslova (potpis: 0x434e4441):** Atributi za podešavanje promenljivih uslova, veličine 12 bajtova.
3. **Once promenljiva (potpis: 0x4f4e4345):**
   - Obezbeđuje da se deo koda za inicijalizaciju izvrši samo jednom. Veličine je 12 bajtova.
4. **Brave za čitanje i upisivanje:**
   - Omogućavaju istovremeno više čitalaca ili jednog upisivača, čime se obezbeđuje efikasan pristup deljenim podacima.
   - **Brava za čitanje i upisivanje (potpis: 0x52574c4b):** Veličine je 196 bajtova.
   - **Atributi brave za čitanje i upisivanje (potpis: 0x52574c41):** Atributi brave za čitanje i upisivanje, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta tih objekata koriste se za otkrivanje prekoračenja bafera.

### Lokalne promenljive niti (TLV)

**Lokalne promenljive niti (TLV)** u kontekstu Mach-O datoteka (formata izvršnih datoteka u macOS-u) koriste se za deklarisanje promenljivih koje su specifične za **svaku nit** u aplikaciji sa više niti. Tako svaka nit dobija sopstvenu instancu promenljive, što omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije poput mutex-a.

U C-u i srodnim jezicima, promenljivu lokalnu za nit možete deklarisati pomoću ključne reči **`__thread`**. Ovako funkcioniše u vašem primeru:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ovaj isečak definiše `tlv_var` kao promenljivu lokalnu za nit. Svaka nit koja izvršava ovaj kod imaće sopstveni `tlv_var`, a izmene koje jedna nit napravi u promenljivoj `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnoj datoteci, podaci povezani sa promenljivama lokalnim za nit organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o promenljivama lokalnim za nit, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za promenljive lokalne za nit koje nisu eksplicitno inicijalizovane. To je deo memorije rezervisan za podatke inicijalizovane nulom.

Mach-O takođe pruža poseban API, **`tlv_atexit`**, za upravljanje promenljivama lokalnim za nit pri završetku niti. Ovaj API omogućava **registrovanje destruktora** — posebnih funkcija koje čiste podatke lokalne za nit kada se nit završi.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva uvid u to kako operativni sistem odlučuje koje niti će pokretati i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS-u i sistemima nalik Unixu, za to se koriste koncepti kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima vrednost nice u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana vrednost nice pri kreiranju procesa obično je 0.
   - Niža vrednost nice (bliža -20) čini proces „sebičnijim“ i daje mu više CPU vremena u odnosu na druge procese sa višim vrednostima nice.
2. **Renice:**
   - `renice` je komanda koja se koristi za promenu vrednosti nice već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa, odnosno za povećanje ili smanjenje dodeljenog CPU vremena na osnovu novih vrednosti nice.
   - Na primer, ako procesu privremeno treba više CPU resursa, možete smanjiti njegovu vrednost nice pomoću `renice`.

#### Klase Quality of Service (QoS)

Klase QoS predstavljaju savremeniji pristup upravljanju prioritetima niti, naročito u sistemima poput macOS-a koji podržavaju **Grand Central Dispatch (GCD)**. Klase QoS omogućavaju programerima da **kategorizuju** posao u različite nivoe na osnovu njegove važnosti ili hitnosti. macOS automatski upravlja prioritetima niti na osnovu ovih klasa QoS:

1. **User Interactive:**
   - Ova klasa namenjena je zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju neposredne rezultate radi dobrog korisničkog iskustva. Ovi zadaci dobijaju najviši prioritet kako bi interfejs ostao odzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
   - Zadaci koje korisnik pokreće i za koje očekuje neposredne rezultate, poput otvaranja dokumenta ili klika na dugme koje zahteva izračunavanja. Imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
   - Ovi zadaci dugo traju i obično prikazuju indikator napretka (npr. preuzimanje datoteka ili uvoz podataka). Imaju niži prioritet od zadataka koje je pokrenuo korisnik i ne moraju odmah da se završe.
4. **Background:**
   - Ova klasa namenjena je zadacima koji se izvršavaju u pozadini i nisu vidljivi korisniku. To mogu biti zadaci poput indeksiranja, sinhronizacije ili pravljenja rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem klasa QoS, programeri ne moraju da upravljaju tačnim brojevima prioriteta, već mogu da se usredsrede na prirodu zadatka, dok sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** koje se prosleđuju radi određivanja skupa parametara raspoređivanja koje će planer uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u napadima zasnovanim na race condition-u.

## Zloupotreba macOS procesa

macOS pruža mnoge mehanizme za **interakciju, komunikaciju i deljenje podataka između procesa**. Iako su ovi mehanizmi neophodni za normalan rad sistema, napadači ih mogu zloupotrebiti za injection, izvršavanje koda ili pristup podacima.

### Library Injection

Library Injection je tehnika kojom napadač **primorava proces da učita zlonamernu biblioteku**. Nakon injection-a, biblioteka se izvršava u kontekstu ciljnog procesa, pa napadač dobija iste dozvole i pristup kao taj proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking-om funkcija, napadač može da **izmeni ponašanje** procesa, nadgleda osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ova stranica obrađuje ARM64 unwind metapodatke, arm64e PAC ograničenja i sintetičke stekove poziva.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) označava različite metode kojima odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC ključan za mnoge legitimne aplikacije, može se zloupotrebiti za narušavanje izolacije procesa, leak osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije koje se izvršavaju sa određenim promenljivama okruženja mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti zastavice `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **man in the browser napada**, čime se omogućava krađa pritisaka na tastere, saobraćaja i kolačića, kao i injection skripti u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB datoteke **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, one mogu **izvršavati proizvoljne komande**, a **Gatekeeper ne sprečava** ponovno izvršavanje već pokrenute aplikacije ako je **NIB datoteka izmenjena**. Zato se mogu koristiti za izvršavanje proizvoljnih komandi proizvoljnim programima:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je ubaciti JVM opcije putem **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ili **`JDK_JAVA_OPTIONS`** i učitati Java ili native agent pre pokretanja aplikacije.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** unapred učitava napadačev JavaScript preko `--require` (datoteka) ili `--import data:text/javascript,…` (bez datoteke, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** učitava modul u interaktivni REPL, a **`ELECTRON_RUN_AS_NODE`** ponovo omogućava sve ovo u Electron binarnim datotekama.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je ubaciti kod u .NET aplikacije pomoću **`DOTNET_STARTUP_HOOKS`** pre funkcije `Main`, ili zloupotrebom funkcionalnosti .NET debagovanja kada su ispunjeni preduslovi.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Neinteraktivni Bash čita **`BASH_ENV`**; interaktivne POSIX ljuske čitaju **`ENV`**; zsh čita **`$ZDOTDIR/.zshenv`**; a fish čita konfiguraciju iz **`XDG_CONFIG_HOME`** ili **`XDG_DATA_DIRS`**. Svaka od njih može da izvrši kontrolisanu datoteku za pokretanje pre predviđene komande. Bash takođe izvršava command substitution postavljen u **`PS4`** svaki put kada je xtrace omogućen (npr. preko nasleđenog **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Pokretanjem `/bin/zsh -s` postiže se da ljuska čita program sa standardnog ulaza. Zato preuzimač koji kopira nepouzdani strukturisani dokument na standardni ulaz deteta bez prethodnog parsiranja pretvara ceo dokument u izvorni kod ljuske. Jedan uočen loader prosleđivao je javnu iCalendar datoteku kroz anonimni pipe, red po red. Metapodaci kalendara nisu se izvršavali kao komande, ali je zsh nastavio sve dok nije stigao do izvršivih redova postavljenih posle `DESCRIPTION:`. Ti redovi su preuzeli i pokrenuli sledeći application bundle. Očekivani tip sadržaja i pouzdani hosting datoteke nisu je činili bezbednom; opasnost je nastala prosleđivanjem njenih bajtova interpreteru.<sup>[[5]](#references)</sup>

Povezane faze obrađene su u odeljcima [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) i [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ili **`PHP_INI_SCAN_DIR`** mogu da učitaju kontrolisanu PHP konfiguraciju čiji **`auto_prepend_file`** izvršava kod pre ciljne skripte.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samostalni Lua interpreter izvršava kod ili `@file` iz **`LUA_INIT`** (ili njegove varijante specifične za verziju) pre obrade ciljne skripte.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** preusmeravaju na profile za pokretanje koji sadrže R kod. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** u kombinaciji sa putanjom R biblioteke mogu umesto toga automatski da učitaju instalirani paket.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** preusmerava na depot čiji se `config/startup.jl` automatski izvršava.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ili **`ERL_ZFLAGS`** mogu da ubace Erlang VM izraz **`-eval`** bez potrebe za datotekom sa payload-om; Elixir workload-i obično pokreću istu VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** preusmeravaju na Octave skripte za pokretanje.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` je višeplatformska .NET aplikacija, pa nekoliko promenljivih okruženja omogućava izvršavanje pre komande: **`XDG_CONFIG_HOME`** preusmerava na profilne skripte koje se pokreću pri startovanju, **`PSModulePath`** omogućava otmicu automatskog učitavanja modula (postavljeni `.psm1` se izvršava pri uvozu i može da zaseni ugrađene cmdlet-e), a .NET promenljive **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** učitavaju napadačev kod u proces pre funkcije `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Proverite različite opcije pomoću kojih Perl skripta može da izvrši proizvoljan kod u:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Moguće je zloupotrebiti i Ruby promenljive okruženja (**`RUBYOPT`**, **`RUBYLIB`**) kako bi proizvoljne skripte izvršavale proizvoljan kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Lanac **`PYTHONWARNINGS`** i **`BROWSER`** iz standardne biblioteke može da izvrši komandu tokom parsiranja filtera upozorenja. Alternativa koja koristi datoteku postavlja `sitecustomize.py` u **`PYTHONPATH`**, tako da ga normalna `site` inicijalizacija uveze pre ciljne skripte. **`PYTHONBREAKPOINT`** pokreće izabranu funkciju/modul kada kod naiđe na `breakpoint()`. Promenljive namenjene isključivo interaktivnoj upotrebi, poput **`PYTHONSTARTUP`**, imaju užu primenu.

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** ne koriste ove promenljive okruženja, čak ni kada se izvršavaju koristeći ugrađeni Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (i njegova rezervna opcija `EXINIT`) izvršavaju se kao Ex komande pri uobičajenom pokretanju, pa `:!cmd` / `:call system(...)` omogućavaju izvršavanje koda kada žrtva otvori Vim/Neovim u kontrolisanom okruženju:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Odvojeno od toga, Homebrew često instalira Python ispod putanje `/opt/homebrew`, gde članovi lokalne grupe `admin` možda mogu da zamene pokretač. To je otmica binarne datoteke koja se može menjati, a ne injection preko promenljive okruženja; proverite vlasništvo i ACL-ove pre nego što je proglasite ranjivom.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je aplikacija otvorenog koda zasnovana na **EndpointSecurity**, koja detektuje i blokira process injection. Dobar je izvor informacija o signalima vidljivim putem Endpoint Security-ja, jer upozorava na sledeće:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection promenljive okruženja** pri pokretanju procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — jedan proces traži task port drugog procesa, što je preduslov za injection u taj proces.
- **Electron argumente za debagovanje** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u režimu debagovanja i omogućavaju bilo kome da se poveže na nju i izvršava kod.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza između nivoa privilegija** — klasični primitiv „postavi vezu kao običan korisnik, pa je usmeri na privilegovanu lokaciju“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne izlaže odredište veze pre njenog kreiranja.

### Pozivi drugih procesa

U [**ovoj objavi na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete saznati kako je moguće koristiti funkciju **`task_name_for_pid`** za dobijanje informacija o drugim **procesima koji ubacuju kod u proces**, a zatim i informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje te funkcije morate imati **isti uid** kao proces koji se pokreće ili biti **root** (funkcija vraća informacije o procesu, a ne mogućnost za injection koda).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — detekcija macOS process injection-a otvorenog koda (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity okvir](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Zašto Electron aplikacije ne mogu da čuvaju vaše tajne poverljivo: opcija --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detektovanje izmena zadataka](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Nova verzija macOS kradljivca MacSync cilja entuzijaste kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
