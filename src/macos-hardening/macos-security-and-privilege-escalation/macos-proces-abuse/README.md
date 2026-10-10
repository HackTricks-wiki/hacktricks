# Zloupotreba procesa u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršne datoteke koja se izvršava, ali procesi ne izvršavaju kod — to rade niti. Dakle, **procesi su samo kontejneri za niti koje se izvršavaju**, a obezbeđuju im memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivom funkcije **`fork`**, koja bi napravila tačnu kopiju trenutnog procesa, a zatim bi **podređeni proces** obično pozvao **`execve`** da učita novu izvršnu datoteku i pokrene je. Zatim je uveden **`vfork`** da bi se ovaj proces ubrzao bez kopiranja memorije.\
Potom je uveden **`posix_spawn`**, koji objedinjuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
- `POSIX_SPAWN_SETEXEC`: Izvršava u istom procesu (kao `execve`, uz više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće proces u suspendovanom stanju
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće proces bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi Nano allocator iz libmalloc-a
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` nad segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve deskriptore datoteka pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično menja visoke bitove ASLR pomeraja

Pored toga, `posix_spawn` prihvata podešavanja **`posix_spawnattr`** koja kontrolišu aspekte pokrenutog procesa, kao i stavke **`posix_spawn_file_actions`** koje menjaju deskriptore datoteka.

Kada proces prestane da radi, šalje **povratni kod roditeljskom procesu** (ako je roditeljski proces prestao da radi, novi roditeljski proces je PID 1) signalom `SIGCHLD`. Roditelj mora da preuzme tu vrednost pozivom funkcije `wait4()` ili `waitid()`. Do tada podređeni proces ostaje u zombi stanju: i dalje je naveden, ali ne troši resurse.

### PID-jevi

PID-jevi, odnosno identifikatori procesa, označavaju jedinstven proces. U XNU-u, **PID-jevi** su **64-bitni**, monotono rastu i **nikada se ne vraćaju na početnu vrednost** (kako bi se sprečile zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** se mogu organizovati u **grupe** kako bi se njima lakše upravljalo. Na primer, komande u shell skripti biće u istoj grupi procesa, pa ih je moguće **signalizirati zajedno**, na primer pomoću kill.\
Moguće je i **grupisati procese u sesije**. Kada proces pokrene sesiju (`setsid(2)`), njegovi podređeni procesi se smeštaju u tu sesiju, osim ako ne pokrenu sopstvenu sesiju.

Koalicija je još jedan način grupisanja procesa u Darwinu. Proces koji se pridruži koaliciji može da pristupi zajedničkim resursima pool-a, deli ledger ili bude podložan mehanizmu Jetsam. Koalicije imaju različite uloge: Leader, XPC service, Extension.

### Akreditivi i personae

Svaki proces ima **akreditive** koji **određuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (iako može pripadati većem broju grupa).\
Korisnički i grupni ID takođe se mogu menjati ako binarna datoteka ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** pruža **alternativni** skup **akreditiva**. Usvajanjem persone odjednom se preuzimaju njeni uid, gid i članstva u grupama. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:

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

1. **POSIX Threads (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za niti za C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koji potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža potrebne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kom je zasnovan macOS). Ovaj sistemski poziv prima različite zastavice izvedene iz `pthread_attr` (atributa), koje određuju ponašanje niti, uključujući pravila raspoređivanja i veličinu steka.
   - **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti iznosi 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi pomoću atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` je ključna tokom podešavanja niti. Koristi argument `env[]` za raščlanjivanje promenljivih okruženja, koje mogu sadržati detalje o lokaciji i veličini steka.

#### Završetak niti u macOS-u

1. **Izlazak iz niti:** Niti se obično završavaju pozivom funkcije `pthread_exit()`. Ova funkcija omogućava niti da se uredno završi, obavi potrebno čišćenje i pošalje povratnu vrednost nitima koje čekaju na njen završetak.
2. **Čišćenje niti:** Kada se pozove `pthread_exit()`, izvršava se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture niti. Ona oslobađa Mach portove niti (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture povezane s niti na nivou kernela.

#### Mehanizmi za sinhronizaciju

Za upravljanje pristupom deljenim resursima i sprečavanje race uslova, macOS pruža nekoliko primitiva za sinhronizaciju. Oni su ključni u okruženjima sa više niti kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
   - **Običan mutex (potpis: 0x4D555458):** Standardni mutex, veličine 60 bajtova (56 bajtova za mutex i 4 bajta za potpis).
   - **Brzi mutex (potpis: 0x4d55545A):** Sličan običnom mutex-u, ali optimizovan za brže operacije; takođe je veličine 60 bajtova.
2. **Uslovne promenljive:**
   - Koriste se za čekanje na ispunjenje određenih uslova; veličina im je 44 bajta (40 bajtova plus potpis od 4 bajta).
   - **Atributi uslovne promenljive (potpis: 0x434e4441):** Atributi za podešavanje uslovnih promenljivih, veličine 12 bajtova.
3. **Once promenljiva (potpis: 0x4f4e4345):**
   - Obezbeđuje da se deo koda za inicijalizaciju izvrši samo jednom. Veličina joj je 12 bajtova.
4. **Brave za čitanje i pisanje:**
   - Omogućavaju istovremeni pristup većem broju čitalaca ili jednom piscu, čime se omogućava efikasan pristup deljenim podacima.
   - **Brava za čitanje i pisanje (potpis: 0x52574c4b):** Veličine je 196 bajtova.
   - **Atributi brave za čitanje i pisanje (potpis: 0x52574c41):** Atributi za brave za čitanje i pisanje, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta tih objekata koriste se za otkrivanje prelivanja.

### Lokalne promenljive niti (TLV)

**Lokalne promenljive niti (TLV)** u kontekstu Mach-O datoteka (format izvršnih datoteka u macOS-u) koriste se za deklarisanje promenljivih koje su specifične za **svaku nit** u višenitnoj aplikaciji. Time se obezbeđuje da svaka nit ima zasebnu instancu promenljive, što omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije, kao što su mutex-i.

U jezicima C i srodnim jezicima možete deklarisati lokalnu promenljivu niti pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ovaj isečak definiše `tlv_var` kao thread-local promenljivu. Svaka nit koja izvršava ovaj kod imaće sopstvenu `tlv_var`, a izmene koje jedna nit napravi u `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnoj datoteci podaci povezani sa thread-local promenljivama organizovani su u posebne sekcije:

- **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o thread-local promenljivama, kao što su njihovi tipovi i status inicijalizacije.
- **`__DATA.__thread_bss`**: Ova sekcija se koristi za thread-local promenljive koje nisu eksplicitno inicijalizovane. To je deo memorije rezervisan za podatke inicijalizovane nulama.

Mach-O takođe pruža poseban API pod nazivom **`tlv_atexit`** za upravljanje thread-local promenljivama kada se nit završi. Ovaj API omogućava **registrovanje destruktora** — posebnih funkcija koje čiste thread-local podatke kada se nit završi.

### Prioriteti niti

Razumevanje prioriteta niti podrazumeva sagledavanje načina na koji operativni sistem odlučuje koje će niti pokrenuti i kada. Na ovu odluku utiče nivo prioriteta dodeljen svakoj niti. U macOS-u i sistemima sličnim Unixu, za to se koriste koncepti kao što su `nice`, `renice` i klase Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Vrednost `nice` procesa je broj koji utiče na njegov prioritet. Svaki proces ima vrednost nice u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana vrednost nice pri kreiranju procesa obično je 0.
   - Niža vrednost nice (bliža -20) čini proces „sebičnijim“, dajući mu više CPU vremena u odnosu na druge procese sa višim vrednostima nice.
2. **Renice:**
   - `renice` je komanda koja se koristi za promenu vrednosti nice već pokrenutog procesa. Može se koristiti za dinamičko podešavanje prioriteta procesa i povećanje ili smanjenje dodeljenog CPU vremena na osnovu novih vrednosti nice.
   - Na primer, ako je procesu privremeno potrebno više CPU resursa, vrednost nice možete smanjiti pomoću `renice`.

#### Klase Quality of Service (QoS)

Klase QoS predstavljaju savremeniji pristup upravljanju prioritetima niti, posebno u sistemima kao što je macOS koji podržavaju **Grand Central Dispatch (GCD)**. Klase QoS omogućavaju programerima da **kategorizuju** posao na različite nivoe prema njegovoj važnosti ili hitnosti. macOS automatski upravlja prioritetima niti na osnovu ovih klasa QoS:

1. **User Interactive:**
   - Ova klasa namenjena je zadacima koji trenutno komuniciraju sa korisnikom ili zahtevaju trenutne rezultate radi dobrog korisničkog iskustva. Ovim zadacima dodeljuje se najviši prioritet kako bi interfejs ostao responzivan (npr. animacije ili obrada događaja).
2. **User Initiated:**
   - Zadaci koje korisnik pokreće i za koje očekuje trenutne rezultate, kao što su otvaranje dokumenta ili klik na dugme koje zahteva izračunavanja. Imaju visok prioritet, ali niži od klase User Interactive.
3. **Utility:**
   - Ovi zadaci dugo traju i obično prikazuju indikator napretka (npr. preuzimanje datoteka, uvoz podataka). Imaju niži prioritet od zadataka koje je pokrenuo korisnik i ne moraju odmah da se završe.
4. **Background:**
   - Ova klasa namenjena je zadacima koji se izvršavaju u pozadini i nisu vidljivi korisniku. To mogu biti zadaci kao što su indeksiranje, sinhronizacija ili pravljenje rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem klasa QoS, programeri ne moraju da upravljaju konkretnim brojevima prioriteta, već mogu da se usredsrede na prirodu zadatka, a sistem u skladu s tim optimizuje CPU resurse.

Pored toga, postoje različite **politike raspoređivanja niti** kojima se zadaje skup parametara raspoređivanja koje će planer uzeti u obzir. To se može uraditi pomoću `thread_policy_[set/get]`. Ovo može biti korisno u napadima zasnovanim na race conditionu.

## Zloupotreba macOS procesa

macOS pruža brojne mehanizme koji omogućavaju **procesima da međusobno komuniciraju i dele podatke**. Iako su ti mehanizmi neophodni za uobičajeni rad sistema, napadači mogu da ih zloupotrebe za injection, izvršavanje koda ili pristup podacima.

### Library Injection

Library Injection je tehnika kojom napadač **primorava proces da učita zlonamernu biblioteku**. Kada se ubaci, biblioteka se izvršava u kontekstu ciljnog procesa i napadaču pruža iste dozvole i pristup kao tom procesu.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hooking funkcija omogućava napadaču da **izmeni ponašanje** procesa, nadgleda osetljive podatke ili čak preuzme kontrolu nad tokom izvršavanja.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) označava različite metode kojima odvojeni procesi **dele i razmenjuju podatke**. Iako je IPC ključan za mnoge legitimne aplikacije, može se i zloupotrebiti za zaobilaženje izolacije procesa, leak osetljivih informacija ili izvršavanje neovlašćenih radnji.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron aplikacije koje se pokreću sa određenim env promenljivama mogu biti ranjive na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Moguće je koristiti zastavice `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **man in the browser attack** napada, koji omogućava krađu pritisnutih tastera, saobraćaja i kolačića, ubacivanje skripti u stranice...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB datoteke **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, mogu **izvršavati proizvoljne komande**, a **Gatekeeper ne sprečava** ponovno pokretanje aplikacije koja je već pokrenuta ako je **NIB datoteka izmenjena**. Zato se mogu koristiti za pokretanje proizvoljnih komandi iz proizvoljnih programa:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Moguće je ubaciti JVM opcije pomoću **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ili **`JDK_JAVA_OPTIONS`** i učitati Java ili native agenta pre pokretanja aplikacije.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** unapred učitava napadačev JavaScript preko `--require` (datoteka) ili `--import data:text/javascript,…` (bez datoteke, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** učitava modul u interaktivni REPL, a **`ELECTRON_RUN_AS_NODE`** ponovo omogućava sve ovo u Electron binarnim datotekama.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Moguće je ubaciti kod u .NET aplikacije pomoću **`DOTNET_STARTUP_HOOKS`** pre funkcije `Main`, ili zloupotrebom .NET funkcionalnosti za otklanjanje grešaka kada su ispunjeni potrebni preduslovi.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Neinteraktivni Bash učitava **`BASH_ENV`**; interaktivne POSIX shell skripte učitavaju **`ENV`**; zsh učitava **`$ZDOTDIR/.zshenv`**; a fish učitava konfiguraciju iz **`XDG_CONFIG_HOME`** ili **`XDG_DATA_DIRS`**. Svaka od njih može izvršiti kontrolisanu startup datoteku pre predviđene komande. Bash takođe izvršava command substitution postavljen u **`PS4`** svaki put kada je xtrace omogućen (npr. nasleđenim **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** ili **`PHP_INI_SCAN_DIR`** mogu učitati kontrolisanu PHP konfiguraciju čiji **`auto_prepend_file`** izvršava kod pre ciljne skripte.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samostalni Lua interpreter izvršava kod ili `@file` iz **`LUA_INIT`** (ili njegove verzije specifične varijante) pre obrade ciljne skripte.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** preusmeravaju na startup profile koji sadrže R kod. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, zajedno sa putanjom do R biblioteke, mogu umesto toga automatski učitati instalirani paket.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** preusmerava na depot čiji se `config/startup.jl` automatski izvršava.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ili **`ERL_ZFLAGS`** mogu ubaciti Erlang VM izraz **`-eval`** bez potrebe za payload datotekom; Elixir radna opterećenja obično pokreću isti VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** preusmeravaju na Octave startup skripte.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` je višeplatformska .NET aplikacija, pa nekoliko env promenljivih omogućava izvršavanje komandi pre predviđene komande: **`XDG_CONFIG_HOME`** preusmerava na profilne skripte koje se pokreću pri pokretanju, **`PSModulePath`** omogućava otmicu automatskog učitavanja modula (postavljeni `.psm1` se pokreće pri uvozu i može da zaseni ugrađene cmdlet-e), a .NET promenljive **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** učitavaju napadačev kod u proces pre funkcije `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Proverite različite mogućnosti pomoću kojih Perl skripta može da izvrši proizvoljan kod:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Moguće je i zloupotrebiti ruby env promenljive (**`RUBYOPT`**, **`RUBYLIB`**) da bi proizvoljne skripte izvršavale proizvoljan kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Standardna bibliotečka veza **`PYTHONWARNINGS`** i **`BROWSER`** može da izvrši komandu tokom parsiranja filtera upozorenja. Alternativa koja koristi datoteku postavlja `sitecustomize.py` na putanju **`PYTHONPATH`**, tako da ga uobičajena inicijalizacija `site` uveze pre ciljne skripte. **`PYTHONBREAKPOINT`** pokreće izabranu callable funkciju ili modul kada kod stigne do `breakpoint()`. Promenljive koje važe samo za interaktivni režim, kao što je **`PYTHONSTARTUP`**, imaju užu primenu.

Imajte na umu da izvršne datoteke kompajlirane pomoću **`pyinstaller`** neće koristiti ove env promenljive, čak i ako se izvršavaju pomoću ugrađenog Python interpretera.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (i njegova zamena `EXINIT`) izvršavaju se kao Ex komande pri uobičajenom pokretanju, pa `:!cmd` / `:call system(...)` omogućavaju izvršavanje koda kada žrtva otvori Vim/Neovim u kontrolisanom okruženju:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Odvojeno od toga, Homebrew često instalira Python u `/opt/homebrew`, gde članovi lokalne grupe `admin` možda mogu da zamene launcher. To je otmica zapisive binarne datoteke, a ne injection preko env promenljive; proverite vlasništvo i ACL-ove pre nego što to smatrate iskoristivim.


## Detekcija

### Shield

[**Shield**](https://github.com/theevilbit/Shield) je open-source aplikacija zasnovana na **EndpointSecurity** koja detektuje i blokira process injection. Dobar je izvor za uvid u signale vidljive kroz Endpoint Security, jer upozorava na:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection env promenljive** pri izvršavanju procesa: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Pozive **`task_for_pid`** — kada jedan proces zatraži task port drugog procesa, što je preduslov za njegovo ubrizgavanje.
- **Electron argumente za otklanjanje grešaka** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, koji pokreću Electron aplikaciju u režimu za otklanjanje grešaka i omogućavaju bilo kome da se poveže i izvrši kod u njoj.<sup>[[3]](#references)</sup>
- **Kreiranje symlink/hardlink veza između nivoa privilegija** — klasičnu primitivu „postavi vezu kao običan korisnik i usmeri je na privilegovanu lokaciju“. Imajte na umu da se **symlink veze mogu detektovati, ali ne i blokirati**: EndpointSecurity ne otkriva odredište veze pre njenog kreiranja.

### Pozivi drugih procesa

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete saznati kako je moguće koristiti funkciju **`task_name_for_pid`** za dobijanje informacija o drugim **procesima koji ubacuju kod u proces**, a zatim i informacija o tom drugom procesu.<sup>[[4]](#references)</sup>

Imajte na umu da za pozivanje ove funkcije morate imati **isti uid** kao proces ili biti **root** (ona vraća informacije o procesu, ali ne omogućava ubacivanje koda).

## References

- [1] [Shield — detekcija process injection napada na macOS-u otvorenog koda (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Zašto Electron aplikacije ne mogu poverljivo da čuvaju vaše tajne: opcija --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detektovanje izmena task-ova](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
