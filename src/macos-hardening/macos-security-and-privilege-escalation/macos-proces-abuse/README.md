# Zloupotreba macOS procesa

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršne datoteke koja se pokreće, međutim, procesi ne izvršavaju kod — to rade niti. Zato su **procesi samo kontejneri za pokrenute niti** koji obezbeđuju memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID 1) pozivanjem funkcije **`fork`**, koja bi kreirala tačnu kopiju trenutnog procesa. Zatim bi **podređeni proces** obično pozvao **`execve`** da učita novu izvršnu datoteku i pokrene je. Potom je uveden **`vfork`** kako bi se ovaj proces ubrzao, bez kopiranja memorije.\
Zatim je uveden **`posix_spawn`**, koji kombinuje **`vfork`** i **`execve`** u jednom pozivu i prihvata zastavice:

- `POSIX_SPAWN_RESETIDS`: Resetuj efektivne ID-jeve na stvarne ID-jeve
- `POSIX_SPAWN_SETPGROUP`: Postavi pripadnost grupi procesa
- `POSUX_SPAWN_SETSIGDEF`: Postavi podrazumevano ponašanje signala
- `POSIX_SPAWN_SETSIGMASK`: Postavi masku signala
- `POSIX_SPAWN_SETEXEC`: Izvrši u istom procesu (kao `execve`, uz više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreni suspendovano
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreni bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc-ov Nano alokator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoli `rwx` na segmentima podataka
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvori sve opise datoteka pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično odredi visoke bitove ASLR pomeraja

Pored toga, `posix_spawn` prihvata podešavanja **`posix_spawnattr`**, koja kontrolišu aspekte pokrenutog procesa, kao i stavke **`posix_spawn_file_actions`**, koje menjaju deskriptore datoteka.

Kada proces završi, šalje **povratni kod roditeljskom procesu** (ako je roditeljski proces završio, novi roditeljski proces je PID 1) pomoću signala `SIGCHLD`. Roditeljski proces mora da preuzme ovu vrednost pozivom funkcije `wait4()` ili `waitid()`. Dok se to ne dogodi, podređeni proces ostaje u zombi stanju: i dalje je na listi procesa, ali ne troši resurse.

### PID-ovi

PID-ovi (identifikatori procesa) identifikuju jedinstven proces. U XNU-u, **PID-ovi** su **64-bitni**, monotono rastu i **nikada se ne prelivaju** (kako bi se izbegle zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** se mogu rasporediti u **grupe** kako bi se lakše upravljalo njima. Na primer, komande u shell skripti biće u istoj grupi procesa, pa ih je moguće **signalizirati zajedno**, na primer pomoću `kill`.\
Moguće je i **grupisati procese u sesije**. Kada proces pokrene sesiju (`setsid(2)`), podređeni procesi se smeštaju u tu sesiju, osim ako ne pokrenu sopstvenu sesiju.

Koalicija je još jedan način grupisanja procesa u Darwin-u. Proces koji se pridruži koaliciji može da pristupa zajedničkim resursima, deli evidenciju ili bude podložan Jetsam-u. Koalicije imaju različite uloge: Leader, XPC service, Extension.

### Akreditivi i Personae

Svaki proces poseduje **akreditive** koji **određuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (iako može pripadati većem broju grupa).\
Korisnički i grupni ID takođe mogu da se promene ako binarna datoteka ima bit `setuid/setgid`.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Sistemski poziv **`persona`** obezbeđuje alternativni skup **akreditiva**. Usvajanjem personae preuzimaju se njen uid, gid i članstva u grupama **istovremeno**. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:

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

1. **POSIX Threads (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za niti u C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koji potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka obezbeđuje neophodne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` koristi se za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, sistemski poziv nižeg nivoa specifičan za XNU kernel (kernel na kom je zasnovan macOS). Ovaj sistemski poziv prima različite zastavice izvedene iz `pthread_attr` (atributa), koje određuju ponašanje niti, uključujući pravila raspoređivanja i veličinu steka.
   - **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi preko atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` je ključna tokom podešavanja niti; koristi argument `env[]` za obradu promenljivih okruženja koje mogu sadržati informacije o lokaciji i veličini steka.

#### Završavanje niti u macOS-u

1. **Izlazak iz niti:** Niti se obično završavaju pozivom funkcije `pthread_exit()`. Ova funkcija omogućava niti da se uredno završi, obavi neophodno čišćenje i prosledi povratnu vrednost nitima koje čekaju na njeno završavanje.
2. **Čišćenje niti:** Pri pozivu funkcije `pthread_exit()` poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture niti. Ona oslobađa Mach portove niti (Mach je podsistem za komunikaciju u XNU kernelu) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture na nivou kernela povezane sa niti.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i sprečavanje race condition-a, macOS pruža nekoliko primitiva za sinhronizaciju. One su ključne u okruženjima sa više niti kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
   - **Običan mutex (potpis: 0x4D555458):** Standardni mutex memorijskog otiska od 60 bajtova (56 bajtova za mutex i 4 bajta za potpis).
   - **Brzi mutex (potpis: 0x4d55545A):** Sličan običnom mutex-u, ali optimizovan za brže operacije; takođe je veličine 60 bajtova.
2. **Uslovne promenljive:**
   - Koriste se za čekanje da se ispune određeni uslovi; veličine su 44 bajta (40 bajtova plus potpis od 4 bajta).
   - **Atributi uslovne promenljive (potpis: 0x434e4441):** Atributi za podešavanje uslovnih promenljivih, veličine 12 bajtova.
3. **Promenljiva Once (potpis: 0x4f4e4345):**
   - Obezbeđuje da se deo koda za inicijalizaciju izvrši samo jednom. Veličine je 12 bajtova.
4. **Brave za čitanje i pisanje:**
   - Omogućavaju više čitalaca ili jednog pisca u datom trenutku, čime se omogućava efikasan pristup deljenim podacima.
   - **Brava za čitanje i pisanje (potpis: 0x52574c4b):** Veličine je 196 bajtova.
   - **Atributi brave za čitanje i pisanje (potpis: 0x52574c41):** Atributi za brave za čitanje i pisanje, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta tih objekata koriste se za otkrivanje prekoračenja.

### Lokalne promenljive niti (TLV)

**Lokalne promenljive niti (TLV)** u kontekstu Mach-O fajlova (format izvršnih fajlova u macOS-u) koriste se za deklarisanje promenljivih specifičnih za **svaku nit** u aplikaciji sa više niti. Time se obezbeđuje da svaka nit ima zasebnu instancu promenljive, što pomaže u izbegavanju konflikata i očuvanju integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije kao što su mutex-i.

U jeziku C i srodnim jezicima, lokalnu promenljivu niti možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Овај исечак дефинише `tlv_var` као thread-local променљиву. Свака нит која извршава овај код имаће сопствену `tlv_var`, а измене које једна нит направи у својој `tlv_var` неће утицати на `tlv_var` друге нити.

У Mach-O бинарној датотеци, подаци који се односе на thread-local променљиве организовани су у посебне секције:

- **`__DATA.__thread_vars`**: Ова секција садржи метаподатке о thread-local променљивама, као што су њихови типови и статус иницијализације.
- **`__DATA.__thread_bss`**: Ова секција се користи за thread-local променљиве које нису експлицитно иницијализоване. Она представља део меморије резервисан за податке иницијализоване на нулу.

Mach-O пружа и посебан API, **`tlv_atexit`**, за управљање thread-local променљивама при завршетку нити. Овај API омогућава **регистровање деструктора** — посебних функција које чисте thread-local податке када се нит заврши.

### Приоритети нити

Разумевање приоритета нити подразумева разматрање начина на који оперативни систем одлучује које нити ће се извршавати и када. На ту одлуку утиче ниво приоритета додељен свакој нити. У macOS-у и системима налик Unix-у, за то се користе концепти као што су `nice`, `renice` и класе Quality of Service (QoS).

#### Nice и Renice

1. **Nice:**
   - Вредност `nice` процеса је број који утиче на његов приоритет. Вредност `nice` сваког процеса је у распону од -20 (највиши приоритет) до 19 (најнижи приоритет). Подразумевана вредност `nice` при креирању процеса обично је 0.
   - Нижа вредност `nice` (ближа вредности -20) чини процес „себичнијим“ и даје му више CPU времена у поређењу са процесима који имају вишу вредност `nice`.
2. **Renice:**
   - `renice` је команда која се користи за промену вредности `nice` већ покренутог процеса. Њоме се приоритет процеса може динамички подесити, чиме се повећава или смањује додела CPU времена на основу нових вредности `nice`.
   - На пример, ако је процесу привремено потребно више CPU ресурса, вредност `nice` му можете снизити помоћу `renice`.

#### Класе Quality of Service (QoS)

Класе QoS представљају савременији приступ управљању приоритетима нити, нарочито у системима као што је macOS који подржавају **Grand Central Dispatch (GCD)**. Класе QoS омогућавају програмерима да **категоришу** задатке у различите нивое према њиховој важности или хитности. macOS аутоматски управља приоритетима нити на основу ових класа QoS:

1. **User Interactive:**
   - Ова класа је намењена задацима који тренутно интерагују са корисником или захтевају тренутне резултате ради доброг корисничког искуства. Овим задацима се додељује највиши приоритет како би интерфејс остао брз и одзиван (нпр. анимације или обрада догађаја).
2. **User Initiated:**
   - Задаци које покреће корисник и за које очекује тренутне резултате, као што су отварање документа или клик на дугме које захтева прорачуне. Имају висок приоритет, али нижи од класе User Interactive.
3. **Utility:**
   - Ови задаци дуго трају и обично приказују индикатор напретка (нпр. преузимање датотека или увоз података). Имају нижи приоритет од задатака које покреће корисник и не морају одмах да се заврше.
4. **Background:**
   - Ова класа је намењена задацима који се извршавају у позадини и нису видљиви кориснику. То могу бити задаци као што су индексирање, синхронизација или прављење резервних копија. Имају најнижи приоритет и минималан утицај на перформансе система.

Користећи класе QoS, програмери не морају да управљају конкретним бројчаним вредностима приоритета, већ могу да се усредсреде на природу задатка, а систем у складу с тим оптимизује CPU ресурсе.

Поред тога, постоје различите **политике распоређивања нити** које омогућавају задацима да наведу скуп параметара распоређивања које ће планер узети у обзир. То се може урадити помоћу `thread_policy_[set/get]`. Ово може бити корисно у нападима заснованим на race condition-у.

## Злоупотреба macOS процеса

macOS пружа бројне механизме за **интеракцију, комуникацију и дељење података између процеса**. Иако су ови механизми неопходни за нормалан рад система, нападачи их могу злоупотребити за injection, извршавање кода или приступ подацима.

### Library Injection

Library Injection је техника којом нападач **приморава процес да учита злонамерну библиотеку**. Када се убаци, библиотека се извршава у контексту циљног процеса, дајући нападачу исте дозволе и приступ као и самом процесу.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking подразумева **пресретање позива функција** или порука унутар софтверског кода. Hooking функција омогућава нападачу да **измени понашање** процеса, посматра осетљиве податке или чак преузме контролу над током извршавања.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ова страница обрађује ARM64 unwind метаподатке, ограничења PAC-а за arm64e и синтетичке ланце позива.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) означава различите методе помоћу којих засебни процеси **деле и размењују податке**. Иако је IPC основа многих легитимних апликација, може се и злоупотребити за нарушавање изолације процеса, цурење осетљивих информација или извршавање неовлашћених радњи.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron апликације покренуте са одређеним env променљивама могу бити рањиве на process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Могуће је користити заставице `--load-extension` и `--use-fake-ui-for-media-stream` за извођење **man in the browser напада**, којим се могу украсти притисци тастера, саобраћај и колачићи, убацити скрипте у странице и слично:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB датотеке **дефинишу елементе корисничког интерфејса (UI)** и њихове интеракције унутар апликације. Међутим, оне могу **извршавати произвољне команде**, а **Gatekeeper не спречава** поновно извршавање већ покренуте апликације ако је **NIB датотека измењена**. Зато се могу користити за покретање произвољних команди из произвољних програма:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Могуће је убацити JVM опције преко **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** или **`JDK_JAVA_OPTIONS`** и учитати Java или native агента пре покретања апликације.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** унапред учитава нападачев JavaScript преко `--require` (датотека) или `--import data:text/javascript,…` (без датотеке, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** учитава модул у интерактивни REPL, а **`ELECTRON_RUN_AS_NODE`** поново омогућава све ове могућности у Electron бинарним датотекама.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Могуће је убацити код у .NET апликације преко **`DOTNET_STARTUP_HOOKS`** пре функције `Main` или злоупотребом .NET функционалности за отклањање грешака када су испуњени предуслови.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Неинтерактивни Bash чита **`BASH_ENV`**; интерактивне POSIX шкољке читају **`ENV`**; zsh чита **`$ZDOTDIR/.zshenv`**; а fish чита конфигурацију из **`XDG_CONFIG_HOME`** или **`XDG_DATA_DIRS`**. Свака од њих може да изврши контролисану startup датотеку пре предвиђене команде. Bash такође извршава command substitution постављен у **`PS4`** сваки пут када је омогућен xtrace (нпр. наслеђени **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Покретање команде `/bin/zsh -s` доводи до тога да шкољка чита програм са стандардног улаза. Зато downloader који копира непоуздани структурирани документ у stdin детета без претходног рашчлањивања претвара цео документ у изворни код шкољке. У једном уоченом loader-у, јавна iCalendar датотека је прослеђивана ред по ред кроз анонимни pipe. Метаподаци календара нису били важеће команде, али је zsh наставио са извршавањем док није стигао до извршивих редова после `DESCRIPTION:`. Ти редови су преузимали и покретали следећи application bundle. Очекивани тип садржаја и поуздано хостовање нису учинили овај поступак безбедним; опасна граница била је прослеђивање бајтова интерпретатору.<sup>[[5]](#references)</sup>

Повезане фазе обрађене су у одељцима [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) и [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** или **`PHP_INI_SCAN_DIR`** могу да учитају контролисану PHP конфигурацију чији **`auto_prepend_file`** извршава код пре циљне скрипте.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Самостални Lua интерпретатор извршава код или датотеку означену са `@file` из **`LUA_INIT`** (или његове верзијски специфичне варијанте) пре обраде циљне скрипте.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** и **`R_PROFILE`** преусмеравају на startup профиле који садрже R код. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** уз путању до R библиотеке могу се, уместо тога, користити за аутоматско учитавање инсталираног пакета.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** преусмерава на depot чији се `config/startup.jl` аутоматски извршава.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** или **`ERL_ZFLAGS`** могу да убаце Erlang VM израз **`-eval`** без потребе за датотеком са payload-ом; Elixir задаци обично покрећу исту VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** и **`OCTAVE_VERSION_INITFILE`** преусмеравају на Octave startup скрипте.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` је .NET апликација за више платформи, па неколико env променљивих омогућава извршавање кода пре команде: **`XDG_CONFIG_HOME`** преусмерава на profile скрипте које се покрећу при стартовању, **`PSModulePath`** отима аутоматско учитавање модула (постављена `.psm1` датотека се извршава при увозу и може да замени уграђене cmdlet-ове), а .NET променљиве **`CORECLR_PROFILER`**/**`COR_PROFILER`** и **`DOTNET_STARTUP_HOOKS`** учитавају нападачев код у процес пре функције `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Проверите различите опције за навођење Perl скрипте да изврши произвољан код у:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Могуће је и злоупотребити ruby env променљиве (**`RUBYOPT`**, **`RUBYLIB`**) да би се произвољне скрипте навеле да изврше произвољан код:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Ланац **`PYTHONWARNINGS`** и **`BROWSER`** из стандардне библиотеке може да изврши команду током рашчлањивања филтера упозорења. Алтернатива која користи датотеку поставља `sitecustomize.py` на **`PYTHONPATH`**, па га уобичајена `site` иницијализација увози пре циљне скрипте. **`PYTHONBREAKPOINT`** покреће изабрану callable функцију или модул када код дође до `breakpoint()`. Променљиве намењене само интерактивном режиму, као што је **`PYTHONSTARTUP`**, имају ужу примену.

Имајте на уму да извршне датотеке компајлиране помоћу **`pyinstaller`** неће користити ове environment променљиве, чак ни када се извршавају помоћу уграђеног python-а.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (и његов резервни избор `EXINIT`) извршавају се као Ex команде при уобичајеном покретању, па `:!cmd` / `:call system(...)` омогућавају извршавање кода када жртва отвори Vim/Neovim у контролисаном окружењу:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Одвојено од тога, Homebrew обично инсталира Python унутар `/opt/homebrew`, где чланови локалне групе `admin` можда могу да замене launcher. То је отимање бинарне датотеке са могућношћу уписа, а не injection преко environment променљиве; пре него што то сматрате експлоатабилним, проверите власништво и ACL-ове.


## Детекција

### Shield

[**Shield**](https://github.com/theevilbit/Shield) је апликација отвореног кода заснована на **EndpointSecurity**-ју која открива и блокира process injection. Добар је извор за утврђивање сигнала који су видљиви преко Endpoint Security-ја, пошто генерише упозорења за:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment променљиве** при извршавању процеса: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` и `ELECTRON_RUN_AS_NODE`.
- Позиве **`task_for_pid`** — један процес тражи task port другог процеса, што је предуслов за injection у њега.
- **Electron аргументе за отклањање грешака** — `--inspect`, `--inspect-brk` и `--remote-debugging-port`, који покрећу Electron апликацију у режиму за отклањање грешака и омогућавају било коме да се повеже са њом и извршава код.<sup>[[3]](#references)</sup>
- **Креирање симболичких/тврдих линкова између нивоа привилегија** — класичан примитив „постави линк као обичан корисник, усмери га на привилеговану локацију“. Имајте на уму да се **симболички линкови могу детектовати, али не и блокирати**: EndpointSecurity не открива одредиште линка пре његовог креирања.

### Позиви других процеса

У [**овом блог посту**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) можете сазнати како је могуће употребити функцију **`task_name_for_pid`** за добијање информација о другим **процесима који убацују код у неки процес**, а затим и о самом том процесу.<sup>[[4]](#references)</sup>

Имајте на уму да за позивање ове функције морате имати **исти uid** као процес који се покреће или бити **root** (она враћа информације о процесу, али не омогућава injection кода).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — детекција process injection-а у macOS-у отвореног кода (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity оквир](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — Зашто Electron апликације не могу поверљиво да чувају ваше тајне: опција --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — Детекција измена задатака](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist — Нова верзија macOS крадљивца MacSync циља ентузијасте криптовалута и програмере](https://securelist.com/macsync-new-version/121383/)
