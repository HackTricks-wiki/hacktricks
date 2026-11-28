# Nadużycia procesów w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces to instancja uruchomionego pliku wykonywalnego, jednak kodu nie wykonują procesy, lecz wątki. Dlatego **procesy są tylko kontenerami dla uruchomionych wątków**, udostępniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy uruchamiano wewnątrz innych procesów (z wyjątkiem PID 1), wywołując **`fork`**, które tworzyło dokładną kopię bieżącego procesu. Następnie **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Później wprowadzono **`vfork`**, aby przyspieszyć ten proces bez kopiowania pamięci.\
Następnie wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu i przyjmujące flagi:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektywne identyfikatory do identyfikatorów rzeczywistych
- `POSIX_SPAWN_SETPGROUP`: Ustawia przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustawia domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustawia maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonuje w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchamia proces w stanie zawieszenia
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchamia proces bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Używa alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwala na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamyka wszystkie opisy plików przy exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losuje wysokie bity przesunięcia ASLR

Ponadto `posix_spawn` akceptuje ustawienia **`posix_spawnattr`**, które kontrolują aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces kończy działanie, wysyła **kod powrotu do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym procesem nadrzędnym zostaje PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie: nadal jest widoczny na liście procesów, ale nie zużywa zasobów.

### PIDs

PID-y, czyli identyfikatory procesów, identyfikują pojedynczy proces. W XNU **PID-y** mają **64 bity**, rosną monotonicznie i **nigdy się nie zawijają** (aby zapobiegać nadużyciom).

### Grupy procesów, sesje i koalicje

**Procesy** można umieszczać w **grupach**, aby łatwiej nimi zarządzać. Na przykład polecenia w skrypcie powłoki będą należeć do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, używając na przykład kill.\
Możliwe jest również **grupowanie procesów w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne zostają do niej przypisane, chyba że same rozpoczną własną sesję.

Coalition to kolejny sposób grupowania procesów w Darwin. Dołączenie procesu do Coalition umożliwia mu dostęp do wspólnej puli zasobów, współdzielenie rejestru rozliczeniowego lub podleganie mechanizmowi Jetsam. Coalition może mieć różne role: Leader, XPC service, Extension.

### Dane uwierzytelniające i persony

Każdy proces posiada **dane uwierzytelniające**, które **określają jego uprawnienia** w systemie. Każdy proces ma jeden podstawowy `uid` i jeden podstawowy `gid` (choć może należeć do wielu grup).\
Można również zmienić identyfikator użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji służących do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia **alternatywny** zestaw **danych uwierzytelniających**. Przyjęcie persony jednocześnie przejmuje jej uid, gid i członkostwo w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:

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

## Podstawowe informacje o wątkach

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla języków C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka udostępnia funkcje potrzebne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje ona `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu, specyficzne dla jądra XNU (jądra, na którym bazuje macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
   - **Domyślny rozmiar stosu:** Domyślny rozmiar stosu nowych wątków wynosi 512 KB, co wystarcza do typowych operacji. Można go jednak zmienić za pomocą atrybutów wątku, jeśli potrzebna jest większa lub mniejsza przestrzeń.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` odgrywa kluczową rolę podczas konfiguracji wątku. Wykorzystuje argument `env[]` do parsowania zmiennych środowiskowych, które mogą zawierać informacje o lokalizacji i rozmiarze stosu.

#### Kończenie wątków w macOS

1. **Kończenie wątków:** Wątki są zazwyczaj kończone przez wywołanie `pthread_exit()`. Funkcja ta pozwala wątkowi zakończyć działanie w kontrolowany sposób, wykonać niezbędne czynności porządkowe i przekazać wartość zwracaną wątkom oczekującym na jego zakończenie.
2. **Czyszczenie wątku:** Po wywołaniu `pthread_exit()` uruchamiana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątku Mach (Mach to podsystem komunikacyjny w jądrze XNU) i wywołuje `bsdthread_terminate` — syscall usuwający struktury wątku na poziomie jądra.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i zapobiegać race condition, macOS udostępnia kilka mechanizmów synchronizacji. Są one niezbędne w środowiskach wielowątkowych, aby zapewnić integralność danych i stabilność systemu:

1. **Mutexy:**
   - **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex o rozmiarze 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
   - **Szybki mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexu, ale zoptymalizowany pod kątem szybszego działania; ma również rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
   - Służą do oczekiwania na wystąpienie określonych warunków. Mają rozmiar 44 bajtów (40 bajtów plus 4-bajtowa sygnatura).
   - **Atrybuty zmiennej warunkowej (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
   - Zapewnia, że fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Ma rozmiar 12 bajtów.
4. **Blokady odczytu i zapisu:**
   - Umożliwiają jednoczesny dostęp wielu czytelnikom albo jednemu zapisującemu, co usprawnia dostęp do współdzielonych danych.
   - **Blokada odczytu i zapisu (sygnatura: 0x52574c4b):** Ma rozmiar 196 bajtów.
   - **Atrybuty blokady odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne dla wątku (TLV)

**Zmienne lokalne dla wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych, które są specyficzne dla **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala uniknąć konfliktów i zachować integralność danych bez potrzeby stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i pokrewnych można zadeklarować zmienną lokalną dla wątku za pomocą słowa kluczowego **`__thread`**. Oto jak działa ono w poniższym przykładzie:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek nie wpłyną na `tlv_var` w innym wątku.

W pliku binarnym Mach-O dane związane ze zmiennymi lokalnymi dla wątków są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątków, takie jak ich typy i stan inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana przez zmienne lokalne dla wątków, które nie zostały jawnie zainicjalizowane. Jest to część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`**, które zarządza zmiennymi lokalnymi dla wątków w chwili zakończenia wątku. To API pozwala **zarejestrować destruktory** — specjalne funkcje czyszczące dane lokalne dla wątku, gdy wątek kończy działanie.

### Priorytety wątków

Zrozumienie priorytetów wątków wymaga przyjrzenia się temu, jak system operacyjny decyduje, które wątki i kiedy mają być uruchamiane. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W systemach macOS i Unix-like służą do tego mechanizmy takie jak `nice`, `renice` oraz klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Wartość `nice` procesu wpływa na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` nowo utworzonego procesu wynosi zazwyczaj 0.
   - Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora niż inne procesy o wyższych wartościach `nice`.
2. **Renice:**
   - `renice` to polecenie służące do zmiany wartości `nice` już działającego procesu. Pozwala dynamicznie dostosować priorytet procesów, zwiększając lub zmniejszając przydział czasu procesora w zależności od nowej wartości `nice`.
   - Jeśli proces tymczasowo potrzebuje więcej zasobów procesora, można na przykład obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, szczególnie w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają deweloperom **kategoryzować** zadania według ich ważności lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **User Interactive:**
   - Ta klasa obejmuje zadania, które w danej chwili wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobre wrażenia z użytkowania. Zadania te otrzymują najwyższy priorytet, aby interfejs pozostawał responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
   - Zadania inicjowane przez użytkownika, od których oczekuje on natychmiastowych wyników, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego obliczeń. Mają wysoki priorytet, ale niższy niż zadania klasy User Interactive.
3. **Utility:**
   - Są to zadania długotrwałe, którym zazwyczaj towarzyszy wskaźnik postępu (np. pobieranie plików lub importowanie danych). Ich priorytet jest niższy niż zadań inicjowanych przez użytkownika i nie muszą zakończyć się od razu.
4. **Background:**
   - Ta klasa obejmuje zadania działające w tle i niewidoczne dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Dzięki klasom QoS deweloperzy nie muszą zarządzać konkretnymi wartościami priorytetów. Mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje przydział zasobów procesora.

Istnieją także różne **polityki planowania wątków**, które pozwalają określić zestaw parametrów planowania branych pod uwagę przez scheduler. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Nadużycia procesów macOS

macOS udostępnia wiele mechanizmów umożliwiających **procesom wzajemną interakcję, komunikację i współdzielenie danych**. Chociaż mechanizmy te są niezbędne do normalnego działania systemu, osoby atakujące mogą nadużywać ich do injection, code execution lub uzyskiwania dostępu do danych.

### Library Injection

Library Injection to technika, w której osoba atakująca **wymusza załadowanie złośliwej biblioteki przez proces**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając osobie atakującej takie same uprawnienia i dostęp jak ten proces.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Osoba atakująca może za pomocą hooków **zmienić zachowanie** procesu, obserwować wrażliwe dane, a nawet przejąć kontrolę nad przepływem wykonania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ta strona omawia metadane unwind dla ARM64, ograniczenia PAC w arm64e oraz syntetyczne łańcuchy wywołań.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) to różne metody, za pomocą których oddzielne procesy **współdzielą i wymieniają dane**. Chociaż IPC ma podstawowe znaczenie dla działania wielu legalnych aplikacji, może być również nadużywane do omijania izolacji procesów, wycieku wrażliwych informacji lub wykonywania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplikacje Electron uruchamiane ze zmiennymi środowiskowymi o określonych wartościach mogą być podatne na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Można użyć flag `--load-extension` i `--use-fake-ui-for-media-stream`, aby przeprowadzić **man in the browser attack**, który pozwala kraść naciśnięcia klawiszy, ruch sieciowy i cookies, wstrzykiwać skrypty na stronach i nie tylko:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** oraz ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie blokuje** ponownego uruchomienia już uruchomionej aplikacji, jeśli **zmodyfikowano plik NIB**. Można więc wykorzystać je do uruchamiania dowolnych poleceń przez dowolne programy:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Można wstrzyknąć opcje JVM za pomocą **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`** i załadować agenta Java lub natywnego agenta przed uruchomieniem aplikacji.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** wczytuje wstępnie złośliwy kod JavaScript za pomocą `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Możliwe jest wstrzyknięcie kodu do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`**, który uruchamia kod przed `Main`, albo przez nadużycie funkcji debugowania .NET, jeśli spełnione są jej wymagania wstępne.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nieinteraktywny Bash odczytuje **`BASH_ENV`**; interaktywne powłoki POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację z lokalizacji wskazanych przez **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każda z tych powłok może wykonać kontrolowany plik startowy przed zamierzonym poleceniem. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`** za każdym razem, gdy włączone jest xtrace (np. przez odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Uruchomienie `/bin/zsh -s` powoduje, że powłoka odczytuje program ze standardowego wejścia. Downloader, który kopiuje niezaufany dokument o ustrukturyzowanej treści do stdin procesu potomnego bez wcześniejszego parsowania, zamienia więc cały dokument w kod źródłowy powłoki. W jednym zaobserwowanym przypadku loader odczytywał linia po linii publiczny plik iCalendar przez anonimowy potok. Metadane kalendarza nie były poprawnymi poleceniami, ale zsh kontynuował działanie aż do napotkania wykonywalnych wierszy umieszczonych po `DESCRIPTION:`. Te wiersze pobierały i uruchamiały kolejny pakiet aplikacji. Oczekiwany typ zawartości i zaufany hosting nie czyniły tego bezpiecznym; niebezpieczną granicą było przekazanie bajtów do interpretera.<sup>[[5]](#references)</sup>

Powiązane etapy opisano w sekcjach [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper i kwarantanna](../macos-security-protections/macos-gatekeeper.md) oraz [lokalizacje automatycznego uruchamiania macOS](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** może wczytać kontrolowaną konfigurację PHP, której **`auto_prepend_file`** wykona się przed docelowym skryptem.

[Konfiguracja PHP i injection podczas uruchamiania za pomocą `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Samodzielny interpreter Lua wykonuje kod lub plik `@file` ze zmiennej **`LUA_INIT`** (albo jej wariantu zależnego od wersji) przed przetworzeniem docelowego skryptu.

[Injection podczas uruchamiania Lua za pomocą `LUA_INIT` (plik i kod inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** wskazują profile startowe zawierające kod R. Z kolei **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** wraz ze ścieżką do biblioteki R mogą automatycznie załadować zainstalowany pakiet.

[Profile startowe R i ładowanie pakietów](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** zmienia ścieżkę do depot, z którego automatycznie wykonywany jest plik `config/startup.jl`.

[Injection za pomocą `JULIA_DEPOT_PATH` i `startup.jl` w Julii](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** lub **`ERL_ZFLAGS`** mogą wstrzyknąć wyrażenie Erlang VM **`-eval`** bez konieczności użycia pliku z payloadem; obciążenia Elixira często uruchamiają tę samą maszynę wirtualną.

[Injection za pomocą flag VM Erlang/Elixir](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** przekierowują do skryptów startowych Octave.

[Injection za pomocą plików startowych GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` to wieloplatformowa aplikacja .NET, więc kilka zmiennych środowiskowych umożliwia wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje do skryptów profilu uruchamianych przy starcie, **`PSModulePath`** umożliwia przejęcie automatycznego ładowania modułów (umieszczony plik `.psm1` wykonuje się podczas importowania i może przesłonić wbudowane cmdlety), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** wczytują kod osoby atakującej do procesu przed `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne sposoby na uruchomienie przez skrypt Perl dowolnego kodu:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Można również nadużyć zmiennych środowiskowych Ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby dowolne skrypty wykonywały dowolny kod:


[Opcje loadera Ruby `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Łańcuch **`PYTHONWARNINGS`** i **`BROWSER`** z biblioteki standardowej może wykonać polecenie podczas parsowania filtrów ostrzeżeń. Alternatywny wariant oparty na pliku umieszcza `sitecustomize.py` w ścieżce **`PYTHONPATH`**, dzięki czemu standardowa inicjalizacja `site` zaimportuje go przed docelowym skryptem. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję/moduł, gdy kod dojdzie do `breakpoint()`.

W CPython 3.13+ **`PYTHONINSPECT`** może również uruchomić plik **`PYTHONSTARTUP`** po wykonaniu skryptu, gdy PyREPL uruchamia się w terminalu.<sup>[[6]](#references)</sup>

Pamiętaj, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają z użyciem wbudowanego Pythona.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (oraz używana jako fallback zmienna `EXINIT`) jest wykonywana jako polecenia Ex podczas zwykłego uruchamiania. Dlatego `:!cmd` / `:call system(...)` umożliwia code execution, gdy ofiara otworzy Vim/Neovim w kontrolowanym środowisku:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Niezależnie od tego Homebrew często instaluje Pythona w `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą mieć możliwość podmiany programu uruchamiającego. Jest to przejęcie zapisywalnego pliku binarnego, a nie injection przez zmienną środowiskową; przed uznaniem tego za podatność sprawdź właściciela i ACL.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje process injection. Jest dobrym źródłem informacji o sygnałach widocznych przez Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmiennych środowiskowych używanych do injection** podczas uruchamiania procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — sytuacji, w której jeden proces żąda portu task innego procesu, co jest warunkiem wstępnym do wykonania injection.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i umożliwiają dowolnej osobie podłączenie się do niej oraz uruchamianie w niej kodu.<sup>[[3]](#references)</sup>
- **Tworzenia symlinków/hardlinków między poziomami uprawnień** — klasycznej techniki „utwórz link jako zwykły użytkownik i wskaż nim uprzywilejowaną lokalizację”. Pamiętaj, że **symlinki można wykrywać, ale nie można ich blokować**: EndpointSecurity nie udostępnia miejsca docelowego linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) opisano, jak można użyć funkcji **`task_name_for_pid`**, aby uzyskać informacje o innych **procesach wstrzykujących kod do procesu**, a następnie dowiedzieć się więcej o tym innym procesie.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz mieć **ten sam uid** co proces lub działać jako **root** (funkcja zwraca informacje o procesie, ale nie umożliwia wstrzyknięcia kodu).



## References

- [1] [Shield — wykrywanie process injection w macOS w projekcie open source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — Dlaczego aplikacje Electron nie mogą przechowywać twoich sekretów w poufny sposób: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — Wykrywanie modyfikacji task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist — Nowa wersja macOS stealera MacSync atakuje entuzjastów kryptowalut i deweloperów](https://securelist.com/macsync-new-version/121383/)
- [6] [Wiersz poleceń i środowisko Pythona — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
