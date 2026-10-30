# Nadużywanie procesów w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces to instancja uruchomionego pliku wykonywalnego, jednak procesy nie wykonują kodu — robią to wątki. Dlatego **procesy są po prostu kontenerami dla uruchomionych wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane wewnątrz innych procesów (z wyjątkiem PID 1) przez wywołanie **`fork`**, które tworzyło dokładną kopię bieżącego procesu, a następnie **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Następnie wprowadzono **`vfork`**, aby przyspieszyć ten proces przez wyeliminowanie kopiowania pamięci.\
Potem wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu i przyjmujące flagi:

- `POSIX_SPAWN_RESETIDS`: Przywraca efektywne identyfikatory do wartości rzeczywistych
- `POSIX_SPAWN_SETPGROUP`: Ustawia przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustawia domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustawia maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonuje `exec` w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchamia proces w stanie wstrzymania
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchamia bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Używa alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwala na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamyka wszystkie deskryptory plików przy wywołaniu exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losuje wysokie bity przesunięcia ASLR

Ponadto `posix_spawn` przyjmuje ustawienia **`posix_spawnattr`**, które kontrolują różne aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces kończy działanie, wysyła **kod zwrotny do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym procesem nadrzędnym zostaje PID 1) wraz z sygnałem `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie — nadal jest widoczny na liście procesów, ale nie zużywa zasobów.

### Identyfikatory PID

PID-y, czyli identyfikatory procesów, identyfikują unikatowy proces. W XNU **PID-y** mają **64 bity**, są przydzielane monotonicznie i **nigdy się nie zawijają** (aby zapobiegać nadużyciom).

### Grupy procesów, sesje i koalicje

**Procesy** można łączyć w **grupy**, aby ułatwić zarządzanie nimi. Na przykład polecenia w skrypcie powłoki należą do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, na przykład za pomocą `kill`.\
Można też **grupować procesy w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne są do niej przypisywane, chyba że rozpoczną własną sesję.

Koalicja to kolejny sposób grupowania procesów w Darwin. Proces dołączający do koalicji uzyskuje dostęp do wspólnej puli zasobów, współdzieli księgę rozliczeniową lub podlega mechanizmowi Jetsam. Koalicje mają różne role: lider, usługa XPC, rozszerzenie.

### Poświadczenia i persony

Każdy proces posiada **poświadczenia**, które **określają jego uprawnienia** w systemie. Każdy proces ma jeden podstawowy `uid` i jeden podstawowy `gid` (choć może należeć do kilku grup).\
Można też zmienić identyfikator użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji służących do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia alternatywny zestaw **poświadczeń**. Przyjęcie persony powoduje jednoczesne przyjęcie jej `uid`, `gid` i członkostwa w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:

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

1. **POSIX Threads (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka udostępnia funkcje niezbędne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje ona `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu, specyficzne dla jądra XNU (jądra, na którym bazuje macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
   - **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB. Jest to wystarczające dla typowych operacji, ale można go zmienić za pomocą atrybutów wątku, jeśli potrzebna jest większa lub mniejsza przestrzeń.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` odgrywa kluczową rolę podczas konfigurowania wątku. Wykorzystuje argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o lokalizacji i rozmiarze stosu.

#### Kończenie działania wątku w macOS

1. **Kończenie wątków:** Wątki są zwykle kończone przez wywołanie `pthread_exit()`. Ta funkcja pozwala wątkowi zakończyć działanie w uporządkowany sposób, wykonać niezbędne operacje porządkowe i przekazać wartość zwrotną wątkom oczekującym na jego zakończenie.
2. **Sprzątanie po wątku:** Po wywołaniu `pthread_exit()` uruchamiana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątków Mach (Mach to podsystem komunikacyjny w jądrze XNU) i wywołuje `bsdthread_terminate`, czyli syscall usuwający struktury na poziomie jądra powiązane z wątkiem.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać race conditions, macOS udostępnia kilka prymitywów synchronizacji. Są one kluczowe w środowiskach wielowątkowych, ponieważ zapewniają integralność danych i stabilność systemu:

1. **Mutexy:**
   - **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex o rozmiarze 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
   - **Fast mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexa, ale zoptymalizowany pod kątem szybszego działania; również ma rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
   - Służą do oczekiwania na wystąpienie określonych warunków; mają rozmiar 44 bajtów (40 bajtów plus 4-bajtowa sygnatura).
   - **Atrybuty zmiennej warunkowej (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
   - Zapewnia, że dany fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Jej rozmiar wynosi 12 bajtów.
4. **Blokady odczytu i zapisu:**
   - Umożliwiają jednoczesny dostęp wielu czytelnikom lub jednemu zapisującemu, zapewniając wydajny dostęp do współdzielonych danych.
   - **Blokada odczytu i zapisu (sygnatura: 0x52574c4b):** Ma rozmiar 196 bajtów.
   - **Atrybuty blokady odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne dla wątku (TLV)

**Zmienne lokalne dla wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych przypisanych do **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala unikać konfliktów i zachować integralność danych bez potrzeby stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i pokrewnych możesz zadeklarować zmienną lokalną dla wątku za pomocą słowa kluczowego **`__thread`**. Oto jak działa to w podanym przykładzie:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek nie wpłyną na `tlv_var` w innym wątku.

W pliku binarnym Mach-O dane powiązane ze zmiennymi lokalnymi dla wątków są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątków, takie jak ich typy i stan inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych lokalnych dla wątków, które nie zostały jawnie zainicjalizowane. Jest to obszar pamięci przeznaczony na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`**, które zarządza zmiennymi lokalnymi dla wątków podczas kończenia działania wątku. To API umożliwia **rejestrowanie destruktorów** — specjalnych funkcji czyszczących dane lokalne dla wątku po jego zakończeniu.

### Priorytety wątków

Aby zrozumieć priorytety wątków, trzeba przyjrzeć się temu, jak system operacyjny decyduje, które wątki i kiedy uruchamiać. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych wykorzystuje się do tego pojęcia takie jak `nice`, `renice` i klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` nowo utworzonego procesu wynosi zazwyczaj 0.
   - Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora niż procesy o wyższych wartościach `nice`.
2. **Renice:**
   - `renice` to polecenie służące do zmiany wartości `nice` już działającego procesu. Umożliwia dynamiczne dostosowanie priorytetu procesów, a tym samym zwiększenie lub zmniejszenie przydzielanego im czasu procesora.
   - Jeśli na przykład proces tymczasowo potrzebuje więcej zasobów procesora, można obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, stosowane zwłaszcza w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** zadania według ich ważności lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas:

1. **User Interactive:**
   - Ta klasa jest przeznaczona dla zadań, które aktualnie wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych rezultatów, aby zapewnić dobre wrażenia z użytkowania. Zadania te otrzymują najwyższy priorytet, co pozwala zachować responsywność interfejsu (np. podczas animacji lub obsługi zdarzeń).
2. **User Initiated:**
   - Zadania inicjowane przez użytkownika, który oczekuje natychmiastowych rezultatów, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego obliczeń. Mają wysoki priorytet, ale niższy niż zadania interaktywne.
3. **Utility:**
   - Są to zadania długotrwałe, którym zazwyczaj towarzyszy wskaźnik postępu (np. pobieranie plików lub importowanie danych). Mają niższy priorytet niż zadania inicjowane przez użytkownika i nie muszą zakończyć się natychmiast.
4. **Background:**
   - Ta klasa obejmuje zadania wykonywane w tle, niewidoczne dla użytkownika, takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Dzięki klasom QoS programiści nie muszą zarządzać konkretnymi wartościami priorytetów, lecz mogą skupić się na charakterze zadania. System odpowiednio optymalizuje wykorzystanie zasobów procesora.

Istnieją również różne **polityki planowania wątków**, które pozwalają przepływom określać zestaw parametrów planowania branych pod uwagę przez planistę. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Nadużycia procesów macOS

macOS udostępnia wiele mechanizmów, dzięki którym **procesy mogą wchodzić ze sobą w interakcje, komunikować się i współdzielić dane**. Choć mechanizmy te są niezbędne do prawidłowego działania systemu, atakujący mogą nadużywać ich do wstrzykiwania kodu, jego wykonywania lub uzyskiwania dostępu do danych.

### Library Injection

Library Injection to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając atakującemu takie same uprawnienia i dostęp jak temu procesowi.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Dzięki hookowaniu funkcji atakujący może **modyfikować zachowanie** procesu, obserwować poufne dane, a nawet przejąć kontrolę nad przepływem wykonania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ta strona omawia metadane unwind dla ARM64, ograniczenia PAC w arm64e oraz syntetyczne łańcuchy wywołań.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) obejmuje różne metody, dzięki którym odrębne procesy **współdzielą i wymieniają dane**. IPC jest podstawą działania wielu legalnych aplikacji, ale można go również nadużywać do obejścia izolacji procesów, wycieku poufnych informacji lub wykonywania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na wstrzykiwanie do procesu:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Można użyć flag `--load-extension` i `--use-fake-ui-for-media-stream`, aby przeprowadzić **man in the browser attack**, który umożliwia kradzież naciśnięć klawiszy, ruchu sieciowego i cookies oraz wstrzykiwanie skryptów na stronach:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie blokuje** ponownego uruchomienia już uruchomionej aplikacji, jeśli **zmodyfikowano plik NIB**. Można więc wykorzystać je do uruchamiania dowolnych poleceń przez dowolne programy:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Można wstrzyknąć opcje JVM za pomocą **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`** i załadować agenta Java lub natywnego agenta przed uruchomieniem aplikacji.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** wczytuje JavaScript atakującego przed uruchomieniem, używając `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Można wstrzyknąć kod do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`** przed wywołaniem `Main` albo nadużyć funkcji debugowania .NET, jeśli spełnione są jej wymagania wstępne.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nieinteraktywny Bash odczytuje **`BASH_ENV`**; interaktywne powłoki POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację z **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każda z tych powłok może wykonać kontrolowany plik startowy przed zamierzonym poleceniem. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`** za każdym razem, gdy włączony jest xtrace (np. przez odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Uruchomienie `/bin/zsh -s` powoduje, że powłoka odczytuje program ze standardowego wejścia. Downloader, który kopiuje niezaufany dokument o ustrukturyzowanej treści na standardowe wejście procesu potomnego bez uprzedniego parsowania, zmienia więc cały dokument w kod źródłowy powłoki. Jeden z zaobserwowanych loaderów przesyłał publiczny plik iCalendar anonimowym potokiem, linia po linii. Metadane kalendarza nie działały jako polecenia, ale zsh kontynuował działanie aż do napotkania wykonywalnych wierszy umieszczonych za `DESCRIPTION:`. Wiersze te pobierały i uruchamiały kolejny pakiet aplikacji. Oczekiwany typ zawartości nośnika ani zaufany hosting nie zapewniały bezpieczeństwa; niebezpieczną granicą było przekazanie jego bajtów interpreterowi.<sup>[[5]](#references)</sup>

Powiązane etapy opisano w sekcjach [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) oraz [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** mogą wczytać kontrolowaną konfigurację PHP, której **`auto_prepend_file`** wykonuje się przed skryptem docelowym.

[Wstrzykiwanie podczas uruchamiania za pomocą konfiguracji PHP i `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Samodzielny interpreter Lua wykonuje kod lub plik `@file` z **`LUA_INIT`** (lub jego wariantu zależnego od wersji) przed przetworzeniem skryptu docelowego.

[Wstrzykiwanie podczas uruchamiania za pomocą Lua `LUA_INIT` (plik i kod inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** przekierowują do profili startowych zawierających kod R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** wraz ze ścieżką do biblioteki R mogą z kolei powodować automatyczne wczytanie zainstalowanego pakietu.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** przekierowuje do depot, z którego automatycznie wykonywany jest plik `config/startup.jl`.

[Wstrzykiwanie za pomocą Julia `JULIA_DEPOT_PATH` i `startup.jl`](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** lub **`ERL_ZFLAGS`** mogą wstrzyknąć wyrażenie Erlang VM **`-eval`** bez konieczności użycia pliku z payloadem; obciążenia Elixir często uruchamiają tę samą maszynę wirtualną.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** przekierowują do skryptów startowych Octave.

[Wstrzykiwanie za pomocą skryptów startowych GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` to wieloplatformowa aplikacja .NET, więc kilka zmiennych środowiskowych umożliwia wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje do skryptów profilu uruchamianych podczas startu, **`PSModulePath`** umożliwia przejęcie automatycznego ładowania modułów (umieszczony tam plik `.psm1` wykonuje się podczas importu i może przesłonić wbudowane polecenia cmdlet), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** wczytują kod atakującego do procesu przed wywołaniem `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne sposoby na to, aby skrypt Perl wykonał dowolny kod:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Można również nadużyć zmiennych środowiskowych ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby dowolne skrypty wykonywały dowolny kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Łańcuch wykorzystujący standardowe biblioteki **`PYTHONWARNINGS`** i **`BROWSER`** może wykonać polecenie podczas parsowania filtrów ostrzeżeń. Alternatywną metodą, wymagającą pliku, jest umieszczenie `sitecustomize.py` w ścieżce **`PYTHONPATH`**, dzięki czemu normalna inicjalizacja `site` zaimportuje go przed skryptem docelowym. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję lub moduł, gdy kod dojdzie do `breakpoint()`. Zmienne przeznaczone wyłącznie do trybu interaktywnego, takie jak **`PYTHONSTARTUP`**, mają węższe zastosowanie.

Zwróć uwagę, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają z osadzonym Pythonem.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (a w razie jego braku `EXINIT`) są wykonywane jako polecenia Ex podczas zwykłego uruchamiania. Dlatego `:!cmd` / `:call system(...)` umożliwiają wykonanie kodu, gdy ofiara otworzy Vim/Neovim w kontrolowanym środowisku:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ponadto Homebrew często instaluje Pythona w katalogu `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą mieć możliwość podmiany programu uruchamiającego. Jest to przejęcie zapisywalnego pliku binarnego, a nie wstrzyknięcie przez zmienną środowiskową; przed uznaniem tego za podatność sprawdź właściciela i listy ACL.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje wstrzykiwanie do procesów. Jest dobrym źródłem informacji o sygnałach obserwowalnych za pomocą Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmiennych środowiskowych służących do wstrzykiwania** podczas uruchamiania procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — sytuacji, w której jeden proces prosi o port zadaniowy innego procesu, co jest warunkiem wstępnym wstrzyknięcia do niego kodu.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania, umożliwiając dowolnej osobie podłączenie się do niej i wykonanie w niej kodu.<sup>[[3]](#references)</sup>
- **Tworzenia symlinków/hardlinków między poziomami uprawnień** — klasycznego schematu „utwórz link jako zwykły użytkownik i wskaż nim uprzywilejowaną lokalizację”. Pamiętaj, że **symlinki można wykrywać, ale nie blokować**: EndpointSecurity nie udostępnia celu linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) opisano, jak za pomocą funkcji **`task_name_for_pid`** można uzyskać informacje o innych **procesach wstrzykujących kod do procesu**, a następnie zebrać informacje o tych procesach.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz mieć **ten sam uid** co użytkownik uruchamiający proces albo być **rootem** (funkcja zwraca informacje o procesie, ale nie umożliwia wstrzyknięcia kodu).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — wykrywanie wstrzykiwania do procesów macOS w ramach open source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — Dlaczego aplikacje Electron nie mogą przechowywać poufnie twoich sekretów: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — Wykrywanie modyfikacji zadań](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist — Nowa wersja złodzieja danych MacSync dla macOS atakuje entuzjastów kryptowalut i programistów](https://securelist.com/macsync-new-version/121383/)
