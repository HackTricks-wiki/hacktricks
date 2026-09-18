# Nadużywanie procesów macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces jest instancją uruchomionego pliku wykonywalnego, jednak procesy nie wykonują kodu — robią to wątki. Dlatego **procesy są tylko kontenerami dla uruchomionych wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane wewnątrz innych procesów (z wyjątkiem PID 1) przez wywołanie **`fork`**, które tworzyło dokładną kopię bieżącego procesu, po czym **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Następnie wprowadzono **`vfork`**, aby przyspieszyć ten proces bez kopiowania pamięci.\
Później wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu oraz przyjmujące flagi:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektywne identyfikatory do rzeczywistych identyfikatorów
- `POSIX_SPAWN_SETPGROUP`: Ustawia przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustawia domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustawia maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonuje exec w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchamia w stanie wstrzymania
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchamia bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Używa alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwala na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamyka wszystkie deskryptory plików przy exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losowo ustawia starsze bity przesunięcia ASLR

Ponadto `posix_spawn` przyjmuje ustawienia **`posix_spawnattr`**, które kontrolują aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces kończy działanie, wysyła **kod zwrotny do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym procesem nadrzędnym zostaje PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie, w którym nadal jest widoczny na liście, ale nie zużywa zasobów.

### PIDs

PIDs, czyli identyfikatory procesów, identyfikują jeden unikatowy proces. W XNU **PIDs** mają długość **64 bitów**, zwiększają się monotonicznie i **nigdy się nie zawijają** (aby zapobiegać nadużyciom).

### Grupy procesów, sesje i coalations

**Procesy** można umieszczać w **grupach**, aby ułatwić zarządzanie nimi. Na przykład polecenia w skrypcie powłoki będą należeć do tej samej grupy procesów, dzięki czemu można je **sygnalizować jednocześnie**, na przykład za pomocą kill.\
Możliwe jest również **grupowanie procesów w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne zostają umieszczone w tej sesji, chyba że rozpoczną własną sesję.

Coalition to kolejny sposób grupowania procesów w Darwin. Dołączenie procesu do coalition pozwala mu uzyskać dostęp do puli zasobów, współdzielić ledger lub podlegać mechanizmowi Jetsam. Coalitions mają różne role: Leader, XPC service, Extension.

### Dane uwierzytelniające i personae

Każdy proces posiada **dane uwierzytelniające**, które **identyfikują jego uprawnienia** w systemie. Każdy proces ma jeden główny `uid` i jeden główny `gid` (choć może należeć do kilku grup).\
Możliwa jest również zmiana identyfikatora użytkownika i grupy, jeśli plik wykonywalny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji służących do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia alternatywny zestaw **danych uwierzytelniających**. Przyjęcie persony oznacza jednoczesne przyjęcie jej uid, gid i członkostwa w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:
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

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla języków C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Biblioteka ta udostępnia funkcje niezbędne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie funkcja ta wywołuje `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu specyficzne dla kernela XNU (kernela, na którym bazuje macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
- **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB, co wystarcza do typowych operacji, ale można go dostosować za pomocą atrybutów wątku, jeśli potrzebna jest większa lub mniejsza przestrzeń.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` ma kluczowe znaczenie podczas konfiguracji wątku. Wykorzystuje argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o lokalizacji i rozmiarze stosu.

#### Kończenie wątków w macOS

1. **Kończenie wątków:** Wątki są zazwyczaj kończone przez wywołanie `pthread_exit()`. Funkcja ta umożliwia bezpieczne zakończenie wątku, wykonanie niezbędnego sprzątania oraz przekazanie wartości zwrotnej wątkom oczekującym na jego zakończenie.
2. **Sprzątanie wątku:** Po wywołaniu `pthread_exit()` wywoływana jest funkcja `pthread_terminate()`, która obsługuje usunięcie wszystkich powiązanych struktur wątku. Dealokuje porty wątków Mach (Mach to podsystem komunikacyjny w kernelu XNU) i wywołuje `bsdthread_terminate` — syscall usuwający struktury na poziomie kernela powiązane z wątkiem.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać race conditions, macOS udostępnia kilka prymitywów synchronizacji. Są one kluczowe w środowiskach wielowątkowych, ponieważ zapewniają integralność danych i stabilność systemu:

1. **Mutexy:**
- **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex zajmujący 60 bajtów pamięci (56 bajtów na mutex i 4 bajty na sygnaturę).
- **Szybki mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexu, ale zoptymalizowany pod kątem szybszego działania; również ma rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
- Służą do oczekiwania na wystąpienie określonych warunków; ich rozmiar wynosi 44 bajty (40 bajtów plus 4-bajtowa sygnatura).
- **Atrybuty zmiennej warunkowej (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
- Zapewnia, że fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Jej rozmiar wynosi 12 bajtów.
4. **Blokady odczytu i zapisu:**
- Umożliwiają jednoczesny dostęp wielu czytelnikom albo dostęp jednego writera, ułatwiając wydajny dostęp do współdzielonych danych.
- **Blokada odczytu i zapisu (sygnatura: 0x52574c4b):** Ma rozmiar 196 bajtów.
- **Atrybuty blokady odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania overflowów.

### Zmienne lokalne wątku (TLV)

**Zmienne lokalne wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych specyficznych dla **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala unikać konfliktów i zachować integralność danych bez konieczności korzystania z jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i pokrewnych można zadeklarować zmienną lokalną wątku za pomocą słowa kluczowego **`__thread`**. Oto jak działa ono w poniższym przykładzie:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ten fragment definiuje `tlv_var` jako zmienną thread-local. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany dokonane przez jeden wątek w `tlv_var` nie wpłyną na `tlv_var` w innym wątku.

W pliku binarnym Mach-O dane związane ze zmiennymi thread-local są uporządkowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych thread-local, takie jak ich typy i stan inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych thread-local, które nie zostały jawnie zainicjalizowane. Jest to część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`** do zarządzania zmiennymi thread-local podczas kończenia wątku. To API umożliwia **rejestrowanie destruktorów** — specjalnych funkcji, które czyszczą dane thread-local po zakończeniu wątku.

### Priorytety wątków

Zrozumienie priorytetów wątków wymaga przyjrzenia się temu, jak system operacyjny decyduje, które wątki uruchamiać i kiedy. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksowych odbywa się to z użyciem takich pojęć jak `nice`, `renice` oraz klas Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
- Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` podczas tworzenia procesu wynosi zazwyczaj 0.
- Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora w porównaniu z innymi procesami o wyższych wartościach `nice`.
2. **Renice:**
- `renice` to polecenie używane do zmiany wartości `nice` już uruchomionego procesu. Można go używać do dynamicznego dostosowywania priorytetu procesów, zwiększając lub zmniejszając przydział czasu procesora na podstawie nowych wartości `nice`.
- Jeśli na przykład proces tymczasowo potrzebuje większych zasobów procesora, można obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, szczególnie w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają deweloperom **kategoryzować** zadania według różnych poziomów, na podstawie ich ważności lub pilności. macOS automatycznie zarządza priorytetyzacją wątków na podstawie tych klas QoS:

1. **User Interactive:**
- Ta klasa jest przeznaczona dla zadań, które aktualnie wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobre doświadczenie użytkownika. Zadania te otrzymują najwyższy priorytet, aby interfejs pozostał responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
- Zadania inicjowane przez użytkownika, dla których oczekuje on natychmiastowych wyników, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego wykonania obliczeń. Mają wysoki priorytet, ale niższy niż User Interactive.
3. **Utility:**
- Są to zadania długotrwałe, które zazwyczaj wyświetlają wskaźnik postępu (np. pobieranie plików lub importowanie danych). Mają niższy priorytet niż zadania inicjowane przez użytkownika i nie muszą zakończyć się natychmiast.
4. **Background:**
- Ta klasa jest przeznaczona dla zadań działających w tle i niewidocznych dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Korzystając z klas QoS, deweloperzy nie muszą zarządzać dokładnymi wartościami priorytetów, lecz mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje zasoby procesora.

Ponadto istnieją różne **polityki planowania wątków**, które pozwalają określić zestaw parametrów planowania uwzględnianych przez scheduler. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Nadużywanie procesów macOS

macOS udostępnia wiele mechanizmów umożliwiających **procesom interakcję, komunikację i współdzielenie danych**. Chociaż mechanizmy te są niezbędne do prawidłowego działania systemu, atakujący mogą je wykorzystywać do injection, code execution lub uzyskiwania dostępu do danych.

### Library Injection

Library Injection to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po injection biblioteka działa w kontekście procesu docelowego, zapewniając atakującemu takie same uprawnienia i dostęp jak procesowi.

{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Dzięki hookingowi funkcji atakujący może **modyfikować zachowanie** procesu, obserwować poufne dane, a nawet przejąć kontrolę nad przepływem wykonania.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) odnosi się do różnych metod, za pomocą których oddzielne procesy **współdzielą i wymieniają dane**. Chociaż IPC ma podstawowe znaczenie dla wielu legalnych aplikacji, może być również niewłaściwie wykorzystywane do omijania izolacji procesów, wycieku poufnych informacji lub wykonywania nieautoryzowanych działań.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na process injection:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Możliwe jest użycie flag `--load-extension` i `--use-fake-ui-for-media-stream` do przeprowadzenia **man in the browser attack**, umożliwiającego kradzież naciśnięć klawiszy, przechwytywanie ruchu i cookies oraz injection skryptów na stronach:

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** oraz ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie powstrzymuje** już uruchomionej aplikacji przed ponownym uruchomieniem, jeśli **plik NIB zostanie zmodyfikowany**. Dlatego można ich użyć do spowodowania, aby dowolne programy wykonywały dowolne polecenia:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Możliwe jest wstrzyknięcie opcji JVM za pośrednictwem **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`** oraz załadowanie agenta Java lub native przed uruchomieniem aplikacji.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** ładuje wstępnie JavaScript atakującego za pomocą `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza wszystkie te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Możliwe jest wstrzyknięcie kodu do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`** przed `Main` lub przez nadużycie funkcji debugowania .NET, gdy spełnione są jej wymagania wstępne.

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nieinteraktywny Bash odczytuje **`BASH_ENV`**; interaktywne shelle POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację znajdującą się poniżej **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każdy z nich może wykonać kontrolowany plik startowy przed zamierzonym poleceniem. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`** za każdym razem, gdy włączone jest xtrace (np. odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** mogą załadować kontrolowaną konfigurację PHP, której **`auto_prepend_file`** zostanie wykonane przed docelowym skryptem.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samodzielny interpreter Lua wykonuje kod lub plik `@file` z **`LUA_INIT`** (albo jego wariantu zależnego od wersji) przed przetworzeniem docelowego skryptu.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** przekierowują profile startowe zawierające kod R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** wraz ze ścieżką biblioteki R mogą zamiast tego automatycznie załadować zainstalowany pakiet.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** przekierowuje depot, którego `config/startup.jl` jest automatycznie wykonywany.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** lub **`ERL_ZFLAGS`** mogą wstrzyknąć wyrażenie Erlang VM **`-eval`** bez konieczności użycia pliku z payloadem; obciążenia Elixir zazwyczaj uruchamiają tę samą VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** przekierowują skrypty startowe Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` jest wieloplatformową aplikacją .NET, dlatego kilka zmiennych środowiskowych umożliwia wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje skrypty profilu uruchamiane podczas startu, **`PSModulePath`** przejmuje automatyczne ładowanie modułów (podstawiony plik `.psm1` jest wykonywany podczas importu i może przesłaniać wbudowane cmdlety), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** oraz **`DOTNET_STARTUP_HOOKS`** ładują kod atakującego do procesu przed `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne opcje umożliwiające skryptowi Perl wykonanie dowolnego kodu w:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Możliwe jest również nadużycie zmiennych środowiskowych Ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby dowolne skrypty wykonywały dowolny kod:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Standard-library chain **`PYTHONWARNINGS`** i **`BROWSER`** może wykonać polecenie podczas parsowania filtrów ostrzeżeń. Alternatywa oparta na pliku umieszcza `sitecustomize.py` w **`PYTHONPATH`**, dzięki czemu podczas zwykłej inicjalizacji `site` zostaje on zaimportowany przed docelowym skryptem. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję/moduł, gdy kod dociera do `breakpoint()`. Zmienne przeznaczone wyłącznie do trybu interaktywnego, takie jak **`PYTHONSTARTUP`**, mają węższe zastosowanie.

Pamiętaj, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają z użyciem embedded python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (oraz jego fallback **`EXINIT`**) są wykonywane jako polecenia Ex podczas normalnego startu, dlatego `:!cmd` / `:call system(...)` umożliwiają code execution, gdy ofiara otworzy Vim/Neovim ze kontrolowanym środowiskiem:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Niezależnie od tego Homebrew często instaluje Python poniżej `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą być w stanie zastąpić launcher. Jest to przejęcie zapisywalnego pliku binarnego, a nie injection za pośrednictwem zmiennej środowiskowej; przed uznaniem tego za podatność należy sprawdzić właściciela i ACL.

## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje process injection. Jest dobrym punktem odniesienia dla sygnałów obserwowalnych za pośrednictwem Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmienne środowiskowe injection** podczas exec procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` oraz `ELECTRON_RUN_AS_NODE`.
- Wywołania **`task_for_pid`** — jeden proces żąda portu task innego procesu, co jest wymaganiem wstępnym do wykonania injection.
- **Argumenty debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają każdemu dołączyć do niej oraz wykonywać w niej kod.<sup>[[3]](#references)</sup>
- **Tworzenie symlinków/hardlinków między poziomami uprawnień** — klasyczny mechanizm „umieść link jako zwykły użytkownik i wskaż go na uprzywilejowaną lokalizację”. Należy pamiętać, że **symlinki można objąć alertami, ale nie można ich zablokować**: EndpointSecurity nie udostępnia miejsca docelowego linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) opisano, jak można użyć funkcji **`task_name_for_pid`** do uzyskania informacji o innych **procesach wstrzykujących kod do procesu**, a następnie uzyskać informacje o tym drugim procesie.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz mieć **ten sam uid**, co użytkownik uruchamiający proces, albo być **rootem** (zwraca ona informacje o procesie, a nie sposób na wykonanie code injection).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Dlaczego aplikacje Electron nie mogą poufnie przechowywać sekretów: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Wykrywanie modyfikacji task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
