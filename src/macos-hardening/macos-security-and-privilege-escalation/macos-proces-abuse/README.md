# Nadużycia procesów w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces to instancja działającego pliku wykonywalnego, jednak procesy nie wykonują kodu — robią to wątki. Dlatego **procesy są jedynie kontenerami dla działających wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane wewnątrz innych procesów (z wyjątkiem PID 1) przez wywołanie **`fork`**, które tworzy dokładną kopię bieżącego procesu. Następnie **proces potomny** zwykle wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Później wprowadzono **`vfork`**, aby przyspieszyć ten proces, eliminując kopiowanie pamięci.\
Następnie wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu i przyjmujące flagi:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektywne identyfikatory do rzeczywistych identyfikatorów
- `POSIX_SPAWN_SETPGROUP`: Ustawia przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustawia domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustawia maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonuje program w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchamia proces w stanie wstrzymania
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchamia proces bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Używa alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwala na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamyka wszystkie deskryptory plików przy wywołaniu exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losuje wysokie bity przesunięcia ASLR

Ponadto `posix_spawn` przyjmuje ustawienia **`posix_spawnattr`**, które kontrolują różne aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces kończy działanie, wysyła **kod zwrotny do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym rodzicem zostaje PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie — nadal jest widoczny na liście procesów, ale nie zużywa zasobów.

### PID-y

PID-y (identyfikatory procesów) identyfikują unikatowy proces. W XNU **PID-y** mają **64 bity**, rosną monotonicznie i **nigdy się nie zawijają** (aby zapobiegać nadużyciom).

### Grupy procesów, sesje i koalicje

**Procesy** można łączyć w **grupy**, aby łatwiej nimi zarządzać. Na przykład polecenia w skrypcie powłoki będą należeć do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, na przykład za pomocą kill.\
Można również **łączyć procesy w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne zostają przypisane do tej sesji, chyba że same rozpoczną własną sesję.

Koalicja to kolejny sposób grupowania procesów w Darwin. Dołączenie procesu do koalicji umożliwia mu dostęp do puli zasobów, współdzielenie księgi rozliczeniowej lub podleganie mechanizmowi Jetsam. Koalicje mają różne role: lider, usługa XPC, rozszerzenie.

### Poświadczenia i persony

Każdy proces przechowuje **poświadczenia**, które **określają jego uprawnienia** w systemie. Każdy proces ma jeden główny `uid` i jeden główny `gid` (choć może należeć do kilku grup).\
Można również zmienić identyfikator użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia alternatywny zestaw **poświadczeń**. Przyjęcie persony oznacza jednoczesne przyjęcie jej uid, gid i członkostwa w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:

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

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka udostępnia funkcje potrzebne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu, specyficzne dla jądra XNU (jądra, na którym bazuje macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
   - **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB. Wystarcza to do typowych operacji, ale można go zmienić za pomocą atrybutów wątku, jeśli potrzeba więcej lub mniej miejsca.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` odgrywa kluczową rolę podczas konfiguracji wątku. Wykorzystuje argument `env[]` do przetwarzania zmiennych środowiskowych, które mogą zawierać informacje o położeniu i rozmiarze stosu.

#### Zakończenie wątku w macOS

1. **Kończenie wątków:** Wątki są zazwyczaj kończone przez wywołanie `pthread_exit()`. Funkcja ta umożliwia czyste zakończenie wątku, wykonanie niezbędnego czyszczenia oraz przekazanie wartości zwrotnej do wątków oczekujących na jego zakończenie.
2. **Czyszczenie wątku:** Po wywołaniu `pthread_exit()` uruchamiana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątków Mach (Mach to podsystem komunikacyjny w jądrze XNU) i wywołuje `bsdthread_terminate` — syscall usuwający struktury wątku na poziomie jądra.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać wyścigów, macOS udostępnia kilka prymitywów synchronizacji. Mają one kluczowe znaczenie w środowiskach wielowątkowych, ponieważ zapewniają integralność danych i stabilność systemu:

1. **Mutexy:**
   - **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex o rozmiarze 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
   - **Szybki mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexu, ale zoptymalizowany pod kątem szybszego działania; ma również rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
   - Służą do oczekiwania na wystąpienie określonych warunków; mają rozmiar 44 bajtów (40 bajtów plus 4-bajtowa sygnatura).
   - **Atrybuty zmiennej warunkowej (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
   - Zapewnia, że kod inicjalizacyjny zostanie wykonany tylko raz. Jej rozmiar wynosi 12 bajtów.
4. **Blokady do odczytu i zapisu:**
   - Umożliwiają jednoczesny dostęp wielu czytelników lub jednemu zapisującemu, co zapewnia wydajny dostęp do współdzielonych danych.
   - **Blokada do odczytu i zapisu (sygnatura: 0x52574c4b):** Ma rozmiar 196 bajtów.
   - **Atrybuty blokady do odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad do odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne wątku (TLV)

**Zmienne lokalne wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych przypisanych do **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, odrębną instancję zmiennej, co pozwala uniknąć konfliktów i zachować integralność danych bez potrzeby stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W C i językach pokrewnych zmienną lokalną wątku można zadeklarować za pomocą słowa kluczowego **`__thread`**. Oto jak działa ono w tym przykładzie:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek nie wpłyną na `tlv_var` w innym wątku.

W binarnym pliku Mach-O dane związane ze zmiennymi lokalnymi dla wątku są przechowywane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątku, takie jak ich typy i status inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych lokalnych dla wątku, które nie zostały jawnie zainicjalizowane. To część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`**, służące do zarządzania zmiennymi lokalnymi dla wątku w chwili zakończenia jego działania. To API umożliwia **rejestrowanie destruktorów** — specjalnych funkcji, które czyszczą dane lokalne dla wątku po jego zakończeniu.

### Priorytety wątków

Aby zrozumieć priorytety wątków, należy przyjrzeć się temu, jak system operacyjny decyduje, które wątki i kiedy uruchamiać. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych wykorzystuje się do tego pojęcia takie jak `nice`, `renice` oraz klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość nice z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość nice nowo utworzonego procesu wynosi zazwyczaj 0.
   - Niższa wartość nice (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora niż inne procesy z wyższymi wartościami nice.
2. **Renice:**
   - `renice` to polecenie służące do zmiany wartości nice już uruchomionego procesu. Pozwala dynamicznie dostosować priorytet procesów, zwiększając lub zmniejszając przydzielany im czas procesora na podstawie nowych wartości nice.
   - Na przykład, jeśli proces chwilowo potrzebuje więcej zasobów procesora, można obniżyć jego wartość nice za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do zarządzania priorytetami wątków, szczególnie w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** zadania według ich ważności lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **User Interactive:**
   - Ta klasa jest przeznaczona dla zadań, które w danej chwili bezpośrednio współdziałają z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobre wrażenia z użytkowania. Zadania te otrzymują najwyższy priorytet, aby interfejs pozostał responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
   - Zadania uruchamiane przez użytkownika, od których oczekuje on natychmiastowych wyników, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego obliczeń. Mają wysoki priorytet, ale niższy niż zadania User Interactive.
3. **Utility:**
   - Są to zadania długotrwałe, którym zwykle towarzyszy wskaźnik postępu (np. pobieranie plików, importowanie danych). Mają niższy priorytet niż zadania uruchamiane przez użytkownika i nie muszą kończyć się natychmiast.
4. **Background:**
   - Ta klasa jest przeznaczona dla zadań wykonywanych w tle i niewidocznych dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Dzięki klasom QoS programiści nie muszą zarządzać konkretnymi wartościami priorytetów, lecz mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje wykorzystanie zasobów procesora.

Istnieją również różne **zasady planowania wątków**, które umożliwiają określenie zestawu parametrów planowania branych pod uwagę przez planistę. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Nadużywanie procesów macOS

macOS udostępnia wiele mechanizmów umożliwiających **procesom interakcję, komunikację i udostępnianie danych**. Choć mechanizmy te są niezbędne do normalnego działania systemu, osoby atakujące mogą nadużywać ich do wstrzykiwania kodu, jego wykonywania lub uzyskiwania dostępu do danych.

### Library Injection

Library Injection to technika, w której osoba atakująca **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając osobie atakującej takie same uprawnienia i dostęp jak temu procesowi.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Hookowanie funkcji pozwala osobie atakującej **zmieniać zachowanie** procesu, obserwować poufne dane, a nawet przejąć kontrolę nad przepływem wykonania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ta strona omawia metadane unwind dla ARM64, ograniczenia PAC w arm64e oraz syntetyczne łańcuchy wywołań.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) obejmuje różne metody, za pomocą których odrębne procesy **udostępniają i wymieniają dane**. Choć IPC ma kluczowe znaczenie dla wielu legalnych aplikacji, może być również nadużywane do podważania izolacji procesów, wykradania poufnych informacji lub wykonywania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na wstrzykiwanie do procesu:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Do przeprowadzenia **ataku man in the browser** można użyć flag `--load-extension` i `--use-fake-ui-for-media-stream`. Pozwala to kraść naciśnięcia klawiszy, przechwytywać ruch sieciowy i pliki cookie, wstrzykiwać skrypty na stronach…:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** oraz ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie blokuje** ponownego uruchomienia już uruchomionej aplikacji, jeśli **zmodyfikowano plik NIB**. Można więc ich użyć do uruchamiania dowolnych programów wykonujących dowolne polecenia:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Możliwe jest wstrzyknięcie opcji JVM za pomocą **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`** oraz załadowanie agenta Java lub natywnego przed uruchomieniem aplikacji.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** wstępnie ładuje JavaScript osoby atakującej przez `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Możliwe jest wstrzyknięcie kodu do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`**, zanim zostanie wywołana funkcja `Main`, lub przez nadużycie funkcji debugowania .NET, jeśli spełnione są wymagane warunki.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nieinteraktywna powłoka Bash odczytuje **`BASH_ENV`**; interaktywne powłoki POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację z **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każda z tych powłok może wykonać kontrolowany plik startowy przed docelowym poleceniem. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`** za każdym razem, gdy włączone jest xtrace (np. przez odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** mogą załadować kontrolowaną konfigurację PHP, której **`auto_prepend_file`** zostanie wykonane przed docelowym skryptem.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samodzielny interpreter Lua wykonuje kod lub plik `@file` z **`LUA_INIT`** (lub jego wariantu zależnego od wersji) przed przetworzeniem docelowego skryptu.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** przekierowują do profili startowych zawierających kod R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** w połączeniu ze ścieżką biblioteki R mogą zamiast tego automatycznie załadować zainstalowany pakiet.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** przekierowuje do depot, z którego automatycznie wykonywany jest plik `config/startup.jl`.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** lub **`ERL_ZFLAGS`** mogą wstrzyknąć wyrażenie Erlang VM **`-eval`** bez potrzeby użycia pliku z payloadem; obciążenia Elixir często uruchamiają tę samą maszynę wirtualną.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** przekierowują do skryptów startowych Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` to wieloplatformowa aplikacja .NET, dlatego kilka zmiennych środowiskowych umożliwia wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje do skryptów profilu uruchamianych podczas startu, **`PSModulePath`** umożliwia przejęcie automatycznego ładowania modułów (umieszczony plik `.psm1` wykonuje się podczas importu i może przesłonić wbudowane polecenia cmdlet), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** ładują kod osoby atakującej do procesu przed `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne sposoby na skłonienie skryptu Perl do wykonania dowolnego kodu w:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Możliwe jest również nadużycie zmiennych środowiskowych ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby skłonić dowolne skrypty do wykonania dowolnego kodu:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Łańcuch **`PYTHONWARNINGS`** i **`BROWSER`** z biblioteki standardowej może wykonać polecenie podczas przetwarzania filtrów ostrzeżeń. Alternatywnie można umieścić plik `sitecustomize.py` w lokalizacji dostępnej przez **`PYTHONPATH`**, aby standardowa inicjalizacja `site` zaimportowała go przed docelowym skryptem. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję lub moduł, gdy kod dochodzi do `breakpoint()`. Zmienne dotyczące wyłącznie trybu interaktywnego, takie jak **`PYTHONSTARTUP`**, mają węższe zastosowanie.

Pamiętaj, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają z osadzonym interpreterem Pythona.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (oraz jego zastępcza zmienna `EXINIT`) są wykonywane jako polecenia Ex podczas standardowego uruchamiania, więc `:!cmd` / `:call system(...)` umożliwiają wykonanie kodu, gdy ofiara otworzy Vim/Neovim w kontrolowanym środowisku:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Osobno: Homebrew często instaluje Pythona w katalogu `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą mieć możliwość podmiany programu uruchamiającego. To przejęcie zapisywalnego pliku binarnego, a nie wstrzyknięcie przez zmienną środowiskową; przed uznaniem go za możliwy do wykorzystania należy sprawdzić właściciela i listy ACL.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje wstrzykiwanie do procesów. Jest dobrym źródłem informacji o sygnałach widocznych przez Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmiennych środowiskowych służących do wstrzykiwania kodu** podczas uruchamiania procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — jeden proces prosi o port zadania innego procesu, co jest warunkiem wstępnym wstrzyknięcia do niego kodu.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają dowolnej osobie podłączyć się do niej oraz uruchamiać w niej kod.<sup>[[3]](#references)</sup>
- **Tworzenia symlinków/hardlinków między poziomami uprawnień** — klasycznej techniki „utwórz link jako zwykły użytkownik i skieruj go do uprzywilejowanej lokalizacji”. Pamiętaj, że **symlinki mogą wywoływać alerty, ale nie można ich zablokować**: EndpointSecurity nie udostępnia miejsca docelowego linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) opisano, jak użyć funkcji **`task_name_for_pid`**, aby uzyskać informacje o innych **procesach wstrzykujących kod do procesu**, a następnie uzyskać informacje o tamtym procesie.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz działać z **tym samym uid** co proces albo jako **root** (funkcja zwraca informacje o procesie, a nie umożliwia wstrzyknięcia kodu).

## References

- [1] [Shield — wykrywanie wstrzykiwania do procesów macOS w projekcie open source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — Dlaczego aplikacje Electron nie mogą przechowywać poufnych danych w bezpieczny sposób: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — Wykrywanie modyfikacji zadań](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
