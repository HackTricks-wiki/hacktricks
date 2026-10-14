# Nadużywanie procesów macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces to instancja uruchomionego pliku wykonywalnego, jednak procesy nie wykonują kodu — robią to wątki. Dlatego **procesy są jedynie kontenerami dla uruchomionych wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy uruchamiano wewnątrz innych procesów (z wyjątkiem PID 1), wywołując **`fork`**, które tworzy dokładną kopię bieżącego procesu. Następnie **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Później wprowadzono **`vfork`**, aby przyspieszyć ten proces przez wyeliminowanie kopiowania pamięci.\
Następnie wprowadzono **`posix_spawn`**, które łączy **`vfork`** i **`execve`** w jednym wywołaniu i przyjmuje flagi:

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
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losuje górne bity przesunięcia ASLR

Ponadto `posix_spawn` przyjmuje ustawienia **`posix_spawnattr`**, które kontrolują różne aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces kończy działanie, wysyła **kod powrotu do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym procesem nadrzędnym zostaje PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie: nadal jest widoczny na liście, ale nie zużywa zasobów.

### PID-y

PID-y (identyfikatory procesów) identyfikują unikatowy proces. W XNU **PID-y** mają **64 bity**, rosną monotonicznie i **nigdy się nie zawijają** (aby zapobiegać nadużyciom).

### Grupy procesów, sesje i koalicje

**Procesy** można umieszczać w **grupach**, aby ułatwić zarządzanie nimi. Na przykład polecenia w skrypcie powłoki będą należeć do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, na przykład za pomocą kill.\
Możliwe jest również **grupowanie procesów w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne są do niej przypisywane, chyba że rozpoczną własną sesję.

Koalicja to kolejny sposób grupowania procesów w Darwinie. Dołączenie procesu do koalicji umożliwia mu dostęp do współdzielonych zasobów puli, współdzielenie księgi rozliczeniowej lub podleganie mechanizmowi Jetsam. Koalicje mają różne role: lider, usługa XPC, rozszerzenie.

### Dane uwierzytelniające i persony

Każdy proces przechowuje **dane uwierzytelniające**, które **określają jego uprawnienia** w systemie. Każdy proces ma jeden główny `uid` i jeden główny `gid` (choć może należeć do kilku grup).\
Możliwa jest również zmiana identyfikatora użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia **alternatywny** zestaw **danych uwierzytelniających**. Przyjęcie persony jednocześnie ustawia jej uid, gid i członkostwo w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:

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

1. **POSIX Threads (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka udostępnia funkcje potrzebne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje ona `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu, specyficzne dla jądra XNU (jądra, na którym opiera się macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
   - **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB. Jest wystarczający do typowych operacji, ale można go zmienić za pomocą atrybutów wątku, jeśli potrzebna jest większa lub mniejsza przestrzeń.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` ma kluczowe znaczenie podczas konfiguracji wątku. Wykorzystuje argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o położeniu i rozmiarze stosu.

#### Kończenie wątków w macOS

1. **Kończenie wątków:** Wątki są zwykle kończone przez wywołanie `pthread_exit()`. Funkcja ta pozwala wątkowi zakończyć działanie w uporządkowany sposób, wykonać niezbędne czynności porządkowe i przekazać wartość zwrotną wątkom oczekującym na jego zakończenie.
2. **Sprzątanie po wątku:** Po wywołaniu `pthread_exit()` wywoływana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątków Mach (Mach to podsystem komunikacyjny jądra XNU) i wywołuje `bsdthread_terminate` — wywołanie systemowe usuwające struktury wątku z poziomu jądra.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać wyścigów, macOS udostępnia kilka prymitywów synchronizacji. Są one niezbędne w środowiskach wielowątkowych, aby zapewnić integralność danych i stabilność systemu:

1. **Mutexy:**
   - **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex o rozmiarze 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
   - **Szybki mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexa, ale zoptymalizowany pod kątem szybszego działania; również ma rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
   - Służą do oczekiwania na wystąpienie określonych warunków. Zajmują 44 bajty (40 bajtów plus 4-bajtowa sygnatura).
   - **Atrybuty zmiennej warunkowej (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
   - Zapewnia, że fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Zajmuje 12 bajtów.
4. **Blokady do odczytu i zapisu:**
   - Umożliwiają jednoczesny dostęp wielu czytelnikom albo jednemu zapisującemu, zapewniając wydajny dostęp do współdzielonych danych.
   - **Blokada do odczytu i zapisu (sygnatura: 0x52574c4b):** Zajmuje 196 bajtów.
   - **Atrybuty blokady do odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad do odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne dla wątku (TLV)

**Zmienne lokalne dla wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych przypisanych do **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala uniknąć konfliktów i zachować integralność danych bez konieczności stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i pokrewnych możesz zadeklarować zmienną lokalną dla wątku za pomocą słowa kluczowego **`__thread`**. Oto jak to działa w podanym przykładzie:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek nie wpłyną na `tlv_var` innego wątku.

W binarnym pliku Mach-O dane związane ze zmiennymi lokalnymi dla wątków są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Sekcja zawiera metadane zmiennych lokalnych dla wątków, takie jak ich typy i status inicjalizacji.
- **`__DATA.__thread_bss`**: Sekcja jest używana dla zmiennych lokalnych dla wątków, które nie zostały jawnie zainicjalizowane. Jest to część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`**, służące do zarządzania zmiennymi lokalnymi dla wątków w chwili zakończenia wątku. API pozwala **rejestrować destruktory** — specjalne funkcje, które czyszczą dane lokalne dla wątku, gdy ten się kończy.

### Priorytety wątków

Zrozumienie priorytetów wątków wymaga przyjrzenia się temu, jak system operacyjny decyduje, które wątki i kiedy uruchomić. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych służą do tego między innymi mechanizmy `nice`, `renice` i klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` nowo utworzonego procesu wynosi zazwyczaj 0.
   - Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora niż inne procesy o wyższych wartościach `nice`.
2. **Renice:**
   - `renice` to polecenie służące do zmiany wartości `nice` już uruchomionego procesu. Można go użyć do dynamicznego dostosowania priorytetu procesu, zwiększając lub zmniejszając przydzielany mu czas procesora na podstawie nowej wartości `nice`.
   - Jeśli proces tymczasowo potrzebuje więcej zasobów procesora, można na przykład obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do zarządzania priorytetami wątków, szczególnie w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** zadania na różnych poziomach w zależności od ich ważności lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **User Interactive:**
   - Ta klasa jest przeznaczona dla zadań, które aktualnie obsługują interakcję z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobre wrażenia z użytkowania. Zadania te otrzymują najwyższy priorytet, dzięki czemu interfejs pozostaje responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
   - Zadania uruchamiane przez użytkownika, od których oczekuje on natychmiastowych wyników, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego obliczeń. Mają wysoki priorytet, ale niższy niż zadania User Interactive.
3. **Utility:**
   - Są to długotrwałe zadania, którym zazwyczaj towarzyszy wskaźnik postępu (np. pobieranie plików lub importowanie danych). Ich priorytet jest niższy niż zadań uruchomionych przez użytkownika i nie muszą kończyć się natychmiast.
4. **Background:**
   - Ta klasa jest przeznaczona dla zadań wykonywanych w tle, niewidocznych dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Dzięki klasom QoS programiści nie muszą zarządzać konkretnymi wartościami priorytetów, lecz mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje wykorzystanie procesora.

Istnieją również różne **zasady planowania wątków**, które pozwalają określić zestaw parametrów planowania branych pod uwagę przez scheduler. Można to zrobić za pomocą `thread_policy_[set/get]`. Może się to przydać w atakach wykorzystujących race condition.

## Nadużywanie procesów macOS

macOS udostępnia wiele mechanizmów umożliwiających **procesom interakcję, komunikację i udostępnianie danych**. Choć mechanizmy te są niezbędne do normalnego działania systemu, atakujący mogą nadużywać ich do wstrzykiwania kodu, jego wykonywania lub uzyskiwania dostępu do danych.

### Library Injection

Library Injection to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając atakującemu takie same uprawnienia i dostęp jak temu procesowi.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Atakujący może za pomocą hooków **zmienić zachowanie** procesu, obserwować wrażliwe dane, a nawet przejąć kontrolę nad przepływem wykonywania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ta strona omawia metadane unwind ARM64, ograniczenia PAC arm64e oraz syntetyczne łańcuchy wywołań.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Komunikacja międzyprocesowa

Komunikacja międzyprocesowa (IPC) obejmuje różne metody, za pomocą których oddzielne procesy **udostępniają i wymieniają dane**. IPC ma podstawowe znaczenie dla wielu legalnych aplikacji, ale może też zostać wykorzystane do obejścia izolacji procesów, ujawnienia wrażliwych informacji lub wykonania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Wstrzykiwanie do aplikacji Electron

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na wstrzykiwanie do procesu:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Chromium

Do przeprowadzenia **ataku man in the browser**, który umożliwia przechwytywanie naciśnięć klawiszy, ruchu sieciowego i ciasteczek oraz wstrzykiwanie skryptów na strony, można użyć flag `--load-extension` i `--use-fake-ui-for-media-stream`:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie blokuje** ponownego uruchomienia już uruchomionej aplikacji, jeśli **zmodyfikowano plik NIB**. Można więc użyć ich do uruchamiania dowolnych poleceń przez dowolne programy:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Wstrzykiwanie do aplikacji Java

Można wstrzykiwać opcje JVM za pomocą **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`**, aby załadować agenta Java lub natywnego agenta przed uruchomieniem aplikacji.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Wstrzykiwanie do Node.js

**`NODE_OPTIONS`** wstępnie ładuje JavaScript atakującego za pomocą `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Wstrzykiwanie do aplikacji .Net

Kod można wstrzyknąć do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`**, jeszcze przed `Main`, lub przez nadużycie funkcji debugowania .NET, jeśli spełnione są wymagane warunki.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Wstrzykiwanie do powłoki

Nieinteraktywny Bash odczytuje **`BASH_ENV`**; interaktywne powłoki POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację z **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każdy z tych mechanizmów może wykonać kontrolowany plik startowy przed uruchomieniem zamierzonego polecenia. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`** za każdym razem, gdy włączone jest xtrace (np. przez odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Przemycanie poleceń przez stdin powłoki

Uruchomienie `/bin/zsh -s` powoduje, że powłoka odczytuje program ze standardowego wejścia. W związku z tym downloader, który bez uprzedniego parsowania kopiuje niezaufany dokument o określonej strukturze do stdin procesu potomnego, zamienia cały dokument w kod źródłowy powłoki. W jednym zaobserwowanym przypadku loader odczytywał publiczny plik iCalendar wiersz po wierszu przez anonimowy potok. Metadane kalendarza nie działały jako polecenia, ale zsh kontynuował działanie, aż dotarł do wykonywalnych wierszy umieszczonych za `DESCRIPTION:`. Wiersze te pobierały i uruchamiały kolejny pakiet aplikacji. Oczekiwany typ zawartości i zaufany hosting nie czyniły tego bezpiecznym; niebezpieczną granicą było przekazanie bajtów interpreterowi.<sup>[[5]](#references)</sup>

Powiązane etapy opisano w artykułach [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) oraz [macOS auto-start locations](../../macos-auto-start-locations.md).

### Wstrzykiwanie do PHP

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** mogą załadować kontrolowaną konfigurację PHP, której **`auto_prepend_file`** wykona się przed skryptem docelowym.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Lua

Samodzielny interpreter Lua wykonuje kod lub plik `@file` z **`LUA_INIT`** (lub jego wariantu zależnego od wersji) przed przetworzeniem skryptu docelowego.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### Wstrzykiwanie do R

**`R_PROFILE_USER`** i **`R_PROFILE`** przekierowują do profili startowych zawierających kod R. Z kolei **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** wraz ze ścieżką do biblioteki R mogą powodować automatyczne załadowanie zainstalowanego pakietu.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Julia

**`JULIA_DEPOT_PATH`** przekierowuje do depot, z którego automatycznie wykonywany jest plik `config/startup.jl`.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Erlang i Elixir

**`ERL_AFLAGS`**, **`ERL_FLAGS`** lub **`ERL_ZFLAGS`** mogą wstrzyknąć wyrażenie Erlang VM **`-eval`** bez konieczności użycia pliku z payloadem; aplikacje Elixir często uruchamiają tę samą maszynę wirtualną.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### Wstrzykiwanie do GNU Octave

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** przekierowują do skryptów startowych Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### Wstrzykiwanie do PowerShell

`pwsh` to wieloplatformowa aplikacja .NET, dlatego kilka zmiennych środowiskowych umożliwia wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje do skryptów profilu uruchamianych podczas startu, **`PSModulePath`** pozwala przejąć automatyczne ładowanie modułów (podstawiony plik `.psm1` uruchamia się podczas importu i może przesłonić wbudowane cmdlety), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** ładują kod atakującego do procesu przed `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Perla

Sprawdź różne sposoby, dzięki którym skrypt Perla może wykonać dowolny kod:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Ruby

Można również nadużyć zmiennych środowiskowych Ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby spowodować wykonywanie dowolnego kodu przez dowolne skrypty:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Python

Łańcuch **`PYTHONWARNINGS`** i **`BROWSER`** z biblioteki standardowej może wykonać polecenie podczas parsowania filtrów ostrzeżeń. Alternatywą wykorzystującą plik jest umieszczenie `sitecustomize.py` w **`PYTHONPATH`**, dzięki czemu zwykła inicjalizacja `site` zaimportuje go przed uruchomieniem skryptu docelowego. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję lub moduł, gdy kod dociera do `breakpoint()`. Zmienne przeznaczone wyłącznie do trybu interaktywnego, takie jak **`PYTHONSTARTUP`**, mają bardziej ograniczone zastosowanie.

Pamiętaj, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają z osadzonym interpreterem Pythona.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Wstrzykiwanie do Vim/Neovim

**`VIMINIT`** (oraz awaryjnie `EXINIT`) są wykonywane jako polecenia Ex podczas zwykłego uruchamiania. Dlatego `:!cmd` / `:call system(...)` umożliwiają wykonanie kodu, gdy ofiara otworzy Vim/Neovim w kontrolowanym środowisku:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Osobno: Homebrew często instaluje Pythona w `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą mieć możliwość podmiany programu uruchamiającego. Jest to przejęcie zapisywalnego pliku binarnego, a nie wstrzykiwanie za pomocą zmiennej środowiskowej; przed uznaniem tego za podatność sprawdź właściciela pliku i listy ACL.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje wstrzykiwanie do procesów. Jest dobrym punktem odniesienia, jeśli chodzi o sygnały widoczne przez Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmiennych środowiskowych wykorzystywanych do wstrzykiwania** podczas uruchamiania procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — gdy jeden proces żąda portu zadań innego procesu, co jest warunkiem wstępnym do wstrzyknięcia kodu.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają każdemu się do niej podłączyć oraz wykonywać w niej kod.<sup>[[3]](#references)</sup>
- **Tworzenia symlinków/hardlinków między poziomami uprawnień** — klasycznej techniki „utwórz link jako zwykły użytkownik i skieruj go do uprzywilejowanej lokalizacji”. Pamiętaj, że **symlinki można wykrywać, ale nie można ich blokować**: EndpointSecurity nie udostępnia celu linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) opisano, jak za pomocą funkcji **`task_name_for_pid`** uzyskać informacje o innych **procesach wstrzykujących kod do procesu**, a następnie zebrać informacje o tym innym procesie.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz mieć **ten sam uid** co użytkownik uruchamiający proces albo działać jako **root** (funkcja zwraca informacje o procesie, ale nie umożliwia wstrzyknięcia kodu).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — wykrywanie wstrzykiwania do procesów macOS o otwartym kodzie źródłowym (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — Dlaczego aplikacje Electron nie mogą przechowywać poufnie twoich sekretów: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — wykrywanie modyfikacji zadań](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist — nowa wersja złodzieja danych MacSync dla macOS atakuje entuzjastów kryptowalut i programistów](https://securelist.com/macsync-new-version/121383/)
