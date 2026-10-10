# Nadużycia procesów w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces to instancja uruchomionego pliku wykonywalnego, jednak kodu nie wykonują procesy, lecz wątki. Dlatego **procesy są jedynie kontenerami dla uruchomionych wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy uruchamiano w ramach innych procesów (z wyjątkiem PID 1), wywołując **`fork`**, które tworzyło dokładną kopię bieżącego procesu. Następnie **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Później wprowadzono **`vfork`**, aby przyspieszyć ten proces przez wyeliminowanie kopiowania pamięci.\
Następnie wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu i przyjmujące flagi:

- `POSIX_SPAWN_RESETIDS`: Zresetuj efektywne identyfikatory do rzeczywistych identyfikatorów
- `POSIX_SPAWN_SETPGROUP`: Ustaw przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustaw domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustaw maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonaj w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchom w stanie wstrzymania
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchom bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Użyj alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwól na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamykaj wszystkie deskryptory plików przy wywołaniu exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losuj górne bity przesunięcia ASLR

Ponadto `posix_spawn` przyjmuje ustawienia **`posix_spawnattr`**, które kontrolują różne aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces kończy działanie, wysyła **kod zakończenia do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym procesem nadrzędnym zostaje PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie — nadal jest widoczny na liście procesów, ale nie zużywa zasobów.

### Identyfikatory PID

PID-y, czyli identyfikatory procesów, identyfikują pojedynczy proces. W XNU **PID-y** mają **64 bity**, rosną monotonicznie i **nigdy się nie zawijają** (aby zapobiec nadużyciom).

### Grupy procesów, sesje i koalicje

**Procesy** można łączyć w **grupy**, aby łatwiej nimi zarządzać. Na przykład polecenia w skrypcie powłoki należą do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, na przykład za pomocą `kill`.\
Można również **łączyć procesy w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne zostają do niej przypisane, chyba że same rozpoczną własną sesję.

Koalicja to kolejny sposób grupowania procesów w Darwin. Dołączenie procesu do koalicji umożliwia mu dostęp do puli zasobów, współdzielenie rejestru rozliczeniowego lub narażenie na działanie Jetsam. Koalicje mają różne role: lider, usługa XPC, rozszerzenie.

### Poświadczenia i Personae

Każdy proces przechowuje **poświadczenia**, które **określają jego uprawnienia** w systemie. Każdy proces ma jeden główny `uid` i jeden główny `gid` (może jednak należeć do kilku grup).\
Można również zmienić identyfikator użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji służących do **ustawiania nowych wartości uid/gid**.

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

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Biblioteka ta udostępnia funkcje niezbędne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje ona `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu, specyficzne dla jądra XNU (na którym bazuje jądro macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
   - **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB. Jest wystarczający do typowych operacji, ale można go zmienić za pomocą atrybutów wątku, jeśli potrzebna jest większa lub mniejsza przestrzeń.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` odgrywa kluczową rolę podczas konfiguracji wątku. Wykorzystuje argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o lokalizacji i rozmiarze stosu.

#### Kończenie wątków w macOS

1. **Kończenie wątków:** Wątki są zwykle kończone przez wywołanie `pthread_exit()`. Funkcja ta umożliwia wątkowi prawidłowe zakończenie działania, wykonanie niezbędnego sprzątania i przekazanie wartości zwrotnej wątkom oczekującym na jego zakończenie.
2. **Sprzątanie wątku:** Po wywołaniu `pthread_exit()` uruchamiana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątków Mach (Mach to podsystem komunikacyjny w jądrze XNU) i wywołuje `bsdthread_terminate` — syscall usuwający struktury wątku z poziomu jądra.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać race conditions, macOS udostępnia kilka prymitywów synchronizacji. Mają one kluczowe znaczenie w środowiskach wielowątkowych, ponieważ zapewniają integralność danych i stabilność systemu:

1. **Mutexy:**
   - **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex o rozmiarze 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
   - **Szybki mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexa, ale zoptymalizowany pod kątem szybszego działania; również ma rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
   - Służą do oczekiwania na wystąpienie określonych warunków; mają rozmiar 44 bajtów (40 bajtów plus 4 bajty na sygnaturę).
   - **Atrybuty zmiennej warunkowej (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
   - Zapewnia, że fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Jej rozmiar wynosi 12 bajtów.
4. **Blokady odczytu i zapisu:**
   - Umożliwiają jednoczesny dostęp wielu czytelników lub dostęp jednego zapisującego naraz, zapewniając wydajny dostęp do współdzielonych danych.
   - **Blokada odczytu i zapisu (sygnatura: 0x52574c4b):** Ma rozmiar 196 bajtów.
   - **Atrybuty blokady odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne dla wątku (TLV)

**Zmienne lokalne dla wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych przypisanych do **poszczególnych wątków** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala unikać konfliktów i zachować integralność danych bez użycia jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i pokrewnych można zadeklarować zmienną lokalną dla wątku za pomocą słowa kluczowego **`__thread`**. Oto jak działa to w podanym przykładzie:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek nie wpłyną na zmienną `tlv_var` w innym wątku.

W binarnym pliku Mach-O dane związane ze zmiennymi lokalnymi dla wątków są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątków, takie jak ich typy i stan inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych lokalnych dla wątków, które nie zostały jawnie zainicjalizowane. To część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`**, które zarządza zmiennymi lokalnymi dla wątków w chwili zakończenia wątku. To API pozwala **zarejestrować destruktory** — specjalne funkcje czyszczące dane lokalne dla wątku po jego zakończeniu.

### Priorytety wątków

Aby zrozumieć priorytety wątków, trzeba przyjrzeć się temu, jak system operacyjny decyduje, które wątki i kiedy uruchamiać. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych służą do tego takie mechanizmy jak `nice`, `renice` i klasy Quality of Service (QoS).

#### Nice i renice

1. **Nice:**
   - Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` w chwili utworzenia procesu wynosi zwykle 0.
   - Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora niż procesy o wyższych wartościach `nice`.
2. **Renice:**
   - `renice` to polecenie służące do zmiany wartości `nice` już uruchomionego procesu. Można go użyć do dynamicznej zmiany priorytetu procesu, zwiększając lub zmniejszając przydzielany mu czas procesora w zależności od nowej wartości `nice`.
   - Jeśli na przykład proces tymczasowo potrzebuje więcej zasobów procesora, można obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, stosowane między innymi w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** zadania według ich ważności lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas:

1. **User Interactive:**
   - Ta klasa jest przeznaczona dla zadań, które aktualnie obsługują działania użytkownika lub wymagają natychmiastowych wyników, by zapewnić dobre wrażenia z użytkowania. Zadania te otrzymują najwyższy priorytet, aby interfejs pozostał responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
   - Zadania zainicjowane przez użytkownika, od których oczekuje on natychmiastowych wyników, na przykład otwarcie dokumentu lub kliknięcie przycisku wymagającego wykonania obliczeń. Mają wysoki priorytet, ale niższy niż zadania klasy User Interactive.
3. **Utility:**
   - Są to zadania długotrwałe, którym zwykle towarzyszy wskaźnik postępu (np. pobieranie plików lub importowanie danych). Mają niższy priorytet niż zadania zainicjowane przez użytkownika i nie muszą kończyć się od razu.
4. **Background:**
   - Ta klasa jest przeznaczona dla zadań działających w tle, niewidocznych dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Dzięki klasom QoS programiści nie muszą zarządzać konkretnymi wartościami priorytetów. Mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje wykorzystanie zasobów procesora.

Istnieją również różne **polityki planowania wątków**, które służą do określania zestawu parametrów planowania branych pod uwagę przez scheduler. Można je ustawiać za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Nadużycia procesów macOS

macOS udostępnia wiele mechanizmów, dzięki którym **procesy mogą wchodzić ze sobą w interakcje, komunikować się i współdzielić dane**. Choć mechanizmy te są niezbędne do normalnego działania systemu, atakujący mogą nadużywać ich do wstrzykiwania kodu, jego uruchamiania lub uzyskiwania dostępu do danych.

### Library Injection

Library Injection to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając atakującemu takie same uprawnienia i dostęp jak temu procesowi.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Dzięki hookowaniu funkcji atakujący może **zmienić zachowanie** procesu, obserwować wrażliwe dane, a nawet przejąć kontrolę nad przepływem wykonania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Komunikacja międzyprocesowa

Komunikacja międzyprocesowa (IPC) obejmuje różne metody, dzięki którym odrębne procesy **współdzielą i wymieniają dane**. IPC ma fundamentalne znaczenie dla wielu legalnych aplikacji, ale może też zostać wykorzystane do obejścia izolacji procesów, wycieku wrażliwych informacji lub wykonywania nieuprawnionych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection w aplikacjach Electron

Aplikacje Electron uruchomione z określonymi zmiennymi środowiskowymi mogą być podatne na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Można użyć flag `--load-extension` i `--use-fake-ui-for-media-stream`, aby przeprowadzić **atak man in the browser**, który umożliwia kradzież naciśnięć klawiszy, ruchu sieciowego i cookies, wstrzykiwanie skryptów na stronach i inne działania:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** oraz ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie powstrzyma** ponownego uruchomienia już uruchomionej aplikacji, jeśli **zmodyfikowano plik NIB**. Można więc wykorzystać je do uruchamiania dowolnych poleceń przez dowolne programy:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection w aplikacjach Java

Można wstrzykiwać opcje JVM za pomocą **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`**, aby załadować agenta Java lub natywnego agenta przed uruchomieniem aplikacji.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** wstępnie ładuje JavaScript atakującego za pomocą `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection w aplikacjach .Net

Można wstrzyknąć kod do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`** przed wywołaniem `Main` lub nadużyć funkcji debugowania .NET, jeśli spełnione są wymagane warunki.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nieinteraktywna powłoka Bash odczytuje **`BASH_ENV`**; interaktywne powłoki POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację z **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każda z nich może wykonać kontrolowany plik startowy przed zamierzonym poleceniem. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`**, gdy włączone jest xtrace (np. przez odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** mogą wczytać kontrolowaną konfigurację PHP, której dyrektywa **`auto_prepend_file`** wykonuje kod przed skryptem docelowym.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samodzielny interpreter Lua wykonuje kod lub plik wskazany przez `@file`, podany w **`LUA_INIT`** (lub jego wariancie specyficznym dla wersji), przed przetworzeniem skryptu docelowego.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** przekierowują do profili startowych zawierających kod R. Zamiast tego zmienne **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** wraz ze ścieżką do biblioteki R mogą powodować automatyczne ładowanie zainstalowanego pakietu.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** przekierowuje do depot, w którym automatycznie wykonywany jest plik `config/startup.jl`.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang i Elixir Injection

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

`pwsh` to wieloplatformowa aplikacja .NET, więc kilka zmiennych środowiskowych pozwala na wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje do skryptów profilu uruchamianych podczas startu, **`PSModulePath`** umożliwia przejęcie automatycznego ładowania modułów (umieszczony przez atakującego plik `.psm1` uruchamia się w chwili importu i może przesłonić wbudowane cmdlety), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** ładują kod atakującego do procesu przed wywołaniem `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne sposoby, dzięki którym skrypt Perl może wykonywać dowolny kod:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Można również nadużyć zmiennych środowiskowych Ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby dowolne skrypty wykonywały dowolny kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Łańcuch wykorzystujący standardowe biblioteki **`PYTHONWARNINGS`** i **`BROWSER`** może wykonać polecenie podczas parsowania filtrów ostrzeżeń. Alternatywna metoda oparta na pliku polega na umieszczeniu `sitecustomize.py` w ścieżce **`PYTHONPATH`**, dzięki czemu zwykła inicjalizacja `site` zaimportuje ten plik przed skryptem docelowym. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję lub moduł, gdy kod dotrze do `breakpoint()`. Zmienne używane wyłącznie w trybie interaktywnym, takie jak **`PYTHONSTARTUP`**, mają węższe zastosowanie.

Pamiętaj, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie korzystają z tych zmiennych środowiskowych, nawet jeśli działają z użyciem osadzonego Pythona.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (a w razie jego braku `EXINIT`) jest wykonywane jako polecenia Ex podczas zwykłego uruchamiania, więc `:!cmd` / `:call system(...)` pozwalają na wykonanie kodu, gdy ofiara uruchomi Vim/Neovim w kontrolowanym środowisku:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Niezależnie od tego Homebrew często instaluje Pythona w katalogu `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą mieć możliwość zastąpienia programu uruchamiającego. Jest to przejęcie zapisywalnego pliku binarnego, a nie injection przez zmienną środowiskową; przed uznaniem go za podatny na wykorzystanie sprawdź właściciela i ACL.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje process injection. Jest dobrym źródłem informacji o sygnałach dostępnych przez Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmiennych środowiskowych służących do injection** przy uruchamianiu procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — gdy jeden proces prosi o port zadania innego procesu, co jest warunkiem koniecznym do przeprowadzenia injection.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają każdemu podłączyć się do niej i wykonać w niej kod.<sup>[[3]](#references)</sup>
- **Tworzenia symlinków/hardlinków między poziomami uprawnień** — klasycznej techniki „utwórz link jako zwykły użytkownik i skieruj go na uprzywilejowaną lokalizację”. Pamiętaj, że **symlinki można wykrywać, ale nie blokować**: EndpointSecurity nie udostępnia miejsca docelowego linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) opisano, jak użyć funkcji **`task_name_for_pid`**, aby uzyskać informacje o innych **procesach wstrzykujących kod do procesu**, a następnie zebrać informacje o tym innym procesie.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz mieć **ten sam uid** co proces albo być **rootem** (funkcja zwraca informacje o procesie, ale nie umożliwia wstrzykiwania kodu).

## References

- [1] [Shield — wykrywanie process injection w macOS w projekcie open source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — dlaczego aplikacje Electron nie mogą przechowywać poufnie Twoich sekretów: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — wykrywanie modyfikacji zadań](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
