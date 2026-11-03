# Nadużycia procesów macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces jest instancją uruchomionego pliku wykonywalnego, jednak procesy nie wykonują kodu — robią to wątki. Dlatego **procesy są tylko kontenerami dla uruchomionych wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane wewnątrz innych procesów (z wyjątkiem PID 1) przez wywołanie **`fork`**, które tworzyło dokładną kopię bieżącego procesu. Następnie **proces potomny** zwykle wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Później wprowadzono **`vfork`**, aby przyspieszyć ten proces bez kopiowania pamięci.\
Następnie wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu i przyjmujące flagi:

- `POSIX_SPAWN_RESETIDS`: Zresetuj efektywne identyfikatory do rzeczywistych identyfikatorów
- `POSIX_SPAWN_SETPGROUP`: Ustaw przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustaw domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustaw maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonaj w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchom w stanie zawieszenia
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchom bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Użyj alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwól na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamknij wszystkie opisy plików przy exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losuj wysokie bity przesunięcia ASLR

Ponadto `posix_spawn` przyjmuje ustawienia **`posix_spawnattr`**, które kontrolują aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces umiera, wysyła **kod zwrotny do procesu nadrzędnego** (jeśli proces nadrzędny umarł, nowym procesem nadrzędnym jest PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie — nadal jest widoczny na liście, ale nie zużywa zasobów.

### PID-y

PID-y, czyli identyfikatory procesów, identyfikują unikatowy proces. W XNU **PID-y** mają **64 bity**, są zwiększane monotonicznie i **nigdy się nie zawijają** (aby zapobiec nadużyciom).

### Grupy procesów, sesje i koalicje

**Procesy** można umieszczać w **grupach**, aby ułatwić zarządzanie nimi. Na przykład polecenia w skrypcie powłoki będą należeć do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, używając na przykład kill.\
Można również **grupować procesy w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne są umieszczane w tej sesji, chyba że rozpoczną własną sesję.

Koalicja to inny sposób grupowania procesów w Darwin. Dołączenie procesu do koalicji umożliwia mu dostęp do wspólnych zasobów, współdzielenie rejestru lub podleganie mechanizmowi Jetsam. Koalicje mają różne role: Lider, usługa XPC, rozszerzenie.

### Dane uwierzytelniające i persony

Każdy proces posiada **dane uwierzytelniające**, które **określają jego uprawnienia** w systemie. Każdy proces ma jeden podstawowy `uid` i jeden podstawowy `gid` (choć może należeć do kilku grup).\
Można również zmienić identyfikator użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia alternatywny zestaw **danych uwierzytelniających**. Przyjęcie persony jednocześnie przyjmuje jej uid, gid i członkostwo w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:

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

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które stanowią część standardowego API wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka udostępnia funkcje niezbędne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje ona `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu, specyficzne dla jądra XNU (jądra, na którym opiera się macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
   - **Domyślny rozmiar stosu:** Domyślny rozmiar stosu nowych wątków wynosi 512 KB. Wystarcza on do typowych operacji, ale można go zmienić za pomocą atrybutów wątku, jeśli potrzeba więcej lub mniej miejsca.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` odgrywa kluczową rolę podczas konfigurowania wątku. Wykorzystuje argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o położeniu i rozmiarze stosu.

#### Kończenie wątków w macOS

1. **Kończenie wątków:** Wątki są zwykle kończone przez wywołanie `pthread_exit()`. Funkcja ta umożliwia poprawne zakończenie wątku, wykonuje niezbędne czynności porządkowe i pozwala wątkowi przekazać wartość zwracaną do wątków oczekujących na jego zakończenie.
2. **Sprzątanie po wątku:** Po wywołaniu `pthread_exit()` uruchamiana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątku Mach (Mach to podsystem komunikacyjny jądra XNU) i wywołuje `bsdthread_terminate` — wywołanie systemowe usuwające struktury jądra powiązane z wątkiem.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać wyścigów, macOS udostępnia kilka prymitywów synchronizacji. Są one niezbędne w środowiskach wielowątkowych, by zapewnić integralność danych i stabilność systemu:

1. **Mutexy:**
   - **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex zajmujący 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
   - **Szybki mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexu, ale zoptymalizowany pod kątem szybszego działania; również zajmuje 60 bajtów.
2. **Zmienne warunkowe:**
   - Służą do oczekiwania na wystąpienie określonych warunków i zajmują 44 bajty (40 bajtów plus 4-bajtowa sygnatura).
   - **Atrybuty zmiennej warunkowej (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych, zajmujące 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
   - Zapewnia, że dany kod inicjalizacyjny zostanie wykonany tylko raz. Zajmuje 12 bajtów.
4. **Blokady do odczytu i zapisu:**
   - Umożliwiają jednoczesny dostęp wielu czytelnikom lub jednemu zapisującemu, zapewniając wydajny dostęp do współdzielonych danych.
   - **Blokada do odczytu i zapisu (sygnatura: 0x52574c4b):** Zajmuje 196 bajtów.
   - **Atrybuty blokady do odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad do odczytu i zapisu, zajmujące 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne dla wątków (TLV)

**Zmienne lokalne dla wątków (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych przypisanych do **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala unikać konfliktów i zachować integralność danych bez konieczności stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i pokrewnych można zadeklarować zmienną lokalną dla wątku za pomocą słowa kluczowego **`__thread`**. Oto jak działa to w podanym przykładzie:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek nie wpłyną na `tlv_var` w innym wątku.

W pliku binarnym Mach-O dane powiązane ze zmiennymi lokalnymi dla wątku są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątku, takie jak ich typy i stan inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja służy do przechowywania zmiennych lokalnych dla wątku, które nie zostały jawnie zainicjalizowane. Jest to część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`**, które zarządza zmiennymi lokalnymi dla wątku podczas jego kończenia. To API pozwala **rejestrować destruktory** — specjalne funkcje czyszczące dane lokalne dla wątku, gdy wątek zostaje zakończony.

### Priorytety wątków

Zrozumienie priorytetów wątków wymaga przyjrzenia się temu, jak system operacyjny decyduje, które wątki i kiedy uruchamiać. Na decyzję tę wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych wykorzystuje się do tego mechanizmy takie jak `nice`, `renice` i klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
   - Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` przy tworzeniu procesu wynosi zazwyczaj 0.
   - Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora niż inne procesy o wyższych wartościach `nice`.
2. **Renice:**
   - `renice` to polecenie służące do zmiany wartości `nice` już uruchomionego procesu. Pozwala dynamicznie dostosowywać priorytet procesów, zwiększając lub zmniejszając przydział czasu procesora na podstawie nowych wartości `nice`.
   - Na przykład, jeśli proces tymczasowo potrzebuje więcej zasobów procesora, można obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, stosowane zwłaszcza w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** zadania według ich ważności lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **User Interactive:**
   - Ta klasa jest przeznaczona dla zadań, które w danej chwili wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych rezultatów, aby zapewnić dobre wrażenia z użytkowania. Zadania te otrzymują najwyższy priorytet, dzięki czemu interfejs pozostaje responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
   - Zadania inicjowane przez użytkownika, od których oczekuje on natychmiastowych rezultatów, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego obliczeń. Mają wysoki priorytet, ale niższy niż zadania interaktywne.
3. **Utility:**
   - Są to zadania długotrwałe, którym zwykle towarzyszy wskaźnik postępu (np. pobieranie plików lub importowanie danych). Mają niższy priorytet niż zadania inicjowane przez użytkownika i nie muszą kończyć się natychmiast.
4. **Background:**
   - Ta klasa jest przeznaczona dla zadań działających w tle, niewidocznych dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Dzięki klasom QoS programiści nie muszą zarządzać konkretnymi wartościami priorytetów, lecz mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje zasoby procesora.

Istnieją też różne **zasady planowania wątków**, które określają zestaw parametrów planowania uwzględnianych przez scheduler. Można je ustawiać za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Nadużycia procesów w macOS

macOS udostępnia wiele mechanizmów umożliwiających **procesom wzajemną interakcję, komunikację i współdzielenie danych**. Chociaż mechanizmy te są niezbędne do normalnego działania systemu, atakujący mogą nadużywać ich do injection, wykonywania kodu lub uzyskiwania dostępu do danych.

### Library Injection

Library Injection to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając atakującemu takie same uprawnienia i dostęp jak procesowi.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Dzięki hookowaniu funkcji atakujący może **zmieniać zachowanie** procesu, obserwować poufne dane, a nawet przejąć kontrolę nad przepływem wykonywania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ta strona opisuje metadane unwind dla ARM64, ograniczenia PAC w arm64e oraz syntetyczne łańcuchy wywołań.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Komunikacja między procesami

Inter Process Communication (IPC) obejmuje różne metody, za pomocą których odrębne procesy **współdzielą i wymieniają dane**. Chociaż IPC ma podstawowe znaczenie dla wielu legalnych aplikacji, może też zostać wykorzystane do obejścia izolacji procesów, wycieku poufnych informacji lub wykonywania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection w aplikacjach Electron

Aplikacje Electron uruchomione z określonymi zmiennymi środowiskowymi mogą być podatne na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection w Chromium

Flagi `--load-extension` i `--use-fake-ui-for-media-stream` można wykorzystać do przeprowadzenia **ataku man in the browser**, umożliwiającego kradzież naciśnięć klawiszy, ruchu sieciowego i cookies, wstrzykiwanie skryptów na stronach itd.:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie uniemożliwia** ponownego uruchomienia już uruchomionej aplikacji, jeśli **plik NIB zostanie zmodyfikowany**. Można więc wykorzystać je do uruchamiania dowolnych poleceń przez dowolne programy:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection w aplikacjach Java

Możliwe jest wstrzyknięcie opcji JVM za pomocą **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`** i załadowanie agenta Java lub natywnego przed uruchomieniem aplikacji.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection w Node.js

**`NODE_OPTIONS`** wstępnie ładuje złośliwy kod JavaScript za pomocą `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection w aplikacjach .Net

Możliwe jest wstrzyknięcie kodu do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`** przed wywołaniem `Main` albo przez nadużycie funkcji debugowania .NET, jeśli spełnione są jej wymagania wstępne.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nieinteraktywny Bash odczytuje **`BASH_ENV`**; interaktywne powłoki POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację z **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każda z nich może wykonać kontrolowany plik startowy przed zamierzonym poleceniem. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`** za każdym razem, gdy włączone jest xtrace (np. odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Przemycanie poleceń przez stdin powłoki

Uruchomienie `/bin/zsh -s` powoduje, że powłoka odczytuje program ze standardowego wejścia. Downloader, który kopiuje niezaufany dokument o ustrukturyzowanym formacie do stdin procesu potomnego bez wcześniejszego parsowania, zmienia więc cały dokument w kod źródłowy powłoki. W jednym zaobserwowanym loaderze publiczny plik iCalendar był przesyłany linia po linii przez anonimowy pipe. Metadane kalendarza nie działały jako polecenia, ale zsh kontynuował działanie, aż dotarł do wykonywalnych linii umieszczonych po `DESCRIPTION:`. Linie te pobierały i uruchamiały kolejny pakiet aplikacji. Oczekiwany typ zawartości i zaufany hosting nie zapewniały bezpieczeństwa; niebezpieczną granicą było przekazanie bajtów interpreterowi.<sup>[[5]](#references)</sup>

Powiązane etapy opisano w sekcjach [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) oraz [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** mogą załadować kontrolowaną konfigurację PHP, której **`auto_prepend_file`** wykona się przed docelowym skryptem.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Samodzielny interpreter Lua wykonuje kod lub plik `@file` z **`LUA_INIT`** (albo jego wariantu zależnego od wersji) przed przetworzeniem docelowego skryptu.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** przekierowują do profili startowych zawierających kod R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** wraz ze ścieżką do biblioteki R mogą natomiast powodować automatyczne ładowanie zainstalowanego pakietu.

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** przekierowuje do depot, z którego `config/startup.jl` jest automatycznie wykonywany.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** lub **`ERL_ZFLAGS`** mogą wstrzyknąć wyrażenie Erlang VM **`-eval`** bez konieczności użycia pliku z payloadem; obciążenia Elixir często uruchamiają tę samą maszynę wirtualną.

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** przekierowują do skryptów startowych Octave.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` to wieloplatformowa aplikacja .NET, więc kilka zmiennych środowiskowych umożliwia wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje do skryptów profilu uruchamianych podczas startu, **`PSModulePath`** umożliwia przejęcie automatycznego ładowania modułów (podłożony plik `.psm1` wykonuje się podczas importu i może przesłonić wbudowane cmdlety), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** ładują kod atakującego do procesu przed wywołaniem `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne opcje umożliwiające skryptowi Perl wykonywanie dowolnego kodu:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Możliwe jest również nadużycie zmiennych środowiskowych Ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby dowolne skrypty wykonywały dowolny kod:


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Łańcuch **`PYTHONWARNINGS`** i **`BROWSER`** z biblioteki standardowej może wykonać polecenie podczas parsowania filtrów ostrzeżeń. Alternatywne podejście wykorzystujące plik polega na umieszczeniu `sitecustomize.py` na ścieżce **`PYTHONPATH`**, aby zwykła inicjalizacja `site` zaimportowała ten plik przed docelowym skryptem. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję/moduł, gdy kod osiąga `breakpoint()`. Zmienne działające wyłącznie w trybie interaktywnym, takie jak **`PYTHONSTARTUP`**, mają bardziej ograniczone zastosowanie.

Pamiętaj, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają z osadzonym interpreterem Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (a w razie jego braku `EXINIT`) są wykonywane jako polecenia Ex podczas zwykłego uruchamiania, więc `:!cmd` / `:call system(...)` umożliwiają wykonanie kodu, gdy ofiara otworzy Vim/Neovim w kontrolowanym środowisku:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Niezależnie od tego Homebrew często instaluje Python w katalogu `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą mieć możliwość zastąpienia programu uruchamiającego. Jest to przejęcie zapisywalnego pliku binarnego, a nie injection przez zmienne środowiskowe; przed uznaniem go za podatny na wykorzystanie sprawdź właściciela i ACL.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje process injection. Jest dobrym przykładem sygnałów obserwowalnych przez Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmiennych środowiskowych służących do injection** przy uruchamianiu procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — gdy jeden proces żąda portu task innego procesu, co jest warunkiem wstępnym wstrzyknięcia kodu do niego.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają każdemu dołączyć do niej i wykonać w niej kod.<sup>[[3]](#references)</sup>
- **Tworzenia symlinków/hardlinków między poziomami uprawnień** — klasycznej techniki „utwórz link jako zwykły użytkownik i skieruj go na uprzywilejowaną lokalizację”. Pamiętaj, że **symlinki można wykrywać, ale nie blokować**: EndpointSecurity nie udostępnia celu linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) opisano, jak można użyć funkcji **`task_name_for_pid`**, aby uzyskać informacje o innych **procesach wstrzykujących kod do procesu**, a następnie uzyskać informacje o tym drugim procesie.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz mieć **ten sam uid** co proces lub działać jako **root** (funkcja zwraca informacje o procesie, a nie umożliwia wstrzyknięcia kodu).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — wykrywanie process injection w macOS — open source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Dlaczego aplikacje Electron nie mogą przechowywać Twoich sekretów w sposób poufny: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Wykrywanie modyfikacji task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Nowa wersja stealera MacSync na macOS atakuje entuzjastów kryptowalut i programistów](https://securelist.com/macsync-new-version/121383/)
