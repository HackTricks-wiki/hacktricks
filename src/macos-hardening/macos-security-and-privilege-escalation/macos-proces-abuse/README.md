# Nadużycia procesów w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces jest instancją uruchomionego pliku wykonywalnego, jednak procesy nie wykonują kodu — robią to wątki. Dlatego **procesy są jedynie kontenerami dla uruchomionych wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane wewnątrz innych procesów (z wyjątkiem PID 1) przez wywołanie **`fork`**, które tworzyło dokładną kopię bieżącego procesu. Następnie **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Później wprowadzono **`vfork`**, aby przyspieszyć ten proces bez kopiowania pamięci.\
Następnie wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu i przyjmujące flagi:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektywne identyfikatory do identyfikatorów rzeczywistych
- `POSIX_SPAWN_SETPGROUP`: Ustawia przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustawia domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustawia maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonuje `exec` w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchamia proces w stanie zawieszenia
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchamia proces bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Używa alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwala na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamyka wszystkie deskryptory plików przy exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losuje górne bity przesunięcia ASLR

Ponadto `posix_spawn` przyjmuje ustawienia **`posix_spawnattr`**, które kontrolują różne aspekty uruchamianego procesu, oraz wpisy **`posix_spawn_file_actions`**, które modyfikują deskryptory plików.

Gdy proces kończy działanie, wysyła **kod zwrotny do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym procesem nadrzędnym zostaje PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie — nadal jest widoczny na liście, ale nie zużywa zasobów.

### PID-y

PID-y, czyli identyfikatory procesów, identyfikują unikatowy proces. W XNU **PID-y** mają **64 bity**, zwiększają się monotonicznie i **nigdy się nie zawijają** (aby zapobiegać nadużyciom).

### Grupy procesów, sesje i koalicje

**Procesy** można umieszczać w **grupach**, aby ułatwić zarządzanie nimi. Na przykład polecenia w skrypcie powłoki należą do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, na przykład za pomocą `kill`.\
Można również **grupować procesy w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne zostają do niej przypisane, chyba że same rozpoczną własną sesję.

Koalicja to kolejny sposób grupowania procesów w Darwin. Dołączenie procesu do koalicji pozwala mu uzyskać dostęp do zasobów puli, współdzielić rejestr rozliczeniowy lub podlegać mechanizmowi Jetsam. Koalicje mają różne role: lider, usługa XPC, rozszerzenie.

### Dane uwierzytelniające i persony

Każdy proces ma **poświadczenia**, które **określają jego uprawnienia** w systemie. Każdy proces ma jeden podstawowy `uid` i jeden podstawowy `gid` (choć może należeć do kilku grup).\
Możliwa jest również zmiana identyfikatora użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia **alternatywny** zestaw **poświadczeń**. Przyjęcie persony powoduje jednoczesne przejęcie jej `uid`, `gid` i członkostwa w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:

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

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka udostępnia funkcje niezbędne do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje ona `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu, specyficzne dla jądra XNU (jądra, na którym bazuje macOS). To wywołanie systemowe przyjmuje różne flagi wywodzące się z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
   - **Domyślny rozmiar stosu:** Domyślny rozmiar stosu nowych wątków wynosi 512 KB, co wystarcza do typowych operacji. W razie potrzeby można go zmienić za pomocą atrybutów wątku.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` odgrywa kluczową rolę podczas konfigurowania wątku. Wykorzystuje argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o położeniu i rozmiarze stosu.

#### Kończenie działania wątku w macOS

1. **Zamykanie wątków:** Wątki są zwykle kończone przez wywołanie `pthread_exit()`. Funkcja ta pozwala wątkowi zakończyć działanie w uporządkowany sposób, wykonując niezbędne operacje porządkowe i umożliwiając przekazanie wartości zwracanej wątkom oczekującym na jego zakończenie.
2. **Czyszczenie zasobów wątku:** Po wywołaniu `pthread_exit()` uruchamiana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątków Mach (Mach to podsystem komunikacyjny w jądrze XNU) i wywołuje `bsdthread_terminate` — wywołanie systemowe, które usuwa struktury wątku na poziomie jądra.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać race conditions, macOS udostępnia kilka mechanizmów synchronizacji. Są one niezbędne w środowiskach wielowątkowych, by zapewnić integralność danych i stabilność systemu:

1. **Mutexy:**
   - **Standardowy mutex (sygnatura: 0x4D555458):** Standardowy mutex o rozmiarze 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
   - **Fast mutex (sygnatura: 0x4d55545A):** Podobny do standardowego mutexa, ale zoptymalizowany pod kątem szybszego działania; również ma rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
   - Służą do oczekiwania na wystąpienie określonych warunków. Mają rozmiar 44 bajtów (40 bajtów plus 4-bajtowa sygnatura).
   - **Atrybuty zmiennych warunkowych (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna once (sygnatura: 0x4f4e4345):**
   - Zapewnia, że dany fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Ma rozmiar 12 bajtów.
4. **Blokady do odczytu i zapisu:**
   - Umożliwiają jednoczesny dostęp wielu czytelników lub jednego zapisującego, zapewniając wydajny dostęp do współdzielonych danych.
   - **Blokada do odczytu i zapisu (sygnatura: 0x52574c4b):** Ma rozmiar 196 bajtów.
   - **Atrybuty blokady do odczytu i zapisu (sygnatura: 0x52574c41):** Atrybuty blokad do odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne dla wątku (TLV)

**Zmienne lokalne dla wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych przypisanych do **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala uniknąć konfliktów i zachować integralność danych bez konieczności stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i pokrewnych można zadeklarować zmienną lokalną dla wątku za pomocą słowa kluczowego **`__thread`**. Oto jak to działa w podanym przykładzie:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek nie wpłyną na `tlv_var` w innym wątku.

W pliku binarnym Mach-O dane związane ze zmiennymi lokalnymi dla wątków są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątków, takie jak ich typy i status inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych lokalnych dla wątków, które nie zostały jawnie zainicjalizowane. To część pamięci zarezerwowana na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`**, które zarządza zmiennymi lokalnymi dla wątków, gdy wątek się kończy. To API pozwala **zarejestrować destruktory** — specjalne funkcje, które porządkują dane lokalne dla wątku po jego zakończeniu.

### Priorytety wątków

Zrozumienie priorytetów wątków wymaga przyjrzenia się temu, jak system operacyjny decyduje, które wątki i kiedy uruchamiać. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych wykorzystuje się w tym celu takie pojęcia jak `nice`, `renice` oraz klasy Quality of Service (QoS).

#### Nice i renice

1. **Nice:**
   - Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` dla nowo utworzonego procesu wynosi zwykle 0.
   - Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny” i otrzymuje więcej czasu procesora niż procesy z wyższymi wartościami `nice`.
2. **Renice:**
   - `renice` to polecenie służące do zmiany wartości `nice` już działającego procesu. Można go użyć do dynamicznej zmiany priorytetu procesów, zwiększając lub zmniejszając przydzielany im czas procesora za pomocą nowych wartości `nice`.
   - Na przykład, jeśli proces tymczasowo potrzebuje więcej zasobów procesora, można obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, stosowane między innymi w systemach takich jak macOS obsługujących **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** zadania według ich ważności lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas:

1. **User Interactive:**
   - Ta klasa jest przeznaczona dla zadań, które wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych rezultatów, aby zapewnić dobre wrażenia z użytkowania. Takie zadania otrzymują najwyższy priorytet, aby interfejs pozostawał responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
   - Zadania inicjowane przez użytkownika, od których oczekuje on natychmiastowych rezultatów, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego obliczeń. Mają wysoki priorytet, ale niższy niż zadania interaktywne.
3. **Utility:**
   - Są to zadania długotrwałe, którym zwykle towarzyszy wskaźnik postępu (np. pobieranie plików, importowanie danych). Mają niższy priorytet niż zadania zainicjowane przez użytkownika i nie muszą zakończyć się natychmiast.
4. **Background:**
   - Ta klasa obejmuje zadania działające w tle, niewidoczne dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Korzystając z klas QoS, programiści nie muszą zarządzać dokładnymi wartościami priorytetów — mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje wykorzystanie zasobów procesora.

Istnieją również różne **zasady planowania wątków**, które określają zestaw parametrów planowania uwzględnianych przez scheduler. Można je ustawiać za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Nadużycia procesów w macOS

macOS udostępnia wiele mechanizmów, dzięki którym **procesy mogą wchodzić w interakcje, komunikować się i współdzielić dane**. Mechanizmy te są niezbędne do prawidłowego działania systemu, ale atakujący mogą nadużywać ich do injection, wykonywania kodu lub uzyskiwania dostępu do danych.

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

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Atakujący może za pomocą hooków **zmienić zachowanie** procesu, obserwować wrażliwe dane, a nawet przejąć kontrolę nad przebiegiem wykonania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ta strona opisuje metadane unwind dla ARM64, ograniczenia PAC w arm64e oraz syntetyczne łańcuchy wywołań.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Komunikacja między procesami

Komunikacja między procesami (IPC) obejmuje różne metody, za pomocą których oddzielne procesy **współdzielą i wymieniają dane**. IPC ma podstawowe znaczenie dla wielu legalnych aplikacji, ale może być również nadużywane do obchodzenia izolacji procesów, wycieku wrażliwych informacji lub wykonywania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection do aplikacji Electron

Aplikacje Electron uruchomione z określonymi zmiennymi środowiskowymi mogą być podatne na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection do Chromium

Do przeprowadzenia **ataku man in the browser**, który pozwala przechwytywać naciśnięcia klawiszy, ruch sieciowy i cookies oraz wstrzykiwać skrypty na stronach, można użyć flag `--load-extension` i `--use-fake-ui-for-media-stream`:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie blokuje** ponownego uruchomienia już uruchomionej aplikacji, jeśli **zmodyfikowano plik NIB**. Można więc wykorzystać je do uruchamiania dowolnych poleceń przez dowolne programy:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection do aplikacji Java

Można wstrzyknąć opcje JVM za pomocą **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** lub **`JDK_JAVA_OPTIONS`**, aby załadować agenta Java lub natywnego agenta przed uruchomieniem aplikacji.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection do Node.js

**`NODE_OPTIONS`** wstępnie ładuje JavaScript atakującego za pomocą `--require` (plik) lub `--import data:text/javascript,…` (bez pliku, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** ładuje moduł do interaktywnego REPL, a **`ELECTRON_RUN_AS_NODE`** ponownie włącza te możliwości w plikach binarnych Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection do aplikacji .Net

Można wstrzyknąć kod do aplikacji .NET za pomocą **`DOTNET_STARTUP_HOOKS`**, przed wywołaniem `Main`, lub nadużyć funkcji debugowania .NET, jeśli spełnione są wymagane warunki.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nieinteraktywny Bash odczytuje **`BASH_ENV`**; interaktywne powłoki POSIX odczytują **`ENV`**; zsh odczytuje **`$ZDOTDIR/.zshenv`**; a fish odczytuje konfigurację z **`XDG_CONFIG_HOME`** lub **`XDG_DATA_DIRS`**. Każda z tych powłok może wykonać kontrolowany plik startowy przed zamierzonym poleceniem. Bash wykonuje również podstawienie polecenia umieszczone w **`PS4`**, gdy włączone jest xtrace (np. odziedziczone **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Przemycanie poleceń przez stdin powłoki

Uruchomienie `/bin/zsh -s` sprawia, że powłoka odczytuje program ze standardowego wejścia. Downloader, który kopiuje niezaufany dokument o określonej strukturze do stdin procesu potomnego bez wcześniejszego parsowania, zmienia więc cały dokument w kod źródłowy powłoki. W jednym zaobserwowanym przypadku loader przesyłał publiczny plik iCalendar przez anonimowy potok, linia po linii. Metadane kalendarza kończyły się błędami jako polecenia, ale zsh kontynuował działanie, aż napotkał wykonywalne linie umieszczone za `DESCRIPTION:`. Linie te pobierały i uruchamiały kolejny pakiet aplikacji. Oczekiwany typ zawartości i zaufany hosting nośnika nie czyniły tego bezpiecznym; niebezpieczną granicą było przekazanie jego bajtów interpreterowi.<sup>[[5]](#references)</sup>

Powiązane etapy omówiono w sekcjach [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) oraz [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** lub **`PHP_INI_SCAN_DIR`** mogą załadować kontrolowaną konfigurację PHP, której **`auto_prepend_file`** wykonuje się przed skryptem docelowym.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Samodzielny interpreter Lua wykonuje kod lub plik `@file` ze zmiennej **`LUA_INIT`** (albo jej wariantu zależnego od wersji) przed przetworzeniem skryptu docelowego.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** i **`R_PROFILE`** przekierowują do profili startowych zawierających kod R. Zmienne **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** wraz ze ścieżką biblioteki R mogą zamiast tego automatycznie załadować zainstalowany pakiet.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** przekierowuje do depot, którego plik `config/startup.jl` jest wykonywany automatycznie.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** lub **`ERL_ZFLAGS`** mogą wstrzyknąć wyrażenie Erlang VM **`-eval`** bez potrzeby używania pliku z payloadem; obciążenia Elixir często uruchamiają tę samą maszynę wirtualną.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** i **`OCTAVE_VERSION_INITFILE`** przekierowują do skryptów startowych Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` to wieloplatformowa aplikacja .NET, dlatego kilka zmiennych środowiskowych umożliwia wykonanie kodu przed poleceniem: **`XDG_CONFIG_HOME`** przekierowuje do skryptów profilu uruchamianych podczas startu, **`PSModulePath`** umożliwia przejęcie automatycznego ładowania modułów (umieszczony plik `.psm1` wykonuje się podczas importu i może przesłonić wbudowane cmdlety), a zmienne .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** i **`DOTNET_STARTUP_HOOKS`** ładują kod atakującego do procesu przed wywołaniem `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne sposoby na to, by skrypt Perla wykonywał dowolny kod:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Można również nadużyć zmiennych środowiskowych ruby (**`RUBYOPT`**, **`RUBYLIB`**), aby dowolne skrypty wykonywały dowolny kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Łańcuch **`PYTHONWARNINGS`** i **`BROWSER`** z biblioteki standardowej może wykonać polecenie podczas parsowania filtra ostrzeżeń. Alternatywna metoda oparta na pliku polega na umieszczeniu `sitecustomize.py` na ścieżce **`PYTHONPATH`**, aby standardowa inicjalizacja `site` zaimportowała go przed skryptem docelowym. **`PYTHONBREAKPOINT`** uruchamia wybraną funkcję lub moduł, gdy kod dotrze do `breakpoint()`. Zmienne przeznaczone wyłącznie do trybu interaktywnego, takie jak **`PYTHONSTARTUP`**, mają węższe zastosowanie.

Pamiętaj, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają z osadzonym Pythonem.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (oraz zapasowa zmienna `EXINIT`) są wykonywane jako polecenia Ex podczas zwykłego uruchamiania, więc `:!cmd` / `:call system(...)` umożliwiają wykonanie kodu, gdy ofiara uruchomi Vim/Neovim w kontrolowanym środowisku:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Niezależnie od tego Homebrew często instaluje Pythona w `/opt/homebrew`, gdzie członkowie lokalnej grupy `admin` mogą mieć możliwość podmiany programu uruchamiającego. To przejęcie za pomocą zapisywalnego pliku binarnego, a nie injection przez zmienną środowiskową; przed uznaniem go za możliwy do wykorzystania sprawdź właściciela i ACL.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje process injection. Stanowi dobre źródło informacji o sygnałach widocznych przez Endpoint Security, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Zmiennych środowiskowych injection** podczas uruchamiania procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — gdy jeden proces żąda portu task innego procesu, co jest warunkiem koniecznym do przeprowadzenia na nim injection.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają każdemu dołączyć do niej oraz uruchamiać w niej kod.<sup>[[3]](#references)</sup>
- **Tworzenia symlinków/hardlinków z przekroczeniem poziomów uprawnień** — klasycznej techniki „utwórz link jako zwykły użytkownik i skieruj go do uprzywilejowanej lokalizacji”. Pamiętaj, że **symlinki można wykrywać, ale nie blokować**: EndpointSecurity nie udostępnia celu linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) znajdziesz informacje o tym, jak za pomocą funkcji **`task_name_for_pid`** uzyskać informacje o innych **procesach wstrzykujących kod do procesu**, a następnie o tym, jak uzyskać informacje o tamtym procesie.<sup>[[4]](#references)</sup>

Pamiętaj, że aby wywołać tę funkcję, musisz mieć **ten sam uid** co proces albo uprawnienia **roota** (funkcja zwraca informacje o procesie, a nie umożliwia wstrzyknięcia kodu).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — wykrywanie process injection w macOS, open source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Dlaczego aplikacje Electron nie mogą przechowywać poufnie twoich sekretów: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Wykrywanie modyfikacji task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Nowa wersja macOS stealera MacSync atakuje entuzjastów kryptowalut i programistów](https://securelist.com/macsync-new-version/121383/)
