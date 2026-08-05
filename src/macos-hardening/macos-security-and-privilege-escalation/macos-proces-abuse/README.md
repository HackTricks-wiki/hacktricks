# Nadużywanie procesów macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces jest instancją uruchomionego pliku wykonywalnego, jednak kodu nie wykonują procesy, lecz wątki. Dlatego **procesy są jedynie kontenerami dla uruchomionych wątków**, zapewniającymi pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane wewnątrz innych procesów (z wyjątkiem PID 1) przez wywołanie **`fork`**, które tworzyło dokładną kopię bieżącego procesu, a następnie **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Następnie wprowadzono **`vfork`**, aby przyspieszyć ten proces bez kopiowania pamięci.\
Później wprowadzono **`posix_spawn`**, łączące **`vfork`** i **`execve`** w jednym wywołaniu oraz obsługujące flagi:

- `POSIX_SPAWN_RESETIDS`: Resetuje efektywne identyfikatory do rzeczywistych identyfikatorów
- `POSIX_SPAWN_SETPGROUP`: Ustawia przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustawia domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustawia maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonuje exec w tym samym procesie (jak `execve`, ale z większą liczbą opcji)
- `POSIX_SPAWN_START_SUSPENDED`: Uruchamia proces w stanie wstrzymania
- `_POSIX_SPAWN_DISABLE_ASLR`: Uruchamia bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Używa alokatora Nano biblioteki libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwala na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamyka wszystkie deskryptory plików podczas exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losowo ustawia wysokie bity przesunięcia ASLR

Ponadto `posix_spawn` pozwala określić tablicę **`posix_spawnattr`**, która kontroluje niektóre aspekty uruchamianego procesu, oraz **`posix_spawn_file_actions`**, aby modyfikować stan deskryptorów.

Gdy proces kończy działanie, wysyła **kod zwrotny do procesu nadrzędnego** (jeśli proces nadrzędny zakończył działanie, nowym procesem nadrzędnym zostaje PID 1) za pomocą sygnału `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`. Do tego czasu proces potomny pozostaje w stanie zombie, w którym nadal jest widoczny na liście, ale nie zużywa zasobów.

### PID-y

PID-y, czyli identyfikatory procesów, identyfikują unikatowy proces. W XNU **PID-y** mają rozmiar **64 bitów**, zwiększają się monotonicznie i **nigdy się nie zawijają** (aby zapobiegać nadużyciom).

### Grupy procesów, sesje i coalitions

**Procesy** można umieszczać w **grupach**, aby ułatwić zarządzanie nimi. Na przykład polecenia w skrypcie powłoki będą należeć do tej samej grupy procesów, dzięki czemu można **wysyłać do nich sygnały jednocześnie**, na przykład za pomocą kill.\
Możliwe jest również **grupowanie procesów w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne zostają umieszczone w tej sesji, chyba że rozpoczną własną sesję.

Coalition to kolejny sposób grupowania procesów w Darwin. Dołączenie procesu do coalition umożliwia mu dostęp do puli zasobów, współdzielenie ledgeru lub podleganie mechanizmowi Jetsam. Coalitions mają różne role: Leader, XPC service, Extension.

### Credentials i personae

Każdy proces posiada **credentials**, które **identyfikują jego uprawnienia** w systemie. Każdy proces ma jeden główny `uid` i jeden główny `gid` (choć może należeć do kilku grup).\
Możliwe jest również zmienienie identyfikatora użytkownika i grupy, jeśli plik binarny ma ustawiony bit **`setuid/setgid`**.\
Istnieje kilka funkcji służących do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** udostępnia alternatywny zestaw **credentials**. Przyjęcie persony oznacza jednoczesne przyjęcie jej uid, gid i członkostwa w grupach. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:
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

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API do obsługi wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Biblioteka ta udostępnia niezbędne funkcje do tworzenia wątków i zarządzania nimi.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie funkcja ta wywołuje `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu specyficzne dla jądra XNU (jądra, na którym opiera się macOS). To wywołanie systemowe przyjmuje różne flagi wyprowadzone z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
- **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB, co wystarcza do typowych operacji, ale może zostać zmienione za pomocą atrybutów wątku, jeśli potrzebne jest więcej lub mniej miejsca.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` ma kluczowe znaczenie podczas konfiguracji wątku i wykorzystuje argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o lokalizacji i rozmiarze stosu.

#### Kończenie wątków w macOS

1. **Kończenie wątków:** Wątki są zwykle kończone przez wywołanie `pthread_exit()`. Funkcja ta umożliwia poprawne zakończenie wątku, wykonanie niezbędnego czyszczenia oraz przekazanie wartości zwracanej do wątków oczekujących na jego zakończenie.
2. **Czyszczenie wątku:** Po wywołaniu `pthread_exit()` wywoływana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Zwalnia porty wątków Mach (Mach jest podsystemem komunikacyjnym w jądrze XNU) i wywołuje `bsdthread_terminate`, czyli syscall usuwający struktury na poziomie jądra powiązane z wątkiem.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać race conditions, macOS udostępnia kilka prymitywów synchronizacji. Są one kluczowe w środowiskach wielowątkowych, ponieważ zapewniają integralność danych i stabilność systemu:

1. **Mutexy:**
- **Zwykły mutex (Signature: 0x4D555458):** Standardowy mutex o rozmiarze 60 bajtów (56 bajtów na mutex i 4 bajty na sygnaturę).
- **Fast Mutex (Signature: 0x4d55545A):** Podobny do zwykłego mutexu, ale zoptymalizowany pod kątem szybszych operacji; również ma rozmiar 60 bajtów.
2. **Zmienne warunkowe:**
- Używane do oczekiwania na wystąpienie określonych warunków; mają rozmiar 44 bajtów (40 bajtów plus 4-bajtowa sygnatura).
- **Atrybuty zmiennych warunkowych (Signature: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (Signature: 0x4f4e4345):**
- Zapewnia, że określony fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Jej rozmiar wynosi 12 bajtów.
4. **Blokady odczytu i zapisu:**
- Umożliwiają jednoczesny dostęp wielu czytelnikom lub dostęp jednego zapisującego naraz, zapewniając wydajny dostęp do współdzielonych danych.
- **Blokada odczytu i zapisu (Signature: 0x52574c4b):** Ma rozmiar 196 bajtów.
- **Atrybuty blokady odczytu i zapisu (Signature: 0x52574c41):** Atrybuty blokad odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne wątków (TLV)

**Zmienne lokalne wątków (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych specyficznych dla **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala unikać konfliktów i zachować integralność danych bez konieczności używania jawnych mechanizmów synchronizacji, takich jak mutexy.

W językach C i powiązanych można zadeklarować zmienną lokalną wątku za pomocą słowa kluczowego **`__thread`**. Oto jak działa ono w podanym przykładzie:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany wprowadzone przez jeden wątek w `tlv_var` nie wpłyną na `tlv_var` w innym wątku.

W pliku binarnym Mach-O dane związane ze zmiennymi lokalnymi dla wątków są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątków, takie jak ich typy i stan inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych lokalnych dla wątków, które nie zostały jawnie zainicjalizowane. Jest to część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`** do zarządzania zmiennymi lokalnymi dla wątków podczas kończenia działania wątku. To API pozwala **rejestrować destruktory** — specjalne funkcje, które czyszczą dane lokalne dla wątku po jego zakończeniu.

### Priorytety wątków

Zrozumienie priorytetów wątków wymaga przyjrzenia się temu, jak system operacyjny decyduje, które wątki uruchamiać i kiedy. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych wykorzystuje się do tego koncepcje takie jak `nice`, `renice` oraz klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
- Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość `nice` z zakresu od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` podczas tworzenia procesu wynosi zazwyczaj 0.
- Niższa wartość `nice` (bliższa -20) sprawia, że proces jest bardziej „samolubny”, przydzielając mu więcej czasu procesora w porównaniu z innymi procesami o wyższych wartościach `nice`.
2. **Renice:**
- `renice` to polecenie używane do zmiany wartości `nice` już uruchomionego procesu. Można go używać do dynamicznego dostosowywania priorytetu procesów, zwiększając lub zmniejszając przydział czasu procesora na podstawie nowych wartości `nice`.
- Na przykład, jeśli proces tymczasowo potrzebuje większej ilości zasobów procesora, można obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, szczególnie w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** zadania według różnych poziomów na podstawie ich znaczenia lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **User Interactive:**
- Ta klasa jest przeznaczona dla zadań, które obecnie wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobre doświadczenie użytkownika. Zadania te otrzymują najwyższy priorytet, aby interfejs pozostał responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
- Zadania inicjowane przez użytkownika, dla których oczekuje on natychmiastowych wyników, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagającego wykonania obliczeń. Mają wysoki priorytet, ale niższy niż zadania User Interactive.
3. **Utility:**
- Są to zadania długotrwałe, które zazwyczaj wyświetlają wskaźnik postępu (np. pobieranie plików lub importowanie danych). Mają niższy priorytet niż zadania inicjowane przez użytkownika i nie muszą zakończyć się natychmiast.
4. **Background:**
- Ta klasa jest przeznaczona dla zadań działających w tle i niewidocznych dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Dzięki klasom QoS programiści nie muszą zarządzać dokładnymi wartościami priorytetów, lecz mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje zasoby procesora.

Ponadto istnieją różne **polityki planowania wątków**, które służą do określania zestawu parametrów planowania uwzględnianych przez scheduler. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach wykorzystujących race condition.

## Abuse procesów w macOS

macOS, podobnie jak każdy inny system operacyjny, udostępnia różne metody i mechanizmy umożliwiające **procesom interakcję, komunikację i współdzielenie danych**. Chociaż techniki te są niezbędne do wydajnego działania systemu, threat actors mogą je również wykorzystywać do **prowadzenia złośliwych działań**.

### Library Injection

Library Injection to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając atakującemu takie same uprawnienia i dostęp jak procesowi.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Dzięki hookowaniu funkcji atakujący może **modyfikować zachowanie** procesu, obserwować poufne dane, a nawet przejąć kontrolę nad przepływem wykonania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) odnosi się do różnych metod, za pomocą których odrębne procesy **współdzielą i wymieniają dane**. Chociaż IPC ma podstawowe znaczenie dla wielu legalnych aplikacji, może być również wykorzystywane do obchodzenia izolacji procesów, leak poufnych informacji lub wykonywania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Możliwe jest użycie flag `--load-extension` i `--use-fake-ui-for-media-stream` do przeprowadzenia **man in the browser attack**, umożliwiającego kradzież naciśnięć klawiszy, przechwytywanie ruchu i cookies oraz wstrzykiwanie skryptów do stron...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie zatrzymuje** już uruchomionej aplikacji przed ponownym uruchomieniem, jeśli **plik NIB zostanie zmodyfikowany**. Dlatego można ich użyć do spowodowania, aby dowolne programy wykonywały dowolne polecenia:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Możliwe jest wykorzystanie niektórych możliwości Java (takich jak zmienna środowiskowa **`_JAVA_OPTS`**) do spowodowania, aby aplikacja Java wykonywała **dowolny kod/polecenia**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Możliwe jest wstrzyknięcie kodu do aplikacji .Net poprzez **wykorzystanie funkcjonalności debugowania .Net** (niechronionej przez zabezpieczenia macOS, takie jak runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne opcje umożliwiające skryptowi Perl wykonywanie dowolnego kodu w:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Możliwe jest również wykorzystanie zmiennych środowiskowych Ruby do spowodowania, aby dowolne skrypty wykonywały dowolny kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Jeśli zmienna środowiskowa **`PYTHONINSPECT`** jest ustawiona, proces Python przejdzie do python cli po zakończeniu działania. Możliwe jest również użycie **`PYTHONSTARTUP`** do wskazania skryptu Python, który ma zostać wykonany na początku sesji interaktywnej.\
Należy jednak pamiętać, że skrypt **`PYTHONSTARTUP`** nie zostanie wykonany, gdy **`PYTHONINSPECT`** utworzy sesję interaktywną.

Inne zmienne środowiskowe, takie jak **`PYTHONPATH`** i **`PYTHONHOME`**, również mogą być przydatne do spowodowania, aby polecenie Python wykonywało dowolny kod.

Należy pamiętać, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie używają tych zmiennych środowiskowych, nawet jeśli działają przy użyciu embedded Python.

> [!CAUTION]
> Ogólnie nie udało mi się znaleźć sposobu na zmuszenie Pythona do wykonywania dowolnego kodu poprzez wykorzystanie zmiennych środowiskowych.\
> Jednak większość osób instaluje pyhton za pomocą **Hombrew**, który zainstaluje pyhton w **lokalizacji zapisywalnej** dla domyślnego użytkownika administratora. Można go przejąć za pomocą czegoś takiego:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Nawet **root** wykona ten kod podczas uruchamiania Pythona.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to open source aplikacja oparta na **EndpointSecurity**, która wykrywa i blokuje process injection. Jest dobrym źródłem informacji o tym, które sygnały są faktycznie obserwowalne za pomocą ES, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)</sup>

- **Injection environment variables** podczas uruchamiania procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołań **`task_for_pid`** — jeden proces żąda portu task innego procesu, co jest warunkiem wstępnym wstrzyknięcia kodu do tego procesu.
- **Argumentów debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają dowolnej osobie dołączyć do niej oraz wykonywać w niej kod.
- **Tworzenia symlinków/hardlinków między poziomami uprawnień** — klasycznego mechanizmu „utwórz link jako zwykły użytkownik i wskaż nim uprzywilejowaną lokalizację”. Należy pamiętać, że **symlinki mogą generować alerty, ale nie mogą być blokowane**: EndpointSecurity nie udostępnia miejsca docelowego linku przed jego utworzeniem.

### Calls made by other processes

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) można znaleźć informacje o tym, jak użyć funkcji **`task_name_for_pid`** do uzyskania informacji o innych **procesach wstrzykujących kod do procesu**, a następnie uzyskania informacji o tym innym procesie.<sup>[[4]](#references)</sup>

Należy pamiętać, że aby wywołać tę funkcję, trzeba mieć **ten sam uid** co użytkownik uruchamiający proces albo być **root** (funkcja zwraca informacje o procesie, ale nie zapewnia sposobu na wstrzyknięcie kodu).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
