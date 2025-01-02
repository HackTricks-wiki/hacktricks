# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o procesach

Proces to instancja uruchamianego pliku wykonywalnego, jednak procesy nie wykonują kodu, to wątki. Dlatego **procesy są tylko kontenerami dla uruchamianych wątków**, zapewniając pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane w ramach innych procesów (z wyjątkiem PID 1) poprzez wywołanie **`fork`**, które tworzyło dokładną kopię bieżącego procesu, a następnie **proces potomny** zazwyczaj wywoływał **`execve`**, aby załadować nowy plik wykonywalny i go uruchomić. Następnie wprowadzono **`vfork`**, aby przyspieszyć ten proces bez kopiowania pamięci.\
Następnie wprowadzono **`posix_spawn`**, łącząc **`vfork`** i **`execve`** w jednym wywołaniu i akceptując flagi:

- `POSIX_SPAWN_RESETIDS`: Resetuj efektywne identyfikatory do rzeczywistych identyfikatorów
- `POSIX_SPAWN_SETPGROUP`: Ustaw przynależność do grupy procesów
- `POSUX_SPAWN_SETSIGDEF`: Ustaw domyślne zachowanie sygnałów
- `POSIX_SPAWN_SETSIGMASK`: Ustaw maskę sygnałów
- `POSIX_SPAWN_SETEXEC`: Wykonaj w tym samym procesie (jak `execve` z dodatkowymi opcjami)
- `POSIX_SPAWN_START_SUSPENDED`: Rozpocznij wstrzymany
- `_POSIX_SPAWN_DISABLE_ASLR`: Rozpocznij bez ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Użyj alokatora Nano z libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwól na `rwx` w segmentach danych
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamknij wszystkie opisy plików przy exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizuj wysokie bity przesunięcia ASLR

Ponadto `posix_spawn` pozwala określić tablicę **`posix_spawnattr`**, która kontroluje niektóre aspekty uruchamianego procesu, oraz **`posix_spawn_file_actions`**, aby zmodyfikować stan deskryptorów.

Gdy proces umiera, wysyła **kod zwrotu do procesu macierzystego** (jeśli proces macierzysty umarł, nowym rodzicem jest PID 1) z sygnałem `SIGCHLD`. Proces macierzysty musi uzyskać tę wartość, wywołując `wait4()` lub `waitid()`, a do tego czasu proces potomny pozostaje w stanie zombie, gdzie nadal jest wymieniany, ale nie zużywa zasobów.

### PIDs

PIDs, identyfikatory procesów, identyfikują unikalny proces. W XNU **PIDs** mają **64 bity**, rosną monotonnie i **nigdy się nie zawijają** (aby uniknąć nadużyć).

### Grupy procesów, sesje i koalicje

**Procesy** mogą być wstawiane do **grup**, aby ułatwić ich obsługę. Na przykład, polecenia w skrypcie powłoki będą w tej samej grupie procesów, więc możliwe jest **sygnalizowanie ich razem** za pomocą kill na przykład.\
Możliwe jest również **grupowanie procesów w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne są umieszczane w tej sesji, chyba że rozpoczynają własną sesję.

Koalicja to inny sposób grupowania procesów w Darwin. Proces dołączający do koalicji pozwala mu uzyskać dostęp do zasobów puli, dzieląc się księgą lub stawiając czoła Jetsam. Koalicje mają różne role: Lider, usługa XPC, Rozszerzenie.

### Uprawnienia i personae

Każdy proces posiada **uprawnienia**, które **identyfikują jego przywileje** w systemie. Każdy proces będzie miał jeden główny `uid` i jeden główny `gid` (chociaż może należeć do kilku grup).\
Możliwe jest również zmienienie identyfikatora użytkownika i grupy, jeśli binarny plik ma bit `setuid/setgid`.\
Istnieje kilka funkcji do **ustawiania nowych uids/gids**.

Wywołanie systemowe **`persona`** zapewnia **alternatywny** zestaw **uprawnień**. Przyjęcie persony zakłada jej `uid`, `gid` i przynależności do grupy **jednocześnie**. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:
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

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego API wątków dla C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib`, która pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka zapewnia niezbędne funkcje do tworzenia i zarządzania wątkami.
2. **Tworzenie wątków:** Funkcja `pthread_create()` jest używana do tworzenia nowych wątków. Wewnątrz ta funkcja wywołuje `bsdthread_create()`, która jest wywołaniem systemowym na niższym poziomie specyficznym dla jądra XNU (na którym oparty jest macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybuty), które określają zachowanie wątku, w tym polityki planowania i rozmiar stosu.
- **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB, co jest wystarczające dla typowych operacji, ale może być dostosowane za pomocą atrybutów wątku, jeśli potrzebna jest większa lub mniejsza przestrzeń.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` jest kluczowa podczas konfiguracji wątku, wykorzystując argument `env[]` do analizy zmiennych środowiskowych, które mogą zawierać szczegóły dotyczące lokalizacji i rozmiaru stosu.

#### Zakończenie wątków w macOS

1. **Zamykanie wątków:** Wątki są zazwyczaj kończone przez wywołanie `pthread_exit()`. Ta funkcja pozwala wątkowi na czyste zakończenie, wykonując niezbędne czynności porządkowe i umożliwiając wątkowi przesłanie wartości zwrotnej do wszelkich oczekujących.
2. **Czyszczenie wątku:** Po wywołaniu `pthread_exit()`, wywoływana jest funkcja `pthread_terminate()`, która zajmuje się usunięciem wszystkich powiązanych struktur wątku. Zwalnia porty wątków Mach (Mach to podsystem komunikacyjny w jądrze XNU) i wywołuje `bsdthread_terminate`, wywołanie systemowe, które usuwa struktury na poziomie jądra związane z wątkiem.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do wspólnych zasobów i unikać warunków wyścigu, macOS zapewnia kilka prymitywów synchronizacji. Są one kluczowe w środowiskach wielowątkowych, aby zapewnić integralność danych i stabilność systemu:

1. **Mutexy:**
- **Zwykły mutex (Podpis: 0x4D555458):** Standardowy mutex o rozmiarze pamięci 60 bajtów (56 bajtów dla mutexa i 4 bajty dla podpisu).
- **Szybki mutex (Podpis: 0x4d55545A):** Podobny do zwykłego mutexa, ale zoptymalizowany do szybszych operacji, również 60 bajtów.
2. **Zmienne warunkowe:**
- Używane do oczekiwania na wystąpienie określonych warunków, o rozmiarze 44 bajtów (40 bajtów plus 4-bajtowy podpis).
- **Atrybuty zmiennych warunkowych (Podpis: 0x434e4441):** Atrybuty konfiguracyjne dla zmiennych warunkowych, o rozmiarze 12 bajtów.
3. **Zmienna Once (Podpis: 0x4f4e4345):**
- Zapewnia, że fragment kodu inicjalizacyjnego jest wykonywany tylko raz. Jej rozmiar wynosi 12 bajtów.
4. **Blokady do odczytu i zapisu:**
- Umożliwiają jednoczesny dostęp wielu czytelników lub jednego pisarza, ułatwiając efektywny dostęp do wspólnych danych.
- **Blokada do odczytu i zapisu (Podpis: 0x52574c4b):** O rozmiarze 196 bajtów.
- **Atrybuty blokady do odczytu i zapisu (Podpis: 0x52574c41):** Atrybuty dla blokad do odczytu i zapisu, o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów są używane do wykrywania przepełnień.

### Zmienne lokalne wątku (TLV)

**Zmienne lokalne wątku (TLV)** w kontekście plików Mach-O (format dla plików wykonywalnych w macOS) są używane do deklarowania zmiennych, które są specyficzne dla **każdego wątku** w aplikacji wielowątkowej. Zapewnia to, że każdy wątek ma swoją własną oddzielną instancję zmiennej, co pozwala unikać konfliktów i utrzymywać integralność danych bez potrzeby stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W C i pokrewnych językach możesz zadeklarować zmienną lokalną wątku, używając słowa kluczowego **`__thread`**. Oto jak to działa w twoim przykładzie:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek uruchamiający ten kod będzie miał swoją własną `tlv_var`, a zmiany wprowadzone przez jeden wątek w `tlv_var` nie wpłyną na `tlv_var` w innym wątku.

W binarnym pliku Mach-O dane związane z zmiennymi lokalnymi dla wątków są zorganizowane w określone sekcje:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątków, takie jak ich typy i status inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych lokalnych dla wątków, które nie są jawnie inicjalizowane. Jest to część pamięci zarezerwowanej dla danych z inicjalizacją zerową.

Mach-O zapewnia również specyficzne API o nazwie **`tlv_atexit`** do zarządzania zmiennymi lokalnymi dla wątków, gdy wątek kończy działanie. To API pozwala na **rejestrowanie destruktorów**—specjalnych funkcji, które sprzątają dane lokalne dla wątków, gdy wątek kończy działanie.

### Priorytety Wątków

Zrozumienie priorytetów wątków polega na przyjrzeniu się, jak system operacyjny decyduje, które wątki uruchomić i kiedy. Ta decyzja jest wpływana przez poziom priorytetu przypisany do każdego wątku. W systemach macOS i podobnych do Uniksa, obsługiwane jest to za pomocą koncepcji takich jak `nice`, `renice` i klasy jakości usług (QoS).

#### Nice i Renice

1. **Nice:**
- Wartość `nice` procesu to liczba, która wpływa na jego priorytet. Każdy proces ma wartość nice w zakresie od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość nice, gdy proces jest tworzony, wynosi zazwyczaj 0.
- Niższa wartość nice (bliżej -20) sprawia, że proces jest bardziej "egoistyczny", przydzielając mu więcej czasu CPU w porównaniu do innych procesów z wyższymi wartościami nice.
2. **Renice:**
- `renice` to polecenie używane do zmiany wartości nice już działającego procesu. Może być używane do dynamicznego dostosowywania priorytetu procesów, zarówno zwiększając, jak i zmniejszając ich przydział czasu CPU na podstawie nowych wartości nice.
- Na przykład, jeśli proces potrzebuje więcej zasobów CPU tymczasowo, możesz obniżyć jego wartość nice za pomocą `renice`.

#### Klasy Jakości Usług (QoS)

Klasy QoS to nowocześniejsze podejście do zarządzania priorytetami wątków, szczególnie w systemach takich jak macOS, które wspierają **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom na **kategoryzowanie** pracy na różne poziomy w zależności od ich znaczenia lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **Interaktywne dla Użytkownika:**
- Ta klasa jest przeznaczona dla zadań, które aktualnie wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobrą jakość doświadczenia użytkownika. Te zadania mają najwyższy priorytet, aby utrzymać responsywność interfejsu (np. animacje lub obsługa zdarzeń).
2. **Inicjowane przez Użytkownika:**
- Zadania, które użytkownik inicjuje i oczekuje natychmiastowych wyników, takie jak otwieranie dokumentu lub klikanie przycisku, który wymaga obliczeń. Te mają wysoki priorytet, ale są poniżej interaktywnych dla użytkownika.
3. **Użyteczność:**
- Te zadania są długoterminowe i zazwyczaj pokazują wskaźnik postępu (np. pobieranie plików, importowanie danych). Mają niższy priorytet niż zadania inicjowane przez użytkownika i nie muszą kończyć się natychmiast.
4. **Tło:**
- Ta klasa jest przeznaczona dla zadań, które działają w tle i nie są widoczne dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub kopie zapasowe. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Korzystając z klas QoS, programiści nie muszą zarządzać dokładnymi numerami priorytetów, ale raczej skupić się na naturze zadania, a system optymalizuje zasoby CPU odpowiednio.

Ponadto istnieją różne **polityki planowania wątków**, które określają zestaw parametrów planowania, które planista weźmie pod uwagę. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach na warunki wyścigu.

## Nadużycie Procesów w MacOS

MacOS, podobnie jak każdy inny system operacyjny, oferuje różnorodne metody i mechanizmy, aby **procesy mogły wchodzić w interakcje, komunikować się i dzielić danymi**. Chociaż te techniki są niezbędne do efektywnego funkcjonowania systemu, mogą być również nadużywane przez aktorów zagrożeń do **przeprowadzania złośliwych działań**.

### Wstrzykiwanie Bibliotek

Wstrzykiwanie bibliotek to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa
