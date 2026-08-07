# Abuse de processos no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas sobre processos

Um processo é uma instância de um executável em execução; no entanto, os processos não executam código, e sim as threads. Portanto, **os processos são apenas contêineres para threads em execução**, fornecendo memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`**, que criava uma cópia exata do processo atual; em seguida, o **processo filho** geralmente chamava **`execve`** para carregar o novo executável e executá-lo. Depois, **`vfork`** foi introduzido para tornar esse processo mais rápido, sem qualquer cópia de memória.\
Então, **`posix_spawn`** foi introduzido, combinando **`vfork`** e **`execve`** em uma única chamada e aceitando flags:

- `POSIX_SPAWN_RESETIDS`: Redefine os IDs efetivos para os IDs reais
- `POSIX_SPAWN_SETPGROUP`: Define a afiliação ao grupo de processos
- `POSUX_SPAWN_SETSIGDEF`: Define o comportamento padrão dos sinais
- `POSIX_SPAWN_SETSIGMASK`: Define a máscara de sinais
- `POSIX_SPAWN_SETEXEC`: Executa no mesmo processo (como `execve`, com mais opções)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia suspenso
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sem ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa o alocador Nano do libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` nos segmentos de dados
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fecha todas as descrições de arquivo no exec(2) por padrão
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiza os bits altos do deslocamento do ASLR

Além disso, `posix_spawn` permite especificar um array de **`posix_spawnattr`** que controla alguns aspectos do processo gerado, e **`posix_spawn_file_actions`** para modificar o estado dos descritores.

Quando um processo morre, ele envia o **código de retorno ao processo pai** (se o pai tiver morrido, o novo pai será o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()` e, até que isso aconteça, o filho permanece em estado zumbi, no qual ainda é listado, mas não consome recursos.

### PIDs

PIDs, identificadores de processos, identificam um processo único. No XNU, os **PIDs** têm **64 bits**, aumentam monotonicamente e **nunca sofrem wraparound** (para evitar abusos).

### Grupos de processos, sessões e coalizões

**Processos** podem ser inseridos em **grupos** para facilitar seu gerenciamento. Por exemplo, os comandos em um shell script estarão no mesmo grupo de processos, portanto é possível **enviar sinais a todos simultaneamente** usando kill, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são colocados dentro da sessão, a menos que iniciem sua própria sessão.

Coalition é outra forma de agrupar processos no Darwin. Um processo que ingressa em uma coalition pode acessar recursos de pool, compartilhar um ledger ou ser afetado pelo Jetsam. Coalitions têm diferentes funções: Leader, XPC service, Extension.

### Credenciais e personae

Cada processo possui **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` primário e um `gid` primário (embora possa pertencer a vários grupos).\
Também é possível alterar o ID de usuário e de grupo se o binário tiver o bit **`setuid/setgid`**.\
Existem várias funções para **definir novos uids/gids**.

A syscall **`persona`** fornece um conjunto **alternativo** de **credenciais**. Adotar uma persona assume seu uid, gid e associações de grupo **de uma só vez**. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), é possível encontrar a struct:
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
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie wywołuje ona `bsdthread_create()`, czyli wywołanie systemowe niższego poziomu charakterystyczne dla kernela XNU (kernela, na którym bazuje macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybutów), które określają zachowanie wątku, w tym zasady planowania i rozmiar stosu.
- **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków wynosi 512 KB, co wystarcza do typowych operacji, ale można go zmienić za pomocą atrybutów wątku, jeśli potrzebne jest więcej lub mniej miejsca.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` odgrywa kluczową rolę podczas konfiguracji wątku, wykorzystując argument `env[]` do analizowania zmiennych środowiskowych, które mogą zawierać informacje o lokalizacji i rozmiarze stosu.

#### Kończenie wątków w macOS

1. **Kończenie wątków:** Wątki są zazwyczaj kończone przez wywołanie `pthread_exit()`. Funkcja ta pozwala wątkowi zakończyć działanie w kontrolowany sposób, wykonując niezbędne czyszczenie i umożliwiając przekazanie wartości zwracanej do wątków oczekujących na jego zakończenie.
2. **Czyszczenie wątku:** Po wywołaniu `pthread_exit()` wywoływana jest funkcja `pthread_terminate()`, która usuwa wszystkie powiązane struktury wątku. Dealokuje porty wątków Mach (Mach to podsystem komunikacyjny w kernelu XNU) i wywołuje `bsdthread_terminate` — syscall usuwający struktury na poziomie kernela powiązane z wątkiem.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać race conditions, macOS udostępnia kilka prymitywów synchronizacji. Są one kluczowe w środowiskach wielowątkowych, ponieważ zapewniają integralność danych i stabilność systemu:

1. **Mutexy:**
- **Zwykły mutex (sygnatura: 0x4D555458):** Standardowy mutex zajmujący 60 bajtów pamięci (56 bajtów dla mutexu i 4 bajty dla sygnatury).
- **Fast Mutex (sygnatura: 0x4d55545A):** Podobny do zwykłego mutexu, ale zoptymalizowany pod kątem szybszego działania; również zajmuje 60 bajtów.
2. **Zmienne warunkowe:**
- Służą do oczekiwania na wystąpienie określonych warunków i mają rozmiar 44 bajtów (40 bajtów plus 4-bajtowa sygnatura).
- **Atrybuty zmiennych warunkowych (sygnatura: 0x434e4441):** Atrybuty konfiguracyjne zmiennych warunkowych o rozmiarze 12 bajtów.
3. **Zmienna Once (sygnatura: 0x4f4e4345):**
- Gwarantuje, że fragment kodu inicjalizacyjnego zostanie wykonany tylko raz. Jej rozmiar wynosi 12 bajtów.
4. **Blokady odczytu i zapisu:**
- Umożliwiają jednoczesny dostęp wielu czytelnikom albo dostęp jednego writera, zapewniając wydajny dostęp do współdzielonych danych.
- **Read Write Lock (sygnatura: 0x52574c4b):** Ma rozmiar 196 bajtów.
- **Atrybuty Read Write Lock (sygnatura: 0x52574c41):** Atrybuty blokad odczytu i zapisu o rozmiarze 20 bajtów.

> [!TIP]
> Ostatnie 4 bajty tych obiektów służą do wykrywania przepełnień.

### Zmienne lokalne wątku (TLV)

**Zmienne lokalne wątku (TLV)** w kontekście plików Mach-O (formatu plików wykonywalnych w macOS) służą do deklarowania zmiennych specyficznych dla **każdego wątku** w aplikacji wielowątkowej. Dzięki temu każdy wątek ma własną, oddzielną instancję zmiennej, co pozwala unikać konfliktów i zachować integralność danych bez konieczności stosowania jawnych mechanizmów synchronizacji, takich jak mutexy.

W języku C i językach pokrewnych zmienną lokalną wątku można zadeklarować za pomocą słowa kluczowego **`__thread`**. Oto jak działa to w podanym przykładzie:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ten fragment definiuje `tlv_var` jako zmienną lokalną dla wątku. Każdy wątek wykonujący ten kod będzie miał własną zmienną `tlv_var`, a zmiany dokonane przez jeden wątek w `tlv_var` nie wpłyną na `tlv_var` w innym wątku.

W binarnym Mach-O dane związane ze zmiennymi lokalnymi dla wątków są zorganizowane w określonych sekcjach:

- **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych dla wątków, takie jak ich typy i stan inicjalizacji.
- **`__DATA.__thread_bss`**: Ta sekcja jest używana dla zmiennych lokalnych dla wątków, które nie zostały jawnie zainicjalizowane. Jest to część pamięci przeznaczona na dane inicjalizowane zerami.

Mach-O udostępnia również specjalne API o nazwie **`tlv_atexit`** do zarządzania zmiennymi lokalnymi dla wątków podczas kończenia działania wątku. To API umożliwia **rejestrowanie destruktorów** — specjalnych funkcji, które czyszczą dane lokalne dla wątku po jego zakończeniu.

### Priorytety wątków

Zrozumienie priorytetów wątków wymaga przyjrzenia się temu, jak system operacyjny decyduje, które wątki uruchamiać i kiedy. Na tę decyzję wpływa poziom priorytetu przypisany do każdego wątku. W macOS i systemach uniksopodobnych obsługują to koncepcje takie jak `nice`, `renice` oraz klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
- Wartość `nice` procesu to liczba wpływająca na jego priorytet. Każdy proces ma wartość nice od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość nice podczas tworzenia procesu wynosi zazwyczaj 0.
- Niższa wartość nice (bliższa -20) sprawia, że proces jest bardziej „samolubny”, dzięki czemu otrzymuje więcej czasu CPU w porównaniu z innymi procesami o wyższych wartościach nice.
2. **Renice:**
- `renice` to polecenie używane do zmiany wartości nice już działającego procesu. Można go używać do dynamicznego dostosowywania priorytetu procesów, zwiększając lub zmniejszając przydzielany im czas CPU na podstawie nowych wartości nice.
- Przykładowo, jeśli proces tymczasowo potrzebuje większej ilości zasobów CPU, można obniżyć jego wartość nice za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to nowocześniejsze podejście do obsługi priorytetów wątków, szczególnie w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS umożliwiają deweloperom **kategoryzowanie** zadań na różnych poziomach w zależności od ich znaczenia lub pilności. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **User Interactive:**
- Ta klasa jest przeznaczona dla zadań, które aktualnie wchodzą w interakcję z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobre doświadczenie użytkownika. Zadania te otrzymują najwyższy priorytet, aby interfejs pozostał responsywny (np. animacje lub obsługa zdarzeń).
2. **User Initiated:**
- Zadania inicjowane przez użytkownika, dla których oczekuje on natychmiastowych wyników, takie jak otwieranie dokumentu lub kliknięcie przycisku wymagające obliczeń. Mają wysoki priorytet, ale niższy niż User Interactive.
3. **Utility:**
- Są to zadania długotrwałe, które zazwyczaj wyświetlają wskaźnik postępu (np. pobieranie plików lub importowanie danych). Mają niższy priorytet niż zadania inicjowane przez użytkownika i nie muszą zakończyć się natychmiast.
4. **Background:**
- Ta klasa jest przeznaczona dla zadań działających w tle i niewidocznych dla użytkownika. Mogą to być takie zadania jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają najniższy priorytet i minimalny wpływ na wydajność systemu.

Korzystając z klas QoS, deweloperzy nie muszą zarządzać konkretnymi numerami priorytetów, lecz mogą skupić się na charakterze zadania, a system odpowiednio optymalizuje zasoby CPU.

Ponadto istnieją różne **polityki planowania wątków** (`thread scheduling policies`), które służą do określania zestawu parametrów planowania uwzględnianych przez scheduler. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach race condition.

## Nadużywanie procesów w MacOS

MacOS, podobnie jak każdy inny system operacyjny, udostępnia różne metody i mechanizmy umożliwiające **procesom interakcję, komunikację i współdzielenie danych**. Chociaż techniki te są niezbędne do wydajnego działania systemu, threat actors mogą je również nadużywać do **wykonywania złośliwych działań**.

### Library Injection

Library Injection to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście procesu docelowego, zapewniając atakującemu takie same uprawnienia i dostęp jak procesowi.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Dzięki hookowaniu funkcji atakujący może **modyfikować zachowanie** procesu, obserwować poufne dane, a nawet przejąć kontrolę nad przepływem wykonywania.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) odnosi się do różnych metod, za pomocą których oddzielne procesy **udostępniają i wymieniają dane**. Chociaż IPC ma podstawowe znaczenie dla wielu legalnych aplikacji, może być również wykorzystywane do obejścia izolacji procesów, wykonywania leak poufnych informacji lub przeprowadzania nieautoryzowanych działań.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplikacje Electron uruchomione z określonymi zmiennymi środowiskowymi mogą być podatne na process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Możliwe jest użycie flag `--load-extension` i `--use-fake-ui-for-media-stream` do przeprowadzenia **man in the browser attack**, umożliwiającego kradzież naciśnięć klawiszy, przechwytywanie ruchu i cookies oraz wstrzykiwanie skryptów do stron...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w aplikacji. Mogą jednak **wykonywać dowolne polecenia**, a **Gatekeeper nie zatrzymuje** już uruchomionej aplikacji przed ponownym wykonaniem, jeśli **plik NIB zostanie zmodyfikowany**. Dlatego można ich użyć do nakłonienia dowolnych programów do wykonywania dowolnych poleceń:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Możliwe jest nadużycie określonych możliwości Java (takich jak zmienna środowiskowa **`_JAVA_OPTS`**), aby aplikacja Java wykonywała **dowolny kod/polecenia**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Możliwe jest wstrzyknięcie kodu do aplikacji .Net poprzez **nadużycie funkcjonalności debugowania .Net** (niechronionej przez zabezpieczenia macOS, takie jak runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Sprawdź różne opcje umożliwiające skryptowi Perl wykonywanie dowolnego kodu w:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Możliwe jest również nadużycie zmiennych środowiskowych ruby, aby dowolne skrypty wykonywały dowolny kod:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Jeśli zmienna środowiskowa **`PYTHONINSPECT`** jest ustawiona, proces python przejdzie do python cli po zakończeniu działania. Możliwe jest również użycie **`PYTHONSTARTUP`** do wskazania skryptu python, który ma zostać wykonany na początku interaktywnej sesji.\
Należy jednak pamiętać, że skrypt **`PYTHONSTARTUP`** nie zostanie wykonany, gdy **`PYTHONINSPECT`** utworzy sesję interaktywną.

Inne zmienne środowiskowe, takie jak **`PYTHONPATH`** i **`PYTHONHOME`**, mogą również być przydatne do zmuszenia polecenia python do wykonywania dowolnego kodu.

Należy pamiętać, że pliki wykonywalne skompilowane za pomocą **`pyinstaller`** nie będą używać tych zmiennych środowiskowych, nawet jeśli działają z użyciem wbudowanego python.

> [!CAUTION]
> Ogólnie rzecz biorąc, nie udało mi się znaleźć sposobu na zmuszenie python do wykonywania dowolnego kodu poprzez nadużycie zmiennych środowiskowych.\
> Jednak większość osób instaluje pyhton za pomocą **Hombrew**, który zainstaluje pyhton w **zapisywalnej lokalizacji** dla domyślnego użytkownika admin. Można przejąć jego działanie za pomocą czegoś takiego:
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
> Nawet **root** wykona ten kod podczas uruchamiania python.


## Wykrywanie

### Shield

[**Shield**](https://github.com/theevilbit/Shield) to aplikacja open source oparta na **EndpointSecurity**, która wykrywa i blokuje process injection. Jest dobrym źródłem informacji o tym, które sygnały są faktycznie obserwowalne z poziomu ES, ponieważ generuje alerty dotyczące:<sup>[[1]](#references)[[2]](#references)</sup>

- **Zmienne środowiskowe injection** podczas exec procesu: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` i `ELECTRON_RUN_AS_NODE`.
- Wywołania **`task_for_pid`** — jeden proces żąda portu task innego procesu, co jest warunkiem wstępnym do przeprowadzenia injection.
- **Argumenty debugowania Electron** — `--inspect`, `--inspect-brk` i `--remote-debugging-port`, które uruchamiają aplikację Electron w trybie debugowania i pozwalają każdemu dołączyć do niej oraz uruchamiać w niej kod.<sup>[[3]](#references)</sup>
- **Tworzenie symlinków/hardlinków między poziomami uprawnień** — klasyczny mechanizm „utwórz link jako zwykły użytkownik i skieruj go do uprzywilejowanej lokalizacji”. Należy pamiętać, że **symlinki mogą generować alerty, ale nie mogą być blokowane**: EndpointSecurity nie udostępnia miejsca docelowego linku przed jego utworzeniem.

### Wywołania wykonywane przez inne procesy

W [**tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) znajdziesz informacje o tym, jak można użyć funkcji **`task_name_for_pid`** do uzyskania informacji o innych **procesach wstrzykujących kod do procesu**, a następnie uzyskać informacje o tym innym procesie.<sup>[[4]](#references)</sup>

Należy pamiętać, że aby wywołać tę funkcję, trzeba mieć **ten sam uid** co użytkownik uruchamiający proces albo być **root** (funkcja zwraca informacje o procesie, a nie sposób na wstrzyknięcie kodu).

## Referencje

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
