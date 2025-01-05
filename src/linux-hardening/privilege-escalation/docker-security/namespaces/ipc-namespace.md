# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Namespace IPC (Inter-Process Communication) to funkcja jądra Linux, która zapewnia **izolację** obiektów IPC System V, takich jak kolejki komunikatów, segmenty pamięci współdzielonej i semafory. Ta izolacja zapewnia, że procesy w **różnych namespace'ach IPC nie mogą bezpośrednio uzyskiwać dostępu do obiektów IPC innych procesów ani ich modyfikować**, co zapewnia dodatkową warstwę bezpieczeństwa i prywatności między grupami procesów.

### Jak to działa:

1. Gdy nowy namespace IPC jest tworzony, zaczyna się od **całkowicie izolowanego zestawu obiektów IPC System V**. Oznacza to, że procesy działające w nowym namespace IPC nie mogą uzyskiwać dostępu ani ingerować w obiekty IPC w innych namespace'ach lub w systemie gospodarza domyślnie.
2. Obiekty IPC utworzone w ramach namespace są widoczne i **dostępne tylko dla procesów w tym namespace**. Każdy obiekt IPC jest identyfikowany przez unikalny klucz w swoim namespace. Chociaż klucz może być identyczny w różnych namespace'ach, same obiekty są izolowane i nie mogą być dostępne między namespace'ami.
3. Procesy mogą przemieszczać się między namespace'ami za pomocą wywołania systemowego `setns()` lub tworzyć nowe namespace'y za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWIPC`. Gdy proces przemieszcza się do nowego namespace'a lub tworzy jeden, zacznie używać obiektów IPC związanych z tym namespace'em.

## Laboratorium:

### Tworzenie różnych namespace'ów

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Montując nową instancję systemu plików `/proc`, używając parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły i rozwiązanie są opisane poniżej:

1. **Wyjaśnienie problemu**:

- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów osieroconych. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni.

2. **Konsekwencja**:

- Zakończenie PID 1 w nowej przestrzeni prowadzi do usunięcia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzieleniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni. `/bin/bash` i jego procesy potomne są następnie bezpiecznie zawarte w tej nowej przestrzeni, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala na działanie `/bin/bash` i jego podprocesów bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w którym namespace znajduje się twój proces
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Znajdź wszystkie przestrzenie nazw IPC
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do przestrzeni nazw IPC
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Możesz **wejść do innej przestrzeni nazw procesów tylko jako root**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (takiego jak `/proc/self/ns/net`).

### Utwórz obiekt IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Odniesienia

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
