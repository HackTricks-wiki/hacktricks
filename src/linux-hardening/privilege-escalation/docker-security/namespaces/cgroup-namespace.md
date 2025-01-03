# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Cgroup namespace to funkcja jądra Linux, która zapewnia **izolację hierarchii cgroup dla procesów działających w obrębie namespace**. Cgroups, skrót od **control groups**, to funkcja jądra, która pozwala na organizowanie procesów w hierarchiczne grupy w celu zarządzania i egzekwowania **ograniczeń na zasoby systemowe** takie jak CPU, pamięć i I/O.

Chociaż cgroup namespaces nie są oddzielnym typem namespace, jak inne, o których rozmawialiśmy wcześniej (PID, mount, network itp.), są związane z koncepcją izolacji namespace. **Cgroup namespaces wirtualizują widok hierarchii cgroup**, tak że procesy działające w obrębie cgroup namespace mają inny widok hierarchii w porównaniu do procesów działających w hoście lub innych namespace.

### Jak to działa:

1. Gdy tworzony jest nowy cgroup namespace, **zaczyna się od widoku hierarchii cgroup opartego na cgroup procesu tworzącego**. Oznacza to, że procesy działające w nowym cgroup namespace będą widziały tylko podzbiór całej hierarchii cgroup, ograniczony do poddrzewa cgroup zakorzenionego w cgroup procesu tworzącego.
2. Procesy w obrębie cgroup namespace **widzą swoją własną cgroup jako korzeń hierarchii**. Oznacza to, że z perspektywy procesów wewnątrz namespace, ich własna cgroup pojawia się jako korzeń, a one nie mogą widzieć ani uzyskiwać dostępu do cgroups poza swoim własnym poddrzewem.
3. Cgroup namespaces nie zapewniają bezpośrednio izolacji zasobów; **zapewniają jedynie izolację widoku hierarchii cgroup**. **Kontrola i izolacja zasobów są nadal egzekwowane przez subsystemy cgroup** (np. cpu, pamięć itp.) same w sobie.

Aby uzyskać więcej informacji na temat CGroups, sprawdź:

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratorium:

### Tworzenie różnych Namespace

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Montując nową instancję systemu plików `/proc`, używając parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni nazw**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły i rozwiązanie są opisane poniżej:

1. **Wyjaśnienie problemu**:

- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni nazw; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów osieroconych. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni nazw.

2. **Konsekwencja**:

- Zakończenie PID 1 w nowej przestrzeni nazw prowadzi do usunięcia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzieleniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są następnie bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala na działanie `/bin/bash` i jego podprocesów bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Sprawdź, w którym namespace znajduje się twój proces
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Znajdź wszystkie przestrzenie nazw CGroup
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do przestrzeni nazw CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Możesz **wejść do innej przestrzeni nazw procesów tylko jeśli jesteś root**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (jak `/proc/self/ns/cgroup`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
