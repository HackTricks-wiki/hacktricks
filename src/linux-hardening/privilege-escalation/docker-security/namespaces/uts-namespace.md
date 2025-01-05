# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Namespace UTS (UNIX Time-Sharing System) to funkcja jądra Linux, która zapewnia **izolację dwóch identyfikatorów systemowych**: **nazwy hosta** i **nazwy domeny NIS** (Network Information Service). Ta izolacja pozwala każdemu namespace UTS mieć **własną niezależną nazwę hosta i nazwę domeny NIS**, co jest szczególnie przydatne w scenariuszach konteneryzacji, gdzie każdy kontener powinien wyglądać jak oddzielny system z własną nazwą hosta.

### Jak to działa:

1. Gdy nowy namespace UTS jest tworzony, zaczyna od **kopii nazwy hosta i nazwy domeny NIS z jego rodzicielskiego namespace**. Oznacza to, że w momencie utworzenia nowy namespace **dzieli te same identyfikatory co jego rodzic**. Jednak wszelkie późniejsze zmiany w nazwie hosta lub nazwie domeny NIS w obrębie namespace nie wpłyną na inne namespace.
2. Procesy w obrębie namespace UTS **mogą zmieniać nazwę hosta i nazwę domeny NIS** za pomocą wywołań systemowych `sethostname()` i `setdomainname()`, odpowiednio. Te zmiany są lokalne dla namespace i nie wpływają na inne namespace ani na system gospodarza.
3. Procesy mogą przemieszczać się między namespace za pomocą wywołania systemowego `setns()` lub tworzyć nowe namespace za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWUTS`. Gdy proces przemieszcza się do nowego namespace lub tworzy jeden, zacznie używać nazwy hosta i nazwy domeny NIS związanej z tym namespace.

## Laboratorium:

### Tworzenie różnych namespace

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
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

- Zakończenie PID 1 w nowej przestrzeni nazw prowadzi do wyczyszczenia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzielaniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są następnie bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala na działanie `/bin/bash` i jego podprocesów bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w której przestrzeni nazw znajduje się twój proces
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Znajdź wszystkie przestrzenie nazw UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do przestrzeni nazw UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
