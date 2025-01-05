# Network Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Network namespace to funkcja jądra Linux, która zapewnia izolację stosu sieciowego, pozwalając **każdemu network namespace na posiadanie własnej niezależnej konfiguracji sieci**, interfejsów, adresów IP, tabel routingu i reguł zapory. Ta izolacja jest przydatna w różnych scenariuszach, takich jak konteneryzacja, gdzie każdy kontener powinien mieć swoją własną konfigurację sieci, niezależnie od innych kontenerów i systemu gospodarza.

### Jak to działa:

1. Gdy nowy network namespace jest tworzony, zaczyna z **całkowicie izolowanym stosie sieciowym**, z **brakiem interfejsów sieciowych** poza interfejsem loopback (lo). Oznacza to, że procesy działające w nowym network namespace nie mogą komunikować się z procesami w innych namespaces lub systemie gospodarza domyślnie.
2. **Wirtualne interfejsy sieciowe**, takie jak pary veth, mogą być tworzone i przenoszone między network namespaces. Umożliwia to nawiązywanie łączności sieciowej między namespaces lub między namespace a systemem gospodarza. Na przykład, jeden koniec pary veth może być umieszczony w network namespace kontenera, a drugi koniec może być podłączony do **mostu** lub innego interfejsu sieciowego w namespace gospodarza, zapewniając łączność sieciową dla kontenera.
3. Interfejsy sieciowe w obrębie namespace mogą mieć **własne adresy IP, tabele routingu i reguły zapory**, niezależnie od innych namespaces. Umożliwia to procesom w różnych network namespaces posiadanie różnych konfiguracji sieciowych i działanie tak, jakby działały na oddzielnych systemach sieciowych.
4. Procesy mogą przemieszczać się między namespaces za pomocą wywołania systemowego `setns()`, lub tworzyć nowe namespaces za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWNET`. Gdy proces przemieszcza się do nowego namespace lub go tworzy, zacznie używać konfiguracji sieci i interfejsów związanych z tym namespace.

## Laboratorium:

### Tworzenie różnych Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Montując nową instancję systemu plików `/proc`, używając parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły oraz rozwiązanie są opisane poniżej:

1. **Wyjaśnienie problemu**:

- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów osieroconych. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni.

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
# Run ifconfig or ip -a
```
### Sprawdź, w którym namespace znajduje się twój proces
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Znajdź wszystkie przestrzenie nazw sieciowych
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do przestrzeni nazw sieciowej
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Możesz **wejść do innej przestrzeni nazw procesów tylko jako root**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (jak `/proc/self/ns/net`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
