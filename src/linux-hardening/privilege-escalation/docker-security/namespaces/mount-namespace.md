# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Mount namespace to funkcja jądra Linux, która zapewnia izolację punktów montowania systemu plików widocznych dla grupy procesów. Każda przestrzeń nazw montowania ma swój własny zestaw punktów montowania systemu plików, a **zmiany w punktach montowania w jednej przestrzeni nazw nie wpływają na inne przestrzenie nazw**. Oznacza to, że procesy działające w różnych przestrzeniach nazw montowania mogą mieć różne widoki hierarchii systemu plików.

Przestrzenie nazw montowania są szczególnie przydatne w konteneryzacji, gdzie każdy kontener powinien mieć swój własny system plików i konfigurację, izolowaną od innych kontenerów i systemu gospodarza.

### Jak to działa:

1. Gdy nowa przestrzeń nazw montowania jest tworzona, jest inicjowana **kopią punktów montowania z jej nadrzędnej przestrzeni nazw**. Oznacza to, że w momencie utworzenia nowa przestrzeń nazw dzieli ten sam widok systemu plików co jej nadrzędna. Jednak wszelkie późniejsze zmiany w punktach montowania w obrębie przestrzeni nazw nie wpłyną na nadrzędną ani inne przestrzenie nazw.
2. Gdy proces modyfikuje punkt montowania w swojej przestrzeni nazw, na przykład montując lub odmontowując system plików, **zmiana jest lokalna dla tej przestrzeni nazw** i nie wpływa na inne przestrzenie nazw. Umożliwia to każdej przestrzeni nazw posiadanie własnej niezależnej hierarchii systemu plików.
3. Procesy mogą przemieszczać się między przestrzeniami nazw za pomocą wywołania systemowego `setns()`, lub tworzyć nowe przestrzenie nazw za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWNS`. Gdy proces przemieszcza się do nowej przestrzeni nazw lub ją tworzy, zacznie używać punktów montowania związanych z tą przestrzenią nazw.
4. **Deskryptory plików i inody są współdzielone między przestrzeniami nazw**, co oznacza, że jeśli proces w jednej przestrzeni nazw ma otwarty deskryptor pliku wskazujący na plik, może **przekazać ten deskryptor pliku** do procesu w innej przestrzeni nazw, a **oba procesy będą miały dostęp do tego samego pliku**. Jednak ścieżka pliku może nie być taka sama w obu przestrzeniach nazw z powodu różnic w punktach montowania.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Montaż nowej instancji systemu plików `/proc` przy użyciu parametru `--mount-proc` zapewnia, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły i rozwiązanie są opisane poniżej:

1. **Wyjaśnienie problemu**:

- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania osieroconych procesów. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni.

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
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Znajdź wszystkie przestrzenie montowania
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Wejdź do przestrzeni montowania
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Również, możesz **wejść do innej przestrzeni nazw tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (jak `/proc/self/ns/mnt`).

Ponieważ nowe montowania są dostępne tylko w obrębie przestrzeni nazw, możliwe jest, że przestrzeń nazw zawiera wrażliwe informacje, które mogą być dostępne tylko z niej.

### Zamontuj coś
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Odniesienia

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
