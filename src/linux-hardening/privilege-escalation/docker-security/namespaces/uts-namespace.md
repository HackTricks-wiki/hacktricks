# Przestrzeń nazw UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**izolację dwóch identyfikatorów systemowych**: the **hostname** and the **NIS** (Network Information Service) domain name. Ta izolacja pozwala każdej przestrzeni nazw UTS mieć swój **własny niezależny hostname i NIS domain name**, co jest szczególnie przydatne w scenariuszach containerization, gdzie każdy container powinien wyglądać jak oddzielny system z własnym hostname.

### Jak to działa:

1. Gdy tworzona jest nowa przestrzeń nazw UTS, zaczyna z **kopią hostname i NIS domain name z przestrzeni nadrzędnej**. Oznacza to, że przy tworzeniu nowa przestrzeń s**dzieli te same identyfikatory co przestrzeń nadrzędna**. Jednak wszelkie późniejsze zmiany hostname lub NIS domain name w obrębie tej przestrzeni nie będą wpływać na inne przestrzenie nazw.
2. Procesy w obrębie przestrzeni nazw UTS **mogą zmienić hostname i NIS domain name** używając wywołań systemowych `sethostname()` i `setdomainname()`, odpowiednio. Zmiany te są lokalne dla tej przestrzeni nazw i nie wpływają na inne przestrzenie ani system hosta.
3. Procesy mogą przenosić się między przestrzeniami nazw przy użyciu wywołania systemowego `setns()` lub tworzyć nowe przestrzenie nazw używając `unshare()` lub `clone()` z flagą `CLONE_NEWUTS`. Gdy proces przejdzie do nowej przestrzeni lub ją utworzy, zacznie używać hostname i NIS domain name przypisanych do tej przestrzeni.

## Laboratorium:

### Tworzenie różnych przestrzeni nazw

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Wyjaśnienie problemu**:

- Jądro Linux pozwala procesowi tworzyć nowe przestrzenie nazw za pomocą wywołania systemowego `unshare`. Jednak proces inicjujący stworzenie nowej przestrzeni nazw PID (referred to as the "unshare" process) nie wchodzi do nowej przestrzeni nazw; wchodzą do niej tylko jego procesy potomne.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Konsekwencja**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Rozwiązanie**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w jakim namespace znajduje się twój proces
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Znajdź wszystkie UTS namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Nadużywanie współdzielenia UTS hosta

Jeśli kontener jest uruchomiony z `--uts=host`, dołącza do UTS namespace hosta zamiast otrzymać izolowaną przestrzeń. Przy uprawnieniach takich jak `--cap-add SYS_ADMIN`, kod w kontenerze może zmienić nazwę hosta/NIS hosta za pomocą `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Zmiana nazwy hosta może manipulować logami/alertami, zmylić wykrywanie klastra lub uszkodzić konfiguracje TLS/SSH, które przypinają nazwę hosta.

### Wykryj kontenery współdzielące UTS z hostem
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
