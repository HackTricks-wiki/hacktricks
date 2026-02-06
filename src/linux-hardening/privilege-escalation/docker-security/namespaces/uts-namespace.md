# Przestrzeń nazw UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**solation of two system identifiers**: the **hostname** and the **NIS** (Network Information Service) domain name. Ta izolacja pozwala każdej przestrzeni nazw UTS mieć swoje **własne niezależne hostname i NIS domain name**, co jest szczególnie przydatne w scenariuszach containerization, gdzie każdy container powinien wyglądać jak oddzielny system z własnym hostname.

### Jak to działa:

1. When a new UTS namespace is created, it starts with a **copy of the hostname and NIS domain name from its parent namespace**. Oznacza to, że przy tworzeniu nowa przestrzeń nazw s**hares the same identifiers as its parent**. Jednakże wszelkie późniejsze zmiany hostname lub NIS domain name w obrębie tej przestrzeni nazw nie wpłyną na inne przestrzenie nazw.
2. Processes within a UTS namespace **can change the hostname and NIS domain name** using the `sethostname()` and `setdomainname()` system calls, respectively. Te zmiany są lokalne dla przestrzeni nazw i nie wpływają na inne namespaces ani na system hosta.
3. Processes can move between namespaces using the `setns()` system call or create new namespaces using the `unshare()` or `clone()` system calls with the `CLONE_NEWUTS` flag. Kiedy proces przenosi się do nowej przestrzeni nazw lub tworzy ją, zacznie używać hostname i NIS domain name związanych z tą przestrzenią nazw.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Montując nową instancję systemu plików `/proc` przy użyciu parametru `--mount-proc`, zapewniasz, że nowa przestrzeń nazw montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni nazw**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. Wyjaśnienie problemu:

- Jądro Linux pozwala procesowi tworzyć nowe przestrzenie nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje stworzenie nowej przestrzeni nazw PID (określany jako proces "unshare"), nie wchodzi do nowej przestrzeni — robią to tylko jego procesy potomne.
- Uruchomienie %unshare -p /bin/bash% startuje `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces się zakończy, powoduje posprzątanie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 pełni specjalną rolę przyjmowania osieroconych procesów. Jądro Linux wtedy wyłączy przydzielanie PID w tej przestrzeni.

2. Konsekwencja:

- Wyjście PID 1 w nowej przestrzeni powoduje wyczyszczenie flagi `PIDNS_HASH_ADDING`. W efekcie funkcja `alloc_pid` nie jest w stanie przydzielić nowego PID przy tworzeniu procesu, co skutkuje błędem "Cannot allocate memory".

3. Rozwiązanie:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja powoduje, że `unshare` wykonuje fork nowego procesu po utworzeniu nowej przestrzeni nazw PID.
- Uruchomienie %unshare -fp /bin/bash% zapewnia, że sam `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie osadzone w tej przestrzeni, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewnienie, że `unshare` uruchamiany jest z flagą `-f`, powoduje poprawne utrzymanie nowej przestrzeni nazw PID, pozwalając `/bin/bash` i jego podprocesom działać bez napotkania błędu alokacji pamięci.

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
### Znajdź wszystkie przestrzenie nazw UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Wykorzystywanie udostępniania UTS hosta

Jeśli kontener jest uruchomiony z `--uts=host`, dołącza do przestrzeni nazw UTS hosta zamiast otrzymać izolowaną. Mając capabilities takie jak `--cap-add SYS_ADMIN`, kod w kontenerze może zmienić hostname/NIS name hosta za pomocą `sethostname()`/`setdomainname()`:
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
