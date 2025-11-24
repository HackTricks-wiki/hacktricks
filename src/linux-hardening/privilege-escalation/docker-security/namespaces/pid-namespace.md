# Przestrzeń nazw PID

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Przestrzeń nazw PID (PID — Process IDentifier) to funkcja w jądrze Linuxa, która zapewnia izolację procesów poprzez umożliwienie grupie procesów posiadania własnego zestawu unikalnych PID-ów, oddzielnych od PID-ów w innych przestrzeniach nazw. Jest to szczególnie przydatne w konteneryzacji, gdzie izolacja procesów jest kluczowa dla bezpieczeństwa i zarządzania zasobami.

Gdy tworzona jest nowa przestrzeń nazw PID, pierwszy proces w tej przestrzeni otrzymuje PID 1. Proces ten staje się procesem "init" nowej przestrzeni nazw i odpowiada za zarządzanie innymi procesami w obrębie tej przestrzeni. Każdy kolejny proces utworzony w tej przestrzeni będzie miał unikalny PID w tej przestrzeni, a te PID-y będą niezależne od PID-ów w innych przestrzeniach nazw.

Z perspektywy procesu znajdującego się w przestrzeni nazw PID, widoczne są tylko inne procesy w tej samej przestrzeni nazw. Nie jest on świadomy procesów w innych przestrzeniach nazw i nie może wchodzić z nimi w interakcję przy użyciu tradycyjnych narzędzi do zarządzania procesami (np. `kill`, `wait` itp.). Zapewnia to poziom izolacji, który pomaga zapobiegać wzajemnemu zakłócaniu się procesów.

### Jak to działa:

1. Gdy tworzony jest nowy proces (np. przy użyciu wywołania systemowego `clone()`), proces może zostać przypisany do nowej lub istniejącej przestrzeni nazw PID. **Jeśli tworzona jest nowa przestrzeń nazw, proces staje się procesem "init" tej przestrzeni**.
2. **Jądro** utrzymuje **mapowanie między PID-ami w nowej przestrzeni nazw a odpowiadającymi im PID-ami** w przestrzeni nadrzędnej (tzn. w przestrzeni, z której utworzono nową przestrzeń nazw). To mapowanie **pozwala jądru tłumaczyć PID-y w razie potrzeby**, na przykład podczas wysyłania sygnałów między procesami w różnych przestrzeniach nazw.
3. **Procesy w obrębie przestrzeni nazw PID mogą widzieć i wchodzić w interakcję tylko z innymi procesami w tej samej przestrzeni nazw**. Nie są świadome procesów w innych przestrzeniach nazw, a ich PID-y są unikalne w obrębie ich przestrzeni.
4. Gdy **przestrzeń nazw PID zostaje zniszczona** (np. gdy proces "init" tej przestrzeni zakończy działanie), **wszystkie procesy w tej przestrzeni zostają zakończone**. Zapewnia to poprawne posprzątanie wszystkich zasobów związanych z przestrzenią nazw.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Kiedy `unshare` jest uruchamiany bez opcji `-f`, pojawia się błąd spowodowany sposobem, w jaki Linux obsługuje nowe przestrzenie nazw PID (Process ID). Poniżej przedstawiono kluczowe informacje i rozwiązanie:

1. **Wyjaśnienie problemu**:

- Jądro Linuxa pozwala procesowi tworzyć nowe przestrzenie nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje utworzenie nowej przestrzeni nazw PID (określany jako "unshare"), nie wchodzi do tej nowej przestrzeni nazw; robią to tylko jego procesy potomne.
- Uruchomienie %unshare -p /bin/bash% uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces zakończy działanie, jeśli nie ma innych procesów, powoduje to sprzątanie przestrzeni nazw, ponieważ PID 1 ma specjalną rolę adoptowania procesów osieroconych. Jądro Linux wyłączy wtedy alokację PID w tej przestrzeni nazw.

2. **Konsekwencja**:

- Wyjście PID 1 w nowej przestrzeni nazw powoduje wyczyszczenie flagi PIDNS_HASH_ADDING. To sprawia, że funkcja `alloc_pid` nie może przydzielić nowego PID przy tworzeniu nowego procesu, co skutkuje błędem "Cannot allocate memory".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja powoduje, że `unshare` wykonuje fork nowego procesu po utworzeniu nowej przestrzeni nazw PID.
- Uruchomienie %unshare -fp /bin/bash% zapewnia, że sam `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie osadzone w tej przestrzeni, co zapobiega przedwczesnemu zakończeniu PID 1 i pozwala na normalną alokację PID.

Upewniając się, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest poprawnie utrzymywana, co pozwala `/bin/bash` i jego procesom potomnym działać bez napotkania błędu alokacji pamięci.

</details>

Montując nową instancję systemu plików `/proc` przy użyciu parametru `--mount-proc`, zapewniasz, że nowa przestrzeń nazw montowania ma **dokładny i odizolowany widok informacji o procesach specyficznych dla tej przestrzeni nazw**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w którym namespace znajduje się twój proces
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Znajdź wszystkie przestrzenie nazw PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Zauważ, że użytkownik root z początkowej (domyślnej) PID namespace może zobaczyć wszystkie procesy, nawet te w nowych PID namespace'ach, dlatego możemy zobaczyć wszystkie PID namespaces.

### Wejdź do PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Kiedy wejdziesz do przestrzeni PID z domyślnej przestrzeni nazw, nadal będziesz widzieć wszystkie procesy. Proces z tej przestrzeni PID będzie też widział nowy bash w tej przestrzeni PID.

Ponadto możesz **wejść do innej przestrzeni PID procesu tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni **bez deskryptora** wskazującego na nią (np. `/proc/self/ns/pid`)

## Najnowsze uwagi dotyczące eksploatacji

### CVE-2025-31133: wykorzystywanie `maskedPaths` do dostępu do PID-ów hosta

runc ≤1.2.7 pozwalał atakującym, którzy kontrolowali obrazy kontenerów lub workloady uruchamiane przez `runc exec`, zastąpić po stronie kontenera `/dev/null` tuż przed tym, jak runtime maskował wrażliwe wpisy procfs. Gdy wyścig się powiedzie, `/dev/null` może zostać zamieniony na symlink wskazujący na dowolną ścieżkę hosta (na przykład `/proc/sys/kernel/core_pattern`), więc nowy namespace PID kontenera nagle dziedziczy dostęp do odczytu/zapisu globalnych ustawień procfs hosta, mimo że nigdy nie opuścił własnej przestrzeni nazw. Gdy `core_pattern` lub `/proc/sysrq-trigger` będzie zapisywalny, wygenerowanie coredumpa lub wywołanie SysRq daje wykonanie kodu lub denial of service w przestrzeni PID hosta.

Praktyczny przebieg:

1. Zbuduj OCI bundle, którego rootfs zastępuje `/dev/null` linkiem do ścieżki hosta, której potrzebujesz (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Uruchom kontener przed załataniem, tak aby runc bind-mountował docelowy plik procfs hosta nad tym linkiem.
3. W obrębie namespace kontenera zapisz do teraz-ujawnionego pliku procfs (np. ustaw `core_pattern` na helper reverse shell) i spowoduj awarię dowolnego procesu, aby zmusić jądro hosta do wykonania twojego helpera w kontekście PID 1.

Możesz szybko sprawdzić, czy bundle maskuje odpowiednie pliki przed jego uruchomieniem:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Jeśli w środowisku uruchomieniowym brakuje oczekiwanego wpisu maskującego (lub zostanie on pominięty, ponieważ `/dev/null` zniknął), traktuj kontener jako mogący mieć widoczność PID hosta.

### Iniekcja przestrzeni nazw za pomocą `insject`

`insject` firmy NCC Group ładuje się jako ładunek LD_PRELOAD, który hookuje późny etap w docelowym programie (domyślnie `main`) i wykonuje sekwencję wywołań `setns()` po `execve()`. To pozwala na dołączenie z hosta (lub innego kontenera) do przestrzeni PID ofiary *po* inicjalizacji jej runtime, zachowując widok `/proc/<pid>` bez konieczności kopiowania binarek do systemu plików kontenera. Ponieważ `insject` może odroczyć dołączenie do przestrzeni PID aż do fork(), możesz utrzymać jeden wątek w namespace hosta (z CAP_SYS_PTRACE), podczas gdy inny wątek wykonuje się w docelowej przestrzeni PID, tworząc potężne prymitywy debugowania lub ofensywne.

Przykładowe użycie:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Najważniejsze wnioski dotyczące wykorzystywania lub obrony przed namespace injection:

- Użyj `-S/--strict`, aby wymusić, by `insject` przerwał, jeśli wątki już istnieją lub dołączenia namespace zakończą się niepowodzeniem — w przeciwnym razie możesz pozostawić częściowo migrowane wątki obejmujące przestrzenie PID hosta i kontenera.
- Nigdy nie dołączaj narzędzi, które nadal trzymają zapisywalne deskryptory plików hosta, chyba że dołączysz też mount namespace — w przeciwnym razie każdy proces wewnątrz PID namespace może użyć ptrace na twoim helperze i ponownie wykorzystać te deskryptory do manipulacji zasobami hosta.

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
