# Przestrzeń użytkownika

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Odniesienia

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Podstawowe informacje

Przestrzeń użytkownika to funkcja jądra Linux, która **zapewnia izolację mapowań identyfikatorów użytkowników i grup**, pozwalając każdej przestrzeni użytkownika mieć swój **własny zestaw identyfikatorów użytkowników i grup**. Ta izolacja umożliwia procesom działającym w różnych przestrzeniach użytkownika **posiadanie różnych uprawnień i właścicieli**, nawet jeśli numerycznie korzystają z tych samych identyfikatorów użytkowników i grup.

Przestrzenie użytkownika są szczególnie użyteczne w konteneryzacji, gdzie każdy kontener powinien mieć własny niezależny zestaw identyfikatorów użytkowników i grup, co pozwala na lepsze zabezpieczenie i izolację między kontenerami a systemem hosta.

### Jak to działa:

1. Kiedy tworzona jest nowa przestrzeń użytkownika, **rozpoczyna się ona z pustym zestawem mapowań identyfikatorów użytkowników i grup**. Oznacza to, że każdy proces działający w nowej przestrzeni użytkownika będzie **początkowo nie posiadał uprawnień poza tą przestrzenią**.
2. Można ustanowić mapowania identyfikatorów pomiędzy identyfikatorami użytkowników i grup w nowej przestrzeni a tymi w przestrzeni nadrzędnej (lub hosta). To **pozwala procesom w nowej przestrzeni uzyskać uprawnienia i własność odpowiadającą identyfikatorom użytkowników i grup w przestrzeni nadrzędnej**. Mapowania ID mogą być jednak ograniczone do konkretnych zakresów i podzbiorów identyfikatorów, co umożliwia precyzyjną kontrolę nad uprawnieniami przyznawanymi procesom w nowej przestrzeni.
3. W obrębie przestrzeni użytkownika **procesy mogą mieć pełne uprawnienia roota (UID 0) do operacji wewnątrz tej przestrzeni**, jednocześnie mając ograniczone uprawnienia poza nią. Pozwala to **kontenerom uruchamiać się z przywilejami podobnymi do roota w obrębie własnej przestrzeni bez posiadania pełnych uprawnień roota na systemie hosta**.
4. Procesy mogą przechodzić między przestrzeniami za pomocą wywołania systemowego `setns()` lub tworzyć nowe przestrzenie używając `unshare()` lub `clone()` z flagą `CLONE_NEWUSER`. Kiedy proces przechodzi do nowej przestrzeni lub ją tworzy, zaczyna korzystać z mapowań identyfikatorów użytkowników i grup przypisanych do tej przestrzeni.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **dokładny i odizolowany widok informacji o procesach specyficznych dla tej przestrzeni nazw**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Wyjaśnienie problemu**:

- Kernel Linux pozwala procesowi tworzyć nowe przestrzenie nazw przy użyciu wywołania systemowego `unshare`. Jednak proces, który inicjuje utworzenie nowej przestrzeni nazw PID (nazywany procesem "unshare"), nie wchodzi do nowej przestrzeni nazw; jedynie jego procesy potomne to robią.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces zakończy działanie, inicjuje to czyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę adoptowania procesów sierot. Kernel Linux następnie wyłączy przydział PID w tej przestrzeni nazw.

2. **Konsekwencja**:

- Wyjście PID 1 w nowej przestrzeni nazw prowadzi do wyczyszczenia flagi `PIDNS_HASH_ADDING`. W rezultacie funkcja `alloc_pid` nie jest w stanie przydzielić nowego PID podczas tworzenia nowego procesu, powodując błąd "Cannot allocate memory".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja powoduje, że `unshare` forkuje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Aby użyć przestrzeni nazw użytkownika, daemon Dockera musi być uruchomiony z **`--userns-remap=default`** (W ubuntu 14.04 można to zrobić modyfikując `/etc/default/docker`, a następnie wykonując `sudo service docker restart`)

### Sprawdź, w jakiej przestrzeni nazw znajduje się twój proces
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Można sprawdzić mapowanie użytkowników z kontenera docker za pomocą:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Lub z hosta za pomocą:
```bash
cat /proc/<pid>/uid_map
```
### Znajdź wszystkie przestrzenie nazw użytkownika
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejście do przestrzeni nazw użytkownika
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Ponadto możesz **wejść do innego namespace procesu tylko jeśli jesteś root**. A **nie możesz** **wejść** do innego namespace **bez deskryptora** wskazującego na niego (np. `/proc/self/ns/user`).

### Utwórz nowy namespace użytkownika (z mapowaniami)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Zasady mapowania UID/GID dla nieuprzywilejowanych

Gdy proces zapisujący do `uid_map`/`gid_map` **nie posiada CAP_SETUID/CAP_SETGID w parent user namespace**, kernel wymusza surowsze reguły: dozwolone jest tylko **pojedyncze mapowanie** dla efektywnego UID/GID wywołującego, a dla `gid_map` musisz **najpierw wyłączyć `setgroups(2)`**, zapisując `deny` do `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mounts **przypinają mapowanie user namespace do mountu**, więc własność plików jest przemapowywana przy dostępie przez ten mount. Jest to powszechnie używane przez container runtimes (szczególnie rootless) do **udostępniania host paths bez rekurencyjnego `chown`**, jednocześnie wymuszając translację UID/GID namespace użytkownika.

Z perspektywy ofensywnej, **jeśli możesz stworzyć mount namespace i posiadać `CAP_SYS_ADMIN` wewnątrz swojego namespace użytkownika**, i system plików obsługuje ID-mapped mounts, możesz przemapować widoki własności bind mountów. To **nie zmienia własności na dysku**, ale może sprawić, że pliki normalnie niezapisywalne będą wyglądać, jakby były własnością twojego zmapowanego UID/GID w obrębie namespace.

### Odzyskiwanie uprawnień

W przypadku namespace'ów użytkownika, **kiedy tworzony jest nowy namespace użytkownika, proces, który wchodzi do tego namespace, otrzymuje pełny zestaw capabilities wewnątrz tego namespace**. Te uprawnienia pozwalają procesowi wykonywać operacje uprzywilejowane, takie jak **montowanie** **systemów plików**, tworzenie urządzeń czy zmiana własności plików, ale **tylko w kontekście tego namespace**.

Na przykład, gdy masz uprawnienie `CAP_SYS_ADMIN` w ramach namespace użytkownika, możesz wykonywać operacje, które zazwyczaj wymagają tego uprawnienia, jak montowanie systemów plików, ale tylko w kontekście twojego namespace użytkownika. Jakiekolwiek operacje wykonane z tym uprawnieniem nie wpłyną na system hosta ani inne namespace'y.

> [!WARNING]
> Dlatego, nawet jeśli uzyskanie nowego procesu wewnątrz nowego User namespace **przywróci ci wszystkie capabilities** (CapEff: 000001ffffffffff), w praktyce możesz **użyć tylko tych związanych z namespace** (np. mount), a nie wszystkich. Zatem samo to nie wystarcza, aby uciec z kontenera Docker.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referencje

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
