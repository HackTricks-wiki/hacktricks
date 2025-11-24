# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Der PID (Process Identifier) Namespace ist ein Feature im Linux-Kernel, das Prozessisolation bereitstellt, indem es einer Gruppe von Prozessen ermöglicht, ein eigenes Set eindeutiger PIDs zu haben, getrennt von den PIDs in anderen Namespaces. Dies ist besonders nützlich bei der Containerisierung, wo Prozessisolation für Sicherheit und Ressourcenmanagement entscheidend ist.

Wenn ein neuer PID-Namespace erstellt wird, wird dem ersten Prozess in diesem Namespace die PID 1 zugewiesen. Dieser Prozess wird zum "init"-Prozess des neuen Namespace und ist dafür verantwortlich, andere Prozesse innerhalb des Namespace zu verwalten. Jeder weitere innerhalb des Namespace erstellte Prozess erhält eine eindeutige PID innerhalb dieses Namespace, und diese PIDs sind unabhängig von den PIDs in anderen Namespaces.

Aus der Perspektive eines Prozesses innerhalb eines PID-Namespaces kann er nur andere Prozesse im selben Namespace sehen. Er ist sich Prozessen in anderen Namespaces nicht bewusst und kann nicht mit ihnen mittels traditioneller Prozessverwaltungswerkzeuge (z. B. `kill`, `wait`, etc.) interagieren. Das bietet ein Maß an Isolation, das verhindert, dass Prozesse sich gegenseitig stören.

### Wie es funktioniert:

1. Wenn ein neuer Prozess erstellt wird (z. B. durch den Systemaufruf `clone()`), kann der Prozess einem neuen oder bestehenden PID-Namespace zugewiesen werden. **Wenn ein neuer Namespace erstellt wird, wird der Prozess zum "init"-Prozess dieses Namespace**.
2. Der **Kernel** pflegt eine **Zuordnung zwischen den PIDs im neuen Namespace und den entsprechenden PIDs** im übergeordneten Namespace (d. h. dem Namespace, aus dem der neue Namespace erstellt wurde). Diese Zuordnung **ermöglicht dem Kernel, PIDs bei Bedarf zu übersetzen**, etwa beim Senden von Signalen zwischen Prozessen in unterschiedlichen Namespaces.
3. **Prozesse innerhalb eines PID-Namespaces können nur andere Prozesse im selben Namespace sehen und mit ihnen interagieren**. Sie sind sich Prozessen in anderen Namespaces nicht bewusst, und ihre PIDs sind innerhalb ihres Namespaces eindeutig.
4. Wenn ein **PID-Namespace zerstört wird** (z. B. wenn der "init"-Prozess des Namespace beendet wird), werden **alle Prozesse innerhalb dieses Namespace beendet**. Dies stellt sicher, dass alle dem Namespace zugehörigen Ressourcen ordnungsgemäß freigegeben werden.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

Wenn Sie durch Mounten einer neuen Instanz des `/proc`-Dateisystems die Option `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Ansicht der prozessspezifischen Informationen dieses Namespaces** hat.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Prüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Alle PID namespaces finden
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Beachte, dass der root user aus dem initialen (default) PID namespace alle Prozesse sehen kann, sogar die in neuen PID namespaces; deshalb können wir alle PID namespaces sehen.

### In einen PID namespace wechseln
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **enter in another process PID namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## Aktuelle Hinweise zu Exploits

### CVE-2025-31133: abusing `maskedPaths` to reach host PIDs

runc ≤1.2.7 allowed attackers that control container images or `runc exec` workloads to replace the container-side `/dev/null` just before the runtime masked sensitive procfs entries. When the race succeeds, `/dev/null` can be turned into a symlink pointing at any host path (for example `/proc/sys/kernel/core_pattern`), so the new container PID namespace suddenly inherits read/write access to host-global procfs knobs even though it never left its own namespace. Once `core_pattern` or `/proc/sysrq-trigger` is writable, generating a coredump or triggering SysRq yields code execution or denial of service in the host PID namespace.

Praktischer Ablauf:

1. Erstelle ein OCI-Bundle, dessen rootfs `/dev/null` durch einen Link auf den gewünschten Host-Pfad ersetzt (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Starte den Container, bevor der Fix eingespielt ist, sodass runc das Host-procfs-Ziel über den Link bind-mountet.
3. Schreibe innerhalb des Container-Namespaces in die nun freigelegte procfs-Datei (z. B. `core_pattern` auf einen reverse shell helper zeigen) und lass einen beliebigen Prozess abstürzen, um den Host-Kernel dazu zu zwingen, deinen Helfer im PID-1-Kontext auszuführen.

Du kannst schnell prüfen, ob ein Bundle die richtigen Dateien maskiert, bevor du es startest:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Wenn zur Laufzeit ein erwarteter Maskierungseintrag fehlt (oder übersprungen wird, weil `/dev/null` verschwunden ist), behandle den Container so, als hätte er potenzielle Sichtbarkeit der Host-PIDs.

### Namespace-Injektion mit `insject`

NCC Groups `insject` wird als LD_PRELOAD-Payload geladen, hookt eine späte Phase im Zielprogramm (Standard `main`) und führt nach `execve()` eine Reihe von `setns()`-Aufrufen aus. Dadurch kannst du dich vom Host (oder einem anderen Container) in das PID-Namespace eines Opfers anhängen, *nachdem* dessen Laufzeit initialisiert wurde, und dabei die `/proc/<pid>`-Ansicht beibehalten, ohne Binärdateien ins Container-Dateisystem kopieren zu müssen. Weil `insject` das Betreten des PID-Namespaces bis zum Forken aufschieben kann, kannst du einen Thread im Host-Namespace (mit CAP_SYS_PTRACE) belassen, während ein anderer Thread im Ziel-PID-Namespace läuft, was mächtige Debugging- oder offensive Primitiven ermöglicht.

Beispiel:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Wichtigste Erkenntnisse beim Ausnutzen oder Verteidigen gegen namespace injection:

- Verwende `-S/--strict`, um `insject` zum Abbruch zu zwingen, falls Threads bereits existieren oder Namespace-Joins fehlschlagen; andernfalls könnten teilweise migrierte Threads zwischen Host- und Container-PID-Räumen verbleiben.
- Hänge niemals Tools an, die weiterhin beschreibbare host file descriptors halten, es sei denn, du trittst auch dem mount namespace bei — andernfalls kann jeder Prozess innerhalb der PID namespace deinen Helper per ptrace angreifen und diese Deskriptoren wiederverwenden, um Host-Ressourcen zu manipulieren.

## Referenzen

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
