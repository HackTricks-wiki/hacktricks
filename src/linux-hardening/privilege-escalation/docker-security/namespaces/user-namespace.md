# Benutzer-Namespace

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referenzen

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Grundlegende Informationen

Ein user namespace ist eine Linux-Kernel-Funktion, die **Isolation von Benutzer- und Gruppen-ID-Zuordnungen bereitstellt**, sodass jeder user namespace sein **eigenes Set von Benutzer- und Gruppen-IDs** haben kann. Diese Isolation ermöglicht es Prozessen, die in verschiedenen user namespaces laufen, **unterschiedliche Privilegien und Besitzverhältnisse** zu haben, selbst wenn sie numerisch dieselben Benutzer- und Gruppen-IDs teilen.

User namespaces sind besonders nützlich bei der Containerisierung, wobei jeder Container sein eigenes unabhängiges Set von Benutzer- und Gruppen-IDs haben sollte, was eine bessere Sicherheit und Isolation zwischen Containern und dem Host-System ermöglicht.

### Funktionsweise:

1. Wenn ein neuer user namespace erstellt wird, **beginnt er mit einem leeren Satz von Benutzer- und Gruppen-ID-Zuordnungen**. Das bedeutet, dass jeder Prozess, der im neuen user namespace läuft, **anfangs keine Privilegien außerhalb des Namespace** hat.
2. ID-Zuordnungen können zwischen den Benutzer- und Gruppen-IDs im neuen Namespace und denen im übergeordneten (oder Host-)Namespace hergestellt werden. Das **erlaubt Prozessen im neuen Namespace, Privilegien und Besitz entsprechend den Benutzer- und Gruppen-IDs im übergeordneten Namespace zu haben**. Die ID-Zuordnungen können jedoch auf bestimmte Bereiche und Teilmengen von IDs beschränkt werden, was eine fein granulare Kontrolle über die an Prozesse im neuen Namespace vergebenen Privilegien erlaubt.
3. Innerhalb eines user namespace **können Prozesse volle Root-Privilegien (UID 0) für Operationen innerhalb des Namespace haben**, während sie außerhalb des Namespace eingeschränkte Privilegien behalten. Das ermöglicht **Containern, mit root-ähnlichen Fähigkeiten innerhalb ihres eigenen Namespace zu laufen, ohne volle Root-Privilegien auf dem Host-System zu besitzen**.
4. Prozesse können zwischen Namespaces wechseln, indem sie den `setns()` Systemaufruf verwenden oder neue Namespaces mit den Systemaufrufen `unshare()` oder `clone()` mit dem Flag `CLONE_NEWUSER` erstellen. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, beginnt er, die mit diesem Namespace verknüpften Benutzer- und Gruppen-ID-Zuordnungen zu verwenden.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running %unshare -p /bin/bash% starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing %unshare -fp /bin/bash% ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Um den User-Namespace zu verwenden, muss der Docker daemon mit **`--userns-remap=default`** gestartet werden (In ubuntu 14.04 kann dies durch Ändern von `/etc/default/docker` und dann Ausführen von `sudo service docker restart` erfolgen)

### Prüfen, in welchem Namespace sich dein Prozess befindet
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Es ist möglich, die Benutzerzuordnung (user map) aus dem docker container heraus zu prüfen mit:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Oder vom Host mit:
```bash
cat /proc/<pid>/uid_map
```
### Alle User-Namespaces finden
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### In einen User-Namespace eintreten
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Außerdem kannst du nur **in einen anderen Prozess-Namespace wechseln, wenn du root bist**. Und du **kannst nicht** **in einen anderen Namespace wechseln** **ohne einen Descriptor**, der auf ihn zeigt (wie `/proc/self/ns/user`).

### Erstelle neuen User-Namespace (mit Mappings)
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
### Regeln für unprivilegierte UID/GID-Zuordnungen

Wenn der Prozess, der in `uid_map`/`gid_map` schreibt, **nicht über CAP_SETUID/CAP_SETGID im übergeordneten user namespace verfügt**, erzwingt der Kernel strengere Regeln: Es ist nur eine **einzige Zuordnung** für die effektive UID/GID des Aufrufers erlaubt, und für `gid_map` **müssen Sie zuerst `setgroups(2)` deaktivieren**, indem Sie `deny` in `/proc/<pid>/setgroups` schreiben.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-abgebildete Mounts (MOUNT_ATTR_IDMAP)

ID-abgebildete Mounts **hängen eine User-Namespace-Mapping an einen Mount an**, sodass Dateibesitz beim Zugriff über diesen Mount umgemappt wird. Dies wird häufig von container runtimes (insbesondere rootless) verwendet, um Host-Pfade zu teilen, ohne rekursives `chown`, und gleichzeitig die UID/GID-Übersetzung des User-Namespace durchzusetzen.

Aus offensiver Sicht, **wenn du eine mount namespace erstellen kannst und CAP_SYS_ADMIN innerhalb deines User-Namespace hältst**, und das Dateisystem ID-mapped mounts unterstützt, kannst du Besitz-*Views* von bind mounts ummappen. Dies **ändert nicht den on-disk Besitz**, aber es kann ansonsten unbeschreibbare Dateien innerhalb des Namespace so erscheinen lassen, als gehörten sie deinem gemappten UID/GID.

### Wiederherstellung von Capabilities

Im Fall von User-Namespaces **erhält der Prozess, der in den Namespace eintritt, beim Erstellen eines neuen User-Namespace innerhalb dieses Namespace eine vollständige Menge an Capabilities**. Diese Capabilities erlauben dem Prozess, privilegierte Operationen wie **mounting** **filesystems**, Erstellen von devices oder Ändern des Datei-Eigentums durchzuführen, aber **nur im Kontext seines User-Namespace**.

Zum Beispiel, wenn du die CAP_SYS_ADMIN Capability innerhalb eines User-Namespace hast, kannst du Operationen durchführen, die typischerweise diese Capability erfordern, wie das Mounten von filesystems, jedoch nur im Kontext deines User-Namespace. Alle Operationen, die du mit dieser Capability ausführst, wirken sich nicht auf das Host-System oder andere Namespaces aus.

> [!WARNING]
> Daher, selbst wenn das Platzieren eines neuen Prozesses in einem neuen User-Namespace **dir alle Capabilities zurückgibt** (CapEff: 000001ffffffffff), kannst du tatsächlich **nur diejenigen verwenden, die mit dem Namespace zusammenhängen** (mount zum Beispiel) und nicht alle. Daher reicht das für sich allein nicht aus, um aus einem Docker container zu entkommen.
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


## Referenzen

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
