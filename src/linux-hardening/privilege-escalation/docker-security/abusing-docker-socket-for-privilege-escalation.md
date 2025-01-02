# Missbrauch des Docker-Sockets zur Privilegieneskalation

{{#include ../../../banners/hacktricks-training.md}}

Es gibt einige Gelegenheiten, bei denen Sie **Zugriff auf den Docker-Socket** haben und ihn nutzen möchten, um **Privilegien zu eskalieren**. Einige Aktionen könnten sehr verdächtig sein, und Sie möchten sie möglicherweise vermeiden. Hier finden Sie verschiedene Flags, die nützlich sein können, um Privilegien zu eskalieren:

### Über Mount

Sie können verschiedene Teile des **Dateisystems** in einem als Root laufenden Container **einbinden** und auf sie **zugreifen**.\
Sie könnten auch **einen Mount missbrauchen, um Privilegien** innerhalb des Containers zu eskalieren.

- **`-v /:/host`** -> Binden Sie das Host-Dateisystem im Container ein, damit Sie das **Host-Dateisystem lesen** können.
- Wenn Sie **das Gefühl haben möchten, dass Sie sich im Host** befinden, aber im Container sind, könnten Sie andere Abwehrmechanismen mit Flags wie deaktivieren:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Dies ist ähnlich wie die vorherige Methode, aber hier binden wir das **Gerätedisk** ein. Führen Sie dann im Container `mount /dev/sda1 /mnt` aus, und Sie können auf das **Host-Dateisystem** in `/mnt` **zugreifen**.
- Führen Sie `fdisk -l` im Host aus, um das `</dev/sda1>`-Gerät zu finden, das Sie einbinden möchten.
- **`-v /tmp:/host`** -> Wenn Sie aus irgendeinem Grund **nur ein Verzeichnis** vom Host einbinden können und Sie Zugriff innerhalb des Hosts haben. Binden Sie es ein und erstellen Sie eine **`/bin/bash`** mit **suid** im eingebundenen Verzeichnis, damit Sie es **vom Host aus ausführen und zu root eskalieren** können.

> [!NOTE]
> Beachten Sie, dass Sie möglicherweise den Ordner `/tmp` nicht einbinden können, aber Sie können ein **anderes beschreibbares Verzeichnis** einbinden. Sie können beschreibbare Verzeichnisse mit `find / -writable -type d 2>/dev/null` finden.
>
> **Beachten Sie, dass nicht alle Verzeichnisse auf einem Linux-Rechner das suid-Bit unterstützen!** Um zu überprüfen, welche Verzeichnisse das suid-Bit unterstützen, führen Sie `mount | grep -v "nosuid"` aus. Zum Beispiel unterstützen normalerweise `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` und `/var/lib/lxcfs` nicht das suid-Bit.
>
> Beachten Sie auch, dass Sie, wenn Sie **`/etc`** oder einen anderen Ordner **mit Konfigurationsdateien** einbinden können, diese vom Docker-Container aus als Root ändern können, um sie **im Host zu missbrauchen** und Privilegien zu eskalieren (vielleicht durch Modifikation von `/etc/shadow`).

### Aus dem Container entkommen

- **`--privileged`** -> Mit diesem Flag [entfernen Sie alle Isolationen vom Container](docker-privileged.md#what-affects). Überprüfen Sie Techniken, um [aus privilegierten Containern als Root zu entkommen](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Um [Privilegien durch Missbrauch von Fähigkeiten zu eskalieren](../linux-capabilities.md), **gewähren Sie diese Fähigkeit dem Container** und deaktivieren Sie andere Schutzmethoden, die verhindern könnten, dass der Exploit funktioniert.

### Curl

Auf dieser Seite haben wir Möglichkeiten zur Eskalation von Privilegien unter Verwendung von Docker-Flags diskutiert. Sie finden **Möglichkeiten, diese Methoden mit dem curl**-Befehl zu missbrauchen, auf der Seite:

{{#include ../../../banners/hacktricks-training.md}}
