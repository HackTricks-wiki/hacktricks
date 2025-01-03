# Docker-Sicherheit

{{#include ../../../banners/hacktricks-training.md}}

## **Grundlegende Sicherheit des Docker-Engines**

Der **Docker-Engine** verwendet die **Namespaces** und **Cgroups** des Linux-Kernels, um Container zu isolieren und bietet eine grundlegende Sicherheitsebene. Zusätzlicher Schutz wird durch **Capabilities dropping**, **Seccomp** und **SELinux/AppArmor** bereitgestellt, was die Container-Isolation verbessert. Ein **auth plugin** kann die Benutzeraktionen weiter einschränken.

![Docker-Sicherheit](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Sicherer Zugriff auf den Docker-Engine

Der Docker-Engine kann entweder lokal über einen Unix-Socket oder remote über HTTP zugegriffen werden. Für den Remote-Zugriff ist es wichtig, HTTPS und **TLS** zu verwenden, um Vertraulichkeit, Integrität und Authentifizierung sicherzustellen.

Der Docker-Engine hört standardmäßig auf dem Unix-Socket unter `unix:///var/run/docker.sock`. Auf Ubuntu-Systemen sind die Startoptionen von Docker in `/etc/default/docker` definiert. Um den Remote-Zugriff auf die Docker-API und den Client zu ermöglichen, exponieren Sie den Docker-Daemon über einen HTTP-Socket, indem Sie die folgenden Einstellungen hinzufügen:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Es wird jedoch nicht empfohlen, den Docker-Daemon über HTTP aus Sicherheitsgründen freizugeben. Es ist ratsam, Verbindungen mit HTTPS abzusichern. Es gibt zwei Hauptansätze zur Sicherung der Verbindung:

1. Der Client überprüft die Identität des Servers.
2. Sowohl der Client als auch der Server authentifizieren gegenseitig ihre Identität.

Zertifikate werden verwendet, um die Identität eines Servers zu bestätigen. Für detaillierte Beispiele beider Methoden siehe [**diese Anleitung**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sicherheit von Container-Images

Container-Images können in privaten oder öffentlichen Repositories gespeichert werden. Docker bietet mehrere Speicheroptionen für Container-Images:

- [**Docker Hub**](https://hub.docker.com): Ein öffentlicher Registrierungsdienst von Docker.
- [**Docker Registry**](https://github.com/docker/distribution): Ein Open-Source-Projekt, das es Benutzern ermöglicht, ihre eigene Registry zu hosten.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Das kommerzielle Registrierungsangebot von Docker, das rollenbasierte Benutzerauthentifizierung und Integration mit LDAP-Verzeichnisdiensten bietet.

### Bild-Scanning

Container können **Sicherheitsanfälligkeiten** aufweisen, entweder aufgrund des Basis-Images oder aufgrund der auf dem Basis-Image installierten Software. Docker arbeitet an einem Projekt namens **Nautilus**, das Sicherheits-Scans von Containern durchführt und die Anfälligkeiten auflistet. Nautilus funktioniert, indem es jede Container-Image-Schicht mit einem Anfälligkeitsrepository vergleicht, um Sicherheitslücken zu identifizieren.

Für weitere [**Informationen lesen Sie dies**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

Der **`docker scan`** Befehl ermöglicht es Ihnen, vorhandene Docker-Images mit dem Bildnamen oder der ID zu scannen. Führen Sie beispielsweise den folgenden Befehl aus, um das hello-world-Image zu scannen:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker Image Signing

Docker-Image-Signierung gewährleistet die Sicherheit und Integrität von Bildern, die in Containern verwendet werden. Hier ist eine kurze Erklärung:

- **Docker Content Trust** nutzt das Notary-Projekt, das auf The Update Framework (TUF) basiert, um die Bildsignierung zu verwalten. Für weitere Informationen siehe [Notary](https://github.com/docker/notary) und [TUF](https://theupdateframework.github.io).
- Um Docker Content Trust zu aktivieren, setze `export DOCKER_CONTENT_TRUST=1`. Diese Funktion ist standardmäßig in Docker-Version 1.10 und höher deaktiviert.
- Mit dieser aktivierten Funktion können nur signierte Bilder heruntergeladen werden. Der erste Bild-Upload erfordert die Festlegung von Passphrasen für die Root- und Tagging-Schlüssel, wobei Docker auch Yubikey zur Verbesserung der Sicherheit unterstützt. Weitere Details sind [hier](https://blog.docker.com/2015/11/docker-content-trust-yubikey/) zu finden.
- Der Versuch, ein unsigniertes Bild mit aktiviertem Content Trust herunterzuladen, führt zu einem "No trust data for latest"-Fehler.
- Bei Bild-Uploads nach dem ersten Mal fragt Docker nach der Passphrase des Repository-Schlüssels, um das Bild zu signieren.

Um deine privaten Schlüssel zu sichern, verwende den Befehl:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Beim Wechseln von Docker-Hosts ist es notwendig, die Root- und Repository-Schlüssel zu verschieben, um den Betrieb aufrechtzuerhalten.

## Sicherheitsmerkmale von Containern

<details>

<summary>Zusammenfassung der Sicherheitsmerkmale von Containern</summary>

**Hauptmerkmale der Prozessisolierung**

In containerisierten Umgebungen ist die Isolierung von Projekten und deren Prozessen von größter Bedeutung für die Sicherheit und das Ressourcenmanagement. Hier ist eine vereinfachte Erklärung der Schlüsselkonzepte:

**Namespaces**

- **Zweck**: Sicherstellung der Isolation von Ressourcen wie Prozessen, Netzwerk und Dateisystemen. Insbesondere in Docker halten Namespaces die Prozesse eines Containers von dem Host und anderen Containern getrennt.
- **Verwendung von `unshare`**: Der Befehl `unshare` (oder der zugrunde liegende Syscall) wird verwendet, um neue Namespaces zu erstellen und eine zusätzliche Isolationsschicht bereitzustellen. Während Kubernetes dies nicht grundsätzlich blockiert, tut es Docker.
- **Einschränkung**: Das Erstellen neuer Namespaces erlaubt es einem Prozess nicht, zu den Standard-Namespaces des Hosts zurückzukehren. Um in die Host-Namespaces einzudringen, benötigt man typischerweise Zugriff auf das `/proc`-Verzeichnis des Hosts und verwendet `nsenter` für den Zugang.

**Control Groups (CGroups)**

- **Funktion**: Primär verwendet zur Zuteilung von Ressourcen unter Prozessen.
- **Sicherheitsaspekt**: CGroups selbst bieten keine Isolationssicherheit, außer für die Funktion `release_agent`, die, wenn sie falsch konfiguriert ist, potenziell für unbefugten Zugriff ausgenutzt werden könnte.

**Capability Drop**

- **Bedeutung**: Es ist ein entscheidendes Sicherheitsmerkmal für die Prozessisolierung.
- **Funktionalität**: Es schränkt die Aktionen ein, die ein Root-Prozess ausführen kann, indem bestimmte Fähigkeiten entzogen werden. Selbst wenn ein Prozess mit Root-Rechten ausgeführt wird, verhindert das Fehlen der erforderlichen Fähigkeiten, dass er privilegierte Aktionen ausführt, da die Syscalls aufgrund unzureichender Berechtigungen fehlschlagen.

Dies sind die **verbleibenden Fähigkeiten**, nachdem der Prozess die anderen fallen gelassen hat:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Es ist standardmäßig in Docker aktiviert. Es hilft, die **Systemaufrufe** weiter zu **beschränken**, die der Prozess aufrufen kann.\
Das **Standard-Docker-Seccomp-Profil** finden Sie unter [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker hat eine Vorlage, die Sie aktivieren können: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Dies ermöglicht es, Fähigkeiten, Systemaufrufe, den Zugriff auf Dateien und Ordner zu reduzieren...

</details>

### Namespaces

**Namespaces** sind ein Feature des Linux-Kernels, das **Kernel-Ressourcen partitioniert**, sodass eine Gruppe von **Prozessen** eine Gruppe von **Ressourcen** sieht, während eine **andere** Gruppe von **Prozessen** eine **andere** Gruppe von Ressourcen sieht. Das Feature funktioniert, indem es denselben Namespace für eine Gruppe von Ressourcen und Prozessen hat, aber diese Namespaces auf unterschiedliche Ressourcen verweisen. Ressourcen können in mehreren Räumen existieren.

Docker nutzt die folgenden Linux-Kernel-Namespaces, um die Container-Isolierung zu erreichen:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Für **weitere Informationen über die Namespaces** besuchen Sie die folgende Seite:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

Die Linux-Kernel-Funktion **cgroups** bietet die Möglichkeit, **Ressourcen wie CPU, Speicher, IO, Netzwerkbandbreite** unter einer Gruppe von Prozessen zu **beschränken**. Docker ermöglicht die Erstellung von Containern unter Verwendung der cgroup-Funktion, die eine Ressourcensteuerung für den spezifischen Container ermöglicht.\
Nachfolgend ein Container, dessen Benutzerspeicher auf 500m, Kernel-Speicher auf 50m, CPU-Anteil auf 512 und blkio-weight auf 400 begrenzt ist. Der CPU-Anteil ist ein Verhältnis, das die CPU-Nutzung des Containers steuert. Er hat einen Standardwert von 1024 und einen Bereich von 0 bis 1024. Wenn drei Container denselben CPU-Anteil von 1024 haben, kann jeder Container bis zu 33 % der CPU im Falle von CPU-Ressourcenkonflikten nutzen. blkio-weight ist ein Verhältnis, das die IO des Containers steuert. Es hat einen Standardwert von 500 und einen Bereich von 10 bis 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Um die cgroup eines Containers zu erhalten, können Sie Folgendes tun:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Für weitere Informationen siehe:

{{#ref}}
cgroups.md
{{#endref}}

### Fähigkeiten

Fähigkeiten ermöglichen **eine genauere Kontrolle über die Fähigkeiten, die für den Root-Benutzer erlaubt sein können**. Docker verwendet die Linux-Kernel-Fähigkeitsfunktion, um **die Operationen zu begrenzen, die innerhalb eines Containers durchgeführt werden können**, unabhängig von der Art des Benutzers.

Wenn ein Docker-Container ausgeführt wird, **gibt der Prozess sensible Fähigkeiten auf, die der Prozess nutzen könnte, um aus der Isolation zu entkommen**. Dies versucht sicherzustellen, dass der Prozess keine sensiblen Aktionen ausführen und entkommen kann:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp in Docker

Dies ist eine Sicherheitsfunktion, die es Docker ermöglicht, **die Syscalls** zu begrenzen, die innerhalb des Containers verwendet werden können:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor in Docker

**AppArmor** ist eine Kernel-Erweiterung, um **Container** auf eine **begrenzte** Menge von **Ressourcen** mit **programmbezogenen Profilen** zu beschränken.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux in Docker

- **Labeling-System**: SELinux weist jedem Prozess und jedem Dateisystemobjekt ein einzigartiges Label zu.
- **Durchsetzung von Richtlinien**: Es setzt Sicherheitsrichtlinien durch, die definieren, welche Aktionen ein Prozesslabel auf anderen Labels im System ausführen kann.
- **Container-Prozess-Labels**: Wenn Container-Engines Container-Prozesse initiieren, wird ihnen typischerweise ein eingeschränktes SELinux-Label, häufig `container_t`, zugewiesen.
- **Dateilabeling innerhalb von Containern**: Dateien innerhalb des Containers werden normalerweise als `container_file_t` gekennzeichnet.
- **Richtlinienregeln**: Die SELinux-Richtlinie stellt hauptsächlich sicher, dass Prozesse mit dem Label `container_t` nur mit Dateien interagieren können, die als `container_file_t` gekennzeichnet sind.

Dieser Mechanismus stellt sicher, dass selbst wenn ein Prozess innerhalb eines Containers kompromittiert wird, er auf die Interaktion mit Objekten beschränkt ist, die die entsprechenden Labels haben, was den potenziellen Schaden durch solche Kompromittierungen erheblich begrenzt.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

In Docker spielt ein Autorisierungs-Plugin eine entscheidende Rolle für die Sicherheit, indem es entscheidet, ob Anfragen an den Docker-Daemon erlaubt oder blockiert werden. Diese Entscheidung wird getroffen, indem zwei wichtige Kontexte untersucht werden:

- **Authentifizierungskontext**: Dies umfasst umfassende Informationen über den Benutzer, wie wer sie sind und wie sie sich authentifiziert haben.
- **Befehlskontext**: Dies umfasst alle relevanten Daten, die mit der gestellten Anfrage zusammenhängen.

Diese Kontexte helfen sicherzustellen, dass nur legitime Anfragen von authentifizierten Benutzern verarbeitet werden, was die Sicherheit der Docker-Operationen erhöht.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS von einem Container

Wenn Sie die Ressourcen, die ein Container nutzen kann, nicht ordnungsgemäß begrenzen, könnte ein kompromittierter Container den Host, auf dem er läuft, DoS.

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- Bandwidth DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interessante Docker-Flags

### --privileged-Flag

Auf der folgenden Seite können Sie lernen, **was der `--privileged`-Flag impliziert**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

Wenn Sie einen Container ausführen, in dem ein Angreifer es schafft, als Benutzer mit niedrigen Rechten Zugriff zu erhalten. Wenn Sie eine **fehlerhaft konfigurierte SUID-Binärdatei** haben, kann der Angreifer diese missbrauchen und **die Privilegien innerhalb** des Containers eskalieren. Dies könnte ihm ermöglichen, aus dem Container zu entkommen.

Das Ausführen des Containers mit der aktivierten **`no-new-privileges`**-Option wird **diese Art der Privilegieneskalation verhindern**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Andere
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Für weitere **`--security-opt`** Optionen siehe: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Weitere Sicherheitsüberlegungen

### Verwaltung von Geheimnissen: Best Practices

Es ist entscheidend, Geheimnisse nicht direkt in Docker-Images einzubetten oder Umgebungsvariablen zu verwenden, da diese Methoden Ihre sensiblen Informationen für jeden, der Zugriff auf den Container hat, durch Befehle wie `docker inspect` oder `exec` offenlegen.

**Docker-Volumes** sind eine sicherere Alternative, die empfohlen wird, um auf sensible Informationen zuzugreifen. Sie können als temporäres Dateisystem im Speicher genutzt werden, wodurch die Risiken im Zusammenhang mit `docker inspect` und Protokollierung gemindert werden. Allerdings könnten Root-Benutzer und solche mit `exec`-Zugriff auf den Container weiterhin auf die Geheimnisse zugreifen.

**Docker-Secrets** bieten eine noch sicherere Methode zur Handhabung sensibler Informationen. Für Instanzen, die während der Image-Bauphase Geheimnisse benötigen, bietet **BuildKit** eine effiziente Lösung mit Unterstützung für Geheimnisse zur Bauzeit, die die Baugeschwindigkeit erhöht und zusätzliche Funktionen bereitstellt.

Um BuildKit zu nutzen, kann es auf drei Arten aktiviert werden:

1. Durch eine Umgebungsvariable: `export DOCKER_BUILDKIT=1`
2. Durch das Voranstellen von Befehlen: `DOCKER_BUILDKIT=1 docker build .`
3. Durch die standardmäßige Aktivierung in der Docker-Konfiguration: `{ "features": { "buildkit": true } }`, gefolgt von einem Docker-Neustart.

BuildKit ermöglicht die Verwendung von Geheimnissen zur Bauzeit mit der Option `--secret`, um sicherzustellen, dass diese Geheimnisse nicht im Image-Bau-Cache oder im endgültigen Image enthalten sind, indem ein Befehl wie folgt verwendet wird:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Für Geheimnisse, die in einem laufenden Container benötigt werden, bieten **Docker Compose und Kubernetes** robuste Lösungen. Docker Compose verwendet einen `secrets`-Schlüssel in der Dienstdefinition, um Geheimnisdateien anzugeben, wie im folgenden Beispiel einer `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Diese Konfiguration ermöglicht die Verwendung von Secrets beim Starten von Diensten mit Docker Compose.

In Kubernetes-Umgebungen werden Secrets nativ unterstützt und können mit Tools wie [Helm-Secrets](https://github.com/futuresimple/helm-secrets) weiter verwaltet werden. Die rollenbasierten Zugriffskontrollen (RBAC) von Kubernetes verbessern die Sicherheit des Secret-Managements, ähnlich wie bei Docker Enterprise.

### gVisor

**gVisor** ist ein Anwendungs-Kernel, der in Go geschrieben ist und einen wesentlichen Teil der Linux-Systemoberfläche implementiert. Er umfasst eine [Open Container Initiative (OCI)](https://www.opencontainers.org) Runtime namens `runsc`, die eine **Isolationsgrenze zwischen der Anwendung und dem Host-Kernel** bietet. Die `runsc` Runtime integriert sich mit Docker und Kubernetes, was es einfach macht, sandboxed Container auszuführen.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** ist eine Open-Source-Community, die daran arbeitet, eine sichere Container-Runtime mit leichten virtuellen Maschinen zu erstellen, die sich anfühlen und wie Container funktionieren, aber **stärkere Arbeitslastisolierung durch Hardware-Virtualisierung** Technologie als zweite Verteidigungsebene bieten.

{% embed url="https://katacontainers.io/" %}

### Zusammenfassende Tipps

- **Verwenden Sie nicht das `--privileged` Flag oder mounten Sie einen** [**Docker-Socket innerhalb des Containers**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Der Docker-Socket ermöglicht das Erstellen von Containern, sodass es ein einfacher Weg ist, die vollständige Kontrolle über den Host zu übernehmen, indem beispielsweise ein weiterer Container mit dem `--privileged` Flag ausgeführt wird.
- **Führen Sie nicht als root innerhalb des Containers aus. Verwenden Sie einen** [**anderen Benutzer**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **und** [**Benutzernamensräume**](https://docs.docker.com/engine/security/userns-remap/)**.** Der Root im Container ist derselbe wie auf dem Host, es sei denn, er wird mit Benutzernamensräumen umgeschrieben. Er ist nur leicht eingeschränkt durch hauptsächlich Linux-Namensräume, Fähigkeiten und cgroups.
- [**Entfernen Sie alle Fähigkeiten**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) und aktivieren Sie nur die, die erforderlich sind** (`--cap-add=...`). Viele Arbeitslasten benötigen keine Fähigkeiten, und das Hinzufügen erhöht den Umfang eines potenziellen Angriffs.
- [**Verwenden Sie die Sicherheitsoption „no-new-privileges“**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/), um zu verhindern, dass Prozesse mehr Privilegien erlangen, beispielsweise durch SUID-Binärdateien.
- [**Begrenzen Sie die Ressourcen, die dem Container zur Verfügung stehen**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Ressourcenlimits können die Maschine vor Denial-of-Service-Angriffen schützen.
- **Passen Sie** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(oder SELinux)** Profile an, um die Aktionen und Syscalls, die für den Container verfügbar sind, auf das Minimum zu beschränken.
- **Verwenden Sie** [**offizielle Docker-Images**](https://docs.docker.com/docker-hub/official_images/) **und verlangen Sie Signaturen** oder erstellen Sie Ihre eigenen basierend auf ihnen. Erben oder verwenden Sie keine [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) Images. Bewahren Sie auch Root-Schlüssel und Passphrasen an einem sicheren Ort auf. Docker plant, Schlüssel mit UCP zu verwalten.
- **Bauen Sie regelmäßig** Ihre Images neu, um **Sicherheitsupdates auf den Host und die Images anzuwenden.**
- Verwalten Sie Ihre **Secrets weise**, damit es für den Angreifer schwierig ist, darauf zuzugreifen.
- Wenn Sie **den Docker-Daemon exponieren, verwenden Sie HTTPS** mit Client- und Serverauthentifizierung.
- In Ihrem Dockerfile, **bevorzugen Sie COPY anstelle von ADD**. ADD extrahiert automatisch gezippte Dateien und kann Dateien von URLs kopieren. COPY hat diese Fähigkeiten nicht. Vermeiden Sie wann immer möglich die Verwendung von ADD, damit Sie nicht anfällig für Angriffe über entfernte URLs und Zip-Dateien sind.
- Haben Sie **getrennte Container für jeden Mikro-s**ervice.
- **Setzen Sie kein ssh** innerhalb des Containers ein, „docker exec“ kann verwendet werden, um sich in den Container einzuloggen.
- Haben Sie **kleinere** Container **Images**.

## Docker Breakout / Privilegieneskalation

Wenn Sie **innerhalb eines Docker-Containers** sind oder Zugriff auf einen Benutzer in der **Docker-Gruppe** haben, könnten Sie versuchen, **zu entkommen und Privilegien zu eskalieren**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Umgehung des Docker-Authentifizierungs-Plugins

Wenn Sie Zugriff auf den Docker-Socket haben oder Zugriff auf einen Benutzer in der **Docker-Gruppe** haben, aber Ihre Aktionen durch ein Docker-Auth-Plugin eingeschränkt werden, überprüfen Sie, ob Sie es **umgehen können:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Härtung von Docker

- Das Tool [**docker-bench-security**](https://github.com/docker/docker-bench-security) ist ein Skript, das Dutzende von gängigen Best Practices zur Bereitstellung von Docker-Containern in der Produktion überprüft. Die Tests sind alle automatisiert und basieren auf dem [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Sie müssen das Tool vom Host ausführen, der Docker ausführt, oder von einem Container mit ausreichenden Berechtigungen. Finden Sie heraus, **wie Sie es im README ausführen:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referenzen

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

{{#include ../../../banners/hacktricks-training.md}}
