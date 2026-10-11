# Acquisizione del traffico, firewall e valutazione dell’egress

{{#include ../../banners/hacktricks-training.md}}

Dopo aver individuato [i listener locali e i socket Unix](local-network-and-socket-triage.md), verifica quali interfacce trasportano il loro traffico e quali regole di firewall o proxy influiscono sulla raggiungibilità. Un servizio accessibile solo tramite loopback può trasportare intestazioni HTTP sensibili anche se non è raggiungibile da un altro host.

## Verifica i permessi di cattura e scegli un’interfaccia

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` può disporre di capability per l'acquisizione dei pacchetti anche quando l'utente corrente non ha accesso a sudo. Controlla le capability effettive dell'eseguibile e i permessi del gruppo. Acquisisci sull'interfaccia e per la durata minime utili, applicando un filtro: una cattura può contenere credenziali o dati personali.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` ricostruisce i flussi TCP in chiaro; `tshark` può filtrare ed estrarre campi da una cattura. Per il traffico TLS, la decrittazione richiede le chiavi degli endpoint oppure un client supportato configurato con `SSLKEYLOGFILE` prima della connessione. La [pagina di triage della rete locale](local-network-and-socket-triage.md#tls-key-logging) illustra questa procedura. Non considerare leggibile in chiaro una cattura cifrata.

Gli artefatti dell'incidente archiviati possono cambiare questa valutazione. Un [core dump Linux è un'immagine della memoria del processo](https://man7.org/linux/man-pages/man5/core.5.html) che potrebbe conservare una chiave di sessione; se un dump leggibile e una cattura di pacchetti provengono dallo stesso processo e dalla stessa sessione, un analista potrebbe riuscire a decrittare quel traffico. Per prima cosa, inventaria i percorsi e i permessi degli artefatti, quindi verifica separatamente l'identità del processo, l'ora della cattura, il protocollo e il formato della chiave. Il traffico decrittato o un archivio recuperato sono indizi di divulgazione, non prove dell'accesso all'account di un'altra persona: qualsiasi materiale parziale di una chiave SSH deve comunque essere ricostruito, confrontato con la chiave pubblica corrispondente e accettato dalle policy SSH di quell'account. Evita di mostrare il contenuto dei core dump o i payload delle catture nell'output di enumerazioni estese.

## Identificare i livelli del firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` e `iptables` possono essere esposti tramite wrapper della distribuzione, come UFW o firewalld. Leggi le regole attive e la configurazione persistente del wrapper: una regola visibile in una rappresentazione potrebbe essere stata generata da un altro strumento. Esamina interfaccia, direzione, origine, destinazione, protocollo, porta e stato della connessione prima di attribuire il blocco di un servizio a una regola specifica. Vedi [revisione delle regole nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) per un esempio specifico.

## Testare il traffico in uscita e il comportamento del proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Distingui un errore DNS da un errore TCP, TLS o del proxy. Verifica la destinazione e il protocollo specifici pertinenti alla valutazione; la raggiungibilità tramite ICMP non implica che TCP o UDP siano consentiti. Se è configurato un proxy, confronta la richiesta prevista tramite proxy con la stessa destinazione applicando le regole `no_proxy` pertinenti. Anche un port forward locale può rendere accessibile altrove un servizio loopback, quindi controlla i listener attivi e i tunnel SSH quando la configurazione del firewall e l’esposizione osservata non corrispondono.
{{#include ../../banners/hacktricks-training.md}}
