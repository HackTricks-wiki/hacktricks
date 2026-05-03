# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Migliora le tue competenze in Wireshark

### Tutorial

I seguenti tutorial sono fantastici per imparare alcuni trucchi base interessanti:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informazioni analizzate

**Informazioni esperte**

Cliccando su _**Analyze** --> **Expert Information**_ avrai una **panoramica** di ciò che sta accadendo nei pacchetti **analizzati**:

![](<../../../images/image (256).png>)

**Indirizzi risolti**

In _**Statistics --> Resolved Addresses**_ puoi trovare diverse **informazioni** che sono state "**risolte**" da wireshark come porta/trasporto verso protocollo, MAC verso il produttore, ecc. È interessante sapere cosa è coinvolto nella comunicazione.

![](<../../../images/image (893).png>)

**Gerarchia dei protocolli**

In _**Statistics --> Protocol Hierarchy**_ puoi trovare i **protocolli** **coinvolti** nella comunicazione e i dati su di essi.

![](<../../../images/image (586).png>)

**Conversazioni**

In _**Statistics --> Conversations**_ puoi trovare un **riepilogo delle conversazioni** nella comunicazione e i dati su di esse.

![](<../../../images/image (453).png>)

**Endpoint**

In _**Statistics --> Endpoints**_ puoi trovare un **riepilogo degli endpoint** nella comunicazione e i dati su ciascuno di essi.

![](<../../../images/image (896).png>)

**Info DNS**

In _**Statistics --> DNS**_ puoi trovare statistiche sulle richieste DNS catturate.

![](<../../../images/image (1063).png>)

**I/O Graph**

In _**Statistics --> I/O Graph**_ puoi trovare un **grafico della comunicazione.**

![](<../../../images/image (992).png>)

### Filtri

Qui puoi trovare i filtri di wireshark a seconda del protocollo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Nell'attuale Wireshark usa `tls.*` invece dei vecchi nomi di filtro `ssl.*`.\
Altri filtri interessanti:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN + richieste DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot sul SNI inviato nel ClientHello anche quando non puoi decifrare il payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Separa rapidamente sessioni classiche HTTPS, HTTP/2 e compatibili con HTTP/3
- `quic or http3`
- Trova traffico UDP/443 moderno che verrebbe perso se rivedessi solo le conversazioni TCP

### Ricerca

Se vuoi **cercare** **contenuto** all'interno dei **pacchetti** delle sessioni premi _CTRL+f_. Puoi aggiungere nuovi livelli alla barra principale delle informazioni (No., Time, Source, ecc.) premendo il tasto destro e poi edit column.

### Seguire stream multiplexati

Le versioni recenti di Wireshark possono seguire direttamente gli stream `TLS`, `HTTP/2` e `QUIC`. Su capture rumorose questo è di solito più veloce che usare solo `Follow TCP Stream`, soprattutto quando più richieste condividono la stessa connessione.

### Laboratori pcap gratuiti

**Fai pratica con le challenge gratuite di:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificare i domini

Puoi aggiungere una colonna che mostra l'header HTTP Host:

![](<../../../images/image (639).png>)

E una colonna che aggiunge il nome del server da una connessione HTTPS iniziale (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Se la capture è per lo più cifrata, aggiungere questi campi come colonne velocizzerà molto il triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Questo ti permette di raggruppare le sessioni per hostname, ALPN (`http/1.1`, `h2`, `h3`, ecc.) e fingerprint del client anche quando il payload rimane cifrato. Per capture HTTP/2 e HTTP/3 decifrate, è utile anche aggiungere `http2.header.value` o `http3.headers.header.value` come colonne e pivotare su path, authority e altri metadata interessanti.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifying local hostnames

### From DHCP

Nella Wireshark attuale, invece di `bootp` devi cercare `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Premi _Edit_ e aggiungi tutti i dati del server e della private key (_IP, Port, Protocol, Key file and password_)

Questo metodo funziona solo in un numero limitato di casi. Per il traffico TLS 1.3 / ECDHE attuale, il metodo del session key log qui sotto è di solito l'opzione pratica.

### Decrypting https traffic with symmetric session keys

Sia Firefox che Chrome hanno la capacità di registrare le TLS session keys, che possono essere usate con Wireshark per decryptare il traffico TLS. Questo consente un'analisi approfondita delle secure communications. Maggiori dettagli su come eseguire questo decryption si possono trovare in una guida su [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Questo è anche il percorso normale per decryptare le moderne acquisizioni TLS 1.3 e QUIC/HTTP/3.

Per rilevarlo, cerca nell'ambiente la variabile `SSLKEYLOGFILE`

Un file di shared keys apparirà così:

![](<../../../images/image (820).png>)

Se la capture è `pcapng`, verifica se contiene già embedded decryption secrets prima di cercare nel filesystem dell'host:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Per importarlo in wireshark vai su \_edit > preferences > protocols > tls > e importalo in (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## Comunicazione ADB

Estrai un APK da una comunicazione ADB in cui l'APK è stato inviato:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
## References

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
