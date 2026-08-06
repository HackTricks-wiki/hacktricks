# Trucchi di Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Migliorare le proprie competenze con Wireshark

### Tutorial

I seguenti tutorial sono ottimi per imparare alcuni utili trucchi di base:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informazioni analizzate

**Informazioni per esperti**

Facendo clic su _**Analyze** --> **Expert Information**_ si ottiene una **panoramica** di ciò che sta accadendo nei pacchetti **analizzati**:

![Tutorial - Informazioni analizzate: facendo clic su Analyze -- Expert Information si ottiene una panoramica di ciò che sta accadendo nei pacchetti analizzati](<../../../images/image (256).png>)

**Indirizzi risolti**

In _**Statistics --> Resolved Addresses**_ è possibile trovare diverse **informazioni** che sono state "**risolte**" da Wireshark, come la porta/il trasporto in base al protocollo, il MAC in base al produttore, ecc. È utile sapere cosa è coinvolto nella comunicazione.

![Tutorial - Informazioni analizzate: in Statistics -- Resolved Addresses è possibile trovare diverse informazioni "risolte" da Wireshark, come la porta/il trasporto in base al protocollo, il MAC in base al...](<../../../images/image (893).png>)

**Gerarchia dei protocolli**

In _**Statistics --> Protocol Hierarchy**_ è possibile trovare i **protocolli** **coinvolti** nella comunicazione e i relativi dati.

![Tutorial - Informazioni analizzate: in Statistics -- Protocol Hierarchy è possibile trovare i protocolli coinvolti nella comunicazione e i relativi dati](<../../../images/image (586).png>)

**Conversazioni**

In _**Statistics --> Conversations**_ è possibile trovare un **riepilogo delle conversazioni** nella comunicazione e i relativi dati.

![Tutorial - Informazioni analizzate: in Statistics -- Conversations è possibile trovare un riepilogo delle conversazioni nella comunicazione e i relativi dati](<../../../images/image (453).png>)

**Endpoint**

In _**Statistics --> Endpoints**_ è possibile trovare un **riepilogo degli endpoint** nella comunicazione e i dati relativi a ciascuno di essi.

![Tutorial - Informazioni analizzate: in Statistics -- Endpoints è possibile trovare un riepilogo degli endpoint nella comunicazione e i dati relativi a ciascuno di essi](<../../../images/image (896).png>)

**Informazioni DNS**

In _**Statistics --> DNS**_ è possibile trovare statistiche sulle richieste DNS catturate.

![Tutorial - Informazioni analizzate: in Statistics -- DNS è possibile trovare statistiche sulle richieste DNS catturate](<../../../images/image (1063).png>)

**Grafico I/O**

In _**Statistics --> I/O Graph**_ è possibile trovare un **grafico della comunicazione.**

![Tutorial - Informazioni analizzate: in Statistics -- I/O Graph è possibile trovare un grafico della comunicazione](<../../../images/image (992).png>)

### Filtri

Qui è possibile trovare i filtri di Wireshark in base al protocollo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Nelle versioni attuali di Wireshark utilizzare `tls.*` invece dei vecchi nomi dei filtri `ssl.*`.\
Altri filtri interessanti:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN + richieste DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Eseguire il pivot sul SNI inviato nel ClientHello anche quando non è possibile decrittografare il payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Separare rapidamente le sessioni HTTPS classiche, HTTP/2 e compatibili con HTTP/3
- `quic or http3`
- Trovare il moderno traffico UDP/443 che non verrebbe rilevato esaminando soltanto le conversazioni TCP

### Ricerca

Se si desidera **cercare** **contenuti** all'interno dei **pacchetti** delle sessioni, premere _CTRL+f_. È possibile aggiungere nuovi livelli alla barra delle informazioni principale (No., Time, Source, ecc.) premendo il pulsante destro e selezionando quindi la modifica della colonna.

### Seguire stream multiplexati

Le versioni recenti di Wireshark possono seguire direttamente gli stream `TLS`, `HTTP/2` e `QUIC`. Nelle catture rumorose, questa operazione è generalmente più rapida rispetto all'utilizzo esclusivo di `Follow TCP Stream`, soprattutto quando più richieste condividono la stessa connessione.

### Laboratori pcap gratuiti

**Esercitarsi con le challenge gratuite di:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificare i domini

È possibile aggiungere una colonna che mostra l'intestazione HTTP Host:

![Laboratori pcap gratuiti - Identificare i domini: è possibile aggiungere una colonna che mostra l'intestazione HTTP Host](<../../../images/image (639).png>)

E una colonna che aggiunge il nome del Server da una connessione HTTPS iniziale (**tls.handshake.type == 1**):

![Laboratori pcap gratuiti - Identificare i domini: una colonna che aggiunge il nome del Server da una connessione HTTPS iniziale ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Se la cattura è principalmente crittografata, aggiungere questi campi come colonne velocizzerà notevolmente il triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Ciò consente di raggruppare le sessioni per hostname, ALPN (`http/1.1`, `h2`, `h3`, ecc.) e fingerprint del client anche quando il payload rimane crittografato. Per le catture HTTP/2 e HTTP/3 decrittografate, è inoltre utile aggiungere `http2.header.value` o `http3.headers.header.value` come colonne ed eseguire il pivot su path, autorità e altri metadati interessanti.<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identificazione dei nomi host locali

### Da DHCP

Nelle versioni attuali di Wireshark, invece di `bootp` è necessario cercare `DHCP`

![Identificazione dei nomi host locali - Da DHCP: Nelle versioni attuali di Wireshark, invece di bootp è necessario cercare DHCP](<../../../images/image (1013).png>)

### Da NBNS

![Da DHCP - Da NBNS: Nelle versioni attuali di Wireshark, invece di bootp è necessario cercare DHCP](<../../../images/image (1003).png>)

## Decrittazione di TLS

### Decrittazione del traffico https con la chiave privata del server

_modifica > preferenze > protocolli > tls >_

![Decrittazione di TLS - Decrittazione del traffico https con la chiave privata del server: Decrittazione del traffico https con la chiave privata del server](<../../../images/image (1103).png>)

Premere _Edit_ e aggiungere tutti i dati del server e della chiave privata (_IP, porta, protocollo, file della chiave e password_)

Questo metodo funziona solo in un numero limitato di casi. Per il traffico TLS 1.3 / ECDHE attuale, il metodo di registrazione delle chiavi di sessione riportato di seguito è generalmente l'opzione più pratica.<sup>[[1]](#references)</sup>

### Decrittazione del traffico https con chiavi di sessione simmetriche

Sia Firefox che Chrome sono in grado di registrare le chiavi di sessione TLS, che possono essere utilizzate con Wireshark per decrittare il traffico TLS. Ciò consente un'analisi approfondita delle comunicazioni protette. Ulteriori dettagli su come eseguire questa decrittazione sono disponibili in una guida su [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Questo è anche il metodo normalmente utilizzato per decrittare le catture moderne TLS 1.3 e QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Per rilevarlo, cercare nell'ambiente la variabile `SSLKEYLOGFILE`

Un file di chiavi condivise sarà simile a questo:

![Decrittazione del traffico https con la chiave privata del server - Decrittazione del traffico https con chiavi di sessione simmetriche: Un file di chiavi condivise sarà simile a questo](<../../../images/image (820).png>)

Se la cattura è in formato `pcapng`, verificare se contiene già segreti di decrittazione incorporati prima di cercare nel filesystem dell'host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Per importarlo in wireshark vai su \_edit > preferences > protocols > tls > e importalo in (Pre)-Master-Secret log filename:

![Decrittografia del traffico https con la chiave privata del server - Decrittografia del traffico https con le chiavi di sessione simmetriche: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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
## Riferimenti

- [1] [Wiki TLS di Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Decrittografia e analisi del traffico HTTP/3 in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Decrittografare il traffico TLS del browser con Wireshark - il modo più semplice!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
