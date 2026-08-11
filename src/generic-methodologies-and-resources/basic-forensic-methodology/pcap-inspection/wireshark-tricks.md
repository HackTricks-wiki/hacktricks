# Trucchi di Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Migliora le tue competenze con Wireshark

### Tutorial

I seguenti tutorial sono fantastici per imparare alcuni utili trucchi di base:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informazioni analizzate

**Informazioni dell'esperto**

Facendo clic su _**Analyze** --> **Expert Information**_ avrai una **panoramica** di ciò che accade nei pacchetti **analizzati**:

![Tutorial - Informazioni analizzate: facendo clic su Analyze -- Expert Information avrai una panoramica di ciò che accade nei pacchetti analizzati](<../../../images/image (256).png>)

**Indirizzi risolti**

In _**Statistics --> Resolved Addresses**_ puoi trovare diverse **informazioni** che sono state "**risolte**" da Wireshark, ad esempio porta/trasporto in protocollo, MAC nel produttore, ecc. È interessante sapere cosa è coinvolto nella comunicazione.

![Tutorial - Informazioni analizzate: in Statistics -- Resolved Addresses puoi trovare diverse informazioni che sono state " risolte " da Wireshark, ad esempio porta/trasporto in protocollo, MAC nel produttore...](<../../../images/image (893).png>)

**Gerarchia dei protocolli**

In _**Statistics --> Protocol Hierarchy**_ puoi trovare i **protocolli** **coinvolti** nella comunicazione e i relativi dati.

![Tutorial - Informazioni analizzate: in Statistics -- Protocol Hierarchy puoi trovare i protocolli coinvolti nella comunicazione e i relativi dati](<../../../images/image (586).png>)

**Conversazioni**

In _**Statistics --> Conversations**_ puoi trovare un **riepilogo delle conversazioni** nella comunicazione e i relativi dati.

![Tutorial - Informazioni analizzate: in Statistics -- Conversations puoi trovare un riepilogo delle conversazioni nella comunicazione e i relativi dati](<../../../images/image (453).png>)

**Endpoint**

In _**Statistics --> Endpoints**_ puoi trovare un **riepilogo degli endpoint** nella comunicazione e i dati relativi a ciascuno di essi.

![Tutorial - Informazioni analizzate: in Statistics -- Endpoints puoi trovare un riepilogo degli endpoint nella comunicazione e i dati relativi a ciascuno di essi](<../../../images/image (896).png>)

**Informazioni DNS**

In _**Statistics --> DNS**_ puoi trovare statistiche sulla richiesta DNS acquisita.

![Tutorial - Informazioni analizzate: in Statistics -- DNS puoi trovare statistiche sulla richiesta DNS acquisita](<../../../images/image (1063).png>)

**Grafico I/O**

In _**Statistics --> I/O Graph**_ puoi trovare un **grafico della comunicazione.**

![Tutorial - Informazioni analizzate: in Statistics -- I/O Graph puoi trovare un grafico della comunicazione](<../../../images/image (992).png>)

### Filtri

Qui puoi trovare i filtri di Wireshark in base al protocollo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Nelle versioni attuali di Wireshark usa `tls.*` invece dei vecchi nomi dei filtri `ssl.*`.<sup>[[1]](#references)</sup>\
Altri filtri interessanti:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN + richieste DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Esegui il pivot sul SNI inviato nel ClientHello anche quando non puoi decrittografare il payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Dividi rapidamente le sessioni HTTPS classiche, HTTP/2 e compatibili con HTTP/3
- `quic or http3`
- Trova il moderno traffico UDP/443 che non verrebbe rilevato se esaminassi solo le conversazioni TCP

### Ricerca

Se vuoi **cercare** **contenuti** all'interno dei **pacchetti** delle sessioni, premi _CTRL+f_. Puoi aggiungere nuovi livelli alla barra principale delle informazioni (No., Time, Source, ecc.) premendo il pulsante destro e selezionando poi la colonna da modificare.

### Seguire gli stream multiplexed

Wireshark può seguire direttamente gli stream `TLS`, `HTTP/2` e `QUIC`. Le sue finestre di dialogo HTTP/2 e QUIC espongono selettori per connessioni e substream, aiutando a isolare gli stream multiplexed che condividono la stessa connessione di livello inferiore.<sup>[[4]](#references)</sup>

### Laboratori pcap gratuiti

**Fai pratica con le challenge gratuite di:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificazione dei domini

Puoi aggiungere una colonna che mostra l'header Host HTTP:

![Laboratori pcap gratuiti - Identificazione dei domini: puoi aggiungere una colonna che mostra l'header Host HTTP](<../../../images/image (639).png>)

E una colonna che aggiunge il nome del Server da una connessione HTTPS iniziale (**tls.handshake.type == 1**):

![Laboratori pcap gratuiti - Identificazione dei domini: e una colonna che aggiunge il nome del Server da una connessione HTTPS iniziale ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Se la cattura è principalmente crittografata, aggiungere questi campi come colonne velocizzerà notevolmente il triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Questo consente di raggruppare le sessioni per hostname, ALPN (`http/1.1`, `h2`, `h3`, ecc.) e fingerprint del client anche quando il payload rimane crittografato. Per le catture HTTP/2 e HTTP/3 decrittografate, è inoltre utile aggiungere `http2.header.value` o `http3.headers.header.value` come colonne ed eseguire il pivot su path, authority e altri metadati interessanti.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identificazione degli hostname locali

### Da DHCP

Nelle versioni attuali di Wireshark, invece di `bootp` è necessario cercare `DHCP`

![Identificazione degli hostname locali - Da DHCP: nelle versioni attuali di Wireshark, invece di bootp è necessario cercare DHCP](<../../../images/image (1013).png>)

### Da NBNS

![Da DHCP - Da NBNS: nelle versioni attuali di Wireshark, invece di bootp è necessario cercare DHCP](<../../../images/image (1003).png>)

## Decrittografia di TLS

### Decrittografia del traffico https con la chiave privata del server

_edit > preferences > protocols > tls >_

![Decrittografia di TLS - Decrittografia del traffico https con la chiave privata del server: Decrittografia del traffico https con la chiave privata del server](<../../../images/image (1103).png>)

Premere _Edit_ e aggiungere tutti i dati del server e della chiave privata (_IP, Port, Protocol, Key file e password_)

Questo metodo funziona solo in un numero limitato di casi. Per il traffico TLS 1.3 / ECDHE attuale, il metodo del log delle chiavi di sessione riportato di seguito è generalmente l'opzione più pratica.<sup>[[1]](#references)</sup>

### Decrittografia del traffico https con chiavi di sessione simmetriche

Sia Firefox sia Chrome sono in grado di registrare le chiavi di sessione TLS, che possono essere utilizzate con Wireshark per decrittografare il traffico TLS. Ciò consente un'analisi approfondita delle comunicazioni sicure. Ulteriori dettagli su come eseguire questa decrittografia sono disponibili in una guida di [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Questo è anche il metodo normalmente utilizzato per decrittografare i capture moderni di TLS 1.3 e QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Per rilevarlo, cercare all'interno dell'ambiente la variabile `SSLKEYLOGFILE`

Un file di chiavi condivise avrà il seguente aspetto:

![Decrittografia del traffico https con la chiave privata del server - Decrittografia del traffico https con chiavi di sessione simmetriche: Un file di chiavi condivise avrà il seguente aspetto](<../../../images/image (820).png>)

Se il capture è `pcapng`, verificare se contiene già segreti di decrittografia incorporati prima di cercarli nel filesystem dell'host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Per importarlo in Wireshark, vai a \_edit > preferences > protocols > tls > e importalo in (Pre)-Master-Secret log filename:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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

- [1] [Wiki TLS di Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Decrittazione e analisi del traffico HTTP/3 in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Decrittografare il traffico TLS del browser con Wireshark – Il modo più semplice!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Seguire i flussi dei protocolli](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Riferimento dei filtri di visualizzazione: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Riferimento dei filtri di visualizzazione: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Riferimento dei filtri di visualizzazione: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
