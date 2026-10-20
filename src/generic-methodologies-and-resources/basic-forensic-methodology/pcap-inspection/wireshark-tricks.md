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

Facendo clic su _**Analyze** --> **Expert Information**_ si ottiene una **panoramica** di ciò che accade nei pacchetti **analizzati**:

![Tutorial - Informazioni analizzate: facendo clic su Analyze -- Expert Information si ottiene una panoramica di ciò che accade nei pacchetti analizzati](<../../../images/image (256).png>)

**Indirizzi risolti**

In _**Statistics --> Resolved Addresses**_ si trovano diverse **informazioni** "**risolte**" da Wireshark, ad esempio la corrispondenza tra porta/trasporto e protocollo, tra MAC e produttore, ecc. È utile sapere quali elementi sono coinvolti nella comunicazione.

![Tutorial - Informazioni analizzate: in Statistics -- Resolved Addresses si trovano diverse informazioni "risolte" da Wireshark, ad esempio la corrispondenza tra porta/trasporto e protocollo, tra MAC e...](<../../../images/image (893).png>)

**Gerarchia dei protocolli**

In _**Statistics --> Protocol Hierarchy**_ si trovano i **protocolli** **coinvolti** nella comunicazione e i relativi dati.

![Tutorial - Informazioni analizzate: in Statistics -- Protocol Hierarchy si trovano i protocolli coinvolti nella comunicazione e i relativi dati](<../../../images/image (586).png>)

**Conversazioni**

In _**Statistics --> Conversations**_ si trova un **riepilogo delle conversazioni** nella comunicazione e i relativi dati.

![Tutorial - Informazioni analizzate: in Statistics -- Conversations si trova un riepilogo delle conversazioni nella comunicazione e i relativi dati](<../../../images/image (453).png>)

**Endpoint**

In _**Statistics --> Endpoints**_ si trova un **riepilogo degli endpoint** nella comunicazione e i dati relativi a ciascuno di essi.

![Tutorial - Informazioni analizzate: in Statistics -- Endpoints si trova un riepilogo degli endpoint nella comunicazione e i dati relativi a ciascuno di essi](<../../../images/image (896).png>)

**Informazioni DNS**

In _**Statistics --> DNS**_ si trovano le statistiche sulle richieste DNS acquisite.

![Tutorial - Informazioni analizzate: in Statistics -- DNS si trovano le statistiche sulle richieste DNS acquisite](<../../../images/image (1063).png>)

**Grafico I/O**

In _**Statistics --> I/O Graph**_ si trova un **grafico della comunicazione.**

![Tutorial - Informazioni analizzate: in Statistics -- I/O Graph si trova un grafico della comunicazione](<../../../images/image (992).png>)

### Filtri

Qui sono disponibili i filtri di Wireshark suddivisi per protocollo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Nelle versioni attuali di Wireshark, usare `tls.*` invece dei vecchi nomi di filtro `ssl.*`.<sup>[[1]](#references)</sup>\
Altri filtri utili:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - Traffico HTTP e HTTPS iniziale
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - Traffico HTTP e HTTPS iniziale + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - Traffico HTTP e HTTPS iniziale + TCP SYN + richieste DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Consente di usare come pivot l'SNI inviato nel ClientHello anche quando non è possibile decrittare il payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Consente di distinguere rapidamente le sessioni HTTPS classiche da quelle compatibili con HTTP/2 e HTTP/3
- `quic or http3`
  - Individua il moderno traffico UDP/443 che sfugge all'analisi se si esaminano solo le conversazioni TCP

### Ricerca

Per **cercare** **contenuti** all'interno dei **pacchetti** delle sessioni, premi _CTRL+f_. Puoi aggiungere nuove colonne alla barra delle informazioni principali (No., Time, Source, ecc.) facendo clic con il pulsante destro e selezionando la modifica delle colonne.

### Seguire flussi multiplexati

Wireshark può seguire direttamente i flussi `TLS`, `HTTP/2` e `QUIC`. Le finestre di dialogo di HTTP/2 e QUIC mostrano selettori per la connessione e i sottoflussi, utili per isolare i flussi multiplexati che condividono la stessa connessione di livello inferiore.<sup>[[4]](#references)</sup>

Se sono disponibili le chiavi di sessione, individua prima l'ID del flusso della richiesta, poi segui quel sottoflusso anziché l'intera conversazione TCP o UDP. L'esempio `0,1` seleziona l'ID del flusso HTTP/2 1 sul flusso TCP 0; per QUIC, usa `follow,quic,utf-8,<connection-number>,<stream-id>`. Seguire solo una five-tuple può mescolare richieste indipendenti o non rilevare una connessione QUIC dopo una migrazione.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Laboratori pcap gratuiti

**Esercitati con le sfide gratuite di:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificazione dei domini

Puoi aggiungere una colonna che mostra l'header Host HTTP:

![Laboratori pcap gratuiti - Identificazione dei domini: puoi aggiungere una colonna che mostra l'header Host HTTP](<../../../images/image (639).png>)

E una colonna che aggiunge il nome del server da una connessione HTTPS iniziale (**tls.handshake.type == 1**):

![Laboratori pcap gratuiti - Identificazione dei domini: e una colonna che aggiunge il nome del server da una connessione HTTPS iniziale ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Se la cattura è perlopiù crittografata, aggiungere questi campi come colonne velocizzerà molto il triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Questo permette di raggruppare le sessioni per hostname, ALPN (`http/1.1`, `h2`, `h3`, ecc.) e fingerprint del client, anche quando il payload rimane crittografato. Per le catture HTTP/2 e HTTP/3 decrittografate, è inoltre utile aggiungere `http2.header.value` o `http3.headers.header.value` come colonne e analizzare percorsi, authority e altri metadati interessanti.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: non confondere l’SNI esterno con l’origine

Encrypted ClientHello (ECH) può inserire un nome pubblico di copertura nell’SNI esterno visibile, mentre cifra il nome interno. Di conseguenza, un inventario dei domini basato solo sull’SNI può attribuire il traffico ECH all’origine sbagliata. La sola estensione ECH non dimostra che ECH abbia avuto successo: i client possono inviare un’estensione ECH GREASE. Su Wireshark 4.2+, trova le offerte ECH esterne con il filtro seguente e considera l’SNI riportato come un possibile nome di copertura, non come il sito richiesto.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Se disponi delle chiavi di sessione client corrispondenti, esamina l’authority/Host HTTP decifrato invece di dedurre l’origine dall’SNI esterno. Senza le chiavi, controlla altre prove dell’origine presenti nella cattura, come il DNS in chiaro, ma non equiparare l’SNI esterno al nome nascosto.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identificazione dei nomi host locali

### Da DHCP

Nelle versioni attuali di Wireshark, invece di `bootp` devi cercare `DHCP`

![Identificazione dei nomi host locali - Da DHCP: Nelle versioni attuali di Wireshark, invece di bootp devi cercare DHCP](<../../../images/image (1013).png>)

### Da NBNS

![Da DHCP - Da NBNS: Nelle versioni attuali di Wireshark, invece di bootp devi cercare DHCP](<../../../images/image (1003).png>)

## Decrittazione di TLS

La decrittazione del livello di collegamento Wi-Fi è separata dalla decrittazione delle sessioni TLS; consulta [Wi-Fi PCAP analysis](wifi-pcap-analysis.md) per i prerequisiti relativi a chiavi e handshake.

### Decrittazione del traffico https con la chiave privata del server

_edit > preferences > protocols > tls >_

![Decrittazione di TLS - Decrittazione del traffico https con la chiave privata del server: Decrittazione del traffico https con la chiave privata del server](<../../../images/image (1103).png>)

Premi _Edit_ e aggiungi tutti i dati del server e la chiave privata (_IP, Port, Protocol, Key file e password_)

Questo metodo funziona solo in un numero limitato di casi. Per il traffico TLS 1.3 / ECDHE attuale, di solito l'opzione più pratica è il metodo del session key log qui sotto.<sup>[[1]](#references)</sup>

### Decrittazione del traffico https con chiavi di sessione simmetriche

Sia Firefox che Chrome possono registrare le chiavi di sessione TLS, che possono essere usate con Wireshark per decrittare il traffico TLS. Ciò consente un'analisi approfondita delle comunicazioni sicure. Maggiori dettagli su come eseguire questa decrittazione sono disponibili in una guida di [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Questo è anche il metodo standard per decrittare le acquisizioni moderne di TLS 1.3 e QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Per rilevarlo, cerca la variabile `SSLKEYLOGFILE` nell'ambiente.

Un file di chiavi condivise avrà questo aspetto:

![Decrittazione del traffico https con la chiave privata del server - Decrittazione del traffico https con chiavi di sessione simmetriche: Un file di chiavi condivise avrà questo aspetto](<../../../images/image (820).png>)

Se l'acquisizione è in formato `pcapng`, verifica se contiene già segreti di decrittazione incorporati prima di cercarli nel filesystem dell'host:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Per importarlo in Wireshark, vai su \_modifica > preferenze > protocolli > tls > e importalo in «Nome file del log dei segreti (Pre)-Master»:

![Decrittazione del traffico https con la chiave privata del server - Decrittazione del traffico https con le chiavi di sessione simmetriche: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Comunicazione ADB

Estrai un APK da una comunicazione ADB in cui è stato inviato:

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
- [2] [Decifrare e analizzare il traffico HTTP/3 in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Decifrare il traffico TLS del browser con Wireshark: il modo semplice!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Seguire i flussi di protocollo](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Riferimento ai filtri di visualizzazione: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Riferimento ai filtri di visualizzazione: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Riferimento ai filtri di visualizzazione: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: Client Hello TLS cifrato](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Manuale di TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
