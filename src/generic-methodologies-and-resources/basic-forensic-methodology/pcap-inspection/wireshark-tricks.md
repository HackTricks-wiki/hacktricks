# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Migliora le tue abilità con Wireshark

### Tutorial

I seguenti tutorial sono fantastici per imparare alcuni trucchi di base:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informazioni analizzate

**Informazioni esperte**

Cliccando su _**Analizza** --> **Informazioni esperte**_ avrai una **panoramica** di ciò che sta accadendo nei pacchetti **analizzati**:

![](<../../../images/image (256).png>)

**Indirizzi risolti**

Sotto _**Statistiche --> Indirizzi risolti**_ puoi trovare diverse **informazioni** che sono state "**risolte**" da wireshark come porta/trasporto a protocollo, MAC al produttore, ecc. È interessante sapere cosa è implicato nella comunicazione.

![](<../../../images/image (893).png>)

**Gerarchia dei protocolli**

Sotto _**Statistiche --> Gerarchia dei protocolli**_ puoi trovare i **protocolli** **coinvolti** nella comunicazione e dati su di essi.

![](<../../../images/image (586).png>)

**Conversazioni**

Sotto _**Statistiche --> Conversazioni**_ puoi trovare un **riassunto delle conversazioni** nella comunicazione e dati su di esse.

![](<../../../images/image (453).png>)

**Punti finali**

Sotto _**Statistiche --> Punti finali**_ puoi trovare un **riassunto dei punti finali** nella comunicazione e dati su ciascuno di essi.

![](<../../../images/image (896).png>)

**Informazioni DNS**

Sotto _**Statistiche --> DNS**_ puoi trovare statistiche sulla richiesta DNS catturata.

![](<../../../images/image (1063).png>)

**Grafico I/O**

Sotto _**Statistiche --> Grafico I/O**_ puoi trovare un **grafico della comunicazione.**

![](<../../../images/image (992).png>)

### Filtri

Qui puoi trovare filtri wireshark a seconda del protocollo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Altri filtri interessanti:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Traffico HTTP e HTTPS iniziale + TCP SYN + richieste DNS

### Ricerca

Se vuoi **cercare** **contenuti** all'interno dei **pacchetti** delle sessioni premi _CTRL+f_. Puoi aggiungere nuovi livelli alla barra delle informazioni principali (No., Tempo, Sorgente, ecc.) premendo il tasto destro e poi modificando la colonna.

### Laboratori pcap gratuiti

**Pratica con le sfide gratuite di:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificazione dei domini

Puoi aggiungere una colonna che mostra l'intestazione Host HTTP:

![](<../../../images/image (639).png>)

E una colonna che aggiunge il nome del server da una connessione HTTPS iniziale (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Identificazione dei nomi host locali

### Da DHCP

Nell'attuale Wireshark invece di `bootp` devi cercare `DHCP`

![](<../../../images/image (1013).png>)

### Da NBNS

![](<../../../images/image (1003).png>)

## Decrittazione TLS

### Decrittazione del traffico https con la chiave privata del server

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

Premi _Edit_ e aggiungi tutti i dati del server e la chiave privata (_IP, Porta, Protocollo, File chiave e password_)

### Decrittazione del traffico https con chiavi di sessione simmetriche

Sia Firefox che Chrome hanno la capacità di registrare le chiavi di sessione TLS, che possono essere utilizzate con Wireshark per decrittare il traffico TLS. Questo consente un'analisi approfondita delle comunicazioni sicure. Maggiori dettagli su come eseguire questa decrittazione possono essere trovati in una guida su [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Per rilevare questo cerca all'interno dell'ambiente la variabile `SSLKEYLOGFILE`

Un file di chiavi condivise apparirà così:

![](<../../../images/image (820).png>)

Per importarlo in wireshark vai su \_edit > preference > protocol > ssl > e importalo in (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## Comunicazione ADB

Estrai un APK da una comunicazione ADB dove l'APK è stato inviato:
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
{{#include ../../../banners/hacktricks-training.md}}
