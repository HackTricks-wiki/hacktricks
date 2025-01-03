# Wireshark truuks

{{#include ../../../banners/hacktricks-training.md}}

## Verbeter jou Wireshark vaardighede

### Tutorials

Die volgende tutorials is wonderlik om 'n paar koel basiese truuks te leer:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Geanaliseerde Inligting

**Deskundige Inligting**

Deur te klik op _**Analyse** --> **Deskundige Inligting**_ sal jy 'n **oorsig** hê van wat in die **geanaliseerde** pakkette gebeur:

![](<../../../images/image (256).png>)

**Opgeloste Adresse**

Onder _**Statistieke --> Opgeloste Adresse**_ kan jy verskeie **inligting** vind wat deur wireshark "**opgelos**" is soos poort/transport na protokol, MAC na die vervaardiger, ens. Dit is interessant om te weet wat betrokke is in die kommunikasie.

![](<../../../images/image (893).png>)

**Protokol Hiërargie**

Onder _**Statistieke --> Protokol Hiërargie**_ kan jy die **protokolle** **betrokke** in die kommunikasie en data oor hulle vind.

![](<../../../images/image (586).png>)

**Gesprekke**

Onder _**Statistieke --> Gesprekke**_ kan jy 'n **opsomming van die gesprekke** in die kommunikasie en data oor hulle vind.

![](<../../../images/image (453).png>)

**Eindpunte**

Onder _**Statistieke --> Eindpunte**_ kan jy 'n **opsomming van die eindpunte** in die kommunikasie en data oor elkeen van hulle vind.

![](<../../../images/image (896).png>)

**DNS inligting**

Onder _**Statistieke --> DNS**_ kan jy statistieke oor die DNS versoek wat gevang is vind.

![](<../../../images/image (1063).png>)

**I/O Grafiek**

Onder _**Statistieke --> I/O Grafiek**_ kan jy 'n **grafiek van die kommunikasie** vind.

![](<../../../images/image (992).png>)

### Filters

Hier kan jy wireshark filter vind afhangende van die protokol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Ander interessante filters:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP en aanvanklike HTTPS verkeer
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP en aanvanklike HTTPS verkeer + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP en aanvanklike HTTPS verkeer + TCP SYN + DNS versoeke

### Soek

As jy wil **soek** vir **inhoud** binne die **pakkette** van die sessies, druk _CTRL+f_. Jy kan nuwe lae by die hoofinligtingsbalk (No., Tyd, Bron, ens.) voeg deur die regterknoppie te druk en dan die kolom te wysig.

### Gratis pcap laboratoriums

**Oefen met die gratis uitdagings van:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifisering van Domeine

Jy kan 'n kolom byvoeg wat die Host HTTP koptekst wys:

![](<../../../images/image (639).png>)

En 'n kolom wat die Bediener naam van 'n inisiërende HTTPS verbinding byvoeg (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Identifisering van plaaslike gasheernames

### Van DHCP

In die huidige Wireshark moet jy in plaas van `bootp` soek vir `DHCP`

![](<../../../images/image (1013).png>)

### Van NBNS

![](<../../../images/image (1003).png>)

## Ontsleuteling van TLS

### Ontsleuteling van https verkeer met bediener se privaat sleutel

_edit>voorkeur>protokol>ssl>_

![](<../../../images/image (1103).png>)

Druk _Wysig_ en voeg al die data van die bediener en die privaat sleutel (_IP, Poort, Protokol, Sleutel lêer en wagwoord_)

### Ontsleuteling van https verkeer met simmetriese sessiesleutels

Sowel Firefox as Chrome het die vermoë om TLS sessiesleutels te log, wat met Wireshark gebruik kan word om TLS verkeer te ontsleutel. Dit stel in-diepte analise van veilige kommunikasies moontlik. Meer besonderhede oor hoe om hierdie ontsleuteling uit te voer, kan in 'n gids by [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) gevind word.

Om dit te detecteer, soek binne die omgewing vir die veranderlike `SSLKEYLOGFILE`

'n Lêer van gedeelde sleutels sal soos volg lyk:

![](<../../../images/image (820).png>)

Om dit in wireshark te invoer, gaan na \_wysig > voorkeur > protokol > ssl > en voer dit in (Pre)-Master-Secret log lêernaam:

![](<../../../images/image (989).png>)

## ADB kommunikasie

Onthaal 'n APK uit 'n ADB kommunikasie waar die APK gestuur is:
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
