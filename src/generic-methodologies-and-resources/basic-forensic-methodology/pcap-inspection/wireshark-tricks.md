# Wireshark-truuks

## Verbeter jou Wireshark-vaardighede

### Tutoriale

Die volgende tutoriale is uitstekend om ’n paar nuttige basiese truuks te leer:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Geanaliseerde inligting

**Expert Information**

Deur op _**Analyze** --> **Expert Information**_ te klik, kry jy ’n **oorsig** van wat in die **geanaliseerde** pakkette gebeur:

![Tutoriale - Geanaliseerde inligting: Deur op Analyze -- Expert Information te klik, kry jy ’n oorsig van wat in die geanaliseerde pakkette gebeur](<../../../images/image (256).png>)

**Resolved Addresses**

Onder _**Statistics --> Resolved Addresses**_ kan jy verskeie stukke **inligting** vind wat deur Wireshark "**resolved**" is, soos poort/vervoer na protokol, MAC na die vervaardiger, ens. Dit is interessant om te weet wat by die kommunikasie betrokke is.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- Resolved Addresses kan jy verskeie stukke inligting vind wat deur Wireshark " resolved " is, soos poort/vervoer na protokol, MAC na die...](<../../../images/image (893).png>)

**Protocol Hierarchy**

Onder _**Statistics --> Protocol Hierarchy**_ kan jy die **protokolle** vind wat by die kommunikasie **betrokke** is, asook data daaroor.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- Protocol Hierarchy kan jy die protokolle vind wat by die kommunikasie betrokke is, asook data daaroor](<../../../images/image (586).png>)

**Conversations**

Onder _**Statistics --> Conversations**_ kan jy ’n **opsomming van die gesprekke** in die kommunikasie en data daaroor vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- Conversations kan jy ’n opsomming van die gesprekke in die kommunikasie en data daaroor vind](<../../../images/image (453).png>)

**Endpoints**

Onder _**Statistics --> Endpoints**_ kan jy ’n **opsomming van die eindpunte** in die kommunikasie en data oor elk van hulle vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- Endpoints kan jy ’n opsomming van die eindpunte in die kommunikasie en data oor elk van hulle vind](<../../../images/image (896).png>)

**DNS-inligting**

Onder _**Statistics --> DNS**_ kan jy statistieke oor die vasgelegde DNS-versoek vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- DNS kan jy statistieke oor die vasgelegde DNS-versoek vind](<../../../images/image (1063).png>)

**I/O Graph**

Onder _**Statistics --> I/O Graph**_ kan jy ’n **grafiek van die kommunikasie** vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- I/O Graph kan jy ’n grafiek van die kommunikasie vind](<../../../images/image (992).png>)

### Filters

Hier kan jy Wireshark-filters volgens protokol vind: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
In huidige Wireshark gebruik `tls.*` in plaas van die ou `ssl.*`-filtern name.<sup>[[1]](#references)</sup>\
Ander interessante filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP- en aanvanklike HTTPS-verkeer
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP- en aanvanklike HTTPS-verkeer + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP- en aanvanklike HTTPS-verkeer + TCP SYN + DNS-versoeke
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot op die SNI wat in die ClientHello gestuur word, selfs wanneer jy nie die payload kan decrypt nie
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Verdeel klassieke HTTPS-, HTTP/2- en HTTP/3-geskikte sessies vinnig
- `quic or http3`
- Vind moderne UDP/443-verkeer wat gemis sal word as jy slegs TCP-gesprekke hersien

### Soek

As jy vir **inhoud** binne die **pakkette** van die sessies wil **soek**, druk _CTRL+f_. Jy kan nuwe lae by die hoofinligtingsbalk voeg (No., Time, Source, ens.) deur die regterknoppie te druk en dan die kolom te wysig.

### Volg multiplexed streams

Wireshark kan `TLS`-, `HTTP/2`- en `QUIC`-streams direk volg. Die HTTP/2- en QUIC-dialoogvensters stel verbindings- en substream-kiesers bloot, wat help om multiplexed streams te isoleer wat dieselfde laervlakverbinding deel.<sup>[[4]](#references)</sup>

### Gratis pcap-laboratoriums

**Oefen met die gratis uitdagings van:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifisering van domeine

Jy kan ’n kolom byvoeg wat die Host HTTP-header wys:

![Gratis pcap-laboratoriums - Identifisering van domeine: Jy kan ’n kolom byvoeg wat die Host HTTP-header wys](<../../../images/image (639).png>)

En ’n kolom wat die Server-naam van ’n inisie­rende HTTPS-verbinding byvoeg (**tls.handshake.type == 1**):

![Gratis pcap-laboratoriums - Identifisering van domeine: En ’n kolom wat die Server-naam van ’n inisiërende HTTPS-verbinding byvoeg ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

As die capture hoofsaaklik geënkripteer is, sal die byvoeging van hierdie velde as kolomme triage aansienlik versnel:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Dit stel jou in staat om sessies volgens hostname, ALPN (`http/1.1`, `h2`, `h3`, ens.) en client fingerprint te groepeer, selfs wanneer die payload self geënkripteer bly. Vir decrypted HTTP/2- en HTTP/3-captures is dit ook nuttig om `http2.header.value` of `http3.headers.header.value` as kolomme by te voeg en op paths, authorities en ander interessante metadata te pivot.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifisering van plaaslike hostnames

### Vanaf DHCP

In huidige Wireshark moet jy eerder vir `DHCP` as `bootp` soek

![Identifisering van plaaslike hostnames - Vanaf DHCP: In huidige Wireshark moet jy eerder vir DHCP as bootp soek](<../../../images/image (1013).png>)

### Vanaf NBNS

![Vanaf DHCP - Vanaf NBNS: In huidige Wireshark moet jy eerder vir DHCP as bootp soek](<../../../images/image (1003).png>)

## Dekriptering van TLS

### Dekriptering van https-verkeer met die bediener se private sleutel

_edit > preferences > protocols > tls >_

![Dekriptering van TLS - Dekriptering van https-verkeer met die bediener se private sleutel: Dekriptering van https-verkeer met die bediener se private sleutel](<../../../images/image (1103).png>)

Druk _Edit_ en voeg al die data van die bediener en die private sleutel by (_IP, Port, Protocol, Key file en password_)

Hierdie metode werk slegs in ’n beperkte aantal gevalle. Vir huidige TLS 1.3 / ECDHE-verkeer is die session key log-metode hieronder gewoonlik die praktiese opsie.<sup>[[1]](#references)</sup>

### Dekriptering van https-verkeer met simmetriese sessiesleutels

Beide Firefox en Chrome kan TLS-sessiesleutels aanteken, wat saam met Wireshark gebruik kan word om TLS-verkeer te dekripteer. Dit maak diepgaande ontleding van veilige kommunikasie moontlik. Meer besonderhede oor hoe om hierdie dekripsie uit te voer, kan gevind word in ’n gids by [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Dit is ook die normale metode om moderne TLS 1.3- en QUIC/HTTP/3-captures te dekripteer.<sup>[[2]](#references)</sup>

Om dit op te spoor, soek binne die omgewing na die veranderlike `SSLKEYLOGFILE`

’n Lêer met gedeelde sleutels sal soos volg lyk:

![Dekriptering van https-verkeer met die bediener se private sleutel - Dekriptering van https-verkeer met simmetriese sessiesleutels: ’n Lêer met gedeelde sleutels sal soos volg lyk](<../../../images/image (820).png>)

Indien die capture `pcapng` is, kontroleer of dit reeds ingebedde dekripsiegeheime bevat voordat jy die gasheer se lêerstelsel ondersoek:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Om dit in Wireshark in te voer, gaan na \_edit > preferences > protocols > tls > en voer dit in by (Pre)-Master-Secret log filename:

![Dekripteer https-verkeer met bediener se private sleutel - Dekripteer https-verkeer met simmetriese sessiesleutels: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB-kommunikasie

Onttrek ’n APK uit ’n ADB-kommunikasie waarin die APK gestuur is:
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

- [1] [Wireshark TLS-wiki](https://wiki.wireshark.org/TLS)
- [2] [Dekriptering en ontleding van HTTP/3-verkeer in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Dekriptering van TLS-blaaierverkeer met Wireshark – die maklike manier!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Volg protokolstrome](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Verwysing vir vertoonfilters: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Verwysing vir vertoonfilters: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Verwysing vir vertoonfilters: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
