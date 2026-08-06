# Wireshark-truuks

{{#include ../../../banners/hacktricks-training.md}}

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

Onder _**Statistics --> Protocol Hierarchy**_ kan jy die **protokolle** wat by die kommunikasie **betrokke** is, sowel as data daaroor, vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- Protocol Hierarchy kan jy die protokolle vind wat by die kommunikasie betrokke is, sowel as data daaroor](<../../../images/image (586).png>)

**Conversations**

Onder _**Statistics --> Conversations**_ kan jy ’n **opsomming van die gesprekke** in die kommunikasie, sowel as data daaroor, vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- Conversations kan jy ’n opsomming van die gesprekke in die kommunikasie, sowel as data daaroor, vind](<../../../images/image (453).png>)

**Endpoints**

Onder _**Statistics --> Endpoints**_ kan jy ’n **opsomming van die eindpunte** in die kommunikasie, sowel as data oor elkeen, vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- Endpoints kan jy ’n opsomming van die eindpunte in die kommunikasie, sowel as data oor elkeen, vind](<../../../images/image (896).png>)

**DNS-inligting**

Onder _**Statistics --> DNS**_ kan jy statistieke oor die vasgelegde DNS-versoek vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- DNS kan jy statistieke oor die vasgelegde DNS-versoek vind](<../../../images/image (1063).png>)

**I/O Graph**

Onder _**Statistics --> I/O Graph**_ kan jy ’n **grafiek van die kommunikasie** vind.

![Tutoriale - Geanaliseerde inligting: Onder Statistics -- I/O Graph kan jy ’n grafiek van die kommunikasie vind](<../../../images/image (992).png>)

### Filters

Hier kan jy Wireshark-filters volgens die protokol vind: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
In die huidige Wireshark gebruik `tls.*` in plaas van die ou `ssl.*`-filtern gevalle.\
Ander interessante filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP en aanvanklike HTTPS-verkeer
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP en aanvanklike HTTPS-verkeer + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP en aanvanklike HTTPS-verkeer + TCP SYN + DNS-versoeke
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot op die SNI wat in die ClientHello gestuur word, selfs wanneer jy nie die payload kan dekripteer nie
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Skei klassieke HTTPS-, HTTP/2- en HTTP/3-vermoënde sessies vinnig
- `quic or http3`
- Vind moderne UDP/443-verkeer wat gemis sal word as jy slegs TCP-gesprekke nagaan

### Soek

As jy vir **inhoud** binne die **pakkette** van die sessies wil **soek**, druk _CTRL+f_. Jy kan nuwe lae by die hoofinligtingsbalk (No., Time, Source, ens.) voeg deur die regterknoppie te druk en dan die kolom te wysig.

### Volg van multiplexed streams

Onlangse Wireshark-weergawes kan `TLS`-, `HTTP/2`- en `QUIC`-streams direk volg. In raserige captures is dit gewoonlik vinniger as om slegs `Follow TCP Stream` te gebruik, veral wanneer verskeie versoeke dieselfde verbinding deel.

### Gratis pcap-laboratoriums

**Oefen met die gratis uitdagings by:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifisering van domeine

Jy kan ’n kolom byvoeg wat die Host HTTP-header vertoon:

![Gratis pcap-laboratoriums - Identifisering van domeine: Jy kan ’n kolom byvoeg wat die Host HTTP-header vertoon](<../../../images/image (639).png>)

En ’n kolom wat die bedienernaam van ’n aanvanklike HTTPS-verbinding byvoeg (**tls.handshake.type == 1**):

![Gratis pcap-laboratoriums - Identifisering van domeine: En ’n kolom wat die bedienernaam van ’n aanvanklike HTTPS-verbinding byvoeg ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

As die capture meestal geënkripteer is, sal dit triage aansienlik versnel om hierdie velde as kolomme by te voeg:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Dit stel jou in staat om sessies volgens gasheernaam, ALPN (`http/1.1`, `h2`, `h3`, ens.) en kliëntvingerafdruk te groepeer, selfs wanneer die payload self geënkripteer bly. Vir gedekripteerde HTTP/2- en HTTP/3-captures is dit ook nuttig om `http2.header.value` of `http3.headers.header.value` as kolomme by te voeg en op paths, authorities en ander interessante metadata te pivot.<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifisering van plaaslike hostnames

### Vanaf DHCP

In huidige Wireshark moet jy in plaas van `bootp` vir `DHCP` soek

![Identifisering van plaaslike hostnames - Vanaf DHCP: In huidige Wireshark moet jy in plaas van bootp vir DHCP soek](<../../../images/image (1013).png>)

### Vanaf NBNS

![Vanaf DHCP - Vanaf NBNS: In huidige Wireshark moet jy in plaas van bootp vir DHCP soek](<../../../images/image (1003).png>)

## Dekriptering van TLS

### Dekriptering van https-verkeer met die private sleutel van die server

_edit > preferences > protocols > tls >_

![Dekriptering van TLS - Dekriptering van https-verkeer met die private sleutel van die server: Dekriptering van https-verkeer met die private sleutel van die server](<../../../images/image (1103).png>)

Druk _Edit_ en voeg al die data van die server en die private sleutel by (_IP, Port, Protocol, Key file en password_)

Hierdie metode werk slegs in ’n beperkte aantal gevalle. Vir huidige TLS 1.3 / ECDHE-verkeer is die session key log-metode hieronder gewoonlik die praktiese opsie.<sup>[[1]](#references)</sup>

### Dekriptering van https-verkeer met simmetriese session keys

Firefox en Chrome kan albei TLS-session keys log, wat saam met Wireshark gebruik kan word om TLS-verkeer te dekripteer. Dit maak diepgaande ontleding van veilige kommunikasie moontlik. Meer besonderhede oor hoe om hierdie dekripsie uit te voer, kan gevind word in ’n gids by [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Dit is ook die normale metode vir die dekripsie van moderne TLS 1.3- en QUIC/HTTP/3-captures.<sup>[[2]](#references)</sup>

Om dit op te spoor, soek binne die environment vir die veranderlike `SSLKEYLOGFILE`

’n Lêer met gedeelde keys sal soos volg lyk:

![Dekriptering van https-verkeer met die private sleutel van die server - Dekriptering van https-verkeer met simmetriese session keys: ’n Lêer met gedeelde keys sal soos volg lyk](<../../../images/image (820).png>)

As die capture `pcapng` is, kyk of dit reeds ingebedde decryption secrets bevat voordat jy die host se filesystem deursoek:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Om dit in Wireshark in te voer, gaan na \_edit > preferences > protocols > tls > en voer dit in by **(Pre)-Master-Secret log filename**:

![Decryptering van HTTPS-verkeer met bediener se private sleutel - Decryptering van HTTPS-verkeer met simmetriese sessiesleutels: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB-kommunikasie

Onttrek ’n APK uit ’n ADB-kommunikasie waar die APK gestuur is:
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
## Verwysings

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Dekriptering en ontleding van HTTP/3-verkeer in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Dekriptering van TLS-blaaierverkeer met Wireshark – Die maklike manier!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
