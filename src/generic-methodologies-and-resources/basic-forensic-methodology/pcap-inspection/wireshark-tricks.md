# Wireshark-truuks

{{#include ../../../banners/hacktricks-training.md}}

## Verbeter jou Wireshark-vaardighede

### Tutoriale

Die volgende tutoriale is uitstekend om ’n paar handige basiese truuks te leer:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Ontleedde inligting

**Kundige inligting**

As jy op _**Analyze** --> **Expert Information**_ klik, kry jy ’n **oorsig** van wat in die **ontleedde** pakkette gebeur:

![Tutoriale - Ontleedde inligting: As jy op Analyze -- Expert Information klik, kry jy ’n oorsig van wat in die ontleedde pakkette gebeur](<../../../images/image (256).png>)

**Opgeloste adresse**

Onder _**Statistics --> Resolved Addresses**_ kan jy verskeie inligting vind wat deur Wireshark "**opgelos**" is, soos poort/vervoer na protokol, MAC na vervaardiger, ens. Dit is nuttig om te weet wat by die kommunikasie betrokke is.

![Tutoriale - Ontleedde inligting: Onder Statistics -- Resolved Addresses kan jy verskeie inligting vind wat deur Wireshark " opgelos " is, soos poort/vervoer na protokol, MAC na die...](<../../../images/image (893).png>)

**Protokolhiërargie**

Onder _**Statistics --> Protocol Hierarchy**_ kan jy die **protokolle** vind wat by die kommunikasie **betrokke** is, asook data daaroor.

![Tutoriale - Ontleedde inligting: Onder Statistics -- Protocol Hierarchy kan jy die protokolle vind wat by die kommunikasie betrokke is, asook data daaroor](<../../../images/image (586).png>)

**Gesprekke**

Onder _**Statistics --> Conversations**_ kan jy ’n **opsomming van die gesprekke** in die kommunikasie vind, asook data daaroor.

![Tutoriale - Ontleedde inligting: Onder Statistics -- Conversations kan jy ’n opsomming van die gesprekke in die kommunikasie vind, asook data daaroor](<../../../images/image (453).png>)

**Eindpunte**

Onder _**Statistics --> Endpoints**_ kan jy ’n **opsomming van die eindpunte** in die kommunikasie vind, asook data oor elkeen.

![Tutoriale - Ontleedde inligting: Onder Statistics -- Endpoints kan jy ’n opsomming van die eindpunte in die kommunikasie vind, asook data oor elkeen](<../../../images/image (896).png>)

**DNS-inligting**

Onder _**Statistics --> DNS**_ kan jy statistieke oor die vasgelegde DNS-versoeke vind.

![Tutoriale - Ontleedde inligting: Onder Statistics -- DNS kan jy statistieke oor die vasgelegde DNS-versoeke vind](<../../../images/image (1063).png>)

**I/O-grafiek**

Onder _**Statistics --> I/O Graph**_ kan jy ’n **grafiek van die kommunikasie** vind.

![Tutoriale - Ontleedde inligting: Onder Statistics -- I/O Graph kan jy ’n grafiek van die kommunikasie vind](<../../../images/image (992).png>)

### Filters

Hier kan jy Wireshark-filters volgens protokol vind: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Gebruik in die huidige Wireshark `tls.*` in plaas van die ou `ssl.*`-filternames.<sup>[[1]](#references)</sup>\
Ander interessante filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP- en aanvanklike HTTPS-verkeer
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP- en aanvanklike HTTPS-verkeer + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP- en aanvanklike HTTPS-verkeer + TCP SYN + DNS-versoeke
- `tls.handshake.extensions_server_name contains "example.com"`
  - Soek op die SNI wat in die ClientHello gestuur word, selfs wanneer jy nie die loonvrag kan dekripteer nie
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Skei vinnig klassieke HTTPS-, HTTP/2- en HTTP/3-sessies
- `quic or http3`
  - Vind moderne UDP/443-verkeer wat jy sal mis as jy slegs TCP-gesprekke nagaan

### Soek

As jy binne die **pakkette** van die sessies na **inhoud** wil **soek**, druk _CTRL+f_. Jy kan nuwe kolomme by die hoofinligtingbalk voeg (No., Time, Source, ens.) deur met die regtermuisknoppie te klik en dan die kolom te wysig.

### Volg van gemultiplekseerde strome

Wireshark kan `TLS`-, `HTTP/2`- en `QUIC`-strome direk volg. Sy HTTP/2- en QUIC-dialoogvensters bied verbindings- en substroomkiesers, wat help om gemultiplekseerde strome te isoleer wat dieselfde laervlakverbinding deel.<sup>[[4]](#references)</sup>

Wanneer sessiesleutels beskikbaar is, identifiseer eers die versoek se stroom-ID en volg dan daardie substroom in plaas van die hele TCP- of UDP-gesprek. Die voorbeeld `0,1` kies HTTP/2-stroom-ID 1 op TCP-stroom 0; vir QUIC, gebruik `follow,quic,utf-8,<connection-number>,<stream-id>`. As jy slegs ’n vyftal volg, kan onafhanklike versoeke vermeng word, of jy kan ’n QUIC-verbinding ná migrasie miskyk.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Gratis pcap-laboratoriums

**Oefen met die gratis uitdagings by:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domeine identifiseer

Jy kan ’n kolom byvoeg wat die Host HTTP-header wys:

![Gratis pcap-laboratoriums - Domeine identifiseer: Jy kan ’n kolom byvoeg wat die Host HTTP-header wys](<../../../images/image (639).png>)

En ’n kolom wat die bedienernaam van ’n aanvangende HTTPS-verbinding wys (**tls.handshake.type == 1**):

![Gratis pcap-laboratoriums - Domeine identifiseer: En ’n kolom wat die bedienernaam van ’n aanvangende HTTPS-verbinding wys ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

As die capture meestal geïnkripteer is, sal die byvoeging van hierdie velde as kolomme triage aansienlik versnel:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Dit laat jou sessies volgens gasheernaam, ALPN (`http/1.1`, `h2`, `h3`, ens.) en kliëntvingerafdruk groepeer, selfs wanneer die payload self geïnkripteer bly. Vir gedekripteerde HTTP/2- en HTTP/3-captures is dit ook nuttig om `http2.header.value` of `http3.headers.header.value` as kolomme by te voeg en volgens paaie, owerhede en ander interessante metadata te sorteer.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: moenie die buitenste SNI met die oorsprong verwar nie

Encrypted ClientHello (ECH) kan ’n publieke deknaam in die sigbare buitenste SNI plaas terwyl die binneste naam geënkripteer word. Daarom kan ’n domeininventaris wat slegs op SNI berus, ECH-verkeer aan die verkeerde oorsprong toeskryf. Die ECH-uitbreiding alleen bewys nie dat ECH geslaag het nie: kliënte kan ’n GREASE ECH-uitbreiding stuur. Op Wireshark 4.2+, vind buitenste ECH-aanbiedinge met die volgende filter en beskou die gerapporteerde SNI as ’n moontlike deknaam, nie as die aangevraagde webwerf nie.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

As jy die ooreenstemmende kliëntsessiesleutels het, ondersoek die gedekripteerde HTTP authority/Host eerder as om die oorsprong uit die buitenste SNI af te lei. Sonder die sleutels, kyk na ander vasgelegde oorsprongbewyse, soos plaintext DNS, maar moenie die buitenste SNI met die versteekte naam gelykstel nie.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identifisering van plaaslike gasheername

### Vanaf DHCP

In huidige Wireshark moet jy in plaas van `bootp` na `DHCP` soek

![Identifisering van plaaslike gasheername - Vanaf DHCP: In huidige Wireshark moet jy in plaas van bootp na DHCP soek](<../../../images/image (1013).png>)

### Vanaf NBNS

![Vanaf DHCP - Vanaf NBNS: In huidige Wireshark moet jy in plaas van bootp na DHCP soek](<../../../images/image (1003).png>)

## Dekripttering van TLS

Wi-Fi-skakellaag-dekripttering is apart van TLS-sessiedekripttering; sien [Wi-Fi PCAP analysis](wifi-pcap-analysis.md) vir die voorvereistes vir sleutels en die handdruk.

### Dekripttering van https-verkeer met die bediener se private sleutel

_edit > preferences > protocols > tls >_

![Dekripttering van TLS - Dekripttering van https-verkeer met die bediener se private sleutel: Dekripttering van https-verkeer met die bediener se private sleutel](<../../../images/image (1103).png>)

Druk _Edit_ en voeg al die bedienerdata en die private sleutel by (_IP, Port, Protocol, Key file and password_)

Hierdie metode werk slegs in ’n beperkte aantal gevalle. Vir huidige TLS 1.3- / ECDHE-verkeer is die sessiesleutellêer-metode hieronder gewoonlik die praktiese opsie.<sup>[[1]](#references)</sup>

### Dekripttering van https-verkeer met simmetriese sessiesleutels

Firefox en Chrome kan albei TLS-sessiesleutels aanteken, wat met Wireshark gebruik kan word om TLS-verkeer te dekripteer. Dit maak ’n diepgaande ontleding van veilige kommunikasie moontlik. Meer besonderhede oor hoe om hierdie dekripttering uit te voer, is beskikbaar in ’n gids by [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Dit is ook die gewone metode om moderne TLS 1.3- en QUIC/HTTP/3-opnames te dekripteer.<sup>[[2]](#references)</sup>

Om dit op te spoor, soek in die omgewing na die veranderlike `SSLKEYLOGFILE`

’n Lêer met gedeelde sleutels lyk soos volg:

![Dekripttering van https-verkeer met die bediener se private sleutel - Dekripttering van https-verkeer met simmetriese sessiesleutels: ’n Lêer met gedeelde sleutels lyk soos volg](<../../../images/image (820).png>)

As die opname `pcapng` is, kyk of dit reeds ingebedde dekripteringsgeheime bevat voordat jy die gasheerlêerstelsel deursoek:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Om dit in wireshark in te voer, gaan na \_edit > preferences > protocols > tls > en voer dit in by Pre-Master-Secret log filename:

![Decryption van https-verkeer met die private bedienersleutel - Decryption van https-verkeer met simmetriese sessiesleutels: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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
- [2] [Dekripsie en ontleding van HTTP/3-verkeer in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Dekripteer TLS-blaaierverkeer met Wireshark – die maklike manier!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protokolstrome volg](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Vertoonfilterverwysing: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Vertoonfilterverwysing: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Vertoonfilterverwysing: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark-handleiding](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
