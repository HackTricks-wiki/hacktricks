# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Verbeter jou Wireshark-vaardighede

### Tutorials

Die volgende tutorials is uitstekend om ’n paar cool basiese tricks te leer:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Geanaliseerde Inligting

**Expert Information**

Deur op _**Analyze** --> **Expert Information**_ te klik, sal jy ’n **oorsig** hê van wat in die **geanaliseerde** pakkies gebeur:

![](<../../../images/image (256).png>)

**Resolved Addresses**

Onder _**Statistics --> Resolved Addresses**_ kan jy verskeie **inligting** vind wat deur wireshark "**opgelos**" is, soos port/transport na protocol, MAC na die vervaardiger, ens. Dit is interessant om te weet wat by die kommunikasie betrokke is.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

Onder _**Statistics --> Protocol Hierarchy**_ kan jy die **protocols** vind wat by die kommunikasie betrokke is, sowel as data daaroor.

![](<../../../images/image (586).png>)

**Conversations**

Onder _**Statistics --> Conversations**_ kan jy ’n **opsomming van die conversations** in die kommunikasie en data daaroor vind.

![](<../../../images/image (453).png>)

**Endpoints**

Onder _**Statistics --> Endpoints**_ kan jy ’n **opsomming van die endpoints** in die kommunikasie en data oor elkeen van hulle vind.

![](<../../../images/image (896).png>)

**DNS info**

Onder _**Statistics --> DNS**_ kan jy statistieke oor die vasgelegde DNS request vind.

![](<../../../images/image (1063).png>)

**I/O Graph**

Onder _**Statistics --> I/O Graph**_ kan jy ’n **grafiek van die kommunikasie** vind.

![](<../../../images/image (992).png>)

### Filters

Hier kan jy wireshark filters vind, afhangend van die protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
In huidige Wireshark gebruik `tls.*` in plaas van die ou `ssl.*` filter name.\
Ander interessante filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot op die SNI gestuur in die ClientHello selfs wanneer jy nie die payload kan decrypt nie
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Skei classic HTTPS, HTTP/2 en HTTP/3-kapabele sessions vinnig
- `quic or http3`
- Vind moderne UDP/443 traffic wat gemis sal word as jy slegs TCP conversations hersien

### Search

As jy **search** vir **content** binne die **packets** van die sessions wil doen, druk _CTRL+f_. Jy kan nuwe layers by die hoofinligtingbalk voeg (No., Time, Source, ens.) deur op die regterknoppie te druk en dan die edit column.

### Following multiplexed streams

Onlangse Wireshark-weergawes kan `TLS`, `HTTP/2` en `QUIC` streams direk volg. Op geraasagtige captures is dit gewoonlik vinniger as om slegs `Follow TCP Stream` te gebruik, veral wanneer verskeie requests dieselfde connection deel.

### Free pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

You can add a column that shows the Host HTTP header:

![](<../../../images/image (639).png>)

And a column that add the Server name from an initiating HTTPS connection (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

If the capture is mostly encrypted, adding these fields as columns will speed up triage a lot:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

This lets you cluster sessions by hostname, ALPN (`http/1.1`, `h2`, `h3`, etc.) and client fingerprint even when the payload itself stays encrypted. For decrypted HTTP/2 and HTTP/3 captures, it is also useful to add `http2.header.value` or `http3.headers.header.value` as columns and pivot on paths, authorities and other interesting metadata.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifying local hostnames

### From DHCP

In current Wireshark instead of `bootp` you need to search for `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Druk _Edit_ en voeg al die data van die server en die private key by (_IP, Port, Protocol, Key file and password_)

This method only works in a limited number of cases. For current TLS 1.3 / ECDHE traffic, the session key log method below is usually the practical option.

### Decrypting https traffic with symmetric session keys

Both Firefox and Chrome have the capability to log TLS session keys, which can be used with Wireshark to decrypt TLS traffic. This allows for in-depth analysis of secure communications. More details on how to perform this decryption can be found in a guide at [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). This is also the normal route for decrypting modern TLS 1.3 and QUIC/HTTP/3 captures.

Om dit op te spoor, soek binne die environment vir die variable `SSLKEYLOGFILE`

A file of shared keys will look like this:

![](<../../../images/image (820).png>)

If the capture is `pcapng`, check whether it already contains embedded decryption secrets before hunting the host filesystem:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Om dit in wireshark in te voer gaan na \_edit > preferences > protocols > tls > en voer dit in by (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB kommunikasie

Onttrek ’n APK uit ’n ADB kommunikasie waar die APK gestuur is:
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

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
