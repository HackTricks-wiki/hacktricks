# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Improve your Wireshark skills

### Tutorials

The following tutorials are amazing to learn some cool basic tricks:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

Clicking on _**Analyze** --> **Expert Information**_ you will have an **overview** of what is happening in the packets **analyzed**:

![](<../../../images/image (256).png>)

**Resolved Addresses**

Under _**Statistics --> Resolved Addresses**_ you can find several **information** that was "**resolved**" by wireshark like port/transport to protocol, MAC to the manufacturer, etc. It is interesting to know what is implicated in the communication.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

Under _**Statistics --> Protocol Hierarchy**_ you can find the **protocols** **involved** in the communication and data about them.

![](<../../../images/image (586).png>)

**Conversations**

Under _**Statistics --> Conversations**_ you can find a **summary of the conversations** in the communication and data about them.

![](<../../../images/image (453).png>)

**Endpoints**

Under _**Statistics --> Endpoints**_ you can find a **summary of the endpoints** in the communication and data about each of them.

![](<../../../images/image (896).png>)

**DNS info**

Under _**Statistics --> DNS**_ you can find statistics about the DNS request captured.

![](<../../../images/image (1063).png>)

**I/O Graph**

Under _**Statistics --> I/O Graph**_ you can find a **graph of the communication.**

![](<../../../images/image (992).png>)

### Filters

Here you can find wireshark filter depending on the protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
In current Wireshark use `tls.*` instead of the old `ssl.*` filter names.\
Other interesting filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot on the SNI sent in the ClientHello even when you cannot decrypt the payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Split classic HTTPS, HTTP/2 and HTTP/3 capable sessions quickly
- `quic or http3`
- Find modern UDP/443 traffic that will be missed if you only review TCP conversations

### Search

If you want to **search** for **content** inside the **packets** of the sessions press _CTRL+f_. You can add new layers to the main information bar (No., Time, Source, etc.) by pressing the right button and then the edit column.

### Following multiplexed streams

Recent Wireshark versions can follow `TLS`, `HTTP/2` and `QUIC` streams directly. On noisy captures this is usually faster than only using `Follow TCP Stream`, especially when several requests share the same connection.

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

У поточному Wireshark замість `bootp` потрібно шукати `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Натисніть _Edit_ і додайте всі дані сервера та private key (_IP, Port, Protocol, Key file and password_)

Цей метод працює лише в обмеженій кількості випадків. Для сучасного TLS 1.3 / ECDHE трафіку зазвичай практичним варіантом є метод із session key log нижче.

### Decrypting https traffic with symmetric session keys

І Firefox, і Chrome мають можливість записувати TLS session keys, які можна використовувати з Wireshark для decrypt TLS traffic. Це дає змогу виконувати детальний аналіз secure communications. Більше деталей про те, як виконати це decrypt, можна знайти в guide на [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Це також стандартний шлях для decrypt сучасних TLS 1.3 і QUIC/HTTP/3 captures.

Щоб це виявити, пошукайте в environment змінну `SSLKEYLOGFILE`

Файл shared keys виглядатиме так:

![](<../../../images/image (820).png>)

Якщо capture має формат `pcapng`, перевірте, чи вже містить він вбудовані decryption secrets, перш ніж шукати їх у файловій системі host:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Щоб імпортувати це в wireshark, перейдіть до \_edit > preferences > protocols > tls > і імпортуйте це в (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB communication

Витягніть APK з ADB communication, де APK було надіслано:
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
