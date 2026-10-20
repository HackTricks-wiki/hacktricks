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

![Tutorials - Analysed Information: Clicking on Analyze -- Expert Information you will have an overview of what is happening in the packets analyzed](<../../../images/image (256).png>)

**Resolved Addresses**

Under _**Statistics --> Resolved Addresses**_ you can find several **information** that was "**resolved**" by wireshark like port/transport to protocol, MAC to the manufacturer, etc. It is interesting to know what is implicated in the communication.

![Tutorials - Analysed Information: Under Statistics -- Resolved Addresses you can find several information that was " resolved " by wireshark like port/transport to protocol, MAC to the...](<../../../images/image (893).png>)

**Protocol Hierarchy**

Under _**Statistics --> Protocol Hierarchy**_ you can find the **protocols** **involved** in the communication and data about them.

![Tutorials - Analysed Information: Under Statistics -- Protocol Hierarchy you can find the protocols involved in the communication and data about them](<../../../images/image (586).png>)

**Conversations**

Under _**Statistics --> Conversations**_ you can find a **summary of the conversations** in the communication and data about them.

![Tutorials - Analysed Information: Under Statistics -- Conversations you can find a summary of the conversations in the communication and data about them](<../../../images/image (453).png>)

**Endpoints**

Under _**Statistics --> Endpoints**_ you can find a **summary of the endpoints** in the communication and data about each of them.

![Tutorials - Analysed Information: Under Statistics -- Endpoints you can find a summary of the endpoints in the communication and data about each of them](<../../../images/image (896).png>)

**DNS info**

Under _**Statistics --> DNS**_ you can find statistics about the DNS request captured.

![Tutorials - Analysed Information: Under Statistics -- DNS you can find statistics about the DNS request captured](<../../../images/image (1063).png>)

**I/O Graph**

Under _**Statistics --> I/O Graph**_ you can find a **graph of the communication.**

![Tutorials - Analysed Information: Under Statistics -- I/O Graph you can find a graph of the communication](<../../../images/image (992).png>)

### Filters

Here you can find wireshark filter depending on the protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
In current Wireshark use `tls.*` instead of the old `ssl.*` filter names.<sup>[[1]](#references)</sup>\
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

Wireshark can follow `TLS`, `HTTP/2`, and `QUIC` streams directly. Its HTTP/2 and QUIC dialogs expose connection and substream selectors, which helps isolate multiplexed streams that share the same lower-level connection.<sup>[[4]](#references)</sup>

With session keys available, first identify the request's stream ID, then follow that substream instead of the whole TCP or UDP conversation. The `0,1` example selects HTTP/2 stream ID 1 on TCP stream 0; for QUIC use `follow,quic,utf-8,<connection-number>,<stream-id>`. Following only a five-tuple can mix independent requests or miss a QUIC connection after migration.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Free pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

You can add a column that shows the Host HTTP header:

![Free pcap labs - Identifying Domains: You can add a column that shows the Host HTTP header](<../../../images/image (639).png>)

And a column that add the Server name from an initiating HTTPS connection (**tls.handshake.type == 1**):

![Free pcap labs - Identifying Domains: And a column that add the Server name from an initiating HTTPS connection ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

If the capture is mostly encrypted, adding these fields as columns will speed up triage a lot:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

This lets you cluster sessions by hostname, ALPN (`http/1.1`, `h2`, `h3`, etc.) and client fingerprint even when the payload itself stays encrypted. For decrypted HTTP/2 and HTTP/3 captures, it is also useful to add `http2.header.value` or `http3.headers.header.value` as columns and pivot on paths, authorities and other interesting metadata.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: do not mistake the outer SNI for the origin

Encrypted ClientHello (ECH) can place a public cover name in the visible outer SNI while encrypting the inner name. Therefore, an SNI-only domain inventory can attribute ECH traffic to the wrong origin. The ECH extension alone is not proof that ECH succeeded: clients can send a GREASE ECH extension. On Wireshark 4.2+, find outer ECH offers with the following filter and treat the reported SNI as a cover candidate, not the requested site.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

If you have the matching client session keys, inspect the decrypted HTTP authority/Host instead of inferring the origin from outer SNI. Without the keys, check other captured origin evidence, such as plaintext DNS, but do not equate the outer SNI with the hidden name.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identifying local hostnames

### From DHCP

In current Wireshark instead of `bootp` you need to search for `DHCP`

![Identifying local hostnames - From DHCP: In current Wireshark instead of bootp you need to search for DHCP](<../../../images/image (1013).png>)

### From NBNS

![From DHCP - From NBNS: In current Wireshark instead of bootp you need to search for DHCP](<../../../images/image (1003).png>)

## Decrypting TLS

Wi-Fi link-layer decryption is separate from TLS session decryption; see [Wi-Fi PCAP analysis](wifi-pcap-analysis.md) for its key and handshake prerequisites.

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![Decrypting TLS - Decrypting https traffic with server private key: Decrypting https traffic with server private key](<../../../images/image (1103).png>)

Press _Edit_ and add all the data of the server and the private key (_IP, Port, Protocol, Key file and password_)

This method only works in a limited number of cases. For current TLS 1.3 / ECDHE traffic, the session key log method below is usually the practical option.<sup>[[1]](#references)</sup>

### Decrypting https traffic with symmetric session keys

Both Firefox and Chrome have the capability to log TLS session keys, which can be used with Wireshark to decrypt TLS traffic. This allows for in-depth analysis of secure communications. More details on how to perform this decryption can be found in a guide at [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> This is also the normal route for decrypting modern TLS 1.3 and QUIC/HTTP/3 captures.<sup>[[2]](#references)</sup>

To detect this search inside the environment for the variable `SSLKEYLOGFILE`

A file of shared keys will look like this:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: A file of shared keys will look like this](<../../../images/image (820).png>)

If the capture is `pcapng`, check whether it already contains embedded decryption secrets before hunting the host filesystem:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

To import this in wireshark go to \_edit > preferences > protocols > tls > and import it in (Pre)-Master-Secret log filename:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

Extract an APK from an ADB communication where the APK was sent:

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

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Decrypting TLS Browser Traffic With Wireshark – The Easy Way!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Following Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)

{{#include ../../../banners/hacktricks-training.md}}
