# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Boresha ujuzi wako wa Wireshark

### Tutorials

Tutorials zifuatazo ni nzuri sana kujifunza baadhi ya tricks za msingi za kufurahisha:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Taarifa Zilizochambuliwa

**Taarifa za Kitaalamu**

Kubofya _**Analyze** --> **Expert Information**_ utapata **muhtasari** wa kinachoendelea katika pakiti **zilizochambuliwa**:

![](<../../../images/image (256).png>)

**Anwani Zilizotatuliwa**

Chini ya _**Statistics --> Resolved Addresses**_ unaweza kupata **taarifa** kadhaa ambazo zilitwa "**resolved**" na wireshark kama port/transport kwenda protocol, MAC kwenda mtengenezaji, n.k. Ni muhimu kujua nini kimehusika katika mawasiliano.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

Chini ya _**Statistics --> Protocol Hierarchy**_ unaweza kupata **protocols** **zilizohusika** katika mawasiliano na data kuzihusu.

![](<../../../images/image (586).png>)

**Mazungumzo**

Chini ya _**Statistics --> Conversations**_ unaweza kupata **muhtasari wa mazungumzo** katika mawasiliano na data kuyahusu.

![](<../../../images/image (453).png>)

**Endpoints**

Chini ya _**Statistics --> Endpoints**_ unaweza kupata **muhtasari wa endpoints** katika mawasiliano na data kuhusu kila moja.

![](<../../../images/image (896).png>)

**Taarifa za DNS**

Chini ya _**Statistics --> DNS**_ unaweza kupata takwimu kuhusu DNS request iliyokamatwa.

![](<../../../images/image (1063).png>)

**I/O Graph**

Chini ya _**Statistics --> I/O Graph**_ unaweza kupata **grafu ya mawasiliano.**

![](<../../../images/image (992).png>)

### Filters

Hapa unaweza kupata Wireshark filter kulingana na protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Katika Wireshark ya sasa tumia `tls.*` badala ya majina ya zamani ya filter `ssl.*`.\
Filters nyingine za kuvutia:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP na trafiki ya awali ya HTTPS
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP na trafiki ya awali ya HTTPS + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP na trafiki ya awali ya HTTPS + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot kwenye SNI iliyotumwa kwenye ClientHello hata wakati huwezi decrypt payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Gawa kwa haraka sessions za classic HTTPS, HTTP/2 na HTTP/3 zinazoweza
- `quic or http3`
- Pata modern UDP/443 traffic ambayo itakosa kuonekana ukikagua tu TCP conversations

### Utafutaji

Ukitaka **kutafuta** **content** ndani ya **pakiti** za sessions bonyeza _CTRL+f_. Unaweza kuongeza layers mpya kwenye main information bar (No., Time, Source, etc.) kwa kubofya button ya kulia kisha edit column.

### Kufuatilia multiplexed streams

Matoleo ya hivi karibuni ya Wireshark yanaweza kufuatilia `TLS`, `HTTP/2` na `QUIC` streams moja kwa moja. Katika captures zenye noise hii kawaida ni haraka zaidi kuliko kutumia tu `Follow TCP Stream`, hasa wakati requests kadhaa zinashiriki connection moja.

### Free pcap labs

**Fanya mazoezi na challenges za bure za:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Kutambua Domains

Unaweza kuongeza column inayoonyesha Host HTTP header:

![](<../../../images/image (639).png>)

Na column inayoongeza Server name kutoka kwenye initiating HTTPS connection (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Kama capture imefichwa kwa njia ya encryption zaidi, kuongeza fields hizi kama columns kutaharakisha triage sana:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Hii inakuwezesha kupanga sessions kwa hostname, ALPN (`http/1.1`, `h2`, `h3`, etc.) na client fingerprint hata payload yenyewe ikibaki encrypted. Kwa decrypted HTTP/2 na HTTP/3 captures, pia ni muhimu kuongeza `http2.header.value` au `http3.headers.header.value` kama columns na pivot kwenye paths, authorities na metadata nyingine za kuvutia.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Kutambua local hostnames

### Kutoka DHCP

Katika Wireshark ya sasa badala ya `bootp` unahitaji kutafuta `DHCP`

![](<../../../images/image (1013).png>)

### Kutoka NBNS

![](<../../../images/image (1003).png>)

## Kumsimbua TLS

### Kumsimbua trafiki ya https kwa kutumia server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Bonyeza _Edit_ na uongeze data zote za server na private key (_IP, Port, Protocol, Key file and password_)

Njia hii inafanya kazi tu katika hali chache. Kwa trafiki ya sasa ya TLS 1.3 / ECDHE, njia ya session key log hapa chini ndiyo kawaida chaguo la vitendo.

### Kumsimbua trafiki ya https kwa kutumia symmetric session keys

Firefox na Chrome zote zina uwezo wa kuandika TLS session keys, ambazo zinaweza kutumiwa na Wireshark kusimbua trafiki ya TLS. Hii inaruhusu uchambuzi wa kina wa mawasiliano salama. Maelezo zaidi kuhusu jinsi ya kufanya msimbuo huu yanaweza kupatikana kwenye mwongozo katika [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Hii pia ndiyo njia ya kawaida ya kusimbua captures za kisasa za TLS 1.3 na QUIC/HTTP/3.

Ili kugundua hili tafuta ndani ya environment kwa variable `SSLKEYLOGFILE`

Faili ya shared keys itaonekana hivi:

![](<../../../images/image (820).png>)

Ikiwa capture ni `pcapng`, angalia kama tayari ina embedded decryption secrets kabla ya kuanza kuchunguza host filesystem:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Ili kuiingiza hii katika wireshark nenda kwa \_edit > preferences > protocols > tls > na uiingize katika (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## Mawasiliano ya ADB

Toa APK kutoka kwenye mawasiliano ya ADB ambapo APK ilitumwa:
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
## Marejeo

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
