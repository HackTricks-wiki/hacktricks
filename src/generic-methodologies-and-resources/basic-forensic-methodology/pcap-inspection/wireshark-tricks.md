# Mbinu za Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Boresha ujuzi wako wa Wireshark

### Tutorials

Tutorials zifuatazo ni nzuri sana kwa kujifunza baadhi ya mbinu za msingi zinazovutia:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Taarifa Zilizochanganuliwa

**Taarifa za Mtaalamu**

Ukibofya _**Analyze** --> **Expert Information**_ utapata **muhtasari** wa kinachotokea katika packets **zilizochanganuliwa**:

![Tutorials - Taarifa Zilizochanganuliwa: Ukibofya Analyze -- Expert Information utapata muhtasari wa kinachotokea katika packets zilizochanganuliwa](<../../../images/image (256).png>)

**Anwani Zilizotatuliwa**

Chini ya _**Statistics --> Resolved Addresses**_ unaweza kupata **taarifa** mbalimbali "**zilizotatuliwa**" na wireshark, kama vile port/transport kwenda kwenye protocol, MAC kwenda kwa mtengenezaji, na kadhalika. Inafaa kujua kinachohusika katika mawasiliano.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Resolved Addresses unaweza kupata taarifa mbalimbali " zilizotatuliwa " na wireshark, kama vile port/transport kwenda kwenye protocol, MAC kwenda kwa...](<../../../images/image (893).png>)

**Mpangilio wa Protocol**

Chini ya _**Statistics --> Protocol Hierarchy**_ unaweza kupata **protocols** **zinazohusika** katika mawasiliano pamoja na data kuzihusu.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Protocol Hierarchy unaweza kupata protocols zinazohusika katika mawasiliano pamoja na data kuzihusu](<../../../images/image (586).png>)

**Mawasiliano**

Chini ya _**Statistics --> Conversations**_ unaweza kupata **muhtasari wa mawasiliano** katika mawasiliano hayo pamoja na data kuyahusu.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Conversations unaweza kupata muhtasari wa mawasiliano katika mawasiliano hayo pamoja na data kuyahusu](<../../../images/image (453).png>)

**Vituo vya Mwisho**

Chini ya _**Statistics --> Endpoints**_ unaweza kupata **muhtasari wa endpoints** katika mawasiliano pamoja na data kuhusu kila kimoja.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Endpoints unaweza kupata muhtasari wa endpoints katika mawasiliano pamoja na data kuhusu kila kimoja](<../../../images/image (896).png>)

**Taarifa za DNS**

Chini ya _**Statistics --> DNS**_ unaweza kupata takwimu kuhusu ombi la DNS lililonaswa.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- DNS unaweza kupata takwimu kuhusu ombi la DNS lililonaswa](<../../../images/image (1063).png>)

**Grafu ya I/O**

Chini ya _**Statistics --> I/O Graph**_ unaweza kupata **grafu ya mawasiliano.**

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- I/O Graph unaweza kupata grafu ya mawasiliano](<../../../images/image (992).png>)

### Filters

Hapa unaweza kupata filter za wireshark kulingana na protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Katika Wireshark ya sasa tumia `tls.*` badala ya majina ya zamani ya filter ya `ssl.*`.\
Filters nyingine zinazovutia:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP na traffic ya awali ya HTTPS
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP na traffic ya awali ya HTTPS + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP na traffic ya awali ya HTTPS + TCP SYN + maombi ya DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Fanya pivot kwenye SNI iliyotumwa katika ClientHello hata kama huwezi ku-decrypt payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Gawanya kwa haraka sessions zinazotumia HTTPS ya kawaida, HTTP/2 na HTTP/3
- `quic or http3`
- Tafuta traffic ya kisasa ya UDP/443 ambayo haitapatikana ukikagua tu mawasiliano ya TCP

### Search

Ikiwa unataka **kutafuta** **content** ndani ya **packets** za sessions, bonyeza _CTRL+f_. Unaweza kuongeza layers mpya kwenye main information bar (No., Time, Source, na kadhalika) kwa kubofya kitufe cha kulia kisha edit column.

### Kufuatilia streams za multiplexed

Matoleo ya hivi karibuni ya Wireshark yanaweza kufuatilia streams za `TLS`, `HTTP/2` na `QUIC` moja kwa moja. Katika captures zenye noise, hii huwa haraka zaidi kuliko kutumia `Follow TCP Stream` pekee, hasa wakati requests kadhaa zinashiriki connection moja.

### Maabara za bure za pcap

**Jizoeze kwa challenges za bure za:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Kutambua Domains

Unaweza kuongeza column inayoonyesha HTTP Host header:

![Free pcap labs - Kutambua Domains: Unaweza kuongeza column inayoonyesha HTTP Host header](<../../../images/image (639).png>)

Na column inayoongeza jina la Server kutoka kwenye HTTPS connection inayoanzishwa (**tls.handshake.type == 1**):

![Free pcap labs - Kutambua Domains: Na column inayoongeza jina la Server kutoka kwenye HTTPS connection inayoanzishwa ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Ikiwa capture ime-encryptiwa kwa kiasi kikubwa, kuongeza fields hizi kama columns kutaharakisha sana triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Hii hukuwezesha kupanga sessions katika clusters kulingana na hostname, ALPN (`http/1.1`, `h2`, `h3`, na kadhalika) na client fingerprint hata wakati payload yenyewe bado ime-encryptiwa. Kwa captures za HTTP/2 na HTTP/3 zilizodecryptiwa, pia inafaa kuongeza `http2.header.value` au `http3.headers.header.value` kama columns na kufanya pivot kwenye paths, authorities na metadata nyingine zinazovutia.<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Kutambua majina ya host ya ndani

### Kutoka DHCP

Katika Wireshark ya sasa, badala ya `bootp` unahitaji kutafuta `DHCP`

![Kutambua majina ya host ya ndani - Kutoka DHCP: Katika Wireshark ya sasa, badala ya bootp unahitaji kutafuta DHCP](<../../../images/image (1013).png>)

### Kutoka NBNS

![Kutoka DHCP - Kutoka NBNS: Katika Wireshark ya sasa, badala ya bootp unahitaji kutafuta DHCP](<../../../images/image (1003).png>)

## Kusimbua TLS

### Kusimbua traffic ya https kwa kutumia server private key

_edit > preferences > protocols > tls >_

![Kusimbua TLS - Kusimbua traffic ya https kwa kutumia server private key: Kusimbua traffic ya https kwa kutumia server private key](<../../../images/image (1103).png>)

Bonyeza _Edit_ na uongeze data yote ya server na private key (_IP, Port, Protocol, Key file na password_)

Njia hii hufanya kazi katika hali chache tu. Kwa traffic ya sasa ya TLS 1.3 / ECDHE, njia ya session key log iliyo hapa chini kwa kawaida ndiyo chaguo linalofaa.<sup>[[1]](#references)</sup>

### Kusimbua traffic ya https kwa kutumia symmetric session keys

Firefox na Chrome zote zina uwezo wa kurekodi TLS session keys, ambazo zinaweza kutumiwa pamoja na Wireshark kusimbua TLS traffic. Hii huruhusu uchambuzi wa kina wa mawasiliano salama. Maelezo zaidi kuhusu jinsi ya kufanya usimbuaji huu yanapatikana katika mwongozo kwenye [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Hii pia ndiyo njia ya kawaida ya kusimbua captures za kisasa za TLS 1.3 na QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Ili kugundua hili, tafuta variable `SSLKEYLOGFILE` ndani ya environment

File ya shared keys itaonekana hivi:

![Kusimbua traffic ya https kwa kutumia server private key - Kusimbua traffic ya https kwa kutumia symmetric session keys: File ya shared keys itaonekana hivi](<../../../images/image (820).png>)

Ikiwa capture ni `pcapng`, angalia kama tayari ina decryption secrets zilizowekwa ndani kabla ya kutafuta kwenye filesystem ya host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Ili kuingiza hii katika Wireshark, nenda kwenye \_edit > preferences > protocols > tls > kisha uiingize katika (Pre)-Master-Secret log filename:

![Kusimbua traffic ya https kwa private key ya server - Kusimbua traffic ya https kwa symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Mawasiliano ya ADB

Extract APK kutoka kwenye mawasiliano ya ADB ambapo APK ilitumwa:
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
## Marejeleo

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Kusimbua na kuchanganua trafiki ya HTTP/3 katika Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Kusimbua trafiki ya TLS ya browser kwa kutumia Wireshark – Njia rahisi!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
