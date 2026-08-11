# Mbinu za Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Boresha ujuzi wako wa Wireshark

### Tutorials

Tutorials zifuatazo ni nzuri sana kwa kujifunza baadhi ya mbinu za msingi za kuvutia:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Taarifa Zilizochanganuliwa

**Taarifa za Kitaalamu**

Ukibofya _**Analyze** --> **Expert Information**_ utapata **muhtasari** wa kinachoendelea katika pakiti **zilizochanganuliwa**:

![Tutorials - Taarifa Zilizochanganuliwa: Ukibofya Analyze -- Expert Information utapata muhtasari wa kinachoendelea katika pakiti zilizochanganuliwa](<../../../images/image (256).png>)

**Anwani Zilizotatuliwa**

Chini ya _**Statistics --> Resolved Addresses**_ unaweza kupata **taarifa** kadhaa ambazo "**zilitatuliwa**" na wireshark, kama vile port/transport kuwa protocol, MAC kuwa mtengenezaji, n.k. Inavutia kujua kinachohusika katika mawasiliano.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Resolved Addresses unaweza kupata taarifa kadhaa ambazo " zilitatuliwa " na wireshark, kama vile port/transport kuwa protocol, MAC kuwa...](<../../../images/image (893).png>)

**Hierarkia ya Protocol**

Chini ya _**Statistics --> Protocol Hierarchy**_ unaweza kupata **protocols** **zinazohusika** katika mawasiliano pamoja na data kuzihusu.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Protocol Hierarchy unaweza kupata protocols zinazohusika katika mawasiliano pamoja na data kuzihusu](<../../../images/image (586).png>)

**Mawasiliano**

Chini ya _**Statistics --> Conversations**_ unaweza kupata **muhtasari wa mawasiliano** katika mawasiliano hayo pamoja na data kuyahusu.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Conversations unaweza kupata muhtasari wa mawasiliano katika mawasiliano hayo pamoja na data kuyahusu](<../../../images/image (453).png>)

**Endpoints**

Chini ya _**Statistics --> Endpoints**_ unaweza kupata **muhtasari wa endpoints** katika mawasiliano pamoja na data kuhusu kila moja.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- Endpoints unaweza kupata muhtasari wa endpoints katika mawasiliano pamoja na data kuhusu kila moja](<../../../images/image (896).png>)

**Taarifa za DNS**

Chini ya _**Statistics --> DNS**_ unaweza kupata takwimu kuhusu ombi la DNS lililonaswa.

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- DNS unaweza kupata takwimu kuhusu ombi la DNS lililonaswa](<../../../images/image (1063).png>)

**Grafu ya I/O**

Chini ya _**Statistics --> I/O Graph**_ unaweza kupata **grafu ya mawasiliano.**

![Tutorials - Taarifa Zilizochanganuliwa: Chini ya Statistics -- I/O Graph unaweza kupata grafu ya mawasiliano](<../../../images/image (992).png>)

### Filters

Hapa unaweza kupata filter za Wireshark kulingana na protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Katika Wireshark ya sasa tumia `tls.*` badala ya majina ya zamani ya filter za `ssl.*`.<sup>[[1]](#references)</sup>\
Filter nyingine za kuvutia:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Traffic ya HTTP na HTTPS ya mwanzo
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Traffic ya HTTP na HTTPS ya mwanzo + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Traffic ya HTTP na HTTPS ya mwanzo + TCP SYN + maombi ya DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Fanya Pivot kwenye SNI iliyotumwa katika ClientHello hata wakati huwezi kusimbua payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Gawanya haraka sessions za kawaida za HTTPS, HTTP/2 na HTTP/3
- `quic or http3`
- Tafuta traffic ya kisasa ya UDP/443 ambayo haitapatikana ukikagua tu mawasiliano ya TCP

### Search

Ukitaka **kutafuta** **maudhui** ndani ya **pakiti** za sessions, bonyeza _CTRL+f_. Unaweza kuongeza layers mpya kwenye upau mkuu wa taarifa (No., Time, Source, n.k.) kwa kubofya kitufe cha kulia kisha uchague edit column.

### Kufuatilia streams zenye multiplexing

Wireshark inaweza kufuatilia moja kwa moja streams za `TLS`, `HTTP/2`, na `QUIC`. Dialog zake za HTTP/2 na QUIC zinaonyesha selectors za connection na substream, jambo linalosaidia kutenga streams zenye multiplexing ambazo zinashiriki connection ileile ya kiwango cha chini.<sup>[[4]](#references)</sup>

### Maabara za bure za pcap

**Fanya mazoezi kwa challenges za bure kwenye:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Kutambua Domains

Unaweza kuongeza column inayoonyesha HTTP Host header:

![Free pcap labs - Kutambua Domains: Unaweza kuongeza column inayoonyesha HTTP Host header](<../../../images/image (639).png>)

Na column inayoongeza Server name kutoka kwenye connection ya HTTPS inayoanzishwa (**tls.handshake.type == 1**):

![Free pcap labs - Kutambua Domains: Na column inayoongeza Server name kutoka kwenye connection ya HTTPS inayoanzishwa ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Ikiwa capture imefichwa kwa kiasi kikubwa, kuongeza fields hizi kama columns kutaharakisha sana triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Hii hukuwezesha kupanga sessions kwa hostname, ALPN (`http/1.1`, `h2`, `h3`, n.k.) na client fingerprint hata payload yenyewe ikiwa bado imesimbwa. Kwa captures za HTTP/2 na HTTP/3 zilizofumbuliwa, inasaidia pia kuongeza `http2.header.value` au `http3.headers.header.value` kama columns na kufanya Pivot kwenye paths, authorities na metadata nyingine za kuvutia.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Kutambua majina ya host za ndani

### Kutoka DHCP

Katika Wireshark ya sasa, badala ya `bootp` unahitaji kutafuta `DHCP`

![Kutambua majina ya host za ndani - Kutoka DHCP: Katika Wireshark ya sasa, badala ya bootp unahitaji kutafuta DHCP](<../../../images/image (1013).png>)

### Kutoka NBNS

![Kutoka DHCP - Kutoka NBNS: Katika Wireshark ya sasa, badala ya bootp unahitaji kutafuta DHCP](<../../../images/image (1003).png>)

## Kusimbua TLS

### Kusimbua trafiki ya https kwa kutumia private key ya server

_edit > preferences > protocols > tls >_

![Kusimbua TLS - Kusimbua trafiki ya https kwa kutumia private key ya server: Kusimbua trafiki ya https kwa kutumia private key ya server](<../../../images/image (1103).png>)

Bonyeza _Edit_ na uongeze data yote ya server pamoja na private key (_IP, Port, Protocol, Key file na password_)

Njia hii hufanya kazi katika idadi ndogo tu ya hali. Kwa trafiki ya sasa ya TLS 1.3 / ECDHE, njia ya session key log iliyo hapa chini kwa kawaida ndiyo chaguo linalofaa.<sup>[[1]](#references)</sup>

### Kusimbua trafiki ya https kwa kutumia symmetric session keys

Firefox na Chrome zote zina uwezo wa kurekodi TLS session keys, ambazo zinaweza kutumiwa pamoja na Wireshark kusimbua trafiki ya TLS. Hii huruhusu uchanganuzi wa kina wa mawasiliano salama. Maelezo zaidi kuhusu jinsi ya kufanya usimbuaji huu yanapatikana kwenye mwongozo wa [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Hii pia ndiyo njia ya kawaida ya kusimbua captures za kisasa za TLS 1.3 na QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Ili kugundua hili, tafuta variable `SSLKEYLOGFILE` ndani ya environment

Faili ya shared keys itaonekana hivi:

![Kusimbua trafiki ya https kwa kutumia private key ya server - Kusimbua trafiki ya https kwa kutumia symmetric session keys: Faili ya shared keys itaonekana hivi](<../../../images/image (820).png>)

Ikiwa capture ni `pcapng`, angalia kama tayari ina decryption secrets zilizopachikwa kabla ya kutafuta kwenye filesystem ya host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Ili kuleta hii katika Wireshark, nenda kwenye \_edit > preferences > protocols > tls > kisha uiingize katika (Pre)-Master-Secret log filename:

![Kudecipher traffic ya https kwa kutumia server private key - Kudecipher traffic ya https kwa kutumia symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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
## References

- [1] [Wiki ya Wireshark TLS](https://wiki.wireshark.org/TLS)
- [2] [Kudecipher na kuchanganua traffic ya HTTP/3 katika Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Kudecipher Traffic ya TLS ya Browser kwa Wireshark - Njia Rahisi!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Kufuatilia Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Marejeleo ya Display Filter: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Marejeleo ya Display Filter: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Marejeleo ya Display Filter: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
