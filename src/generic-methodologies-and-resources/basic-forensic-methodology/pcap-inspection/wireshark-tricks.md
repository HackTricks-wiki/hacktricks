# Mbinu za Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Boresha ujuzi wako wa Wireshark

### Mafunzo

Mafunzo yafuatayo ni mazuri sana kwa kujifunza mbinu kadhaa muhimu za msingi:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Taarifa Zilizochanganuliwa

**Taarifa za Wataalamu**

Ukibofya _**Changanua** --> **Taarifa za Wataalamu**_ utapata **muhtasari** wa kinachoendelea katika pakiti **zilizochanganuliwa**:

![Mafunzo - Taarifa Zilizochanganuliwa: Ukibofya Changanua -- Taarifa za Wataalamu utapata muhtasari wa kinachoendelea katika pakiti zilizochanganuliwa](<../../../images/image (256).png>)

**Anwani Zilizotatuliwa**

Chini ya _**Takwimu --> Anwani Zilizotatuliwa**_ unaweza kupata **taarifa** kadhaa ambazo Wireshark "**imetatua**", kama vile port/transport kwa itifaki, MAC kwa mtengenezaji, n.k. Ni vizuri kujua kinachohusika katika mawasiliano.

![Mafunzo - Taarifa Zilizochanganuliwa: Chini ya Takwimu -- Anwani Zilizotatuliwa unaweza kupata taarifa kadhaa ambazo Wireshark " imetatua " kama vile port/transport kwa itifaki, MAC kwa...](<../../../images/image (893).png>)

**Mpangilio wa Itifaki**

Chini ya _**Takwimu --> Mpangilio wa Itifaki**_ unaweza kupata **itifaki** **zinazohusika** katika mawasiliano na data kuzihusu.

![Mafunzo - Taarifa Zilizochanganuliwa: Chini ya Takwimu -- Mpangilio wa Itifaki unaweza kupata itifaki zinazohusika katika mawasiliano na data kuzihusu](<../../../images/image (586).png>)

**Mazungumzo**

Chini ya _**Takwimu --> Mazungumzo**_ unaweza kupata **muhtasari wa mazungumzo** katika mawasiliano na data kuyahusu.

![Mafunzo - Taarifa Zilizochanganuliwa: Chini ya Takwimu -- Mazungumzo unaweza kupata muhtasari wa mazungumzo katika mawasiliano na data kuyahusu](<../../../images/image (453).png>)

**Vituo vya Mwisho**

Chini ya _**Takwimu --> Vituo vya Mwisho**_ unaweza kupata **muhtasari wa vituo vya mwisho** katika mawasiliano na data kuhusu kila kimoja.

![Mafunzo - Taarifa Zilizochanganuliwa: Chini ya Takwimu -- Vituo vya Mwisho unaweza kupata muhtasari wa vituo vya mwisho katika mawasiliano na data kuhusu kila kimoja](<../../../images/image (896).png>)

**Taarifa za DNS**

Chini ya _**Takwimu --> DNS**_ unaweza kupata takwimu kuhusu ombi la DNS lililonaswa.

![Mafunzo - Taarifa Zilizochanganuliwa: Chini ya Takwimu -- DNS unaweza kupata takwimu kuhusu ombi la DNS lililonaswa](<../../../images/image (1063).png>)

**Grafu ya I/O**

Chini ya _**Takwimu --> Grafu ya I/O**_ unaweza kupata **grafu ya mawasiliano.**

![Mafunzo - Taarifa Zilizochanganuliwa: Chini ya Takwimu -- Grafu ya I/O unaweza kupata grafu ya mawasiliano](<../../../images/image (992).png>)

### Vichujio

Hapa unaweza kupata vichujio vya Wireshark kulingana na itifaki: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Katika Wireshark ya sasa, tumia `tls.*` badala ya majina ya vichujio ya zamani ya `ssl.*`.<sup>[[1]](#references)</sup>\
Vichujio vingine vya kuvutia:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - Trafiki ya HTTP na HTTPS ya awali
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - Trafiki ya HTTP na HTTPS ya awali + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - Trafiki ya HTTP na HTTPS ya awali + TCP SYN + maombi ya DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Chunguza SNI iliyotumwa katika ClientHello hata kama huwezi kusimbua payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Tenganisha haraka miunganisho ya HTTPS ya kawaida, HTTP/2 na inayoweza kutumia HTTP/3
- `quic or http3`
  - Tafuta trafiki ya kisasa ya UDP/443 ambayo hutakiona ukikagua mazungumzo ya TCP pekee

### Utafutaji

Ikiwa unataka **kutafuta** **maudhui** ndani ya **pakiti** za vipindi, bonyeza _CTRL+f_. Unaweza kuongeza safu wima mpya kwenye upau mkuu wa taarifa (Na., Muda, Chanzo, n.k.) kwa kubofya kitufe cha kulia kisha kuchagua kuhariri safu wima.

### Kufuatilia mitiririko iliyozidishwa

Wireshark inaweza kufuatilia mitiririko ya `TLS`, `HTTP/2`, na `QUIC` moja kwa moja. Vidirisha vyake vya HTTP/2 na QUIC vina chaguo za kuchagua muunganisho na substream, zinazosaidia kutenga mitiririko iliyozidishwa inayotumia muunganisho uleule wa ngazi ya chini.<sup>[[4]](#references)</sup>

Ukiwa na funguo za session, tambua kwanza stream ID ya ombi, kisha fuatilia substream hiyo badala ya mazungumzo yote ya TCP au UDP. Mfano wa `0,1` huchagua stream ID 1 ya HTTP/2 kwenye TCP stream 0; kwa QUIC tumia `follow,quic,utf-8,<connection-number>,<stream-id>`. Kufuatilia tu five-tuple kunaweza kuchanganya maombi huru au kukosa muunganisho wa QUIC baada ya kuhamishwa.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Maabara za pcap zisizolipishwa

**Fanya mazoezi kwa kutumia changamoto zisizolipishwa za:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Kutambua Domains

Unaweza kuongeza safu inayoonyesha header ya Host ya HTTP:

![Maabara za pcap zisizolipishwa - Kutambua Domains: Unaweza kuongeza safu inayoonyesha header ya Host ya HTTP](<../../../images/image (639).png>)

Na safu inayoonyesha jina la Server kutoka kwenye muunganisho wa HTTPS unaoanzishwa (**tls.handshake.type == 1**):

![Maabara za pcap zisizolipishwa - Kutambua Domains: Na safu inayoonyesha jina la Server kutoka kwenye muunganisho wa HTTPS unaoanzishwa ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Ikiwa sehemu kubwa ya capture imesimbwa kwa njia fiche, kuongeza sehemu hizi kama safu kutaharakisha sana uchunguzi wa awali:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Hii hukuwezesha kupanga sessions katika vikundi kulingana na hostname, ALPN (`http/1.1`, `h2`, `h3`, n.k.) na fingerprint ya client, hata payload yenyewe ikiwa bado imesimbwa kwa njia fiche. Kwa captures za HTTP/2 na HTTP/3 zilizofumbuliwa, ni muhimu pia kuongeza `http2.header.value` au `http3.headers.header.value` kama safu na kuchunguza paths, authorities na metadata nyingine zinazovutia.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: usikosee SNI ya nje kuwa ndiyo origin

Encrypted ClientHello (ECH) inaweza kuweka jina la umma la kufunika kwenye SNI ya nje inayoonekana huku ikisimba jina la ndani. Kwa hiyo, orodha ya domain zinazotegemea SNI pekee inaweza kuhusisha traffic ya ECH na origin isiyo sahihi. Extension ya ECH pekee haithibitishi kuwa ECH ilifaulu: clients wanaweza kutuma extension ya GREASE ECH. Kwenye Wireshark 4.2+, tafuta ofa za ECH za nje kwa kutumia filter ifuatayo na chukulia SNI iliyoripotiwa kama jina linalowezekana la kufunika, si tovuti iliyoombwa.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Ikiwa una client session keys zinazolingana, kagua HTTP authority/Host iliyosimbuliwa badala ya kukisia origin kutokana na outer SNI. Bila keys hizo, angalia ushahidi mwingine wa origin uliorekodiwa, kama vile DNS ya maandishi wazi, lakini usichukulie outer SNI kuwa sawa na jina lililofichwa.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Kutambua hostnames za ndani

### Kutoka DHCP

Katika Wireshark ya sasa, badala ya `bootp`, unahitaji kutafuta `DHCP`

![Kutambua hostnames za ndani - Kutoka DHCP: Katika Wireshark ya sasa, badala ya bootp, unahitaji kutafuta DHCP](<../../../images/image (1013).png>)

### Kutoka NBNS

![Kutoka DHCP - Kutoka NBNS: Katika Wireshark ya sasa, badala ya bootp, unahitaji kutafuta DHCP](<../../../images/image (1003).png>)

## Kusimbua TLS

Usimbuaji wa Wi-Fi link-layer ni tofauti na usimbuaji wa TLS session; tazama [Wi-Fi PCAP analysis](wifi-pcap-analysis.md) kwa masharti ya key na handshake.

### Kusimbua HTTPS traffic kwa kutumia server private key

_edit > preferences > protocols > tls >_

![Kusimbua TLS - Kusimbua HTTPS traffic kwa kutumia server private key: Kusimbua HTTPS traffic kwa kutumia server private key](<../../../images/image (1103).png>)

Bonyeza _Edit_ na uongeze data yote ya server na private key (_IP, Port, Protocol, Key file and password_)

Njia hii hufanya kazi katika hali chache tu. Kwa traffic ya sasa ya TLS 1.3 / ECDHE, kwa kawaida njia inayofaa zaidi ni kutumia session key log iliyo hapa chini.<sup>[[1]](#references)</sup>

### Kusimbua HTTPS traffic kwa kutumia symmetric session keys

Firefox na Chrome zina uwezo wa kurekodi TLS session keys, ambazo zinaweza kutumika pamoja na Wireshark kusimbua TLS traffic. Hii huwezesha uchanganuzi wa kina wa mawasiliano salama. Maelezo zaidi kuhusu jinsi ya kufanya usimbuaji huu yanapatikana katika mwongozo wa [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Hii pia ndiyo njia ya kawaida ya kusimbua captures za kisasa za TLS 1.3 na QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Ili kugundua hili, tafuta variable `SSLKEYLOGFILE` ndani ya mazingira.

Faili ya shared keys itaonekana hivi:

![Kusimbua HTTPS traffic kwa kutumia server private key - Kusimbua HTTPS traffic kwa kutumia symmetric session keys: Faili ya shared keys itaonekana hivi](<../../../images/image (820).png>)

Ikiwa capture ni `pcapng`, hakikisha kama tayari ina decryption secrets zilizopachikwa kabla ya kutafuta kwenye filesystem ya host:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Ili kuingiza hii kwenye Wireshark, nenda kwenye \_edit > preferences > protocols > tls > kisha uiingize kwenye sehemu ya (Pre)-Master-Secret log filename:

![Kudecipher mawasiliano ya https kwa kutumia private key ya server - Kudecipher mawasiliano ya https kwa kutumia symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Mawasiliano ya ADB

Toa APK kutoka kwenye mawasiliano ya ADB ambamo APK ilitumwa:

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

- [1] [Wiki ya TLS ya Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Kusimbua na kuchanganua trafiki ya HTTP/3 katika Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Kusimbua trafiki ya kivinjari ya TLS kwa Wireshark – Njia rahisi!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Kufuatilia mitiririko ya itifaki](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Rejeleo la Kichujio cha Onyesho: Usalama wa Tabaka la Usafirishaji](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Rejeleo la Kichujio cha Onyesho: Itifaki ya Uhamishaji wa HyperText 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Rejeleo la Kichujio cha Onyesho: Toleo la 3 la Itifaki ya Uhamishaji wa Hypertext](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: Hello ya Mteja Iliyosimbwa kwa TLS](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Mwongozo wa TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
