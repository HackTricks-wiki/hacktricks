# Wireshark trikovi

{{#include ../../../banners/hacktricks-training.md}}

## Unapredite svoje veštine rada u Wiresharku

### Tutorijali

Sledeći tutorijali su odlični za učenje zanimljivih osnovnih trikova:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizirane informacije

**Informacije za stručnjake**

Klikom na _**Analyze** --> **Expert Information**_ dobićete **pregled** onoga što se dešava u **analiziranim** paketima:

![Tutorijali - Analizirane informacije: Klikom na Analyze -- Expert Information dobićete pregled onoga što se dešava u analiziranim paketima](<../../../images/image (256).png>)

**Razrešene adrese**

U odeljku _**Statistics --> Resolved Addresses**_ možete pronaći razne informacije koje je Wireshark „**razrešio**“, kao što su port/transport do protokola, MAC adresa do proizvođača itd. Korisno je znati šta učestvuje u komunikaciji.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Resolved Addresses možete pronaći razne informacije koje je Wireshark „razrešio“, kao što su port/transport do protokola, MAC adresa do...](<../../../images/image (893).png>)

**Hijerarhija protokola**

U odeljku _**Statistics --> Protocol Hierarchy**_ možete pronaći **protokole** koji **učestvuju** u komunikaciji i podatke o njima.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Protocol Hierarchy možete pronaći protokole koji učestvuju u komunikaciji i podatke o njima](<../../../images/image (586).png>)

**Razgovori**

U odeljku _**Statistics --> Conversations**_ možete pronaći **pregled razgovora** u komunikaciji i podatke o njima.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Conversations možete pronaći pregled razgovora u komunikaciji i podatke o njima](<../../../images/image (453).png>)

**Krajnje tačke**

U odeljku _**Statistics --> Endpoints**_ možete pronaći **pregled krajnjih tačaka** u komunikaciji i podatke o svakoj od njih.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Endpoints možete pronaći pregled krajnjih tačaka u komunikaciji i podatke o svakoj od njih](<../../../images/image (896).png>)

**DNS informacije**

U odeljku _**Statistics --> DNS**_ možete pronaći statistiku o zabeleženim DNS zahtevima.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- DNS možete pronaći statistiku o zabeleženim DNS zahtevima](<../../../images/image (1063).png>)

**I/O grafikon**

U odeljku _**Statistics --> I/O Graph**_ možete pronaći **grafikon komunikacije.**

![Tutorijali - Analizirane informacije: U odeljku Statistics -- I/O Graph možete pronaći grafikon komunikacije](<../../../images/image (992).png>)

### Filteri

Ovde možete pronaći Wireshark filtere u zavisnosti od protokola: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
U aktuelnoj verziji Wiresharka koristite `tls.*` umesto starih naziva filtera `ssl.*`.<sup>[[1]](#references)</sup>\
Još neki korisni filteri:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP i početni HTTPS saobraćaj
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP i početni HTTPS saobraćaj + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP i početni HTTPS saobraćaj + TCP SYN + DNS zahtevi
- `tls.handshake.extensions_server_name contains "example.com"`
  - Pratite SNI poslat u ClientHello paketu čak i kada ne možete da dešifrujete sadržaj
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Brzo razdvojite klasične HTTPS sesije od sesija koje podržavaju HTTP/2 i HTTP/3
- `quic or http3`
  - Pronađite savremeni UDP/443 saobraćaj koji ćete propustiti ako pregledate samo TCP razgovore

### Pretraga

Ako želite da **pretražite** **sadržaj** unutar **paketa** sesija, pritisnite _CTRL+f_. Možete dodati nove kolone u glavnu traku sa informacijama (No., Time, Source itd.) tako što ćete kliknuti desnim tasterom miša, a zatim izabrati uređivanje kolone.

### Praćenje multipleksiranih tokova

Wireshark može direktno da prati tokove `TLS`, `HTTP/2` i `QUIC`. Njegovi dijalozi za HTTP/2 i QUIC prikazuju birače konekcija i podtokova, što olakšava izdvajanje multipleksiranih tokova koji dele istu vezu nižeg nivoa.<sup>[[4]](#references)</sup>

Kada su ključevi sesije dostupni, prvo utvrdite ID toka zahteva, a zatim pratite taj podtok umesto celog TCP ili UDP razgovora. Primer `0,1` bira HTTP/2 tok sa ID-jem 1 na TCP toku 0; za QUIC koristite `follow,quic,utf-8,<connection-number>,<stream-id>`. Praćenje samo petorke može da pomeša nezavisne zahteve ili da propusti QUIC konekciju nakon migracije.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Besplatne pcap laboratorije

**Vežbajte uz besplatne izazove na:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifikovanje domena

Možete dodati kolonu koja prikazuje HTTP zaglavlje Host:

![Besplatne pcap laboratorije - Identifikovanje domena: Možete dodati kolonu koja prikazuje HTTP zaglavlje Host](<../../../images/image (639).png>)

I kolonu koja prikazuje ime servera iz započete HTTPS konekcije (**tls.handshake.type == 1**):

![Besplatne pcap laboratorije - Identifikovanje domena: I kolonu koja prikazuje ime servera iz započete HTTPS konekcije ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Ako je saobraćaj u snimku uglavnom šifrovan, dodavanje ovih polja kao kolona može znatno ubrzati trijažu:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Tako možete grupisati sesije prema imenu hosta, ALPN-u (`http/1.1`, `h2`, `h3` itd.) i fingerprintu klijenta, čak i kada je sam payload i dalje šifrovan. Za dešifrovane HTTP/2 i HTTP/3 snimke, korisno je i dodati `http2.header.value` ili `http3.headers.header.value` kao kolone i pretraživati putanje, autoritete i druge zanimljive metapodatke.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: ne mešajte spoljašnji SNI sa izvornim domenom

Encrypted ClientHello (ECH) može da postavi javni naziv za prikrivanje u vidljivi spoljašnji SNI, dok se unutrašnji naziv šifruje. Zato inventar domena zasnovan samo na SNI-ju može da pripiše ECH saobraćaj pogrešnom izvornom domenu. Sama ECH ekstenzija nije dokaz da je ECH uspeo: klijenti mogu da šalju GREASE ECH ekstenziju. U Wireshark-u 4.2+ pronađite spoljašnje ECH ponude pomoću sledećeg filtera i tretirajte prikazani SNI kao mogući naziv za prikrivanje, a ne kao traženi sajt.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Ako imate odgovarajuće ključeve klijentske sesije, pregledajte dešifrovani HTTP authority/Host umesto da zaključujete o poreklu na osnovu spoljnog SNI-ja. Bez ključeva proverite druge zabeležene dokaze o poreklu, kao što je plaintext DNS, ali nemojte poistovećivati spoljašnji SNI sa skrivenim imenom.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identifikovanje lokalnih naziva hostova

### Iz DHCP-a

U aktuelnom Wireshark-u, umesto `bootp`, treba da tražite `DHCP`

![Identifikovanje lokalnih naziva hostova - Iz DHCP-a: U aktuelnom Wireshark-u, umesto bootp, treba da tražite DHCP](<../../../images/image (1013).png>)

### Iz NBNS-a

![Iz DHCP-a - Iz NBNS-a: U aktuelnom Wireshark-u, umesto bootp, treba da tražite DHCP](<../../../images/image (1003).png>)

## Dešifrovanje TLS-a

Dešifrovanje Wi-Fi link-layer saobraćaja odvojeno je od dešifrovanja TLS sesije; pogledajte [analizu Wi-Fi PCAP-a](wifi-pcap-analysis.md) za preduslove u vezi sa ključevima i handshake-om.

### Dešifrovanje HTTPS saobraćaja pomoću privatnog ključa servera

_uredi > podešavanja > protokoli > tls >_

![Dešifrovanje TLS-a - Dešifrovanje HTTPS saobraćaja pomoću privatnog ključa servera: Dešifrovanje HTTPS saobraćaja pomoću privatnog ključa servera](<../../../images/image (1103).png>)

Pritisnite _Uredi_ i dodajte sve podatke servera i privatnog ključa (_IP, port, protokol, datoteka ključa i lozinka_)

Ovaj metod funkcioniše samo u ograničenom broju slučajeva. Za aktuelni TLS 1.3 / ECDHE saobraćaj, metod sa evidencijom ključeva sesije u nastavku obično je praktičnija opcija.<sup>[[1]](#references)</sup>

### Dešifrovanje HTTPS saobraćaja pomoću simetričnih ključeva sesije

I Firefox i Chrome mogu da evidentiraju ključeve TLS sesije, koji se mogu koristiti u Wireshark-u za dešifrovanje TLS saobraćaja. To omogućava detaljnu analizu bezbedne komunikacije. Više detalja o ovom dešifrovanju možete pronaći u vodiču na sajtu [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Ovo je ujedno i uobičajen način dešifrovanja savremenih TLS 1.3 i QUIC/HTTP/3 snimaka saobraćaja.<sup>[[2]](#references)</sup>

Da biste ovo otkrili, potražite promenljivu `SSLKEYLOGFILE` u okruženju.

Datoteka deljenih ključeva izgleda ovako:

![Dešifrovanje HTTPS saobraćaja pomoću privatnog ključa servera - Dešifrovanje HTTPS saobraćaja pomoću simetričnih ključeva sesije: Datoteka deljenih ključeva izgleda ovako](<../../../images/image (820).png>)

Ako je snimak u formatu `pcapng`, proverite da li već sadrži ugrađene tajne za dešifrovanje pre nego što pretražite hostov sistem datoteka:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Da biste ovo uvezli u Wireshark, idite na \_Edit > Preferences > Protocols > TLS > i uvezite ga u polje (Pre)-Master-Secret log filename:

![Dešifrovanje HTTPS saobraćaja pomoću privatnog ključa servera - Dešifrovanje HTTPS saobraćaja pomoću simetričnih ključeva sesije: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB komunikacija

Izdvojite APK iz ADB komunikacije u kojoj je APK poslat:

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

- [1] [Wireshark TLS viki](https://wiki.wireshark.org/TLS)
- [2] [Dekripcija i parsiranje HTTP/3 saobraćaja u Wireshark-u](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Dekripcija TLS saobraćaja pregledača pomoću Wireshark-a – jednostavan način!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Praćenje tokova protokola](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Referenca filtera prikaza: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Referenca filtera prikaza: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Referenca filtera prikaza: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS šifrovani Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark priručnik](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
