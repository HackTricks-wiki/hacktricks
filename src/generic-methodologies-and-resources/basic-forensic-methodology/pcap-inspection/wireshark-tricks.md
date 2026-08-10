# Wireshark trikovi

## Poboljšajte svoje Wireshark veštine

### Tutorijali

Sledeći tutorijali su odlični za učenje zanimljivih osnovnih trikova:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizirane informacije

**Stručne informacije**

Klikom na _**Analyze** --> **Expert Information**_ dobićete **pregled** onoga što se dešava u **analiziranim** paketima:

![Tutorijali - Analizirane informacije: Klikom na Analyze -- Expert Information dobićete pregled onoga što se dešava u analiziranim paketima](<../../../images/image (256).png>)

**Razrešene adrese**

U odeljku _**Statistics --> Resolved Addresses**_ možete pronaći nekoliko **informacija** koje je Wireshark "**razrešio**", kao što su port/transport do protokola, MAC adresa do proizvođača itd. Zanimljivo je znati šta je obuhvaćeno komunikacijom.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Resolved Addresses možete pronaći nekoliko informacija koje je Wireshark " razrešio ", kao što su port/transport do protokola, MAC adresa do...](<../../../images/image (893).png>)

**Hijerarhija protokola**

U odeljku _**Statistics --> Protocol Hierarchy**_ možete pronaći **protokole** **uključene** u komunikaciju i podatke o njima.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Protocol Hierarchy možete pronaći protokole uključene u komunikaciju i podatke o njima](<../../../images/image (586).png>)

**Konverzacije**

U odeljku _**Statistics --> Conversations**_ možete pronaći **rezime konverzacija** u komunikaciji i podatke o njima.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Conversations možete pronaći rezime konverzacija u komunikaciji i podatke o njima](<../../../images/image (453).png>)

**Krajnje tačke**

U odeljku _**Statistics --> Endpoints**_ možete pronaći **rezime krajnjih tačaka** u komunikaciji i podatke o svakoj od njih.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- Endpoints možete pronaći rezime krajnjih tačaka u komunikaciji i podatke o svakoj od njih](<../../../images/image (896).png>)

**DNS informacije**

U odeljku _**Statistics --> DNS**_ možete pronaći statistiku o uhvaćenom DNS zahtevu.

![Tutorijali - Analizirane informacije: U odeljku Statistics -- DNS možete pronaći statistiku o uhvaćenom DNS zahtevu](<../../../images/image (1063).png>)

**I/O grafikon**

U odeljku _**Statistics --> I/O Graph**_ možete pronaći **grafikon komunikacije.**

![Tutorijali - Analizirane informacije: U odeljku Statistics -- I/O Graph možete pronaći grafikon komunikacije](<../../../images/image (992).png>)

### Filteri

Ovde možete pronaći Wireshark filtere u zavisnosti od protokola: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
U aktuelnom Wireshark-u koristite `tls.*` umesto starih naziva filtera `ssl.*`.<sup>[[1]](#references)</sup>\
Ostali zanimljivi filteri:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP i početni HTTPS saobraćaj
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP i početni HTTPS saobraćaj + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP i početni HTTPS saobraćaj + TCP SYN + DNS zahtevi
- `tls.handshake.extensions_server_name contains "example.com"`
- Analizirajte SNI poslat u ClientHello poruci čak i kada ne možete da dešifrujete payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Brzo razdvojite klasične HTTPS sesije i sesije koje podržavaju HTTP/2 i HTTP/3
- `quic or http3`
- Pronađite savremeni UDP/443 saobraćaj koji će biti propušten ako pregledate samo TCP konverzacije

### Pretraga

Ako želite da **pretražite** **sadržaj** unutar **paketa** sesija, pritisnite _CTRL+f_. Možete dodati nove slojeve u glavnu informacionu traku (No., Time, Source itd.) tako što ćete pritisnuti desno dugme, a zatim izabrati uređivanje kolone.

### Praćenje multipleksiranih tokova

Wireshark može direktno da prati `TLS`, `HTTP/2` i `QUIC` tokove. Njegovi HTTP/2 i QUIC dijalozi prikazuju birače konekcija i podtokova, što pomaže u izolovanju multipleksiranih tokova koji dele istu konekciju nižeg nivoa.<sup>[[4]](#references)</sup>

### Besplatne pcap laboratorije

**Vežbajte uz besplatne izazove na:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifikovanje domena

Možete dodati kolonu koja prikazuje HTTP Host zaglavlje:

![Besplatne pcap laboratorije - Identifikovanje domena: Možete dodati kolonu koja prikazuje HTTP Host zaglavlje](<../../../images/image (639).png>)

I kolonu koja dodaje ime servera iz početne HTTPS konekcije (**tls.handshake.type == 1**):

![Besplatne pcap laboratorije - Identifikovanje domena: I kolonu koja dodaje ime servera iz početne HTTPS konekcije ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Ako je capture uglavnom šifrovan, dodavanje ovih polja kao kolona znatno će ubrzati triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Ovo vam omogućava grupisanje sesija prema imenu hosta, ALPN-u (`http/1.1`, `h2`, `h3` itd.) i fingerprint-u klijenta, čak i kada sam payload ostane šifrovan. Za dešifrovane HTTP/2 i HTTP/3 capture-ove takođe je korisno dodati `http2.header.value` ili `http3.headers.header.value` kao kolone i analizirati putanje, authorities i druge zanimljive metapodatke.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifikovanje lokalnih imena hostova

### Iz DHCP-a

U aktuelnom Wireshark-u, umesto `bootp`, potrebno je da pretražujete `DHCP`

![Identifikovanje lokalnih imena hostova - Iz DHCP-a: U aktuelnom Wireshark-u, umesto bootp, potrebno je da pretražujete DHCP](<../../../images/image (1013).png>)

### Iz NBNS-a

![Iz DHCP-a - Iz NBNS-a: U aktuelnom Wireshark-u, umesto bootp, potrebno je da pretražujete DHCP](<../../../images/image (1003).png>)

## Dešifrovanje TLS-a

### Dešifrovanje https saobraćaja privatnim ključem servera

_izaberite Edit > preferences > protocols > tls >_

![Dešifrovanje TLS-a - Dešifrovanje https saobraćaja privatnim ključem servera: Dešifrovanje https saobraćaja privatnim ključem servera](<../../../images/image (1103).png>)

Pritisnite _Edit_ i dodajte sve podatke o serveru i privatnom ključu (_IP, Port, Protocol, Key file and password_)

Ovaj metod funkcioniše samo u ograničenom broju slučajeva. Za aktuelni TLS 1.3 / ECDHE saobraćaj, metod evidentiranja ključeva sesije u nastavku obično je praktična opcija.<sup>[[1]](#references)</sup>

### Dešifrovanje https saobraćaja simetričnim ključevima sesije

I Firefox i Chrome mogu da evidentiraju ključeve TLS sesije, koji se mogu koristiti sa Wireshark-om za dešifrovanje TLS saobraćaja. Ovo omogućava detaljnu analizu bezbednih komunikacija. Više detalja o tome kako izvršiti ovo dešifrovanje možete pronaći u vodiču na adresi [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Ovo je takođe uobičajen način za dešifrovanje modernih TLS 1.3 i QUIC/HTTP/3 snimaka.<sup>[[2]](#references)</sup>

Da biste ovo otkrili, pretražite okruženje za promenljivu `SSLKEYLOGFILE`

Datoteka deljenih ključeva izgleda ovako:

![Dešifrovanje https saobraćaja privatnim ključem servera - Dešifrovanje https saobraćaja simetričnim ključevima sesije: Datoteka deljenih ključeva izgleda ovako](<../../../images/image (820).png>)

Ako je snimak u formatu `pcapng`, proverite da li već sadrži ugrađene tajne za dešifrovanje pre nego što počnete da pretražujete datotečni sistem hosta:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Da biste ovo uvezli u wireshark, idite na \_edit > preferences > protocols > tls > i uvezite ga u polje (Pre)-Master-Secret log filename:

![Dešifrovanje https saobraćaja pomoću privatnog ključa servera - Dešifrovanje https saobraćaja pomoću simetričnih ključeva sesije: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Dešifrovanje i parsiranje HTTP/3 saobraćaja u Wireshark-u](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Dešifrovanje TLS saobraćaja pregledača pomoću Wireshark-a – jednostavan način!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Praćenje tokova protokola](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Referenca filtera prikaza: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Referenca filtera prikaza: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Referenca filtera prikaza: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
