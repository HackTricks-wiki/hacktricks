# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Poboljšaj svoje Wireshark veštine

### Tutorijali

Sledeći tutorijali su sjajni za učenje nekih korisnih osnovnih trikova:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizirane informacije

**Ekspertne informacije**

Klikom na _**Analyze** --> **Expert Information**_ dobićeš **pregled** onoga što se dešava u **analiziranim** paketima:

![](<../../../images/image (256).png>)

**Razrešene adrese**

Pod _**Statistics --> Resolved Addresses**_ možeš pronaći nekoliko **informacija** koje je wireshark "**razrešio**", kao što su port/transport u protokol, MAC u proizvođača, itd. Zanimljivo je znati šta je uključeno u komunikaciju.

![](<../../../images/image (893).png>)

**Hijerarhija protokola**

Pod _**Statistics --> Protocol Hierarchy**_ možeš pronaći **protokole** koji su **uključeni** u komunikaciju i podatke o njima.

![](<../../../images/image (586).png>)

**Konverzacije**

Pod _**Statistics --> Conversations**_ možeš pronaći **sažetak konverzacija** u komunikaciji i podatke o njima.

![](<../../../images/image (453).png>)

**Krajnje tačke**

Pod _**Statistics --> Endpoints**_ možeš pronaći **sažetak krajnjih tačaka** u komunikaciji i podatke o svakoj od njih.

![](<../../../images/image (896).png>)

**DNS info**

Pod _**Statistics --> DNS**_ možeš pronaći statistiku o uhvaćenim DNS zahtevima.

![](<../../../images/image (1063).png>)

**I/O Graph**

Pod _**Statistics --> I/O Graph**_ možeš pronaći **graf komunikacije.**

![](<../../../images/image (992).png>)

### Filteri

Ovde možeš pronaći wireshark filtere u zavisnosti od protokola: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
U trenutnom Wireshark-u koristi `tls.*` umesto starih naziva `ssl.*` filtera.\
Drugi zanimljivi filteri:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP i početni HTTPS saobraćaj
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP i početni HTTPS saobraćaj + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP i početni HTTPS saobraćaj + TCP SYN + DNS zahtevi
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot na SNI poslat u ClientHello čak i kada ne možeš da dekriptuješ payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Brzo odvoji klasične HTTPS, HTTP/2 i HTTP/3 sesije
- `quic or http3`
- Pronađi moderni UDP/443 saobraćaj koji će biti propušten ako pregledaš samo TCP konverzacije

### Pretraga

Ako želiš da **pretražiš** **sadržaj** unutar **paketa** sesija, pritisni _CTRL+f_. Možeš dodati nove kolone u glavnu informacionu traku (No., Time, Source, itd.) tako što ćeš pritisnuti desni taster i zatim edit column.

### Praćenje multiplexed stream-ova

Nedavne verzije Wireshark-a mogu direktno da prate `TLS`, `HTTP/2` i `QUIC` stream-ove. Na bučnim capture-ima ovo je obično brže nego koristiti samo `Follow TCP Stream`, posebno kada više zahteva deli istu konekciju.

### Besplatni pcap labovi

**Vežbaj sa besplatnim izazovima na:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifikovanje domena

Možeš dodati kolonu koja prikazuje Host HTTP header:

![](<../../../images/image (639).png>)

I kolonu koja dodaje Server name iz inicijalne HTTPS konekcije (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Ako je capture uglavnom enkriptovan, dodavanje ovih polja kao kolona će mnogo ubrzati triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Ovo ti omogućava da grupišeš sesije po hostname-u, ALPN-u (`http/1.1`, `h2`, `h3`, itd.) i fingerprint-u klijenta čak i kada sam payload ostane enkriptovan. Za dekriptovane HTTP/2 i HTTP/3 capture-e, korisno je i dodati `http2.header.value` ili `http3.headers.header.value` kao kolone i pivotovati na paths, authorities i druge zanimljive metapodatke.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifying local hostnames

### From DHCP

U trenutnom Wireshark-u umesto `bootp` treba da tražiš `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Pritisni _Edit_ i dodaj sve podatke servera i privatnog ključa (_IP, Port, Protocol, Key file and password_)

Ovaj metod radi samo u ograničenom broju slučajeva. Za trenutni TLS 1.3 / ECDHE saobraćaj, metoda sa session key log-om ispod je obično praktična opcija.

### Decrypting https traffic with symmetric session keys

I Firefox i Chrome imaju mogućnost da beleže TLS session keys, koji se mogu koristiti sa Wireshark-om za dekripciju TLS saobraćaja. Ovo omogućava detaljnu analizu secure communications. Više detalja o tome kako da uradiš ovu dekripciju možeš pronaći u vodiču na [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Ovo je takođe normalan put za dekripciju modernih TLS 1.3 i QUIC/HTTP/3 capture-ova.

Da bi otkrio ovo, pretraži okruženje za varijablu `SSLKEYLOGFILE`

Fajl sa shared keys će izgledati ovako:

![](<../../../images/image (820).png>)

Ako je capture `pcapng`, proveri da li već sadrži ugrađene decryption secrets pre nego što pretražuješ host filesystem:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Za importovanje ovoga u wireshark idite na \_edit > preferences > protocols > tls > i importujte ga u (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB communication

Ekstrahujte APK iz ADB communication gde je APK bio poslat:
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
## Reference

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
