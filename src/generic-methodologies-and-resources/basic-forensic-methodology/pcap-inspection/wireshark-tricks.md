# Sztuczki Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Doskonalenie umiejętności korzystania z Wireshark

### Samouczki

Poniższe samouczki są świetne do nauki kilku przydatnych podstawowych sztuczek:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizowane informacje

**Informacje eksperckie**

Klikając _**Analyze** --> **Expert Information**_, uzyskasz **przegląd** tego, co dzieje się w **analizowanych** pakietach:

![Samouczki - Analizowane informacje: Klikając Analyze -- Expert Information, uzyskasz przegląd tego, co dzieje się w analizowanych pakietach](<../../../images/image (256).png>)

**Rozwiązane adresy**

W sekcji _**Statistics --> Resolved Addresses**_ znajdziesz różne **informacje**, które zostały "**rozwiązane**" przez Wireshark, takie jak port/transport do protokołu, MAC do producenta itp. Warto wiedzieć, co bierze udział w komunikacji.

![Samouczki - Analizowane informacje: W sekcji Statistics -- Resolved Addresses znajdziesz różne informacje, które zostały „rozwiązane” przez Wireshark, takie jak port/transport do protokołu, MAC do producenta itd.](<../../../images/image (893).png>)

**Hierarchia protokołów**

W sekcji _**Statistics --> Protocol Hierarchy**_ znajdziesz **protokoły** **zaangażowane** w komunikację oraz dane na ich temat.

![Samouczki - Analizowane informacje: W sekcji Statistics -- Protocol Hierarchy znajdziesz protokoły zaangażowane w komunikację oraz dane na ich temat](<../../../images/image (586).png>)

**Rozmowy**

W sekcji _**Statistics --> Conversations**_ znajdziesz **podsumowanie rozmów** w ramach komunikacji oraz dane na ich temat.

![Samouczki - Analizowane informacje: W sekcji Statistics -- Conversations znajdziesz podsumowanie rozmów w ramach komunikacji oraz dane na ich temat](<../../../images/image (453).png>)

**Punkty końcowe**

W sekcji _**Statistics --> Endpoints**_ znajdziesz **podsumowanie punktów końcowych** w ramach komunikacji oraz dane dotyczące każdego z nich.

![Samouczki - Analizowane informacje: W sekcji Statistics -- Endpoints znajdziesz podsumowanie punktów końcowych w ramach komunikacji oraz dane dotyczące każdego z nich](<../../../images/image (896).png>)

**Informacje DNS**

W sekcji _**Statistics --> DNS**_ znajdziesz statystyki dotyczące przechwyconych żądań DNS.

![Samouczki - Analizowane informacje: W sekcji Statistics -- DNS znajdziesz statystyki dotyczące przechwyconych żądań DNS](<../../../images/image (1063).png>)

**Wykres I/O**

W sekcji _**Statistics --> I/O Graph**_ znajdziesz **wykres komunikacji.**

![Samouczki - Analizowane informacje: W sekcji Statistics -- I/O Graph znajdziesz wykres komunikacji](<../../../images/image (992).png>)

### Filtry

Tutaj znajdziesz filtry Wireshark zależne od protokołu: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
W obecnej wersji Wireshark używaj `tls.*` zamiast starych nazw filtrów `ssl.*`.\
Inne interesujące filtry:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Ruch HTTP i początkowy ruch HTTPS
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Ruch HTTP i początkowy ruch HTTPS + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Ruch HTTP i początkowy ruch HTTPS + TCP SYN + żądania DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Wykorzystaj SNI wysłane w ClientHello jako punkt odniesienia, nawet jeśli nie możesz odszyfrować payloadu
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Szybko rozdziel klasyczne sesje HTTPS oraz sesje obsługujące HTTP/2 i HTTP/3
- `quic or http3`
- Znajdź nowoczesny ruch UDP/443, który zostanie pominięty, jeśli przeanalizujesz tylko rozmowy TCP

### Wyszukiwanie

Jeśli chcesz **wyszukać** **treść** wewnątrz **pakietów** sesji, naciśnij _CTRL+f_. Możesz dodać nowe kolumny do głównego paska informacji (No., Time, Source itd.), klikając prawym przyciskiem myszy, a następnie wybierając opcję edycji kolumny.

### Śledzenie strumieni multipleksowanych

Nowsze wersje Wireshark mogą bezpośrednio śledzić strumienie `TLS`, `HTTP/2` i `QUIC`. W przypadku zaszumionych przechwyceń jest to zwykle szybsze niż korzystanie wyłącznie z opcji `Follow TCP Stream`, szczególnie gdy wiele żądań współdzieli to samo połączenie.

### Bezpłatne laboratoria pcap

**Ćwicz, korzystając z bezpłatnych wyzwań:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identyfikowanie domen

Możesz dodać kolumnę wyświetlającą nagłówek HTTP Host:

![Bezpłatne laboratoria pcap - Identyfikowanie domen: Możesz dodać kolumnę wyświetlającą nagłówek HTTP Host](<../../../images/image (639).png>)

Oraz kolumnę dodającą nazwę serwera z inicjującego połączenia HTTPS (**tls.handshake.type == 1**):

![Bezpłatne laboratoria pcap - Identyfikowanie domen: Oraz kolumnę dodającą nazwę serwera z inicjującego połączenia HTTPS ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Jeśli przechwycony ruch jest w większości zaszyfrowany, dodanie tych pól jako kolumn znacznie przyspieszy wstępną analizę:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Pozwala to grupować sesje według nazwy hosta, ALPN (`http/1.1`, `h2`, `h3` itd.) oraz odcisku klienta, nawet gdy sam payload pozostaje zaszyfrowany. W przypadku odszyfrowanych przechwyceń HTTP/2 i HTTP/3 przydatne jest również dodanie `http2.header.value` lub `http3.headers.header.value` jako kolumn i używanie ich jako punktu odniesienia dla ścieżek, authority oraz innych interesujących metadanych.<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identyfikowanie lokalnych nazw hostów

### Z DHCP

W aktualnym Wireshark zamiast `bootp` należy wyszukać `DHCP`

![Identyfikowanie lokalnych nazw hostów - Z DHCP: W aktualnym Wireshark zamiast bootp należy wyszukać DHCP](<../../../images/image (1013).png>)

### Z NBNS

![Z DHCP - Z NBNS: W aktualnym Wireshark zamiast bootp należy wyszukać DHCP](<../../../images/image (1003).png>)

## Deszyfrowanie TLS

### Deszyfrowanie ruchu https za pomocą prywatnego klucza serwera

_edytuj > preferencje > protokoły > tls >_

![Deszyfrowanie TLS - Deszyfrowanie ruchu https za pomocą prywatnego klucza serwera: Deszyfrowanie ruchu https za pomocą prywatnego klucza serwera](<../../../images/image (1103).png>)

Naciśnij _Edytuj_ i dodaj wszystkie dane serwera oraz klucz prywatny (_IP, port, protokół, plik klucza i hasło_)

Ta metoda działa tylko w ograniczonej liczbie przypadków. W przypadku aktualnego ruchu TLS 1.3 / ECDHE praktyczną opcją jest zwykle metoda logowania kluczy sesji opisana poniżej.<sup>[[1]](#references)</sup>

### Deszyfrowanie ruchu https za pomocą symetrycznych kluczy sesji

Zarówno Firefox, jak i Chrome umożliwiają rejestrowanie kluczy sesji TLS, których można używać z Wireshark do deszyfrowania ruchu TLS. Umożliwia to szczegółową analizę bezpiecznej komunikacji. Więcej informacji o przeprowadzaniu tego deszyfrowania można znaleźć w przewodniku na stronie [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Jest to również standardowa metoda deszyfrowania współczesnych przechwyceń TLS 1.3 i QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Aby to wykryć, wyszukaj w środowisku zmienną `SSLKEYLOGFILE`

Plik współdzielonych kluczy będzie wyglądał tak:

![Deszyfrowanie ruchu https za pomocą prywatnego klucza serwera - Deszyfrowanie ruchu https za pomocą symetrycznych kluczy sesji: Plik współdzielonych kluczy będzie wyglądał tak](<../../../images/image (820).png>)

Jeśli przechwycenie ma format `pcapng`, sprawdź, czy nie zawiera już osadzonych sekretów deszyfrowania, zanim zaczniesz przeszukiwać system plików hosta:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Aby zaimportować to w Wireshark, przejdź do \_edit > preferences > protocols > tls > i zaimportuj to w polu (Pre)-Master-Secret log filename:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Komunikacja ADB

Wyodrębnij APK z komunikacji ADB, w której APK został przesłany:
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
## Referencje

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Deszyfrowanie i analizowanie ruchu HTTP/3 w Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Deszyfrowanie ruchu przeglądarki TLS za pomocą Wireshark – łatwy sposób!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
