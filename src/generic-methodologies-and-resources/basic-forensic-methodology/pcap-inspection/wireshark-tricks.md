# Sztuczki Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Doskonalenie umiejętności obsługi Wireshark

### Samouczki

Poniższe samouczki są świetne do nauki kilku przydatnych podstawowych sztuczek:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizowane informacje

**Informacje eksperta**

Klikając _**Analyze** --> **Expert Information**_, uzyskasz **przegląd** tego, co dzieje się w **analizowanych** pakietach:

![Samouczki - Analizowane informacje: Klikając Analyze -- Expert Information, uzyskasz przegląd tego, co dzieje się w analizowanych pakietach](<../../../images/image (256).png>)

**Rozwiązane adresy**

W sekcji _**Statistics --> Resolved Addresses**_ znajdziesz różne **informacje**, które zostały "**rozwiązane**" przez Wireshark, takie jak port/transport do protokołu, MAC do producenta itp. Warto wiedzieć, co bierze udział w komunikacji.

![Samouczki - Analizowane informacje: W sekcji Statistics -- Resolved Addresses znajdziesz różne informacje, które zostały „rozwiązane” przez Wireshark, takie jak port/transport do protokołu, MAC do...](<../../../images/image (893).png>)

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
W obecnym Wireshark używaj `tls.*` zamiast starych nazw filtrów `ssl.*`.<sup>[[1]](#references)</sup>\
Inne interesujące filtry:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Ruch HTTP i początkowy ruch HTTPS
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Ruch HTTP i początkowy ruch HTTPS + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Ruch HTTP i początkowy ruch HTTPS + TCP SYN + żądania DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivotowanie na SNI wysłanym w ClientHello, nawet gdy nie możesz odszyfrować payloadu
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Szybkie rozdzielanie klasycznych sesji HTTPS oraz sesji obsługujących HTTP/2 i HTTP/3
- `quic or http3`
- Znajdowanie współczesnego ruchu UDP/443, który zostanie pominięty, jeśli przejrzysz tylko rozmowy TCP

### Wyszukiwanie

Jeśli chcesz **wyszukać** **treść** wewnątrz **pakietów** sesji, naciśnij _CTRL+f_. Możesz dodać nowe warstwy do głównego paska informacji (No., Time, Source itd.), klikając prawym przyciskiem, a następnie wybierając edycję kolumny.

### Śledzenie strumieni multipleksowanych

Wireshark może bezpośrednio śledzić strumienie `TLS`, `HTTP/2` i `QUIC`. Jego okna dialogowe HTTP/2 i QUIC udostępniają selektory połączeń i podstrumieni, co pomaga odizolować multipleksowane strumienie współdzielące to samo połączenie niższego poziomu.<sup>[[4]](#references)</sup>

### Darmowe laboratoria pcap

**Ćwicz z darmowymi wyzwaniami na stronie:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identyfikowanie domen

Możesz dodać kolumnę pokazującą nagłówek Host HTTP:

![Darmowe laboratoria pcap - Identyfikowanie domen: Możesz dodać kolumnę pokazującą nagłówek Host HTTP](<../../../images/image (639).png>)

Oraz kolumnę dodającą nazwę Server z inicjującego połączenia HTTPS (**tls.handshake.type == 1**):

![Darmowe laboratoria pcap - Identyfikowanie domen: Oraz kolumnę dodającą nazwę Server z inicjującego połączenia HTTPS ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Jeśli przechwycony ruch jest w większości zaszyfrowany, dodanie tych pól jako kolumn znacznie przyspieszy wstępną analizę:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Pozwala to grupować sesje według nazwy hosta, ALPN (`http/1.1`, `h2`, `h3` itd.) oraz odcisku klienta, nawet gdy sam payload pozostaje zaszyfrowany. W przypadku odszyfrowanych przechwyceń HTTP/2 i HTTP/3 przydatne jest również dodanie `http2.header.value` lub `http3.headers.header.value` jako kolumn i pivotowanie na ścieżkach, authority oraz innych interesujących metadanych.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identyfikowanie lokalnych nazw hostów

### Z DHCP

W bieżącej wersji Wireshark zamiast `bootp` należy wyszukiwać `DHCP`

![Identyfikowanie lokalnych nazw hostów - Z DHCP: W bieżącej wersji Wireshark zamiast bootp należy wyszukiwać DHCP](<../../../images/image (1013).png>)

### Z NBNS

![Z DHCP - Z NBNS: W bieżącej wersji Wireshark zamiast bootp należy wyszukiwać DHCP](<../../../images/image (1003).png>)

## Odszyfrowywanie TLS

### Odszyfrowywanie ruchu HTTPS za pomocą klucza prywatnego serwera

_edytuj > preferencje > protokoły > tls >_

![Odszyfrowywanie TLS - Odszyfrowywanie ruchu HTTPS za pomocą klucza prywatnego serwera: Odszyfrowywanie ruchu HTTPS za pomocą klucza prywatnego serwera](<../../../images/image (1103).png>)

Naciśnij _Edytuj_ i dodaj wszystkie dane serwera oraz klucz prywatny (_IP, Port, Protokół, Plik klucza i hasło_)

Ta metoda działa tylko w ograniczonej liczbie przypadków. W przypadku bieżącego ruchu TLS 1.3 / ECDHE praktycznym rozwiązaniem jest zazwyczaj opisana poniżej metoda logowania kluczy sesji.<sup>[[1]](#references)</sup>

### Odszyfrowywanie ruchu HTTPS za pomocą symetrycznych kluczy sesji

Zarówno Firefox, jak i Chrome mogą rejestrować klucze sesji TLS, których można użyć w Wireshark do odszyfrowania ruchu TLS. Umożliwia to szczegółową analizę bezpiecznej komunikacji. Więcej informacji na temat wykonywania tego odszyfrowywania można znaleźć w przewodniku na stronie [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Jest to również standardowa metoda odszyfrowywania współczesnych przechwyceń TLS 1.3 i QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Aby to wykryć, wyszukaj w środowisku zmienną `SSLKEYLOGFILE`

Plik współdzielonych kluczy będzie wyglądał tak:

![Odszyfrowywanie ruchu HTTPS za pomocą klucza prywatnego serwera - Odszyfrowywanie ruchu HTTPS za pomocą symetrycznych kluczy sesji: Plik współdzielonych kluczy będzie wyglądał tak](<../../../images/image (820).png>)

Jeśli przechwycenie ma format `pcapng`, przed przeszukaniem systemu plików hosta sprawdź, czy nie zawiera już osadzonych sekretów deszyfrowania:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Aby zaimportować to do Wireshark, przejdź do \_edit > preferences > protocols > tls > i zaimportuj to w polu (Pre)-Master-Secret log filename:

![Deszyfrowanie ruchu https za pomocą klucza prywatnego serwera - Deszyfrowanie ruchu https za pomocą symetrycznych kluczy sesji: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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
## References

- [1] [Wiki TLS Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Deszyfrowanie i parsowanie ruchu HTTP/3 w Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Deszyfrowanie ruchu TLS przeglądarki za pomocą Wireshark – łatwy sposób!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Śledzenie strumieni protokołów](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Dokumentacja filtrów wyświetlania: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Dokumentacja filtrów wyświetlania: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Dokumentacja filtrów wyświetlania: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
