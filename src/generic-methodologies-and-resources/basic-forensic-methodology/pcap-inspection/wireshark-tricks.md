# Sztuczki w Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Rozwijaj umiejętności obsługi Wireshark

### Samouczki

Poniższe samouczki świetnie pomagają poznać przydatne podstawowe sztuczki:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizowane informacje

**Informacje eksperckie**

Klikając _**Analyze** --> **Expert Information**_, uzyskasz **przegląd** tego, co dzieje się w **analizowanych** pakietach:

![Samouczki — Analizowane informacje: Kliknięcie Analyze -- Expert Information zapewnia przegląd tego, co dzieje się w analizowanych pakietach](<../../../images/image (256).png>)

**Rozpoznane adresy**

W _**Statistics --> Resolved Addresses**_ znajdziesz różne **informacje** „**rozpoznane**” przez Wireshark, takie jak port/protokół transportowy, adres MAC/producent itp. Pozwala to ustalić, co bierze udział w komunikacji.

![Samouczki — Analizowane informacje: W Statistics -- Resolved Addresses znajdziesz różne informacje „rozpoznane” przez Wireshark, takie jak port/protokół transportowy, adres MAC/producent itp.](<../../../images/image (893).png>)

**Hierarchia protokołów**

W _**Statistics --> Protocol Hierarchy**_ znajdziesz **protokoły** **biorące udział** w komunikacji oraz dotyczące ich dane.

![Samouczki — Analizowane informacje: W Statistics -- Protocol Hierarchy znajdziesz protokoły biorące udział w komunikacji oraz dotyczące ich dane](<../../../images/image (586).png>)

**Konwersacje**

W _**Statistics --> Conversations**_ znajdziesz **podsumowanie konwersacji** w komunikacji oraz dotyczące ich dane.

![Samouczki — Analizowane informacje: W Statistics -- Conversations znajdziesz podsumowanie konwersacji w komunikacji oraz dotyczące ich dane](<../../../images/image (453).png>)

**Punkty końcowe**

W _**Statistics --> Endpoints**_ znajdziesz **podsumowanie punktów końcowych** w komunikacji oraz dotyczące każdego z nich dane.

![Samouczki — Analizowane informacje: W Statistics -- Endpoints znajdziesz podsumowanie punktów końcowych w komunikacji oraz dotyczące każdego z nich dane](<../../../images/image (896).png>)

**Informacje DNS**

W _**Statistics --> DNS**_ znajdziesz statystyki dotyczące przechwyconych żądań DNS.

![Samouczki — Analizowane informacje: W Statistics -- DNS znajdziesz statystyki dotyczące przechwyconych żądań DNS](<../../../images/image (1063).png>)

**Wykres I/O**

W _**Statistics --> I/O Graph**_ znajdziesz **wykres komunikacji.**

![Samouczki — Analizowane informacje: W Statistics -- I/O Graph znajdziesz wykres komunikacji](<../../../images/image (992).png>)

### Filtry

Filtry Wireshark dla poszczególnych protokołów znajdziesz tutaj: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
W aktualnych wersjach Wireshark używaj `tls.*` zamiast starszych nazw filtrów `ssl.*`.<sup>[[1]](#references)</sup>\
Inne przydatne filtry:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - Ruch HTTP i początkowy ruch HTTPS
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - Ruch HTTP i początkowy ruch HTTPS + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - Ruch HTTP i początkowy ruch HTTPS + TCP SYN + żądania DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Wyszukiwanie na podstawie SNI wysłanego w ClientHello, nawet gdy nie możesz odszyfrować zawartości
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Szybkie rozdzielenie sesji klasycznego HTTPS oraz sesji obsługujących HTTP/2 i HTTP/3
- `quic or http3`
  - Znajdowanie nowoczesnego ruchu UDP/443, który można przeoczyć, analizując wyłącznie konwersacje TCP

### Wyszukiwanie

Aby **wyszukać** **treść** w **pakietach** sesji, naciśnij _CTRL+f_. Możesz dodać nowe kolumny do głównego paska informacji (No., Time, Source itp.), klikając prawym przyciskiem myszy, a następnie wybierając edycję kolumny.

### Śledzenie strumieni multipleksowanych

Wireshark umożliwia bezpośrednie śledzenie strumieni `TLS`, `HTTP/2` i `QUIC`. Okna dialogowe HTTP/2 i QUIC udostępniają selektory połączeń i podstrumieni, co ułatwia wyodrębnianie multipleksowanych strumieni współdzielących to samo połączenie niższej warstwy.<sup>[[4]](#references)</sup>

Gdy masz dostęp do kluczy sesji, najpierw zidentyfikuj identyfikator strumienia żądania, a następnie śledź ten podstrumień zamiast całej konwersacji TCP lub UDP. Przykład `0,1` wybiera strumień HTTP/2 o identyfikatorze 1 w strumieniu TCP 0; w przypadku QUIC użyj `follow,quic,utf-8,<connection-number>,<stream-id>`. Śledzenie wyłącznie pięcioelementowego identyfikatora przepływu może połączyć niezależne żądania albo pominąć połączenie QUIC po migracji.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Darmowe laboratoria pcap

**Ćwicz, korzystając z darmowych wyzwań:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identyfikowanie domen

Możesz dodać kolumnę wyświetlającą nagłówek HTTP Host:

![Darmowe laboratoria pcap - Identyfikowanie domen: Możesz dodać kolumnę wyświetlającą nagłówek HTTP Host](<../../../images/image (639).png>)

Oraz kolumnę wyświetlającą nazwę serwera z inicjującego połączenia HTTPS (**tls.handshake.type == 1**):

![Darmowe laboratoria pcap - Identyfikowanie domen: Możesz dodać kolumnę wyświetlającą nazwę serwera z inicjującego połączenia HTTPS ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Jeśli przechwycony ruch jest w większości zaszyfrowany, dodanie tych pól jako kolumn znacznie przyspieszy wstępną analizę:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Dzięki temu możesz grupować sesje według nazwy hosta, ALPN (`http/1.1`, `h2`, `h3` itd.) i odcisku klienta, nawet gdy sam payload pozostaje zaszyfrowany. W przypadku odszyfrowanych przechwyconych danych HTTP/2 i HTTP/3 warto również dodać `http2.header.value` lub `http3.headers.header.value` jako kolumny i analizować ścieżki, authority oraz inne interesujące metadane.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: nie pomyl zewnętrznego SNI z hostem źródłowym

Encrypted ClientHello (ECH) może umieszczać publiczną nazwę maskującą w widocznym zewnętrznym SNI, jednocześnie szyfrując nazwę wewnętrzną. Dlatego wykaz domen oparty wyłącznie na SNI może błędnie przypisać ruch ECH do hosta źródłowego. Samo rozszerzenie ECH nie dowodzi, że ECH zadziałało: klienci mogą wysyłać rozszerzenie GREASE ECH. W Wireshark 4.2+ znajdź oferty zewnętrznego ECH za pomocą poniższego filtra i traktuj zgłoszony SNI jako potencjalną nazwę maskującą, a nie żądaną witrynę.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Jeśli masz pasujące klucze sesji klienta, sprawdź odszyfrowane pole authority/Host protokołu HTTP, zamiast wnioskować o originie na podstawie zewnętrznego SNI. Jeśli nie masz kluczy, sprawdź inne przechwycone dowody dotyczące originu, takie jak jawne zapytania DNS, ale nie utożsamiaj zewnętrznego SNI z ukrytą nazwą.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identyfikowanie lokalnych nazw hostów

### Z DHCP

W aktualnym Wiresharku zamiast `bootp` należy wyszukać `DHCP`

![Identyfikowanie lokalnych nazw hostów - Z DHCP: W aktualnym Wiresharku zamiast bootp należy wyszukać DHCP](<../../../images/image (1013).png>)

### Z NBNS

![Z DHCP - Z NBNS: W aktualnym Wiresharku zamiast bootp należy wyszukać DHCP](<../../../images/image (1003).png>)

## Odszyfrowywanie TLS

Odszyfrowywanie Wi-Fi na warstwie łącza jest niezależne od odszyfrowywania sesji TLS; zobacz [analizę Wi-Fi PCAP](wifi-pcap-analysis.md), aby poznać wymagania dotyczące kluczy i uzgadniania.

### Odszyfrowywanie ruchu https za pomocą klucza prywatnego serwera

_edit > preferences > protocols > tls >_

![Odszyfrowywanie TLS - Odszyfrowywanie ruchu https za pomocą klucza prywatnego serwera: Odszyfrowywanie ruchu https za pomocą klucza prywatnego serwera](<../../../images/image (1103).png>)

Kliknij _Edit_ i dodaj wszystkie dane serwera oraz klucz prywatny (_IP, Port, Protocol, Key file i password_)

Ta metoda działa tylko w ograniczonej liczbie przypadków. W przypadku współczesnego ruchu TLS 1.3 / ECDHE praktyczniejszym rozwiązaniem jest zwykle metoda z plikiem logu kluczy sesji opisana poniżej.<sup>[[1]](#references)</sup>

### Odszyfrowywanie ruchu https za pomocą symetrycznych kluczy sesji

Firefox i Chrome mogą zapisywać klucze sesji TLS, których można użyć w Wiresharku do odszyfrowania ruchu TLS. Umożliwia to szczegółową analizę bezpiecznej komunikacji. Więcej informacji o tym, jak przeprowadzić odszyfrowywanie, znajdziesz w przewodniku [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Jest to również standardowa metoda odszyfrowywania współczesnych przechwyceń TLS 1.3 i QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Aby to wykryć, wyszukaj w środowisku zmienną `SSLKEYLOGFILE`

Plik z zapisanymi kluczami będzie wyglądał tak:

![Odszyfrowywanie ruchu https za pomocą klucza prywatnego serwera - Odszyfrowywanie ruchu https za pomocą symetrycznych kluczy sesji: Plik z zapisanymi kluczami będzie wyglądał tak](<../../../images/image (820).png>)

Jeśli przechwycenie ma format `pcapng`, sprawdź, czy nie zawiera już osadzonych sekretów deszyfrujących, zanim zaczniesz przeszukiwać system plików hosta:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Aby zaimportować to do Wireshark, przejdź do \_edit > preferences > protocols > tls > i zaimportuj plik w polu Pre)-Master-Secret log filename:

![Odszyfrowywanie ruchu HTTPS za pomocą klucza prywatnego serwera — odszyfrowywanie ruchu HTTPS za pomocą symetrycznych kluczy sesji: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Komunikacja ADB

Wyodrębnij APK z komunikacji ADB, podczas której wysłano APK:

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

- [1] [Wiki TLS programu Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Odszyfrowywanie i parsowanie ruchu HTTP/3 w Wiresharku](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Odszyfrowywanie ruchu TLS przeglądarki za pomocą Wiresharka – prosty sposób!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Śledzenie strumieni protokołów](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Dokumentacja filtrów wyświetlania: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Dokumentacja filtrów wyświetlania: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Dokumentacja filtrów wyświetlania: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: Zaszyfrowane Client Hello w TLS](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Podręcznik TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
