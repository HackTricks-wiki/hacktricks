# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Popraw swoje umiejętności w Wireshark

### Samouczki

Następujące samouczki są świetne do nauki kilku fajnych podstawowych trików:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizowane informacje

**Informacje eksperckie**

Klikając na _**Analiza** --> **Informacje eksperckie**_ uzyskasz **przegląd** tego, co dzieje się w **analizowanych** pakietach:

![](<../../../images/image (256).png>)

**Rozwiązane adresy**

Pod _**Statystyki --> Rozwiązane adresy**_ możesz znaleźć kilka **informacji**, które zostały "**rozwiązane**" przez Wireshark, takich jak port/transport do protokołu, MAC do producenta itp. Interesujące jest, co jest zaangażowane w komunikację.

![](<../../../images/image (893).png>)

**Hierarchia protokołów**

Pod _**Statystyki --> Hierarchia protokołów**_ możesz znaleźć **protokoły** **zaangażowane** w komunikację oraz dane o nich.

![](<../../../images/image (586).png>)

**Rozmowy**

Pod _**Statystyki --> Rozmowy**_ możesz znaleźć **podsumowanie rozmów** w komunikacji oraz dane o nich.

![](<../../../images/image (453).png>)

**Punkty końcowe**

Pod _**Statystyki --> Punkty końcowe**_ możesz znaleźć **podsumowanie punktów końcowych** w komunikacji oraz dane o każdym z nich.

![](<../../../images/image (896).png>)

**Informacje DNS**

Pod _**Statystyki --> DNS**_ możesz znaleźć statystyki dotyczące przechwyconego żądania DNS.

![](<../../../images/image (1063).png>)

**Wykres I/O**

Pod _**Statystyki --> Wykres I/O**_ możesz znaleźć **wykres komunikacji.**

![](<../../../images/image (992).png>)

### Filtry

Tutaj możesz znaleźć filtry Wireshark w zależności od protokołu: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Inne interesujące filtry:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP i początkowy ruch HTTPS
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP i początkowy ruch HTTPS + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP i początkowy ruch HTTPS + TCP SYN + żądania DNS

### Wyszukiwanie

Jeśli chcesz **wyszukiwać** **treść** wewnątrz **pakietów** sesji, naciśnij _CTRL+f_. Możesz dodać nowe warstwy do głównego paska informacji (Nr, Czas, Źródło itp.) naciskając prawy przycisk i następnie edytując kolumnę.

### Darmowe laboratoria pcap

**Ćwicz z darmowymi wyzwaniami na:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identyfikacja domen

Możesz dodać kolumnę, która pokazuje nagłówek Host HTTP:

![](<../../../images/image (639).png>)

I kolumnę, która dodaje nazwę serwera z inicjującego połączenia HTTPS (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Identyfikacja lokalnych nazw hostów

### Z DHCP

W aktualnym Wireshark zamiast `bootp` musisz szukać `DHCP`

![](<../../../images/image (1013).png>)

### Z NBNS

![](<../../../images/image (1003).png>)

## Deszyfrowanie TLS

### Deszyfrowanie ruchu https za pomocą prywatnego klucza serwera

_edit>preferencje>protokół>ssl>_

![](<../../../images/image (1103).png>)

Naciśnij _Edytuj_ i dodaj wszystkie dane serwera oraz prywatny klucz (_IP, Port, Protokół, Plik klucza i hasło_)

### Deszyfrowanie ruchu https za pomocą symetrycznych kluczy sesji

Zarówno Firefox, jak i Chrome mają możliwość rejestrowania kluczy sesji TLS, które można wykorzystać z Wireshark do deszyfrowania ruchu TLS. Umożliwia to szczegółową analizę zabezpieczonej komunikacji. Więcej informacji na temat tego, jak przeprowadzić to deszyfrowanie, można znaleźć w przewodniku na stronie [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Aby to wykryć, przeszukaj środowisko pod kątem zmiennej `SSLKEYLOGFILE`

Plik z kluczami współdzielonymi będzie wyglądał tak:

![](<../../../images/image (820).png>)

Aby zaimportować to do Wireshark, przejdź do _edytuj > preferencje > protokół > ssl > i zaimportuj to w (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## Komunikacja ADB

Wyodrębnij APK z komunikacji ADB, gdzie APK został wysłany:
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
{{#include ../../../banners/hacktricks-training.md}}
