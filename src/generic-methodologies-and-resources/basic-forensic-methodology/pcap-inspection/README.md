# Inspekcja Pcap

> [!TIP]
> **PCAP** i **PCAPNG** to odrębne formaty przechwytywania; **PCAPNG jest elastycznym i rozszerzalnym następcą PCAP**, ale obsługa różni się w zależności od narzędzia. Jeśli narzędzie nie może odczytać PCAPNG, przekonwertuj go do PCAP za pomocą Wireshark lub innego kompatybilnego narzędzia.<sup>[[1]](#references)[[18]](#references)</sup>

## Narzędzia online do analizy pcap

- Jeśli nagłówek pliku pcap jest **uszkodzony**, spróbuj go **naprawić** za pomocą: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Wyodrębniaj **informacje** i wyszukuj **malware** wewnątrz pliku pcap za pomocą [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Wyszukuj **złośliwą aktywność** za pomocą [**www.virustotal.com**](https://www.virustotal.com) i [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Pełna analiza pcap z poziomu przeglądarki w** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Wyodrębnianie informacji

Poniższe narzędzia są przydatne do wyodrębniania statystyk, plików itp.

### Wireshark

> [!TIP]
> **Jeśli zamierzasz analizować PCAP, zasadniczo musisz wiedzieć, jak używać Wireshark**

Kilka trików dotyczących Wireshark znajdziesz w:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Analiza pcap z poziomu przeglądarki.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) to uniksowe narzędzie do analizy sieci i informatyki śledczej, które dekoduje pliki PCAP oraz może wyodrębniać wiadomości e-mail przez POP/IMAP/SMTP, zawartość HTTP, połączenia SIP VoIP, dane FTP i dane TFTP.<sup>[[6]](#references)</sup>

**Instalacja**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Uruchom**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Dostęp do _**127.0.0.1:9876**_ za pomocą danych uwierzytelniających _**xplico:xplico**_

Następnie utwórz **nowy przypadek**, utwórz **nową sesję** w ramach przypadku i **prześlij plik** pcap.

### NetworkMiner

Podobnie jak Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) analizuje ruch PCAP w celu wyodrębnienia artefaktów, takich jak pliki, obrazy, wiadomości e-mail i hasła, a także agreguje informacje o hostach; jego darmowa edycja jest przeznaczona głównie dla Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Możesz pobrać [**NetWitness Investigator stąd**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Działa w Windows)**.\
Dostawca opisuje freeware jako interaktywne narzędzie do analizy sesji sieciowych, służące do wstępnej analizy złośliwej aktywności, a obecnie udostępnia je za pośrednictwem formularza kontaktowego.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Udokumentowane moduły BruteShark mogą analizować dane uwierzytelniające z HTTP, FTP, Telnet, IMAP i SMTP, eksportować hashe uwierzytelniania Kerberos, NTLM, CRAM-MD5 i HTTP-Digest do Hashcat, mapować węzły sieciowe i użytkowników, wyodrębniać zapytania DNS, odbudowywać sesje TCP/UDP oraz wycinać pliki.<sup>[[9]](#references)</sup>

### Capinfos

`capinfos` z Wireshark domyślnie wyświetla obszerny raport dotyczący pliku przechwycenia.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` wyszukuje ładunki pakietów za pomocą wyrażeń regularnych i akceptuje filtry BPF; `-I` odczytuje plik przechwytywania zgodny z pcap.<sup>[[11]](#references)</sup> Przykład łączy te funkcje, aby wyszukać żądanie HTTP w wybranym ruchu.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Użycie common carving techniques może być przydatne do wyodrębniania plików i informacji z pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Przechwytywanie danych uwierzytelniających

Możesz użyć [PCredz](https://github.com/lgandx/PCredz) do analizowania danych uwierzytelniających z zapisanego pliku PCAP lub aktywnego interfejsu.<sup>[[12]](#references)</sup>

## Sprawdzanie Exploits/Malware

### Suricata

**Instalacja i konfiguracja**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Sprawdź pcap**

Opcja `-r` programu Suricata odtwarza plik PCAP w trybie offline; w tym przykładzie `-k none` wyłącza sprawdzanie sum kontrolnych, `-v` zwiększa poziom logowania, a `-l` wybiera katalog logów.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) przetwarza strumienie HTTP z plików PCAP, opcjonalnie dekompresuje strumienie gzip, skanuje wyodrębnione pliki za pomocą YARA, zapisuje `report.txt` i może zapisywać pasujące pliki w katalogu.<sup>[[14]](#references)</sup>

### Analiza malware

Sprawdź, czy możesz znaleźć jakikolwiek ślad znanego malware:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) to pasywny, open-source'owy analizator ruchu sieciowego, używany jako Network Security Monitor (NSM) oraz do szerszej analizy ruchu, w tym pomiaru wydajności i rozwiązywania problemów.<sup>[[15]](#references)</sup>

Zeek generuje ustrukturyzowane logi zamiast plików PCAP, dlatego do ich analizy używaj narzędzi takich jak `zeek-cut`.<sup>[[15]](#references)[[16]](#references)</sup>

### Informacje o połączeniach

Poniższe przykłady używają `zeek-cut` do wybierania nazwanych pól z logów TSV, a następnie standardowych narzędzi Unix do porządkowania i zliczania połączeń; RITA może również wczytywać logi Zeek do analizy długotrwałych połączeń, beaconingu i tunelowania DNS.<sup>[[16]](#references)[[17]](#references)</sup>
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### Informacje o DNS
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## Inne sztuczki analizy pcap


{{#ref}}
dnscat-exfiltration.md
{{#endref}}


{{#ref}}
wifi-pcap-analysis.md
{{#endref}}


{{#ref}}
usb-keystrokes.md
{{#endref}}

## References

- [1] [Przewodnik użytkownika Wireshark: otwieranie plików przechwyceń](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - internetowa usługa naprawy pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Przegląd API v3 VirusTotal](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - informacje](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Repozytorium BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Podręcznik `capinfos` Wireshark](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Dokumentacja ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Repozytorium PCredz](https://github.com/lgandx/PCredz)
- [13] [Opcje wiersza poleceń Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Repozytorium YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [Czym jest Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Samouczek dotyczący logów Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Repozytorium RITA](https://github.com/activecm/rita)
- [18] [Dokumentacja `editcap` Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Ogłoszenie dotyczące API przesyłania PacketTotal](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
