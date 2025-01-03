# Inspekcja Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Uwagi dotyczące **PCAP** a **PCAPNG**: istnieją dwie wersje formatu pliku PCAP; **PCAPNG jest nowszy i nie jest obsługiwany przez wszystkie narzędzia**. Może być konieczne przekształcenie pliku z PCAPNG na PCAP za pomocą Wireshark lub innego kompatybilnego narzędzia, aby móc z nim pracować w niektórych innych narzędziach.

## Narzędzia online do pcapów

- Jeśli nagłówek twojego pcap jest **uszkodzony**, powinieneś spróbować go **naprawić** za pomocą: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Wyodrębnij **informacje** i szukaj **złośliwego oprogramowania** w pcap w [**PacketTotal**](https://packettotal.com)
- Szukaj **złośliwej aktywności** za pomocą [**www.virustotal.com**](https://www.virustotal.com) i [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Wyodrębnij informacje

Następujące narzędzia są przydatne do wyodrębniania statystyk, plików itp.

### Wireshark

> [!NOTE]
> **Jeśli zamierzasz analizować PCAP, musisz zasadniczo wiedzieć, jak używać Wireshark**

Możesz znaleźć kilka sztuczek Wireshark w:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(tylko linux)_ może **analizować** **pcap** i wyodrębniać z niego informacje. Na przykład, z pliku pcap Xplico wyodrębnia każdą wiadomość e-mail (protokół POP, IMAP i SMTP), wszystkie treści HTTP, każde połączenie VoIP (SIP), FTP, TFTP itd.

**Zainstaluj**
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
Dostęp do _**127.0.0.1:9876**_ z danymi logowania _**xplico:xplico**_

Następnie utwórz **nową sprawę**, utwórz **nową sesję** w ramach sprawy i **prześlij plik pcap**.

### NetworkMiner

Podobnie jak Xplico, jest to narzędzie do **analizowania i wyodrębniania obiektów z pcapów**. Ma darmową edycję, którą możesz **pobrać** [**tutaj**](https://www.netresec.com/?page=NetworkMiner). Działa na **Windows**.\
To narzędzie jest również przydatne do uzyskania **innych analizowanych informacji** z pakietów, aby móc szybciej zrozumieć, co się działo.

### NetWitness Investigator

Możesz pobrać [**NetWitness Investigator stąd**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Działa na Windows)**.\
To kolejne przydatne narzędzie, które **analizuje pakiety** i sortuje informacje w użyteczny sposób, aby **wiedzieć, co się dzieje wewnątrz**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Wyodrębnianie i kodowanie nazw użytkowników i haseł (HTTP, FTP, Telnet, IMAP, SMTP...)
- Wyodrębnianie hashy uwierzytelniających i łamanie ich za pomocą Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Budowanie wizualnego diagramu sieci (Węzły i użytkownicy sieci)
- Wyodrębnianie zapytań DNS
- Rekonstrukcja wszystkich sesji TCP i UDP
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Jeśli **szukasz** **czegoś** wewnątrz pcap, możesz użyć **ngrep**. Oto przykład użycia głównych filtrów:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Użycie powszechnych technik carvingowych może być przydatne do wydobywania plików i informacji z pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Możesz użyć narzędzi takich jak [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) do analizy poświadczeń z pcap lub z aktywnego interfejsu.

## Check Exploits/Malware

### Suricata

**Install and setup**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Sprawdź pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) to narzędzie, które

- Odczytuje plik PCAP i wyodrębnia strumienie Http.
- gzip dekompresuje wszelkie skompresowane strumienie
- Skanuje każdy plik za pomocą yara
- Tworzy report.txt
- Opcjonalnie zapisuje pasujące pliki do katalogu

### Analiza złośliwego oprogramowania

Sprawdź, czy możesz znaleźć jakiekolwiek odciski palców znanego złośliwego oprogramowania:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) to pasywny, open-source'owy analizator ruchu sieciowego. Wielu operatorów używa Zeeka jako Monitor Bezpieczeństwa Sieci (NSM) do wspierania dochodzeń w sprawie podejrzanej lub złośliwej aktywności. Zeek wspiera również szeroki zakres zadań analizy ruchu poza domeną bezpieczeństwa, w tym pomiar wydajności i rozwiązywanie problemów.

Zasadniczo, logi tworzone przez `zeek` nie są **pcapami**. Dlatego będziesz musiał użyć **innych narzędzi** do analizy logów, w których znajdują się **informacje** o pcapach.

### Informacje o połączeniach
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
## Inne triki analizy pcap

{{#ref}}
dnscat-exfiltration.md
{{#endref}}

{{#ref}}
wifi-pcap-analysis.md
{{#endref}}

{{#ref}}
usb-keystrokes.md
{{#endref}}

​

{{#include ../../../banners/hacktricks-training.md}}
