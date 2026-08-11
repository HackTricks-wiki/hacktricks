# Аналіз Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** і **PCAPNG** є різними форматами захоплення; **PCAPNG — це гнучкий і розширюваний наступник PCAP**, але підтримка залежить від інструментів. Якщо інструмент не може прочитати PCAPNG, конвертуйте його в PCAP за допомогою Wireshark або іншого сумісного інструмента.<sup>[[1]](#references)[[18]](#references)</sup>

## Онлайн-інструменти для pcap

- Якщо заголовок вашого pcap **пошкоджений**, спробуйте **виправити** його за допомогою: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Витягуйте **інформацію** та шукайте **malware** у pcap за допомогою [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Шукайте **шкідливу активність** за допомогою [**www.virustotal.com**](https://www.virustotal.com) і [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Повний аналіз pcap у браузері за допомогою** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Витягування інформації

Наведені нижче інструменти корисні для вилучення статистики, файлів тощо.

### Wireshark

> [!TIP]
> **Якщо ви збираєтеся аналізувати PCAP, вам фактично необхідно знати, як користуватися Wireshark**

Деякі прийоми Wireshark можна знайти тут:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Аналіз pcap у браузері.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) — це інструмент мережевої криміналістики для Unix-подібних систем, який декодує файли PCAP і може витягувати електронні листи через POP/IMAP/SMTP, вміст HTTP, VoIP-виклики SIP, дані FTP і дані TFTP.<sup>[[6]](#references)</sup>

**Встановлення**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Запуск**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Доступ до _**127.0.0.1:9876**_ з обліковими даними _**xplico:xplico**_

Потім створіть **новий case**, створіть **нову session** у case та **завантажте** файл **pcap**.

### NetworkMiner

Як і Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) аналізує трафік PCAP для вилучення артефактів, таких як файли, зображення, електронні листи та паролі, а також агрегує інформацію про хости; його безкоштовна версія призначена переважно для Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Ви можете завантажити [**NetWitness Investigator звідси**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(працює у Windows)**.\
Постачальник описує freeware як інтерактивний інструмент аналізу мережевих сесій для первинного аналізу шкідливої активності та наразі пропонує доступ через контактну форму.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Документовані модулі BruteShark можуть вилучати облікові дані з HTTP, FTP, Telnet, IMAP і SMTP, експортувати хеші автентифікації Kerberos, NTLM, CRAM-MD5 і HTTP-Digest для Hashcat, створювати карту мережевих вузлів і користувачів, вилучати DNS-запити, відновлювати TCP/UDP-сесії та виділяти файли.<sup>[[9]](#references)</sup>

### Capinfos

`capinfos` у Wireshark за замовчуванням виводить докладний звіт для capture-файлу.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` шукає дані пакетів за допомогою регулярних виразів і підтримує BPF-фільтри; `-I` читає capture file, сумісний із pcap.<sup>[[11]](#references)</sup> У прикладі ці можливості поєднано для пошуку HTTP-запиту у вибраному трафіку.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Використання поширених технік carving може бути корисним для вилучення файлів та інформації з pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Збір облікових даних

Ви можете використовувати [PCredz](https://github.com/lgandx/PCredz) для аналізу облікових даних зі збереженого PCAP-файлу або активного інтерфейсу.<sup>[[12]](#references)</sup>

## Перевірка експлойтів/шкідливого ПЗ

### Suricata

**Встановлення та налаштування**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Перевірка pcap**

Опція `-r` у Suricata відтворює PCAP в offline mode; у цьому прикладі `-k none` вимикає перевірки контрольних сум, `-v` збільшує обсяг журналювання, а `-l` вибирає каталог журналів.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) обробляє HTTP-потоки з PCAP-файлів, за потреби розпаковує gzip-потоки, сканує витягнуті файли за допомогою YARA, записує `report.txt` і може зберігати файли, що відповідають умовам, до каталогу.<sup>[[14]](#references)</sup>

### Аналіз шкідливого програмного забезпечення

Перевірте, чи можете ви знайти будь-який відбиток відомого шкідливого програмного забезпечення:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) — це пасивний аналізатор мережевого трафіку з відкритим кодом, який використовується як Network Security Monitor (NSM) і для ширшого аналізу трафіку, зокрема вимірювання продуктивності та усунення несправностей.<sup>[[15]](#references)</sup>

Zeek створює структуровані журнали, а не PCAP-файли, тому для перевірки цих журналів використовуйте інструменти аналізу журналів, такі як `zeek-cut`.<sup>[[15]](#references)[[16]](#references)</sup>

### Інформація про з'єднання

У наведених нижче прикладах `zeek-cut` використовується для вибору іменованих полів із TSV-журналів, а потім стандартні інструменти Unix — для ранжування та підрахунку з'єднань; RITA також може імпортувати журнали Zeek для аналізу тривалих з'єднань, beaconing і DNS-тунелювання.<sup>[[16]](#references)[[17]](#references)</sup>
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
### Інформація про DNS
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
## Інші трюки аналізу pcap


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

- [1] [Посібник користувача Wireshark: відкриття файлів захоплення](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix — онлайн-сервіс відновлення pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Огляд VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [Аналізатор PCAP A-Packets](https://apackets.com/)
- [6] [Xplico — про проєкт](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [Безкоштовна версія NetWitness Investigator](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Репозиторій BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Посібник Wireshark `capinfos`](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Документація ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Репозиторій PCredz](https://github.com/lgandx/PCredz)
- [13] [Опції командного рядка Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Репозиторій YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [Що таке Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Посібник із журналів Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Репозиторій RITA](https://github.com/activecm/rita)
- [18] [Документація Wireshark `editcap`](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Оголошення про Upload API PacketTotal](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
