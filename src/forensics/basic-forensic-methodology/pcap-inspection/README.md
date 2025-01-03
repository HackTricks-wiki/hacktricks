# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Примітка про **PCAP** та **PCAPNG**: існує дві версії формату файлів PCAP; **PCAPNG є новішим і не підтримується всіма інструментами**. Вам може знадобитися конвертувати файл з PCAPNG в PCAP за допомогою Wireshark або іншого сумісного інструменту, щоб працювати з ним в деяких інших інструментах.

## Онлайн-інструменти для pcaps

- Якщо заголовок вашого pcap **пошкоджений**, ви повинні спробувати **виправити** його за допомогою: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Витягніть **інформацію** та шукайте **шкідливе ПЗ** всередині pcap в [**PacketTotal**](https://packettotal.com)
- Шукайте **зловмисну активність** за допомогою [**www.virustotal.com**](https://www.virustotal.com) та [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Витяг інформації

Наступні інструменти корисні для витягування статистики, файлів тощо.

### Wireshark

> [!NOTE]
> **Якщо ви збираєтеся аналізувати PCAP, ви в основному повинні знати, як користуватися Wireshark**

Ви можете знайти деякі трюки Wireshark у:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(тільки linux)_ може **аналізувати** **pcap** та витягувати інформацію з нього. Наприклад, з файлу pcap Xplico витягує кожен електронний лист (протоколи POP, IMAP та SMTP), весь HTTP контент, кожен VoIP дзвінок (SIP), FTP, TFTP тощо.

**Встановіть**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Запустити**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Доступ до _**127.0.0.1:9876**_ з обліковими даними _**xplico:xplico**_

Потім створіть **нову справу**, створіть **нову сесію** всередині справи та **завантажте pcap** файл.

### NetworkMiner

Як і Xplico, це інструмент для **аналізу та витягування об'єктів з pcaps**. Він має безкоштовну версію, яку ви можете **завантажити** [**тут**](https://www.netresec.com/?page=NetworkMiner). Він працює з **Windows**.\
Цей інструмент також корисний для отримання **іншої інформації, проаналізованої** з пакетів, щоб мати можливість швидше зрозуміти, що відбувалося.

### NetWitness Investigator

Ви можете завантажити [**NetWitness Investigator звідси**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Працює в Windows)**.\
Це ще один корисний інструмент, який **аналізує пакети** та сортує інформацію у зручний спосіб, щоб **знати, що відбувається всередині**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Витягування та кодування імен користувачів і паролів (HTTP, FTP, Telnet, IMAP, SMTP...)
- Витягування хешів аутентифікації та їх злом за допомогою Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Створення візуальної мережевої діаграми (мережеві вузли та користувачі)
- Витягування DNS запитів
- Відновлення всіх TCP та UDP сесій
- Файловий карвінг

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Якщо ви **шукаєте** **щось** всередині pcap, ви можете використовувати **ngrep**. Ось приклад з використанням основних фільтрів:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Витягування

Використання загальних технік витягування може бути корисним для вилучення файлів та інформації з pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Захоплення облікових даних

Ви можете використовувати інструменти, такі як [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz), для парсингу облікових даних з pcap або живого інтерфейсу.

## Перевірка експлойтів/Шкідливого ПЗ

### Suricata

**Встановлення та налаштування**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Перевірте pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) - це інструмент, який

- Читає файл PCAP та витягує Http потоки.
- gzip розпаковує будь-які стиснуті потоки
- Сканує кожен файл за допомогою yara
- Пише report.txt
- За бажанням зберігає відповідні файли в директорію

### Malware Analysis

Перевірте, чи можете ви знайти будь-які відбитки відомого шкідливого ПЗ:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) - це пасивний, з відкритим вихідним кодом аналізатор мережевого трафіку. Багато операторів використовують Zeek як монітор безпеки мережі (NSM) для підтримки розслідувань підозрілої або шкідливої діяльності. Zeek також підтримує широкий спектр завдань аналізу трафіку, які виходять за межі безпеки, включаючи вимірювання продуктивності та усунення неполадок.

В основному, журнали, створені `zeek`, не є **pcaps**. Тому вам потрібно буде використовувати **інші інструменти** для аналізу журналів, де міститься **інформація** про pcaps.

### Connections Info
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

​

{{#include ../../../banners/hacktricks-training.md}}
