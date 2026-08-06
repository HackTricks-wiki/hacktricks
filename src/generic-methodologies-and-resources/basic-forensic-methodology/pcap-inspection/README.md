# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** और **PCAPNG** के बारे में एक नोट: PCAP file format के दो versions हैं; **PCAPNG नया है और सभी tools द्वारा supported नहीं है**। किसी अन्य tools में इसके साथ काम करने के लिए आपको Wireshark या किसी अन्य compatible tool का उपयोग करके file को PCAPNG से PCAP में convert करना पड़ सकता है।

## pcaps के लिए Online tools

- यदि आपके pcap का **header** **broken** है, तो इसे ठीक करने के लिए यह आज़माएँ: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- [**PacketTotal**](https://packettotal.com) में pcap के अंदर से **information** extract करें और **malware** खोजें
- [**www.virustotal.com**](https://www.virustotal.com) और [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) का उपयोग करके **malicious activity** खोजें
- [**https://apackets.com/**](https://apackets.com/) में browser से **full pcap analysis**

## Information Extract करना

Statistics, files आदि extract करने के लिए निम्नलिखित tools उपयोगी हैं।

### Wireshark

> [!TIP]
> **यदि आप PCAP analyze करने वाले हैं, तो आपको मूल रूप से Wireshark का उपयोग करना आना चाहिए**

आप कुछ Wireshark tricks यहाँ पा सकते हैं:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Browser से Pcap analysis।

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(only linux)_ एक **pcap** को **analyze** कर सकता है और उसमें से information extract कर सकता है। उदाहरण के लिए, pcap file से Xplico प्रत्येक email (POP, IMAP और SMTP protocols), सभी HTTP contents, प्रत्येक VoIP call (SIP), FTP, TFTP आदि extract करता है।

**Install करें**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**चलाएँ**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
_**127.0.0.1:9876**_ पर credentials _**xplico:xplico**_ के साथ access करें।

फिर एक **new case** बनाएं, case के अंदर एक **new session** बनाएं और **pcap** file upload करें।

### NetworkMiner

Xplico की तरह यह **pcaps से objects analyze और extract** करने का एक tool है। इसका एक free edition है जिसे आप [**यहां download**](https://www.netresec.com/?page=NetworkMiner) कर सकते हैं। यह **Windows** के साथ काम करता है।\
यह tool packets से **other information analysed** प्राप्त करने के लिए भी उपयोगी है, ताकि यह पता लगाया जा सके कि **quicker** तरीके से क्या हो रहा था।

### NetWitness Investigator

आप [**NetWitness Investigator को यहां से download**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) कर सकते हैं **(यह Windows में काम करता है)**।\
यह एक अन्य उपयोगी tool है जो **packets को analyse** करता है और information को उपयोगी तरीके से sort करता है, ताकि **अंदर क्या हो रहा है यह जानना** संभव हो सके।

### [BruteShark](https://github.com/odedshimon/BruteShark)

- usernames और passwords को extract और encode करना (HTTP, FTP, Telnet, IMAP, SMTP...)
- authentication hashes extract करना और Hashcat का उपयोग करके उन्हें crack करना (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- एक visual network diagram बनाना (Network nodes और users)
- DNS queries extract करना
- सभी TCP और UDP Sessions को reconstruct करना
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

यदि आप pcap के अंदर **कुछ** **खोज** रहे हैं, तो आप **ngrep** का उपयोग कर सकते हैं। यहाँ मुख्य filters का उपयोग करने वाला एक उदाहरण है:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

common carving techniques का उपयोग pcap से files और information extract करने के लिए उपयोगी हो सकता है:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

आप [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) जैसे tools का उपयोग pcap या live interface से credentials parse करने के लिए कर सकते हैं।

## Check Exploits/Malware

### Suricata

**Install और setup**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcap जांचें**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) एक ऐसा tool है जो

- एक PCAP File को पढ़ता है और Http Streams को Extract करता है।
- किसी भी compressed streams को gzip से deflate करता है।
- हर file को yara से Scan करता है।
- एक report.txt लिखता है।
- वैकल्पिक रूप से matching files को एक Dir में save करता है।

### Malware Analysis

जाँचें कि क्या आपको किसी ज्ञात malware का कोई fingerprint मिल सकता है:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) एक passive, open-source network traffic analyzer है। कई operators suspicious या malicious activity की investigations में सहायता के लिए Zeek का उपयोग Network Security Monitor (NSM) के रूप में करते हैं। Zeek security domain के अलावा traffic analysis tasks की एक विस्तृत range को भी support करता है, जिसमें performance measurement और troubleshooting शामिल हैं।

मूल रूप से, `zeek` द्वारा बनाए गए logs **pcaps** नहीं होते। इसलिए आपको उन logs का analysis करने के लिए **अन्य tools** का उपयोग करना होगा, जिनमें pcaps से संबंधित **information** होती है।

### Connections की जानकारी
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
### DNS जानकारी
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
## अन्य pcap विश्लेषण तकनीकें


{{#ref}}
dnscat-exfiltration.md
{{#endref}}


{{#ref}}
wifi-pcap-analysis.md
{{#endref}}


{{#ref}}
usb-keystrokes.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
