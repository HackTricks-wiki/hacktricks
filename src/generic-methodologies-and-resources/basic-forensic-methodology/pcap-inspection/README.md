# Pcap Inspection

> [!TIP]
> **PCAP** और **PCAPNG** अलग-अलग capture formats हैं; **PCAPNG, PCAP का अधिक flexible और extensible successor है**, लेकिन अलग-अलग tools में इसका support अलग हो सकता है। यदि कोई tool PCAPNG को read नहीं कर सकता, तो इसे Wireshark या किसी अन्य compatible tool से PCAP में convert करें।<sup>[[1]](#references)[[18]](#references)</sup>

## PCAPs के लिए Online tools

- यदि आपके pcap का **header** **broken** है, तो इसे [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php) का उपयोग करके **fix** करने का प्रयास करें।<sup>[[2]](#references)</sup>
- [**PacketTotal**](https://packettotal.com) में pcap के अंदर **information** extract करें और **malware** खोजें।<sup>[[19]](#references)</sup>
- [**www.virustotal.com**](https://www.virustotal.com) और [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) का उपयोग करके **malicious activity** खोजें।<sup>[[3]](#references)[[4]](#references)</sup>
- [**https://apackets.com/**](https://apackets.com/) में **browser से full pcap analysis** करें।<sup>[[5]](#references)</sup>

## Information Extract करें

निम्नलिखित tools statistics, files आदि extract करने के लिए उपयोगी हैं।

### Wireshark

> [!TIP]
> **यदि आप किसी PCAP का analysis करने वाले हैं, तो आपको मूल रूप से Wireshark का उपयोग करना आना ही चाहिए।**

आप Wireshark की कुछ tricks यहां पा सकते हैं:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Browser से Pcap analysis।<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) एक Unix-like network-forensics tool है, जो PCAP files को decode कर सकता है और POP/IMAP/SMTP से email, HTTP contents, SIP VoIP calls, FTP data और TFTP data extract कर सकता है।<sup>[[6]](#references)</sup>

**Install**
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
_**127.0.0.1:9876**_ पर _**xplico:xplico**_ credentials के साथ access करें।

फिर एक **new case** बनाएं, case के अंदर एक **new session** बनाएं और **pcap** file upload करें।

### NetworkMiner

Xplico की तरह, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) PCAP traffic को parse करके files, images, email और passwords जैसे artifacts extract करता है और host information को aggregate करता है; इसका free edition मुख्य रूप से Windows के लिए है।<sup>[[7]](#references)</sup>

### NetWitness Investigator

आप [**NetWitness Investigator को यहाँ से download कर सकते हैं**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(यह Windows में काम करता है)**।\
Vendor freeware को malicious-activity triage के लिए interactive network-session analysis tool के रूप में describe करता है और वर्तमान में contact form के माध्यम से access प्रदान करता है।<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark के documented modules HTTP, FTP, Telnet, IMAP और SMTP से credentials parse कर सकते हैं, Hashcat के लिए Kerberos, NTLM, CRAM-MD5 और HTTP-Digest authentication hashes export कर सकते हैं, network nodes और users को map कर सकते हैं, DNS queries extract कर सकते हैं, TCP/UDP sessions को rebuild कर सकते हैं और files carve कर सकते हैं।<sup>[[9]](#references)</sup>

### Capinfos

Wireshark का `capinfos` default रूप से capture file के लिए एक लंबी report print करता है।<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` regular expressions के साथ packet payloads में खोजता है और BPF filters स्वीकार करता है; `-I` pcap-compatible capture file को पढ़ता है।<sup>[[11]](#references)</sup> यह उदाहरण इन सुविधाओं को मिलाकर चुने गए traffic में HTTP request खोजता है।
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

सामान्य carving techniques का उपयोग pcap से files और information extract करने के लिए उपयोगी हो सकता है:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

आप stored PCAP file या live interface से credentials parse करने के लिए [PCredz](https://github.com/lgandx/PCredz) का उपयोग कर सकते हैं।<sup>[[12]](#references)</sup>

## Check Exploits/Malware

### Suricata

**Install and setup**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**PCAP जांचें**

Suricata का `-r` विकल्प offline mode में PCAP को replay करता है; इस उदाहरण में, `-k none` checksum checks को disable करता है, `-v` logging बढ़ाता है, और `-l` log directory चुनता है।<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) PCAP files से HTTP streams को process करता है, वैकल्पिक रूप से gzip streams को decompress करता है, extracted files को YARA से scan करता है, `report.txt` लिखता है, और matching files को किसी directory में save कर सकता है।<sup>[[14]](#references)</sup>

### Malware Analysis

जाँचें कि क्या आपको किसी ज्ञात malware का कोई fingerprint मिल सकता है:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) एक passive, open-source network traffic analyzer है, जिसका उपयोग Network Security Monitor (NSM) के रूप में और performance measurement तथा troubleshooting सहित व्यापक traffic analysis के लिए किया जाता है।<sup>[[15]](#references)</sup>

Zeek PCAP files के बजाय structured logs generate करता है, इसलिए उन logs का निरीक्षण करने के लिए `zeek-cut` जैसे log-analysis tools का उपयोग करें।<sup>[[15]](#references)[[16]](#references)</sup>

### Connections Info

नीचे दिए गए examples TSV logs से named fields select करने के लिए `zeek-cut` और फिर connections को rank तथा count करने के लिए standard Unix tools का उपयोग करते हैं; RITA long-connection, beaconing और DNS-tunneling analysis के लिए Zeek logs को ingest भी कर सकता है।<sup>[[16]](#references)[[17]](#references)</sup>
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
## pcap analysis की अन्य tricks


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

- [1] [Wireshark User's Guide: Capture Files खोलना](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - online pcap / pcapng repair service](https://f00l.de/hacking/pcapfix.php)
- [3] [VirusTotal API v3 का अवलोकन](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - परिचय](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark repository](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos` manual](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep documentation](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz repository](https://github.com/lgandx/PCredz)
- [13] [Suricata command-line options](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap repository](https://github.com/kevthehermit/YaraPcap)
- [15] [What Is Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek logs tutorial](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA repository](https://github.com/activecm/rita)
- [18] [Wireshark `editcap` documentation](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [PacketTotal Upload API announcement](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
