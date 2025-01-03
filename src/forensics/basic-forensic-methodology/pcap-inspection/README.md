# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> **PCAP** और **PCAPNG** के बारे में एक नोट: PCAP फ़ाइल प्रारूप के दो संस्करण हैं; **PCAPNG नया है और सभी उपकरणों द्वारा समर्थित नहीं है**। आपको कुछ अन्य उपकरणों में इसके साथ काम करने के लिए Wireshark या किसी अन्य संगत उपकरण का उपयोग करके PCAPNG से PCAP में फ़ाइल को परिवर्तित करने की आवश्यकता हो सकती है।

## Online tools for pcaps

- यदि आपके pcap का हेडर **टूट गया** है, तो आपको इसे **सुधारने** का प्रयास करना चाहिए: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- एक pcap के अंदर **सूचना** निकालें और **malware** के लिए खोजें [**PacketTotal**](https://packettotal.com)
- [**www.virustotal.com**](https://www.virustotal.com) और [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) का उपयोग करके **malicious activity** के लिए खोजें

## Extract Information

निम्नलिखित उपकरण आँकड़े, फ़ाइलें आदि निकालने के लिए उपयोगी हैं।

### Wireshark

> [!NOTE]
> **यदि आप एक PCAP का विश्लेषण करने जा रहे हैं, तो आपको मूल रूप से Wireshark का उपयोग करना आना चाहिए**

आप कुछ Wireshark ट्रिक्स यहाँ पा सकते हैं:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(केवल लिनक्स)_ एक **pcap** का **विश्लेषण** कर सकता है और इससे जानकारी निकाल सकता है। उदाहरण के लिए, एक pcap फ़ाइल से Xplico, प्रत्येक ईमेल (POP, IMAP, और SMTP प्रोटोकॉल), सभी HTTP सामग्री, प्रत्येक VoIP कॉल (SIP), FTP, TFTP, आदि निकालता है।

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
_**127.0.0.1:9876**_ पर _**xplico:xplico**_ क्रेडेंशियल्स के साथ पहुँचें।

फिर एक **नया केस** बनाएं, केस के अंदर एक **नया सत्र** बनाएं और **pcap** फ़ाइल **अपलोड** करें।

### NetworkMiner

Xplico की तरह, यह एक उपकरण है जो **pcaps से वस्तुओं का विश्लेषण और निकालने** के लिए है। इसका एक मुफ्त संस्करण है जिसे आप **यहां** [**डाउनलोड**](https://www.netresec.com/?page=NetworkMiner) कर सकते हैं। यह **Windows** पर काम करता है।\
यह उपकरण पैकेट्स से **अन्य जानकारी का विश्लेषण** करने के लिए भी उपयोगी है ताकि आप जान सकें कि क्या हो रहा था, **तेजी** से।

### NetWitness Investigator

आप [**NetWitness Investigator यहाँ से डाउनलोड**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) कर सकते हैं **(यह Windows पर काम करता है)**।\
यह एक और उपयोगी उपकरण है जो **पैकेट्स का विश्लेषण** करता है और जानकारी को एक उपयोगी तरीके से क्रमबद्ध करता है ताकि **आप जान सकें कि अंदर क्या हो रहा है**।

### [BruteShark](https://github.com/odedshimon/BruteShark)

- उपयोगकर्ता नाम और पासवर्ड निकालना और एन्कोड करना (HTTP, FTP, Telnet, IMAP, SMTP...)
- प्रमाणीकरण हैश निकालें और Hashcat का उपयोग करके उन्हें क्रैक करें (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- एक दृश्य नेटवर्क आरेख बनाएं (नेटवर्क नोड्स और उपयोगकर्ता)
- DNS क्वेरी निकालें
- सभी TCP और UDP सत्रों का पुनर्निर्माण करें
- फ़ाइल कार्विंग

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

यदि आप pcap के अंदर **कुछ** **खोज** रहे हैं तो आप **ngrep** का उपयोग कर सकते हैं। यहाँ मुख्य फ़िल्टर का उपयोग करते हुए एक उदाहरण है:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

सामान्य carving तकनीकों का उपयोग pcap से फ़ाइलों और जानकारी निकालने के लिए उपयोगी हो सकता है:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

आप pcap या एक लाइव इंटरफ़ेस से क्रेडेंशियल्स को पार्स करने के लिए [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) जैसे उपकरणों का उपयोग कर सकते हैं।

## Check Exploits/Malware

### Suricata

**Install and setup**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcap की जांच करें**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) एक उपकरण है जो

- एक PCAP फ़ाइल पढ़ता है और Http स्ट्रीम निकालता है।
- gzip किसी भी संकुचित स्ट्रीम को डिफ्लेट करता है
- हर फ़ाइल को यारा के साथ स्कैन करता है
- एक report.txt लिखता है
- वैकल्पिक रूप से मेल खाने वाली फ़ाइलों को एक Dir में सहेजता है

### Malware Analysis

जांचें कि क्या आप किसी ज्ञात मैलवेयर का कोई फिंगरप्रिंट ढूंढ सकते हैं:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) एक पैसिव, ओपन-सोर्स नेटवर्क ट्रैफिक एनालाइज़र है। कई ऑपरेटर संदिग्ध या दुर्भावनापूर्ण गतिविधियों की जांच का समर्थन करने के लिए Zeek का उपयोग नेटवर्क सुरक्षा मॉनिटर (NSM) के रूप में करते हैं। Zeek सुरक्षा डोमेन के अलावा प्रदर्शन माप और समस्या निवारण सहित ट्रैफिक विश्लेषण कार्यों की एक विस्तृत श्रृंखला का समर्थन करता है।

बुनियादी रूप से, `zeek` द्वारा बनाए गए लॉग **pcaps** नहीं होते हैं। इसलिए आपको उन लॉग का विश्लेषण करने के लिए **अन्य उपकरणों** का उपयोग करने की आवश्यकता होगी जहाँ **pcaps** के बारे में **जानकारी** होती है।

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

​

{{#include ../../../banners/hacktricks-training.md}}
