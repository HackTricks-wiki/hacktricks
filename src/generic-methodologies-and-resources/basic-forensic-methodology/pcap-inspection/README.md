# Ukaguzi wa Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** na **PCAPNG** ni formats tofauti za capture; **PCAPNG ni toleo linaloweza kunyumbulika na kupanuka la PCAP**, lakini support hutofautiana kati ya tools. Ikiwa tool haiwezi kusoma PCAPNG, ibadilishe kuwa PCAP kwa kutumia Wireshark au tool nyingine inayooana.<sup>[[1]](#references)[[18]](#references)</sup>

## Tools za mtandaoni za pcaps

- Ikiwa header ya pcap yako **imeharibika**, unapaswa kujaribu **kuirekebisha** kwa kutumia: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Extract **information** na tafuta **malware** ndani ya pcap katika [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Tafuta **malicious activity** kwa kutumia [**www.virustotal.com**](https://www.virustotal.com) na [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Full pcap analysis from the browser in** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Extract Information

Tools zifuatazo ni muhimu kwa ku-extract statistics, files, n.k.

### Wireshark

> [!TIP]
> **Ikiwa uta-analyze PCAP, kimsingi lazima ujue jinsi ya kutumia Wireshark**

Unaweza kupata mbinu kadhaa za Wireshark katika:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Pcap analysis kutoka kwenye browser.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) ni network-forensics tool ya Unix-like inayodecode files za PCAP na inaweza ku-extract email kupitia POP/IMAP/SMTP, HTTP contents, SIP VoIP calls, FTP data, na TFTP data.<sup>[[6]](#references)</sup>

**Install**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
Endesha
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Ufikiaji wa _**127.0.0.1:9876**_ kwa credentials _**xplico:xplico**_

Kisha create **case** mpya, create **session** mpya ndani ya case hiyo na **upload** faili la **pcap**.

### NetworkMiner

Kama Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) huchanganua traffic ya PCAP ili kutoa artifacts kama vile faili, picha, barua pepe na passwords, na hukusanya taarifa za hosts; toleo lake lisilolipishwa ni hasa kwa Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Unaweza kupakua [**NetWitness Investigator kutoka hapa**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Inafanya kazi kwenye Windows)**.\
Vendor anaeleza freeware hiyo kama tool ya interactive network-session analysis kwa triage ya malicious activity, na kwa sasa anawasilisha access kupitia contact form.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Modules zilizoandikwa za BruteShark zinaweza kuchanganua credentials kutoka HTTP, FTP, Telnet, IMAP na SMTP, ku-export authentication hashes za Kerberos, NTLM, CRAM-MD5 na HTTP-Digest kwa Hashcat, ku-map network nodes na users, kutoa DNS queries, kujenga upya TCP/UDP sessions na ku-carve files.<sup>[[9]](#references)</sup>

### Capinfos

`capinfos` ya Wireshark huchapisha report ndefu ya capture file kwa default.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` hutafuta payload za packet kwa kutumia regular expressions na inakubali BPF filters; `-I` husoma capture file inayooana na pcap.<sup>[[11]](#references)</sup> Mfano huu unaunganisha vipengele hivyo kutafuta HTTP request katika traffic iliyochaguliwa.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Kutumia mbinu za kawaida za carving kunaweza kusaidia kutoa faili na taarifa kutoka kwenye pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Kukusanya credentials

Unaweza kutumia [PCredz](https://github.com/lgandx/PCredz) kuchanganua credentials kutoka kwenye faili ya PCAP iliyohifadhiwa au interface ya moja kwa moja.<sup>[[12]](#references)</sup>

## Kukagua Exploits/Malware

### Suricata

**Sakinisha na usanidi**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Kagua pcap**

Chaguo la `-r` la Suricata hucheza tena PCAP katika offline mode; katika mfano huu, `-k none` huzima ukaguzi wa checksum, `-v` huongeza logging, na `-l` huchagua saraka ya log.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) huchakata HTTP streams kutoka kwenye PCAP files, kwa hiari hufungua gzip streams, hukagua files zilizotolewa kwa YARA, huandika `report.txt`, na inaweza kuhifadhi files zinazolingana kwenye directory.<sup>[[14]](#references)</sup>

### Malware Analysis

Angalia kama unaweza kupata fingerprint yoyote ya malware inayojulikana:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) ni network traffic analyzer ya passive na open-source inayotumika kama Network Security Monitor (NSM) na kwa traffic analysis pana zaidi, ikijumuisha kupima utendaji na troubleshooting.<sup>[[15]](#references)</sup>

Zeek hutengeneza logs zilizopangwa badala ya PCAP files, kwa hivyo tumia log-analysis tools kama `zeek-cut` kukagua logs hizo.<sup>[[15]](#references)[[16]](#references)</sup>

### Connections Info

Mifano iliyo hapa chini hutumia `zeek-cut` kuchagua fields zilizopewa majina kutoka kwenye TSV logs, kisha Unix tools za kawaida kupanga na kuhesabu connections; RITA pia inaweza kuingiza Zeek logs kwa ajili ya uchanganuzi wa long-connection, beaconing, na DNS-tunneling.<sup>[[16]](#references)[[17]](#references)</sup>
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
### Taarifa za DNS
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
## Mbinu nyingine za uchanganuzi wa pcap


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

- [1] [Mwongozo wa Mtumiaji wa Wireshark: Kufungua Capture Files](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - huduma ya mtandaoni ya kurekebisha pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Muhtasari wa VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - Kuhusu](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Hazina ya BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Mwongozo wa `capinfos` wa Wireshark](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Nyaraka za ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Hazina ya PCredz](https://github.com/lgandx/PCredz)
- [13] [Chaguo za command-line za Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Hazina ya YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [Zeek ni nini?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Mafunzo ya logs za Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Hazina ya RITA](https://github.com/activecm/rita)
- [18] [Nyaraka za `editcap` za Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Tangazo la PacketTotal Upload API](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
