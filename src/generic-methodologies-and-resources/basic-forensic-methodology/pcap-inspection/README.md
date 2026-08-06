# Pcap-inspeksie

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> 'n Nota oor **PCAP** vs **PCAPNG**: daar is twee weergawes van die PCAP-lêerformaat; **PCAPNG is nuwer en word nie deur alle tools ondersteun nie**. Jy moet dalk 'n lêer van PCAPNG na PCAP omskakel deur Wireshark of 'n ander versoenbare tool te gebruik om daarmee in sommige ander tools te werk.

## Aanlyn tools vir pcaps

- As die kopskrif van jou pcap **gebreek** is, moet jy probeer om dit reg te stel deur: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Onttrek **inligting** en soek vir **malware** binne 'n pcap in [**PacketTotal**](https://packettotal.com)
- Soek vir **kwaadwillige aktiwiteit** deur [**www.virustotal.com**](https://www.virustotal.com) en [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) te gebruik
- **Volledige pcap-analise vanuit die blaaier in** [**https://apackets.com/**](https://apackets.com/)

## Onttrek inligting

Die volgende tools is nuttig om statistieke, lêers, ensovoorts te onttrek.

### Wireshark

> [!TIP]
> **As jy 'n PCAP gaan analiseer, moet jy basies weet hoe om Wireshark te gebruik**

Jy kan sommige Wireshark-truuks vind in:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Pcap-analise vanuit die blaaier.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(slegs linux)_ kan 'n **pcap** **analiseer** en inligting daaruit onttrek. Byvoorbeeld, uit 'n pcap-lêer onttrek Xplico elke e-pos (POP-, IMAP- en SMTP-protokolle), alle HTTP-inhoud, elke VoIP-oproep (SIP), FTP, TFTP, en so meer.

**Installeer**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Voer uit**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Kry toegang tot _**127.0.0.1:9876**_ met die geloofsbriewe _**xplico:xplico**_

Skep dan 'n **nuwe case**, skep 'n **nuwe session** binne die case en **upload die pcap**-lêer.

### NetworkMiner

Soos Xplico is dit 'n hulpmiddel om **objects uit pcaps te analiseer en te onttrek**. Dit het 'n gratis uitgawe wat jy [**hier**](https://www.netresec.com/?page=NetworkMiner) kan **download**. Dit werk met **Windows**.\
Hierdie hulpmiddel is ook nuttig om **ander ontleedde inligting** uit die pakkette te verkry, sodat jy op 'n **vinniger** manier kan weet wat gebeur het.

### NetWitness Investigator

Jy kan [**NetWitness Investigator hier download**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Dit werk in Windows)**.\
Dit is nog 'n nuttige hulpmiddel wat die **pakkette analiseer** en die inligting op 'n nuttige manier sorteer om te **weet wat binne gebeur**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Onttrek en encode usernames en passwords (HTTP, FTP, Telnet, IMAP, SMTP...)
- Onttrek authentication hashes en crack hulle met Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Bou 'n visuele network diagram (Network nodes & users)
- Onttrek DNS queries
- Rekonstrueer alle TCP- en UDP-sessies
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

As jy op soek is na **iets** binne die pcap, kan jy **ngrep** gebruik. Hier is ’n voorbeeld wat die belangrikste filters gebruik:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Die gebruik van algemene carving-tegnieke kan nuttig wees om lêers en inligting uit die pcap te onttrek:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Jy kan tools soos [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) gebruik om credentials uit 'n pcap of 'n lewendige interface te ontleed.

## Kontroleer Exploits/Malware

### Suricata

**Installeer en stel op**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Kontroleer pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) is ’n tool wat

- ’n PCAP File lees en Http Streams onttrek.
- enige saamgeperste streams met gzip dekomprimeer
- elke file met yara skandeer
- ’n report.txt skryf
- opsioneel ooreenstemmende files in ’n Dir stoor

### Malware-analise

Kyk of jy enige vingerafdruk van bekende malware kan vind:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) is ’n passiewe, open-source network traffic analyzer. Baie operateurs gebruik Zeek as ’n Network Security Monitor (NSM) om ondersoeke van verdagte of kwaadwillige aktiwiteit te ondersteun. Zeek ondersteun ook ’n wye reeks traffic analysis-take buite die security-domein, insluitend prestasiemeting en troubleshooting.

Basies is logs wat deur `zeek` geskep word nie **pcaps** nie. Daarom sal jy **ander tools** moet gebruik om die logs te ontleed waarin die **information** oor die pcaps is.

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
### DNS-inligting
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
## Ander pcap-analise-truuks


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
