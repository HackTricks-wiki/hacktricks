# Pcap-inspeksie

> [!TIP]
> **PCAP** en **PCAPNG** is onderskeie capture-formate; **PCAPNG is 'n buigsame, uitbreidbare opvolger van PCAP**, maar ondersteuning verskil tussen tools. As 'n tool nie PCAPNG kan lees nie, skakel dit om na PCAP met Wireshark of 'n ander versoenbare tool.<sup>[[1]](#references)[[18]](#references)</sup>

## Aanlyn tools vir pcaps

- As die header van jou pcap **gebreek** is, moet jy probeer om dit reg te **maak** deur: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php) te gebruik.<sup>[[2]](#references)</sup>
- Onttrek **inligting** en soek vir **malware** binne 'n pcap met [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Soek vir **kwaadwillige aktiwiteit** deur [**www.virustotal.com**](https://www.virustotal.com) en [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) te gebruik.<sup>[[3]](#references)[[4]](#references)</sup>
- **Volledige pcap-analise vanuit die browser in** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Onttrek inligting

Die volgende tools is nuttig om statistieke, lêers, ens. te onttrek.

### Wireshark

> [!TIP]
> **As jy 'n PCAP gaan analiseer, moet jy basies weet hoe om Wireshark te gebruik**

Jy kan 'n paar Wireshark-truuks vind in:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Pcap-analise vanuit die browser.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) is 'n Unix-agtige netwerkforensiese tool wat PCAP-lêers dekodeer en e-posse oor POP/IMAP/SMTP, HTTP-inhoud, SIP VoIP-oproepe, FTP-data en TFTP-data kan onttrek.<sup>[[6]](#references)</sup>

**Installeer**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Laat loop**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Toegang tot _**127.0.0.1:9876**_ met geloofsbriewe _**xplico:xplico**_

Skep dan 'n **new case**, skep 'n **new session** binne die case en **upload the pcap**-lêer.

### NetworkMiner

Soos Xplico ontleed [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) PCAP-verkeer om artifacts soos lêers, beelde, e-pos en wagwoorde te onttrek, en dit versamel host-inligting; sy gratis uitgawe is hoofsaaklik vir Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Jy kan [**NetWitness Investigator from here**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) aflaai **(It works in Windows)**.\
Die verskaffer beskryf die freeware as 'n interaktiewe network-session analysis tool vir die triage van malicious activity en bied tans toegang deur 'n contact form.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark se gedokumenteerde modules kan credentials uit HTTP, FTP, Telnet, IMAP en SMTP ontleed, Kerberos-, NTLM-, CRAM-MD5- en HTTP-Digest authentication hashes vir Hashcat uitvoer, network nodes en users karteer, DNS queries onttrek, TCP/UDP sessions herbou en lêers carve.<sup>[[9]](#references)</sup>

### Capinfos

Wireshark se `capinfos` druk by verstek 'n lang verslag vir 'n capture file uit.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` soek pakketinoud met reguliere uitdrukkings en aanvaar BPF-filters; `-I` lees ’n pcap-versoenbare capture-lêer.<sup>[[11]](#references)</sup> Die voorbeeld kombineer hierdie kenmerke om na ’n HTTP-versoek in geselekteerde verkeer te soek.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Die gebruik van algemene carving-tegnieke kan nuttig wees om lêers en inligting uit die pcap te onttrek:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Vang credentials vas

Jy kan [PCredz](https://github.com/lgandx/PCredz) gebruik om credentials uit ’n gestoorde PCAP-lêer of ’n lewendige koppelvlak te ontleed.<sup>[[12]](#references)</sup>

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

Suricata se `-r`-opsie speel 'n PCAP in vanlynmodus af; in hierdie voorbeeld deaktiveer `-k none` kontrolesomkontroles, verhoog `-v` logboekbesonderhede, en kies `-l` die logboekgids.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) verwerk HTTP-strome vanaf PCAP-lêers, dekomprimeer gzip-strome opsioneel, skandeer onttrekte lêers met YARA, skryf `report.txt`, en kan lêers wat ooreenstem, in ’n gids stoor.<sup>[[14]](#references)</sup>

### Malware-analise

Kyk of jy enige fingerprint van bekende malware kan vind:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) is ’n passiewe, open-source netwerkverkeersanaliseerder wat as ’n Network Security Monitor (NSM) en vir breër verkeersanalise, insluitend prestasiemeting en probleemoplossing, gebruik word.<sup>[[15]](#references)</sup>

Zeek genereer gestruktureerde logs eerder as PCAP-lêers, dus gebruik log-analise-nutsgoed soos `zeek-cut` om daardie logs te inspekteer.<sup>[[15]](#references)[[16]](#references)</sup>

### Verbindingsinligting

Die voorbeelde hieronder gebruik `zeek-cut` om benoemde velde uit TSV-logs te kies, en daarna standaard Unix-nutsgoed om verbindings te rangskik en te tel; RITA kan ook Zeek-logs inneem vir ontleding van lang verbindings, beaconing en DNS-tunneling.<sup>[[16]](#references)[[17]](#references)</sup>
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

## References

- [1] [Wireshark User's Guide: Maak vasgelêde lêers oop](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - aanlyn pcap / pcapng-hersteldiens](https://f00l.de/hacking/pcapfix.php)
- [3] [VirusTotal API v3-oorsig](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - Oor](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark-bewaarplek](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos`-handleiding](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep-dokumentasie](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz-bewaarplek](https://github.com/lgandx/PCredz)
- [13] [Suricata-opdragreëlopsies](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap-bewaarplek](https://github.com/kevthehermit/YaraPcap)
- [15] [Wat is Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek-logs-tutoriaal](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA-bewaarplek](https://github.com/activecm/rita)
- [18] [Wireshark `editcap`-dokumentasie](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Aankondiging van PacketTotal se Upload API](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
