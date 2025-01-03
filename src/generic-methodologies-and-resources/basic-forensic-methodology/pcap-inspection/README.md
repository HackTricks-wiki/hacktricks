# Pcap Inspeksie

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> 'n Nota oor **PCAP** teenoor **PCAPNG**: daar is twee weergawes van die PCAP lêerformaat; **PCAPNG is nuwer en word nie deur alle gereedskap ondersteun nie**. Jy mag dalk 'n lêer van PCAPNG na PCAP moet omskakel met Wireshark of 'n ander kompatible gereedskap, om daarmee in sommige ander gereedskap te werk.

## Aanlyn gereedskap vir pcaps

- As die kop van jou pcap **gebroke** is, moet jy probeer om dit te **herstel** met: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Trek **inligting** uit en soek vir **kwaadaardige sagteware** binne 'n pcap in [**PacketTotal**](https://packettotal.com)
- Soek vir **kwaadaardige aktiwiteit** met [**www.virustotal.com**](https://www.virustotal.com) en [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
- **Volledige pcap analise vanaf die blaaier in** [**https://apackets.com/**](https://apackets.com/)

## Trek Inligting Uit

Die volgende gereedskap is nuttig om statistieke, lêers, ens. uit te trek.

### Wireshark

> [!NOTE]
> **As jy 'n PCAP gaan analiseer, moet jy basies weet hoe om Wireshark te gebruik**

Jy kan 'n paar Wireshark truuks vind in:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Pcap analise vanaf die blaaier.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(slegs linux)_ kan **analiseer** 'n **pcap** en inligting daaruit onttrek. Byvoorbeeld, uit 'n pcap lêer onttrek Xplico elke e-pos (POP, IMAP, en SMTP protokolle), al HTTP-inhoud, elke VoIP-oproep (SIP), FTP, TFTP, ensovoorts.

**Installeer**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Hardloop**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Toegang tot _**127.0.0.1:9876**_ met inligting _**xplico:xplico**_

Skep dan 'n **nuwe saak**, skep 'n **nuwe sessie** binne die saak en **laai die pcap** lêer op.

### NetworkMiner

Soos Xplico is dit 'n hulpmiddel om **te analiseer en voorwerpe uit pcaps te onttrek**. Dit het 'n gratis weergawe wat jy kan **aflaai** [**hier**](https://www.netresec.com/?page=NetworkMiner). Dit werk met **Windows**.\
Hierdie hulpmiddel is ook nuttig om **ander inligting te analiseer** uit die pakkette om te weet wat gebeur het op 'n **sneller** manier.

### NetWitness Investigator

Jy kan [**NetWitness Investigator van hier**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **aflaai (Dit werk in Windows)**.\
Dit is 'n ander nuttige hulpmiddel wat **die pakkette analiseer** en die inligting op 'n nuttige manier sorteer om **te weet wat binne gebeur**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Onttrek en kodeer gebruikersname en wagwoorde (HTTP, FTP, Telnet, IMAP, SMTP...)
- Onttrek verifikasie-hashes en kraak dit met Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Bou 'n visuele netwerkdiagram (Netwerk nodes & gebruikers)
- Onttrek DNS versoeke
- Herbou alle TCP & UDP Sessies
- Lêer Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

As jy **soek** na **iets** binne die pcap kan jy **ngrep** gebruik. Hier is 'n voorbeeld wat die hooffilters gebruik:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Die gebruik van algemene carving tegnieke kan nuttig wees om lêers en inligting uit die pcap te onttrek:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Jy kan gereedskap soos [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) gebruik om akrediteerbare inligting uit 'n pcap of 'n lewende koppelvlak te parse.

## Check Exploits/Malware

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

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) is 'n hulpmiddel wat

- 'n PCAP-lêer lees en Http-strome onttrek.
- gzip ontplof enige gecomprimeerde strome
- elke lêer met yara skandeer
- 'n report.txt skryf
- Opsioneel ooreenstemmende lêers na 'n gids stoor

### Malware Analysis

Kyk of jy enige vingerafdruk van 'n bekende malware kan vind:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) is 'n passiewe, oopbron netwerkverkeeranaliseerder. Baie operateurs gebruik Zeek as 'n Netwerk Sekuriteitsmoniter (NSM) om ondersoeke van verdagte of kwaadwillige aktiwiteite te ondersteun. Zeek ondersteun ook 'n wye reeks verkeeranalise take buite die sekuriteitsdomein, insluitend prestasiemeting en probleemoplossing.

Basies, logs wat deur `zeek` geskep word, is nie **pcaps** nie. Daarom sal jy **ander hulpmiddels** moet gebruik om die logs te analiseer waar die **inligting** oor die pcaps is.

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
## Ander pcap ontledings truuks

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
