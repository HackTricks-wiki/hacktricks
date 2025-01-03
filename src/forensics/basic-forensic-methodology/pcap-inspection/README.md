# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Kumbuka kuhusu **PCAP** dhidi ya **PCAPNG**: kuna toleo mbili za muundo wa faili wa PCAP; **PCAPNG ni mpya na haikubaliwi na zana zote**. Unaweza kuhitaji kubadilisha faili kutoka PCAPNG hadi PCAP kwa kutumia Wireshark au zana nyingine zinazofaa, ili kufanya kazi nayo katika zana nyingine.

## Zana za mtandaoni za pcaps

- Ikiwa kichwa cha pcap yako ni **kilichovunjika** unapaswa kujaribu **kurekebisha** kwa kutumia: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Toa **habari** na tafuta **malware** ndani ya pcap katika [**PacketTotal**](https://packettotal.com)
- Tafuta **shughuli mbaya** kwa kutumia [**www.virustotal.com**](https://www.virustotal.com) na [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Toa Habari

Zana zifuatazo ni muhimu kutoa takwimu, faili, n.k.

### Wireshark

> [!NOTE]
> **Ikiwa unakusudia kuchambua PCAP lazima ujue jinsi ya kutumia Wireshark**

Unaweza kupata hila za Wireshark katika:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(tu linux)_ inaweza **kuchambua** **pcap** na kutoa habari kutoka kwake. Kwa mfano, kutoka kwa faili ya pcap Xplico, inatoa kila barua pepe (protokali za POP, IMAP, na SMTP), maudhui yote ya HTTP, kila simu ya VoIP (SIP), FTP, TFTP, na kadhalika.

**Sakinisha**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Kimbia**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Kupata _**127.0.0.1:9876**_ kwa akauti _**xplico:xplico**_

Kisha tengeneza **kesi mpya**, tengeneza **sehemu mpya** ndani ya kesi na **pakia** faili ya pcap.

### NetworkMiner

Kama Xplico, ni chombo cha **kuchambua na kutoa vitu kutoka pcaps**. Ina toleo la bure ambalo unaweza **kupakua** [**hapa**](https://www.netresec.com/?page=NetworkMiner). Inafanya kazi na **Windows**.\
Chombo hiki pia ni muhimu kupata **habari nyingine zilizochambuliwa** kutoka kwa pakiti ili uweze kujua kilichokuwa kinaendelea kwa **njia ya haraka**.

### NetWitness Investigator

Unaweza kupakua [**NetWitness Investigator kutoka hapa**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Inafanya kazi kwenye Windows)**.\
Hiki ni chombo kingine muhimu ambacho **kuchambua pakiti** na kupanga habari kwa njia inayofaa ili **kujua kinachoendelea ndani**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Kutolewa na kuandika majina ya watumiaji na nywila (HTTP, FTP, Telnet, IMAP, SMTP...)
- Toa hash za uthibitishaji na uzivunje kwa kutumia Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Jenga mchoro wa mtandao wa kuona (Vituo vya Mtandao & watumiaji)
- Toa maswali ya DNS
- Rejesha kila Kikao cha TCP & UDP
- Kukata Faili

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Ikiwa unatafuta **kitu** ndani ya pcap unaweza kutumia **ngrep**. Hapa kuna mfano ukitumia vichujio vikuu:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Kutumia mbinu za kawaida za carving kunaweza kuwa na manufaa kutoa faili na taarifa kutoka pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Unaweza kutumia zana kama [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) kuchambua credentials kutoka pcap au interface ya moja kwa moja.

## Check Exploits/Malware

### Suricata

**Install and setup**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Angalia pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) ni chombo ambacho

- Hutoa Faili la PCAP na Kutolewa kwa Mito ya Http.
- gzip inachambua mitiririko yoyote iliyoshinikizwa
- Inachunguza kila faili kwa kutumia yara
- Inaandika ripoti.txt
- Kwa hiari huhifadhi faili zinazolingana kwenye Dir

### Uchambuzi wa Malware

Angalia kama unaweza kupata alama yoyote ya malware inayojulikana:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) ni mchambuzi wa trafiki wa mtandao wa wazi na wa kupita. Wengi wa waendeshaji hutumia Zeek kama Msimamizi wa Usalama wa Mtandao (NSM) kusaidia uchunguzi wa shughuli za kushuku au zenye uhalifu. Zeek pia inasaidia aina mbalimbali za kazi za uchambuzi wa trafiki zaidi ya eneo la usalama, ikiwa ni pamoja na kipimo cha utendaji na kutatua matatizo.

Kimsingi, kumbukumbu zinazoundwa na `zeek` si **pcaps**. Hivyo utahitaji kutumia **vifaa vingine** kuchambua kumbukumbu ambapo **habari** kuhusu pcaps ziko. 

### Taarifa za Munganisho
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
## Njia Nyingine za Uchambuzi wa pcap

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
