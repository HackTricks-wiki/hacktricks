# Inspekcija Pcap datoteka

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> Napomena o **PCAP** u odnosu na **PCAPNG**: postoje dve verzije formata PCAP datoteka; **PCAPNG je noviji i ne podržavaju ga svi alati**. Možda ćete morati da konvertujete datoteku iz PCAPNG u PCAP pomoću Wireshark-a ili drugog kompatibilnog alata kako biste mogli da je koristite u nekim drugim alatima.

## Online alati za pcap datoteke

- Ako je zaglavlje vašeg pcap-a **oštećeno**, pokušajte da ga **popravite** pomoću: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Izdvojite **informacije** i pretražite **malware** unutar pcap datoteke pomoću alata [**PacketTotal**](https://packettotal.com)
- Pretražite **zlonamernu aktivnost** pomoću [**www.virustotal.com**](https://www.virustotal.com) i [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
- **Potpuna analiza pcap datoteke iz browser-a pomoću** [**https://apackets.com/**](https://apackets.com/)

## Izdvajanje informacija

Sledeći alati su korisni za izdvajanje statistika, datoteka itd.

### Wireshark

> [!TIP]
> **Ako ćete analizirati PCAP, praktično morate znati da koristite Wireshark**

Neke trikove za Wireshark možete pronaći na:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Analiza pcap datoteka iz browser-a.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(samo linux)_ može da **analizira** **pcap** i iz njega izdvoji informacije. Na primer, iz pcap datoteke Xplico izdvaja svaku email poruku (POP, IMAP i SMTP protokole), kompletan HTTP sadržaj, svaki VoIP poziv (SIP), FTP, TFTP i tako dalje.

**Instalacija**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Pokreni**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Pristupite _**127.0.0.1:9876**_ sa kredencijalima _**xplico:xplico**_

Zatim kreirajte **novi slučaj**, kreirajte **novu sesiju** unutar slučaja i **otpremite pcap** fajl.

### NetworkMiner

Kao i Xplico, to je alat za **analizu i ekstrakciju objekata iz pcap fajlova**. Ima besplatno izdanje koje možete **preuzeti** [**ovde**](https://www.netresec.com/?page=NetworkMiner). Radi na sistemu **Windows**.\
Ovaj alat je takođe koristan za dobijanje **drugih analiziranih informacija** iz paketa, kako biste mogli da saznate šta se dešavalo na **brži** način.

### NetWitness Investigator

[**NetWitness Investigator možete preuzeti ovde**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(radi na sistemu Windows)**.\
Ovo je još jedan koristan alat koji **analizira pakete** i sortira informacije na koristan način kako biste **saznali šta se dešava unutar** njih.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Ekstrakcija i kodiranje korisničkih imena i lozinki (HTTP, FTP, Telnet, IMAP, SMTP...)
- Ekstrakcija authentication hash-eva i njihovo razbijanje pomoću Hashcat-a (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Izrada vizuelnog mrežnog dijagrama (mrežni čvorovi i korisnici)
- Ekstrakcija DNS upita
- Rekonstrukcija svih TCP i UDP sesija
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Ako **tražite** **nešto** unutar pcap-a, možete koristiti **ngrep**. Evo primera koji koristi glavne filtere:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Korišćenje uobičajenih carving tehnika može biti korisno za izdvajanje fajlova i informacija iz pcap-a:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Hvatanje credentials-a

Možete koristiti alate kao što je [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) za parsiranje credentials-a iz pcap-a ili live interfejsa.

## Provera Exploits/Malware-a

### Suricata

**Instalacija i podešavanje**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Proveri pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) je alat koji

- Čita PCAP fajl i izdvaja HTTP streamove.
- gzip dekompresuje sve kompresovane streamove
- Skenira svaki fajl pomoću yara
- Upisuje report.txt
- Opciono čuva fajlove koji se podudaraju u direktorijum

### Analiza malvera

Proverite da li možete da pronađete neki fingerprint poznatog malvera:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) je pasivni, open-source analyzer mrežnog saobraćaja. Mnogi operateri koriste Zeek kao Network Security Monitor (NSM) za podršku istragama sumnjivih ili zlonamernih aktivnosti. Zeek takođe podržava širok raspon zadataka analize saobraćaja izvan domena bezbednosti, uključujući merenje performansi i rešavanje problema.

U osnovi, logovi koje kreira `zeek` nisu **pcaps**. Zato ćete morati da koristite **druge alate** za analizu logova u kojima se nalaze **informacije** o pcap fajlovima.

### Informacije o konekcijama
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
### DNS informacije
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
## Drugi trikovi za analizu pcap datoteka


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
