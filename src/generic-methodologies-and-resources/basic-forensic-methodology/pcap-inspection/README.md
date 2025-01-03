# Pcap Inspekcija

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Napomena o **PCAP** vs **PCAPNG**: postoje dve verzije PCAP formata datoteka; **PCAPNG je noviji i nije podržan od svih alata**. Možda ćete morati da konvertujete datoteku iz PCAPNG u PCAP koristeći Wireshark ili neki drugi kompatibilni alat, kako biste mogli da radite s njom u nekim drugim alatima.

## Online alati za pcaps

- Ako je zaglavlje vašeg pcap-a **pokvareno**, trebali biste pokušati da ga **popravite** koristeći: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Ekstrahujte **informacije** i tražite **malver** unutar pcap-a u [**PacketTotal**](https://packettotal.com)
- Tražite **malicioznu aktivnost** koristeći [**www.virustotal.com**](https://www.virustotal.com) i [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
- **Potpuna pcap analiza iz pregledača u** [**https://apackets.com/**](https://apackets.com/)

## Ekstrahovanje informacija

Sledeći alati su korisni za ekstrakciju statistike, datoteka itd.

### Wireshark

> [!NOTE]
> **Ako planirate da analizirate PCAP, osnovno je da znate kako da koristite Wireshark**

Možete pronaći neke Wireshark trikove u:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Pcap analiza iz pregledača.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(samo linux)_ može **analizirati** **pcap** i ekstrahovati informacije iz njega. Na primer, iz pcap datoteke Xplico ekstrahuje svaku email poruku (POP, IMAP i SMTP protokoli), sav HTTP sadržaj, svaki VoIP poziv (SIP), FTP, TFTP, i tako dalje.

**Instalirajte**
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

Zatim kreirajte **novi slučaj**, kreirajte **novu sesiju** unutar slučaja i **otpremite pcap** datoteku.

### NetworkMiner

Poput Xplico, to je alat za **analizu i ekstrakciju objekata iz pcaps**. Ima besplatnu verziju koju možete **preuzeti** [**ovde**](https://www.netresec.com/?page=NetworkMiner). Radi sa **Windows**.\
Ovaj alat je takođe koristan za dobijanje **druge analizirane informacije** iz paketa kako biste mogli brže saznati šta se dešava.

### NetWitness Investigator

Možete preuzeti [**NetWitness Investigator odavde**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Radi na Windows)**.\
Ovo je još jedan koristan alat koji **analizira pakete** i sortira informacije na koristan način da **znate šta se dešava unutra**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Ekstrakcija i kodiranje korisničkih imena i lozinki (HTTP, FTP, Telnet, IMAP, SMTP...)
- Ekstrakcija autentifikacionih hash-ova i njihovo razbijanje pomoću Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Izrada vizuelnog dijagrama mreže (Mrežni čvorovi i korisnici)
- Ekstrakcija DNS upita
- Rekonstrukcija svih TCP i UDP sesija
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Ako **tražite** **nešto** unutar pcap-a, možete koristiti **ngrep**. Evo primera koji koristi glavne filtre:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Isecanje

Korišćenje uobičajenih tehnika isecanja može biti korisno za ekstrakciju fajlova i informacija iz pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Hvatanje kredencijala

Možete koristiti alate kao što je [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) za parsiranje kredencijala iz pcap-a ili sa aktivnog interfejsa.

## Proverite Eksploite/Malver

### Suricata

**Instalirajte i postavite**
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

- Čita PCAP datoteku i ekstrahuje Http tokove.
- gzip dekompresuje sve kompresovane tokove
- Skandira svaku datoteku sa yara
- Piše report.txt
- Opcionalno čuva odgovarajuće datoteke u direktorijum

### Malware Analysis

Proverite da li možete pronaći bilo koji otisak poznatog malvera:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) je pasivni, open-source analizator mrežnog saobraćaja. Mnogi operateri koriste Zeek kao Mrežni Sigurnosni Monitor (NSM) za podršku istragama sumnjivih ili zlonamernih aktivnosti. Zeek takođe podržava širok spektar zadataka analize saobraćaja van domena sigurnosti, uključujući merenje performansi i rešavanje problema.

U suštini, logovi koje kreira `zeek` nisu **pcaps**. Stoga ćete morati da koristite **druge alate** za analizu logova gde se nalaze **informacije** o pcaps. 

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
## Ostali trikovi analize pcap-a

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
