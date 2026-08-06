# Pcap-Analyse

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> Ein Hinweis zu **PCAP** vs **PCAPNG**: Es gibt zwei Versionen des PCAP-Dateiformats; **PCAPNG ist neuer und wird nicht von allen Tools unterstützt**. Möglicherweise musst du eine Datei von PCAPNG in PCAP konvertieren, indem du Wireshark oder ein anderes kompatibles Tool verwendest, um sie mit einigen anderen Tools zu bearbeiten.

## Online-Tools für PCAPs

- Wenn der Header deines PCAP **beschädigt** ist, solltest du versuchen, ihn mit [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php) zu **reparieren**
- **Informationen** extrahieren und in einem PCAP nach **Malware** suchen mit [**PacketTotal**](https://packettotal.com)
- Mit [**www.virustotal.com**](https://www.virustotal.com) und [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) nach **schädlichen Aktivitäten** suchen
- **Vollständige PCAP-Analyse im Browser mit** [**https://apackets.com/**](https://apackets.com/)

## Informationen extrahieren

Die folgenden Tools sind nützlich, um Statistiken, Dateien usw. zu extrahieren.

### Wireshark

> [!TIP]
> **Wenn du einen PCAP analysieren möchtest, musst du grundsätzlich wissen, wie man Wireshark verwendet**

Einige Wireshark-Tricks findest du unter:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

PCAP-Analyse im Browser.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(nur Linux)_ kann einen **PCAP** **analysieren** und daraus Informationen extrahieren. Beispielsweise extrahiert Xplico aus einer PCAP-Datei jede E-Mail (POP-, IMAP- und SMTP-Protokolle), alle HTTP-Inhalte, jeden VoIP-Anruf (SIP), FTP, TFTP und so weiter.

**Installieren**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Ausführen**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Zugriff auf _**127.0.0.1:9876**_ mit den Zugangsdaten _**xplico:xplico**_

Erstelle anschließend einen **neuen Case**, erstelle eine **neue Session** innerhalb des Cases und **lade die pcap**-Datei hoch.

### NetworkMiner

Wie Xplico ist es ein Tool zum **Analysieren und Extrahieren von Objekten aus pcaps**. Es gibt eine kostenlose Edition, die du [**hier**](https://www.netresec.com/?page=NetworkMiner) **downloaden** kannst. Es funktioniert mit **Windows**.\
Dieses Tool ist auch nützlich, um **weitere analysierte Informationen** aus den Paketen zu erhalten und dadurch **schneller** herauszufinden, was passiert ist.

### NetWitness Investigator

Du kannst [**NetWitness Investigator hier downloaden**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(es funktioniert unter Windows)**.\
Dies ist ein weiteres nützliches Tool, das die **Pakete analysiert** und die Informationen auf nützliche Weise sortiert, um **herauszufinden, was im Inneren passiert**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Extrahieren und Encoden von Usernames und Passwörtern (HTTP, FTP, Telnet, IMAP, SMTP...)
- Authentifizierungs-Hashes extrahieren und mit Hashcat cracken (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Ein visuelles Netzwerkdiagramm erstellen (Netzwerk-Nodes & User)
- DNS-Abfragen extrahieren
- Alle TCP- & UDP-Sessions rekonstruieren
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Wenn du im pcap nach **etwas** **suchst**, kannst du **ngrep** verwenden. Hier ist ein Beispiel mit den wichtigsten Filtern:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Die Verwendung gängiger Carving-Techniken kann nützlich sein, um Dateien und Informationen aus dem pcap zu extrahieren:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Anmeldedaten erfassen

Du kannst Tools wie [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) verwenden, um Anmeldedaten aus einem pcap oder einer Live-Schnittstelle zu analysieren.

## Exploits/Malware überprüfen

### Suricata

**Installieren und einrichten**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**PCAP prüfen**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) ist ein Tool, das

- eine PCAP-Datei liest und HTTP-Streams extrahiert.
- komprimierte Streams mit gzip dekomprimiert
- jede Datei mit yara scannt
- eine report.txt schreibt
- passende Dateien optional in einem Verzeichnis speichert

### Malware Analysis

Prüfe, ob du einen Fingerabdruck bekannter Malware finden kannst:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) ist ein passiver, Open-Source-Netzwerktraffic-Analyzer. Viele Betreiber verwenden Zeek als Network Security Monitor (NSM), um Untersuchungen verdächtiger oder schädlicher Aktivitäten zu unterstützen. Zeek unterstützt außerdem eine große Bandbreite an Traffic-Analyseaufgaben außerhalb des Security-Bereichs, einschließlich Performancemessung und Troubleshooting.

Grundsätzlich sind von `zeek` erstellte Logs keine **pcaps**. Daher musst du **andere Tools** verwenden, um die Logs zu analysieren, in denen sich die **Informationen** über die pcaps befinden.

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
### DNS-Information
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
## Weitere Tricks zur pcap-Analyse


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
