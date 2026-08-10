# Pcap-Analyse

> [!TIP]
> **PCAP** und **PCAPNG** sind unterschiedliche Capture-Formate; **PCAPNG ist ein flexibler, erweiterbarer Nachfolger von PCAP**, aber die Unterstützung variiert je nach Tool. Wenn ein Tool PCAPNG nicht lesen kann, konvertiere es mit Wireshark oder einem anderen kompatiblen Tool in PCAP.<sup>[[1]](#references)[[18]](#references)</sup>

## Online-Tools für PCAP-Dateien

- Wenn der Header deines PCAP **beschädigt** ist, solltest du versuchen, ihn mit [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php) zu **reparieren**.<sup>[[2]](#references)</sup>
- Extrahiere **Informationen** und suche in einem PCAP mit [**PacketTotal**](https://packettotal.com) nach **malware**.<sup>[[19]](#references)</sup>
- Suche mit [**www.virustotal.com**](https://www.virustotal.com) und [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) nach **bösartigen Aktivitäten**.<sup>[[3]](#references)[[4]](#references)</sup>
- **Vollständige PCAP-Analyse im Browser mit** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

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

PCAP-Analyse im Browser.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) ist ein Unix-ähnliches Tool für Netzwerkforensik, das PCAP-Dateien decodiert und E-Mails über POP/IMAP/SMTP, HTTP-Inhalte, SIP-VoIP-Anrufe, FTP-Daten und TFTP-Daten extrahieren kann.<sup>[[6]](#references)</sup>

**Installation**
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

Erstelle anschließend einen **neuen Fall**, erstelle innerhalb des Falls eine **neue Session** und **lade** die **pcap**-Datei **hoch**.

### NetworkMiner

Wie Xplico analysiert [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) PCAP-Datenverkehr, um Artefakte wie Dateien, Bilder, E-Mails und Passwörter zu extrahieren, und aggregiert Host-Informationen; die kostenlose Edition ist hauptsächlich für Windows verfügbar.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Du kannst [**NetWitness Investigator hier herunterladen**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(es funktioniert unter Windows)**.\
Der Anbieter beschreibt die Freeware als interaktives Tool zur Analyse von Network Sessions für die Triage bösartiger Aktivitäten und bietet den Zugriff derzeit über ein Kontaktformular an.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Die dokumentierten Module von BruteShark können Credentials aus HTTP, FTP, Telnet, IMAP und SMTP parsen, Kerberos-, NTLM-, CRAM-MD5- und HTTP-Digest-Authentifizierungshashes für Hashcat exportieren, Network Nodes und User abbilden, DNS-Abfragen extrahieren, TCP/UDP-Sessions rekonstruieren und Dateien carven.<sup>[[9]](#references)</sup>

### Capinfos

Wiresharks `capinfos` gibt standardmäßig einen ausführlichen Bericht für eine Capture-Datei aus.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` durchsucht Paket-Payloads mit regulären Ausdrücken und akzeptiert BPF-Filter; `-I` liest eine pcap-kompatible Capture-Datei ein.<sup>[[11]](#references)</sup> Das Beispiel kombiniert diese Funktionen, um in ausgewähltem Traffic nach einer HTTP-Anfrage zu suchen.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Die Verwendung gängiger Carving-Techniken kann nützlich sein, um Dateien und Informationen aus dem pcap zu extrahieren:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Anmeldedaten erfassen

Du kannst [PCredz](https://github.com/lgandx/PCredz) verwenden, um Anmeldedaten aus einer gespeicherten PCAP-Datei oder einer Live-Schnittstelle zu analysieren.<sup>[[12]](#references)</sup>

## Exploits/Malware überprüfen

### Suricata

**Installation und Einrichtung**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**PCAP prüfen**

Suricatas Option `-r` gibt eine PCAP-Datei im Offline-Modus wieder; in diesem Beispiel deaktiviert `-k none` die Prüfsummenüberprüfung, `-v` erhöht die Protokollierung und `-l` legt das Protokollverzeichnis fest.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) verarbeitet HTTP-Streams aus PCAP-Dateien, dekomprimiert optional gzip-Streams, scannt extrahierte Dateien mit YARA, schreibt `report.txt` und kann übereinstimmende Dateien in einem Verzeichnis speichern.<sup>[[14]](#references)</sup>

### Malware-Analyse

Prüfe, ob du einen Fingerabdruck bekannter Malware finden kannst:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) ist ein passiver, quelloffener Network-Traffic-Analyzer, der als Network Security Monitor (NSM) und für umfassendere Traffic-Analysen, einschließlich Leistungsmessung und Fehlerbehebung, eingesetzt wird.<sup>[[15]](#references)</sup>

Zeek erzeugt strukturierte Logs statt PCAP-Dateien. Verwende daher Log-Analyse-Tools wie `zeek-cut`, um diese Logs zu untersuchen.<sup>[[15]](#references)[[16]](#references)</sup>

### Verbindungsinformationen

Die folgenden Beispiele verwenden `zeek-cut`, um benannte Felder aus TSV-Logs auszuwählen, und anschließend standardmäßige Unix-Tools, um Verbindungen zu ordnen und zu zählen. RITA kann Zeek-Logs ebenfalls für die Analyse langer Verbindungen, von Beaconing und DNS-Tunneling einlesen.<sup>[[16]](#references)[[17]](#references)</sup>
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
## Andere Tricks zur pcap-Analyse


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

- [1] [Wireshark-Benutzerhandbuch: Capture-Dateien öffnen](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - Online-Reparaturservice für pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Übersicht über die VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - Über](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark-Repository](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark-`capinfos`-Handbuch](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [`ngrep`-Dokumentation](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz-Repository](https://github.com/lgandx/PCredz)
- [13] [Suricata-Kommandozeilenoptionen](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap-Repository](https://github.com/kevthehermit/YaraPcap)
- [15] [Was ist Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Tutorial zu Zeek-Logs](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA-Repository](https://github.com/activecm/rita)
- [18] [Wireshark-`editcap`-Dokumentation](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Ankündigung der PacketTotal Upload API](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
