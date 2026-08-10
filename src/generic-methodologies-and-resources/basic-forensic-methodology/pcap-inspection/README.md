# Επιθεώρηση Pcap

> [!TIP]
> Τα **PCAP** και **PCAPNG** είναι διαφορετικές μορφές capture· το **PCAPNG είναι ένας ευέλικτος και επεκτάσιμος διάδοχος του PCAP**, αλλά η υποστήριξη διαφέρει ανάλογα με τα εργαλεία. Αν ένα εργαλείο δεν μπορεί να διαβάσει PCAPNG, μετατρέψτε το σε PCAP με το Wireshark ή άλλο συμβατό εργαλείο.<sup>[[1]](#references)[[18]](#references)</sup>

## Online εργαλεία για pcaps

- Αν το header του pcap σας είναι **κατεστραμμένο**, θα πρέπει να προσπαθήσετε να το **διορθώσετε** χρησιμοποιώντας το: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Εξαγάγετε **πληροφορίες** και αναζητήστε **malware** μέσα σε ένα pcap στο [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Αναζητήστε **κακόβουλη δραστηριότητα** χρησιμοποιώντας τα [**www.virustotal.com**](https://www.virustotal.com) και [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Πλήρης ανάλυση pcap από τον browser στο** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Εξαγωγή πληροφοριών

Τα παρακάτω εργαλεία είναι χρήσιμα για την εξαγωγή στατιστικών, αρχείων κ.λπ.

### Wireshark

> [!TIP]
> **Αν πρόκειται να αναλύσετε ένα PCAP, βασικά πρέπει να γνωρίζετε πώς να χρησιμοποιείτε το Wireshark**

Μπορείτε να βρείτε μερικά Wireshark tricks στο:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Ανάλυση pcap από τον browser.<sup>[[5]](#references)</sup>

### Xplico Framework

Το [**Xplico**](https://github.com/xplico/xplico) είναι ένα Unix-like εργαλείο network-forensics που αποκωδικοποιεί αρχεία PCAP και μπορεί να εξαγάγει email μέσω POP/IMAP/SMTP, περιεχόμενο HTTP, κλήσεις SIP VoIP, δεδομένα FTP και δεδομένα TFTP.<sup>[[6]](#references)</sup>

**Εγκατάσταση**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Εκτέλεση**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Πρόσβαση στο _**127.0.0.1:9876**_ με credentials _**xplico:xplico**_

Στη συνέχεια δημιουργήστε ένα **new case**, δημιουργήστε ένα **new session** μέσα στο case και **ανεβάστε** το αρχείο **pcap**.

### NetworkMiner

Όπως το Xplico, το [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) αναλύει την κίνηση PCAP για να εξαγάγει artifacts όπως αρχεία, εικόνες, email και passwords, ενώ συγκεντρώνει πληροφορίες για hosts· η δωρεάν έκδοσή του προορίζεται κυρίως για Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Μπορείτε να κατεβάσετε το [**NetWitness Investigator από εδώ**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Λειτουργεί σε Windows)**.\
Ο vendor περιγράφει το freeware ως ένα interactive εργαλείο ανάλυσης network-session για triage κακόβουλης δραστηριότητας και προς το παρόν παρέχει πρόσβαση μέσω contact form.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Τα documented modules του BruteShark μπορούν να αναλύσουν credentials από HTTP, FTP, Telnet, IMAP και SMTP, να εξαγάγουν authentication hashes Kerberos, NTLM, CRAM-MD5 και HTTP-Digest για το Hashcat, να χαρτογραφήσουν network nodes και users, να εξαγάγουν DNS queries, να ανακατασκευάσουν TCP/UDP sessions και να κάνουν carve αρχεία.<sup>[[9]](#references)</sup>

### Capinfos

Το `capinfos` του Wireshark εκτυπώνει από προεπιλογή μια εκτενή αναφορά για ένα capture file.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

Το `ngrep` αναζητά payloads πακέτων με regular expressions και δέχεται BPF filters· το `-I` διαβάζει ένα pcap-compatible capture file.<sup>[[11]](#references)</sup> Το παράδειγμα συνδυάζει αυτές τις δυνατότητες για να αναζητήσει ένα HTTP request στην επιλεγμένη κίνηση.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Η χρήση κοινών τεχνικών carving μπορεί να είναι χρήσιμη για την εξαγωγή αρχείων και πληροφοριών από το pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Λήψη διαπιστευτηρίων

Μπορείτε να χρησιμοποιήσετε το [PCredz](https://github.com/lgandx/PCredz) για την ανάλυση διαπιστευτηρίων από ένα αποθηκευμένο αρχείο PCAP ή από ένα live interface.<sup>[[12]](#references)</sup>

## Έλεγχος Exploits/Malware

### Suricata

**Εγκατάσταση και ρύθμιση**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Έλεγχος pcap**

Η επιλογή `-r` του Suricata αναπαράγει ένα PCAP σε λειτουργία offline· σε αυτό το παράδειγμα, η επιλογή `-k none` απενεργοποιεί τους ελέγχους checksum, η `-v` αυξάνει την καταγραφή και η `-l` επιλέγει τον κατάλογο logs.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

Το [**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) επεξεργάζεται HTTP streams από αρχεία PCAP, αποσυμπιέζει προαιρετικά gzip streams, σαρώνει τα extracted files με YARA, γράφει το `report.txt` και μπορεί να αποθηκεύσει τα matching files σε έναν κατάλογο.<sup>[[14]](#references)</sup>

### Ανάλυση Malware

Ελέγξτε αν μπορείτε να βρείτε κάποιο αποτύπωμα γνωστού malware:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> Το [Zeek](https://docs.zeek.org/en/master/about.html) είναι ένας παθητικός, open-source αναλυτής network traffic που χρησιμοποιείται ως Network Security Monitor (NSM) και για ευρύτερη ανάλυση traffic, συμπεριλαμβανομένης της μέτρησης απόδοσης και του troubleshooting.<sup>[[15]](#references)</sup>

Το Zeek δημιουργεί structured logs αντί για αρχεία PCAP, επομένως χρησιμοποιήστε εργαλεία log-analysis όπως το `zeek-cut` για την επιθεώρηση αυτών των logs.<sup>[[15]](#references)[[16]](#references)</sup>

### Πληροφορίες Connections

Τα παρακάτω παραδείγματα χρησιμοποιούν το `zeek-cut` για την επιλογή named fields από TSV logs και στη συνέχεια standard Unix tools για την κατάταξη και καταμέτρηση των connections· το RITA μπορεί επίσης να εισάγει Zeek logs για ανάλυση long-connection, beaconing και DNS-tunneling.<sup>[[16]](#references)[[17]](#references)</sup>
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
### Πληροφορίες DNS
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
## Άλλα κόλπα ανάλυσης pcap


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

- [1] [Οδηγός χρήστη του Wireshark: Άνοιγμα αρχείων capture](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - online υπηρεσία επιδιόρθωσης pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Επισκόπηση του VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - Σχετικά](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [Δωρεάν έκδοση του NetWitness Investigator](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Αποθετήριο του BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Εγχειρίδιο του Wireshark `capinfos`](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Τεκμηρίωση του ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Αποθετήριο του PCredz](https://github.com/lgandx/PCredz)
- [13] [Επιλογές γραμμής εντολών του Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Αποθετήριο του YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [Τι είναι το Zeek;](https://docs.zeek.org/en/master/about/what.html)
- [16] [Οδηγός εκμάθησης για τα logs του Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Αποθετήριο του RITA](https://github.com/activecm/rita)
- [18] [Τεκμηρίωση του Wireshark `editcap`](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Ανακοίνωση του PacketTotal Upload API](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
