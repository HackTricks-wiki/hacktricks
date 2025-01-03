# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Μια σημείωση σχετικά με το **PCAP** και το **PCAPNG**: υπάρχουν δύο εκδόσεις της μορφής αρχείου PCAP; **Το PCAPNG είναι πιο νέο και δεν υποστηρίζεται από όλα τα εργαλεία**. Μπορεί να χρειαστεί να μετατρέψετε ένα αρχείο από PCAPNG σε PCAP χρησιμοποιώντας το Wireshark ή κάποιο άλλο συμβατό εργαλείο, προκειμένου να εργαστείτε με αυτό σε κάποια άλλα εργαλεία.

## Online tools for pcaps

- Αν η κεφαλίδα του pcap σας είναι **κατεστραμμένη**, θα πρέπει να προσπαθήσετε να την **διορθώσετε** χρησιμοποιώντας: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Εξαγάγετε **πληροφορίες** και αναζητήστε **malware** μέσα σε ένα pcap στο [**PacketTotal**](https://packettotal.com)
- Αναζητήστε **κακόβουλη δραστηριότητα** χρησιμοποιώντας [**www.virustotal.com**](https://www.virustotal.com) και [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
- **Πλήρης ανάλυση pcap από τον περιηγητή στο** [**https://apackets.com/**](https://apackets.com/)

## Extract Information

Τα παρακάτω εργαλεία είναι χρήσιμα για την εξαγωγή στατιστικών, αρχείων κ.λπ.

### Wireshark

> [!NOTE]
> **Αν πρόκειται να αναλύσετε ένα PCAP, πρέπει βασικά να ξέρετε πώς να χρησιμοποιείτε το Wireshark**

Μπορείτε να βρείτε μερικά κόλπα του Wireshark στο:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Ανάλυση pcap από τον περιηγητή.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(μόνο linux)_ μπορεί να **αναλύσει** ένα **pcap** και να εξαγάγει πληροφορίες από αυτό. Για παράδειγμα, από ένα αρχείο pcap, το Xplico εξάγει κάθε email (πρωτόκολλα POP, IMAP και SMTP), όλα τα περιεχόμενα HTTP, κάθε κλήση VoIP (SIP), FTP, TFTP, κ.λπ.

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
Η πρόσβαση στο _**127.0.0.1:9876**_ με διαπιστευτήρια _**xplico:xplico**_

Στη συνέχεια, δημιουργήστε μια **νέα υπόθεση**, δημιουργήστε μια **νέα συνεδρία** μέσα στην υπόθεση και **ανεβάστε το pcap** αρχείο.

### NetworkMiner

Όπως το Xplico, είναι ένα εργαλείο για **ανάλυση και εξαγωγή αντικειμένων από pcaps**. Έχει μια δωρεάν έκδοση που μπορείτε να **κατεβάσετε** [**εδώ**](https://www.netresec.com/?page=NetworkMiner). Λειτουργεί με **Windows**.\
Αυτό το εργαλείο είναι επίσης χρήσιμο για να αποκτήσετε **άλλες πληροφορίες που αναλύονται** από τα πακέτα προκειμένου να γνωρίζετε τι συνέβαινε με **ταχύτερο** τρόπο.

### NetWitness Investigator

Μπορείτε να κατεβάσετε [**NetWitness Investigator από εδώ**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Λειτουργεί σε Windows)**.\
Αυτό είναι ένα άλλο χρήσιμο εργαλείο που **αναλύει τα πακέτα** και ταξινομεί τις πληροφορίες με χρήσιμο τρόπο για να **γνωρίζετε τι συμβαίνει μέσα**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Εξαγωγή και κωδικοποίηση ονομάτων χρηστών και κωδικών πρόσβασης (HTTP, FTP, Telnet, IMAP, SMTP...)
- Εξαγωγή κατακερματισμένων κωδικών αυθεντικοποίησης και σπάσιμο τους χρησιμοποιώντας το Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Δημιουργία οπτικού διαγράμματος δικτύου (Κόμβοι δικτύου & χρήστες)
- Εξαγωγή ερωτημάτων DNS
- Ανακατασκευή όλων των TCP & UDP Συνεδριών
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Αν **ψάχνετε** για **κάτι** μέσα στο pcap μπορείτε να χρησιμοποιήσετε το **ngrep**. Ακολουθεί ένα παράδειγμα χρησιμοποιώντας τα κύρια φίλτρα:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Η χρήση κοινών τεχνικών carving μπορεί να είναι χρήσιμη για την εξαγωγή αρχείων και πληροφοριών από το pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) για να αναλύσετε διαπιστευτήρια από ένα pcap ή μια ζωντανή διεπαφή.

## Check Exploits/Malware

### Suricata

**Εγκατάσταση και ρύθμιση**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Έλεγχος pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) είναι ένα εργαλείο που

- Διαβάζει ένα αρχείο PCAP και εξάγει ροές Http.
- Το gzip αποσυμπιέζει οποιεσδήποτε συμπιεσμένες ροές
- Σαρώσει κάθε αρχείο με yara
- Γράφει ένα report.txt
- Προαιρετικά αποθηκεύει τα αρχεία που ταιριάζουν σε έναν φάκελο

### Malware Analysis

Ελέγξτε αν μπορείτε να βρείτε οποιοδήποτε αποτύπωμα γνωστού κακόβουλου λογισμικού:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) είναι ένας παθητικός, ανοιχτού κώδικα αναλυτής δικτυακής κίνησης. Πολλοί χειριστές χρησιμοποιούν το Zeek ως Δίκτυο Ασφαλείας Monitor (NSM) για να υποστηρίξουν τις έρευνες για ύποπτη ή κακόβουλη δραστηριότητα. Το Zeek υποστηρίζει επίσης μια ευρεία γκάμα εργασιών ανάλυσης κίνησης πέρα από τον τομέα της ασφάλειας, συμπεριλαμβανομένης της μέτρησης απόδοσης και της αποσφαλμάτωσης.

Βασικά, τα αρχεία καταγραφής που δημιουργούνται από το `zeek` δεν είναι **pcaps**. Επομένως, θα χρειαστεί να χρησιμοποιήσετε **άλλα εργαλεία** για να αναλύσετε τα αρχεία καταγραφής όπου οι **πληροφορίες** σχετικά με τα pcaps είναι.

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
## Άλλες τεχνικές ανάλυσης pcap

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
