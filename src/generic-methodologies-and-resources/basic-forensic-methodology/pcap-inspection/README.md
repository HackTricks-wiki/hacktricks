# Επιθεώρηση Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> Μια σημείωση σχετικά με τα **PCAP** και **PCAPNG**: υπάρχουν δύο εκδόσεις της μορφής αρχείων PCAP· το **PCAPNG είναι νεότερο και δεν υποστηρίζεται από όλα τα εργαλεία**. Ίσως χρειαστεί να μετατρέψετε ένα αρχείο από PCAPNG σε PCAP χρησιμοποιώντας το Wireshark ή άλλο συμβατό εργαλείο, ώστε να μπορέσετε να το χρησιμοποιήσετε σε ορισμένα άλλα εργαλεία.

## Online εργαλεία για pcaps

- Αν η κεφαλίδα του pcap σας είναι **κατεστραμμένη**, θα πρέπει να προσπαθήσετε να τη **διορθώσετε** χρησιμοποιώντας: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Εξαγάγετε **πληροφορίες** και αναζητήστε **malware** μέσα σε ένα pcap στο [**PacketTotal**](https://packettotal.com)
- Αναζητήστε **κακόβουλη δραστηριότητα** χρησιμοποιώντας τα [**www.virustotal.com**](https://www.virustotal.com) και [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
- **Πλήρης ανάλυση pcap από τον browser στο** [**https://apackets.com/**](https://apackets.com/)

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

Ανάλυση Pcap από τον browser.

### Xplico Framework

Το [**Xplico** ](https://github.com/xplico/xplico)_(μόνο linux)_ μπορεί να **αναλύσει** ένα **pcap** και να εξαγάγει πληροφορίες από αυτό. Για παράδειγμα, από ένα αρχείο pcap το Xplico εξάγει κάθε email (πρωτόκολλα POP, IMAP και SMTP), όλο το περιεχόμενο HTTP, κάθε κλήση VoIP (SIP), FTP, TFTP κ.ο.κ.

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

Στη συνέχεια δημιουργήστε μια **new case**, δημιουργήστε μια **new session** μέσα στην υπόθεση και **ανεβάστε το** αρχείο **pcap**.

### NetworkMiner

Όπως το Xplico, είναι ένα tool για **ανάλυση και εξαγωγή objects από pcaps**. Διαθέτει free edition που μπορείτε να **κατεβάσετε** [**εδώ**](https://www.netresec.com/?page=NetworkMiner). Λειτουργεί σε **Windows**.\
Αυτό το tool είναι επίσης χρήσιμο για τη λήψη **άλλων analysed πληροφοριών** από τα packets, ώστε να είναι δυνατή η **γρηγορότερη** κατανόηση του τι συνέβαινε.

### NetWitness Investigator

Μπορείτε να κατεβάσετε το [**NetWitness Investigator από εδώ**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Λειτουργεί σε Windows)**.\
Αυτό είναι ένα ακόμη χρήσιμο tool που **αναλύει τα packets** και ταξινομεί τις πληροφορίες με χρήσιμο τρόπο, ώστε να **γνωρίζετε τι συμβαίνει στο εσωτερικό**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Εξαγωγή και encoding usernames και passwords (HTTP, FTP, Telnet, IMAP, SMTP...)
- Εξαγωγή authentication hashes και crack με χρήση Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Δημιουργία visual network diagram (Network nodes & users)
- Εξαγωγή DNS queries
- Ανακατασκευή όλων των TCP & UDP Sessions
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Εάν **αναζητάτε** **κάτι** μέσα στο pcap, μπορείτε να χρησιμοποιήσετε το **ngrep**. Ακολουθεί ένα παράδειγμα που χρησιμοποιεί τα κύρια φίλτρα:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Η χρήση κοινών τεχνικών Carving μπορεί να είναι χρήσιμη για την εξαγωγή αρχείων και πληροφοριών από το pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) για την ανάλυση credentials από ένα pcap ή ένα live interface.

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
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) είναι ένα tool που

- Διαβάζει ένα αρχείο PCAP και εξάγει HTTP streams.
- Αποσυμπιέζει με gzip τυχόν compressed streams
- Σαρώνει κάθε αρχείο με yara
- Γράφει ένα report.txt
- Προαιρετικά αποθηκεύει τα αρχεία που ταιριάζουν σε ένα Dir

### Ανάλυση Malware

Ελέγξτε αν μπορείτε να βρείτε κάποιο fingerprint γνωστού Malware:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> Το [Zeek](https://docs.zeek.org/en/master/about.html) είναι ένας παθητικός, open-source αναλυτής κίνησης δικτύου. Πολλοί operators χρησιμοποιούν το Zeek ως Network Security Monitor (NSM) για την υποστήριξη ερευνών ύποπτης ή κακόβουλης δραστηριότητας. Το Zeek υποστηρίζει επίσης ένα ευρύ φάσμα εργασιών ανάλυσης κίνησης πέρα από τον τομέα της ασφάλειας, συμπεριλαμβανομένων των μετρήσεων απόδοσης και της αντιμετώπισης προβλημάτων.

Βασικά, τα logs που δημιουργούνται από το `zeek` δεν είναι **pcaps**. Επομένως, θα χρειαστεί να χρησιμοποιήσετε **άλλα εργαλεία** για να αναλύσετε τα logs, όπου βρίσκονται οι **πληροφορίες** σχετικά με τα pcaps.

### Πληροφορίες συνδέσεων
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
## Άλλα tricks ανάλυσης pcap


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
