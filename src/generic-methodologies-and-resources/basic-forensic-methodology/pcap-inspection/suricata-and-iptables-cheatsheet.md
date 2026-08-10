# Suricata & Iptables: φυλλάδιο αναφοράς

## Iptables

### Αλυσίδες

Στο iptables, κάθε αλυσίδα είναι μια διαδοχική λίστα κανόνων αντιστοίχισης πακέτων. Ο προεπιλεγμένος πίνακας `filter` διαθέτει τις ενσωματωμένες αλυσίδες `INPUT`, `FORWARD` και `OUTPUT`· άλλοι πίνακες, όπως ο `nat`, ενδέχεται να είναι διαθέσιμοι ανάλογα με τη διαμόρφωση του kernel και τα φορτωμένα modules.<sup>[[1]](#references)</sup>

- **Αλυσίδα Input**: Χρησιμοποιείται για τη διαχείριση της συμπεριφοράς των εισερχόμενων συνδέσεων.
- **Αλυσίδα Forward**: Χρησιμοποιείται για τον χειρισμό εισερχόμενων συνδέσεων που δεν προορίζονται για το τοπικό σύστημα. Αυτό είναι σύνηθες σε συσκευές που λειτουργούν ως routers, όπου τα δεδομένα που λαμβάνονται προορίζονται να προωθηθούν σε άλλο προορισμό. Αυτή η αλυσίδα είναι κυρίως σχετική όταν το σύστημα συμμετέχει σε routing, NATing ή παρόμοιες δραστηριότητες.
- **Αλυσίδα Output**: Είναι αφιερωμένη στη ρύθμιση των εξερχόμενων συνδέσεων.

Αυτές οι αλυσίδες εξασφαλίζουν την orderly επεξεργασία της κίνησης δικτύου, επιτρέποντας τον καθορισμό λεπτομερών κανόνων που διέπουν τη ροή δεδομένων προς, μέσα από και έξω από ένα σύστημα.

Τα παραδείγματα αντιστοίχισης συμβολοσειρών χρησιμοποιούν την τυπική αντιστοίχιση `string`· η αντιστοίχιση κάνει διάκριση πεζών-κεφαλαίων, εκτός εάν παρέχεται το `--icase`, ενώ το `--algo` επιλέγει τη στρατηγική αναζήτησης BM ή KMP.<sup>[[2]](#references)</sup>
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Εγκατάσταση & Ρύθμιση

Οι εντολές πακέτων παρακάτω είναι συγκεκριμένες για κάθε distribution και release· ο επίσημος οδηγός εγκατάστασης τεκμηριώνει το Ubuntu PPA, τα Debian backports, τα πακέτα RPM και τη διαχείριση υπηρεσιών systemd.<sup>[[3]](#references)</sup>
```bash
# Package installation details vary by distribution and release; see References.
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update update-sources
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl start suricata
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure Suricata as an IPS
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
Η ακολουθία `suricata-update` ακολουθεί την τεκμηριωμένη ροή εργασίας του Suricata για τη λήψη, την καταχώριση, την ενεργοποίηση και τη φόρτωση πηγών κανόνων.<sup>[[4]](#references)</sup> Η εντολή `suricatasc` παραπάνω είναι μια τεκμηριωμένη μέθοδος επαναφόρτωσης κανόνων μέσω Unix socket χωρίς αποκλεισμό.<sup>[[8]](#references)</sup> Οι κανόνες NFQUEUE αποστέλλουν την τοπική εισερχόμενη/εξερχόμενη κίνηση στο Suricata, ενώ το `-q 0` επιλέγει την ουρά 0 για inline επεξεργασία.<sup>[[7]](#references)</sup>

### Ορισμοί κανόνων

Ένας κανόνας/υπογραφή του Suricata αποτελείται από τρία μέρη.<sup>[[5]](#references)</sup>

- Η **ενέργεια** καθορίζει τι συμβαίνει όταν υπάρχει αντιστοίχιση με την υπογραφή.
- Η **κεφαλίδα** επιλέγει το πρωτόκολλο, τις διευθύνσεις IP, τις θύρες και την κατεύθυνση.
- Οι **επιλογές κανόνα** καθορίζουν τις λεπτομέρειες που αφορούν τη συγκεκριμένη αντιστοίχιση.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Οι έγκυρες ενέργειες είναι**

- alert - δημιουργία alert
- pass - διακοπή περαιτέρω επιθεώρησης του packet
- **drop** - απόρριψη του packet και δημιουργία alert
- **reject** - αποστολή σφάλματος RST/ICMP unreachable στον αποστολέα του packet που ταιριάζει.
- rejectsrc - ίδιο με το _reject_
- rejectdst - αποστολή packet σφάλματος RST/ICMP στον παραλήπτη του packet που ταιριάζει.
- rejectboth - αποστολή packet σφαλμάτων RST/ICMP και στις δύο πλευρές της επικοινωνίας.

#### **Πρωτόκολλα**

- tcp (για tcp-traffic)
- udp
- icmp
- ip (το ip σημαίνει «όλα» ή «οποιοδήποτε»)
- _πρωτόκολλα layer7_: http, ftp, tls, smb, dns, ssh και άλλα.<sup>[[5]](#references)</sup>

#### Διευθύνσεις Πηγής και Προορισμού

Το Suricata υποστηρίζει ranges IP, άρνηση και ομαδοποιημένες λίστες διευθύνσεων.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Κάθε διεύθυνση IP εκτός από την 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Κάθε διεύθυνση IP εκτός από τις 1.1.1.1 και 1.1.1.2 |
| $HOME_NET                     | Η ρύθμισή σας για το HOME_NET στο yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET και όχι HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 εκτός από τη 10.0.0.5          |

#### Ports Πηγής και Προορισμού

Το Suricata υποστηρίζει ranges ports, άρνηση και λίστες ports.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | οποιαδήποτε διεύθυνση                            |
| \[80, 81, 82]   | τα ports 80, 81 και 82                     |
| \[80: 82]       | Range από το 80 έως το 82                  |
| \[1024: ]       | Από το 1024 έως τον υψηλότερο αριθμό port |
| !80             | Κάθε port εκτός από το 80                      |
| \[80:100,!99]   | Range από το 80 έως το 100, με εξαίρεση το 99 |
| \[1:80,!\[2,4]] | Range από το 1 έως το 80, εκτός από τα ports 2 και 4  |

#### Κατεύθυνση

Οι κανόνες του Suricata μπορούν να καθορίζουν την κατεύθυνση επικοινωνίας που αξιολογείται.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Λέξεις-κλειδιά

Τα παρακάτω παραδείγματα χρησιμοποιούν λέξεις-κλειδιά κανόνων του Suricata, συμπεριλαμβανομένων επιλογών για metadata, IP, ICMP, payload και application layer· η επίσημη τεκμηρίωση κανόνων καταγράφει αυτές τις κατηγορίες και τη σύνταξή τους.<sup>[[6]](#references)[[9]](#references)</sup>
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
## The replace modifier is IPS-only and operates on individual packets
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
## References

- [1] [iptables(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Εγκατάσταση — Τεκμηρίωση Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Διαχείριση κανόνων με Suricata-Update — Τεκμηρίωση Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Μορφή κανόνων — Τεκμηρίωση Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Λέξεις-κλειδιά Payload — Τεκμηρίωση Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Ρύθμιση IPS/inline για Linux — Τεκμηρίωση Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Επαναφορτώσεις κανόνων — Τεκμηρίωση Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Κανόνες Suricata — Τεκμηρίωση Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
