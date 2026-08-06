# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

Στο iptables, λίστες κανόνων γνωστές ως chains επεξεργάζονται διαδοχικά. Μεταξύ αυτών, τρεις κύριες chains υπάρχουν καθολικά, ενώ άλλες, όπως η NAT, ενδέχεται να υποστηρίζονται ανάλογα με τις δυνατότητες του συστήματος.

- **Input Chain**: Χρησιμοποιείται για τη διαχείριση της συμπεριφοράς των εισερχόμενων συνδέσεων.
- **Forward Chain**: Χρησιμοποιείται για τη διαχείριση εισερχόμενων συνδέσεων που δεν προορίζονται για το τοπικό σύστημα. Αυτό είναι συνηθισμένο σε συσκευές που λειτουργούν ως routers, όπου τα δεδομένα που λαμβάνονται προωθούνται σε άλλο προορισμό. Αυτή η chain είναι κυρίως σχετική όταν το σύστημα συμμετέχει σε routing, NATing ή παρόμοιες δραστηριότητες.
- **Output Chain**: Είναι αφιερωμένη στη ρύθμιση των εξερχόμενων συνδέσεων.

Αυτές οι chains διασφαλίζουν την ομαλή επεξεργασία της κίνησης δικτύου, επιτρέποντας τον καθορισμό λεπτομερών κανόνων που διέπουν τη ροή δεδομένων προς, μέσω και έξω από ένα σύστημα.
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

### Εγκατάσταση και Ρύθμιση
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
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
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
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
### Ορισμοί Κανόνων

[Από την τεκμηρίωση:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Ένας κανόνας/υπογραφή αποτελείται από τα εξής:

- Η **ενέργεια**, καθορίζει τι συμβαίνει όταν η υπογραφή ταιριάζει.
- Η **κεφαλίδα**, καθορίζει το πρωτόκολλο, τις διευθύνσεις IP, τις θύρες και την κατεύθυνση του κανόνα.
- Οι **επιλογές κανόνα**, καθορίζουν τις λεπτομέρειες του κανόνα.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Έγκυρες ενέργειες είναι**

- alert - δημιουργία alert
- pass - διακοπή περαιτέρω επιθεώρησης του packet
- **drop** - απόρριψη του packet και δημιουργία alert
- **reject** - αποστολή σφάλματος RST/ICMP unreachable στον αποστολέα του packet που ταιριάζει.
- rejectsrc - ίδιο με το _reject_
- rejectdst - αποστολή packet σφάλματος RST/ICMP στον παραλήπτη του packet που ταιριάζει.
- rejectboth - αποστολή packet σφάλματος RST/ICMP και στις δύο πλευρές της επικοινωνίας.

#### **Πρωτόκολλα**

- tcp (για tcp-traffic)
- udp
- icmp
- ip (το ip σημαίνει ‘all’ ή ‘any’)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh... (περισσότερα στα [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Διευθύνσεις Source και Destination

Υποστηρίζει ranges IP, negations και λίστα διευθύνσεων:

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Κάθε διεύθυνση IP εκτός από την 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Κάθε διεύθυνση IP εκτός από τις 1.1.1.1 και 1.1.1.2 |
| $HOME_NET                     | Η ρύθμιση του HOME_NET στο yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET και όχι HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 εκτός από την 10.0.0.5          |

#### Ports Source και Destination

Υποστηρίζει ranges ports, negations και λίστες ports

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

Είναι δυνατό να υποδειχθεί η κατεύθυνση της επικοινωνίας στην οποία εφαρμόζεται ο κανόνας:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Υπάρχουν **εκατοντάδες επιλογές** διαθέσιμες στο Suricata για την αναζήτηση του **συγκεκριμένου πακέτου** που ψάχνετε· εδώ θα αναφέρεται αν βρεθεί κάτι ενδιαφέρον. Δείτε την [**τεκμηρίωση** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)για περισσότερα!
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
{{#include ../../../banners/hacktricks-training.md}}
