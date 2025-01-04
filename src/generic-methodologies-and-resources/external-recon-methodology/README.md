# Εξωτερική Μεθοδολογία Αναγνώρισης

{{#include ../../banners/hacktricks-training.md}}

## Ανακαλύψεις Περιουσιακών Στοιχείων

> Έτσι σας είπαν ότι όλα όσα ανήκουν σε μια εταιρεία είναι εντός του πεδίου εφαρμογής, και θέλετε να καταλάβετε τι πραγματικά κατέχει αυτή η εταιρεία.

Ο στόχος αυτής της φάσης είναι να αποκτήσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **περιουσιακά στοιχεία** αυτών των εταιρειών. Για να το κάνουμε αυτό, θα:

1. Βρούμε τις εξαγορές της κύριας εταιρείας, αυτό θα μας δώσει τις εταιρείες εντός του πεδίου εφαρμογής.
2. Βρούμε το ASN (αν υπάρχει) κάθε εταιρείας, αυτό θα μας δώσει τις περιοχές IP που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε αναζητήσεις reverse whois για να ψάξουμε για άλλες καταχωρίσεις (ονόματα οργανισμών, τομείς...) σχετικές με την πρώτη (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιήσουμε άλλες τεχνικές όπως τα φίλτρα shodan `org` και `ssl` για να ψάξουμε για άλλα περιουσιακά στοιχεία (το κόλπο `ssl` μπορεί να γίνει αναδρομικά).

### **Εξαγορές**

Πρώτα απ' όλα, πρέπει να ξέρουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφθείτε [https://www.crunchbase.com/](https://www.crunchbase.com), **να αναζητήσετε** την **κύρια εταιρεία**, και **να κάνετε κλικ** στις "**εξαγορές**". Εκεί θα δείτε άλλες εταιρείες που αποκτήθηκαν από την κύρια.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα **Wikipedia** της κύριας εταιρείας και να αναζητήσετε **εξαγορές**.

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζετε όλες τις εταιρείες εντός του πεδίου εφαρμογής. Ας δούμε πώς να βρούμε τα περιουσιακά τους στοιχεία.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που αποδίδεται σε ένα **αυτόνομο σύστημα** (AS) από την **Αρχή Ανάθεσης Αριθμών Διαδικτύου (IANA)**.\
Ένα **AS** αποτελείται από **μπλοκ** **διευθύνσεων IP** που έχουν μια σαφώς καθορισμένη πολιτική για την πρόσβαση σε εξωτερικά δίκτυα και διοικούνται από μια μόνο οργάνωση αλλά μπορεί να αποτελείται από αρκετούς φορείς.

Είναι ενδιαφέρον να βρούμε αν η **εταιρεία έχει αναθέσει κάποιο ASN** για να βρούμε τις **περιοχές IP της.** Θα είναι ενδιαφέρον να εκτελέσουμε μια **δοκιμή ευπάθειας** σε όλους τους **φιλοξενούμενους** εντός του **πεδίου εφαρμογής** και **να αναζητήσουμε τομείς** μέσα σε αυτές τις IPs.\
Μπορείτε να **αναζητήσετε** με το όνομα της εταιρείας, με **IP** ή με **τομέα** στο [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Ανάλογα με την περιοχή της εταιρείας, αυτοί οι σύνδεσμοι θα μπορούσαν να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Ούτως ή άλλως, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(περιοχές IP και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** η αναγνώριση υποτομέων συγκεντρώνει και συνοψίζει αυτόματα τα ASNs στο τέλος της σάρωσης.
```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```
Μπορείτε να βρείτε τα εύρη IP μιας οργάνωσης χρησιμοποιώντας επίσης [http://asnlookup.com/](http://asnlookup.com) (έχει δωρεάν API).\
Μπορείτε να βρείτε το IP και το ASN ενός τομέα χρησιμοποιώντας [http://ipv4info.com/](http://ipv4info.com).

### **Αναζητώντας ευπάθειες**

Σε αυτό το σημείο γνωρίζουμε **όλα τα περιουσιακά στοιχεία εντός του πεδίου**, οπότε αν έχετε άδεια, μπορείτε να εκκινήσετε κάποιο **σάρωσης ευπαθειών** (Nessus, OpenVAS) σε όλους τους υπολογιστές.\
Επίσης, μπορείτε να εκκινήσετε κάποιες [**σάρωσεις θυρών**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως** shodan **για να βρείτε** ανοιχτές θύρες **και ανάλογα με το τι θα βρείτε, θα πρέπει να** ρίξετε μια ματιά σε αυτό το βιβλίο για το πώς να κάνετε pentest σε πολλές πιθανές υπηρεσίες που τρέχουν.\
**Επίσης, αξίζει να αναφερθεί ότι μπορείτε επίσης να προετοιμάσετε κάποιες** λίστες με προεπιλεγμένα ονόματα χρήστη **και** κωδικούς πρόσβασης **και να προσπαθήσετε να** κάνετε bruteforce υπηρεσίες με [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Τομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του πεδίου και τα περιουσιακά τους στοιχεία, ήρθε η ώρα να βρούμε τους τομείς εντός του πεδίου.

_Παρακαλώ σημειώστε ότι στις παρακάτω προτεινόμενες τεχνικές μπορείτε επίσης να βρείτε υποτομείς και αυτή η πληροφορία δεν θα πρέπει να υποτιμάται._

Πρώτα απ' όλα, θα πρέπει να αναζητήσετε τον **κύριο τομέα**(ες) κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι _tesla.com_.

### **Αντίστροφη DNS**

Καθώς έχετε βρει όλα τα εύρη IP των τομέων, μπορείτε να προσπαθήσετε να εκτελέσετε **αντίστροφες αναζητήσεις dns** σε αυτές τις **IPs για να βρείτε περισσότερους τομείς εντός του πεδίου**. Προσπαθήστε να χρησιμοποιήσετε κάποιον dns server του θύματος ή κάποιον γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online εργαλείο για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com)

### **Αντίστροφος Whois (loop)**

Μέσα σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες** όπως **όνομα οργανισμού**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Αλλά το πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα περιουσιακά στοιχεία που σχετίζονται με την εταιρεία** αν εκτελέσετε **αντίστροφες αναζητήσεις whois με οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα άλλες καταχωρίσεις whois όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** web, όχι δωρεάν API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Όχι δωρεάν
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Όχι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Όχι δωρεάν

Μπορείτε να αυτοματοποιήσετε αυτή την εργασία χρησιμοποιώντας [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτεί κλειδί API whoxy).\
Μπορείτε επίσης να εκτελέσετε κάποια αυτόματη ανακάλυψη αντίστροφου whois με [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτή την τεχνική για να ανακαλύψετε περισσότερα ονόματα τομέα κάθε φορά που βρίσκετε ένα νέο τομέα.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** διαχειρίζονται από την **ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε πολλές σελίδες.

Υπάρχουν κάποιες σελίδες και εργαλεία που σας επιτρέπουν να αναζητήσετε με αυτούς τους trackers και περισσότερα:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε σχετικούς τομείς και υποτομείς με τον στόχο μας αναζητώντας το ίδιο hash εικονιδίου favicon; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) που δημιούργησε ο [@m4ll0k2](https://twitter.com/m4ll0k2). Να πώς να το χρησιμοποιήσετε:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ανακαλύψτε τομείς με το ίδιο hash εικονιδίου favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Απλά, το favihash θα μας επιτρέψει να ανακαλύψουμε τομείς που έχουν το ίδιο hash εικονιδίου favicon με τον στόχο μας.

Επιπλέον, μπορείτε επίσης να αναζητήσετε τεχνολογίες χρησιμοποιώντας το hash του favicon όπως εξηγείται σε [**αυτή την ανάρτηση blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Αυτό σημαίνει ότι αν γνωρίζετε το **hash του favicon μιας ευάλωτης έκδοσης μιας διαδικτυακής τεχνολογίας** μπορείτε να αναζητήσετε αν στο shodan και **να βρείτε περισσότερες ευάλωτες τοποθεσίες**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Αυτός είναι ο τρόπος με τον οποίο μπορείτε να **υπολογίσετε το hash του favicon** ενός ιστότοπου:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
### **Copyright / Uniq string**

Αναζητήστε μέσα στις ιστοσελίδες **αλφαριθμητικούς χαρακτήρες που θα μπορούσαν να μοιραστούν σε διάφορες ιστοσελίδες της ίδιας οργάνωσης**. Η **αλφαριθμητική δήλωση πνευματικών δικαιωμάτων** θα μπορούσε να είναι ένα καλό παράδειγμα. Στη συνέχεια, αναζητήστε αυτή τη δήλωση σε **google**, σε άλλους **προγράμματα περιήγησης** ή ακόμη και σε **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Είναι συνηθισμένο να υπάρχει μια εργασία cron όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
να ανανεώσετε όλα τα πιστοποιητικά τομέα στον διακομιστή. Αυτό σημαίνει ότι ακόμη και αν η CA που χρησιμοποιείται για αυτό δεν ορίζει την ώρα που δημιουργήθηκε στην περίοδο ισχύος, είναι δυνατόν να **βρείτε τομείς που ανήκουν στην ίδια εταιρεία στα αρχεία διαφάνειας πιστοποιητικών**.\
Δείτε αυτό το [**writeup για περισσότερες πληροφορίες**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Πληροφορίες DMARC Mail

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο όπως [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **τομείς και υποτομείς που μοιράζονται τις ίδιες πληροφορίες DMARC**.

### **Passive Takeover**

Φαίνεται ότι είναι κοινό για τους ανθρώπους να αναθέτουν υποτομείς σε IP που ανήκουν σε παρόχους cloud και σε κάποιο σημείο **να χάσουν αυτήν την διεύθυνση IP αλλά να ξεχάσουν να αφαιρέσουν την εγγραφή DNS**. Επομένως, απλά **δημιουργώντας μια VM** σε ένα cloud (όπως το Digital Ocean) θα **αναλαμβάνετε στην πραγματικότητα κάποιους υποτομείς**.

[**Αυτή η ανάρτηση**](https://kmsec.uk/blog/passive-takeover/) εξηγεί μια ιστορία σχετικά με αυτό και προτείνει ένα σενάριο που **δημιουργεί μια VM στο DigitalOcean**, **παίρνει** την **IPv4** της νέας μηχανής και **αναζητά σε Virustotal για εγγραφές υποτομέων** που δείχνουν σε αυτήν.

### **Άλλοι τρόποι**

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύψετε περισσότερα ονόματα τομέων κάθε φορά που βρίσκετε έναν νέο τομέα.**

**Shodan**

Όπως ήδη γνωρίζετε το όνομα της οργάνωσης που κατέχει τον χώρο IP. Μπορείτε να αναζητήσετε με αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους βρεθέντες διακομιστές για νέους απροσδόκητους τομείς στο πιστοποιητικό TLS.

Μπορείτε να αποκτήσετε το **πιστοποιητικό TLS** της κύριας ιστοσελίδας, να αποκτήσετε το **όνομα Οργάνωσης** και στη συνέχεια να αναζητήσετε αυτό το όνομα μέσα στα **πιστοποιητικά TLS** όλων των ιστοσελίδων που είναι γνωστές από το **shodan** με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) είναι ένα εργαλείο που αναζητά **τομείς σχετικούς** με έναν κύριο τομέα και **υποτομείς** αυτών, αρκετά εκπληκτικό.

### **Αναζητώντας ευπάθειες**

Ελέγξτε για κάποια [ανάληψη τομέα](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία να **χρησιμοποιεί κάποιον τομέα** αλλά να **έχει χάσει την ιδιοκτησία**. Απλά καταχωρίστε τον (αν είναι αρκετά φθηνός) και ενημερώστε την εταιρεία.

Αν βρείτε οποιονδήποτε **τομέα με μια IP διαφορετική** από αυτές που έχετε ήδη βρει στην ανακάλυψη περιουσιακών στοιχείων, θα πρέπει να εκτελέσετε μια **βασική σάρωση ευπαθειών** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποια [**σάρωση θυρών**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για να "επιτεθείτε" σε αυτές**.\
&#xNAN;_&#x4E;ote ότι μερικές φορές ο τομέας φιλοξενείται μέσα σε μια IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι στο πεδίο εφαρμογής, να είστε προσεκτικοί._

## Υποτομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του πεδίου εφαρμογής, όλα τα περιουσιακά στοιχεία κάθε εταιρείας και όλους τους τομείς που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλους τους πιθανούς υποτομείς κάθε βρεθέντος τομέα.

> [!TIP]
> Σημειώστε ότι ορισμένα από τα εργαλεία και τις τεχνικές για την εύρεση τομέων μπορούν επίσης να βοηθήσουν στην εύρεση υποτομέων

### **DNS**

Ας προσπαθήσουμε να αποκτήσουμε **υποτομείς** από τις **εγγραφές DNS**. Πρέπει επίσης να προσπαθήσουμε για **Μεταφορά Ζώνης** (Αν είναι ευάλωτη, θα πρέπει να την αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο ταχύτερος τρόπος για να αποκτήσετε πολλούς υποτομείς είναι η αναζήτηση σε εξωτερικές πηγές. Τα πιο χρησιμοποιούμενα **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα ρυθμίστε τα κλειδιά API):

- [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
- [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
- [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
- [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
- [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
- [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
- [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
- [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Υπάρχουν **άλλα ενδιαφέροντα εργαλεία/APIs** που, ακόμη και αν δεν είναι άμεσα εξειδικευμένα στην εύρεση υποτομέων, θα μπορούσαν να είναι χρήσιμα για την εύρεση υποτομέων, όπως:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για να αποκτήσει υποτομείς
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC δωρεάν API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) δωρεάν API
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
- [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστές διευθύνσεις URL από το Open Threat Exchange της AlienVault, το Wayback Machine και το Common Crawl για οποιοδήποτε δεδομένο τομέα.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Ψάχνουν στο διαδίκτυο για αρχεία JS και εξάγουν υποτομείς από εκεί.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
- [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
- [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) έχει δωρεάν API για αναζήτηση υποτομέων και ιστορικό IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το έργο προσφέρει **δωρεάν όλους τους υποτομείς που σχετίζονται με προγράμματα bug-bounty**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα χρησιμοποιώντας επίσης [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμα και να αποκτήσετε πρόσβαση στο πεδίο που χρησιμοποιείται από αυτό το έργο [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέους **υποτομείς** κάνοντας brute-force στους DNS servers χρησιμοποιώντας πιθανά ονόματα υποτομέων.

Για αυτή την ενέργεια θα χρειαστείτε μερικές **κοινές λίστες λέξεων υποτομέων όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Και επίσης IPs καλών DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers μπορείτε να κατεβάσετε τους resolvers από [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) και να χρησιμοποιήσετε [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Ή μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο συνιστώμενα εργαλεία για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτέλεσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε ψευδώς θετικά αποτελέσματα.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί μόνο 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε go, που σας επιτρέπει να καταγράφετε έγκυρους υποτομείς χρησιμοποιώντας ενεργό bruteforce, καθώς και να επιλύετε υποτομείς με διαχείριση wildcard και εύκολη υποστήριξη εισόδου-εξόδου.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης το `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί το asyncio για να κάνει brute force σε ονόματα τομέα ασύγχρονα.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Δεύτερος Γύρος Brute-Force DNS

Αφού έχετε βρει υποτομείς χρησιμοποιώντας ανοιχτές πηγές και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των υποτομέων που βρήκατε για να προσπαθήσετε να βρείτε ακόμη περισσότερους. Πολλά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δίνοντας τους τομείς και τους υποτομείς, δημιουργεί παραλλαγές.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Δίνοντας τα domains και subdomains, δημιουργεί παραλλαγές.
- Μπορείτε να αποκτήσετε τις παραλλαγές του goaltdns **wordlist** [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Δίνοντας τα domains και subdomains, δημιουργεί παραλλαγές. Αν δεν υποδειχθεί αρχείο παραλλαγών, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από την παραγωγή παραλλαγών υποτομέων, μπορεί επίσης να προσπαθήσει να τις επιλύσει (αλλά είναι καλύτερο να χρησιμοποιήσετε τα προηγούμενα εργαλεία που αναφέρθηκαν).
- Μπορείτε να αποκτήσετε παραλλαγές altdns **wordlist** [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμα εργαλείο για την εκτέλεση παραλλαγών, μεταλλάξεων και τροποποιήσεων υποτομέων. Αυτό το εργαλείο θα εκτελέσει brute force στο αποτέλεσμα (δεν υποστηρίζει dns wild card).
- Μπορείτε να αποκτήσετε τη λίστα λέξεων παραλλαγών dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Βασισμένο σε έναν τομέα, **δημιουργεί νέα πιθανά ονόματα υποτομέων** με βάση τις υποδεικνυόμενες προτύπες για να προσπαθήσει να ανακαλύψει περισσότερους υποτομείς.

#### Έξυπνη γενιά παραλλαγών

- [**regulator**](https://github.com/cramppet/regulator): Για περισσότερες πληροφορίες διαβάστε αυτήν την [**ανάρτηση**](https://cramppet.github.io/regulator/index.html) αλλά βασικά θα πάρει τα **κύρια μέρη** από τους **ανακαλυφθέντες υποτομείς** και θα τα αναμίξει για να βρει περισσότερους υποτομείς.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένα εργαλείο brute-force για υποτομείς που συνδυάζεται με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από την απάντηση DNS. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως μια προσαρμοσμένη λίστα λέξεων ή ιστορικά αρχεία DNS/TLS, για να συνθέσει με ακρίβεια περισσότερα αντίστοιχα ονόματα τομέων και να τα επεκτείνει ακόμη περισσότερο σε έναν βρόχο με βάση τις πληροφορίες που συλλέγονται κατά τη διάρκεια της σάρωσης DNS.
```
echo www | subzuf facebook.com
```
### **Ροή Εργασίας Ανακάλυψης Υποτομέων**

Δείτε αυτή την ανάρτηση στο blog που έγραψα σχετικά με το πώς να **αυτοματοποιήσετε την ανακάλυψη υποτομέων** από έναν τομέα χρησιμοποιώντας **Trickest workflows** ώστε να μην χρειάζεται να εκκινώ χειροκίνητα μια σειρά εργαλείων στον υπολογιστή μου:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Εικονικοί Φιλοξενούμενοι**

Αν βρείτε μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** που ανήκουν σε υποτομείς, μπορείτε να προσπαθήσετε να **βρείτε άλλους υποτομείς με ιστοσελίδες σε αυτή την IP** αναζητώντας σε **πηγές OSINT** για τομείς σε μια IP ή **δοκιμάζοντας ονόματα τομέων VHost σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε μερικούς **VHosts σε IPs χρησιμοποιώντας** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλες APIs**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιος υποτομέας μπορεί να είναι κρυμμένος σε έναν διακομιστή ιστού, μπορείτε να προσπαθήσετε να τον δοκιμάσετε με brute force:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> Με αυτή την τεχνική μπορεί να είστε σε θέση να αποκτήσετε πρόσβαση σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν μόνο την κεφαλίδα _**Access-Control-Allow-Origin**_ όταν έχει οριστεί ένα έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτές τις περιπτώσεις, μπορείτε να εκμεταλλευτείτε αυτή τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Ενώ ψάχνετε για **subdomains**, προσέξτε αν **δείχνει** σε οποιοδήποτε τύπο **bucket**, και σε αυτή την περίπτωση [**ελέγξτε τις άδειες**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains μέσα στο πεδίο, προσπαθήστε να [**brute force πιθανές ονομασίες buckets και ελέγξτε τις άδειες**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Μπορείτε να **παρακολουθείτε** αν **δημιουργούνται νέα subdomains** ενός domain παρακολουθώντας τα **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Ελέγξτε για πιθανές [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**ελέγξτε τις άδειες**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρείτε οποιοδήποτε **subdomain με IP διαφορετική** από αυτές που έχετε ήδη βρει στην ανακάλυψη assets, θα πρέπει να εκτελέσετε μια **βασική σάρωση ευπαθειών** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποια [**σάρωση θυρών**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που τρέχουν, μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για να "επιτεθείτε" σε αυτές**.\
&#xNAN;_&#x4E;ote ότι μερικές φορές το subdomain φιλοξενείται σε μια IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι στο πεδίο, προσέξτε._

## IPs

Στα αρχικά βήματα μπορεί να έχετε **βρει κάποιες IP ranges, domains και subdomains**.\
Ήρθε η ώρα να **συλλέξετε όλες τις IPs από αυτές τις ranges** και για τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας υπηρεσίες από τις παρακάτω **δωρεάν APIs** μπορείτε επίσης να βρείτε **προηγούμενες IPs που χρησιμοποιήθηκαν από domains και subdomains**. Αυτές οι IPs μπορεί να ανήκουν ακόμα στον πελάτη (και μπορεί να σας επιτρέψουν να βρείτε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να ελέγξετε για domains που δείχνουν σε μια συγκεκριμένη διεύθυνση IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Σαρώστε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μην βρείτε τίποτα ενδιαφέρον εκεί). Στις υπηρεσίες που ανακαλύφθηκαν μπορεί να είστε **σε θέση να βρείτε ευπάθειες**.

**Βρείτε έναν** [**οδηγό**](../pentesting-network/index.html) **για το πώς να σαρώσετε hosts.**

## Web servers hunting

> Έχουμε βρει όλες τις εταιρείες και τα assets τους και γνωρίζουμε IP ranges, domains και subdomains μέσα στο πεδίο. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα έχετε πιθανώς ήδη εκτελέσει κάποια **recon των IPs και domains που ανακαλύφθηκαν**, οπότε μπορεί να έχετε **ήδη βρει όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, τώρα θα δούμε μερικά **γρήγορα κόλπα για να αναζητήσουμε web servers** μέσα στο πεδίο.

Παρακαλώ σημειώστε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, οπότε θα πρέπει να **εκτελέσετε τη σάρωση ευπαθειών** και **σάρωση θυρών** επίσης (**αν επιτρέπεται** από το πεδίο).

Μια **γρήγορη μέθοδος** για να ανακαλύψετε **ανοιχτές θύρες** σχετικές με **web** servers χρησιμοποιώντας [**masscan** μπορεί να βρεθεί εδώ](../pentesting-network/index.html#http-port-discovery).\
Ένα άλλο φιλικό εργαλείο για να αναζητήσετε web servers είναι [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλά περάστε μια λίστα domains και θα προσπαθήσει να συνδεθεί στις θύρες 80 (http) και 443 (https). Επιπλέον, μπορείτε να υποδείξετε να δοκιμάσει άλλες θύρες:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Στιγμιότυπα**

Τώρα που έχετε ανακαλύψει **όλους τους διακομιστές ιστού** που υπάρχουν στο πεδίο (μεταξύ των **IP** της εταιρείας και όλων των **τομέων** και **υποτομέων**) πιθανόν **να μην ξέρετε από πού να ξεκινήσετε**. Έτσι, ας το κάνουμε απλό και ας ξεκινήσουμε απλά παίρνοντας στιγμιότυπα όλων τους. Απλά με το **να ρίξετε μια ματιά** στη **κύρια σελίδα** μπορείτε να βρείτε **παράξενες** διευθύνσεις που είναι πιο **επιρρεπείς** να είναι **ευάλωτες**.

Για να εκτελέσετε την προτεινόμενη ιδέα μπορείτε να χρησιμοποιήσετε [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε να χρησιμοποιήσετε [**eyeballer**](https://github.com/BishopFox/eyeballer) για να ελέγξετε όλα τα **στιγμιότυπα** και να σας πει **τι είναι πιθανό να περιέχει ευπάθειες**, και τι όχι.

## Δημόσια Περιουσιακά Στοιχεία Cloud

Για να βρείτε πιθανά περιουσιακά στοιχεία cloud που ανήκουν σε μια εταιρεία θα πρέπει να **ξεκινήσετε με μια λίστα λέξεων-κλειδιών που προσδιορίζουν αυτή την εταιρεία**. Για παράδειγμα, για μια κρυπτονομισματική εταιρεία μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης λίστες λέξεων με **κοινές λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις θα πρέπει να δημιουργήσετε **παραλλαγές** (δείτε το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τις προκύπτουσες λίστες λέξεων μπορείτε να χρησιμοποιήσετε εργαλεία όπως [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Θυμηθείτε ότι όταν ψάχνετε για περιουσιακά στοιχεία Cloud θα πρέπει να **ψάχνετε για περισσότερα από απλά buckets σε AWS**.

### **Αναζητώντας ευπάθειες**

Αν βρείτε πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions** θα πρέπει να **τα αποκτήσετε πρόσβαση** και να δείτε τι σας προσφέρουν και αν μπορείτε να τα εκμεταλλευτείτε.

## Emails

Με τους **τομείς** και **υποτομείς** μέσα στο πεδίο έχετε βασικά όλα όσα **χρειάζεστε για να ξεκινήσετε την αναζήτηση για emails**. Αυτές είναι οι **APIs** και **εργαλεία** που έχουν λειτουργήσει καλύτερα για μένα για να βρω emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
- API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
- API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζητώντας ευπάθειες**

Τα emails θα φανούν χρήσιμα αργότερα για **brute-force web logins και auth services** (όπως το SSH). Επίσης, είναι απαραίτητα για **phishings**. Επιπλέον, αυτές οι APIs θα σας δώσουν ακόμα περισσότερες **πληροφορίες για το άτομο** πίσω από το email, που είναι χρήσιμες για την εκστρατεία phishing.

## Διαρροές Διαπιστευτηρίων

Με τους **τομείς,** **υποτομείς**, και **emails** μπορείτε να αρχίσετε να ψάχνετε για διαπιστευτήρια που έχουν διαρρεύσει στο παρελθόν που ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζητώντας ευπάθειες**

Αν βρείτε **έγκυρα διαρρεύσαντα** διαπιστευτήρια, αυτό είναι μια πολύ εύκολη νίκη.

## Διαρροές Μυστικών

Οι διαρροές διαπιστευτηρίων σχετίζονται με επιθέσεις σε εταιρείες όπου **ευαίσθητες πληροφορίες διαρρεύσαν και πωλήθηκαν**. Ωστόσο, οι εταιρείες μπορεί να επηρεαστούν από **άλλες διαρροές** των οποίων οι πληροφορίες δεν είναι σε αυτές τις βάσεις δεδομένων:

### Διαρροές Github

Διαπιστευτήρια και APIs μπορεί να έχουν διαρρεύσει στις **δημόσιες αποθήκες** της **εταιρείας** ή των **χρηστών** που εργάζονται για αυτή την εταιρεία στο github.\
Μπορείτε να χρησιμοποιήσετε το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλες τις **δημόσιες αποθήκες** μιας **οργάνωσης** και των **προγραμματιστών** της και να εκτελέσετε [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω τους αυτόματα.

**Leakos** μπορεί επίσης να χρησιμοποιηθεί για να εκτελέσει **gitleaks** σε όλο το **κείμενο** που παρέχεται **URLs που του έχουν περαστεί** καθώς μερικές φορές **οι ιστοσελίδες περιέχουν επίσης μυστικά**.

#### Github Dorks

Ελέγξτε επίσης αυτή τη **σελίδα** για πιθανούς **github dorks** που θα μπορούσατε επίσης να αναζητήσετε στην οργάνωση που επιτίθεστε:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Διαρροές Pastes

Μερικές φορές οι επιτιθέμενοι ή απλώς οι εργαζόμενοι θα **δημοσιεύσουν περιεχόμενο της εταιρείας σε μια ιστοσελίδα paste**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά είναι πολύ ενδιαφέρον να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για να αναζητήσετε σε περισσότερες από 80 ιστοσελίδες paste ταυτόχρονα.

### Google Dorks

Οι παλιοί αλλά χρυσοί google dorks είναι πάντα χρήσιμοι για να βρείτε **εκτεθειμένες πληροφορίες που δεν θα έπρεπε να υπάρχουν εκεί**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανές ερωτήσεις που δεν μπορείτε να εκτελέσετε χειροκίνητα. Έτσι, μπορείτε να πάρετε τις 10 αγαπημένες σας ή να χρησιμοποιήσετε ένα **εργαλείο όπως** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τις εκτελέσετε όλες**.

_Σημειώστε ότι τα εργαλεία που αναμένονται να εκτελέσουν όλη τη βάση δεδομένων χρησιμοποιώντας τον κανονικό περιηγητή Google δεν θα τελειώσουν ποτέ καθώς η Google θα σας μπλοκάρει πολύ πολύ σύντομα._

### **Αναζητώντας ευπάθειες**

Αν βρείτε **έγκυρα διαρρεύσαντα** διαπιστευτήρια ή API tokens, αυτή είναι μια πολύ εύκολη νίκη.

## Δημόσιες Ευπάθειες Κώδικα

Αν διαπιστώσετε ότι η εταιρεία έχει **ανοιχτό κώδικα** μπορείτε να **αναλύσετε** αυτόν και να αναζητήσετε **ευπάθειες** σε αυτόν.

**Ανάλογα με τη γλώσσα** υπάρχουν διαφορετικά **εργαλεία** που μπορείτε να χρησιμοποιήσετε:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Υπάρχουν επίσης δωρεάν υπηρεσίες που σας επιτρέπουν να **σκανάρετε δημόσιες αποθήκες**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειοψηφία των ευπαθειών** που βρίσκονται από κυνηγούς σφαλμάτων βρίσκεται μέσα σε **web applications**, οπότε σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία δοκιμών web εφαρμογών**, και μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω μια ειδική αναφορά στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, αν δεν πρέπει να περιμένετε να σας βρουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για να τα εφαρμόσετε σε **ροές εργασίας για να έχετε κάποιες αρχικές πληροφορίες ιστού.**

## Ανακεφαλαίωση

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη εκτελέσει **όλη την βασική καταμέτρηση**. Ναι, είναι βασική γιατί μπορεί να γίνει πολύ περισσότερη καταμέτρηση (θα δούμε περισσότερα κόλπα αργότερα).

Έτσι έχετε ήδη:

1. Βρει όλους τους **τομείς** μέσα στο πεδίο
2. Βρει όλα τα **περιουσιακά στοιχεία** που ανήκουν στις εταιρείες (και εκτελέσει κάποια σάρωση ευπαθειών αν είναι στο πεδίο)
3. Βρει όλους τους **τομείς** που ανήκουν στις εταιρείες
4. Βρει όλους τους **υποτομείς** των τομέων (κάποια κατάληψη υποτομέα;)
5. Βρει όλες τις **IP** (από και **όχι από CDNs**) μέσα στο πεδίο.
6. Βρει όλους τους **διακομιστές ιστού** και πήρε ένα **στιγμιότυπο** από αυτούς (κάτι παράξενο που αξίζει μια πιο βαθιά ματιά;)
7. Βρει όλα τα **πιθανά δημόσια περιουσιακά στοιχεία cloud** που ανήκουν στην εταιρεία.
8. **Emails**, **διαρροές διαπιστευτηρίων**, και **διαρροές μυστικών** που θα μπορούσαν να σας δώσουν μια **μεγάλη νίκη πολύ εύκολα**.
9. **Pentesting όλων των ιστότοπων που βρήκατε**

## **Πλήρη Αυτόματα Εργαλεία Αναγνώρισης**

Υπάρχουν αρκετά εργαλεία εκεί έξω που θα εκτελέσουν μέρος των προτεινόμενων ενεργειών κατά ενός δεδομένου πεδίου.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και όχι ενημερωμένο

## **Αναφορές**

- Όλα τα δωρεάν μαθήματα του [**@Jhaddix**](https://twitter.com/Jhaddix) όπως [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
