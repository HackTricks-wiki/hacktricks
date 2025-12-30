# Εξωτερική Μεθοδολογία Recon

{{#include ../../banners/hacktricks-training.md}}

## Ανακαλύψεις περιουσιακών στοιχείων

> Σου είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία είναι εντός του scope, και θέλεις να ανακαλύψεις τι ακριβώς κατέχει αυτή η εταιρεία.

Ο σκοπός αυτής της φάσης είναι να εντοπιστούν όλες οι **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **περιουσιακά στοιχεία** αυτών των εταιρειών. Για να το κάνουμε αυτό, θα:

1. Βρούμε τις acquisitions της κύριας εταιρείας — αυτό θα μας δείξει τις εταιρείες εντός του scope.
2. Βρούμε το ASN (αν υπάρχει) κάθε εταιρείας — αυτό θα μας δώσει τα εύρη IP που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε reverse whois lookups για να αναζητήσουμε άλλες εγγραφές (ονόματα οργανισμών, domains...) σχετικές με την αρχική (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιήσουμε άλλες τεχνικές όπως shodan `org` και `ssl` filters για να αναζητήσουμε άλλα assets (το `ssl` trick μπορεί να γίνει αναδρομικά).

### **Acquisitions**

Πρώτα απ' όλα, πρέπει να ξέρουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφθείτε [https://www.crunchbase.com/](https://www.crunchbase.com), να **search** για την **κύρια εταιρεία**, και να **click** στο "**acquisitions**". Εκεί θα δείτε άλλες εταιρείες που έχει αποκτήσει η κύρια.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα της **Wikipedia** της κύριας εταιρείας και να αναζητήσετε **acquisitions**.\
Για δημόσιες εταιρείες, ελέγξτε **SEC/EDGAR filings**, σελίδες **investor relations**, ή τοπικά μητρώα εταιρειών (π.χ. **Companies House** στο ΗΒ).\
Για παγκόσμια corporate trees και θυγατρικές, δοκιμάστε **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζετε όλες τις εταιρείες εντός του scope. Ας δούμε πώς θα βρούμε τα assets τους.

### **ASNs**

Ένας autonomous system number (**ASN**) είναι ένας **μοναδικός αριθμός** που ανατίθεται σε ένα **autonomous system** (AS) από το **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** διευθύνσεων **IP** που έχουν σαφώς ορισμένη πολιτική για πρόσβαση σε εξωτερικά δίκτυα και διοικούνται από μία οργάνωση αλλά μπορεί να απαρτίζονται από πολλούς operators.

Είναι χρήσιμο να βρούμε αν η **εταιρεία έχει αναθέσει κάποιο ASN** για να εντοπίσουμε τα **εύρη IP** της. Είναι επίσης ενδιαφέρον να πραγματοποιηθεί ένας **vulnerability test** σε όλους τους **hosts** εντός του **scope** και να **αναζητηθούν domains** μέσα σε αυτά τα IP.\
Μπορείτε να **search** με το όνομα της εταιρείας, με **IP** ή με **domain** στα [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή της εταιρείας, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για περισσότερα δεδομένα:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Σε κάθε περίπτωση, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(IP ranges και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration αυτόματα συγκεντρώνει και συνοψίζει ASNs στο τέλος του scan.
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (έχει δωρεάν API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets inside the scope**, οπότε αν έχετε άδεια μπορείτε να τρέξετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να πραγματοποιήσετε μερικά [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως** Shodan, Censys, ή ZoomEye **για να βρείτε** ανοικτές θύρες **και ανάλογα με αυτά που θα βρείτε θα πρέπει να** ρίξετε μια ματιά σε αυτό το βιβλίο για το πώς να pentest διάφορες πιθανές υπηρεσίες που τρέχουν.\
**Επίσης, αξίζει να αναφερθεί ότι μπορείτε να προετοιμάσετε κάποιες** default username **και** passwords **λίστες και να προσπαθήσετε να** bruteforce υπηρεσίες με [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες inside the scope και τα assets τους, είναι ώρα να βρούμε τα domains inside the scope.

_Παρακαλώ σημειώστε ότι στις παρακάτω προτεινόμενες τεχνικές μπορείτε επίσης να βρείτε subdomains και ότι αυτή η πληροφορία δεν πρέπει να υποτιμηθεί._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλα τα IP ranges των domains μπορείτε να προσπαθήσετε να εκτελέσετε **reverse dns lookups** σε εκείνα τα **IPs για να βρείτε περισσότερα domains εντός του scope**. Προσπαθήστε να χρησιμοποιήσετε κάποιο dns server του victim ή κάποιο γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online εργαλείο για αυτή την πληροφορία: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλες περιοχές, εργαλεία όπως [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του enrichment.

### **Reverse Whois (loop)**

Μέσα σε ένα **whois** μπορείτε να βρείτε πολλά ενδιαφέροντα **στοιχεία** όπως **όνομα οργανισμού**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Ακόμα πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα assets σχετιζόμενα με την εταιρεία** αν πραγματοποιήσετε **reverse whois lookups με οποιοδήποτε από αυτά τα πεδία** (π.χ. άλλα whois μητρώα όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Δωρεάν** web, όχι δωρεάν API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Όχι δωρεάν
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Όχι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Όχι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Όχι δωρεάν (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Όχι δωρεάν (API)

Μπορείτε να αυτοματοποιήσετε αυτήν την εργασία χρησιμοποιώντας [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
Μπορείτε επίσης να κάνετε κάποια αυτόματη reverse whois ανακάλυψη με [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτή την τεχνική για να ανακαλύπτετε περισσότερα ονόματα domain κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** είναι **διαχειριζόμενες από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε πολλές σελίδες.

Υπάρχουν κάποιες σελίδες και εργαλεία που επιτρέπουν αναζήτηση βάσει αυτών των trackers και όχι μόνο:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (βρίσκει σχετικές ιστοσελίδες με κοινά analytics/trackers)

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε σχετικά domains και subdomains με το στόχο μας κοιτώντας για το ίδιο favicon icon hash; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) του [@m4ll0k2](https://twitter.com/m4ll0k2). Εδώ πώς το χρησιμοποιείτε:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash θα μας επιτρέψει να ανακαλύψουμε domains που έχουν το ίδιο favicon icon hash με τον στόχο μας.

Επιπλέον, μπορείτε επίσης να αναζητήσετε τεχνολογίες χρησιμοποιώντας το favicon hash όπως εξηγείται στο [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Αυτό σημαίνει ότι αν γνωρίζετε το **hash of the favicon of a vulnerable version of a web tech** μπορείτε να το αναζητήσετε στο shodan και **find more vulnerable places**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Έτσι μπορείτε να **calculate the favicon hash** μιας ιστοσελίδας:
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
Μπορείτε επίσης να λάβετε favicon hashes σε μεγάλη κλίμακα με [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και στη συνέχεια να κάνετε pivot σε Shodan/Censys.

### **Πνευματικά Δικαιώματα / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που θα μπορούσαν να μοιράζονται ανάμεσα σε διαφορετικές ιστοσελίδες της ίδιας οργάνωσης**. Η **συμβολοσειρά πνευματικών δικαιωμάτων** θα μπορούσε να είναι ένα καλό παράδειγμα. Στη συνέχεια αναζητήστε αυτή τη συμβολοσειρά στο **google**, σε άλλα **προγράμματα περιήγησης** ή ακόμα και στο **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Συνήθως υπάρχει ένα cron job, όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
να ανανεώσουν όλα τα domain certificates στον server. Αυτό σημαίνει ότι ακόμα κι αν η CA που χρησιμοποιήθηκε για αυτό δεν καταχωρεί την ώρα δημιουργίας στο πεδίο Validity, είναι δυνατό να **βρείτε domains που ανήκουν στην ίδια εταιρεία στα certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε μια ιστοσελίδα όπως [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **domains και subdomain που μοιράζονται τις ίδιες πληροφορίες dmarc**.\
Άλλα χρήσιμα εργαλεία είναι [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Φαίνεται συχνό το φαινόμενο να εκχωρούν άνθρωποι subdomains σε IPs που ανήκουν σε cloud providers και κάποια στιγμή **χάνουν αυτή την IP αλλά ξεχνούν να αφαιρέσουν την εγγραφή DNS**. Επομένως, απλώς **spawn-άροντας ένα VM** σε ένα cloud (όπως Digital Ocean) στην πραγματικότητα θα **αναλάβετε κάποια subdomains**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) εξηγεί μια ιστορία γι' αυτό και προτείνει ένα script που **spawn-άρει ένα VM στο DigitalOcean**, **παίρνει** την **IPv4** της νέας μηχανής, και **ψάχνει στο Virustotal για εγγραφές subdomain** που δείχνουν σε αυτήν.

### **Other ways**

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύψετε περισσότερα ονόματα domain κάθε φορά που βρίσκετε ένα νέο domain.**

**Shodan**

Καθώς ήδη γνωρίζετε το όνομα της οργάνωσης που κατέχει το IP space, μπορείτε να αναζητήσετε με αυτά τα δεδομένα στο Shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους εντοπισμένους hosts για νέα απροσδόκητα domains στο TLS certificate.

Μπορείτε να έχετε πρόσβαση στο **TLS certificate** της κύριας ιστοσελίδας, να λάβετε το **Organisation name** και μετά να αναζητήσετε αυτό το όνομα μέσα στα **TLS certificates** όλων των ιστοσελίδων που γνωρίζει ο **shodan** με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) είναι ένα εργαλείο που ψάχνει για **domains related** με ένα κύριο domain και τα **subdomains** τους — αρκετά εντυπωσιακό.

**Passive DNS / Historical DNS**

Τα Passive DNS δεδομένα είναι εξαιρετικά για να βρείτε **παλιές και ξεχασμένες εγγραφές** που εξακολουθούν να επιλύονται ή που μπορούν να αναληφθούν. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιούσε κάποιο domain** αλλά **έχασε την ιδιοκτησία**. Απλώς εγγραφείτε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε κάποιο **domain με διαφορετική IP** από αυτές που ήδη βρήκατε στην ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **βασικό vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που τρέχουν μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για να τα "attack"**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε ένα IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι εντός του scope — να είστε προσεκτικοί._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες εντός του scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλα τα πιθανά subdomains του κάθε εντοπισμένου domain.

> [!TIP]
> Σημειώστε ότι κάποια από τα εργαλεία και τις τεχνικές για την εύρεση domains μπορούν επίσης να βοηθήσουν στην εύρεση subdomains

### **DNS**

Ας προσπαθήσουμε να πάρουμε **subdomains** από τις εγγραφές **DNS**. Θα πρέπει επίσης να δοκιμάσουμε για **Zone Transfer** (εάν είναι ευάλωτο, πρέπει να το αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο πιο γρήγορος τρόπος να βρείτε πολλά subdomains είναι η αναζήτηση σε εξωτερικές πηγές. Τα πιο χρησιμοποιημένα **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα ρυθμίστε τα API keys):

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

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για την απόκτηση υποτομέων
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
- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστές URLs από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιοδήποτε domain.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Σαρώνουν τον ιστό ψάχνοντας για JS files και εξάγουν subdomains από εκεί.
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
- [**Censys εργαλείο εύρεσης υποτομέων**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) έχει ένα δωρεάν API για αναζήτηση subdomains και ιστορικού IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με bug-bounty programs**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα επίσης χρησιμοποιώντας [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμα και να αποκτήσετε πρόσβαση στο scope που χρησιμοποιείται από αυτό το project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** με brute-force σε DNS servers χρησιμοποιώντας πιθανά ονόματα subdomain.

Για αυτή την ενέργεια θα χρειαστείτε μερικά **κοινά wordlists για subdomains όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Και επίσης IPs από αξιόπιστους DNS resolvers. Για να δημιουργήσετε μια λίστα με trusted DNS resolvers μπορείτε να κατεβάσετε τους resolvers από [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) και να χρησιμοποιήσετε [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Ή μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο συνιστώμενα εργαλεία για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτέλεσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο τείνει σε ψευδώς θετικά.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω χρησιμοποιεί μόνο 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένας wrapper γύρω από `massdns`, γραμμένος σε go, που σας επιτρέπει να απαριθμήσετε έγκυρα subdomains χρησιμοποιώντας active bruteforce, καθώς και να επιλύσετε subdomains με χειρισμό wildcard και εύκολη υποστήριξη εισόδου-εξόδου.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Επίσης χρησιμοποιεί `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί asyncio για να κάνει ασύγχρονο brute force σε ονόματα domain.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Δεύτερος γύρος DNS Brute-Force

Αφού έχετε βρει subdomains χρησιμοποιώντας ανοιχτές πηγές και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρέθηκαν για να προσπαθήσετε να βρείτε ακόμη περισσότερα. Πολλά εργαλεία είναι χρήσιμα γι' αυτόν τον σκοπό:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δίνοντας τα domains και subdomains, δημιουργεί παραλλαγές.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Δεδομένων των domains και subdomains, παράγει permutations.
- Μπορείτε να βρείτε το goaltdns permutations **wordlist** από [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Δεδομένων των domains και subdomains, δημιουργεί permutations. Αν δεν έχει υποδειχθεί αρχείο permutations, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από την παραγωγή subdomains permutations, μπορεί επίσης να προσπαθήσει να resolve them (αλλά είναι καλύτερο να χρησιμοποιήσετε τα προηγούμενα σχολιασμένα εργαλεία).
- Μπορείτε να βρείτε το altdns permutations **wordlist** [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για να πραγματοποιεί permutations, mutations και alteration των subdomains. Αυτό το εργαλείο θα brute force το αποτέλεσμα (δεν υποστηρίζει dns wild card).
- Μπορείτε να βρείτε το dmut permutations wordlist στο [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Βασισμένο σε ένα domain, αυτό **παράγει νέες πιθανές ονομασίες subdomains** βάσει των υποδεικνυόμενων προτύπων για να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Έξυπνη δημιουργία παραλλαγών

- [**regulator**](https://github.com/cramppet/regulator): Για περισσότερες πληροφορίες διαβάστε αυτό το [**post**](https://cramppet.github.io/regulator/index.html) αλλά βασικά θα εξάγει τα **κύρια μέρη** από τα **ανακαλυφθέντα subdomains** και θα τα αναμείξει για να βρει περισσότερα subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένας subdomain brute-force fuzzer συνδυασμένος με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από τις αποκρίσεις DNS. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως ένα προσαρμοσμένο wordlist ή ιστορικά DNS/TLS records, για να συνθέσει με ακρίβεια περισσότερα αντίστοιχα domain names και να τα επεκτείνει ακόμη περισσότερο σε έναν βρόχο βασισμένο σε πληροφορίες που συγκεντρώθηκαν κατά τη διάρκεια του DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Δες αυτό το άρθρο στο blog που έγραψα για το πώς να **αυτοματοποιήσω το subdomain discovery** από ένα domain χρησιμοποιώντας **Trickest workflows** ώστε να μην χρειάζεται να εκκινώ χειροκίνητα πολλά εργαλεία στον υπολογιστή μου:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Αν βρήκες μια διεύθυνση IP που περιέχει **μία ή περισσότερες σελίδες web** που ανήκουν σε subdomains, μπορείς να προσπαθήσεις να **βρεις άλλα subdomains με σελίδες σε εκείνο το IP** κοιτάζοντας σε **πηγές OSINT** για domains σε μια IP ή κάνοντας **brute-forcing VHost domain names σε εκείνο το IP**.

#### OSINT

Μπορείς να βρεις μερικά **VHosts σε IPs χρησιμοποιώντας** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλες APIs**.

**Brute Force**

Αν υποψιάζεσαι ότι κάποιο subdomain μπορεί να είναι κρυμμένο σε έναν web server, μπορείς να προσπαθήσεις να το brute force:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!TIP]
> Με αυτή την τεχνική μπορεί ακόμη να καταφέρετε να αποκτήσετε πρόσβαση σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Κάποιες φορές θα βρείτε σελίδες που επιστρέφουν μόνο τον header _**Access-Control-Allow-Origin**_ όταν στο header _**Origin**_ έχει οριστεί ένα έγκυρο domain/subdomain. Σε αυτές τις περιπτώσεις μπορείτε να καταχραστείτε αυτή τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Κατά την αναζήτηση για **subdomains** πρόσεχε αν δείχνει σε κάποιο είδος **bucket**, και σε αυτή την περίπτωση [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζεις όλα τα domains που βρίσκονται στο scope, προσπάθησε να [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείς να **monitor** εάν δημιουργούνται **new subdomains** ενός domain παρακολουθώντας τα logs του **Certificate Transparency** όπως κάνει το [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση ευπαθειών**

Έλεγξε για πιθανές [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρεις κάποιο **subdomain with an IP different** από αυτά που ήδη βρήκες στην assets discovery, πρέπει να πραγματοποιήσεις ένα **basic vulnerability scan** (using Nessus or OpenVAS) και κάποιους [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που τρέχουν μπορείς να βρεις στο **this book some tricks to "attack" them**.\
_Σημείωση ότι μερικές φορές το subdomain φιλοξενείται σε ένα IP που δεν ελέγχεται από τον client, οπότε δεν είναι στο scope — πρόσεχε._

## IPs

Στα αρχικά βήματα μπορεί να έχεις **found some IP ranges, domains and subdomains**.\
Ήρθε η ώρα να **recollect all the IPs from those ranges** και για τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας υπηρεσίες από τα παρακάτω **free apis** μπορείς επίσης να βρεις **previous IPs used by domains and subdomains**. Αυτά τα IPs μπορεί να ανήκουν ακόμα στον client (και μπορεί να σου επιτρέψουν να βρεις [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείς επίσης να ελέγξεις για domains που δείχνουν σε συγκεκριμένο IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση ευπαθειών**

**Port scan all the IPs that doesn’t belong to CDNs** (καθώς πολύ πιθανό να μην βρεις κάτι ενδιαφέρον εκεί). Στις υπηρεσίες που ανακαλύφθηκαν μπορεί να μπορέσεις να βρεις ευπάθειες.

**Βρες έναν** [**guide**](../pentesting-network/index.html) **για το πώς να σκανάρεις hosts.**

## Web servers hunting

> Έχουμε βρει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τα IP ranges, domains και subdomains που είναι μέσα στο scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανώς να έχεις ήδη κάνει κάποιο **recon of the IPs and domains discovered**, οπότε ίσως έχεις **already found all the possible web servers**. Ωστόσο, αν δεν το έχεις κάνει, τώρα θα δούμε μερικά **fast tricks to search for web servers** μέσα στο scope.

Παρακαλώ σημείωσε ότι αυτό θα είναι **oriented for web apps discovery**, οπότε πρέπει επίσης να **perform the vulnerability** και **port scanning** (**if allowed** από το scope).

Μια **fast method** για να ανακαλύψεις **ports open** σχετικές με **web** servers χρησιμοποιώντας [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμα φιλικό εργαλείο για την ανεύρεση web servers είναι [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς δίνεις μια λίστα με domains και θα προσπαθήσει να συνδεθεί στις θύρες 80 (http) και 443 (https). Επιπλέον, μπορείς να ορίσεις να δοκιμάσει άλλες θύρες:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Στιγμιότυπα**

Τώρα που έχετε ανακαλύψει **all the web servers** που υπάρχουν στο scope (μεταξύ των **IPs** της εταιρείας και όλων των **domains** και **subdomains**) πιθανόν **δεν ξέρετε από πού να ξεκινήσετε**. Ας το κάνουμε απλό — ξεκινήστε απλά παίρνοντας στιγμιότυπα (screenshots) από όλα. Μόνο με το να **ρίξετε μια ματιά** στην **main page** μπορείτε να εντοπίσετε **weird** endpoints που είναι πιο **prone** να είναι **vulnerable**.

Για να υλοποιήσετε την ιδέα μπορείτε να χρησιμοποιήσετε [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να τρέξετε πάνω από όλα τα **screenshots** και να σας δείξει **what's likely to contain vulnerabilities**, και τι όχι.

## Public Cloud Assets

Για να βρείτε πιθανά cloud assets που ανήκουν σε μια εταιρεία θα πρέπει να **ξεκινήσετε με μια λίστα λέξεων-κλειδιών που ταυτοποιούν την εταιρεία**. Για παράδειγμα, για μια crypto εταιρεία μπορεί να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης wordlists με **common words used in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις θα πρέπει να δημιουργήσετε **permutations** (τσεκάρετε το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τα προκύπτοντα wordlists μπορείτε να χρησιμοποιήσετε εργαλεία όπως [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Θυμηθείτε ότι όταν ψάχνετε για Cloud Assets θα πρέπει να **l**ook for more than just buckets in AWS**.

### **Looking for vulnerabilities**

Αν βρείτε πράγματα όπως **open buckets or cloud functions exposed** θα πρέπει να **προσπελάσετε** αυτά και να δείτε τι σας προσφέρουν και αν μπορείτε να τα εκμεταλλευτείτε.

## Emails

Με τα **domains** και **subdomains** που είναι στο scope έχετε ουσιαστικά όλα όσα χρειάζεστε για να **ξεκινήσετε την αναζήτηση για emails**. Αυτά είναι τα **APIs** και τα **εργαλεία** που μου έχουν δουλέψει καλύτερα για να βρω emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Τα emails θα σας φανούν χρήσιμα αργότερα για **brute-force web logins and auth services** (όπως SSH). Επίσης χρειάζονται για **phishings**. Επιπλέον, αυτά τα APIs θα σας δώσουν περισσότερες **πληροφορίες για το πρόσωπο** πίσω από το email, χρήσιμες για καμπάνιες phishing.

## Credential Leaks

Με τα **domains,** **subdomains**, και **emails** μπορείτε να αρχίσετε να ψάχνετε για credentials που έχουν been leaked στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Αν βρείτε **valid leaked** credentials, αυτό είναι ένα πολύ εύκολο win.

## Secrets Leaks

Τα credential leaks σχετίζονται με hacks εταιρειών όπου **sensitive information was leaked and sold**. Ωστόσο, οι εταιρείες μπορεί να επηρεαστούν από **άλλες leaks** των οποίων οι πληροφορίες δεν υπάρχουν σε αυτές τις βάσεις:

### Github Leaks

Credentials και APIs μπορεί να έχουν been leaked σε **public repositories** της **εταιρείας** ή των **users** που δουλεύουν για την εταιρεία στο github.\
Μπορείτε να χρησιμοποιήσετε το **tool** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **public repos** ενός **organization** και των **developers** του και να τρέξετε [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω τους αυτόματα.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για να τρέξει **gitleaks** ενάντια σε όλο το **text** των παρεχόμενων **URLs passed** σε αυτό, καθώς μερικές φορές **web pages also contains secrets**.

#### Github Dorks

Δείτε επίσης αυτή τη **σελίδα** για πιθανές **github dorks** που θα μπορούσατε να ψάξετε στην οργάνωση που στοχεύετε:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Κάποιες φορές attackers ή απλά εργαζόμενοι θα **δημοσιεύσουν περιεχόμενο της εταιρείας σε paste site**. Αυτό μπορεί ή όχι να περιέχει **sensitive information**, αλλά είναι πολύ ενδιαφέρον να το ψάξετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για να ψάξετε σε πάνω από 80 paste sites ταυτόχρονα.

### Google Dorks

Οι παλιές αλλά χρήσιμες google dorks είναι πάντα χρήσιμες για να βρείτε **exposed information that shouldn't be there**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει χιλιάδες πιθανές queries που δεν μπορείτε να τρέξετε χειροκίνητα. Έτσι, μπορείτε να πάρετε τις αγαπημένες σας 10 ή να χρησιμοποιήσετε ένα **εργαλείο όπως** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τις τρέξετε όλες**.

Σημείωση ότι τα εργαλεία που περιμένουν να τρέξουν ολόκληρη τη βάση χρησιμοποιώντας τον κανονικό Google browser δεν θα τελειώσουν ποτέ καθώς το google θα σας μπλοκάρει πολύ γρήγορα.

### **Looking for vulnerabilities**

Αν βρείτε **valid leaked** credentials ή API tokens, αυτό είναι ένα πολύ εύκολο win.

## Public Code Vulnerabilities

Αν ανακαλύψατε ότι η εταιρεία έχει **open-source code** μπορείτε να το **αναλύσετε** και να ψάξετε για **vulnerabilities** σε αυτό.

**Ανάλογα με τη γλώσσα** υπάρχουν διάφορα **εργαλεία** που μπορείτε να χρησιμοποιήσετε:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Υπάρχουν επίσης δωρεάν υπηρεσίες που επιτρέπουν να **σκανάρετε public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των vulnerabilities** που βρίσκουν οι bug hunters βρίσκεται μέσα σε **web applications**, οπότε σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία testing web εφαρμογών**, την οποία μπορείτε να [**βρείτε εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική μνεία στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, ακόμα κι αν δεν πρέπει να περιμένετε να βρουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για να τα εντάξετε σε **workflows** ώστε να έχετε αρχικές web πληροφορίες.

## Recapitulation

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη πραγματοποιήσει **όλη την βασική enumeration**. Ναι, είναι βασική γιατί μπορεί να γίνει πολύ περισσότερη enumeration (θα δούμε περισσότερα κόλπα αργότερα).

Έτσι έχετε ήδη:

1. Found all the **companies** inside the scope
2. Found all the **assets** belonging to the companies (and perform some vuln scan if in scope)
3. Found all the **domains** belonging to the companies
4. Found all the **subdomains** of the domains (any subdomain takeover?)
5. Found all the **IPs** (from and **not from CDNs**) inside the scope.
6. Found all the **web servers** and took a **screenshot** of them (anything weird worth a deeper look?)
7. Found all the **potential public cloud assets** belonging to the company.
8. **Emails**, **credentials leaks**, and **secret leaks** that could give you a **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Υπάρχουν αρκετά εργαλεία εκεί έξω που θα πραγματοποιήσουν μέρος από τις προτεινόμενες ενέργειες ενάντια σε ένα δοσμένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
