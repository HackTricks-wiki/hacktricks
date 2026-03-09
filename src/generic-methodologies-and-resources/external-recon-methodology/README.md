# Μεθοδολογία Εξωτερικής Αναγνώρισης

{{#include ../../banners/hacktricks-training.md}}

## Ανακαλύψεις περιουσιακών στοιχείων

> Σου είπαν ότι ό,τι ανήκει σε κάποια εταιρεία είναι εντός του scope, και θέλεις να καταλάβεις τι ακριβώς κατέχει αυτή η εταιρεία.

Ο στόχος αυτής της φάσης είναι να αποκτήσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **περιουσιακά στοιχεία** αυτών των εταιρειών. Για να το κάνουμε, θα:

1. Βρούμε τις εξαγορές της κύριας εταιρείας — αυτό θα μας δώσει τις εταιρείες εντός του scope.
2. Βρούμε το ASN (αν υπάρχει) κάθε εταιρείας — αυτό θα μας δώσει τα εύρη διευθύνσεων IP που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε reverse whois αναζητήσεις για να εντοπίσουμε άλλες εγγραφές (ονόματα οργανώσεων, domains...) σχετιζόμενες με την αρχική (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιήσουμε άλλες τεχνικές όπως τα φίλτρα shodan `org` και `ssl` για να ψάξουμε για άλλα περιουσιακά στοιχεία (το κόλπο με το `ssl` μπορεί να γίνει αναδρομικά).

### **Acquisitions**

Πρώτα απ' όλα, πρέπει να ξέρουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μία επιλογή είναι να επισκεφθείς [https://www.crunchbase.com/](https://www.crunchbase.com), να **αναζητήσεις** την **κύρια εταιρεία**, και να **κλικάρεις** στο "acquisitions". Εκεί θα δεις άλλες εταιρείες που αποκτήθηκαν από την κύρια.\
Άλλη επιλογή είναι να επισκεφθείς τη σελίδα της κύριας εταιρείας στη Wikipedia και να αναζητήσεις τις **exacquisitions**.\
Για δημόσιες εταιρείες, έλεγξε τις καταχωρίσεις SEC/EDGAR, τις σελίδες investor relations, ή τα τοπικά εταιρικά μητρώα (π.χ., **Companies House** στο ΗΒ).\
Για παγκόσμια δέντρα εταιρειών και θυγατρικές, δοκίμασε **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζεις όλες τις εταιρείες εντός του scope. Ας δούμε πώς θα βρούμε τα περιουσιακά τους στοιχεία.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (ASN) είναι ένας μοναδικός αριθμός που εκχωρείται σε ένα αυτόνομο σύστημα (AS) από την Internet Assigned Numbers Authority (IANA).\
Ένα AS αποτελείται από μπλοκ διευθύνσεων IP που έχουν σαφώς καθορισμένη πολιτική πρόσβασης σε εξωτερικά δίκτυα και διοικούνται από μια ενιαία οργάνωση, αλλά μπορεί να αποτελείται από πολλούς operators.

Είναι χρήσιμο να βρούμε αν η εταιρεία έχει εκχωρημένο κάποιο ASN ώστε να εντοπίσουμε τα εύρη IP της. Είναι ενδιαφέρον να διεξαχθεί vulnerability test σε όλους τους hosts εντός του scope και να αναζητηθούν domains εντός αυτών των IP.\
Μπορείς να **αναζητήσεις** με το όνομα της εταιρείας, με IP ή με domain σε [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή της εταιρείας αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για να συλλέξεις περισσότερα δεδομένα:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Πάντως, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(εύρη IP και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration συγκεντρώνει αυτόματα και συνοψίζει τα ASNs στο τέλος του scan.
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
Μπορείτε επίσης να βρείτε τα IP ranges μιας οργάνωσης χρησιμοποιώντας [http://asnlookup.com/](http://asnlookup.com) (διαθέτει δωρεάν API).\
Μπορείτε να βρείτε το IP και το ASN ενός domain χρησιμοποιώντας [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

Σε αυτό το στάδιο γνωρίζουμε **όλα τα assets εντός του scope**, οπότε εάν έχετε άδεια μπορείτε να τρέξετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να πραγματοποιήσετε μερικά [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως** Shodan, Censys ή ZoomEye **για να βρείτε** open ports **και ανάλογα με όσα βρείτε θα πρέπει** να ανατρέξετε σε αυτό το βιβλίο για το πώς να pentest διάφορες υπηρεσίες που τρέχουν.\
**Επίσης, αξίζει να αναφέρουμε ότι μπορείτε να προετοιμάσετε λίστες με default username και passwords και να δοκιμάσετε να** bruteforce υπηρεσίες με [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες εντός του scope και τα assets τους, είναι ώρα να βρούμε τα domains εντός του scope.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

Πρώτα απ' όλα πρέπει να ψάξετε για το **main domain**(s) κάθε εταιρείας. Για παράδειγμα, για _Tesla Inc._ θα είναι _tesla.com_.

### **Reverse DNS**

Μόλις έχετε βρει όλα τα IP ranges των domains, μπορείτε να προσπαθήσετε να κάνετε **reverse dns lookups** σε αυτά τα **IPs για να βρείτε περισσότερα domains εντός του scope**. Προσπαθήστε να χρησιμοποιήσετε κάποιο dns server του θύματος ή κάποιο γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα διαδικτυακό εργαλείο για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλα εύρη, εργαλεία όπως [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του enrichment.

### **Reverse Whois (loop)**

Μέσα σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες** όπως **όνομα οργανισμού**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Αλλά ακόμη πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα assets related to the company** αν εκτελέσετε **reverse whois lookups by any of those fields** (για παράδειγμα άλλες whois καταχωρίσεις όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε διαδικτυακά εργαλεία όπως:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Δωρεάν** web, όχι δωρεάν API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Όχι δωρεάν
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Όχι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Όχι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Όχι δωρεάν (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Όχι δωρεάν (API)

Μπορείτε να αυτοματοποιήσετε αυτή την εργασία χρησιμοποιώντας [**DomLink** ](https://github.com/vysecurity/DomLink) (απαιτεί ένα whoxy API key).\
Μπορείτε επίσης να πραγματοποιήσετε κάποια αυτόματη reverse whois ανίχνευση με [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτή την τεχνική για να ανακαλύψετε περισσότερα ονόματα domain κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε διάφορες σελίδες.

Υπάρχουν κάποιες σελίδες και εργαλεία που σας επιτρέπουν να αναζητήσετε με βάση αυτούς τους trackers και άλλα:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Ξέρατε ότι μπορούμε να βρούμε σχετικά domains και subdomains με τον στόχο μας αναζητώντας το ίδιο favicon icon hash; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) που δημιούργησε ο [@m4ll0k2](https://twitter.com/m4ll0k2). Να πώς να το χρησιμοποιήσετε:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash θα μας επιτρέψει να εντοπίσουμε domains που έχουν το ίδιο favicon icon hash με τον στόχο μας.

Επιπλέον, μπορείτε επίσης να αναζητήσετε τεχνολογίες χρησιμοποιώντας το favicon hash όπως εξηγείται στο [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Αυτό σημαίνει ότι αν γνωρίζετε το **hash of the favicon of a vulnerable version of a web tech** μπορείτε να το αναζητήσετε στο shodan και να **find more vulnerable places**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Έτσι μπορείτε να **calculate the favicon hash** ενός ιστότοπου:
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
Μπορείτε επίσης να αποκτήσετε favicon hashes σε κλίμακα με [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και στη συνέχεια να κάνετε pivot σε Shodan/Censys.

### **Πνευματικά Δικαιώματα / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που μπορεί να μοιράζονται σε διαφορετικούς ιστότοπους της ίδιας οργάνωσης**. Η **συμβολοσειρά πνευματικών δικαιωμάτων** μπορεί να είναι ένα καλό παράδειγμα. Στη συνέχεια αναζητήστε αυτή τη συμβολοσειρά στο **google**, σε άλλους **περιηγητές** ή ακόμα και στο **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
να ανανεώσετε όλα τα πιστοποιητικά των domains στον server. Αυτό σημαίνει ότι ακόμα κι αν η CA που χρησιμοποιήθηκε δεν καταγράφει την ώρα δημιουργίας στο πεδίο Validity time, είναι δυνατόν να **βρείτε domains που ανήκουν στην ίδια εταιρεία στα certificate transparency logs**.\
Δείτε αυτό το [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Επίσης χρησιμοποιήστε απευθείας τα **certificate transparency** logs:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε μια σελίδα όπως [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **domains και subdomain που μοιράζονται τις ίδιες πληροφορίες DMARC**.\
Άλλα χρήσιμα εργαλεία είναι τα [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Φαίνεται ότι είναι συνηθισμένο άνθρωποι να αναθέτουν subdomains σε IPs που ανήκουν σε cloud providers και κάποια στιγμή να **χάνουν αυτήν την IP διεύθυνση αλλά να ξεχνούν να αφαιρέσουν το DNS record**. Επομένως, απλά **spawning a VM** σε ένα cloud (όπως Digital Ocean) θα καταλάβετε στην πραγματικότητα **κάποια subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) εξηγεί μια ιστορία σχετικά με αυτό και προτείνει ένα σενάριο που **spawns a VM in DigitalOcean**, **gets** την **IPv4** της νέας μηχανής, και **searches in Virustotal for subdomain records** που δείχνουν σε αυτήν.

### **Other ways**

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύψετε περισσότερα ονόματα domain κάθε φορά που βρίσκετε ένα νέο domain.**

**Shodan**

Καθώς ήδη γνωρίζετε το όνομα της οργάνωσης που κατέχει το IP space, μπορείτε να ψάξετε με αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τα ευρεθέντα hosts για νέα απροσδόκητα domains στο TLS certificate.

Μπορείτε να αποκτήσετε το **TLS certificate** της κύριας ιστοσελίδας, να πάρετε το **Organisation name** και στη συνέχεια να ψάξετε για αυτό το όνομα μέσα στα **TLS certificates** όλων των ιστοσελίδων που γνωρίζει το **shodan** με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) είναι ένα εργαλείο που ψάχνει για **domains related** με ένα κύριο domain και για **subdomains** αυτών, πολύ χρήσιμο.

**Passive DNS / Historical DNS**

Τα Passive DNS δεδομένα είναι ιδανικά για να βρείτε **παλιά και ξεχασμένα records** που ακόμα επιλύονται ή που μπορούν να ανακτηθούν/καταληφθούν. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Ελέγξτε για κάποιο [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί κάποιο domain** αλλά έχει **χάσει την ιδιοκτησία**. Απλώς εγγραφείτε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε κάποιο **domain με διαφορετική IP** από αυτές που ήδη βρήκατε στην ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που τρέχουν μπορείτε να βρείτε σε **αυτό το βιβλίο μερικά κόλπα για να "επιτεθείτε" σε αυτές**.\
_Σημείωση: μερικές φορές το domain φιλοξενείται σε μια IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι εντός του scope — προσέξτε._

## Υποτομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του scope, όλα τα assets της κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλους τους πιθανούς υποτομείς κάθε βρεθέντος domain.

> [!TIP]
> Σημειώστε ότι κάποια από τα εργαλεία και τις τεχνικές για να βρείτε domains μπορούν επίσης να βοηθήσουν στο να βρείτε subdomains

### **DNS**

Ας προσπαθήσουμε να πάρουμε **subdomains** από τα **DNS** records. Πρέπει επίσης να δοκιμάσουμε για **Zone Transfer** (Αν είναι ευάλωτο, πρέπει να το αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο γρηγορότερος τρόπος για να αποκτήσεις πολλά subdomains είναι να κάνεις αναζήτηση σε εξωτερικές πηγές. Τα πιο χρησιμοποιούμενα **tools** είναι τα εξής (για καλύτερα αποτελέσματα ρύθμισε τα API keys):

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
Υπάρχουν **άλλα ενδιαφέροντα εργαλεία/API** που, ακόμη κι αν δεν είναι άμεσα εξειδικευμένα στην εύρεση subdomains, θα μπορούσαν να φανούν χρήσιμα για την εύρεση subdomains, όπως:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για να αποκτήσει subdomains
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
- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστές διευθύνσεις URL από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιονδήποτε δοθέντα domain.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Σαρώνουν το διαδίκτυο αναζητώντας αρχεία JS και εξάγουν subdomains από εκεί.
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
- [**securitytrails.com**](https://securitytrails.com/) διαθέτει δωρεάν API για αναζήτηση subdomains και IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

This project offers for **free all the subdomains related to bug-bounty programs**. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** με brute-forcing των DNS servers χρησιμοποιώντας πιθανές ονομασίες subdomain.

Για αυτή τη δράση θα χρειαστείτε μερικά κοινά subdomains wordlists όπως:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Και επίσης IPs καλών DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers μπορείτε να κατεβάσετε τους resolvers από [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) και να χρησιμοποιήσετε [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τα φιλτράρετε. Ή μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο συνιστώμενα εργαλεία για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτέλεσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Αυτό, νομίζω, χρησιμοποιεί μόνο 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από `massdns`, γραμμένο σε go, που σας επιτρέπει να εντοπίζετε έγκυρα subdomains χρησιμοποιώντας active bruteforce, καθώς και να επιλύετε subdomains με wildcard handling και εύκολη υποστήριξη input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί asyncio για brute force ονομάτων domain ασύγχρονα.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Second DNS Brute-Force Round

Αφού εντοπίσετε subdomains χρησιμοποιώντας ανοιχτές πηγές και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρέθηκαν για να προσπαθήσετε να βρείτε ακόμη περισσότερα. Πολλά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δίνοντας τα domains και subdomains, δημιουργεί παραλλαγές.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Δημιουργεί permutations από τα domains και subdomains.
- Μπορείτε να βρείτε το permutations **wordlist** του goaltdns στο [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Δεδομένων των domains και subdomains, δημιουργεί permutations. Αν δεν υποδειχθεί αρχείο permutations, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία subdomains permutations, μπορεί επίσης να προσπαθήσει να τα επιλύσει (αλλά είναι προτιμότερο να χρησιμοποιήσετε τα εργαλεία που σχολιάστηκαν παραπάνω).
- Μπορείτε να βρείτε τη wordlist με τις altdns permutations στο [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Άλλο εργαλείο για την εκτέλεση permutations, mutations και alteration των subdomains. Αυτό το εργαλείο θα brute force το αποτέλεσμα (δεν υποστηρίζει dns wild card).
- Μπορείτε να βρείτε το dmut permutations wordlist στο [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Βάσει ενός domain παράγει νέα πιθανά ονόματα subdomains βάσει των υποδεικνυόμενων προτύπων για να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Έξυπνη δημιουργία παραλλαγών

- [**regulator**](https://github.com/cramppet/regulator): Για περισσότερες πληροφορίες διάβασε αυτό το [**post**](https://cramppet.github.io/regulator/index.html) αλλά βασικά θα εξάγει τα **κύρια μέρη** από τα **ανακαλυφθέντα subdomains** και θα τα αναμείξει για να βρει περισσότερα subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένα subdomain brute-force fuzzer σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό DNS response-guided algorithm. Χρησιμοποιεί ένα παρεχόμενο σύνολο input data, όπως μια προσαρμοσμένη wordlist ή ιστορικά DNS/TLS records, για να συνθέσει με ακρίβεια περισσότερα αντίστοιχα domain names και να τα επεκτείνει ακόμη περισσότερο σε βρόχο βάσει πληροφοριών που συλλέχθηκαν κατά τη διάρκεια DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Δες αυτό το άρθρο που έγραψα για το πώς να **automate the subdomain discovery** από ένα domain χρησιμοποιώντας **Trickest workflows**, ώστε να μην χρειάζεται να εκκινώ χειροκίνητα μια σειρά εργαλείων στον υπολογιστή μου:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Αν εντόπισες μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** που ανήκουν σε subdomains, μπορείς να προσπαθήσεις να **βρεις άλλα subdomains με ιστοσελίδες σε αυτήν την IP** ψάχνοντας σε **OSINT sources** για domains στην IP ή κάνοντας **brute-forcing VHost domain names in that IP**.

#### OSINT

Μπορείς να βρεις μερικά **VHosts σε IPs χρησιμοποιώντας** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεσαι ότι κάποιο subdomain μπορεί να είναι κρυμμένο σε έναν web server, μπορείς να προσπαθήσεις να το **brute force**:

When the **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
-w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

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
> Με αυτήν την τεχνική ίσως να μπορείτε ακόμη και να αποκτήσετε πρόσβαση σε internal/hidden endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν μόνο την κεφαλίδα _**Access-Control-Allow-Origin**_ όταν μια έγκυρη domain/subdomain έχει οριστεί στην κεφαλίδα _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να καταχραστείτε αυτή τη συμπεριφορά για να **εντοπίσετε** νέες **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Ενώ ψάχνετε για **subdomains**, προσέξτε αν δείχνουν σε κάποιο τύπο **bucket**, και σε αυτή την περίπτωση [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains μέσα στο scope, δοκιμάστε να [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείτε να **monitor** αν δημιουργούνται **new subdomains** ενός domain παρακολουθώντας τα **Certificate Transparency** Logs όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Ελέγξτε για πιθανές [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρείτε κάποιο **subdomain with an IP different** από αυτά που ήδη βρήκατε στην ανακάλυψη assets, θα πρέπει να κάνετε ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που τρέχουν, μπορείτε να βρείτε σε **this book some tricks to "attack" them**.\
_Σημείωση: μερικές φορές το subdomain φιλοξενείται σε ένα IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι στο scope — προσοχή._

## IPs

Στα αρχικά βήματα ενδέχεται να έχετε **found some IP ranges, domains and subdomains**.\
Ήρθε η ώρα να **recollect all the IPs from those ranges** και για τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας υπηρεσίες από τα παρακάτω **free apis** μπορείτε επίσης να βρείτε **previous IPs used by domains and subdomains**. Αυτά τα IPs μπορεί ακόμα να ανήκουν στον πελάτη (και μπορεί να σας επιτρέψουν να βρείτε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)):

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να ελέγξετε για domains που δείχνουν σε συγκεκριμένη IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (καθώς πολύ πιθανόν να μην βρείτε τίποτα ενδιαφέρον εκεί). Στις υπηρεσίες που εντοπιστούν μπορεί να **βρείτε ευπάθειες**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Αναζήτηση Web servers

> Έχουμε βρει όλες τις εταιρείες και τα assets τους και γνωρίζουμε IP ranges, domains and subdomains μέσα στο scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη κάνει κάποιο **recon of the IPs and domains discovered**, οπότε ίσως έχετε **already found all the possible web servers**. Ωστόσο, αν δεν το έχετε κάνει, θα δούμε τώρα μερικά **fast tricks to search for web servers** μέσα στο scope.

Παρακαλώ σημειώστε ότι αυτό θα είναι **oriented for web apps discovery**, οπότε θα πρέπει να κάνετε και **perform the vulnerability** και **port scanning** (**if allowed** από το scope).

Μια **fast method** για να βρείτε **ports open** που σχετίζονται με **web** servers χρησιμοποιώντας [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμα φιλικό εργαλείο για αναζήτηση web servers είναι τα [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Τροφοδοτείτε μια λίστα με domains και θα προσπαθήσει να συνδεθεί στις θύρες 80 (http) και 443 (https). Επιπλέον, μπορείτε να ορίσετε να δοκιμάσει άλλες θύρες:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Τώρα που έχετε εντοπίσει **all the web servers** που υπάρχουν στο scope (μεταξύ των **IPs** της εταιρείας και όλων των **domains** και **subdomains**) μάλλον **don't know where to start**. Οπότε, ας το κάνουμε απλό και ξεκινάμε απλά παίρνοντας screenshots από όλα. Απλώς κοιτάζοντας την **main page** μπορείτε να βρείτε περίεργα endpoints που είναι πιο πιθανό να είναι **vulnerable**.

Για να υλοποιήσετε την πρόταση μπορείτε να χρησιμοποιήσετε [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε στη συνέχεια να χρησιμοποιήσετε [**eyeballer**](https://github.com/BishopFox/eyeballer) για να τρέξετε πάνω από όλα τα **screenshots** και να σας πει τι **is likely to contain vulnerabilities**, και τι όχι.

## Public Cloud Assets

Για να βρείτε πιθανά cloud assets που ανήκουν σε μια εταιρεία πρέπει να **start with a list of keywords that identify that company**. Για παράδειγμα, για μια crypto εταιρεία μπορεί να χρησιμοποιήσετε λέξεις όπως: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Θα χρειαστείτε επίσης wordlists από **common words used in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Έπειτα, με αυτές τις λέξεις θα πρέπει να δημιουργήσετε **permutations** (δείτε το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τα προκύπτοντα wordlists μπορείτε να χρησιμοποιήσετε εργαλεία όπως [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Θυμηθείτε ότι όταν ψάχνετε για Cloud Assets πρέπει να **look for more than just buckets in AWS**.

### **Looking for vulnerabilities**

Αν βρείτε πράγματα όπως **open buckets or cloud functions exposed** θα πρέπει να **access them** και να δοκιμάσετε τι σας προσφέρουν και αν μπορείτε να τα abuse.

## Emails

Με τα **domains** και **subdomains** εντός του scope έχετε πρακτικά όλα όσα χρειάζεστε για να **start searching for emails**. Αυτά είναι τα **APIs** και τα **tools** που μου έχουν δουλέψει καλύτερα για να βρω emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Τα emails θα φανούν χρήσιμα αργότερα για να **brute-force web logins and auth services** (όπως SSH). Επίσης, είναι απαραίτητα για **phishings**. Επιπλέον, αυτά τα APIs θα σας δώσουν ακόμη περισσότερες **info about the person** πίσω από το email, που είναι χρήσιμο για την phishing καμπάνια.

## Credential Leaks

Με τα **domains,** **subdomains**, και **emails** μπορείτε να ξεκινήσετε να ψάχνετε για credentials που have been leaked στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Αν βρείτε **valid leaked** credentials, αυτό είναι ένα πολύ εύκολο win.

## Secrets Leaks

Τα credential leaks σχετίζονται με hacks εταιρειών όπου **sensitive information was leaked and sold**. Ωστόσο, οι εταιρείες μπορεί να επηρεαστούν από **άλλες leaks** των οποίων οι πληροφορίες δεν εμφανίζονται σε αυτές τις βάσεις δεδομένων:

### Github Leaks

Credentials και APIs μπορεί να έχουν διαρρεύσει σε **public repositories** της **εταιρείας** ή των **users** που δουλεύουν για αυτήν.\
Μπορείτε να χρησιμοποιήσετε το **tool** [**Leakos**](https://github.com/carlospolop/Leakos) για να **download** όλα τα **public repos** μιας **organization** και των **developers** της και να τρέξετε [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω τους αυτόματα.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για να τρέξει **gitleaks** ενάντια σε όλα τα **text** provided **URLs passed** σε αυτό καθώς μερικές φορές **web pages also contains secrets**.

#### Github Dorks

Ελέγξτε επίσης αυτή τη **σελίδα** για potential **github dorks** που μπορείτε επίσης να ψάξετε στην organization που επιτίθεστε:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Κάποιες φορές attackers ή απλώς εργαζόμενοι θα **publish company content in a paste site**. Αυτό μπορεί ή όχι να περιέχει **sensitive information**, αλλά είναι πολύ ενδιαφέρον να το ψάξετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για να ψάξετε σε πάνω από 80 paste sites ταυτόχρονα.

### Google Dorks

Οι παλιοί αλλά χρήσιμοι google dorks είναι πάντα χρήσιμοι για να βρείτε **exposed information that shouldn't be there**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **thousands** πιθανές queries που δεν μπορείτε να τρέξετε χειροκίνητα. Οπότε, μπορείτε να πάρετε τις αγαπημένες σας 10 ή να χρησιμοποιήσετε ένα **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τρέξετε όλες**.

_Σημειώστε ότι τα εργαλεία που προσπαθούν να τρέξουν όλη τη βάση χρησιμοποιώντας τον κανονικό Google browser δεν θα τελειώσουν ποτέ καθώς η google θα σας μπλοκάρει πολύ πολύ σύντομα._

### **Looking for vulnerabilities**

Αν βρείτε **valid leaked** credentials ή API tokens, αυτό είναι ένα πολύ εύκολο win.

## Public Code Vulnerabilities

Αν βρήκατε ότι η εταιρεία έχει **open-source code** μπορείτε να το **analyse** και να ψάξετε για **vulnerabilities** σε αυτό.

**Ανάλογα με τη γλώσσα** υπάρχουν διάφορα **tools** που μπορείτε να χρησιμοποιήσετε:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Υπάρχουν επίσης free services που επιτρέπουν να **scan public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Η **majority of the vulnerabilities** που βρίσκουν οι bug hunters βρίσκονται μέσα σε **web applications**, οπότε σε αυτό το σημείο θέλω να μιλήσω για μια **web application testing methodology**, και μπορείτε να [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική μνεία στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, αν και δεν πρέπει να περιμένετε να βρουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για να τα ενσωματώσετε σε **workflows** για να έχετε κάποιες αρχικές web πληροφορίες.

## Recapitulation

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη εκτελέσει **all the basic enumeration**. Ναι, είναι basic γιατί μπορεί να γίνει πολύ περισσότερη enumeration (θα δούμε περισσότερα κόλπα αργότερα).

Άρα έχετε ήδη:

1. Βρει όλες τις **companies** μέσα στο scope
2. Βρει όλα τα **assets** που ανήκουν στις companies (και εκτελέσει κάποιο vuln scan αν είναι in scope)
3. Βρει όλα τα **domains** που ανήκουν στις companies
4. Βρει όλα τα **subdomains** των domains (any subdomain takeover?)
5. Βρει όλα τα **IPs** (από και **όχι από CDNs**) μέσα στο scope.
6. Βρει όλους τους **web servers** και έχετε πάρει ένα **screenshot** τους (κάτι περίεργο που αξίζει πιο βαθιά έρευνα?)
7. Βρει όλα τα **potential public cloud assets** που ανήκουν στην company.
8. **Emails**, **credentials leaks**, και **secret leaks** που θα μπορούσαν να σας δώσουν ένα **big win very easily**.
9. **Pentesting** όλων των webs που βρήκατε

## **Full Recon Automatic Tools**

Υπάρχουν αρκετά εργαλεία έξω που θα εκτελέσουν μέρος από τις προτεινόμενες ενέργειες ενάντια σε ένα δοσμένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- Όλα τα free courses του [**@Jhaddix**](https://twitter.com/Jhaddix) όπως [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
