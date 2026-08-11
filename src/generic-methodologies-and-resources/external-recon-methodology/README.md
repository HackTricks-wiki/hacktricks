# Μεθοδολογία External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ανακάλυψη assets

> Έτσι, σας είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία βρίσκονται εντός του scope και θέλετε να εντοπίσετε τι ακριβώς ανήκει σε αυτή την εταιρεία.

Ο στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **assets** αυτών των εταιρειών. Για να το πετύχουμε, θα:<sup>[[1]](#references)</sup>

1. Εντοπίσουμε τις εξαγορές της κύριας εταιρείας, ώστε να βρούμε τις εταιρείες που βρίσκονται εντός του scope.
2. Εντοπίσουμε το ASN (αν υπάρχει) κάθε εταιρείας, ώστε να βρούμε τα IP ranges που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε reverse whois lookups για να αναζητήσουμε άλλες καταχωρίσεις (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει recursively).
4. Χρησιμοποιήσουμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το `ssl` trick μπορεί να γίνει recursively).

### **Εξαγορές**

Καταρχάς, πρέπει να γνωρίζουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μία επιλογή είναι να επισκεφθείτε το [https://www.crunchbase.com/](https://www.crunchbase.com), να κάνετε **search** για την **κύρια εταιρεία** και να κάνετε **click** στις "**acquisitions**". Εκεί θα δείτε άλλες εταιρείες που εξαγοράστηκαν από την κύρια εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα της κύριας εταιρείας στη **Wikipedia** και να αναζητήσετε **acquisitions**.\
Για δημόσιες εταιρείες, ελέγξτε τις **SEC/EDGAR filings**, τις σελίδες **investor relations** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμια εταιρικά δέντρα και θυγατρικές, δοκιμάστε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζετε όλες τις εταιρείες που βρίσκονται εντός του scope. Ας δούμε πώς μπορούμε να βρούμε τα assets τους.

### **ASNs**

Ένας autonomous system number (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **autonomous system** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** από **IP addresses**, τα οποία διαθέτουν μια σαφώς καθορισμένη πολιτική πρόσβασης σε εξωτερικά δίκτυα και διαχειρίζονται από έναν μόνο οργανισμό, αλλά μπορεί να αποτελούνται από αρκετούς operators.

Είναι χρήσιμο να εντοπίσουμε αν η **εταιρεία έχει εκχωρημένο κάποιο ASN**, ώστε να βρούμε τα **IP ranges** της. Θα ήταν ενδιαφέρον να πραγματοποιήσουμε ένα **vulnerability test** σε όλους τους **hosts** που βρίσκονται εντός του **scope** και να **αναζητήσουμε domains** μέσα σε αυτά τα IPs.\
Μπορείτε να κάνετε **search** με βάση το **όνομα εταιρείας**, το **IP** ή το **domain** στα [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή της εταιρείας, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Σε κάθε περίπτωση, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(IP ranges και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, η enumeration του [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** συγκεντρώνει και συνοψίζει αυτόματα τα ASNs στο τέλος της σάρωσης.
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
Μπορείτε να βρείτε τα IP ranges ενός οργανισμού χρησιμοποιώντας επίσης το [http://asnlookup.com/](http://asnlookup.com) (διαθέτει δωρεάν API).\
Μπορείτε να βρείτε το IP και το ASN ενός domain χρησιμοποιώντας το [http://ipv4info.com/](http://ipv4info.com).

### **Αναζήτηση vulnerabilities**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets εντός του scope**, επομένως, αν επιτρέπεται, θα μπορούσατε να εκτελέσετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, θα μπορούσατε να εκτελέσετε [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε services όπως** τα Shodan, Censys ή ZoomEye **για να βρείτε** ανοιχτές ports **και, ανάλογα με όσα βρείτε, θα πρέπει να** ανατρέξετε σε αυτό το βιβλίο για να δείτε πώς να κάνετε pentest σε διάφορα πιθανά services που εκτελούνται.\
**Επίσης, αξίζει να αναφερθεί ότι μπορείτε να προετοιμάσετε και κάποιες** λίστες με default usernames **και** passwords **και να προσπαθήσετε να κάνετε** bruteforce σε services με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες εντός του scope και τα assets τους· τώρα είναι ώρα να βρούμε τα domains εντός του scope.

_Παρακαλώ σημειώστε ότι με τις παρακάτω προτεινόμενες τεχνικές μπορείτε επίσης να βρείτε subdomains και ότι αυτές οι πληροφορίες δεν θα πρέπει να υποτιμώνται._

Αρχικά, θα πρέπει να αναζητήσετε το **κύριο domain** ή τα **κύρια domains** κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλα τα IP ranges των domains, θα μπορούσατε να προσπαθήσετε να εκτελέσετε **reverse dns lookups** σε αυτά τα **IPs για να βρείτε περισσότερα domains εντός του scope**. Προσπαθήστε να χρησιμοποιήσετε κάποιο dns server του victim ή κάποιον γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο administrator πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online εργαλείο για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλα ranges, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του εμπλουτισμού.

### **Reverse Whois (loop)**

Μέσα σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα οργανισμού**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Ακόμη πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **reverse whois lookups χρησιμοποιώντας οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλα whois registries όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - Δωρεάν web, όχι δωρεάν API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Όχι δωρεάν
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Όχι δωρεάν (μόνο **100 δωρεάν** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Όχι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Όχι δωρεάν (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Όχι δωρεάν (API)

Μπορείτε να αυτοματοποιήσετε αυτή την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτείται κλειδί API του whoxy).\
Μπορείτε επίσης να εκτελέσετε αυτόματο reverse whois discovery με το [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτή την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να κάνετε αναζήτηση με βάση αυτά τα trackers και άλλα στοιχεία:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (εντοπίζει related sites μέσω κοινών analytics/trackers)

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε related domains και subdomains του target αναζητώντας το ίδιο favicon icon hash; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), το οποίο δημιουργήθηκε από τον [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς μπορείτε να το χρησιμοποιήσετε:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Με απλά λόγια, το favihash θα μας επιτρέψει να ανακαλύψουμε domains που έχουν το ίδιο favicon icon hash με το target μας.

![Έξοδος του favihash που χρησιμοποιείται για την ανακάλυψη domains με το ίδιο favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Χρησιμοποιήστε ένα γνωστό favicon hash ως pivot στο Shodan ή στο FOFA, για να βρείτε άλλα εκτεθειμένα instances της ίδιας technology.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Έτσι μπορείτε να **υπολογίσετε το favicon hash** ενός web (MMH3 πάνω στα **base64-encoded** bytes του favicon):
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url, timeout=10)
favicon = codecs.encode(response.content, "base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
Μπορείτε επίσης να λάβετε favicon hashes σε κλίμακα με το [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και στη συνέχεια να κάνετε pivot σε Shodan/Censys.

Αντιμετωπίστε τα favicon fingerprints ως ενδείξεις και επικυρώστε τα με περιβάλλοντα σήματα.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίστε το hash ως ένδειξη, όχι ως απόδειξη**: Το MMH3 είναι συμπαγές· είναι πιθανές οι collisions, τα reused icons και το σκόπιμο spoofing.
- **Κάντε probe σε περισσότερα από** `/favicon.ico`: ελέγξτε framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και HTML tags `<link rel="icon">`.
- **Τα static assets μπορεί να παραμένουν προσβάσιμα πίσω από ελέγχους WAF/SSO/IdP**: ζητήστε το icon απευθείας και εξετάστε τα `ETag`, `Last-Modified`, redirects και cache headers.
- **Επικυρώστε τα matches με περιβάλλοντα σήματα**: συγκρίνετε τον τίτλο, το HTML/body hash, τα headers, τα TLS certificate subjects/SANs, τα product components και τις exposed ports.
- **Κάντε cluster βάσει HTML/body hash**: ένα συνεπές template ενισχύει το fingerprint· mixed templates υποδεικνύουν generic ή shared icon.
- **Αντιμετωπίστε ένα hash που εμφανίζεται σε unrelated signatures, ports και products ως πιθανό honeypot ή placeholder.**
- **Σε ambiguous targets, συγκρίνετε μια πραγματική σελίδα με ένα nonexistent path** όπως `/_favicon_probe_<8-hex>`· οι matching hosting ή parking responses μπορεί να εξηγούν το shared icon.
- **Κάντε bootstrap το triage από Nuclei detection rules ή public datasets** που αντιστοιχίζουν favicon hashes σε products και CPEs.
- **Να θυμάστε το IP-centric coverage gap**: επιφάνειες πίσω από CDN, με SNI routing, anycast και domain-only surfaces μπορεί να απουσιάζουν από datasets τύπου Shodan.

### **Copyright / Uniq string**

Αναζητήστε μέσα στις web pages **strings που θα μπορούσαν να είναι κοινά σε διαφορετικά webs του ίδιου οργανισμού**. Το **copyright string** θα μπορούσε να αποτελέσει καλό παράδειγμα. Στη συνέχεια αναζητήστε αυτό το string στο **Google**, σε άλλα **browsers** ή ακόμη και στο **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως το
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
για την ανανέωση όλων των certificates σε έναν server ταυτόχρονα. Η συσχέτιση των timestamps των certificates ή των θέσεων στα certificate-transparency logs μπορεί να αποκαλύψει related domains.<sup>[[6]](#references)</sup>

Μπορείτε επίσης να χρησιμοποιήσετε απευθείας τα **certificate transparency** logs:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες dmarc**.\
Άλλα χρήσιμα εργαλεία είναι τα [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ένα εγκαταλελειμμένο A record μπορεί να γίνει προσβάσιμο όταν ένας cloud provider επαναassigns μια IP. Η σχετική έρευνα παρουσιάζει μια opportunistic ροή εργασίας που κάνει provision ένα instance και συσχετίζει τη διεύθυνσή του με passive DNS data· δοκιμάζετε σενάρια takeover μόνο μέσα στο εξουσιοδοτημένο scope.<sup>[[7]](#references)</sup>

### **Άλλοι τρόποι**

Επαναλαμβάνετε τα κατάλληλα discovery pivots κάθε φορά που βρίσκετε ένα νέο domain: κάθε αποτέλεσμα μπορεί να αποκαλύψει επιπλέον certificate names, passive-DNS relationships, favicon matches και organization identifiers που δεν ήταν ορατά από το αρχικό seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Όπως ήδη γνωρίζετε το όνομα του οργανισμού που κατέχει το IP space. Μπορείτε να κάνετε αναζήτηση με αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τα hosts που βρέθηκαν για νέα, μη αναμενόμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας web σελίδας, να λάβετε το **Organisation name** και στη συνέχεια να αναζητήσετε αυτό το όνομα μέσα στα **TLS certificates** όλων των web σελίδων που είναι γνωστές στο **shodan**, με το filter : `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)είναι ένα εργαλείο που αναζητά **domains που σχετίζονται** με ένα main domain και **subdomains** αυτών· είναι πραγματικά εξαιρετικό.

**Passive DNS / Historical DNS**

Τα Passive DNS data είναι εξαιρετικά για την εύρεση **παλιών και ξεχασμένων records** που εξακολουθούν να κάνουν resolve ή μπορούν να γίνουν takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Αναζήτηση για vulnerabilities**

Ελέγξτε για κάποιο [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί κάποιο domain**, αλλά **έχασε την ιδιοκτησία του**. Απλώς κάντε register σε αυτό (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε οποιοδήποτε **domain με διαφορετική IP** από αυτές που έχετε ήδη βρει στο assets discovery, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο ορισμένα tricks για να τις "attacking"**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον client, επομένως δεν είναι στο scope· να είστε προσεκτικοί._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες που βρίσκονται στο scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλα τα πιθανά subdomains κάθε domain που βρέθηκε.

> [!TIP]
> Σημειώστε ότι ορισμένα από τα εργαλεία και τις τεχνικές για την εύρεση domains μπορούν επίσης να βοηθήσουν στην εύρεση subdomains

### **DNS**

Ας προσπαθήσουμε να βρούμε **subdomains** από τα records του **DNS**. Θα πρέπει επίσης να δοκιμάσουμε για **Zone Transfer** (αν είναι vulnerable, θα πρέπει να το αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο ταχύτερος τρόπος για να αποκτήσετε πολλά subdomains είναι η αναζήτηση σε εξωτερικές πηγές. Τα πιο συχνά χρησιμοποιούμενα **εργαλεία** είναι τα ακόλουθα (για καλύτερα αποτελέσματα, διαμορφώστε τα API keys):

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
Υπάρχουν **άλλα ενδιαφέροντα tools/APIs** που, ακόμη και αν δεν εξειδικεύονται άμεσα στην εύρεση subdomains, θα μπορούσαν να φανούν χρήσιμα για την εύρεση subdomains, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) δωρεάν API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για την εύρεση subdomains
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
- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστά URLs από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιοδήποτε domain.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Συλλέγουν δεδομένα από το web αναζητώντας αρχεία JS και εξάγουν subdomains από αυτά.
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
- Το [**securitytrails.com**](https://securitytrails.com/) διαθέτει δωρεάν API για αναζήτηση subdomains και ιστορικού IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με bug-bounty programs**. Μπορείτε να αποκτήσετε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμη και να αποκτήσετε το scope που χρησιμοποιεί αυτό το project από το [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα tools εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να εντοπίσουμε νέα **subdomains**, πραγματοποιώντας brute-force σε DNS servers χρησιμοποιώντας πιθανά ονόματα subdomains.

Για αυτή την ενέργεια θα χρειαστείτε ορισμένα **common subdomains wordlists, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Καθώς και IPs καλών DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε το: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο συνιστώμενα tools για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο tool που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Αυτό, νομίζω, χρησιμοποιεί μόνο 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε `go`, που σας επιτρέπει να κάνετε enumerate έγκυρα subdomains χρησιμοποιώντας active bruteforce, καθώς και να κάνετε resolve subdomains με χειρισμό wildcard και εύκολη υποστήριξη input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης το `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί το asyncio για ασύγχρονο brute force ονομάτων domain.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Δεύτερος Γύρος DNS Brute-Force

Αφού βρείτε subdomains χρησιμοποιώντας open sources και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρέθηκαν, ώστε να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Αρκετά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Με δεδομένα τα domains και τα subdomains, δημιουργεί permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Με δεδομένα τα domains και τα subdomains, δημιουργεί permutations.
- Μπορείτε να βρείτε το **wordlist** των permutations του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Με δεδομένα τα domains και τα subdomains, δημιουργεί permutations. Αν δεν καθοριστεί αρχείο permutations, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία permutations για subdomains, μπορεί επίσης να προσπαθήσει να τα κάνει resolve (αλλά είναι καλύτερο να χρησιμοποιήσετε τα προηγούμενα σχολιασμένα tools).
- Μπορείτε να βρείτε το **wordlist** με τα permutations του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για την εκτέλεση permutations, mutations και alteration σε subdomains. Αυτό το εργαλείο θα εκτελέσει brute force στο αποτέλεσμα (δεν υποστηρίζει dns wild card).
- Μπορείτε να βρείτε το dmut permutations wordlist [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί νέα πιθανά ονόματα subdomains** σύμφωνα με υποδεικνυόμενα patterns, για να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Έξυπνη δημιουργία permutations

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει patterns παρόμοια με regex από τα subdomains που έχουν ανακαλυφθεί και δημιουργεί υποψήφια ονόματα για επίλυση.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένας fuzzer brute-force για subdomains, συνδυασμένος με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από DNS responses. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως ένα προσαρμοσμένο wordlist ή ιστορικά DNS/TLS records, για να συνθέσει με ακρίβεια περισσότερα αντίστοιχα domain names και να τα επεκτείνει ακόμη περισσότερο σε loop, με βάση τις πληροφορίες που συλλέγονται κατά τη διάρκεια του DNS scan.
```
echo www | subzuf facebook.com
```
### **Workflow Ανακάλυψης Subdomain**

Τα παραδείγματα workflow του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλήψιμη απαρίθμηση subdomain.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρήκατε μια IP address που περιέχει **μία ή περισσότερες web σελίδες** οι οποίες ανήκουν σε subdomains, μπορείτε να προσπαθήσετε να **βρείτε άλλα subdomains με web σελίδες σε αυτή την IP** αναζητώντας σε **OSINT sources** domains που αντιστοιχούν σε μια IP ή κάνοντας **brute-force VHost domain names σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε ορισμένα **VHosts σε IPs χρησιμοποιώντας το** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιο subdomain μπορεί να είναι κρυμμένο σε έναν web server, μπορείτε να προσπαθήσετε να το βρείτε με brute force:

Για vhosts που βασίζονται σε όνομα, κάντε fuzz το `Host` header και χρησιμοποιήστε το auto-calibration του ffuf για να φιλτράρετε την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>
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
> Με αυτήν την τεχνική ίσως μπορέσετε ακόμη και να αποκτήσετε πρόσβαση σε internal/hidden endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν το header _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί ένα έγκυρο domain/subdomain στο header _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να εκμεταλλευτείτε αυτήν τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force Buckets**

Κατά την αναζήτηση **subdomains**, έχετε το νου σας για να δείτε αν κάποιο **pointing** οδηγεί σε οποιονδήποτε τύπο **bucket** και, σε αυτή την περίπτωση, [**ελέγξτε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains εντός του scope, προσπαθήστε να [**κάνετε brute force σε πιθανά ονόματα bucket και να ελέγξετε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείτε να **παρακολουθείτε** αν δημιουργούνται **νέα subdomains** ενός domain, παρακολουθώντας τα Logs του **Certificate Transparency**, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση για vulnerabilities**

Ελέγξτε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**ελέγξτε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρείτε οποιοδήποτε **subdomain με IP διαφορετικό** από αυτά που έχετε ήδη εντοπίσει κατά την ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** (με χρήση των Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε σε **αυτό το βιβλίο ορισμένα tricks για να τις "attack"**.\
_Σημειώστε ότι μερικές φορές το subdomain φιλοξενείται σε IP που δεν ελέγχεται από τον client, επομένως δεν βρίσκεται εντός του scope· να είστε προσεκτικοί._

## IPs

Στα αρχικά βήματα μπορεί να έχετε **εντοπίσει ορισμένα IP ranges, domains και subdomains**.\
Ήρθε η ώρα να **συλλέξετε ξανά όλες τις IPs από αυτά τα ranges** και για τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας υπηρεσίες από τα ακόλουθα **free apis**, μπορείτε επίσης να βρείτε **προηγούμενες IPs που χρησιμοποιούνταν από domains και subdomains**. Αυτές οι IPs μπορεί να ανήκουν ακόμη στον client (και να σας επιτρέψουν να βρείτε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να ελέγξετε για domains που δείχνουν σε μια συγκεκριμένη IP address, χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση για vulnerabilities**

**Κάντε port scan σε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μη βρείτε εκεί κάτι ενδιαφέρον). Στις υπηρεσίες που εκτελούνται και εντοπίζονται, ενδέχεται να **μπορέσετε να βρείτε vulnerabilities**.

**Βρείτε έναν** [**οδηγό**](../pentesting-network/index.html) **σχετικά με το πώς να κάνετε scan σε hosts.**

## Αναζήτηση web servers

> Έχουμε βρει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τα IP ranges, τα domains και τα subdomains που βρίσκονται εντός του scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη πραγματοποιήσει κάποιο **recon των IPs και των domains που εντοπίστηκαν**, επομένως μπορεί να έχετε **ήδη βρει όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, τώρα θα δούμε ορισμένα **γρήγορα tricks για την αναζήτηση web servers** εντός του scope.

Παρακαλούμε σημειώστε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, επομένως θα πρέπει να εκτελέσετε επίσης **vulnerability** και **port scanning** (**εφόσον επιτρέπεται** από το scope).

Μια **γρήγορη μέθοδος** για την ανακάλυψη **ανοιχτών ports** που σχετίζονται με **web** servers, χρησιμοποιώντας το [**masscan**, μπορεί να βρεθεί εδώ](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι τα [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς περνάτε μια λίστα από domains και θα προσπαθήσει να συνδεθεί στις ports 80 (http) και 443 (https). Επιπλέον, μπορείτε να ορίσετε να δοκιμάσει και άλλα ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Τώρα που ανακαλύψατε **όλους τους web servers** που υπάρχουν στο scope (μεταξύ των **IPs** της εταιρείας και όλων των **domains** και **subdomains**) πιθανότατα **δεν γνωρίζετε από πού να ξεκινήσετε**. Ας το κάνουμε, λοιπόν, απλό και ας ξεκινήσουμε λαμβάνοντας screenshots όλων. Απλώς **ρίχνοντας μια ματιά** στην **main page** μπορείτε να εντοπίσετε **περίεργα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να υλοποιήσετε την προτεινόμενη ιδέα μπορείτε να χρησιμοποιήσετε τα [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε στη συνέχεια να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να επεξεργαστεί όλα τα **screenshots** και να σας υποδείξει **τι είναι πιθανό να περιέχει vulnerabilities** και τι όχι.

## Public Cloud Assets

Για να εντοπίσετε πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει **να ξεκινήσετε με μια λίστα από keywords που ταυτοποιούν την εταιρεία**. Για παράδειγμα, για μια crypto εταιρεία θα μπορούσατε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις θα πρέπει να δημιουργήσετε **permutations** (δείτε το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τις wordlists που θα προκύψουν μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάστε ότι, όταν αναζητάτε Cloud Assets, θα πρέπει να ψάχνετε για περισσότερα από απλώς buckets στο AWS.

### **Looking for vulnerabilities**

Αν εντοπίσετε πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει να **αποκτήσετε πρόσβαση σε αυτά** και να προσπαθήσετε να δείτε τι σας προσφέρουν και αν μπορείτε να τα κάνετε abuse.

## Emails

Με τα **domains** και τα **subdomains** που βρίσκονται μέσα στο scope, ουσιαστικά έχετε όλα όσα **χρειάζεστε για να ξεκινήσετε την αναζήτηση emails**. Αυτά είναι τα **APIs** και τα **tools** που έχουν λειτουργήσει καλύτερα για εμένα στην εύρεση emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (free version)
- API του [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API του [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Τα emails θα σας φανούν χρήσιμα αργότερα για **brute-force web logins και auth services** (όπως το SSH). Επίσης, είναι απαραίτητα για **phishings**. Επιπλέον, αυτά τα APIs θα σας δώσουν ακόμη περισσότερες **πληροφορίες για το άτομο** πίσω από το email, κάτι που είναι χρήσιμο για την phishing campaign.

## Credential Leaks

Με τα **domains,** τα **subdomains** και τα **emails** μπορείτε να ξεκινήσετε να αναζητάτε credentials που έχουν γίνει leak στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Αν βρείτε **έγκυρα credentials που έχουν γίνει leak**, αυτό αποτελεί πολύ εύκολη επιτυχία.

## Secrets Leaks

Τα credential leaks σχετίζονται με hacks εταιρειών, όπου **ευαίσθητες πληροφορίες έγιναν leak και πουλήθηκαν**. Ωστόσο, οι εταιρείες μπορεί να επηρεαστούν και από **άλλα leaks**, των οποίων οι πληροφορίες δεν υπάρχουν σε αυτές τις databases:

### Github Leaks

Credentials και APIs μπορεί να έχουν γίνει leak στα **public repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται για αυτή την εταιρεία στο github.\
Μπορείτε να χρησιμοποιήσετε το **tool** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **public repos** ενός **organization** και των **developers** του και να εκτελέσετε αυτόματα το [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω τους.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για την εκτέλεση του **gitleaks** εναντίον όλου του **text** που παρέχεται μέσω **URLs passed** σε αυτό, καθώς μερικές φορές και οι **web pages περιέχουν secrets**.

#### Github Dorks

Ελέγξτε τη [GitHub dorks and leaks page](github-leaked-secrets.md) για πιθανά **GitHub dorks** προς αναζήτηση στο organization.

### Pastes Leaks

Μερικές φορές attackers ή απλώς εργαζόμενοι θα **δημοσιεύσουν περιεχόμενο της εταιρείας σε ένα paste site**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά είναι πολύ ενδιαφέρον να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το tool [**Pastos**](https://github.com/carlospolop/Pastos) για αναζήτηση σε περισσότερα από 80 paste sites ταυτόχρονα.

### Google Dorks

Τα παλιά αλλά πολύτιμα google dorks είναι πάντα χρήσιμα για την εύρεση **εκτεθειμένων πληροφοριών που δεν θα έπρεπε να βρίσκονται εκεί**. Το μόνο πρόβλημα είναι ότι το [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανές queries που δεν μπορείτε να εκτελέσετε χειροκίνητα. Έτσι, μπορείτε να επιλέξετε τις 10 αγαπημένες σας ή να χρησιμοποιήσετε ένα **tool όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τις εκτελέσετε όλες**.

_Σημειώστε ότι τα tools που προσπαθούν να εκτελέσουν ολόκληρη τη database μέσω του κανονικού Google browser δεν θα ολοκληρώσουν ποτέ, καθώς η Google θα σας κάνει block πολύ σύντομα._

### **Looking for vulnerabilities**

Αν βρείτε **έγκυρα credentials ή API tokens που έχουν γίνει leak**, αυτό αποτελεί πολύ εύκολη επιτυχία.

## Public Code Vulnerabilities

Αν διαπιστώσετε ότι η εταιρεία διαθέτει **open-source code**, μπορείτε να το **αναλύσετε** και να αναζητήσετε **vulnerabilities** σε αυτό.

**Ανάλογα με τη γλώσσα** υπάρχουν διαφορετικά **tools** που μπορείτε να χρησιμοποιήσετε· δείτε τη λίστα με τα [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν services που σας επιτρέπουν να **σκανάρετε public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των vulnerabilities** που εντοπίζουν οι bug hunters βρίσκεται μέσα σε **web applications**, επομένως σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία testing web applications**, και μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική αναφορά στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρόλο που δεν θα πρέπει να περιμένετε να εντοπίσουν πολύ ευαίσθητα vulnerabilities, είναι χρήσιμα για την ενσωμάτωσή τους σε **workflows, ώστε να έχετε κάποιες αρχικές πληροφορίες για το web.**

## Recapitulation

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη ολοκληρώσει **όλο το basic enumeration**. Ναι, είναι basic, επειδή μπορεί να γίνει πολύ περισσότερο enumeration (θα δούμε περισσότερα tricks αργότερα).

Έχετε ήδη:

1. Εντοπίσει όλες τις **εταιρείες** μέσα στο scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και εκτελέσει κάποιο vuln scan, αν βρίσκεται εντός scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Εντοπίσει όλες τις **IPs** (από και **όχι από CDNs**) μέσα στο scope.
6. Εντοπίσει όλους τους **web servers** και λάβει ένα **screenshot** από αυτούς (υπάρχει κάτι περίεργο που αξίζει βαθύτερη εξέταση;)
7. Εντοπίσει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. Εντοπίσει **emails**, **credential leaks** και **secret leaks** που θα μπορούσαν να σας δώσουν μια **μεγάλη επιτυχία πολύ εύκολα**.
9. Εκτελέσει **pentesting σε όλα τα web** που εντοπίσατε

## **Full Recon Automatic Tools**

Υπάρχουν αρκετά tools που θα εκτελέσουν μέρος των προτεινόμενων ενεργειών εναντίον ενός δεδομένου scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και χωρίς updates

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
