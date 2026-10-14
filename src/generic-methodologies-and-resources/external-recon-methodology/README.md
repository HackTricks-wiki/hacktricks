# Μεθοδολογία Εξωτερικού Recon

{{#include ../../banners/hacktricks-training.md}}

## Ανακαλύψεις assets

> Σου είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία είναι εντός scope και θέλεις να ανακαλύψεις τι ακριβώς της ανήκει.

Στόχος αυτής της φάσης είναι να εντοπίσεις όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και, στη συνέχεια, όλα τα **assets** αυτών των εταιρειών. Για να το πετύχουμε, θα:<sup>[[1]](#references)</sup>

1. Βρούμε τις εξαγορές της κύριας εταιρείας, ώστε να εντοπίσουμε τις εταιρείες που είναι εντός scope.
2. Βρούμε το ASN (αν υπάρχει) κάθε εταιρείας, ώστε να εντοπίσουμε τις περιοχές IP που της ανήκουν.
3. Χρησιμοποιήσουμε reverse whois lookups για να αναζητήσουμε άλλες καταχωρίσεις (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιήσουμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το κόλπο με το `ssl` μπορεί να εφαρμοστεί αναδρομικά).

### **Εξαγορές**

Πρώτα απ' όλα, πρέπει να μάθουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μία επιλογή είναι να επισκεφτείς το [https://www.crunchbase.com/](https://www.crunchbase.com), να **αναζητήσεις** την **κύρια εταιρεία** και να **κάνεις κλικ** στο "**acquisitions**". Εκεί θα δεις άλλες εταιρείες που εξαγοράστηκαν από την κύρια εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφτείς τη σελίδα της κύριας εταιρείας στη **Wikipedia** και να αναζητήσεις τις **εξαγορές**.\
Για εισηγμένες εταιρείες, έλεγξε τις καταχωρίσεις **SEC/EDGAR**, τις σελίδες **investor relations** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμιες εταιρικές δομές και θυγατρικές, δοκίμασε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ωραία, σε αυτό το σημείο θα πρέπει να γνωρίζεις όλες τις εταιρείες που είναι εντός scope. Ας δούμε πώς θα βρούμε τα assets τους.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που αποδίδεται σε ένα **αυτόνομο σύστημα** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** **διευθύνσεων IP** με σαφώς καθορισμένη πολιτική πρόσβασης σε εξωτερικά δίκτυα. Διαχειρίζεται από έναν οργανισμό, αλλά μπορεί να αποτελείται από αρκετούς παρόχους.

Είναι χρήσιμο να διαπιστώσουμε αν έχουν **εκχωρηθεί ASN στην εταιρεία**, ώστε να βρούμε τις **περιοχές IP** της. Θα ήταν χρήσιμο να γίνει **έλεγχος ευπαθειών** σε όλους τους **hosts** εντός του **scope** και να **αναζητηθούν domains** μέσα σε αυτές τις IP.\
Μπορείς να κάνεις **αναζήτηση** με βάση το **όνομα** της εταιρείας, μια **IP** ή ένα **domain** στο [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή όπου βρίσκεται η εταιρεία, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Σε κάθε περίπτωση, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(περιοχές IP και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Επίσης, το enumeration του [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** συγκεντρώνει και συνοψίζει αυτόματα τα ASN στο τέλος της σάρωσης.

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

Μπορείτε επίσης να βρείτε τα εύρη IP ενός οργανισμού χρησιμοποιώντας το [http://asnlookup.com/](http://asnlookup.com) (διαθέτει δωρεάν API).\
Μπορείτε να βρείτε την IP και το ASN ενός domain χρησιμοποιώντας το [http://ipv4info.com/](http://ipv4info.com).

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets εντός scope**, οπότε, αν έχετε άδεια, μπορείτε να εκτελέσετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να εκτελέσετε κάποια [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως το** Shodan, το Censys ή το ZoomEye **για να εντοπίσετε** ανοιχτές θύρες **και, ανάλογα με όσα βρείτε, θα πρέπει να** ανατρέξετε σε αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορες πιθανές υπηρεσίες που εκτελούνται.\
**Επίσης, αξίζει να αναφέρουμε ότι μπορείτε να ετοιμάσετε λίστες με** προεπιλεγμένα usernames **και** passwords **και να δοκιμάσετε να κάνετε** bruteforce σε υπηρεσίες με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες εντός scope και τα assets τους· τώρα είναι ώρα να βρούμε τα domains εντός scope.

_Σημειώστε ότι οι παρακάτω προτεινόμενες τεχνικές μπορούν επίσης να αποκαλύψουν subdomains, και δεν πρέπει να υποτιμάτε αυτές τις πληροφορίες._

Πρώτα απ’ όλα, θα πρέπει να αναζητήσετε το **κύριο domain** ή τα **κύρια domains** κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλα τα εύρη IP των domains, μπορείτε να δοκιμάσετε να εκτελέσετε **reverse DNS lookups** σε αυτές τις **IP για να βρείτε περισσότερα domains εντός scope**. Δοκιμάστε να χρησιμοποιήσετε κάποιον DNS server του θύματος ή κάποιον ευρέως γνωστό DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online εργαλείο για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλα εύρη, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του εμπλουτισμού των δεδομένων.

### **Reverse Whois (loop)**

Σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **το όνομα του οργανισμού**, **τη διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Ακόμα πιο ενδιαφέρον, όμως, είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **reverse whois lookups με βάση οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλες εγγραφές whois στις οποίες εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** μέσω web, το API επί πληρωμή.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Επί πληρωμή
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Επί πληρωμή (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Επί πληρωμή
- [https://securitytrails.com/](https://securitytrails.com/) - Επί πληρωμή (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Επί πληρωμή (API)

Μπορείτε να αυτοματοποιήσετε αυτή την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτεί κλειδί API του whoxy).\
Μπορείτε επίσης να εκτελέσετε αυτόματη αναζήτηση reverse whois με το [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτή την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που εντοπίζετε ένα νέο domain.**

### **Trackers**

Αν εντοπίσετε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να αναζητάτε με βάση αυτούς τους trackers και άλλα στοιχεία:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (εντοπίζει σχετικούς ιστότοπους με βάση κοινά analytics/trackers)
- [**StackScan**](https://www.stackscan.com) - **Δωρεάν επίπεδο** (Web και API). Κάντε pivot σε οποιοδήποτε asset σερβίρεται, όχι μόνο σε tracker IDs: σε ένα script path, σε ένα όνομα self-hosted bundle ή στον host από τον οποίο φορτώνεται ένα asset, για να εμφανιστεί κάθε ιστότοπος που το διαθέτει

Το API επιστρέφει το stack για ένα μεμονωμένο domain, κάτι που είναι χρήσιμο για να επιβεβαιώσετε ότι ένα υποψήφιο asset ανήκει στο ίδιο estate:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Επιστρέφει κάθε τεχνολογία που εντοπίστηκε μαζί με την κατηγορία της. Το asset pivoting προς το παρόν λειτουργεί μόνο για web assets, ενώ το API υποστηρίζει αναζήτηση ανά domain.

### **Favicon**

Γνωρίζατε ότι μπορούμε να εντοπίσουμε σχετικά domains και subdomains του στόχου μας αναζητώντας το ίδιο hash του εικονιδίου favicon; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), που δημιούργησε ο [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς μπορείτε να το χρησιμοποιήσετε:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Αποτελέσματα του Favihash που χρησιμοποιούνται για την ανακάλυψη domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash μάς επιτρέπει να ανακαλύπτουμε domains που έχουν το ίδιο hash favicon με τον στόχο μας.

![Έξοδος του favihash που χρησιμοποιείται για την ανακάλυψη domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Χρησιμοποιήστε ένα γνωστό hash favicon ως pivot στο Shodan ή στο FOFA, για να βρείτε άλλες εκτεθειμένες εγκαταστάσεις της ίδιας τεχνολογίας.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Έτσι μπορείτε να **υπολογίσετε το favicon hash** ενός ιστότοπου (MMH3 πάνω στα **base64-encoded** bytes του favicon):

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

Μπορείτε επίσης να συλλέξετε hashes favicon σε μεγάλη κλίμακα με το [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και έπειτα να κάνετε pivot στο Shodan/Censys.

Αντιμετωπίστε τα αποτυπώματα favicon ως ενδείξεις και επαληθεύστε τα με βάση τα γύρω σήματα.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίστε το hash ως ένδειξη, όχι ως απόδειξη**: το MMH3 είναι συμπαγές· είναι πιθανά collisions, επαναχρησιμοποιημένα εικονίδια και εσκεμμένη παραποίηση.
- **Ελέγξτε περισσότερα από το** `/favicon.ico`: εξετάστε διαδρομές framework/build, αρχεία manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και ετικέτες HTML `<link rel="icon">`.
- **Τα στατικά assets μπορεί να παραμένουν προσβάσιμα πίσω από ελέγχους WAF/SSO/IdP**: ζητήστε απευθείας το εικονίδιο και εξετάστε τα `ETag`, `Last-Modified`, τις ανακατευθύνσεις και τις κεφαλίδες cache.
- **Επαληθεύστε τις αντιστοιχίες με βάση τα γύρω σήματα**: συγκρίνετε τον τίτλο, το hash HTML/body, τις κεφαλίδες, τα subjects/SANs των πιστοποιητικών TLS, τα στοιχεία προϊόντων και τις εκτεθειμένες θύρες.
- **Ομαδοποιήστε με βάση το hash HTML/body**: ένα συνεπές template ενισχύει το αποτύπωμα· διαφορετικά templates υποδηλώνουν ένα γενικό ή κοινόχρηστο εικονίδιο.
- **Αντιμετωπίστε ένα hash που εμφανίζεται σε άσχετες υπογραφές, θύρες και προϊόντα ως πιθανό honeypot ή placeholder.**
- **Σε αμφίβολους στόχους, συγκρίνετε μια πραγματική σελίδα με μια ανύπαρκτη διαδρομή**, όπως `/_favicon_probe_<8-hex>`· οι ίδιες απαντήσεις φιλοξενίας ή στάθμευσης μπορεί να εξηγούν το κοινό εικονίδιο.
- **Ξεκινήστε τη διαλογή με κανόνες ανίχνευσης του Nuclei ή δημόσια datasets** που αντιστοιχίζουν hashes favicon σε προϊόντα και CPE.
- **Θυμηθείτε το κενό κάλυψης που οφείλεται στην εστίαση στις IP**: επιφάνειες πίσω από CDN, με δρομολόγηση SNI, anycast και μόνο μέσω domain μπορεί να απουσιάζουν από datasets τύπου Shodan.

### **Copyright / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που θα μπορούσαν να είναι κοινές σε διαφορετικούς ιστότοπους του ίδιου οργανισμού**. Η **συμβολοσειρά copyright** θα μπορούσε να είναι ένα καλό παράδειγμα. Έπειτα αναζητήστε αυτή τη συμβολοσειρά στο **google**, σε άλλα **browsers** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **Χρόνος CRT**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως το

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

για την ταυτόχρονη ανανέωση όλων των certificates σε έναν server. Η συσχέτιση των χρονικών σημάνσεων των certificates ή των θέσεών τους στα logs του certificate transparency μπορεί να αποκαλύψει σχετικά domains.<sup>[[6]](#references)</sup>

Χρησιμοποιήστε επίσης απευθείας τα logs του **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες DMARC αλληλογραφίας

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να εντοπίσετε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες DMARC**.\
Άλλα χρήσιμα εργαλεία είναι τα [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Μια εγκαταλελειμμένη εγγραφή A μπορεί να γίνει προσβάσιμη όταν ένας cloud provider εκχωρήσει ξανά μια IP. Η έρευνα που αναφέρεται παρουσιάζει μια ευκαιριακή ροή εργασιών που δημιουργεί ένα instance και συσχετίζει τη διεύθυνσή του με δεδομένα passive DNS· δοκιμάζετε σενάρια takeover μόνο εντός του εξουσιοδοτημένου scope.<sup>[[7]](#references)</sup>

### **Άλλοι τρόποι**

Επαναλάβετε τις κατάλληλες μεθόδους αναζήτησης κάθε φορά που εντοπίζετε ένα νέο domain: κάθε αποτέλεσμα μπορεί να αποκαλύψει επιπλέον ονόματα certificate, σχέσεις passive DNS, αντιστοιχίες favicon και αναγνωριστικά οργανισμού που δεν ήταν ορατά από το αρχικό seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Αφού γνωρίζετε ήδη το όνομα του οργανισμού στον οποίο ανήκει ο χώρος διευθύνσεων IP, μπορείτε να αναζητήσετε αυτά τα δεδομένα στο Shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους hosts που βρέθηκαν για νέα, μη αναμενόμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας ιστοσελίδας, να λάβετε το **Organisation name** και έπειτα να αναζητήσετε αυτό το όνομα στα **TLS certificates** όλων των ιστοσελίδων που γνωρίζει το **Shodan** με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is ένα εργαλείο που αναζητά **domains που σχετίζονται** με ένα κύριο domain και τα **subdomains** τους· είναι πραγματικά εντυπωσιακό.

**Passive DNS / Historical DNS**

Τα δεδομένα Passive DNS είναι εξαιρετικά χρήσιμα για τον εντοπισμό **παλιών και ξεχασμένων εγγραφών** που εξακολουθούν να επιλύονται ή να γίνουν αντικείμενο takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Αναζήτηση ευπαθειών**

Ελέγξτε για κάποιο [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί ένα domain**, αλλά **έχει χάσει την κυριότητά του**. Απλώς κατοχυρώστε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε κάποιο **domain με διαφορετική IP** από αυτές που εντοπίσατε ήδη κατά την ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και ένα [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο ορισμένα κόλπα για να τις «επιτεθείτε»**.\
_Λάβετε υπόψη ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, επομένως βρίσκεται εκτός scope· προσέξτε._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες εντός scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να εντοπίσουμε όλα τα πιθανά subdomains κάθε domain που βρέθηκε.

> [!TIP]
> Σημειώστε ότι ορισμένα εργαλεία και τεχνικές για τον εντοπισμό domains μπορούν επίσης να βοηθήσουν στον εντοπισμό subdomains.

### **DNS**

Ας προσπαθήσουμε να εντοπίσουμε **subdomains** από τις εγγραφές **DNS**. Θα πρέπει επίσης να δοκιμάσουμε το **Zone Transfer** (αν είναι ευάλωτο, θα πρέπει να το αναφέρετε).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Για APIs και πλατφόρμες που καλύπτουν υποδομές, φήμη, αρχεία παραβιάσεων και enrichment πέρα από την ανακάλυψη subdomains, δείτε τον [κατάλογο APIs για αναγνώριση και threat intelligence](reconnaissance-and-threat-intelligence-apis.md).

Ο πιο γρήγορος τρόπος για να βρείτε πολλά subdomains είναι να κάνετε αναζήτηση σε εξωτερικές πηγές. Τα **εργαλεία** που χρησιμοποιούνται περισσότερο είναι τα εξής (για καλύτερα αποτελέσματα, ρυθμίστε τα API keys):


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

Υπάρχουν **και άλλα ενδιαφέροντα εργαλεία/API** που, παρόλο που δεν ειδικεύονται άμεσα στην εύρεση subdomains, θα μπορούσαν να φανούν χρήσιμα για την εύρεση subdomains, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) δωρεάν API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για να εντοπίσει υποτομείς.

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

- [**gau**](https://github.com/lc/gau)**:** συλλέγει γνωστά URL από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιοδήποτε domain.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Σαρώνουν τον ιστό αναζητώντας αρχεία JS και εξάγουν υποτομείς από αυτά.

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

- [**Censys: εργαλείο εύρεσης υποτομέων**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**securitytrails.com**](https://securitytrails.com/) διαθέτει δωρεάν API για αναζήτηση subdomains και ιστορικού IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με προγράμματα bug-bounty**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/dr-0x0x/chaospy), ή ακόμα και να δείτε το scope που χρησιμοποιεί αυτό το project: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε εδώ μια **σύγκριση** πολλών από αυτά τα εργαλεία: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** κάνοντας brute-force στους DNS servers με πιθανά ονόματα subdomain.

Για αυτήν την ενέργεια θα χρειαστείτε μερικές **συνηθισμένες wordlists subdomains, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Θα χρειαστείτε επίσης IPs αξιόπιστων DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε το [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα εργαλεία που συνιστώνται περισσότερο για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, αλλά επιρρεπές σε false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Αυτό, νομίζω, χρησιμοποιεί απλώς 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε Go, που επιτρέπει την απαρίθμηση έγκυρων subdomains με active bruteforce, καθώς και την επίλυση subdomains με διαχείριση wildcard και εύκολη υποστήριξη εισόδου-εξόδου.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης το `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί το asyncio για να κάνει ασύγχρονο brute force σε ονόματα domain.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Δεύτερος γύρος DNS Brute-Force

Αφού εντοπίσετε subdomains χρησιμοποιώντας ανοικτές πηγές και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρέθηκαν, ώστε να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Για αυτόν τον σκοπό είναι χρήσιμα αρκετά εργαλεία:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δέχεται domains και subdomains και δημιουργεί permutations.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Με δεδομένα domains και subdomains, δημιουργεί permutations.
  - Μπορείτε να βρείτε το **wordlist** για τα permutations του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Με δεδομένους τους τομείς και τους υποτομείς, δημιουργεί μεταθέσεις. Αν δεν καθοριστεί αρχείο μεταθέσεων, το gotator θα χρησιμοποιήσει το δικό του.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία permutations των subdomains, μπορεί επίσης να προσπαθήσει να τα επιλύσει (αλλά είναι προτιμότερο να χρησιμοποιήσεις τα εργαλεία που αναφέρθηκαν προηγουμένως).
  - Μπορείς να βρεις τη **wordlist** για τα altdns permutations [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για την παραγωγή permutations, mutations και παραλλαγών υποτομέων. Αυτό το εργαλείο θα κάνει brute force στο αποτέλεσμα (δεν υποστηρίζει dns wild card).
  - Μπορείτε να βρείτε τη λίστα λέξεων με τα dmut permutations [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί πιθανά νέα ονόματα subdomain** σύμφωνα με τα καθορισμένα μοτίβα, για να εντοπίσει περισσότερα subdomain.

#### Δημιουργία έξυπνων μεταθέσεων

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει μοτίβα τύπου regex από τα subdomain που έχουν εντοπιστεί και δημιουργεί υποψήφια ονόματα προς επίλυση.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** Το _subzuf_ είναι ένα fuzzer brute-force για subdomain, σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από τις απαντήσεις DNS. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως μια προσαρμοσμένη wordlist ή ιστορικές εγγραφές DNS/TLS, για να συνθέτει με ακρίβεια περισσότερα αντίστοιχα domain names και να τα επεκτείνει περαιτέρω σε έναν βρόχο, με βάση τις πληροφορίες που συλλέγονται κατά τη σάρωση DNS.

```
echo www | subzuf facebook.com
```

### **Ροή εργασίας εντοπισμού subdomain**

Παραδείγματα workflows του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλήψιμη απαρίθμηση subdomain.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρείτε μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** οι οποίες ανήκουν σε subdomain, μπορείτε να προσπαθήσετε να **βρείτε άλλα subdomain με ιστοσελίδες σε αυτή την IP**, αναζητώντας σε **πηγές OSINT** domain που αντιστοιχούν σε μια IP ή κάνοντας **brute force ονομάτων domain VHost σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε ορισμένα **VHost σε IP χρησιμοποιώντας** το [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα API**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιο subdomain μπορεί να είναι κρυμμένο σε έναν web server, μπορείτε να δοκιμάσετε brute force:

Για vhost που βασίζονται σε όνομα, κάντε fuzz το header `Host` και χρησιμοποιήστε το auto-calibration του ffuf για να φιλτράρετε την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>

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
> Με αυτή την τεχνική μπορεί να καταφέρετε να αποκτήσετε πρόσβαση ακόμη και σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να καταχραστείτε αυτή τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute force για buckets**

Κατά την αναζήτηση **subdomains**, έχετε τον νου σας μήπως κάποιο **δείχνει** σε κάποιο είδος **bucket** και, σε αυτή την περίπτωση, [**ελέγξτε τα δικαιώματα**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains εντός του scope, δοκιμάστε να [**κάνετε brute force σε πιθανά ονόματα bucket και να ελέγξετε τα δικαιώματα**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείτε να **παρακολουθείτε** αν δημιουργούνται **νέα subdomains** ενός domain παρακολουθώντας τα Logs του **Certificate Transparency**, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση για ευπάθειες**

Ελέγξτε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**ελέγξτε τα δικαιώματα**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρείτε **subdomain με IP διαφορετική** από αυτές που εντοπίσατε ήδη κατά την ανακάλυψη των assets, θα πρέπει να πραγματοποιήσετε μια **βασική σάρωση ευπαθειών** (με Nessus ή OpenVAS) και κάποια [**σάρωση θυρών**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο μερικά κόλπα για να τις «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το subdomain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, επομένως δεν ανήκει στο scope. Να είστε προσεκτικοί._

## IPs

Στα αρχικά βήματα μπορεί να **εντοπίσατε κάποιες περιοχές IP, domains και subdomains**.\
Ήρθε η ώρα να **συγκεντρώσετε όλες τις IPs από αυτές τις περιοχές**, καθώς και τις IPs για τα **domains/subdomains (μέσω DNS queries).**

Χρησιμοποιώντας υπηρεσίες από τα παρακάτω **δωρεάν APIs**, μπορείτε επίσης να βρείτε **IP που χρησιμοποιούσαν παλαιότερα domains και subdomains**. Αυτές οι IP μπορεί να ανήκουν ακόμη στον πελάτη (και να σας επιτρέψουν να εντοπίσετε [**παρακάμψεις του CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να αναζητήσετε domains που δείχνουν σε μια συγκεκριμένη διεύθυνση IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση για ευπάθειες**

**Σαρώστε τις θύρες όλων των IP που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μη βρείτε κάτι ενδιαφέρον εκεί). Στις υπηρεσίες που εντοπίστηκαν να εκτελούνται ενδέχεται να **βρείτε ευπάθειες**.

**Βρείτε έναν** [**οδηγό**](../pentesting-network/index.html) **σχετικά με τη σάρωση hosts.**

## Αναζήτηση web servers

> Έχουμε βρει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τις περιοχές IP, τα domains και τα subdomains εντός του scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη κάνει **recon στις IP και στα domains που εντοπίσατε**, επομένως μπορεί να έχετε **ήδη βρει όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, θα δούμε τώρα μερικά **γρήγορα κόλπα για την αναζήτηση web servers** εντός του scope.

Σημειώστε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, επομένως θα πρέπει να πραγματοποιήσετε επίσης **σάρωση ευπαθειών** και **σάρωση θυρών** (**αν επιτρέπεται** από το scope).

Μια **γρήγορη μέθοδος** για τον εντοπισμό **ανοιχτών θυρών** που σχετίζονται με **web** servers, χρησιμοποιώντας το [**masscan, θα τη βρείτε εδώ**](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** το [**fprobe**](https://github.com/theblackturtle/fprobe) και το [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς περνάτε μια λίστα με domains και το εργαλείο θα προσπαθήσει να συνδεθεί στις θύρες 80 (http) και 443 (https). Επιπλέον, μπορείτε να ορίσετε να δοκιμάσει και άλλες θύρες:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Στιγμιότυπα οθόνης**

Τώρα που έχετε εντοπίσει **όλους τους web servers** που περιλαμβάνονται στο scope (ανάμεσα στις **IP** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν ξέρετε από πού να ξεκινήσετε**. Ας το απλοποιήσουμε, λοιπόν, ξεκινώντας απλώς με τη λήψη στιγμιότυπων οθόνης όλων. Αρκεί να **ρίξετε μια ματιά** στην **κύρια σελίδα** για να εντοπίσετε **παράξενα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να υλοποιήσετε την ιδέα, μπορείτε να χρησιμοποιήσετε τα [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε στη συνέχεια να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να αναλύσετε όλα τα **στιγμιότυπα οθόνης** και να σας υποδείξει **ποια είναι πιθανό να περιέχουν ευπάθειες** και ποια όχι.

## Δημόσια στοιχεία Cloud

Για να εντοπίσετε πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει **να ξεκινήσετε με μια λίστα λέξεων-κλειδιών που την προσδιορίζουν**. Για παράδειγμα, για μια εταιρεία crypto, μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, χρησιμοποιήστε αυτές τις λέξεις για να δημιουργήσετε **παραλλαγές** (για περισσότερες πληροφορίες, δείτε τη [**Δεύτερη φάση DNS Brute-Force**](#second-dns-bruteforce-round)).

Με τις wordlists που θα προκύψουν, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάστε ότι κατά την αναζήτηση Cloud Assets, θα πρέπει να **αναζητάτε περισσότερα από απλώς buckets στο AWS**.

### **Αναζήτηση ευπαθειών**

Αν εντοπίσετε πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει να **αποκτήσετε πρόσβαση σε αυτά** και να δείτε τι παρέχουν και αν μπορείτε να τα εκμεταλλευτείτε.

## Email

Με τα **domains** και τα **subdomains** που περιλαμβάνονται στο scope, έχετε ουσιαστικά όλα όσα **χρειάζεστε για να ξεκινήσετε την αναζήτηση email**. Αυτά είναι τα **APIs** και τα **εργαλεία** που έχουν αποδώσει καλύτερα για μένα στην εύρεση email μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
- API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
- API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση ευπαθειών**

Τα email θα σας φανούν χρήσιμα αργότερα για **brute-force σε web logins και auth services** (όπως το SSH). Είναι επίσης απαραίτητα για **phishing**. Επιπλέον, αυτά τα APIs θα σας δώσουν περισσότερες **πληροφορίες για το άτομο** πίσω από το email, κάτι χρήσιμο για την καμπάνια phishing.

## Διαρροές διαπιστευτηρίων

Με τα **domains,** **subdomains** και **email**, μπορείτε να ξεκινήσετε την αναζήτηση διαπιστευτηρίων που διέρρευσαν στο παρελθόν και σχετίζονται με αυτά τα email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα διαπιστευτήρια που έχουν διαρρεύσει**, πρόκειται για μια πολύ εύκολη επιτυχία.

## Διαρροές secrets

Οι διαρροές διαπιστευτηρίων σχετίζονται με παραβιάσεις εταιρειών, κατά τις οποίες **διέρρευσαν και πωλήθηκαν ευαίσθητες πληροφορίες**. Ωστόσο, οι εταιρείες μπορεί να έχουν επηρεαστεί και από **άλλες διαρροές**, των οποίων οι πληροφορίες δεν περιλαμβάνονται σε αυτές τις βάσεις δεδομένων:

### Διαρροές στο Github

Διαπιστευτήρια και APIs μπορεί να έχουν διαρρεύσει στα **δημόσια repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται σε αυτήν.\
Μπορείτε να χρησιμοποιήσετε το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **δημόσια repos** ενός **οργανισμού** και των **developers** του και να εκτελέσετε αυτόματα το [**gitleaks**](https://github.com/zricethezav/gitleaks) σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για την εκτέλεση του **gitleaks** σε όλο το **κείμενο** των **URLs που του παρέχονται**, καθώς μερικές φορές και οι **ιστοσελίδες περιέχουν secrets**.

#### Github Dorks

Δείτε τη σελίδα [GitHub dorks and leaks](github-leaked-secrets.md) για πιθανά **GitHub dorks** που μπορείτε να αναζητήσετε στον οργανισμό.

### Διαρροές σε Pastes

Μερικές φορές, επιτιθέμενοι ή απλώς εργαζόμενοι **δημοσιεύουν εταιρικό περιεχόμενο σε έναν ιστότοπο paste**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά αξίζει πολύ να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για ταυτόχρονη αναζήτηση σε περισσότερους από 80 ιστότοπους paste.

### Google Dorks

Τα παλιά αλλά πολύτιμα Google dorks είναι πάντα χρήσιμα για τον εντοπισμό **εκτεθειμένων πληροφοριών που δεν θα έπρεπε να είναι εκεί**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανά queries, τα οποία δεν μπορείτε να εκτελέσετε χειροκίνητα. Μπορείτε, λοιπόν, να επιλέξετε τα 10 αγαπημένα σας ή να χρησιμοποιήσετε ένα **εργαλείο όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τα εκτελέσετε όλα**.

_Σημειώστε ότι τα εργαλεία που επιχειρούν να εκτελέσουν ολόκληρη τη βάση δεδομένων μέσω του κανονικού Google browser δεν θα ολοκληρώσουν ποτέ, καθώς η Google θα σας αποκλείσει πολύ σύντομα._

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα διαπιστευτήρια ή API tokens που έχουν διαρρεύσει**, πρόκειται για μια πολύ εύκολη επιτυχία.

## Ευπάθειες σε δημόσιο κώδικα

Αν διαπιστώσετε ότι η εταιρεία διαθέτει **open-source κώδικα**, μπορείτε να τον **αναλύσετε** και να αναζητήσετε **ευπάθειες**.

**Ανάλογα με τη γλώσσα**, μπορείτε να χρησιμοποιήσετε διαφορετικά **εργαλεία**· δείτε τη λίστα με τα [εργαλεία ελέγχου πηγαίου κώδικα](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν υπηρεσίες που σας επιτρέπουν να **σαρώσετε δημόσια repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Μεθοδολογία Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των ευπαθειών** που εντοπίζουν οι bug hunters βρίσκεται μέσα σε **web applications**, οπότε σε αυτό το σημείο θα ήθελα να αναφερθώ σε μια **μεθοδολογία ελέγχου web applications**. Μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να αναφερθώ ειδικά στην ενότητα [**Εργαλεία open source για αυτοματοποιημένους web scanners**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρόλο που δεν θα πρέπει να περιμένετε να εντοπίσουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για την ενσωμάτωσή τους σε **workflows, ώστε να συγκεντρώσετε κάποιες αρχικές πληροφορίες για το web.**

## Ανακεφαλαίωση

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη ολοκληρώσει **όλη τη βασική enumeration**. Ναι, είναι βασική, επειδή υπάρχουν πολλά περισσότερα που μπορείτε να κάνετε στην enumeration (θα δούμε περισσότερα κόλπα αργότερα).

Έχετε, λοιπόν, ήδη:

1. Εντοπίσει όλες τις **εταιρείες** που περιλαμβάνονται στο scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και εκτελέσει κάποιο vuln scan, αν περιλαμβάνεται στο scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Εντοπίσει όλες τις **IP** (από και **εκτός CDN**) που περιλαμβάνονται στο scope.
6. Εντοπίσει όλους τους **web servers** και τραβήξει **στιγμιότυπο οθόνης** για τον καθένα (υπάρχει κάτι παράξενο που αξίζει να εξεταστεί πιο διεξοδικά;)
7. Εντοπίσει όλα τα **πιθανά δημόσια cloud assets** που ανήκουν στην εταιρεία.
8. Εντοπίσει **email**, **διαρροές διαπιστευτηρίων** και **διαρροές secrets** που θα μπορούσαν να σας οδηγήσουν εύκολα σε μια **μεγάλη επιτυχία**.
9. Κάνει **Pentesting σε όλους τους ιστότοπους που εντοπίσατε**

## **Εργαλεία για πλήρως αυτοματοποιημένο Recon**

Υπάρχουν αρκετά εργαλεία που εκτελούν μέρος των προτεινόμενων ενεργειών σε ένα δεδομένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Είναι λίγο παλιό και δεν έχει ενημερωθεί

## References

- [1] [Jason Haddix – Η μεθοδολογία του Bug Hunter, έκδοση 4.0: Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Για τα Favicons: Από τα εικονίδια browser στην ευφυΐα επιφάνειας επίθεσης](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Αξιοποίηση του favicon.ico για BugBounties, OSINT και άλλα](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ανακάλυψη Domains μέσω επίθεσης χρονικής συσχέτισης στο Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Παθητικό Takeover: Αποκάλυψη (και εξομοίωση) μιας δαπανηρής καμπάνιας Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Μια μοναδική μέθοδος enumeration subdomains](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Πλήρης ροή εργασίας εντοπισμού subdomains, Μέρος 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Πλήρης αυτοματοποιημένη ανακάλυψη subdomains μέσω brute force με το Trickest Workflow, Μέρος 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Στιγμιότυπο οθόνης εξόδου του favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
