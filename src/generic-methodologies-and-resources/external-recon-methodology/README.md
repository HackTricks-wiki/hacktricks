# Μεθοδολογία External Recon

{{#include ../../banners/hacktricks-training.md}}

## Ανακάλυψη assets

> Σου είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία είναι εντός scope και θέλεις να ανακαλύψεις τι ακριβώς της ανήκει.

Στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και, στη συνέχεια, όλα τα **assets** αυτών των εταιρειών. Για να το κάνουμε αυτό, θα:<sup>[[1]](#references)</sup>

1. Βρούμε τις εξαγορές της κύριας εταιρείας, ώστε να εντοπίσουμε τις εταιρείες που είναι εντός scope.
2. Βρούμε το ASN (αν υπάρχει) κάθε εταιρείας, ώστε να εντοπίσουμε τα IP ranges που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε reverse whois lookups για να αναζητήσουμε άλλες καταχωρίσεις (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιήσουμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το κόλπο με το `ssl` μπορεί να γίνει αναδρομικά).

Για τη σταδιακή μετάβαση από τα subdomains που έχουν επιλυθεί στο HTTP crawling και στην ανακάλυψη θυρών, δείτε τη [Μεθοδολογία Pentesting](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Εξαγορές**

Πρώτα απ' όλα, πρέπει να μάθουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφθείτε το [https://www.crunchbase.com/](https://www.crunchbase.com), να **αναζητήσετε** την **κύρια εταιρεία** και να **κάνετε κλικ** στο "**acquisitions**". Εκεί θα δείτε άλλες εταιρείες που εξαγοράστηκαν από την κύρια εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα της κύριας εταιρείας στη **Wikipedia** και να αναζητήσετε τις **εξαγορές**.\
Για εισηγμένες εταιρείες, ελέγξτε τις **καταχωρίσεις SEC/EDGAR**, τις σελίδες **investor relations** ή τα τοπικά εταιρικά μητρώα (π.χ., το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμιες εταιρικές δομές και θυγατρικές, δοκιμάστε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ωραία, σε αυτό το σημείο θα πρέπει να γνωρίζετε όλες τις εταιρείες που είναι εντός scope. Ας δούμε πώς μπορούμε να βρούμε τα assets τους.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **αυτόνομο σύστημα** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** **IP addresses** με σαφώς καθορισμένη πολιτική για την πρόσβαση σε εξωτερικά δίκτυα. Η διαχείρισή τους γίνεται από έναν οργανισμό, αλλά μπορεί να περιλαμβάνουν πολλούς παρόχους.

Είναι χρήσιμο να εξακριβώσουμε αν έχει εκχωρηθεί κάποιο **ASN στην εταιρεία**, ώστε να βρούμε τα **IP ranges** της. Ενδιαφέρει να εκτελεστεί **έλεγχος ευπαθειών** σε όλους τους **hosts** που είναι **εντός scope** και να **αναζητηθούν domains** μέσα σε αυτές τις IPs.\
Μπορείτε να κάνετε **αναζήτηση** με βάση το **όνομα** της εταιρείας, μια **IP** ή ένα **domain** στο [**https://bgp.he.net/**](https://bgp.he.net) **ή** στο [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή της εταιρείας, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Σε κάθε περίπτωση, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(IP ranges και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.

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

Μπορείτε επίσης να βρείτε τα IP ranges ενός οργανισμού μέσω του [ASNLookup](https://asnlookup.com/), το οποίο διαθέτει περιορισμένο δωρεάν API tier.

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets εντός του scope**, επομένως, αν έχετε την άδεια, μπορείτε να εκτελέσετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να εκτελέσετε [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως το** Shodan, το Censys ή το ZoomEye **για να εντοπίσετε** ανοιχτές θύρες **και, ανάλογα με όσα βρείτε, να ανατρέξετε σε αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορες πιθανές υπηρεσίες που εκτελούνται.**\
**Επίσης, αξίζει να αναφέρουμε ότι μπορείτε να ετοιμάσετε λίστες με** προεπιλεγμένα username **και** passwords **και να επιχειρήσετε να κάνετε** bruteforce σε υπηρεσίες με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες εντός του scope και τα assets τους· τώρα είναι ώρα να βρούμε τα domains εντός του scope.

_Σημειώστε ότι με τις τεχνικές που προτείνονται παρακάτω μπορείτε επίσης να εντοπίσετε subdomains και δεν πρέπει να υποτιμάτε αυτές τις πληροφορίες._

Πρώτα απ' όλα, θα πρέπει να αναζητήσετε το **κύριο domain** κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλα τα IP ranges των domains, μπορείτε να δοκιμάσετε να κάνετε **reverse DNS lookups** σε αυτές τις **IP για να βρείτε περισσότερα domains εντός του scope**. Δοκιμάστε να χρησιμοποιήσετε κάποιον DNS server του θύματος ή κάποιον γνωστό DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε το [SecurityTrails](https://securitytrails.com/) για αυτές τις πληροφορίες, αν και τα ιστορικά δεδομένα DNS απαιτούν συνδρομή επί πληρωμή.\
Για μεγάλα ranges, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του εμπλουτισμού δεδομένων.

### **Reverse Whois (loop)**

Σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα οργανισμού**, **διεύθυνση**, **email**, αριθμούς τηλεφώνου... Ακόμα πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **reverse whois lookups με βάση κάποιο από αυτά τα πεδία** (για παράδειγμα, άλλα μητρώα whois όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** web interface· API επί πληρωμή.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Επί πληρωμή
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Δεν είναι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Δεν είναι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Περιορισμένη δωρεάν πρόσβαση στο API για τρέχοντα DNS/subdomains· τα ιστορικά δεδομένα και τα reverse lookups απαιτούν συνδρομή επί πληρωμή.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 δωρεάν API credits κατά την εγγραφή· στη συνέχεια επί πληρωμή.

Μπορείτε να αυτοματοποιήσετε αυτήν την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτείται κλειδί API του whoxy).\
Μπορείτε επίσης να εκτελέσετε αυτόματη αναζήτηση reverse whois με το [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτήν την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να κάνετε αναζήτηση με βάση αυτούς και άλλους trackers:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Υπηρεσία web και API **επί πληρωμή** ([τιμολόγηση](https://www.stackscan.com/pricing))· προς το παρόν δεν διαφημίζεται δωρεάν πρόγραμμα. Αναζητήστε συσχετίσεις με οποιοδήποτε asset που παρέχεται, όχι μόνο με tracker IDs: μια διαδρομή script, ένα όνομα self-hosted bundle ή το host από το οποίο φορτώνεται ένα asset, ώστε να εντοπίσετε κάθε site που το περιλαμβάνει.

Το API επιστρέφει το stack για ένα μόνο domain, κάτι που είναι χρήσιμο για να επιβεβαιώσετε ότι ένα υποψήφιο asset ανήκει στο ίδιο estate:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Επιστρέφει κάθε τεχνολογία που εντοπίζει μαζί με την κατηγορία της. Το asset pivoting είναι προς το παρόν διαθέσιμο μόνο για web, ενώ το API υποστηρίζει αναζήτηση ανά domain.

### **Favicon**

Γνωρίζατε ότι μπορούμε να εντοπίσουμε σχετικά domains και subdomains του στόχου μας αναζητώντας το ίδιο hash εικονιδίου favicon; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), που δημιούργησε ο [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς να το χρησιμοποιήσετε:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Αποτελέσματα Favihash που χρησιμοποιούνται για την ανακάλυψη domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash μάς επιτρέπει να ανακαλύψουμε domains που έχουν το ίδιο hash εικονιδίου favicon με τον στόχο μας.

![Έξοδος του favihash που χρησιμοποιείται για την ανακάλυψη domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Χρησιμοποιήστε ένα γνωστό hash favicon ως σημείο εκκίνησης στο Shodan ή στο FOFA, για να βρείτε άλλες εκτεθειμένες παρουσίες της ίδιας τεχνολογίας.<sup>[[5]](#references)</sup>

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

Μπορείτε επίσης να συλλέξετε hashes favicon σε μεγάλη κλίμακα με το [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και έπειτα να κάνετε pivot σε Shodan/Censys.

Αντιμετωπίζετε τα αποτυπώματα favicon ως ενδείξεις και τα επιβεβαιώνετε με βάση τα περιβάλλοντα στοιχεία.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίζετε το hash ως ένδειξη, όχι ως απόδειξη**: το MMH3 είναι συμπαγές· είναι πιθανά τα collisions, η επαναχρησιμοποίηση εικονιδίων και η σκόπιμη παραποίηση.
- **Εξετάζετε περισσότερα από το** `/favicon.ico`: ελέγχετε διαδρομές framework/build, αρχεία manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και ετικέτες HTML `<link rel="icon">`.
- **Τα static assets μπορεί να παραμένουν προσβάσιμα πίσω από ελέγχους WAF/SSO/IdP**: ζητάτε απευθείας το εικονίδιο και εξετάζετε τα headers `ETag`, `Last-Modified`, redirects και cache.
- **Επιβεβαιώνετε τις αντιστοιχίες με βάση τα περιβάλλοντα στοιχεία**: συγκρίνετε τον τίτλο, το hash HTML/body, τα headers, τα subjects/SANs των TLS certificates, τα product components και τις exposed ports.
- **Ομαδοποιείτε με βάση το hash HTML/body**: ένα συνεπές template ενισχύει το αποτύπωμα· διαφορετικά templates υποδηλώνουν γενικό ή κοινόχρηστο εικονίδιο.
- **Αντιμετωπίζετε ένα hash που εμφανίζεται σε άσχετες υπογραφές, ports και προϊόντα ως πιθανό honeypot ή placeholder.**
- **Σε αμφίβολους στόχους, συγκρίνετε μια πραγματική σελίδα με ένα ανύπαρκτο path**, όπως `/_favicon_probe_<8-hex>`· οι ίδιες απαντήσεις hosting ή parking μπορεί να εξηγούν το κοινό εικονίδιο.
- **Ξεκινάτε την αρχική διαλογή με κανόνες detection του Nuclei ή δημόσια datasets** που αντιστοιχίζουν hashes favicon σε προϊόντα και CPEs.
- **Να θυμάστε το κενό κάλυψης που βασίζεται στις IP**: επιφάνειες που βρίσκονται πίσω από CDN, δρομολογούνται μέσω SNI, χρησιμοποιούν anycast ή είναι διαθέσιμες μόνο μέσω domain μπορεί να λείπουν από datasets τύπου Shodan.

### **Copyright / Μοναδική συμβολοσειρά**

Αναζητάτε μέσα στις ιστοσελίδες **συμβολοσειρές που μπορεί να είναι κοινές σε διαφορετικούς ιστοτόπους του ίδιου οργανισμού**. Η **συμβολοσειρά copyright** θα μπορούσε να είναι ένα καλό παράδειγμα. Έπειτα, αναζητήστε αυτή τη συμβολοσειρά στο **google**, σε άλλους **περιηγητές** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **Χρόνος CRT**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως το

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

για να ανανεωθούν όλα τα certificates ενός server ταυτόχρονα. Η συσχέτιση των χρονικών σημάνσεων των certificates ή των θέσεών τους στα certificate-transparency logs μπορεί να αποκαλύψει σχετικά domains.<sup>[[6]](#references)</sup>

Χρησιμοποιήστε επίσης απευθείας τα logs **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), για να βρείτε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες dmarc**.\
Μια άλλη χρήσιμη υπηρεσία είναι το [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ένα εγκαταλελειμμένο A record μπορεί να γίνει προσβάσιμο όταν ένας cloud provider εκχωρήσει ξανά μια IP. Η έρευνα που αναφέρεται παρουσιάζει μια opportunistic ροή εργασίας που δημιουργεί ένα instance και συσχετίζει τη διεύθυνσή του με δεδομένα passive DNS· δοκιμάζετε σενάρια takeover μόνο εντός του εγκεκριμένου scope.<sup>[[7]](#references)</sup>

### **Άλλοι τρόποι**

Επαναλαμβάνετε τα σχετικά βήματα ανακάλυψης κάθε φορά που βρίσκετε ένα νέο domain: κάθε αποτέλεσμα μπορεί να αποκαλύψει επιπλέον ονόματα certificates, σχέσεις passive-DNS, αντιστοιχίες favicon και αναγνωριστικά οργανισμών που δεν ήταν ορατά από το αρχικό seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Αφού γνωρίζετε ήδη το όνομα του οργανισμού στον οποίο ανήκει ο χώρος IP, μπορείτε να αναζητήσετε αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους hosts που βρέθηκαν για νέα, απρόσμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας ιστοσελίδας, να λάβετε το **όνομα Organisation** και στη συνέχεια να αναζητήσετε αυτό το όνομα στα **TLS certificates** όλων των ιστοσελίδων που γνωρίζει το **shodan**, χρησιμοποιώντας το φίλτρο: `ssl:"Tesla Motors"` ή ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)είναι ένα εργαλείο που αναζητά **domains που σχετίζονται** με ένα κύριο domain, καθώς και τα **subdomains** τους. Είναι πραγματικά εντυπωσιακό.

**Passive DNS / Historical DNS**

Τα δεδομένα Passive DNS είναι εξαιρετικά για την εύρεση **παλιών και ξεχασμένων records** που εξακολουθούν να επιλύονται ή μπορούν να αποτελέσουν αντικείμενο takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Αναζήτηση ευπαθειών**

Ελέγξτε για πιθανό [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί ένα domain**, αλλά **έχει χάσει την ιδιοκτησία του**. Απλώς καταχωρίστε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε κάποιο **domain με διαφορετική IP** από αυτές που ήδη εντοπίσατε κατά την ανακάλυψη assets, θα πρέπει να πραγματοποιήσετε ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και ένα [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, οπότε είναι εκτός scope· προσέξτε._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες εντός scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρείτε όλα τα πιθανά subdomains κάθε domain που εντοπίστηκε.

> [!TIP]
> Σημειώστε ότι ορισμένα εργαλεία και τεχνικές για την εύρεση domains μπορούν επίσης να βοηθήσουν στην εύρεση subdomains.

### **DNS**

Ας προσπαθήσουμε να εντοπίσουμε **subdomains** από τα records του **DNS**. Θα πρέπει επίσης να δοκιμάσουμε το **Zone Transfer** (αν είναι ευάλωτο, θα πρέπει να το αναφέρετε).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Για APIs και πλατφόρμες που καλύπτουν υποδομές, φήμη, αρχεία παραβιάσεων και εμπλουτισμό πέρα από την ανακάλυψη subdomain, δείτε τον [κατάλογο APIs αναγνώρισης και πληροφοριών απειλών](reconnaissance-and-threat-intelligence-apis.md).

Ο πιο γρήγορος τρόπος για να βρείτε πολλά subdomain είναι η αναζήτηση σε εξωτερικές πηγές. Τα πιο χρησιμοποιούμενα **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα, διαμορφώστε τα API keys):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

Υπάρχουν **και άλλα ενδιαφέροντα εργαλεία/API** που, παρότι δεν είναι εξειδικευμένα στην εύρεση subdomains, μπορεί να φανούν χρήσιμα για τον εντοπισμό subdomains, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) free API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Δωρεάν API του AnubisDB**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστά URL από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιοδήποτε domain.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Σαρώνουν τον ιστό αναζητώντας αρχεία JS και εξάγουν subdomains από αυτά.

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

- [**Εύρεση υποτομέων Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) προσφέρει περιορισμένη δωρεάν πρόσβαση στο API για τρέχοντα δεδομένα DNS και subdomain· για ιστορικά δεδομένα DNS/IP απαιτείται πρόγραμμα επί πληρωμή.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με προγράμματα bug-bounty**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/Moaaz-0x/chaospy) ή ακόμη και να αποκτήσετε πρόσβαση στο scope που χρησιμοποιεί αυτό το project [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** κάνοντας brute-forcing σε DNS servers με πιθανά ονόματα subdomain.

Για αυτή την ενέργεια θα χρειαστείτε μερικά **συνηθισμένα wordlists subdomain όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Θα χρειαστείτε επίσης IPs αξιόπιστων DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα εργαλεία που προτείνονται περισσότερο για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, αλλά είναι επιρρεπές σε false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί μόνο 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper για το `massdns`, γραμμένο σε Go, που επιτρέπει την απαρίθμηση έγκυρων subdomains μέσω active bruteforce, καθώς και την επίλυση subdomains με χειρισμό wildcard και εύκολη υποστήριξη εισόδου-εξόδου.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης το `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί το asyncio για να κάνει brute force σε ονόματα domain ασύγχρονα.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Δεύτερος γύρος DNS Brute-Force

Αφού εντοπίσετε υποτομείς μέσω ανοικτών πηγών και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των υποτομέων που βρήκατε, ώστε να προσπαθήσετε να εντοπίσετε ακόμη περισσότερους. Για αυτόν τον σκοπό είναι χρήσιμα αρκετά εργαλεία:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Δέχεται domains και υποτομείς και δημιουργεί παραλλαγές.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Δεδομένων των domains και subdomains, δημιουργεί permutations.
  - Μπορείτε να βρείτε το **wordlist** με τις permutations του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Με βάση τα domains και subdomains, δημιουργεί permutations. Αν δεν καθοριστεί αρχείο permutations, το gotator θα χρησιμοποιήσει το δικό του.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία permutations για subdomains, μπορεί επίσης να προσπαθήσει να τα επιλύσει (αλλά είναι προτιμότερο να χρησιμοποιήσετε τα εργαλεία που αναφέρθηκαν προηγουμένως).
  - Μπορείτε να βρείτε **wordlist** με permutations του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για τη δημιουργία permutations, mutations και παραλλαγών υποτομέων. Αυτό το εργαλείο θα κάνει brute force το αποτέλεσμα (δεν υποστηρίζει DNS wildcard).
  - Μπορείτε να βρείτε wordlist με permutations για το dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί ονόματα πιθανών νέων subdomains** σύμφωνα με τα υποδεικνυόμενα μοτίβα, για να εντοπίσει περισσότερα subdomains.

#### Δημιουργία έξυπνων μεταθέσεων

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει μοτίβα τύπου regex από τα subdomains που έχουν εντοπιστεί και δημιουργεί υποψήφια ονόματα για επίλυση.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** Το _subzuf_ είναι ένα fuzzer για brute-force subdomain, το οποίο συνδυάζει έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από τις αποκρίσεις DNS. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως μια προσαρμοσμένη wordlist ή ιστορικές εγγραφές DNS/TLS, για να συνθέτει με ακρίβεια περισσότερα αντίστοιχα ονόματα domain και να τα επεκτείνει περαιτέρω επαναληπτικά, με βάση τις πληροφορίες που συλλέγονται κατά τη σάρωση DNS.

```
echo www | subzuf facebook.com
```

### **Ροή εργασίας για την ανακάλυψη subdomain**

Τα παραδείγματα workflow του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλαμβανόμενη απαρίθμηση subdomain.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρείτε μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** που ανήκουν σε subdomains, μπορείτε να προσπαθήσετε να **βρείτε άλλα subdomains με ιστοσελίδες σε αυτή την IP**, αναζητώντας σε **πηγές OSINT** domains που αντιστοιχούν σε μια IP ή κάνοντας **brute force στα ονόματα domain VHost σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε ορισμένα **VHosts σε IPs χρησιμοποιώντας το** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιο subdomain μπορεί να είναι κρυμμένο σε έναν web server, μπορείτε να δοκιμάσετε να κάνετε brute force:

Για vhosts που βασίζονται σε όνομα, κάντε fuzzing στην κεφαλίδα `Host` και χρησιμοποιήστε το auto-calibration του ffuf για να φιλτράρετε την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>

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
> Με αυτή την τεχνική μπορεί ακόμη και να αποκτήσετε πρόσβαση σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί ένα έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να εκμεταλλευτείτε αυτή τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Κατά την αναζήτηση **subdomains**, έχετε τον νου σας για να δείτε αν κάποιο **δείχνει** σε οποιονδήποτε τύπο **bucket** και, σε αυτή την περίπτωση, [**ελέγξτε τα permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains εντός του scope, δοκιμάστε να [**κάνετε brute force σε πιθανά ονόματα bucket και να ελέγξετε τα permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Παρακολούθηση**

Μπορείτε να **παρακολουθείτε** αν δημιουργούνται **νέα subdomains** ενός domain, παρακολουθώντας τα Logs του **Certificate Transparency**, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση ευπαθειών**

Ελέγξτε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**ελέγξτε τα permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Αν βρείτε κάποιο **subdomain με IP διαφορετική** από όσες εντοπίσατε ήδη κατά την ανακάλυψη των assets, θα πρέπει να εκτελέσετε ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το subdomain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, επομένως δεν είναι εντός scope. Να είστε προσεκτικοί._

## IPs

Στα αρχικά βήματα μπορεί να **εντοπίσατε ορισμένα εύρη IP, domains και subdomains**.\
Ήρθε η ώρα να **συγκεντρώσετε όλες τις IPs από αυτά τα εύρη**, καθώς και για τα **domains/subdomains (μέσω DNS queries).**

Χρησιμοποιώντας υπηρεσίες όπως οι παρακάτω, μπορείτε επίσης να βρείτε **παλαιότερες IPs που χρησιμοποιούσαν domains και subdomains**. Αυτές οι IPs μπορεί να εξακολουθούν να ανήκουν στον πελάτη (και μπορεί να σας βοηθήσουν να εντοπίσετε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (τα ιστορικά δεδομένα DNS/IP απαιτούν συνδρομή επί πληρωμή)

Μπορείτε επίσης να ελέγξετε ποια domains δείχνουν σε μια συγκεκριμένη διεύθυνση IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση ευπαθειών**

**Κάντε port scan σε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μη βρείτε κάτι ενδιαφέρον εκεί). Στις υπηρεσίες που εκτελούνται και εντοπίστηκαν ίσως **μπορέσετε να βρείτε ευπάθειες**.

**Βρείτε έναν** [**οδηγό**](../pentesting-network/index.html) **σχετικά με το πώς να κάνετε scan σε hosts.**

## Αναζήτηση web servers

> Έχουμε εντοπίσει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τα εύρη IP, τα domains και τα subdomains εντός του scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη κάνει **recon στις IPs και στα domains που εντοπίστηκαν**, επομένως ίσως **έχετε ήδη βρει όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, θα δούμε τώρα μερικά **γρήγορα κόλπα για την αναζήτηση web servers** εντός του scope.

Σημειώστε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, επομένως θα πρέπει να εκτελέσετε επίσης **vulnerability** και **port scanning** (**αν επιτρέπεται** από το scope).

Μια **γρήγορη μέθοδος** για τον εντοπισμό **ανοιχτών ports** που σχετίζονται με **web** servers, χρησιμοποιώντας το [**masscan**, θα τη βρείτε εδώ](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι τα [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς δίνετε μια λίστα με domains και το εργαλείο θα προσπαθήσει να συνδεθεί στις ports 80 (http) και 443 (https). Επιπλέον, μπορείτε να καθορίσετε να δοκιμάσει και άλλες ports:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Στιγμιότυπα οθόνης**

Τώρα που ανακαλύψατε **όλους τους web servers** που βρίσκονται εντός του scope (ανάμεσα στις **IP** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν ξέρετε από πού να ξεκινήσετε**. Ας το απλοποιήσουμε, λοιπόν, και ας ξεκινήσουμε βγάζοντας στιγμιότυπα οθόνης όλων τους. Αρκεί να **ρίξετε μια ματιά** στην **κύρια σελίδα** για να εντοπίσετε **περίεργα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να εφαρμόσετε την προτεινόμενη ιδέα, μπορείτε να χρησιμοποιήσετε τα [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε έπειτα να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να αναλύσει όλα τα **στιγμιότυπα οθόνης** και να σας πει **ποια είναι πιθανό να περιέχουν ευπάθειες** και ποια όχι.

## Assets δημόσιου cloud

Για να βρείτε πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει **να ξεκινήσετε με μια λίστα λέξεων-κλειδιών που την προσδιορίζουν**. Για παράδειγμα, για μια εταιρεία crypto μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις, θα πρέπει να δημιουργήσετε **permutations** (δείτε τον [**Δεύτερο γύρο DNS brute-force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τις wordlists που θα προκύψουν, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάστε ότι, όταν αναζητάτε Cloud Assets, θα πρέπει να **αναζητάτε περισσότερα από buckets στο AWS**.

### **Αναζήτηση ευπαθειών**

Αν εντοπίσετε πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει **να αποκτήσετε πρόσβαση σε αυτά** και να προσπαθήσετε να δείτε τι προσφέρουν και αν μπορείτε να τα καταχραστείτε.

## Emails

Με τα **domains** και τα **subdomains** που βρίσκονται εντός του scope, έχετε ουσιαστικά όλα όσα **χρειάζεστε για να ξεκινήσετε την αναζήτηση emails**. Αυτά είναι τα **APIs** και τα **εργαλεία** που έχουν αποδώσει καλύτερα για μένα στον εντοπισμό emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
- API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
- API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση ευπαθειών**

Τα emails θα σας φανούν χρήσιμα αργότερα για **brute-force σε web logins και υπηρεσίες auth** (όπως το SSH). Είναι επίσης απαραίτητα για **phishing**. Επιπλέον, αυτά τα APIs θα σας δώσουν ακόμα περισσότερες **πληροφορίες για το άτομο** πίσω από το email, κάτι χρήσιμο για την καμπάνια phishing.

## Διαρροές διαπιστευτηρίων

Με τα **domains,** τα **subdomains** και τα **emails**, μπορείτε να ξεκινήσετε την αναζήτηση για διαπιστευτήρια που έχουν διαρρεύσει στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα διαπιστευτήρια που έχουν διαρρεύσει**, πρόκειται για μια πολύ εύκολη επιτυχία.

## Διαρροές μυστικών

Οι διαρροές διαπιστευτηρίων σχετίζονται με παραβιάσεις εταιρειών, κατά τις οποίες **ευαίσθητες πληροφορίες διέρρευσαν και πουλήθηκαν**. Ωστόσο, οι εταιρείες ενδέχεται να επηρεάζονται και από **άλλες διαρροές**, των οποίων οι πληροφορίες δεν βρίσκονται σε αυτές τις βάσεις δεδομένων:

### Διαρροές στο Github

Διαπιστευτήρια και APIs ενδέχεται να έχουν διαρρεύσει στα **δημόσια repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται σε αυτήν την εταιρεία github.\
Μπορείτε να χρησιμοποιήσετε το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **δημόσια repos** ενός **οργανισμού** και των **developers** του και να εκτελέσετε αυτόματα το [**gitleaks**](https://github.com/gitleaks/gitleaks) σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για την εκτέλεση του **gitleaks** σε όλα τα **κείμενα** που παρέχονται μέσω **URLs**, καθώς μερικές φορές **οι ιστοσελίδες περιέχουν επίσης μυστικά**.

#### Github Dorks

Δείτε τη σελίδα [GitHub dorks and leaks](github-leaked-secrets.md) για πιθανά **GitHub dorks** που μπορείτε να αναζητήσετε στον οργανισμό.

### Διαρροές σε paste sites

Μερικές φορές, επιτιθέμενοι ή απλώς εργαζόμενοι **δημοσιεύουν εταιρικό περιεχόμενο σε κάποιο paste site**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά αξίζει πολύ να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για να κάνετε αναζήτηση σε περισσότερα από 80 paste sites ταυτόχρονα.

### Google Dorks

Τα παλιά αλλά δοκιμασμένα google dorks είναι πάντα χρήσιμα για τον εντοπισμό **εκτεθειμένων πληροφοριών που δεν θα έπρεπε να βρίσκονται εκεί**. Το μόνο πρόβλημα είναι ότι το [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανά queries που δεν μπορείτε να εκτελέσετε χειροκίνητα. Επομένως, μπορείτε να επιλέξετε τα 10 αγαπημένα σας ή να χρησιμοποιήσετε ένα **εργαλείο όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τα εκτελέσετε όλα**.

_Σημειώστε ότι τα εργαλεία που προσπαθούν να εκτελέσουν ολόκληρη τη βάση δεδομένων μέσω του κανονικού Google browser δεν θα ολοκληρώσουν ποτέ, καθώς η Google θα σας αποκλείσει πολύ γρήγορα._

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα διαπιστευτήρια ή API tokens που έχουν διαρρεύσει**, πρόκειται για μια πολύ εύκολη επιτυχία.

## Ευπάθειες σε δημόσιο κώδικα

Αν διαπιστώσετε ότι η εταιρεία διαθέτει **open-source code**, μπορείτε να τον **αναλύσετε** και να αναζητήσετε **ευπάθειες** σε αυτόν.

**Ανάλογα με τη γλώσσα**, υπάρχουν διάφορα **εργαλεία** που μπορείτε να χρησιμοποιήσετε· δείτε τη λίστα με τα [εργαλεία ελέγχου πηγαίου κώδικα](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν υπηρεσίες που σας επιτρέπουν να **σαρώσετε δημόσια repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Μεθοδολογία Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των ευπαθειών** που εντοπίζουν οι bug hunters βρίσκεται μέσα σε **web applications**, γι' αυτό σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία ελέγχου web application**, και μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ιδιαίτερη αναφορά στην ενότητα [**Εργαλεία open source για αυτοματοποιημένους σαρωτές Web**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρόλο που δεν θα πρέπει να περιμένετε να εντοπίσουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμο να τα εντάξετε σε **workflows για να αποκτήσετε κάποιες αρχικές πληροφορίες για το web.**

## Ανακεφαλαίωση

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη ολοκληρώσει **όλη τη βασική απαρίθμηση**. Ναι, είναι βασική, επειδή μπορεί να γίνει πολύ περισσότερη απαρίθμηση (θα δούμε περισσότερα κόλπα αργότερα).

Έχετε ήδη:

1. Βρει όλες τις **εταιρείες** που βρίσκονται εντός του scope
2. Βρει όλα τα **assets** που ανήκουν στις εταιρείες (και πραγματοποιήσει κάποιο vuln scan, αν βρίσκεται εντός του scope)
3. Βρει όλα τα **domains** που ανήκουν στις εταιρείες
4. Βρει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Βρει όλες τις **IP** (από και **εκτός CDN**) που βρίσκονται εντός του scope.
6. Βρει όλους τους **web servers** και έχει τραβήξει ένα **στιγμιότυπο οθόνης** για καθέναν (υπάρχει κάτι περίεργο που αξίζει να εξετάσετε σε βάθος;)
7. Βρει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. **Emails**, **διαρροές διαπιστευτηρίων** και **διαρροές μυστικών** που θα μπορούσαν να σας προσφέρουν **μια εύκολη και σημαντική επιτυχία**.
9. **Κάνει Pentesting σε όλους τους ιστότοπους που βρήκατε**

## **Πλήρως αυτοματοποιημένα εργαλεία Recon**

Υπάρχουν αρκετά εργαλεία που εκτελούν μέρος των προτεινόμενων ενεργειών σε ένα δεδομένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Αρκετά παλιό και χωρίς ενημερώσεις



## References

- [1] [Jason Haddix – Η μεθοδολογία του bug hunter, έκδοση 4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Για τα favicons: Από τα εικονίδια του browser στην ευφυΐα επιφάνειας επίθεσης](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Αξιοποίηση του favicon.ico για BugBounties, OSINT και άλλα](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ανακάλυψη domains μέσω επίθεσης χρονικής συσχέτισης στο Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Παθητικό takeover: Αποκάλυψη (και προσομοίωση) μιας ακριβής καμπάνιας subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Μια μοναδική μέθοδος απαρίθμησης subdomain](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Πλήρης ροή εργασίας ανακάλυψης subdomain, Μέρος 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Πλήρης ανακάλυψη subdomain με brute force μέσω αυτοματοποιημένης ροής εργασίας Trickest, Μέρος 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – στιγμιότυπο οθόνης εξόδου του favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
