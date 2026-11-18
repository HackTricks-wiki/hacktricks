# Μεθοδολογία Εξωτερικού Recon

{{#include ../../banners/hacktricks-training.md}}

## Ανακάλυψη assets

Για μια κατηγοριοποιημένη λίστα πρόσθετων project OSINT και web discovery, δείτε [Εργαλεία και πόροι τρίτων](../third-party-tools-and-resources.md#osint).

> Σου είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία περιλαμβάνονται στο scope και θέλεις να μάθεις τι πραγματικά της ανήκει.

Στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στη βασική εταιρεία** και στη συνέχεια όλα τα **assets** αυτών των εταιρειών. Για να το πετύχουμε, θα κάνουμε τα εξής:<sup>[[1]](#references)</sup>

1. Εντοπίζουμε τις εξαγορές της βασικής εταιρείας, ώστε να βρούμε τις εταιρείες που περιλαμβάνονται στο scope.
2. Εντοπίζουμε το ASN (αν υπάρχει) κάθε εταιρείας, ώστε να βρούμε τα IP ranges που της ανήκουν.
3. Χρησιμοποιούμε reverse whois lookups για να αναζητήσουμε άλλες εγγραφές (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει επαναληπτικά).
4. Χρησιμοποιούμε άλλες τεχνικές, όπως τα φίλτρα `org`και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το τέχνασμα με το `ssl` μπορεί να χρησιμοποιηθεί επαναληπτικά).

Για τη σταδιακή μετάβαση από τα subdomains που έχουν επιλυθεί στο HTTP crawling και στην ανακάλυψη θυρών, δείτε τη [Μεθοδολογία Pentesting](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Εξαγορές**

Πρώτα απ' όλα, πρέπει να μάθουμε ποιες **άλλες εταιρείες ανήκουν στη βασική εταιρεία**.\
Μια επιλογή είναι να επισκεφθείτε το [https://www.crunchbase.com/](https://www.crunchbase.com), να **αναζητήσετε** τη **βασική εταιρεία** και να **κάνετε κλικ** στο "**acquisitions**". Εκεί θα δείτε άλλες εταιρείες που εξαγόρασε η βασική εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα της βασικής εταιρείας στη **Wikipedia** και να αναζητήσετε τις **εξαγορές**.\
Για εισηγμένες εταιρείες, ελέγξτε τις **καταθέσεις SEC/EDGAR**, τις σελίδες **επενδυτικών σχέσεων** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμια εταιρικά δέντρα και θυγατρικές, δοκιμάστε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ωραία, σε αυτό το σημείο θα πρέπει να γνωρίζετε όλες τις εταιρείες που περιλαμβάνονται στο scope. Ας δούμε πώς μπορούμε να βρούμε τα assets τους.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **αυτόνομο σύστημα** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** **IP addresses** με σαφώς καθορισμένη πολιτική πρόσβασης σε εξωτερικά δίκτυα. Η διαχείρισή τους γίνεται από έναν οργανισμό, αλλά μπορεί να περιλαμβάνουν περισσότερους από έναν φορείς εκμετάλλευσης.

Έχει ενδιαφέρον να μάθουμε αν έχει εκχωρηθεί **ASN** στην **εταιρεία**, ώστε να εντοπίσουμε τα **IP ranges** της. Θα ήταν χρήσιμο να γίνει **έλεγχος ευπαθειών** σε όλους τους **hosts** εντός του **scope** και να **αναζητηθούν domains** μέσα σε αυτές τις IPs.\
Μπορείτε να κάνετε **αναζήτηση** με βάση το **όνομα** της εταιρείας, μια **IP** ή ένα **domain** στο [**https://bgp.he.net/**](https://bgp.he.net) **ή** στο [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή της εταιρείας, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Ωστόσο, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(IP ranges και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Επίσης, το enumeration του [**BBOT**](https://github.com/blacklanternsecurity/bbot) συγκεντρώνει και συνοψίζει αυτόματα τα ASN στο τέλος της σάρωσης.

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

Μπορείτε επίσης να βρείτε τις περιοχές IP ενός οργανισμού χρησιμοποιώντας το [ASNLookup](https://asnlookup.com/), το οποίο διαθέτει περιορισμένο δωρεάν επίπεδο API.

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets εντός του scope**, οπότε, αν έχετε άδεια, θα μπορούσατε να εκτελέσετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, θα μπορούσατε να εκτελέσετε κάποια [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως το** Shodan, το Censys ή το ZoomEye **για να εντοπίσετε** ανοιχτές θύρες **και, ανάλογα με όσα βρείτε, θα πρέπει να συμβουλευτείτε αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορες πιθανές υπηρεσίες που εκτελούνται.**\
**Αξίζει επίσης να αναφέρουμε ότι μπορείτε να ετοιμάσετε λίστες με** προεπιλεγμένα ονόματα χρήστη **και** κωδικούς πρόσβασης **και να δοκιμάσετε να κάνετε** bruteforce σε υπηρεσίες με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Τομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του scope και τα assets τους· ήρθε η ώρα να βρούμε τους τομείς εντός του scope.

_Σημειώστε ότι με τις τεχνικές που προτείνονται παρακάτω μπορείτε επίσης να εντοπίσετε subdomains, και δεν θα πρέπει να υποτιμάτε αυτή την πληροφορία._

Πρώτα απ’ όλα, θα πρέπει να αναζητήσετε τον **κύριο τομέα** ή τους **κύριους τομείς** κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλες τις περιοχές IP των τομέων, μπορείτε να δοκιμάσετε να εκτελέσετε **reverse dns lookups** σε αυτές τις **IP για να βρείτε περισσότερους τομείς εντός του scope**. Δοκιμάστε να χρησιμοποιήσετε κάποιον dns server του θύματος ή κάποιον γνωστό dns server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε το [SecurityTrails](https://securitytrails.com/) για αυτές τις πληροφορίες, αν και τα ιστορικά δεδομένα DNS απαιτούν συνδρομή επί πληρωμή.\
Για μεγάλα εύρη, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των αντίστροφων αναζητήσεων και τον εμπλουτισμό των δεδομένων.

### **Αντίστροφο Whois (loop)**

Σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα οργανισμού**, **διεύθυνση**, **email**, αριθμούς τηλεφώνου... Ακόμα πιο ενδιαφέρον, μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **αντίστροφες αναζητήσεις whois με βάση οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλες εγγραφές whois όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε διαδικτυακά εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** διαδικτυακό περιβάλλον· API επί πληρωμή.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Επί πληρωμή
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Δεν είναι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Δεν είναι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Περιορισμένη δωρεάν πρόσβαση στο API για τρέχοντα DNS/subdomains· τα ιστορικά δεδομένα και οι αντίστροφες αναζητήσεις απαιτούν συνδρομή επί πληρωμή.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 δωρεάν μονάδες API κατά την εγγραφή· στη συνέχεια επί πληρωμή.

Μπορείτε να αυτοματοποιήσετε αυτήν την εργασία με το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτείται κλειδί API whoxy).\
Μπορείτε επίσης να εκτελέσετε αυτόματη ανακάλυψη μέσω αντίστροφου whois με το [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Έχετε υπόψη ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύπτετε περισσότερα ονόματα domain κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε πολλές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να αναζητήσετε αυτά τα trackers και άλλα:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Επί πληρωμή** υπηρεσία web και API ([τιμολόγηση](https://www.stackscan.com/pricing))· δεν διαφημίζεται προς το παρόν δωρεάν πρόγραμμα. Αναζητήστε συσχετίσεις με οποιοδήποτε asset που εξυπηρετείται, όχι μόνο με tracker IDs: διαδρομή script, όνομα self-hosted bundle ή host από τον οποίο φορτώνεται ένα asset, για να βρείτε κάθε ιστότοπο που το περιλαμβάνει

Το API επιστρέφει το stack για ένα μεμονωμένο domain, κάτι χρήσιμο για να επιβεβαιώσετε ότι ένα υποψήφιο asset ανήκει στο ίδιο estate:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Επιστρέφει κάθε τεχνολογία που εντοπίστηκε μαζί με την κατηγορία της. Το asset pivoting είναι προς το παρόν διαθέσιμο μόνο για web, ενώ το API καλύπτει αναζητήσεις ανά domain.

### **Favicon**

Γνωρίζατε ότι μπορούμε να εντοπίσουμε σχετιζόμενα domains και subdomains του στόχου μας αναζητώντας το ίδιο hash εικονιδίου favicon; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), που δημιουργήθηκε από τον [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς να το χρησιμοποιήσετε:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Αποτελέσματα του Favihash που χρησιμοποιούνται για την ανακάλυψη domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash μάς επιτρέπει να ανακαλύψουμε domains που έχουν το ίδιο hash εικονιδίου favicon με τον στόχο μας.

![Έξοδος του favihash που χρησιμοποιείται για την ανακάλυψη domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Χρησιμοποιήστε ένα γνωστό hash favicon ως pivot στο Shodan ή το FOFA για να βρείτε άλλες εκτεθειμένες περιπτώσεις της ίδιας τεχνολογίας.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Έτσι μπορείτε να **υπολογίσετε το hash του favicon** ενός ιστότοπου (MMH3 πάνω στα **base64-encoded** bytes του favicon):

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

Μπορείτε επίσης να συλλέξετε favicon hashes σε μεγάλη κλίμακα με το [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και μετά να κάνετε pivot στο Shodan/Censys.

Αντιμετωπίστε τα favicon fingerprints ως ενδείξεις και επαληθεύστε τα με πρόσθετα σήματα.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίστε το hash ως ένδειξη, όχι ως απόδειξη**: το MMH3 είναι συμπαγές· είναι πιθανά τα collisions, η επαναχρησιμοποίηση εικονιδίων και η σκόπιμη παραποίηση.
- **Ελέγξτε περισσότερα από το** `/favicon.ico`: εξετάστε διαδρομές framework/build, αρχεία manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και ετικέτες HTML `<link rel="icon">`.
- **Τα static assets μπορεί να παραμένουν προσβάσιμα πίσω από ελέγχους WAF/SSO/IdP**: ζητήστε απευθείας το εικονίδιο και ελέγξτε τα `ETag`, `Last-Modified`, τις ανακατευθύνσεις και τις κεφαλίδες cache.
- **Επαληθεύστε τις αντιστοιχίες με πρόσθετα σήματα**: συγκρίνετε τον τίτλο, το HTML/body hash, τις κεφαλίδες, τα subjects/SANs του TLS certificate, τα product components και τις εκτεθειμένες θύρες.
- **Ομαδοποιήστε βάσει HTML/body hash**: ένα συνεπές template ενισχύει το fingerprint· διαφορετικά templates υποδηλώνουν γενικό ή κοινόχρηστο εικονίδιο.
- **Αντιμετωπίστε ένα hash που εμφανίζεται σε άσχετες υπογραφές, θύρες και προϊόντα ως πιθανό honeypot ή placeholder.**
- **Σε αμφίβολους στόχους, συγκρίνετε μια πραγματική σελίδα με μια ανύπαρκτη διαδρομή**, όπως `/_favicon_probe_<8-hex>`· οι ίδιες απαντήσεις φιλοξενίας ή στάθμευσης domain μπορεί να εξηγούν το κοινό εικονίδιο.
- **Ξεκινήστε τη διαλογή από κανόνες ανίχνευσης του Nuclei ή δημόσια datasets** που αντιστοιχίζουν favicon hashes σε προϊόντα και CPEs.
- **Να θυμάστε το κενό κάλυψης που αφορά τις IP**: επιφάνειες πίσω από CDN, με δρομολόγηση SNI, anycast και μόνο domain μπορεί να λείπουν από datasets τύπου Shodan.

### **Copyright / Μοναδική συμβολοσειρά**

Αναζητήστε στις ιστοσελίδες **συμβολοσειρές που μπορεί να είναι κοινές σε διαφορετικούς ιστότοπους του ίδιου οργανισμού**. Η **συμβολοσειρά copyright** είναι ένα καλό παράδειγμα. Στη συνέχεια, αναζητήστε αυτήν τη συμβολοσειρά στο **google**, σε άλλους **περιηγητές** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **Χρόνος CRT**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως το ακόλουθο:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

για την ταυτόχρονη ανανέωση όλων των πιστοποιητικών σε έναν server. Η συσχέτιση των χρονικών σημάνσεων των πιστοποιητικών ή των θέσεών τους στα certificate-transparency logs μπορεί να αποκαλύψει σχετικά domains.<sup>[[6]](#references)</sup>

Χρησιμοποιήστε επίσης απευθείας τα logs **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες DMARC αλληλογραφίας

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο, όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), ή ένα εργαλείο, όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), για να βρείτε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες DMARC**.\
Μια άλλη χρήσιμη υπηρεσία είναι το [**dmarcian**](https://dmarcian.com/).

### **Παθητικό Takeover**

Μια εγκαταλελειμμένη εγγραφή A μπορεί να γίνει προσβάσιμη όταν ένας cloud provider εκχωρήσει ξανά μια IP. Η έρευνα που αναφέρεται παρουσιάζει μια opportunistic ροή εργασίας που δημιουργεί ένα instance και συσχετίζει τη διεύθυνσή του με δεδομένα passive DNS· δοκιμάζετε σενάρια takeover μόνο εντός του εξουσιοδοτημένου scope.<sup>[[7]](#references)</sup>

### **Άλλοι τρόποι**

Επαναλάβετε τα κατάλληλα βήματα αναζήτησης κάθε φορά που βρίσκετε ένα νέο domain: κάθε αποτέλεσμα μπορεί να αποκαλύψει επιπλέον ονόματα πιστοποιητικών, σχέσεις passive-DNS, αντιστοιχίες favicon και αναγνωριστικά οργανισμών που δεν ήταν ορατά από το αρχικό seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Αφού γνωρίζετε ήδη το όνομα του οργανισμού στον οποίο ανήκει ο χώρος IP, μπορείτε να αναζητήσετε αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τα hosts που βρέθηκαν για νέα, μη αναμενόμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας ιστοσελίδας, να λάβετε το **όνομα Οργανισμού** και έπειτα να αναζητήσετε αυτό το όνομα στα **TLS certificates** όλων των ιστοσελίδων που είναι γνωστές στο **shodan** με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder) είναι ένα εργαλείο που αναζητά **domains που σχετίζονται** με ένα κύριο domain και τα **subdomains** τους· είναι εξαιρετικό.

**Passive DNS / Historical DNS**

Τα δεδομένα Passive DNS είναι εξαιρετικά για τον εντοπισμό **παλιών και ξεχασμένων εγγραφών** που εξακολουθούν να επιλύονται ή μπορούν να γίνουν αντικείμενο takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Αναζήτηση ευπαθειών**

Ελέγξτε για κάποιο [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί ένα domain**, αλλά **έχασε την ιδιοκτησία του**. Απλώς καταχωρίστε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε οποιοδήποτε **domain με IP διαφορετική** από αυτές που έχετε ήδη εντοπίσει κατά την ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, επομένως είναι εκτός scope· να είστε προσεκτικοί._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες που περιλαμβάνονται στο scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλα τα πιθανά subdomains κάθε domain που εντοπίσαμε.

> [!TIP]
> Σημειώστε ότι ορισμένα εργαλεία και τεχνικές για την εύρεση domains μπορούν επίσης να βοηθήσουν στην εύρεση subdomains

### **DNS**

Ας προσπαθήσουμε να εντοπίσουμε **subdomains** από τις εγγραφές **DNS**. Θα πρέπει επίσης να δοκιμάσουμε το **Zone Transfer** (αν είναι ευάλωτο, θα πρέπει να το αναφέρετε).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Για APIs και πλατφόρμες που καλύπτουν υποδομές, φήμη, αρχεία παραβιάσεων και εμπλουτισμό πέρα από την ανακάλυψη subdomains, δείτε τον [κατάλογο APIs Αναγνώρισης και Πληροφοριών Απειλών](reconnaissance-and-threat-intelligence-apis.md).

Ο ταχύτερος τρόπος για να αποκτήσετε πολλά subdomains είναι να κάνετε αναζήτηση σε εξωτερικές πηγές. Τα πιο χρησιμοποιούμενα **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα, ρυθμίστε τα API keys):


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

Υπάρχουν **και άλλα ενδιαφέροντα εργαλεία/API** που, παρόλο που δεν εξειδικεύονται άμεσα στην εύρεση subdomains, θα μπορούσαν να είναι χρήσιμα για τον εντοπισμό subdomains, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) δωρεάν API

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

- [**gau**](https://github.com/lc/gau)**:** συλλέγει γνωστά URL από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιονδήποτε τομέα.

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

- [**Εύρεση subdomain μέσω Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) προσφέρει περιορισμένη δωρεάν πρόσβαση μέσω API για τρέχοντα δεδομένα DNS και subdomains· για ιστορικά δεδομένα DNS/IP απαιτείται πρόγραμμα επί πληρωμή.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με προγράμματα bug-bounty**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/Moaaz-0x/chaospy) ή ακόμη και να αποκτήσετε πρόσβαση στο scope που χρησιμοποιεί αυτό το project [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** κάνοντας brute-force στους DNS servers με πιθανά ονόματα subdomain.

Για αυτή την ενέργεια θα χρειαστείτε μερικά **συνηθισμένα wordlists για subdomains, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Επίσης, θα χρειαστείτε IPs αξιόπιστων DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο προτεινόμενα εργαλεία για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί μόνο 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper για το `massdns`, γραμμένο σε go, που σου επιτρέπει να απαριθμήσεις έγκυρα subdomains μέσω active bruteforce, καθώς και να επιλύσεις subdomains με χειρισμό wildcard και εύκολη υποστήριξη εισόδου-εξόδου.

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

Αφού εντοπίσετε subdomains μέσω ανοιχτών πηγών και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρήκατε, για να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Για αυτόν τον σκοπό είναι χρήσιμα διάφορα εργαλεία:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Δεδομένων των domains και subdomains, δημιουργεί μεταθέσεις.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Με δεδομένα τα domains και subdomains, δημιουργεί παραλλαγές.
  - Μπορείτε να βρείτε το **wordlist** με τις παραλλαγές του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Με βάση τα domains και τα subdomains, δημιουργεί permutations. Αν δεν καθοριστεί αρχείο permutations, το gotator θα χρησιμοποιήσει το δικό του.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία μεταθέσεων υποτομέων, μπορεί επίσης να προσπαθήσει να επιλύσει τα ονόματά τους (αλλά είναι προτιμότερο να χρησιμοποιήσετε τα εργαλεία που αναφέρθηκαν προηγουμένως).
  - Μπορείτε να βρείτε το **wordlist** μεταθέσεων του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για την εκτέλεση permutations, mutations και τροποποιήσεων υποτομέων. Αυτό το εργαλείο θα κάνει brute force στο αποτέλεσμα (δεν υποστηρίζει DNS wildcard).
  - Μπορείτε να βρείτε τη λίστα λέξεων permutations του dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί πιθανά νέα ονόματα subdomain** σύμφωνα με τα μοτίβα που υποδεικνύονται, για να προσπαθήσει να ανακαλύψει περισσότερα subdomain.

#### Έξυπνη δημιουργία μεταθέσεων

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει μοτίβα τύπου regex από τα subdomain που έχουν ανακαλυφθεί και δημιουργεί υποψήφια ονόματα για επίλυση.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** Το _subzuf_ είναι ένας fuzzer brute-force για subdomain, σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από αποκρίσεις DNS. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως ένα προσαρμοσμένο wordlist ή ιστορικές εγγραφές DNS/TLS, για να συνθέτει με ακρίβεια περισσότερα σχετικά ονόματα domain και να τα επεκτείνει περαιτέρω σε βρόχο, με βάση τις πληροφορίες που συλλέγονται κατά τη σάρωση DNS.

```
echo www | subzuf facebook.com
```

### **Ροή εργασιών για την ανακάλυψη subdomain**

Τα παραδείγματα ροών εργασιών του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλήψιμη απαρίθμηση subdomain.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρήκες μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** που ανήκουν σε subdomain, μπορείς να προσπαθήσεις να **βρεις άλλα subdomain με ιστοσελίδες σε αυτή την IP**, αναζητώντας σε **πηγές OSINT** domains που βρίσκονται σε μια IP ή κάνοντας **brute force σε ονόματα domain VHost σε αυτή την IP**.

#### OSINT

Μπορείς να βρεις ορισμένα **VHosts σε IP χρησιμοποιώντας το** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα API**.

**Brute Force**

Αν υποψιάζεσαι ότι κάποιο subdomain μπορεί να είναι κρυμμένο σε έναν web server, μπορείς να δοκιμάσεις να κάνεις brute force:

Για vhosts που βασίζονται σε όνομα, κάνε fuzz στο `Host` header και χρησιμοποίησε την αυτόματη βαθμονόμηση του ffuf για να φιλτράρεις την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>

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
> Με αυτήν την τεχνική μπορεί να καταφέρεις ακόμα και να αποκτήσεις πρόσβαση σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρεις σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί ένα έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτές τις περιπτώσεις, μπορείς να εκμεταλλευτείς αυτήν τη συμπεριφορά για να **ανακαλύψεις** νέα **subdomains**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Κατά την αναζήτηση για **subdomains**, προσέξτε αν κάποιο **δείχνει** σε οποιονδήποτε τύπο **bucket** και, σε αυτή την περίπτωση, [**ελέγξτε τα permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Επίσης, αφού σε αυτό το σημείο θα γνωρίζετε όλα τα domains που βρίσκονται εντός του scope, προσπαθήστε να [**κάνετε brute force πιθανά ονόματα bucket και να ελέγξετε τα permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Παρακολούθηση**

Μπορείτε να **παρακολουθείτε** αν δημιουργούνται **νέα subdomains** ενός domain, ελέγχοντας τα logs **Certificate Transparency**, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση ευπαθειών**

Ελέγξτε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**ελέγξτε τα permissions**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Αν βρείτε κάποιο **subdomain με διαφορετική IP** από αυτές που έχετε ήδη εντοπίσει κατά την ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο ορισμένα κόλπα για να τις «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το subdomain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, επομένως είναι εκτός scope. Να είστε προσεκτικοί._

## IPs

Στα αρχικά βήματα μπορεί να έχετε **εντοπίσει ορισμένα ranges IP, domains και subdomains**.\
Ώρα να **συγκεντρώσετε όλες τις IPs από αυτά τα ranges**, καθώς και από τα **domains/subdomains (μέσω DNS queries).**

Χρησιμοποιώντας υπηρεσίες όπως οι παρακάτω, μπορείτε επίσης να βρείτε **παλαιότερες IPs που χρησιμοποιούσαν domains και subdomains**. Αυτές οι IPs μπορεί να εξακολουθούν να ανήκουν στον πελάτη (και να σας επιτρέψουν να βρείτε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**SecurityTrails**](https://securitytrails.com/) (τα ιστορικά δεδομένα DNS/IP απαιτούν συνδρομή επί πληρωμή)

Μπορείτε επίσης να εντοπίσετε domains που δείχνουν σε συγκεκριμένη διεύθυνση IP χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση ευπαθειών**

Κάντε **port scan σε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς πιθανότατα δεν θα βρείτε εκεί κάτι ενδιαφέρον). Στις υπηρεσίες που εντοπίσατε να εκτελούνται, ίσως **μπορέσετε να βρείτε ευπάθειες**.

**Βρείτε έναν** [**οδηγό**](../pentesting-network/index.html) **για το πώς να κάνετε scan σε hosts.**

## Αναζήτηση web servers

> Έχουμε εντοπίσει όλες τις εταιρείες και τα assets τους, καθώς και τα ranges IP, τα domains και τα subdomains που βρίσκονται εντός του scope. Ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη κάνει **recon των IPs και των domains που εντοπίσατε**, οπότε ίσως **έχετε ήδη βρει όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, τώρα θα δούμε μερικά **γρήγορα κόλπα για να αναζητήσετε web servers** εντός του scope.

Σημειώστε ότι αυτή η διαδικασία θα είναι **προσανατολισμένη στην ανακάλυψη web apps**, επομένως θα πρέπει να κάνετε επίσης **vulnerability scanning** και **port scanning** (**αν επιτρέπεται** από το scope).

Μπορείτε να βρείτε [**εδώ μια γρήγορη μέθοδο**](../pentesting-network/index.html#http-port-discovery) για να εντοπίσετε **ανοιχτές θύρες** που σχετίζονται με **web** servers χρησιμοποιώντας το [**masscan**].\
Ένα άλλο εύχρηστο εργαλείο για την αναζήτηση web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** το [**fprobe**](https://github.com/theblackturtle/fprobe) και το [**httpx**](https://github.com/projectdiscovery/httpx). Αρκεί να τους δώσετε μια λίστα με domains και θα προσπαθήσουν να συνδεθούν στις θύρες 80 (http) και 443 (https). Επιπλέον, μπορείτε να ορίσετε να δοκιμάσουν και άλλες θύρες:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Τώρα που ανακαλύψατε **όλους τους web servers** που βρίσκονται εντός scope (ανάμεσα στις **IP** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν ξέρετε από πού να ξεκινήσετε**. Ας το απλοποιήσουμε, λοιπόν, ξεκινώντας απλώς με τη λήψη screenshots όλων τους. Αρκεί να **ρίξετε μια ματιά** στην **κύρια σελίδα** για να εντοπίσετε **περίεργα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να εφαρμόσετε αυτή την ιδέα, μπορείτε να χρησιμοποιήσετε τα [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε στη συνέχεια να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να αναλύσει όλα τα **screenshots** και να σας πει **ποια είναι πιθανό να περιέχουν ευπάθειες** και ποια όχι.

## Assets σε Public Cloud

Για να εντοπίσετε πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει να **ξεκινήσετε με μια λίστα λέξεων-κλειδιών που προσδιορίζουν την εταιρεία**. Για παράδειγμα, για μια εταιρεία crypto, μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης wordlists με **συνήθεις λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις, θα πρέπει να δημιουργήσετε **permutations** (για περισσότερες πληροφορίες, δείτε τον [**δεύτερο γύρο DNS brute-force**](#second-dns-bruteforce-round)).

Με τις wordlists που θα προκύψουν, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάστε ότι, όταν αναζητάτε Cloud Assets, πρέπει να **ψάχνετε για περισσότερα από απλώς buckets στο AWS**.

### **Αναζήτηση για ευπάθειες**

Αν βρείτε στοιχεία όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει να **αποκτήσετε πρόσβαση σε αυτά** και να προσπαθήσετε να δείτε τι παρέχουν και αν μπορείτε να τα εκμεταλλευτείτε.

## Emails

Με τα **domains** και τα **subdomains** που βρίσκονται εντός scope, έχετε ουσιαστικά όλα όσα **χρειάζεστε για να ξεκινήσετε την αναζήτηση emails**. Αυτά είναι τα **APIs** και τα **εργαλεία** που έχουν αποδειχθεί πιο αποτελεσματικά για να εντοπίζω emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
- API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
- API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση για ευπάθειες**

Τα emails θα σας φανούν χρήσιμα αργότερα για **brute-force σε web logins και auth services** (όπως το SSH). Είναι επίσης απαραίτητα για **phishing**. Επιπλέον, αυτά τα APIs θα σας δώσουν ακόμη περισσότερες **πληροφορίες για το άτομο** που βρίσκεται πίσω από το email, κάτι χρήσιμο για την καμπάνια phishing.

## Credential Leaks

Με τα **domains,** τα **subdomains** και τα **emails**, μπορείτε να ξεκινήσετε την αναζήτηση για διαπιστευτήρια που έχουν γίνει leak στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζήτηση για ευπάθειες**

Αν βρείτε **έγκυρα leaked** διαπιστευτήρια, πρόκειται για μια πολύ εύκολη επιτυχία.

## Secrets Leaks

Τα Credential Leaks σχετίζονται με hacks εταιρειών κατά τα οποία **διέρρευσαν και πουλήθηκαν ευαίσθητες πληροφορίες**. Ωστόσο, οι εταιρείες μπορεί να επηρεάζονται και από **άλλα leaks**, των οποίων οι πληροφορίες δεν βρίσκονται σε αυτές τις βάσεις δεδομένων:

### Github Leaks

Διαπιστευτήρια και APIs μπορεί να έχουν γίνει leak στα **public repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται στην εταιρεία στο github.\
Μπορείτε να χρησιμοποιήσετε το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **public repos** ενός **organization** και των **developers** του και να εκτελέσετε αυτόματα το [**gitleaks**](https://github.com/gitleaks/gitleaks) σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για την εκτέλεση του **gitleaks** σε όλα τα **κείμενα** που παρέχονται ως **URLs** σε αυτό, καθώς μερικές φορές και οι **web pages περιέχουν secrets**.

#### Github Dorks

Δείτε τη σελίδα [GitHub dorks και leaks](github-leaked-secrets.md) για πιθανά **GitHub dorks** που μπορείτε να αναζητήσετε στο organization.

### Paste Leaks

Μερικές φορές, επιτιθέμενοι ή απλώς εργαζόμενοι **δημοσιεύουν εταιρικό περιεχόμενο σε έναν paste site**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά αξίζει πολύ να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για να κάνετε αναζήτηση σε περισσότερους από 80 paste sites ταυτόχρονα.

### Google Dorks

Τα παλιά αλλά δοκιμασμένα google dorks είναι πάντα χρήσιμα για τον εντοπισμό **εκτεθειμένων πληροφοριών που δεν θα έπρεπε να βρίσκονται εκεί**. Το μόνο πρόβλημα είναι ότι το [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανά queries, τα οποία δεν μπορείτε να εκτελέσετε χειροκίνητα. Έτσι, μπορείτε να διαλέξετε τα 10 αγαπημένα σας ή να χρησιμοποιήσετε ένα **εργαλείο όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τα εκτελέσετε όλα**.

_Σημειώστε ότι τα εργαλεία που επιχειρούν να εκτελέσουν ολόκληρη τη βάση δεδομένων μέσω του κανονικού Google browser δεν θα ολοκληρώσουν ποτέ, καθώς η Google θα σας αποκλείσει πολύ σύντομα._

### **Αναζήτηση για ευπάθειες**

Αν βρείτε **έγκυρα leaked** διαπιστευτήρια ή API tokens, πρόκειται για μια πολύ εύκολη επιτυχία.

## Ευπάθειες σε Public Code

Αν διαπιστώσετε ότι η εταιρεία διαθέτει **open-source code**, μπορείτε να το **αναλύσετε** και να αναζητήσετε **ευπάθειες** σε αυτό.

**Ανάλογα με τη γλώσσα**, υπάρχουν διαφορετικά **εργαλεία** που μπορείτε να χρησιμοποιήσετε· δείτε τη λίστα με τα [εργαλεία ελέγχου source code](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν υπηρεσίες που σας επιτρέπουν να **σαρώσετε public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Μεθοδολογία Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των ευπαθειών** που εντοπίζουν οι bug hunters βρίσκεται μέσα σε **web applications**, επομένως σε αυτό το σημείο θα ήθελα να αναφερθώ σε μια **μεθοδολογία ελέγχου web applications**. Μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική αναφορά στην ενότητα [**εργαλεία open source για αυτοματοποιημένους web scanners**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρότι δεν θα πρέπει να περιμένετε να εντοπίσουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για την ενσωμάτωσή τους σε **workflows, ώστε να αποκτήσετε κάποιες αρχικές πληροφορίες για το web.**

## Ανακεφαλαίωση

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη ολοκληρώσει **όλη τη βασική enumeration**. Ναι, είναι βασική, επειδή μπορεί να γίνει πολύ περισσότερη enumeration (θα δούμε περισσότερα κόλπα αργότερα).

Έχετε ήδη:

1. Εντοπίσει όλες τις **εταιρείες** που βρίσκονται εντός scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και εκτελέσει κάποιο vuln scan, αν είναι εντός scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Εντοπίσει όλες τις **IP** (από και **εκτός των CDNs**) που βρίσκονται εντός scope.
6. Εντοπίσει όλους τους **web servers** και τραβήξει ένα **screenshot** για καθέναν (υπάρχει κάτι περίεργο που αξίζει να εξετάσετε περισσότερο;)
7. Εντοπίσει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. **Emails**, **credential leaks** και **secret leaks** που θα μπορούσαν να σας δώσουν μια **μεγάλη και εύκολη επιτυχία**.
9. **Κάνει pentesting σε όλους τους ιστότοπους που εντοπίσατε**

## **Εργαλεία Full Recon Automation**

Υπάρχουν αρκετά εργαλεία που εκτελούν μέρος των προτεινόμενων ενεργειών για ένα δεδομένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και δεν έχει ενημερωθεί



## References

- [1] [Jason Haddix – Η μεθοδολογία του Bug Hunter v4.0: Έκδοση Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Σχετικά με τα Favicons: Από τα εικονίδια του browser στην ευφυΐα της επιφάνειας επίθεσης](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Αξιοποίηση του favicon.ico για BugBounties, OSINT και άλλα](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Εντοπισμός Domains μέσω επίθεσης χρονικής συσχέτισης στο Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Παθητικό Takeover: Αποκάλυψη (και προσομοίωση) μιας δαπανηρής καμπάνιας Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Μια μοναδική μέθοδος enumeration subdomain](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Πλήρης ροή εργασίας για την ανακάλυψη subdomain, Μέρος 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Πλήρης ανακάλυψη subdomain με brute force μέσω αυτοματοποιημένης ροής εργασίας Trickest, Μέρος 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot εξόδου του favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
