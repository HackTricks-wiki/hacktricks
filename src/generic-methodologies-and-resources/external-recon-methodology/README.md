# Μεθοδολογία εξωτερικού Recon

{{#include ../../banners/hacktricks-training.md}}

## Ανακάλυψη assets

> Σου είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία είναι εντός scope και θέλεις να εξακριβώσεις τι ακριβώς της ανήκει.

Στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και, στη συνέχεια, όλα τα **assets** αυτών των εταιρειών. Για να το κάνουμε αυτό, θα:<sup>[[1]](#references)</sup>

1. Εντοπίσουμε τις εξαγορές της κύριας εταιρείας. Έτσι θα βρούμε τις εταιρείες που βρίσκονται εντός scope.
2. Εντοπίσουμε το ASN (αν υπάρχει) κάθε εταιρείας. Έτσι θα βρούμε τα IP ranges που της ανήκουν.
3. Χρησιμοποιήσουμε reverse whois lookups για να αναζητήσουμε άλλες εγγραφές (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη. (Αυτό μπορεί να γίνει επαναληπτικά.)
4. Χρησιμοποιήσουμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets. (Το τέχνασμα `ssl` μπορεί να εφαρμοστεί επαναληπτικά.)

Για τη σταδιακή μετάβαση από τα επιλυμένα subdomains στο HTTP crawling και την ανακάλυψη θυρών, δες τη [Μεθοδολογία Pentesting](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Εξαγορές**

Πρώτα απ' όλα, πρέπει να μάθουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφτείς το [https://www.crunchbase.com/](https://www.crunchbase.com), να **αναζητήσεις** την **κύρια εταιρεία** και να **κάνεις κλικ** στο "**acquisitions**". Εκεί θα δεις άλλες εταιρείες που εξαγοράστηκαν από την κύρια εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφτείς τη σελίδα της κύριας εταιρείας στη **Wikipedia** και να αναζητήσεις τις **εξαγορές** της.\
Για εισηγμένες εταιρείες, έλεγξε τις καταθέσεις **SEC/EDGAR**, τις σελίδες **επενδυτικών σχέσεων** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμιους εταιρικούς ομίλους και θυγατρικές, δοκίμασε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζεις όλες τις εταιρείες που βρίσκονται εντός scope. Ας δούμε πώς μπορούμε να βρούμε τα assets τους.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **αυτόνομο σύστημα** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** **IP διευθύνσεων** που έχουν σαφώς καθορισμένη πολιτική πρόσβασης σε εξωτερικά δίκτυα και διαχειρίζονται από έναν οργανισμό, αλλά μπορεί να αποτελούνται από πολλούς παρόχους.

Είναι χρήσιμο να εξακριβώσεις αν έχουν εκχωρηθεί **ASN στην εταιρεία**, ώστε να βρεις τα **IP ranges** της. Θα ήταν χρήσιμο να πραγματοποιήσεις **έλεγχο ευπαθειών** σε όλους τους **hosts** που βρίσκονται εντός **scope** και να **αναζητήσεις domains** μέσα σε αυτές τις IP.\
Μπορείς να κάνεις **αναζήτηση** με βάση το **όνομα** της εταιρείας, μια **IP** ή ένα **domain** στο [**https://bgp.he.net/**](https://bgp.he.net) **ή** στο [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή όπου βρίσκεται η εταιρεία, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Σε κάθε περίπτωση, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(IP ranges και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Επίσης, η διαδικασία enumeration του [**BBOT**](https://github.com/blacklanternsecurity/bbot) συγκεντρώνει και συνοψίζει αυτόματα τα ASN στο τέλος της σάρωσης.

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

Μπορείτε επίσης να βρείτε τα εύρη IP ενός οργανισμού μέσω του [ASNLookup](https://asnlookup.com/), το οποίο διαθέτει περιορισμένο δωρεάν επίπεδο API.

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets εντός του scope**, επομένως, αν έχετε την άδεια, μπορείτε να εκτελέσετε έναν **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να εκτελέσετε [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως** Shodan, Censys ή ZoomEye **για να βρείτε** ανοιχτές θύρες **και, ανάλογα με όσα βρείτε, θα πρέπει να συμβουλευτείτε** αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορες πιθανές υπηρεσίες που εκτελούνται.\
**Επίσης, αξίζει να αναφέρουμε ότι μπορείτε να ετοιμάσετε λίστες με** προεπιλεγμένα usernames **και** passwords **και να προσπαθήσετε να κάνετε** bruteforce σε υπηρεσίες με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες εντός του scope και τα assets τους· ήρθε η ώρα να βρούμε τα domains εντός του scope.

_Σημειώστε ότι με τις παρακάτω προτεινόμενες τεχνικές μπορείτε επίσης να βρείτε subdomains και δεν πρέπει να υποτιμάτε αυτή την πληροφορία._

Πρώτα απ’ όλα, θα πρέπει να αναζητήσετε το **κύριο domain** κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι το _tesla.com_.

### **Reverse DNS**

Αφού βρείτε όλα τα εύρη IP των domains, μπορείτε να δοκιμάσετε να κάνετε **reverse DNS lookups** σε αυτές τις **IP για να βρείτε περισσότερα domains εντός του scope**. Δοκιμάστε να χρησιμοποιήσετε κάποιον DNS server του θύματος ή κάποιον ευρέως γνωστό DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε το [SecurityTrails](https://securitytrails.com/) για αυτές τις πληροφορίες, αν και για τα ιστορικά δεδομένα DNS απαιτείται συνδρομή επί πληρωμή.\
Για μεγάλα ranges, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του εμπλουτισμού δεδομένων.

### **Reverse Whois (loop)**

Σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα οργανισμού**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Ακόμα πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν κάνετε **reverse whois lookups με βάση οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλες εγγραφές whois στις οποίες εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** web interface· API επί πληρωμή.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Επί πληρωμή
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Δεν είναι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Δεν είναι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Περιορισμένη δωρεάν πρόσβαση στο API για τρέχοντα DNS/subdomains· για ιστορικές αναζητήσεις και reverse lookups απαιτείται συνδρομή επί πληρωμή.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 δωρεάν credits API κατά την εγγραφή· στη συνέχεια επί πληρωμή.

Μπορείτε να αυτοματοποιήσετε αυτήν την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτεί κλειδί API του whoxy).\
Μπορείτε επίσης να κάνετε αυτόματη ανακάλυψη μέσω reverse whois με το [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να αναζητάτε με βάση αυτούς τους trackers και άλλα στοιχεία:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Υπηρεσία web και API **επί πληρωμή** ([τιμολόγηση](https://www.stackscan.com/pricing))· προς το παρόν δεν διαφημίζεται δωρεάν πλάνο. Κάντε pivot με βάση οποιοδήποτε asset σερβίρεται, όχι μόνο τα IDs των trackers: μια διαδρομή script, ένα όνομα self-hosted bundle ή ο host από τον οποίο φορτώνεται ένα asset, και λάβετε κάθε site που το περιέχει

Το API επιστρέφει το stack για ένα domain, κάτι που είναι χρήσιμο για να επιβεβαιώσετε ότι ένα υποψήφιο asset ανήκει στο ίδιο estate:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Επιστρέφει κάθε τεχνολογία που εντοπίζει μαζί με την κατηγορία της. Το asset pivoting είναι προς το παρόν διαθέσιμο μόνο για web, ενώ το API καλύπτει αναζητήσεις ανά domain.

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε σχετιζόμενα domains και subdomains του στόχου μας αναζητώντας το ίδιο hash εικονιδίου favicon; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), που δημιουργήθηκε από τον [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς μπορείτε να το χρησιμοποιήσετε:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Αποτελέσματα του Favihash που χρησιμοποιήθηκαν για τον εντοπισμό domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash μάς επιτρέπει να εντοπίζουμε domains που έχουν το ίδιο hash εικονιδίου favicon με τον στόχο μας.

![Έξοδος του favihash που χρησιμοποιήθηκε για τον εντοπισμό domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Χρησιμοποιήστε ένα γνωστό hash favicon ως pivot στο Shodan ή το FOFA, για να εντοπίσετε άλλες εκτεθειμένες εγκαταστάσεις της ίδιας τεχνολογίας.<sup>[[5]](#references)</sup>

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

Μπορείτε επίσης να συλλέξετε hashes favicon σε μεγάλη κλίμακα με το [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και στη συνέχεια να κάνετε pivot στο Shodan/Censys.

Αντιμετωπίζετε τα αποτυπώματα favicon ως ενδείξεις και τα επαληθεύετε με βάση τα συνοδευτικά σήματα.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίζετε το hash ως ένδειξη, όχι ως απόδειξη**: Το MMH3 είναι συμπαγές· είναι πιθανά collisions, επαναχρησιμοποιημένα εικονίδια και σκόπιμη πλαστογράφηση.
- **Εξετάζετε περισσότερα από το** `/favicon.ico`: ελέγχετε διαδρομές framework/build, αρχεία manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και ετικέτες HTML `<link rel="icon">`.
- **Τα static assets μπορεί να παραμένουν προσβάσιμα πίσω από ελέγχους WAF/SSO/IdP**: ζητήστε απευθείας το εικονίδιο και ελέγξτε τα `ETag`, `Last-Modified`, redirects και cache headers.
- **Επαληθεύετε τις αντιστοιχίες με βάση τα συνοδευτικά σήματα**: συγκρίνετε τον τίτλο, το HTML/body hash, τα headers, τα subjects/SANs του TLS certificate, τα components προϊόντων και τις εκτεθειμένες ports.
- **Ομαδοποιείτε βάσει HTML/body hash**: ένα σταθερό template ενισχύει το αποτύπωμα· διαφορετικά templates υποδηλώνουν ένα γενικό ή κοινόχρηστο εικονίδιο.
- **Αντιμετωπίζετε ένα hash που εμφανίζεται σε άσχετες υπογραφές, ports και προϊόντα ως πιθανό honeypot ή placeholder.**
- **Σε αμφίσημους στόχους, συγκρίνετε μια πραγματική σελίδα με ένα ανύπαρκτο path**, όπως το `/_favicon_probe_<8-hex>`· οι ίδιες απαντήσεις hosting ή parking μπορεί να εξηγούν το κοινό εικονίδιο.
- **Ξεκινάτε την αρχική διαλογή από κανόνες ανίχνευσης του Nuclei ή δημόσια datasets** που αντιστοιχίζουν hashes favicon σε προϊόντα και CPEs.
- **Να θυμάστε το κενό κάλυψης που αφορά τις IP**: επιφάνειες πίσω από CDN, με δρομολόγηση SNI, anycast και μόνο domain μπορεί να απουσιάζουν από datasets τύπου Shodan.

### **Copyright / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που μπορεί να είναι κοινές σε διαφορετικούς ιστότοπους του ίδιου οργανισμού**. Η **συμβολοσειρά copyright** είναι ένα καλό παράδειγμα. Στη συνέχεια, αναζητήστε αυτή τη συμβολοσειρά στο **google**, σε άλλα **browsers** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **Χρόνος CRT**

Είναι συνηθισμένο να υπάρχει μια cron job όπως η παρακάτω:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

για την ταυτόχρονη ανανέωση όλων των πιστοποιητικών σε έναν server. Η συσχέτιση των χρονικών σημάνσεων των πιστοποιητικών ή των θέσεών τους στα αρχεία καταγραφής certificate transparency μπορεί να αποκαλύψει συσχετιζόμενα domains.<sup>[[6]](#references)</sup>

Χρησιμοποιήστε επίσης απευθείας τα αρχεία καταγραφής **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες DMARC**.\
Μια άλλη χρήσιμη υπηρεσία είναι το [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Μια εγκαταλελειμμένη εγγραφή A μπορεί να γίνει προσβάσιμη όταν ένας cloud provider εκχωρήσει ξανά μια IP. Η έρευνα που αναφέρεται παρουσιάζει μια ευκαιριακή ροή εργασίας που δημιουργεί ένα instance και συσχετίζει τη διεύθυνσή του με δεδομένα passive DNS· δοκιμάζετε σενάρια takeover μόνο εντός του εγκεκριμένου πεδίου.<sup>[[7]](#references)</sup>

### **Άλλοι τρόποι**

Επαναλαμβάνετε τις κατάλληλες μεθόδους αναζήτησης κάθε φορά που βρίσκετε ένα νέο domain: κάθε αποτέλεσμα μπορεί να αποκαλύψει επιπλέον ονόματα πιστοποιητικών, συσχετίσεις passive DNS, αντιστοιχίες favicon και αναγνωριστικά οργανισμών που δεν ήταν ορατά από το αρχικό seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Αφού γνωρίζετε ήδη το όνομα του οργανισμού στον οποίο ανήκει ο χώρος IP, μπορείτε να αναζητήσετε αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους hosts που βρέθηκαν για νέα, απροσδόκητα domains στο πιστοποιητικό TLS.

Μπορείτε να αποκτήσετε πρόσβαση στο **πιστοποιητικό TLS** της κύριας ιστοσελίδας, να λάβετε το **όνομα του οργανισμού** και έπειτα να αναζητήσετε αυτό το όνομα στα **πιστοποιητικά TLS** όλων των ιστοσελίδων που γνωρίζει το **shodan**, με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)είναι ένα εργαλείο που αναζητά **domains σχετικά** με ένα κύριο domain και τα **subdomains** τους· είναι εξαιρετικό.

**Passive DNS / Ιστορικό DNS**

Τα δεδομένα Passive DNS είναι εξαιρετικά για την εύρεση **παλιών και ξεχασμένων εγγραφών** που εξακολουθούν να επιλύονται ή που μπορούν να γίνουν αντικείμενο takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Αναζήτηση ευπαθειών**

Ελέγξτε για πιθανό [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί ένα domain**, αλλά **έχασε την κυριότητά του**. Απλώς κατοχυρώστε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε οποιοδήποτε **domain με διαφορετική IP** από αυτές που έχετε ήδη εντοπίσει στην ανακάλυψη assets, θα πρέπει να εκτελέσετε μια **βασική σάρωση ευπαθειών** (με Nessus ή OpenVAS) και κάποια [**σάρωση θυρών**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε μια IP που δεν ελέγχεται από τον πελάτη, επομένως είναι εκτός πεδίου· προσέξτε._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες εντός του πεδίου, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρείτε όλα τα πιθανά subdomains για κάθε domain που εντοπίστηκε.

> [!TIP]
> Σημειώστε ότι ορισμένα από τα εργαλεία και τις τεχνικές εύρεσης domains μπορούν να βοηθήσουν και στην εύρεση subdomains

### **DNS**

Ας προσπαθήσουμε να βρούμε **subdomains** από τις εγγραφές **DNS**. Θα πρέπει επίσης να δοκιμάσουμε το **Zone Transfer** (αν είναι ευάλωτο, θα πρέπει να το αναφέρετε).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Για API και πλατφόρμες που καλύπτουν υποδομές, φήμη, αρχεία παραβιάσεων και εμπλουτισμό πέρα από την ανακάλυψη subdomains, δείτε τον [κατάλογο API αναγνώρισης και πληροφοριών απειλών](reconnaissance-and-threat-intelligence-apis.md).

Ο πιο γρήγορος τρόπος για να βρείτε πολλά subdomains είναι να κάνετε αναζήτηση σε εξωτερικές πηγές. Τα πιο δημοφιλή **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα, διαμορφώστε τα API keys):


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

Υπάρχουν **και άλλα ενδιαφέροντα εργαλεία/API** που, παρότι δεν είναι εξειδικευμένα στην εύρεση subdomains, θα μπορούσαν να είναι χρήσιμα για την εύρεσή τους, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) δωρεάν API

```bash
curl https://ip.thc.org/tesla.com
```

- [**δωρεάν API του AnubisDB**](https://github.com/jonluca/Anubis-DB)

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

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Κάνουν scraping στο web αναζητώντας αρχεία JS και εξάγουν subdomains από αυτά.

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

- [**Εργαλείο εύρεσης subdomain του Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) προσφέρει περιορισμένη δωρεάν πρόσβαση στο API για τρέχοντα δεδομένα DNS και subdomains· για ιστορικά δεδομένα DNS/IP απαιτείται συνδρομή επί πληρωμή.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Αυτό το project προσφέρει δωρεάν όλα τα subdomains που σχετίζονται με προγράμματα bug-bounty. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/Moaaz-0x/chaospy) ή ακόμη και να αποκτήσετε πρόσβαση στο scope που χρησιμοποιεί αυτό το project: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να εντοπίσουμε νέα **subdomains** κάνοντας brute force στους DNS servers με πιθανά ονόματα subdomain.

Για αυτήν την ενέργεια θα χρειαστείτε μερικά **wordlists με κοινά subdomains, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Θα χρειαστείτε επίσης IPs αξιόπιστων DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε το [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα εργαλεία που προτείνονται περισσότερο για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί απλώς 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε go, που επιτρέπει την απαρίθμηση έγκυρων subdomains μέσω active bruteforce, καθώς και την επίλυση subdomains με χειρισμό wildcard και εύκολη υποστήριξη εισόδου-εξόδου.

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

Αφού εντοπίσετε subdomains μέσω open sources και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρήκατε, για να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Για αυτόν τον σκοπό είναι χρήσιμα διάφορα εργαλεία:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Δέχεται domains και subdomains και δημιουργεί permutations.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Με βάση τα domains και subdomains, δημιουργεί permutations.
  - Μπορείτε να βρείτε το **wordlist** με τα permutations του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Με δεδομένα τα domains και τα subdomains, δημιουργεί μεταθέσεις. Αν δεν οριστεί αρχείο μεταθέσεων, το gotator θα χρησιμοποιήσει το δικό του.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία μεταθέσεων υποτομέων, μπορεί επίσης να προσπαθήσει να τις επιλύσει (αλλά είναι προτιμότερο να χρησιμοποιήσετε τα εργαλεία που αναφέρθηκαν προηγουμένως).
  - Μπορείτε να βρείτε το **wordlist** μεταθέσεων του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για την εκτέλεση μεταθέσεων, μεταλλάξεων και τροποποιήσεων υποτομέων. Αυτό το εργαλείο θα κάνει brute force στα αποτελέσματα (δεν υποστηρίζει dns wild card).
  - Μπορείτε να βρείτε τη λίστα λέξεων με τις μεταθέσεις του dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί ονόματα πιθανών νέων subdomains** σύμφωνα με καθορισμένα μοτίβα, για να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Δημιουργία έξυπνων μεταθέσεων

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει μοτίβα τύπου regex από subdomains που έχουν εντοπιστεί και δημιουργεί υποψήφια ονόματα προς επίλυση.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** Το _subzuf_ είναι ένα fuzzer brute-force υποτομέων, σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο που καθοδηγείται από τις απαντήσεις DNS. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως μια προσαρμοσμένη wordlist ή ιστορικές εγγραφές DNS/TLS, για να συνθέτει με ακρίβεια περισσότερα αντίστοιχα ονόματα domain και να τα επεκτείνει περαιτέρω σε επαναληπτικό βρόχο, με βάση τις πληροφορίες που συλλέγονται κατά τη σάρωση DNS.

```
echo www | subzuf facebook.com
```

### **Ροή εργασίας για την ανακάλυψη subdomain**

Τα παραδείγματα ροών εργασίας του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλήψιμη απαρίθμηση subdomain.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρείτε μια διεύθυνση IP που φιλοξενεί **μία ή περισσότερες ιστοσελίδες** οι οποίες ανήκουν σε subdomain, μπορείτε να προσπαθήσετε να **βρείτε άλλα subdomain με ιστοσελίδες σε αυτή την IP**, αναζητώντας σε **πηγές OSINT** domains που σχετίζονται με μια IP ή κάνοντας **brute force στα ονόματα domain των VHost σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε **VHosts σε IP χρησιμοποιώντας** το [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα API**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιο subdomain είναι κρυμμένο σε έναν web server, μπορείτε να δοκιμάσετε να το εντοπίσετε με brute force:

Για vhost που βασίζονται σε όνομα, κάντε fuzz στο `Host` header και χρησιμοποιήστε την αυτόματη βαθμονόμηση του ffuf για να φιλτράρετε την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>

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
> Με αυτήν την τεχνική μπορεί ακόμη και να αποκτήσετε πρόσβαση σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί ένα έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτές τις περιπτώσεις, μπορείτε να εκμεταλλευτείτε αυτήν τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Κατά την αναζήτηση για **subdomains**, έχε τον νου σου μήπως κάποιο **δείχνει** σε οποιονδήποτε τύπο **bucket** και, σε αυτή την περίπτωση, [**έλεγξε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, αφού σε αυτό το σημείο θα γνωρίζεις όλα τα domains εντός του scope, δοκίμασε να κάνεις [**brute force σε πιθανά ονόματα bucket και να ελέγξεις τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείς να **παρακολουθείς** αν δημιουργούνται **νέα subdomains** ενός domain, παρακολουθώντας τα **Certificate Transparency** Logs, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση ευπαθειών**

Έλεγξε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**έλεγξε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρεις κάποιο **subdomain με IP διαφορετική** από αυτές που έχεις ήδη εντοπίσει κατά την ανακάλυψη assets, θα πρέπει να πραγματοποιήσεις ένα **basic vulnerability scan** (με Nessus ή OpenVAS) και ένα [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείς να βρεις **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείς»**.\
_Να έχεις υπόψη ότι μερικές φορές το subdomain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη και, επομένως, είναι εκτός scope. Να είσαι προσεκτικός._

## IPs

Στα αρχικά βήματα μπορεί να **εντόπισες ορισμένα εύρη IP, domains και subdomains**.\
Ήρθε η ώρα να **συγκεντρώσεις όλες τις IPs από αυτά τα εύρη** και από τα **domains/subdomains (μέσω DNS queries).**

Χρησιμοποιώντας υπηρεσίες όπως οι παρακάτω, μπορείς επίσης να βρεις **παλαιότερες IPs που χρησιμοποιούσαν domains και subdomains**. Αυτές οι IPs ενδέχεται να ανήκουν ακόμη στον πελάτη (και ίσως να σου επιτρέψουν να εντοπίσεις [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (τα ιστορικά δεδομένα DNS/IP απαιτούν επί πληρωμή πρόγραμμα)

Μπορείς επίσης να εντοπίσεις domains που δείχνουν σε μια συγκεκριμένη διεύθυνση IP, χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση ευπαθειών**

Κάνε **port scan σε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μη βρεις εκεί κάτι ενδιαφέρον). Στις υπηρεσίες που εντοπίστηκαν να εκτελούνται, ίσως **μπορέσεις να βρεις ευπάθειες**.

**Βρες έναν** [**οδηγό**](../pentesting-network/index.html) **σχετικά με το πώς να κάνεις scan σε hosts.**

## Αναζήτηση web servers

> Έχουμε βρει όλες τις εταιρείες και τα assets τους, και γνωρίζουμε τα εύρη IP, τα domains και τα subdomains εντός του scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχεις ήδη κάνει κάποιο **recon των IPs και των domains που εντόπισες**, οπότε μπορεί να έχεις **βρει ήδη όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχεις κάνει, θα δούμε τώρα μερικά **γρήγορα κόλπα για την αναζήτηση web servers** εντός του scope.

Σημείωσε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, επομένως θα πρέπει να πραγματοποιήσεις επίσης **σάρωση για ευπάθειες** και **port scanning** (**αν επιτρέπεται** από το scope).

Μπορείς να βρεις [**εδώ μια γρήγορη μέθοδο για τον εντοπισμό ανοιχτών ports**](../pentesting-network/index.html#http-port-discovery) που σχετίζονται με **web** servers, χρησιμοποιώντας το [**masscan**].\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** το [**fprobe**](https://github.com/theblackturtle/fprobe) και το [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς περνάς μια λίστα με domains και το εργαλείο θα προσπαθήσει να συνδεθεί στις ports 80 (http) και 443 (https). Επιπλέον, μπορείς να ορίσεις να δοκιμάσει και άλλες ports:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Στιγμιότυπα οθόνης**

Τώρα που έχετε ανακαλύψει **όλους τους web servers** που υπάρχουν στο scope (ανάμεσα στις **IPs** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν ξέρετε από πού να ξεκινήσετε**. Ας το απλοποιήσουμε, λοιπόν, και ας αρχίσουμε απλώς να τραβάμε στιγμιότυπα οθόνης όλων. Αρκεί να **ρίξετε μια ματιά** στην **κύρια σελίδα** για να εντοπίσετε **περίεργα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να εφαρμόσετε την παραπάνω ιδέα, μπορείτε να χρησιμοποιήσετε τα [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε στη συνέχεια να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να αναλύσετε όλα τα **στιγμιότυπα οθόνης** και να σας υποδείξει **ποια είναι πιθανό να περιέχουν ευπάθειες** και ποια όχι.

## Assets σε Public Cloud

Για να εντοπίσετε πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει **να ξεκινήσετε με μια λίστα λέξεων-κλειδιών που την ταυτοποιούν**. Για παράδειγμα, για μια εταιρεία crypto, μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, χρησιμοποιώντας αυτές τις λέξεις, θα πρέπει να δημιουργήσετε **permutations** (για περισσότερες πληροφορίες, δείτε το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Με τις wordlists που θα προκύψουν, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάστε ότι όταν αναζητάτε Cloud Assets, θα πρέπει να **ψάχνετε για περισσότερα από buckets στο AWS**.

### **Αναζήτηση ευπαθειών**

Αν εντοπίσετε πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει **να αποκτήσετε πρόσβαση σε αυτά** και να δείτε τι προσφέρουν και αν μπορείτε να τα καταχραστείτε.

## Emails

Με τα **domains** και τα **subdomains** που περιλαμβάνονται στο scope, έχετε ουσιαστικά όλα όσα **χρειάζεστε για να αρχίσετε να αναζητάτε emails**. Αυτά είναι τα **APIs** και τα **εργαλεία** που έχουν λειτουργήσει καλύτερα για μένα στην εύρεση emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
- API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
- API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση ευπαθειών**

Τα emails θα σας φανούν χρήσιμα αργότερα για **brute-force σε web logins και auth services** (όπως το SSH). Χρειάζονται επίσης για **phishings**. Επιπλέον, αυτά τα APIs θα σας δώσουν ακόμη περισσότερες **πληροφορίες για το άτομο** πίσω από το email, χρήσιμες για την καμπάνια phishing.

## Credential Leaks

Με τα **domains,** τα **subdomains** και τα **emails**, μπορείτε να αρχίσετε να αναζητάτε credentials που έχουν διαρρεύσει στο παρελθόν και σχετίζονται με αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα leaked** credentials, είναι μια πολύ εύκολη επιτυχία.

## Secrets Leaks

Τα credential leaks σχετίζονται με παραβιάσεις εταιρειών, κατά τις οποίες **διέρρευσαν και πωλήθηκαν ευαίσθητες πληροφορίες**. Ωστόσο, οι εταιρείες μπορεί να έχουν επηρεαστεί και από **άλλα leaks**, των οποίων οι πληροφορίες δεν βρίσκονται σε αυτές τις βάσεις δεδομένων:

### Github Leaks

Credentials και APIs μπορεί να έχουν διαρρεύσει στα **δημόσια repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται στην εταιρεία github.\
Μπορείτε να χρησιμοποιήσετε το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **δημόσια repos** ενός **οργανισμού** και των **developers** του και να εκτελέσετε αυτόματα το [**gitleaks**](https://github.com/gitleaks/gitleaks) σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για να εκτελέσει το **gitleaks** σε όλα τα **κείμενα** που παρέχονται μέσω **URLs**, καθώς μερικές φορές και οι **ιστοσελίδες περιέχουν secrets**.

#### Github Dorks

Δείτε τη σελίδα [GitHub dorks and leaks](github-leaked-secrets.md) για πιθανά **GitHub dorks** προς αναζήτηση στον οργανισμό.

### Pastes Leaks

Μερικές φορές, επιτιθέμενοι ή απλώς εργαζόμενοι **δημοσιεύουν περιεχόμενο εταιρειών σε έναν ιστότοπο paste**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά αξίζει πολύ να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για ταυτόχρονη αναζήτηση σε περισσότερους από 80 ιστότοπους paste.

### Google Dorks

Τα παλιά αλλά δοκιμασμένα google dorks είναι πάντα χρήσιμα για να βρείτε **εκτεθειμένες πληροφορίες που δεν θα έπρεπε να βρίσκονται εκεί**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανά queries, τα οποία δεν μπορείτε να εκτελέσετε χειροκίνητα. Επομένως, μπορείτε να επιλέξετε τα 10 αγαπημένα σας ή να χρησιμοποιήσετε ένα **εργαλείο όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τα εκτελέσετε όλα**.

_Σημειώστε ότι τα εργαλεία που προσπαθούν να εκτελέσουν ολόκληρη τη βάση δεδομένων μέσω του κανονικού Google browser δεν θα ολοκληρώσουν ποτέ, καθώς η Google θα σας αποκλείσει πολύ σύντομα._

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα leaked** credentials ή API tokens, είναι μια πολύ εύκολη επιτυχία.

## Ευπάθειες σε Public Code

Αν διαπιστώσετε ότι η εταιρεία διαθέτει **open-source code**, μπορείτε να το **αναλύσετε** και να αναζητήσετε **ευπάθειες** σε αυτό.

**Ανάλογα με τη γλώσσα**, υπάρχουν διαφορετικά **εργαλεία** που μπορείτε να χρησιμοποιήσετε· δείτε τη λίστα [εργαλείων ελέγχου source code](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν υπηρεσίες που σας επιτρέπουν να **σαρώσετε δημόσια repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Μεθοδολογία Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των ευπαθειών** που εντοπίζουν οι bug hunters βρίσκεται μέσα σε **web applications**, οπότε σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία ελέγχου web applications**. Μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική αναφορά στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρόλο που δεν θα πρέπει να περιμένετε να εντοπίσουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για την ενσωμάτωσή τους σε **workflows, ώστε να λαμβάνετε κάποιες αρχικές πληροφορίες για το web.**

## Ανακεφαλαίωση

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη ολοκληρώσει **όλη τη βασική enumeration**. Ναι, είναι βασική, επειδή μπορεί να γίνει πολύ περισσότερη enumeration (θα δούμε περισσότερα κόλπα αργότερα).

Έχετε ήδη:

1. Εντοπίσει όλες τις **εταιρείες** που περιλαμβάνονται στο scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και εκτελέσει κάποιο vuln scan, αν περιλαμβάνεται στο scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Εντοπίσει όλες τις **IPs** (από **CDNs** και **όχι από CDNs**) που περιλαμβάνονται στο scope.
6. Εντοπίσει όλους τους **web servers** και τραβήξει ένα **στιγμιότυπο οθόνης** από καθέναν (υπάρχει κάτι περίεργο που αξίζει να εξεταστεί καλύτερα;)
7. Εντοπίσει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. **Emails**, **credential leaks** και **secret leaks** που θα μπορούσαν να σας οδηγήσουν σε **μεγάλη επιτυχία πολύ εύκολα**.
9. **Κάνει Pentesting σε όλους τους ιστότοπους που βρήκατε**

## **Εργαλεία αυτοματοποίησης Full Recon**

Υπάρχουν αρκετά εργαλεία που εκτελούν μέρος των προτεινόμενων ενεργειών για ένα συγκεκριμένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και δεν έχει ενημερωθεί



## References

- [1] [Jason Haddix – Η μεθοδολογία του Bug Hunter v4.0: Έκδοση Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Για τα Favicons: Από τα εικονίδια του browser στην ευφυΐα της επιφάνειας επίθεσης](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Αξιοποίηση του favicon.ico για BugBounties, OSINT και πολλά άλλα](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ανακάλυψη Domains μέσω επίθεσης χρονικής συσχέτισης στο Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Παθητικό takeover: Αποκάλυψη (και προσομοίωση) μιας ακριβής καμπάνιας Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Μια μοναδική μέθοδος enumeration subdomain](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Πλήρης ροή εργασίας ανακάλυψης subdomain, Μέρος 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Πλήρης ανακάλυψη subdomain με brute force μέσω αυτοματοποιημένης ροής εργασίας Trickest, Μέρος 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Στιγμιότυπο οθόνης εξόδου του favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
