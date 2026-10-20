# Μεθοδολογία εξωτερικού recon

{{#include ../../banners/hacktricks-training.md}}

## Ανακάλυψη assets

> Σου είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία είναι εντός scope και θέλεις να μάθεις τι ακριβώς κατέχει αυτή η εταιρεία.

Στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και, στη συνέχεια, όλα τα **assets** αυτών των εταιρειών. Για να το πετύχουμε, θα:<sup>[[1]](#references)</sup>

1. Βρούμε τις εξαγορές της κύριας εταιρείας· αυτό θα μας δώσει τις εταιρείες που βρίσκονται εντός scope.
2. Βρούμε το ASN (αν υπάρχει) κάθε εταιρείας· αυτό θα μας δώσει τις περιοχές IP που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε αντίστροφες αναζητήσεις whois για να αναζητήσουμε άλλες εγγραφές (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη· αυτό μπορεί να γίνει αναδρομικά.
4. Χρησιμοποιήσουμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το κόλπο με το `ssl` μπορεί να εφαρμοστεί αναδρομικά).

### **Εξαγορές**

Πρώτα απ’ όλα, πρέπει να μάθουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφτείς το [https://www.crunchbase.com/](https://www.crunchbase.com), να **αναζητήσεις** την **κύρια εταιρεία** και να **κάνεις κλικ** στις "**acquisitions**". Εκεί θα δεις άλλες εταιρείες που εξαγοράστηκαν από την κύρια εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφτείς τη σελίδα της κύριας εταιρείας στη **Wikipedia** και να αναζητήσεις τις **εξαγορές**.\
Για εισηγμένες εταιρείες, έλεγξε τις καταθέσεις **SEC/EDGAR**, τις σελίδες **investor relations** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμια εταιρικά δέντρα και θυγατρικές, δοκίμασε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζεις όλες τις εταιρείες που βρίσκονται εντός scope. Ας δούμε πώς να βρούμε τα assets τους.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **αυτόνομο σύστημα** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** **διευθύνσεων IP** που έχουν σαφώς καθορισμένη πολιτική πρόσβασης σε εξωτερικά δίκτυα και διαχειρίζονται από έναν οργανισμό, αλλά ενδέχεται να αποτελούνται από πολλούς παρόχους.

Είναι χρήσιμο να βρούμε αν στην **εταιρεία έχει εκχωρηθεί κάποιο ASN**, ώστε να εντοπίσουμε τις **περιοχές IP** της. Θα ήταν χρήσιμο να πραγματοποιηθεί **vulnerability test** σε όλους τους **hosts** εντός **scope** και να **αναζητηθούν domains** μέσα σε αυτές τις IP.\
Μπορείς να **αναζητήσεις** με βάση το **όνομα** της εταιρείας, μια **IP** ή ένα **domain** στο [**https://bgp.he.net/**](https://bgp.he.net) **ή** στο [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή στην οποία βρίσκεται η εταιρεία, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη). Σε κάθε περίπτωση, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(περιοχές IP και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.

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

Μπορείτε επίσης να βρείτε τα εύρη IP ενός οργανισμού χρησιμοποιώντας το [ASNLookup](https://asnlookup.com/), το οποίο διαθέτει περιορισμένο δωρεάν επίπεδο API.

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets εντός του scope**, οπότε, αν έχετε την άδεια, μπορείτε να εκτελέσετε έναν **σαρωτή ευπαθειών** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να εκτελέσετε [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως οι** Shodan, Censys ή ZoomEye **για να εντοπίσετε** ανοιχτές θύρες **και, ανάλογα με όσα βρείτε, θα πρέπει να** ανατρέξετε σε αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορες πιθανές υπηρεσίες που εκτελούνται.\
**Επίσης, αξίζει να αναφέρουμε ότι μπορείτε να ετοιμάσετε λίστες με** προεπιλεγμένα ονόματα χρηστών **και** κωδικούς πρόσβασης **και να δοκιμάσετε να κάνετε** bruteforce σε υπηρεσίες με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Τομείς

> Γνωρίζουμε όλες τις εταιρείες εντός του scope και τα assets τους· ήρθε η ώρα να εντοπίσουμε τους τομείς εντός του scope.

_Σημειώστε ότι με τις τεχνικές που προτείνονται παρακάτω μπορείτε επίσης να βρείτε subdomains, και δεν πρέπει να υποτιμάτε αυτές τις πληροφορίες._

Αρχικά, θα πρέπει να αναζητήσετε τον/τους **κύριο/κύριους τομέα/τομείς** κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι ο _tesla.com_.

### **Reverse DNS**

Αφού εντοπίσατε όλα τα εύρη IP των τομέων, μπορείτε να δοκιμάσετε να κάνετε **reverse DNS lookups** σε αυτές τις **IP για να βρείτε περισσότερους τομείς εντός του scope**. Δοκιμάστε να χρησιμοποιήσετε κάποιον DNS server του στόχου ή κάποιον γνωστό DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

For να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε το [SecurityTrails](https://securitytrails.com/) για αυτές τις πληροφορίες, αν και τα ιστορικά δεδομένα DNS απαιτούν συνδρομή επί πληρωμή.\
Για μεγάλα εύρη, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των αντίστροφων αναζητήσεων και τον εμπλουτισμό των αποτελεσμάτων.

### **Reverse Whois (loop)**

Σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα οργανισμού**, **διεύθυνση**, **email**, αριθμούς τηλεφώνου... Ακόμα πιο ενδιαφέρον, όμως, είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **reverse whois lookups με βάση οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλες εγγραφές whois όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** web interface· API επί πληρωμή.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Επί πληρωμή
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Δεν είναι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Δεν είναι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Περιορισμένη δωρεάν πρόσβαση API για τρέχοντα DNS/subdomains· τα ιστορικά δεδομένα και οι reverse lookups απαιτούν συνδρομή επί πληρωμή.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 δωρεάν credits API κατά την εγγραφή· στη συνέχεια επί πληρωμή.

Μπορείτε να αυτοματοποιήσετε αυτή την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτείται κλειδί API whoxy).\
Μπορείτε επίσης να εκτελέσετε αυτόματη αναζήτηση reverse whois με το [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτή την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που εντοπίζετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που επιτρέπουν την αναζήτηση με βάση αυτούς τους trackers και άλλα στοιχεία:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Υπηρεσία web και API **επί πληρωμή** ([τιμολόγηση](https://www.stackscan.com/pricing))· προς το παρόν δεν διαφημίζεται δωρεάν πρόγραμμα. Αναζητήστε οποιοδήποτε asset που εξυπηρετείται, όχι μόνο tracker IDs: μια διαδρομή script, ένα self-hosted όνομα bundle ή τον host από τον οποίο φορτώνεται ένα asset, ώστε να εντοπίσετε κάθε site που το χρησιμοποιεί.

Το API επιστρέφει την τεχνολογική στοίβα ενός domain, κάτι που είναι χρήσιμο για να επιβεβαιώσετε ότι ένα πιθανό asset ανήκει στην ίδια υποδομή:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Επιστρέφει κάθε τεχνολογία που εντοπίζει μαζί με την κατηγορία της. Το asset pivoting είναι προς το παρόν διαθέσιμο μόνο για web, ενώ το API υποστηρίζει αναζήτηση ανά domain.

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε domains και subdomains που σχετίζονται με το target μας αναζητώντας το ίδιο favicon icon hash; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), που δημιούργησε ο [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς να το χρησιμοποιήσετε:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash μάς επιτρέπει να εντοπίσουμε domains που έχουν το ίδιο favicon icon hash με τον στόχο μας.

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Χρησιμοποιήστε ένα γνωστό favicon hash ως pivot στο Shodan ή στο FOFA για να εντοπίσετε άλλες εκτεθειμένες παρουσίες της ίδιας τεχνολογίας.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Έτσι μπορείτε να **υπολογίσετε το hash του favicon** μιας ιστοσελίδας (MMH3 πάνω στα **base64-encoded bytes** του favicon):

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

Αντιμετωπίστε τα fingerprints favicon ως ενδείξεις και επιβεβαιώστε τα με συμπληρωματικά σήματα.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίστε το hash ως ένδειξη, όχι ως απόδειξη**: το MMH3 είναι συμπαγές· είναι πιθανά τα collisions, η επαναχρησιμοποίηση εικονιδίων και η σκόπιμη παραποίηση.
- **Ελέγξτε περισσότερα από το** `/favicon.ico`: εξετάστε διαδρομές framework/build, αρχεία manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και HTML tags `<link rel="icon">`.
- **Τα static assets μπορεί να παραμένουν προσβάσιμα πίσω από ελέγχους WAF/SSO/IdP**: ζητήστε απευθείας το εικονίδιο και ελέγξτε τα `ETag`, `Last-Modified`, redirects και cache headers.
- **Επαληθεύστε τις αντιστοιχίες με συμπληρωματικά σήματα**: συγκρίνετε τον τίτλο, το hash HTML/body, τα headers, τα subjects/SANs του TLS certificate, τα product components και τις εκτεθειμένες θύρες.
- **Ομαδοποιήστε με βάση το hash HTML/body**: ένα συνεπές template ενισχύει το fingerprint· διαφορετικά templates υποδεικνύουν ένα γενικό ή κοινόχρηστο εικονίδιο.
- **Αντιμετωπίστε ένα hash που εμφανίζεται σε άσχετες υπογραφές, θύρες και προϊόντα ως πιθανό honeypot ή placeholder.**
- **Σε αμφίβολους στόχους, συγκρίνετε μια πραγματική σελίδα με μια ανύπαρκτη διαδρομή**, όπως `/_favicon_probe_<8-hex>`· οι ίδιες απαντήσεις φιλοξενίας ή στάθμευσης μπορεί να εξηγούν το κοινό εικονίδιο.
- **Ξεκινήστε την αρχική διαλογή με κανόνες ανίχνευσης του Nuclei ή δημόσια datasets** που αντιστοιχίζουν hashes favicon σε προϊόντα και CPEs.
- **Λάβετε υπόψη το κενό κάλυψης που οφείλεται στην εστίαση στις IP**: επιφάνειες πίσω από CDN, δρομολογημένες μέσω SNI, anycast και μόνο με domain ενδέχεται να απουσιάζουν από datasets τύπου Shodan.

### **Copyright / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που μπορεί να είναι κοινές σε διαφορετικούς ιστότοπους του ίδιου οργανισμού**. Η **συμβολοσειρά copyright** θα μπορούσε να είναι ένα καλό παράδειγμα. Έπειτα αναζητήστε τη συμβολοσειρά στο **google**, σε άλλους **περιηγητές** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **Ώρα CRT**

Είναι συνηθισμένο να υπάρχει μια cron job όπως η ακόλουθη:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

για την ταυτόχρονη ανανέωση όλων των πιστοποιητικών σε έναν server. Η συσχέτιση των χρονικών σημάνσεων των πιστοποιητικών ή των θέσεών τους στα certificate-transparency logs μπορεί να αποκαλύψει σχετικά domains.<sup>[[6]](#references)</sup>

Χρησιμοποιήστε επίσης απευθείας τα logs του **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), για να βρείτε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες DMARC**.\
Μια άλλη χρήσιμη υπηρεσία είναι το [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ένα εγκαταλελειμμένο A record μπορεί να γίνει προσβάσιμο όταν ένας cloud provider εκχωρήσει ξανά μια IP. Η έρευνα που παρατίθεται παρουσιάζει μια ευκαιριακή ροή εργασιών που δημιουργεί ένα instance και συσχετίζει τη διεύθυνσή του με δεδομένα passive DNS· δοκιμάζετε σενάρια takeover μόνο εντός του εγκεκριμένου πεδίου.<sup>[[7]](#references)</sup>

### **Άλλοι τρόποι**

Επαναλαμβάνετε τα κατάλληλα pivots ανακάλυψης κάθε φορά που βρίσκετε ένα νέο domain: κάθε αποτέλεσμα μπορεί να αποκαλύψει πρόσθετα ονόματα πιστοποιητικών, συσχετίσεις passive DNS, αντιστοιχίες favicon και αναγνωριστικά οργανισμών που δεν ήταν ορατά από το αρχικό seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Αφού γνωρίζετε ήδη το όνομα του οργανισμού στον οποίο ανήκει ο χώρος IP, μπορείτε να αναζητήσετε αυτά τα δεδομένα στο Shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους hosts που βρέθηκαν για νέα, μη αναμενόμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας ιστοσελίδας, να λάβετε το **Organisation name** και έπειτα να αναζητήσετε αυτό το όνομα στα **TLS certificates** όλων των ιστοσελίδων που γνωρίζει το **Shodan**, με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)είναι ένα εργαλείο που αναζητά **domains που σχετίζονται** με ένα κύριο domain και τα **subdomains** τους· είναι πραγματικά εκπληκτικό.

**Passive DNS / Ιστορικό DNS**

Τα δεδομένα Passive DNS είναι εξαιρετικά για την εύρεση **παλιών και ξεχασμένων records** που εξακολουθούν να επιλύονται ή μπορούν να γίνουν αντικείμενο takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Αναζήτηση ευπαθειών**

Ελέγξτε για [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί ένα domain**, αλλά **έχασε την ιδιοκτησία του**. Απλώς κατοχυρώστε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε οποιοδήποτε **domain με IP διαφορετική** από αυτές που εντοπίσατε ήδη κατά την ανακάλυψη assets, θα πρέπει να εκτελέσετε μια **βασική σάρωση ευπαθειών** (με Nessus ή OpenVAS) και κάποια [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο κάποια κόλπα για να τις «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη και επομένως είναι εκτός scope· προσέξτε._

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

Για APIs και πλατφόρμες που καλύπτουν υποδομές, φήμη, αρχεία παραβιάσεων και εμπλουτισμό πέρα από την ανακάλυψη subdomains, δείτε τον [κατάλογο των APIs για Reconnaissance και Threat Intelligence](reconnaissance-and-threat-intelligence-apis.md).

Ο πιο γρήγορος τρόπος για να βρείτε πολλά subdomains είναι να κάνετε αναζήτηση σε εξωτερικές πηγές. Τα εργαλεία που χρησιμοποιούνται περισσότερο είναι τα εξής (για καλύτερα αποτελέσματα, διαμορφώστε τα API keys):


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

Υπάρχουν **και άλλα ενδιαφέροντα εργαλεία/API** που, παρότι δεν εξειδικεύονται άμεσα στην εύρεση subdomains, θα μπορούσαν να φανούν χρήσιμα για τον εντοπισμό subdomains, όπως:

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

- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστά URL από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιοδήποτε domain.

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

- [**Εύρεση subdomain στο Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) προσφέρει περιορισμένη δωρεάν πρόσβαση στο API για τρέχοντα δεδομένα DNS και subdomains· για ιστορικά δεδομένα DNS/IP απαιτείται επί πληρωμή πρόγραμμα.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με προγράμματα bug-bounty**. Μπορείτε επίσης να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα μέσω του [chaospy](https://github.com/Moaaz-0x/chaospy) ή ακόμα και να δείτε το scope που χρησιμοποιεί αυτό το project: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Μπορείτε να βρείτε εδώ μια **σύγκριση** πολλών από αυτά τα εργαλεία: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** κάνοντας brute-force στους DNS servers με πιθανά ονόματα subdomain.

Για αυτή την ενέργεια θα χρειαστείτε μερικές **συνηθισμένες wordlists για subdomains, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Θα χρειαστείτε επίσης IPs αξιόπιστων DNS resolvers. Για να δημιουργήσετε μια λίστα με αξιόπιστους DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο προτεινόμενα εργαλεία για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, αλλά είναι επιρρεπές σε false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Νομίζω ότι αυτό χρησιμοποιεί μόνο 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα εργαλείο-περιτύλιγμα για το `massdns`, γραμμένο σε Go, που επιτρέπει την εύρεση έγκυρων subdomains με ενεργό bruteforce, καθώς και την επίλυση subdomains με χειρισμό wildcard και εύκολη υποστήριξη εισόδου-εξόδου.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Χρησιμοποιεί επίσης το `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί το asyncio για ασύγχρονο brute force σε ονόματα domain.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Δεύτερος γύρος DNS Brute-Force

Αφού εντοπίσετε subdomains από ανοικτές πηγές και με brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρήκατε, για να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Για αυτόν τον σκοπό είναι χρήσιμα διάφορα εργαλεία:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Δέχεται domains και subdomains και δημιουργεί μεταθέσεις.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Με δεδομένα τα domains και subdomains, δημιουργεί permutations.
  - Μπορείτε να βρείτε το **wordlist** για τα permutations του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Δεδομένων των domains και subdomains, δημιουργεί παραλλαγές. Αν δεν καθοριστεί αρχείο με παραλλαγές, το gotator θα χρησιμοποιήσει το δικό του.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία μεταθέσεων subdomains, μπορεί επίσης να προσπαθήσει να τα επιλύσει (αλλά είναι προτιμότερο να χρησιμοποιήσετε τα εργαλεία που αναφέρθηκαν προηγουμένως).
  - Μπορείτε να βρείτε **wordlist** με μεταθέσεις για το altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για την εκτέλεση permutations, mutations και τροποποιήσεων σε subdomains. Αυτό το εργαλείο κάνει brute force στα αποτελέσματα (δεν υποστηρίζει DNS wildcard).
  - Μπορείτε να βρείτε το wordlist permutations του dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί νέα πιθανά ονόματα subdomains** βάσει καθορισμένων μοτίβων, ώστε να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Δημιουργία έξυπνων permutations

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει μοτίβα τύπου regex από subdomains που έχουν ανακαλυφθεί και δημιουργεί υποψήφια ονόματα για επίλυση.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** Το _subzuf_ είναι ένα fuzzer brute-force υποτομέων, σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από τις απαντήσεις DNS. Αξιοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως μια προσαρμοσμένη wordlist ή ιστορικές εγγραφές DNS/TLS, για να συνθέτει με ακρίβεια περισσότερα αντίστοιχα ονόματα τομέων και να τα επεκτείνει ακόμη περισσότερο σε έναν βρόχο, με βάση τις πληροφορίες που συλλέγονται κατά τη σάρωση DNS.

```
echo www | subzuf facebook.com
```

### **Ροή εργασιών για την ανακάλυψη υποτομέων**

Τα παραδείγματα ροών εργασιών του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλήψιμη απαρίθμηση υποτομέων.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρείτε μια διεύθυνση IP που περιέχει **μία ή περισσότερες ιστοσελίδες** οι οποίες ανήκουν σε υποτομείς, μπορείτε να προσπαθήσετε να **βρείτε άλλους υποτομείς με ιστοσελίδες σε αυτήν την IP**, αναζητώντας σε **πηγές OSINT** domains που βρίσκονται σε μια IP ή κάνοντας **brute force ονομάτων domain VHost σε αυτήν την IP**.

#### OSINT

Μπορείτε να βρείτε ορισμένα **VHosts σε IP χρησιμοποιώντας το** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα API**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιος υποτομέας μπορεί να είναι κρυμμένος σε έναν web server, μπορείτε να δοκιμάσετε να κάνετε brute force:

Για vhosts που βασίζονται σε όνομα, κάντε fuzz το header `Host` και χρησιμοποιήστε το auto-calibration του ffuf για να φιλτράρετε την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>

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
> Με αυτήν την τεχνική ίσως μπορέσετε ακόμη και να αποκτήσετε πρόσβαση σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί ένα έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να καταχραστείτε αυτήν τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Καθώς αναζητάτε **subdomains**, προσέξτε αν κάποιο **δείχνει** σε κάποιο είδος **bucket** και, σε αυτή την περίπτωση, [**ελέγξτε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains εντός του scope, δοκιμάστε να [**κάνετε brute force σε πιθανά ονόματα bucket και να ελέγξετε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείτε να **παρακολουθείτε** αν δημιουργούνται **νέα subdomains** ενός domain, παρακολουθώντας τα **Certificate Transparency** Logs, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση ευπαθειών**

Ελέγξτε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**ελέγξτε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρείτε οποιοδήποτε **subdomain με IP διαφορετική** από αυτές που έχετε ήδη εντοπίσει κατά την ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το subdomain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη και επομένως είναι εκτός scope· προσέξτε._

## IPs

Στα αρχικά βήματα μπορεί να έχετε **εντοπίσει κάποιες περιοχές IP, domains και subdomains**.\
Ήρθε η ώρα να **συγκεντρώσετε όλες τις IPs από αυτές τις περιοχές**, καθώς και εκείνες των **domains/subdomains (μέσω DNS queries).**

Χρησιμοποιώντας υπηρεσίες όπως οι παρακάτω, μπορείτε επίσης να βρείτε **παλαιότερες IPs που χρησιμοποιούσαν domains και subdomains**. Αυτές οι IPs ενδέχεται να ανήκουν ακόμη στον πελάτη (και ίσως σας επιτρέψουν να εντοπίσετε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**SecurityTrails**](https://securitytrails.com/) (τα ιστορικά δεδομένα DNS/IP απαιτούν επί πληρωμή πρόγραμμα)

Μπορείτε επίσης να αναζητήσετε domains που δείχνουν σε συγκεκριμένη διεύθυνση IP με το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση ευπαθειών**

**Κάντε port scan σε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μη βρείτε εκεί κάτι ενδιαφέρον). Στις υπηρεσίες που εντοπίσατε ότι εκτελούνται, ίσως **καταφέρετε να βρείτε ευπάθειες**.

**Βρείτε έναν** [**οδηγό**](../pentesting-network/index.html) **για το πώς να σαρώσετε hosts.**

## Αναζήτηση web servers

> Έχουμε εντοπίσει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τις περιοχές IP, τα domains και τα subdomains εντός του scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη κάνει κάποιο **recon στις IPs και στα domains που εντοπίσατε**, επομένως ίσως **έχετε ήδη βρει όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, θα δούμε τώρα μερικά **γρήγορα κόλπα για την αναζήτηση web servers** εντός του scope.

Σημειώστε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, επομένως θα πρέπει επίσης να εκτελέσετε **vulnerability** και **port scanning** (**αν επιτρέπεται** από το scope).

Μια **γρήγορη μέθοδος** για να εντοπίσετε **ανοιχτές θύρες** που σχετίζονται με **web** servers, χρησιμοποιώντας [**masscan, βρίσκεται εδώ**](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** το [**fprobe**](https://github.com/theblackturtle/fprobe) και το [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς δίνετε μια λίστα με domains και θα προσπαθήσει να συνδεθεί στις θύρες 80 (http) και 443 (https). Επιπλέον, μπορείτε να ορίσετε να δοκιμάσει και άλλες θύρες:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Στιγμιότυπα οθόνης**

Τώρα που ανακαλύψατε **όλους τους web servers** που περιλαμβάνονται στο scope (ανάμεσα στις **IP** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν ξέρετε από πού να ξεκινήσετε**. Ας το απλοποιήσουμε, λοιπόν, ξεκινώντας απλώς με τη λήψη screenshots όλων τους. Αρκεί να **ρίξετε μια ματιά** στην **αρχική σελίδα** για να εντοπίσετε **περίεργα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να υλοποιήσετε την παραπάνω ιδέα, μπορείτε να χρησιμοποιήσετε τα [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείτε στη συνέχεια να χρησιμοποιήσετε το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να αναλύσετε όλα τα **screenshots** και να σας πει **ποια είναι πιθανό να περιέχουν ευπάθειες** και ποια όχι.

## Public Cloud Assets

Για να βρείτε πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει **να ξεκινήσετε με μια λίστα λέξεων-κλειδιών που προσδιορίζουν την εταιρεία**. Για παράδειγμα, για μια εταιρεία crypto μπορείτε να χρησιμοποιήσετε λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείτε επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις, θα πρέπει να δημιουργήσετε **permutations** (δείτε τον [**Δεύτερο γύρο DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τα wordlists που θα προκύψουν, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Όταν αναζητάτε Cloud Assets, να θυμάστε ότι πρέπει να **ψάχνετε και για άλλα πράγματα πέρα από τα buckets στο AWS**.

### **Αναζήτηση ευπαθειών**

Αν βρείτε πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει να **αποκτήσετε πρόσβαση σε αυτά** και να δείτε τι προσφέρουν και αν μπορείτε να τα εκμεταλλευτείτε.

## Emails

Με τα **domains** και τα **subdomains** που περιλαμβάνονται στο scope, έχετε ουσιαστικά όλα όσα **χρειάζεστε για να ξεκινήσετε την αναζήτηση emails**. Αυτά είναι τα **APIs** και τα **εργαλεία** που έχουν αποδώσει καλύτερα για μένα στην εύρεση emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
- API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
- API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση ευπαθειών**

Τα emails θα σας φανούν χρήσιμα αργότερα για **brute-force σε web logins και auth services** (όπως το SSH). Χρειάζονται επίσης για **phishing**. Επιπλέον, αυτά τα APIs θα σας δώσουν ακόμη περισσότερες **πληροφορίες για το άτομο** που βρίσκεται πίσω από το email, κάτι χρήσιμο για την καμπάνια phishing.

## Credential Leaks

Με τα **domains,** τα **subdomains** και τα **emails**, μπορείτε να ξεκινήσετε την αναζήτηση credentials που έχουν διαρρεύσει στο παρελθόν και ανήκουν σε αυτές τις διευθύνσεις email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα leaked** credentials, πρόκειται για μια πολύ εύκολη επιτυχία.

## Secrets Leaks

Τα credential leaks σχετίζονται με εταιρικά hacks, όπου **διέρρευσαν και πωλήθηκαν ευαίσθητες πληροφορίες**. Ωστόσο, οι εταιρείες μπορεί να έχουν επηρεαστεί και από **άλλα leaks**, των οποίων οι πληροφορίες δεν υπάρχουν σε αυτές τις βάσεις δεδομένων:

### Github Leaks

Credentials και APIs μπορεί να έχουν διαρρεύσει στα **public repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται σε αυτήν την εταιρεία github.\
Μπορείτε να χρησιμοποιήσετε το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσετε** όλα τα **public repos** ενός **organization** και των **developers** του και να εκτελέσετε αυτόματα το [**gitleaks**](https://github.com/gitleaks/gitleaks) σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για την εκτέλεση του **gitleaks** σε όλα τα **κείμενα** που παρέχονται μέσω **URLs που του μεταβιβάζονται**, καθώς μερικές φορές **και οι ιστοσελίδες περιέχουν secrets**.

#### Github Dorks

Δείτε τη σελίδα [GitHub dorks and leaks](github-leaked-secrets.md) για πιθανά **GitHub dorks** που μπορείτε να αναζητήσετε στον οργανισμό.

### Pastes Leaks

Μερικές φορές οι επιτιθέμενοι ή απλώς οι εργαζόμενοι **δημοσιεύουν εταιρικό περιεχόμενο σε έναν paste site**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά αξίζει πολύ να το αναζητήσετε.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για να κάνετε αναζήτηση σε περισσότερα από 80 paste sites ταυτόχρονα.

### Google Dorks

Τα παλιά αλλά δοκιμασμένα google dorks είναι πάντα χρήσιμα για την εύρεση **εκτεθειμένων πληροφοριών που δεν θα έπρεπε να βρίσκονται εκεί**. Το μόνο πρόβλημα είναι ότι το [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανά queries που δεν μπορείτε να εκτελέσετε χειροκίνητα. Επομένως, μπορείτε να επιλέξετε τα 10 αγαπημένα σας ή να χρησιμοποιήσετε ένα **εργαλείο όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τα εκτελέσετε όλα**.

_Σημειώστε ότι τα εργαλεία που επιχειρούν να εκτελέσουν ολόκληρη τη βάση δεδομένων μέσω του κανονικού browser του Google δεν θα τελειώσουν ποτέ, καθώς το Google θα σας μπλοκάρει πολύ γρήγορα._

### **Αναζήτηση ευπαθειών**

Αν βρείτε **έγκυρα leaked** credentials ή API tokens, πρόκειται για μια πολύ εύκολη επιτυχία.

## Public Code Vulnerabilities

Αν διαπιστώσετε ότι η εταιρεία διαθέτει **open-source code**, μπορείτε να τον **αναλύσετε** και να αναζητήσετε **ευπάθειες**.

**Ανάλογα με τη γλώσσα**, υπάρχουν διαφορετικά **εργαλεία** που μπορείτε να χρησιμοποιήσετε· δείτε τη λίστα με τα [εργαλεία code review](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν υπηρεσίες που σας επιτρέπουν να **σαρώσετε public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Μεθοδολογία Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των ευπαθειών** που εντοπίζουν οι bug hunters βρίσκεται μέσα σε **web applications**, επομένως σε αυτό το σημείο θα ήθελα να αναφερθώ σε μια **μεθοδολογία ελέγχου web applications**. Μπορείτε να [**βρείτε αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική μνεία στην ενότητα [**εργαλεία open source για αυτοματοποιημένους web scanners**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρόλο που δεν θα πρέπει να περιμένετε να εντοπίσουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για την ενσωμάτωσή τους σε **workflows, ώστε να συλλέξετε κάποιες αρχικές πληροφορίες για το web.**

## Recapitulation

> Συγχαρητήρια! Σε αυτό το σημείο έχετε ήδη ολοκληρώσει **όλο το βασικό enumeration**. Ναι, είναι βασικό, επειδή μπορεί να γίνει πολύ περισσότερο enumeration (θα δούμε περισσότερα κόλπα αργότερα).

Έχετε ήδη:

1. Εντοπίσει όλες τις **εταιρείες** που περιλαμβάνονται στο scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και πραγματοποιήσει κάποιο vuln scan, αν περιλαμβάνεται στο scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Εντοπίσει όλες τις **IP** (από και **εκτός CDN**) που περιλαμβάνονται στο scope.
6. Εντοπίσει όλους τους **web servers** και τραβήξει ένα **screenshot** τους (υπάρχει κάτι περίεργο που αξίζει να εξεταστεί πιο προσεκτικά;)
7. Εντοπίσει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. Βρει **emails**, **credential leaks** και **secret leaks** που θα μπορούσαν να σας προσφέρουν **μια μεγάλη επιτυχία με πολύ εύκολο τρόπο**.
9. Κάνει **Pentesting σε όλους τους ιστότοπους που εντοπίσατε**

## **Πλήρη εργαλεία αυτόματου Recon**

Υπάρχουν αρκετά εργαλεία που εκτελούν μέρος των προτεινόμενων ενεργειών σε ένα συγκεκριμένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Κάπως παλιό και δεν έχει ενημερωθεί

## References

- [1] [Jason Haddix – Η μεθοδολογία του Bug Hunter v4.0: Έκδοση Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Σχετικά με τα Favicons: Από τα εικονίδια browser έως την ευφυΐα επιφάνειας επίθεσης](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Αξιοποίηση του favicon.ico για BugBounties, OSINT και πολλά άλλα](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ανακάλυψη Domains μέσω μιας επίθεσης χρονικής συσχέτισης στο Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Παθητικό Takeover: Αποκάλυψη (και προσομοίωση) μιας ακριβής καμπάνιας Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Μια μοναδική μέθοδος απαρίθμησης Subdomain](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Πλήρης ροή εργασιών ανακάλυψης Subdomain, Μέρος 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Πλήρης ανακάλυψη Subdomain με Brute Force μέσω αυτοματοποιημένης ροής εργασιών Trickest, Μέρος 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot εξόδου του favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
