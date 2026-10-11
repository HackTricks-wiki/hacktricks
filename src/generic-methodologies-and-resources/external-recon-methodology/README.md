# Μεθοδολογία εξωτερικής αναγνώρισης

{{#include ../../banners/hacktricks-training.md}}

## Ανακάλυψη assets

> Σου είπαν ότι όλα όσα ανήκουν σε κάποια εταιρεία είναι εντός scope και θέλεις να εξακριβώσεις τι πραγματικά κατέχει αυτή η εταιρεία.

Στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και έπειτα όλα τα **assets** αυτών των εταιρειών. Για να το πετύχουμε, θα κάνουμε τα εξής:<sup>[[1]](#references)</sup>

1. Εντοπίζουμε τις εξαγορές της κύριας εταιρείας, ώστε να βρούμε τις εταιρείες που περιλαμβάνονται στο scope.
2. Εντοπίζουμε το ASN (αν υπάρχει) κάθε εταιρείας, ώστε να βρούμε τις περιοχές IP που της ανήκουν.
3. Χρησιμοποιούμε reverse whois lookups για να αναζητήσουμε άλλες εγγραφές (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει αναδρομικά).
4. Χρησιμοποιούμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το κόλπο με το `ssl` μπορεί να εφαρμοστεί αναδρομικά).

### **Εξαγορές**

Πρώτα απ’ όλα, πρέπει να μάθουμε **ποιες άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφτείς το [https://www.crunchbase.com/](https://www.crunchbase.com), να **αναζητήσεις** την **κύρια εταιρεία** και να **κάνεις κλικ** στο "**acquisitions**". Εκεί θα δεις άλλες εταιρείες που εξαγόρασε η κύρια εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφτείς τη σελίδα **Wikipedia** της κύριας εταιρείας και να αναζητήσεις τις **εξαγορές**.\
Για εισηγμένες εταιρείες, έλεγξε τις **καταχωρίσεις SEC/EDGAR**, τις σελίδες **investor relations** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για εταιρικές δομές και θυγατρικές σε παγκόσμιο επίπεδο, δοκίμασε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ωραία, σε αυτό το σημείο θα πρέπει να γνωρίζεις όλες τις εταιρείες που περιλαμβάνονται στο scope. Ας δούμε πώς μπορούμε να βρούμε τα assets τους.

### **ASNs**

Ένας αριθμός αυτόνομου συστήματος (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **αυτόνομο σύστημα** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **μπλοκ** **διευθύνσεων IP** με σαφώς καθορισμένη πολιτική πρόσβασης σε εξωτερικά δίκτυα και διαχειρίζεται από έναν οργανισμό, αλλά μπορεί να περιλαμβάνει αρκετούς παρόχους.

Είναι χρήσιμο να διαπιστώσουμε αν έχει εκχωρηθεί κάποιο **ASN στην εταιρεία**, ώστε να βρούμε τις **περιοχές IP της**. Θα ήταν χρήσιμο να γίνει **έλεγχος ευπαθειών** σε όλους τους **hosts** εντός του **scope** και να **αναζητηθούν domains** μέσα σε αυτές τις IP.\
Μπορείς να κάνεις **αναζήτηση** με βάση το **όνομα** της εταιρείας, μια **IP** ή ένα **domain** στο [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
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

Μπορείτε επίσης να βρείτε τα εύρη IP ενός οργανισμού μέσω του [http://asnlookup.com/](http://asnlookup.com) (διαθέτει δωρεάν API).\
Μπορείτε να βρείτε την IP και το ASN ενός domain μέσω του [http://ipv4info.com/](http://ipv4info.com).

### **Αναζήτηση ευπαθειών**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets εντός του scope**, επομένως, αν έχετε άδεια, μπορείτε να εκτελέσετε έναν **σαρωτή ευπαθειών** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να εκτελέσετε ορισμένα [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε υπηρεσίες όπως** Shodan, Censys ή ZoomEye **για να βρείτε** ανοιχτές θύρες **και, ανάλογα με όσα βρείτε, θα πρέπει να ανατρέξετε σε αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορες πιθανές υπηρεσίες που εκτελούνται.**\
**Επίσης, αξίζει να αναφέρουμε ότι μπορείτε να ετοιμάσετε λίστες με** προεπιλεγμένα ονόματα χρήστη **και** κωδικούς πρόσβασης **και να δοκιμάσετε να κάνετε** bruteforce σε υπηρεσίες με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες εντός του scope και τα assets τους· τώρα είναι ώρα να βρούμε τα domains εντός του scope.

_Σημειώστε ότι οι τεχνικές που προτείνονται παρακάτω μπορούν επίσης να εντοπίσουν subdomains, και δεν πρέπει να υποτιμάτε αυτή την πληροφορία._

Πρώτα απ’ όλα, θα πρέπει να αναζητήσετε το **κύριο domain**(s) κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλα τα εύρη IP των domains, μπορείτε να δοκιμάσετε να κάνετε **reverse dns lookups** σε αυτές τις **IP για να βρείτε περισσότερα domains εντός του scope**. Δοκιμάστε να χρησιμοποιήσετε κάποιον DNS server του θύματος ή κάποιον ευρέως γνωστό DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online εργαλείο για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλα ranges, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση reverse lookups και enrichment.

### **Reverse Whois (loop)**

Σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα οργανισμού**, **διεύθυνση**, **email**, αριθμούς τηλεφώνου... Ακόμα πιο ενδιαφέρον, όμως, είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **reverse whois lookups με βάση οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλα whois registries όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** μέσω web, όχι μέσω API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Δεν είναι δωρεάν
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Δεν είναι δωρεάν (μόνο **100 δωρεάν** αναζητήσεις)
- [https://www.domainiq.com/](https://www.domainiq.com) - Δεν είναι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Δεν είναι δωρεάν (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Δεν είναι δωρεάν (API)

Μπορείτε να αυτοματοποιήσετε αυτήν την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτείται κλειδί API του whoxy).\
Μπορείτε επίσης να εκτελέσετε αυτόματη ανακάλυψη reverse whois με το [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτήν την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που επιτρέπουν την αναζήτηση με βάση αυτούς τους trackers και άλλα στοιχεία:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (εντοπίζει σχετικά sites με βάση κοινά analytics/trackers)
- [**StackScan**](https://www.stackscan.com) - **Δωρεάν πακέτο** (Web και API). Κάντε pivot με βάση οποιοδήποτε asset παρέχεται, όχι μόνο με βάση tracker IDs: ένα script path, ένα όνομα self-hosted bundle ή τον host από τον οποίο φορτώνεται ένα asset, ώστε να εμφανιστούν όλα τα sites που το περιέχουν

Το API επιστρέφει το stack για ένα domain, κάτι που είναι χρήσιμο για να επιβεβαιώσετε ότι ένα υποψήφιο asset ανήκει στην ίδια υποδομή:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Επιστρέφει κάθε τεχνολογία που εντοπίστηκε μαζί με την κατηγορία της. Το asset pivoting είναι προς το παρόν διαθέσιμο μόνο για web, ενώ το API υποστηρίζει αναζήτηση ανά domain.

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε domains και subdomains που σχετίζονται με τον στόχο μας αναζητώντας το ίδιο hash εικονιδίου favicon; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), που δημιουργήθηκε από τον [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς να το χρησιμοποιήσετε:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Αποτελέσματα του Favihash που χρησιμοποιούνται για την ανακάλυψη domains με κοινό hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash μάς επιτρέπει να ανακαλύπτουμε domains που έχουν το ίδιο hash εικονιδίου favicon με τον στόχο μας.

![Έξοδος του favihash που χρησιμοποιείται για την ανακάλυψη domains με το ίδιο hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Χρησιμοποιήστε ένα γνωστό hash favicon ως pivot στο Shodan ή το FOFA, για να εντοπίσετε άλλες εκτεθειμένες παρουσίες της ίδιας τεχνολογίας.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Έτσι μπορείτε να **υπολογίσετε το hash του favicon** ενός ιστότοπου (MMH3 πάνω στα **base64-encoded bytes** του favicon):

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

Μπορείτε επίσης να συλλέξετε favicon hashes σε μεγάλη κλίμακα με το [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και στη συνέχεια να κάνετε pivot στο Shodan/Censys.

Αντιμετωπίστε τα favicon fingerprints ως ενδείξεις και επιβεβαιώστε τα με βάση τα γύρω σήματα.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίστε το hash ως ένδειξη, όχι ως απόδειξη**: το MMH3 είναι συμπαγές· είναι πιθανά τα collisions, η επαναχρησιμοποίηση icons και η σκόπιμη παραποίηση.
- **Ελέγξτε περισσότερα από το** `/favicon.ico`: εξετάστε paths framework/build, αρχεία manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και tags HTML `<link rel="icon">`.
- **Τα static assets μπορεί να παραμένουν προσβάσιμα πίσω από ελέγχους WAF/SSO/IdP**: ζητήστε απευθείας το icon και ελέγξτε τα `ETag`, `Last-Modified`, redirects και cache headers.
- **Επιβεβαιώστε τις αντιστοιχίες με βάση τα γύρω σήματα**: συγκρίνετε τον τίτλο, το hash HTML/body, τα headers, τα subjects/SANs του TLS certificate, τα product components και τις εκτεθειμένες θύρες.
- **Ομαδοποιήστε βάσει hash HTML/body**: ένα συνεπές template ενισχύει το fingerprint· τα μεικτά templates υποδηλώνουν ένα γενικό ή κοινόχρηστο icon.
- **Αντιμετωπίστε ένα hash που εμφανίζεται σε άσχετες υπογραφές, θύρες και προϊόντα ως πιθανό honeypot ή placeholder.**
- **Σε ασαφείς στόχους, συγκρίνετε μια πραγματική σελίδα με ένα ανύπαρκτο path**, όπως `/_favicon_probe_<8-hex>`· οι ίδιες αποκρίσεις φιλοξενίας ή parking μπορεί να εξηγούν το κοινό icon.
- **Ξεκινήστε το triage με κανόνες ανίχνευσης του Nuclei ή δημόσια datasets** που αντιστοιχίζουν favicon hashes σε προϊόντα και CPEs.
- **Λάβετε υπόψη το κενό κάλυψης που οφείλεται στην εστίαση στις IP**: επιφάνειες πίσω από CDN, με δρομολόγηση SNI, anycast και μόνο μέσω domain μπορεί να λείπουν από datasets τύπου Shodan.

### **Copyright / Μοναδική συμβολοσειρά**

Αναζητήστε μέσα στις ιστοσελίδες **συμβολοσειρές που θα μπορούσαν να είναι κοινές σε διαφορετικούς ιστοτόπους του ίδιου οργανισμού**. Η **συμβολοσειρά copyright** θα μπορούσε να είναι ένα καλό παράδειγμα. Στη συνέχεια, αναζητήστε αυτή τη συμβολοσειρά στο **google**, σε άλλα **browsers** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **Χρόνος CRT**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως το񎟿

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

για την ταυτόχρονη ανανέωση όλων των πιστοποιητικών σε έναν server. Η συσχέτιση των χρονικών σημείων των πιστοποιητικών ή των θέσεών τους στα logs certificate transparency μπορεί να αποκαλύψει σχετικά domains.<sup>[[6]](#references)</sup>

Χρησιμοποιήστε επίσης απευθείας τα logs **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε έναν ιστότοπο όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), για να εντοπίσετε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες DMARC**.\
Άλλα χρήσιμα εργαλεία είναι τα [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Μια εγκαταλελειμμένη εγγραφή A μπορεί να γίνει προσβάσιμη όταν ένας cloud provider εκχωρήσει ξανά μια IP. Η έρευνα που αναφέρεται παρουσιάζει μια opportunistic ροή εργασίας, η οποία δημιουργεί ένα instance και συσχετίζει τη διεύθυνσή του με δεδομένα passive DNS· δοκιμάζετε σενάρια takeover μόνο εντός του εξουσιοδοτημένου scope.<sup>[[7]](#references)</sup>

### **Άλλοι τρόποι**

Επαναλαμβάνετε τα κατάλληλα discovery pivots κάθε φορά που εντοπίζετε ένα νέο domain: κάθε αποτέλεσμα μπορεί να αποκαλύψει πρόσθετα ονόματα πιστοποιητικών, σχέσεις passive DNS, αντιστοιχίες favicon και αναγνωριστικά οργανισμών που δεν ήταν ορατά από το αρχικό seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Αφού γνωρίζετε ήδη το όνομα του οργανισμού στον οποίο ανήκει το IP space, μπορείτε να αναζητήσετε αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τους hosts που εντοπίστηκαν για νέα, μη αναμενόμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας ιστοσελίδας, να λάβετε το **Organisation name** και, στη συνέχεια, να αναζητήσετε αυτό το όνομα στα **TLS certificates** όλων των ιστοσελίδων που είναι γνωστές στο **shodan**, με το φίλτρο: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)είναι ένα εργαλείο που εντοπίζει **domains που σχετίζονται** με ένα κύριο domain και τα **subdomains** τους· είναι πραγματικά εντυπωσιακό.

**Passive DNS / Historical DNS**

Τα δεδομένα Passive DNS είναι εξαιρετικά χρήσιμα για τον εντοπισμό **παλιών και ξεχασμένων εγγραφών** που εξακολουθούν να επιλύονται ή μπορούν να γίνουν αντικείμενο takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Αναζήτηση ευπαθειών**

Ελέγξτε για [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί ένα domain**, αλλά **έχει χάσει την ιδιοκτησία του**. Απλώς κατοχυρώστε το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν εντοπίσετε κάποιο **domain με IP διαφορετική** από αυτές που βρήκατε ήδη στην ανακάλυψη assets, θα πρέπει να εκτελέσετε ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και ένα [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείτε»**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, οπότε δεν είναι εντός scope· προσέξτε._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες που περιλαμβάνονται στο scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να εντοπίσουμε όλα τα πιθανά subdomains κάθε domain που βρέθηκε.

> [!TIP]
> Σημειώστε ότι ορισμένα εργαλεία και τεχνικές για τον εντοπισμό domains μπορούν επίσης να βοηθήσουν στον εντοπισμό subdomains

### **DNS**

Ας προσπαθήσουμε να εντοπίσουμε **subdomains** από τις εγγραφές **DNS**. Θα πρέπει επίσης να δοκιμάσουμε το **Zone Transfer** (αν είναι ευάλωτο, θα πρέπει να το αναφέρετε).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Ο ταχύτερος τρόπος για να εντοπίσετε πολλούς υποτομείς είναι να αναζητήσετε πληροφορίες σε εξωτερικές πηγές. Τα **tools** που χρησιμοποιούνται περισσότερο είναι τα εξής (για καλύτερα αποτελέσματα, ρυθμίστε τα API keys):


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

Υπάρχουν **και άλλα ενδιαφέροντα εργαλεία/APIs** που, παρόλο που δεν εξειδικεύονται άμεσα στον εντοπισμό subdomains, θα μπορούσαν να είναι χρήσιμα για τον εντοπισμό τους, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) free API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για την εύρεση subdomains.

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

- [**gau**](https://github.com/lc/gau)**:** αντλεί γνωστές διευθύνσεις URL από το AlienVault's Open Threat Exchange, το Wayback Machine και το Common Crawl για οποιονδήποτε domain.

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

- [**securitytrails.com**](https://securitytrails.com/) διαθέτει δωρεάν API για αναζήτηση subdomains και ιστορικού IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με προγράμματα bug bounty**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμη και να αποκτήσετε πρόσβαση στο scope που χρησιμοποιεί αυτό το project: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα εργαλεία εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να εντοπίσουμε νέα **subdomains** κάνοντας brute-force στους DNS servers με πιθανά ονόματα subdomain.

Για αυτήν την ενέργεια θα χρειαστείτε μερικά **wordlists με συνηθισμένα subdomains, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Θα χρειαστείτε επίσης IPs αξιόπιστων DNS resolvers. Για να δημιουργήσετε μια λίστα έμπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα εργαλεία που συνιστώνται περισσότερο για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο εργαλείο που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, αλλά είναι επιρρεπές σε false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί απλώς 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε Go, που επιτρέπει την απαρίθμηση έγκυρων subdomains μέσω active brute force, καθώς και την επίλυση subdomains με χειρισμό wildcard και εύκολη υποστήριξη εισόδου-εξόδου.

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

### Δεύτερος γύρος DNS brute-force

Αφού εντοπίσετε subdomains μέσω ανοιχτών πηγών και brute-force, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρήκατε, για να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Για αυτόν τον σκοπό είναι χρήσιμα διάφορα εργαλεία:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δέχεται domains και subdomains και δημιουργεί permutations.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Δεδομένων των domains και subdomains, δημιουργεί permutations.
  - Μπορείτε να βρείτε το **wordlist** των permutations του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Με δεδομένα τα domains και subdomains, δημιουργεί παραλλαγές. Αν δεν οριστεί αρχείο παραλλαγών, το gotator θα χρησιμοποιήσει το δικό του.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία παραλλαγών υποτομέων, μπορεί επίσης να προσπαθήσει να τους επιλύσει (αλλά είναι προτιμότερο να χρησιμοποιήσετε τα εργαλεία που αναφέρθηκαν προηγουμένως).
  - Μπορείτε να βρείτε **wordlist** με παραλλαγές του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για permutations, mutations και τροποποιήσεις υποτομέων. Αυτό το εργαλείο θα κάνει brute force στο αποτέλεσμα (δεν υποστηρίζει DNS wildcard).
  - Μπορείτε να βρείτε τη λίστα λέξεων permutations του dmut [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί πιθανά ονόματα νέων subdomains** βάσει των μοτίβων που υποδεικνύονται, για να εντοπίσει περισσότερα subdomains.

#### Δημιουργία έξυπνων permutations

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει μοτίβα τύπου regex από τα subdomains που έχουν εντοπιστεί και δημιουργεί υποψήφια ονόματα προς επίλυση.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένας fuzzer brute-force υποτομέων, σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο που καθοδηγείται από τις αποκρίσεις DNS. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως μια προσαρμοσμένη wordlist ή ιστορικά αρχεία DNS/TLS, για να συνθέτει με ακρίβεια περισσότερα αντίστοιχα ονόματα domain και να τα επεκτείνει ακόμη περισσότερο σε έναν βρόχο, με βάση τις πληροφορίες που συλλέγονται κατά τη σάρωση DNS.

```
echo www | subzuf facebook.com
```

### **Ροή εργασίας για την ανακάλυψη υποτομέων**

Τα παραδείγματα ροών εργασίας του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλήψιμη απαρίθμηση υποτομέων.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρήκατε μια διεύθυνση IP που φιλοξενεί **μία ή περισσότερες ιστοσελίδες** οι οποίες ανήκουν σε υποτομείς, μπορείτε να προσπαθήσετε να **βρείτε άλλους υποτομείς με ιστοσελίδες σε αυτή την IP**, αναζητώντας **πηγές OSINT** για domains σε μια IP ή κάνοντας **brute force σε ονόματα domain VHost σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε ορισμένα **VHosts σε IP χρησιμοποιώντας το** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιος υποτομέας μπορεί να είναι κρυμμένος σε έναν web server, μπορείτε να δοκιμάσετε να κάνετε brute force:

Για vhosts που βασίζονται σε όνομα, κάντε fuzzing στην κεφαλίδα `Host` και χρησιμοποιήστε την αυτόματη βαθμονόμηση του ffuf για να φιλτράρετε την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>

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

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτές τις περιπτώσεις, μπορείτε να εκμεταλλευτείτε αυτήν τη συμπεριφορά για να **ανακαλύψετε** νέα **subdomains**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Κατά την αναζήτηση για **subdomains**, έχε τον νου σου για να δεις αν κάποιο **δείχνει** σε κάποιο είδος **bucket** και, αν ναι, [**έλεγξε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζεις όλα τα domains εντός του scope, δοκίμασε να [**κάνεις brute force σε πιθανά ονόματα bucket και να ελέγξεις τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείς να **παρακολουθείς** αν δημιουργούνται **νέα subdomains** ενός domain, παρακολουθώντας τα logs του **Certificate Transparency**, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση για vulnerabilities**

Έλεγξε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**έλεγξε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρεις κάποιο **subdomain με IP διαφορετικό** από αυτά που εντόπισες ήδη κατά την ανακάλυψη assets, θα πρέπει να κάνεις ένα **βασικό vulnerability scan** (με Nessus ή OpenVAS) και ένα [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείς να βρεις **σε αυτό το βιβλίο μερικά κόλπα για να τους «επιτεθείς»**.\
_Σημείωσε ότι μερικές φορές το subdomain φιλοξενείται σε IP που δεν ελέγχεται από τον πελάτη, επομένως δεν είναι εντός scope. Να είσαι προσεκτικός._

## IPs

Στα αρχικά βήματα μπορεί να έχεις **εντοπίσει κάποια ranges IP, domains και subdomains**.\
Ήρθε η ώρα να **συγκεντρώσεις όλες τις IPs από αυτά τα ranges** και από τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας υπηρεσίες από τα παρακάτω **δωρεάν APIs**, μπορείς επίσης να βρεις **IP addresses που χρησιμοποιούσαν παλαιότερα domains και subdomains**. Αυτές οι IPs μπορεί να ανήκουν ακόμα στον πελάτη (και να σου επιτρέψουν να εντοπίσεις [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείς επίσης να αναζητήσεις domains που δείχνουν σε μια συγκεκριμένη IP address, χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση για vulnerabilities**

Κάνε **port scan σε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μη βρεις εκεί κάτι ενδιαφέρον). Στις υπηρεσίες που εντοπίστηκαν να εκτελούνται μπορεί να **βρεις vulnerabilities**.

**Βρες έναν** [**οδηγό**](../pentesting-network/index.html) **για το πώς να κάνεις scan σε hosts.**

## Αναζήτηση web servers

> Έχουμε εντοπίσει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τα ranges IP, τα domains και τα subdomains που βρίσκονται εντός scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχεις ήδη κάνει **recon στις IPs και στα domains που εντοπίστηκαν**, επομένως μπορεί να έχεις **βρει ήδη όλους τους πιθανούς web servers**. Αν όχι, τώρα θα δούμε μερικά **γρήγορα κόλπα για να αναζητήσουμε web servers** εντός scope.

Σημείωσε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, επομένως θα πρέπει να κάνεις και **vulnerability scanning** και **port scanning** (**αν επιτρέπεται** από το scope).

Μια **γρήγορη μέθοδος** για τον εντοπισμό **ανοιχτών ports** που σχετίζονται με **web** servers, χρησιμοποιώντας [**masscan**, υπάρχει εδώ](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** το [**fprobe**](https://github.com/theblackturtle/fprobe) και το [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς δίνεις μια λίστα από domains και θα προσπαθήσει να συνδεθεί στις ports 80 (http) και 443 (https). Επιπλέον, μπορείς να ορίσεις να δοκιμάσει και άλλες ports:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Τώρα που ανακάλυψες **όλους τους web servers** που υπάρχουν εντός του scope (ανάμεσα στις **IP** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν ξέρεις από πού να ξεκινήσεις**. Ας το απλοποιήσουμε, λοιπόν, ξεκινώντας απλώς με τη λήψη screenshots όλων τους. Αρκεί να **ρίξεις μια ματιά** στην **κύρια σελίδα** για να εντοπίσεις **περίεργα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να υλοποιήσεις την παραπάνω ιδέα, μπορείς να χρησιμοποιήσεις τα [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείς στη συνέχεια να χρησιμοποιήσεις το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να εξετάσει όλα τα **screenshots** και να σου πει **ποια είναι πιθανό να περιέχουν ευπάθειες** και ποια όχι.

## Public Cloud Assets

Για να εντοπίσεις πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει να **ξεκινήσεις με μια λίστα λέξεων-κλειδιών που την προσδιορίζουν**. Για παράδειγμα, για μια εταιρεία crypto μπορείς να χρησιμοποιήσεις λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείς επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις, θα πρέπει να δημιουργήσεις **permutations** (δες τον [**δεύτερο γύρο DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τα wordlists που θα προκύψουν, μπορείς να χρησιμοποιήσεις εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Θυμήσου ότι όταν ψάχνεις για Cloud Assets, πρέπει να ψάχν**εις για κάτι περισσότερο από buckets στο AWS**.

### **Αναζήτηση για ευπάθειες**

Αν εντοπίσεις πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει να **αποκτήσεις πρόσβαση σε αυτά** και να δεις τι σου προσφέρουν και αν μπορείς να τα κάνεις abuse.

## Emails

Με τα **domains** και τα **subdomains** που περιλαμβάνονται στο scope έχεις ουσιαστικά όλα όσα **χρειάζεσαι για να αρχίσεις να αναζητάς emails**. Αυτά είναι τα **APIs** και τα **εργαλεία** που έχουν αποδειχθεί πιο αποτελεσματικά για την εύρεση εταιρικών emails:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (δωρεάν έκδοση)
- API του [**https://app.snov.io/**](https://app.snov.io/) (δωρεάν έκδοση)
- API του [**https://minelead.io/**](https://minelead.io/) (δωρεάν έκδοση)

### **Αναζήτηση για ευπάθειες**

Τα emails θα σου φανούν χρήσιμα αργότερα για **brute-force σε web logins και auth services** (όπως το SSH). Χρειάζονται επίσης για **phishing**. Επιπλέον, αυτά τα APIs θα σου δώσουν ακόμα περισσότερες **πληροφορίες για το άτομο** πίσω από το email, κάτι χρήσιμο για την phishing campaign.

## Credential Leaks

Με τα **domains,** τα **subdomains** και τα **emails**, μπορείς να αρχίσεις να ψάχνεις για credentials που διέρρευσαν στο παρελθόν και σχετίζονται με αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Αναζήτηση για ευπάθειες**

Αν βρεις **έγκυρα leaked** credentials, είναι πολύ εύκολο να πετύχεις μια νίκη.

## Secrets Leaks

Τα credential leaks σχετίζονται με hacks εταιρειών, κατά τα οποία **διέρρευσαν και πωλήθηκαν ευαίσθητες πληροφορίες**. Ωστόσο, οι εταιρείες μπορεί να επηρεάζονται και από **άλλα leaks**, των οποίων οι πληροφορίες δεν υπάρχουν σε αυτές τις βάσεις δεδομένων:

### Github Leaks

Credentials και APIs μπορεί να έχουν διαρρεύσει στα **public repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται σε αυτήν.\
Μπορείς να χρησιμοποιήσεις το **εργαλείο** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσεις** όλα τα **public repos** ενός **organization** και των **developers** του και να εκτελέσεις αυτόματα το [**gitleaks**](https://github.com/zricethezav/gitleaks) σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για να εκτελέσει το **gitleaks** σε όλα τα **text URLs** που του παρέχονται, καθώς μερικές φορές **και οι ιστοσελίδες περιέχουν secrets**.

#### Github Dorks

Δες τη σελίδα [GitHub dorks and leaks](github-leaked-secrets.md) για πιθανά **GitHub dorks** που μπορείς να χρησιμοποιήσεις για αναζήτηση στον οργανισμό.

### Pastes Leaks

Μερικές φορές, επιτιθέμενοι ή απλώς εργαζόμενοι **δημοσιεύουν εταιρικό περιεχόμενο σε κάποιο paste site**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά αξίζει πολύ να το αναζητήσεις.\
Μπορείς να χρησιμοποιήσεις το εργαλείο [**Pastos**](https://github.com/carlospolop/Pastos) για ταυτόχρονη αναζήτηση σε περισσότερα από 80 paste sites.

### Google Dorks

Τα παλιά αλλά δοκιμασμένα google dorks είναι πάντα χρήσιμα για να εντοπίζεις **εκτεθειμένες πληροφορίες που δεν θα έπρεπε να υπάρχουν εκεί**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανά queries, τα οποία δεν μπορείς να εκτελέσεις χειροκίνητα. Επομένως, μπορείς να επιλέξεις τα 10 αγαπημένα σου ή να χρησιμοποιήσεις ένα **εργαλείο όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τα εκτελέσεις όλα**.

_Σημείωσε ότι τα εργαλεία που επιχειρούν να εκτελέσουν ολόκληρη τη βάση δεδομένων μέσω του κανονικού Google browser δεν θα τελειώσουν ποτέ, καθώς η Google θα σε μπλοκάρει πολύ σύντομα._

### **Αναζήτηση για ευπάθειες**

Αν βρεις **έγκυρα leaked** credentials ή API tokens, είναι πολύ εύκολο να πετύχεις μια νίκη.

## Public Code Vulnerabilities

Αν ανακάλυψες ότι η εταιρεία διαθέτει **open-source code**, μπορείς να τον **αναλύσεις** και να αναζητήσεις **ευπάθειες**.

**Ανάλογα με τη γλώσσα**, υπάρχουν διαφορετικά **εργαλεία** που μπορείς να χρησιμοποιήσεις· δες τη λίστα με τα [εργαλεία ελέγχου source code](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν υπηρεσίες που σου επιτρέπουν να **σαρώσεις public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Μεθοδολογία Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των ευπαθειών** που βρίσκουν οι bug hunters βρίσκεται μέσα σε **web applications**, γι’ αυτό σε αυτό το σημείο θα ήθελα να αναφερθώ σε μια **μεθοδολογία ελέγχου web applications**. Μπορείς να [**βρεις αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική αναφορά στην ενότητα [**εργαλεία open source για Web Automated Scanners**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρότι δεν πρέπει να περιμένεις ότι θα εντοπίσουν πολύ ευαίσθητες ευπάθειες, είναι χρήσιμα για την ενσωμάτωσή τους σε **workflows ώστε να παρέχουν αρχικές πληροφορίες για το web.**

## Ανακεφαλαίωση

> Συγχαρητήρια! Σε αυτό το σημείο έχεις ήδη πραγματοποιήσει **όλη τη βασική αναγνώριση**. Ναι, είναι βασική, επειδή μπορεί να γίνει πολύ περισσότερη αναγνώριση (θα δούμε περισσότερα tricks αργότερα).

Έχεις ήδη:

1. Εντοπίσει όλες τις **εταιρείες** που περιλαμβάνονται στο scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και εκτελέσει κάποιο vuln scan, αν περιλαμβάνεται στο scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Εντοπίσει όλες τις **IP** (από και **εκτός CDN**) που περιλαμβάνονται στο scope.
6. Εντοπίσει όλους τους **web servers** και έχεις πάρει **screenshot** τους (υπάρχει κάτι περίεργο που αξίζει να εξετάσεις περαιτέρω;)
7. Εντοπίσει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. Βρει **emails**, **credential leaks** και **secret leaks** που θα μπορούσαν να σου δώσουν μια **μεγάλη νίκη πολύ εύκολα**.
9. Κάνει **pentesting σε όλα τα web sites που εντόπισες**

## **Πλήρως αυτοματοποιημένα εργαλεία Recon**

Υπάρχουν διάφορα εργαλεία που εκτελούν μέρος των προτεινόμενων ενεργειών σε ένα δεδομένο scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Κάπως παλιό και χωρίς ενημερώσεις

## References

- [1] [Jason Haddix – Η μεθοδολογία του Bug Hunter v4.0: Έκδοση Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Σχετικά με τα Favicons: Από τα εικονίδια browser στην ευφυΐα επιφάνειας επίθεσης](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Αξιοποίηση του favicon.ico για BugBounties, OSINT και πολλά άλλα](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Ανακάλυψη domains μέσω επίθεσης χρονικής συσχέτισης στο Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Παθητικό takeover: Αποκάλυψη (και προσομοίωση) μιας δαπανηρής καμπάνιας Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Μια μοναδική μέθοδος απαρίθμησης subdomains](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Πλήρης ροή εργασίας εντοπισμού subdomains, Μέρος 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Πλήρης αυτοματοποιημένη ανακάλυψη subdomains με brute force μέσω Trickest Workflow, Μέρος 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot εξόδου του favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
