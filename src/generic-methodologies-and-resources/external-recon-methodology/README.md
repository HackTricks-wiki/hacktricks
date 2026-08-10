# Μεθοδολογία External Recon

## Ανακαλύψεις Assets

> Σου είπαν λοιπόν ότι όλα όσα ανήκουν σε κάποια εταιρεία βρίσκονται μέσα στο scope και θέλεις να выясσεις τι κατέχει πραγματικά αυτή η εταιρεία.

Ο στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **assets** αυτών των εταιρειών. Για να το κάνουμε αυτό, θα:

1. Εντοπίσουμε τις acquisitions της κύριας εταιρείας, κάτι που θα μας δώσει τις εταιρείες που βρίσκονται μέσα στο scope.
2. Εντοπίσουμε το ASN (αν υπάρχει) κάθε εταιρείας, κάτι που θα μας δώσει τα IP ranges που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε reverse whois lookups για να αναζητήσουμε άλλες εγγραφές (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει recursively).
4. Χρησιμοποιήσουμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το `ssl` trick μπορεί να γίνει recursively).

### **Acquisitions**

Πρώτα απ' όλα, πρέπει να γνωρίζουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφτούμε το [https://www.crunchbase.com/](https://www.crunchbase.com), να κάνουμε **search** για την **κύρια εταιρεία** και να κάνουμε **click** στο "**acquisitions**". Εκεί θα δούμε άλλες εταιρείες που αποκτήθηκαν από την κύρια.\
Μια άλλη επιλογή είναι να επισκεφτούμε τη σελίδα **Wikipedia** της κύριας εταιρείας και να αναζητήσουμε **acquisitions**.\
Για δημόσιες εταιρείες, ελέγξτε τα **SEC/EDGAR filings**, τις σελίδες **investor relations** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμια εταιρικά δέντρα και subsidiaries, δοκιμάστε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζεις όλες τις εταιρείες που βρίσκονται μέσα στο scope. Ας δούμε πώς μπορούμε να βρούμε τα assets τους.

### **ASNs**

Ένας autonomous system number (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **autonomous system** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** **IP addresses** τα οποία έχουν μια σαφώς καθορισμένη πολιτική για την πρόσβαση σε εξωτερικά δίκτυα και διαχειρίζονται από έναν μόνο οργανισμό, αλλά μπορεί να αποτελούνται από πολλούς operators.

Είναι ενδιαφέρον να βρούμε αν η **εταιρεία έχει εκχωρημένο κάποιο ASN**, ώστε να εντοπίσουμε τα **IP ranges** της. Θα ήταν χρήσιμο να πραγματοποιήσουμε **vulnerability test** σε όλους τους **hosts** μέσα στο **scope** και να **αναζητήσουμε domains** μέσα σε αυτά τα IPs.\
Μπορείς να κάνεις **search** με βάση το **όνομα** της εταιρείας, το **IP** ή το **domain** στα [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή της εταιρείας, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Σε κάθε περίπτωση, πιθανότατα όλες οι** χρήσιμες πληροφορίες **(IP ranges και Whois)** εμφανίζονται ήδη στον πρώτο σύνδεσμο.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, η enumeration του [**BBOT**](https://github.com/blacklanternsecurity/bbot) συγκεντρώνει και συνοψίζει αυτόματα τα ASNs στο τέλος του scan.
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
Μπορείτε να βρείτε τα IP ranges ενός οργανισμού χρησιμοποιώντας επίσης το [http://asnlookup.com/](http://asnlookup.com) (διαθέτει free API).\
Μπορείτε να βρείτε το IP και το ASN ενός domain χρησιμοποιώντας το [http://ipv4info.com/](http://ipv4info.com).

### **Αναζήτηση vulnerabilities**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets μέσα στο scope**, επομένως, αν επιτρέπεται, μπορείτε να εκτελέσετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, μπορείτε να εκτελέσετε [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε services όπως** τα Shodan, Censys ή ZoomEye **για να βρείτε** ανοιχτές ports **και, ανάλογα με όσα βρείτε, θα πρέπει να** ανατρέξετε σε αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορα πιθανά services που εκτελούνται.\
**Επίσης, αξίζει να αναφερθεί ότι μπορείτε να προετοιμάσετε** λίστες με default usernames **και** passwords **και να προσπαθήσετε να κάνετε** bruteforce σε services με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες μέσα στο scope και τα assets τους· τώρα είναι ώρα να βρούμε τα domains μέσα στο scope.

_Παρακαλούμε σημειώστε ότι με τις παρακάτω προτεινόμενες τεχνικές μπορείτε επίσης να βρείτε subdomains και ότι αυτές οι πληροφορίες δεν θα πρέπει να υποτιμώνται._

Αρχικά, θα πρέπει να αναζητήσετε το **κύριο domain**(s) κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλα τα IP ranges των domains, μπορείτε να επιχειρήσετε να εκτελέσετε **reverse dns lookups** σε αυτά τα **IPs για να βρείτε περισσότερα domains μέσα στο scope**. Προσπαθήστε να χρησιμοποιήσετε κάποιο dns server του victim ή κάποιο ευρέως γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο διαχειριστής πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online εργαλείο για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλα ranges, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του enrichment.

### **Reverse Whois (loop)**

Σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα οργανισμού**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Ακόμη πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **reverse whois lookups χρησιμοποιώντας οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλα whois registries όπου εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Δωρεάν** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Δωρεάν**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Δωρεάν**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Δωρεάν**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Δωρεάν** στο web, όχι δωρεάν API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Όχι δωρεάν
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Όχι δωρεάν (μόνο **100 δωρεάν** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Όχι δωρεάν
- [https://securitytrails.com/](https://securitytrails.com/) - Όχι δωρεάν (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Όχι δωρεάν (API)

Μπορείτε να αυτοματοποιήσετε αυτή την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτεί API key του whoxy).\
Μπορείτε επίσης να εκτελέσετε automatic reverse whois discovery με το [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτή την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** **διαχειρίζονται από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε αρκετές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να κάνετε αναζητήσεις με βάση αυτούς τους trackers και άλλα στοιχεία:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (βρίσκει related sites βάσει κοινών analytics/trackers)

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε related domains και subdomains του στόχου μας αναζητώντας το ίδιο favicon icon hash; Αυτό ακριβώς κάνει το εργαλείο [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), το οποίο δημιουργήθηκε από τον [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς να το χρησιμοποιήσετε:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Με απλά λόγια, το favihash θα μας επιτρέψει να εντοπίσουμε domains που έχουν το ίδιο favicon icon hash με τον στόχο μας.

Χρησιμοποιήστε ένα γνωστό favicon hash ως pivot στο Shodan ή το FOFA, για να βρείτε άλλα εκτεθειμένα instances της ίδιας τεχνολογίας.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Έτσι μπορείτε να **υπολογίσετε το favicon hash** ενός ιστοτόπου (MMH3 πάνω στα **base64-encoded** bytes του favicon):
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

Αντιμετωπίζετε τα favicon fingerprints ως ενδείξεις και τα επικυρώνετε με surrounding signals.<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίζετε το hash ως indicator, όχι ως proof**: Το MMH3 είναι compact· collisions, reused icons και deliberate spoofing είναι πιθανά.
- **Κάνετε probe σε περισσότερα από** `/favicon.ico`: ελέγχετε framework/build paths, manifest files, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs και HTML `<link rel="icon">` tags.
- **Τα static assets μπορεί να παραμένουν reachable πίσω από ελέγχους WAF/SSO/IdP**: κάνετε request το icon απευθείας και ελέγχετε τα `ETag`, `Last-Modified`, redirects και cache headers.
- **Επικυρώνετε τα matches με surrounding signals**: συγκρίνετε τον τίτλο, το HTML/body hash, τα headers, τα TLS certificate subjects/SANs, τα product components και τα exposed ports.
- **Κάνετε cluster ανά HTML/body hash**: ένα consistent template ενισχύει το fingerprint· mixed templates υποδεικνύουν generic ή shared icon.
- **Αντιμετωπίζετε ένα hash που εμφανίζεται σε unrelated signatures, ports και products ως πιθανό honeypot ή placeholder.**
- **Σε ambiguous targets, συγκρίνετε μια πραγματική σελίδα με ένα nonexistent path**, όπως `/_favicon_probe_<8-hex>`· matching hosting ή parking responses μπορεί να εξηγούν το shared icon.
- **Κάνετε bootstrap το triage από Nuclei detection rules ή public datasets** που αντιστοιχίζουν favicon hashes σε products και CPEs.
- **Θυμάστε το IP-centric coverage gap**: επιφάνειες πίσω από CDN, με SNI routing, anycast και domain-only επιφάνειες μπορεί να λείπουν από datasets τύπου Shodan.

### **Copyright / Uniq string**

Αναζητήστε μέσα στις web pages **strings που θα μπορούσαν να είναι shared μεταξύ διαφορετικών webs στον ίδιο οργανισμό**. Το **copyright string** θα μπορούσε να είναι ένα καλό παράδειγμα. Στη συνέχεια αναζητήστε αυτό το string στο **google**, σε άλλους **browsers** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
για την ταυτόχρονη ανανέωση όλων των certificates σε έναν server. Η συσχέτιση των timestamps των certificates ή των θέσεων στα certificate-transparency logs μπορεί να αποκαλύψει related domains.<sup>[[6]](#references)</sup>

Χρησιμοποιήστε επίσης απευθείας τα logs του **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Μπορείτε να χρησιμοποιήσετε ένα web όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα tool όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες dmarc**.\
Άλλα χρήσιμα tools είναι τα [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ένα εγκαταλελειμμένο A record μπορεί να γίνει προσβάσιμο όταν ένας cloud provider επαναassignάρει μια IP. Η έρευνα που αναφέρεται παρουσιάζει ένα opportunistic workflow που κάνει provision ένα instance και συσχετίζει τη διεύθυνσή του με passive DNS data· δοκιμάζετε takeover scenarios μόνο μέσα στο authorized scope.<sup>[[7]](#references)</sup>

### **Other ways**

**Shodan**

Όπως ήδη γνωρίζετε το όνομα του οργανισμού που κατέχει το IP space. Μπορείτε να κάνετε αναζήτηση με βάση αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τα hosts που βρέθηκαν για νέα, μη αναμενόμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας web σελίδας, να λάβετε το **Organisation name** και στη συνέχεια να αναζητήσετε αυτό το όνομα μέσα στα **TLS certificates** όλων των web σελίδων που είναι γνωστές από το **shodan**, με το filter: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα tool όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)είναι ένα tool που αναζητά **domains related** με ένα main domain και τα **subdomains** τους, πραγματικά εκπληκτικό.

**Passive DNS / Historical DNS**

Τα Passive DNS data είναι εξαιρετικά για την εύρεση **παλιών και ξεχασμένων records** που εξακολουθούν να κάνουν resolve ή μπορούν να γίνουν takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Ελέγξτε για κάποιο [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί κάποιο domain**, αλλά **έχασε την ιδιοκτησία του**. Απλώς κάντε register το (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε οποιοδήποτε **domain με διαφορετική IP** από αυτές που έχετε ήδη εντοπίσει στο assets discovery, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τα services που εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο κάποια tricks για να τα "attack"**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον client, οπότε δεν ανήκει στο scope· να είστε προσεκτικοί._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες που βρίσκονται στο scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλα τα πιθανά subdomains κάθε domain που εντοπίστηκε.

> [!TIP]
> Σημειώστε ότι ορισμένα από τα tools και τις τεχνικές για την εύρεση domains μπορούν επίσης να βοηθήσουν στην εύρεση subdomains

### **DNS**

Ας προσπαθήσουμε να λάβουμε **subdomains** από τα **DNS** records. Θα πρέπει επίσης να δοκιμάσουμε για **Zone Transfer** (αν είναι vulnerable, θα πρέπει να το αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο ταχύτερος τρόπος για να αποκτήσετε πολλά subdomains είναι να κάνετε αναζήτηση σε εξωτερικές πηγές. Τα πιο συχνά χρησιμοποιούμενα **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα, ρυθμίστε τα API keys):

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
Υπάρχουν **άλλα ενδιαφέροντα εργαλεία/API** που, παρότι δεν είναι άμεσα εξειδικευμένα στην εύρεση subdomains, θα μπορούσαν να είναι χρήσιμα για την εύρεση subdomains, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) δωρεάν API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για να εντοπίσει subdomains
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
- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστά URLs από τα AlienVault's Open Threat Exchange, Wayback Machine και Common Crawl για οποιοδήποτε δεδομένο domain.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Κάνουν scraping στον ιστό αναζητώντας αρχεία JS και εξάγουν subdomains από αυτά.
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
- Το [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με bug-bounty προγράμματα**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμη και να αποκτήσετε πρόσβαση στο scope που χρησιμοποιεί αυτό το project: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα tools εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains**, εκτελώντας brute force σε DNS servers χρησιμοποιώντας πιθανά ονόματα subdomains.

Για αυτή την ενέργεια θα χρειαστείτε ορισμένα **common subdomains wordlists, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Καθώς και IPs καλών DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε το: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο recommended tools για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο tool που εκτελούσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί μόνο 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε go, που σας επιτρέπει να απαριθμήσετε έγκυρα subdomains χρησιμοποιώντας active bruteforce, καθώς και να κάνετε resolve subdomains με διαχείριση wildcard και εύκολη υποστήριξη input-output.
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
### Δεύτερος γύρος DNS Brute-Force

Αφού εντοπίσετε subdomains χρησιμοποιώντας open sources και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρέθηκαν, ώστε να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Αρκετά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δεδομένων των domains και subdomains, δημιουργεί permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Δεδομένων των domains και subdomains, δημιουργεί permutations.
- Μπορείτε να βρείτε το **wordlist** των permutations του goaltdns [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Με δεδομένα τα domains και subdomains, δημιουργεί permutations. Αν δεν καθοριστεί αρχείο permutations, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία permutations για subdomains, μπορεί επίσης να προσπαθήσει να τα κάνει resolve (αλλά είναι προτιμότερο να χρησιμοποιήσετε τα προηγούμενα σχολιασμένα tools).
- Μπορείτε να βρείτε το **wordlist** των permutations του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για την εκτέλεση permutations, mutations και alteration των subdomains. Αυτό το εργαλείο θα κάνει brute force στο αποτέλεσμα (δεν υποστηρίζει DNS wildcard).
- Μπορείτε να βρείτε το dmut permutations wordlist [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί νέα πιθανά ονόματα subdomains** σύμφωνα με τα υποδεικνυόμενα patterns, για να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Δημιουργία έξυπνων permutations

- [**regulator**](https://github.com/cramppet/regulator): Μαθαίνει μοτίβα τύπου regex από τα subdomains που έχουν ανακαλυφθεί και δημιουργεί υποψήφια ονόματα για επίλυση.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** Το _subzuf_ είναι ένας **subdomain brute-force fuzzer** που συνδυάζεται με έναν εξαιρετικά απλό αλλά αποτελεσματικό **DNS response-guided algorithm**. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως ένα προσαρμοσμένο **wordlist** ή ιστορικά **DNS/TLS records**, για να συνθέτει με ακρίβεια περισσότερα αντίστοιχα **domain names** και να τα επεκτείνει ακόμη περισσότερο σε έναν βρόχο, με βάση τις πληροφορίες που συλλέγονται κατά τη διάρκεια του **DNS scan**.
```
echo www | subzuf facebook.com
```
### **Workflow Ανακάλυψης Subdomain**

Τα παραδείγματα workflow του Trickest συνδυάζουν OSINT, DNS brute force και στάδια permutation για επαναλήψιμη απαρίθμηση subdomain.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Αν βρήκατε μια διεύθυνση IP που περιέχει **μία ή περισσότερες web σελίδες** οι οποίες ανήκουν σε subdomains, μπορείτε να προσπαθήσετε να **βρείτε άλλα subdomains με webs σε αυτή την IP**, αναζητώντας σε **OSINT sources** domains που αντιστοιχούν σε μια IP ή κάνοντας **brute-forcing VHost domain names σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε ορισμένα **VHosts σε IPs χρησιμοποιώντας** το [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιο subdomain μπορεί να είναι κρυφό σε έναν web server, μπορείτε να προσπαθήσετε να το κάνετε brute force:

Για name-based vhosts, κάντε fuzz το `Host` header και χρησιμοποιήστε το auto-calibration του ffuf για να φιλτράρετε την προεπιλεγμένη απόκριση.<sup>[[2]](#references)</sup>
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
> Με αυτήν την τεχνική μπορεί ακόμη και να αποκτήσετε πρόσβαση σε internal/hidden endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί ένα έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να κάνετε abuse αυτής της συμπεριφοράς για να **ανακαλύψετε** νέα **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Κατά την αναζήτηση για **subdomains**, έχετε τον νου σας για να δείτε αν **pointing** σε οποιονδήποτε τύπο **bucket** και, σε αυτήν την περίπτωση, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains εντός του scope, προσπαθήστε να [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Παρακολούθηση**

Μπορείτε να **monitor** αν δημιουργούνται **new subdomains** ενός domain, παρακολουθώντας τα **Certificate Transparency** Logs, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση για vulnerabilities**

Ελέγξτε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρείτε οποιοδήποτε **subdomain with an IP different** από αυτά που βρήκατε ήδη κατά το assets discovery, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με το ποια services εκτελούνται, μπορείτε να βρείτε **σε αυτό το βιβλίο ορισμένα tricks για να τα "attack"**.\
_Σημειώστε ότι μερικές φορές το subdomain φιλοξενείται σε ένα IP που δεν ελέγχεται από τον client, επομένως δεν βρίσκεται εντός του scope· να είστε προσεκτικοί._

## IPs

Στα αρχικά βήματα ενδέχεται να έχετε **εντοπίσει ορισμένα IP ranges, domains και subdomains**.\
Ήρθε η ώρα να **συλλέξετε ξανά όλα τα IPs από αυτά τα ranges** και για τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας services από τα ακόλουθα **free apis**, μπορείτε επίσης να βρείτε **previous IPs used by domains and subdomains**. Αυτά τα IPs ενδέχεται να εξακολουθούν να ανήκουν στον client (και ενδέχεται να σας επιτρέψουν να βρείτε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να ελέγξετε για domains που δείχνουν σε μια συγκεκριμένη IP address χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση για vulnerabilities**

**Κάντε port scan σε όλα τα IPs που δεν ανήκουν σε CDNs** (καθώς είναι πολύ πιθανό να μη βρείτε κάτι ενδιαφέρον εκεί). Στα services που εντοπίστηκαν να εκτελούνται ενδέχεται να **μπορέσετε να βρείτε vulnerabilities**.

**Βρείτε έναν** [**guide**](../pentesting-network/index.html) **σχετικά με το πώς να κάνετε scan σε hosts.**

## Αναζήτηση web servers

> Έχουμε βρει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τα IP ranges, τα domains και τα subdomains εντός του scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη πραγματοποιήσει κάποιο **recon των IPs και των domains που εντοπίστηκαν**, επομένως μπορεί να έχετε **εντοπίσει ήδη όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, τώρα θα δούμε μερικά **γρήγορα tricks για την αναζήτηση web servers** εντός του scope.

Σημειώστε ότι αυτό θα είναι **προσανατολισμένο στο web apps discovery**, επομένως θα πρέπει να πραγματοποιήσετε επίσης **vulnerability** και **port scanning** (**αν επιτρέπεται** από το scope).

Μια **γρήγορη μέθοδος για τον εντοπισμό **ports open** που σχετίζονται με **web** servers, χρησιμοποιώντας το [**masscan** μπορεί να βρεθεί εδώ](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** το [**fprobe**](https://github.com/theblackturtle/fprobe) και το [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς δίνετε μια λίστα με domains και θα προσπαθήσει να συνδεθεί στη θύρα 80 (http) και 443 (https). Επιπλέον, μπορείτε να δηλώσετε την προσπάθεια σύνδεσης και σε άλλες θύρες:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Τώρα που ανακάλυψες **όλους τους web servers** που υπάρχουν στο scope (ανάμεσα στις **IPs** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν ξέρεις από πού να ξεκινήσεις**. Ας το κάνουμε λοιπόν απλό και ας ξεκινήσουμε παίρνοντας screenshots από όλους. Απλώς **ρίχνοντας μια ματιά** στην **κύρια σελίδα**, μπορείς να εντοπίσεις **περίεργα** endpoints που είναι περισσότερο **πιθανό** να είναι **ευάλωτα**.

Για να υλοποιήσεις την προτεινόμενη ιδέα, μπορείς να χρησιμοποιήσεις τα [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείς στη συνέχεια να χρησιμοποιήσεις το [**eyeballer**](https://github.com/BishopFox/eyeballer) πάνω σε όλα τα **screenshots**, ώστε να σου υποδείξει **τι είναι πιθανό να περιέχει vulnerabilities** και τι όχι.

## Public Cloud Assets

Για να εντοπίσεις πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει να **ξεκινήσεις με μια λίστα keywords που αναγνωρίζουν την εταιρεία**. Για παράδειγμα, για μια crypto εταιρεία μπορείς να χρησιμοποιήσεις λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείς επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις θα πρέπει να δημιουργήσεις **permutations** (δες το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τα wordlists που θα προκύψουν, μπορείς να χρησιμοποιήσεις εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάσαι ότι, όταν αναζητάς Cloud Assets, θα πρέπει να **ψάχνεις για περισσότερα από απλώς buckets στο AWS**.

### **Looking for vulnerabilities**

Αν εντοπίσεις πράγματα όπως **ανοιχτά buckets ή εκτεθειμένες cloud functions**, θα πρέπει να **αποκτήσεις πρόσβαση σε αυτά** και να προσπαθήσεις να δεις τι σου προσφέρουν και αν μπορείς να τα κάνεις abuse.

## Emails

Με τα **domains** και τα **subdomains** που βρίσκονται μέσα στο scope, έχεις ουσιαστικά όλα όσα **χρειάζεσαι για να ξεκινήσεις την αναζήτηση emails**. Αυτά είναι τα **APIs** και τα **tools** που έχουν λειτουργήσει καλύτερα για εμένα στην εύρεση emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (free version)
- API του [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API του [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Τα emails θα φανούν χρήσιμα αργότερα για **brute-force web logins και auth services** (όπως το SSH). Επίσης, είναι απαραίτητα για **phishings**. Επιπλέον, αυτά τα APIs θα σου δώσουν ακόμη περισσότερες **πληροφορίες για το άτομο** πίσω από το email, κάτι χρήσιμο για την phishing campaign.

## Credential Leaks

Με τα **domains,** **subdomains** και **emails**, μπορείς να ξεκινήσεις την αναζήτηση credentials που έχουν γίνει leak στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Αν βρεις **έγκυρα leaked** credentials, πρόκειται για μια πολύ εύκολη επιτυχία.

## Secrets Leaks

Τα credential leaks σχετίζονται με hacks εταιρειών, όπου **ευαίσθητες πληροφορίες διέρρευσαν και πουλήθηκαν**. Ωστόσο, οι εταιρείες μπορεί να επηρεάζονται από **άλλα leaks**, των οποίων οι πληροφορίες δεν υπάρχουν σε αυτές τις βάσεις δεδομένων:

### Github Leaks

Credentials και APIs μπορεί να έχουν γίνει leak στα **public repositories** της **εταιρείας** ή των **χρηστών** που εργάζονται για αυτή την εταιρεία στο github.\
Μπορείς να χρησιμοποιήσεις το **tool** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσεις** όλα τα **public repos** ενός **organization** και των **developers** του και να εκτελέσεις αυτόματα το [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω τους.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για την εκτέλεση του **gitleaks** σε όλο το **text** που παρέχεται μέσω **URLs που περνούν** σε αυτό, καθώς μερικές φορές και οι **web pages περιέχουν secrets**.

#### Github Dorks

Δες τη σελίδα [GitHub dorks and leaks](github-leaked-secrets.md) για πιθανά **GitHub dorks** προς αναζήτηση στο organization.

### Pastes Leaks

Μερικές φορές attackers ή απλοί εργαζόμενοι **δημοσιεύουν περιεχόμενο εταιρειών σε ένα paste site**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά είναι πολύ ενδιαφέρον να το αναζητήσεις.\
Μπορείς να χρησιμοποιήσεις το tool [**Pastos**](https://github.com/carlospolop/Pastos) για αναζήτηση σε περισσότερα από 80 paste sites ταυτόχρονα.

### Google Dorks

Τα παλιά αλλά πολύτιμα Google dorks είναι πάντα χρήσιμα για την εύρεση **εκτεθειμένων πληροφοριών που δεν θα έπρεπε να βρίσκονται εκεί**. Το μόνο πρόβλημα είναι ότι το [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανές queries που δεν μπορείς να εκτελέσεις χειροκίνητα. Έτσι, μπορείς να πάρεις τις αγαπημένες σου 10 ή να χρησιμοποιήσεις ένα **tool όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τις εκτελέσεις όλες**.

_Σημείωσε ότι τα tools που αναμένουν να εκτελέσουν ολόκληρη τη database χρησιμοποιώντας τον κανονικό Google browser δεν θα ολοκληρώσουν ποτέ, καθώς η Google θα σε μπλοκάρει πολύ σύντομα._

### **Looking for vulnerabilities**

Αν βρεις **έγκυρα leaked** credentials ή API tokens, πρόκειται για μια πολύ εύκολη επιτυχία.

## Public Code Vulnerabilities

Αν διαπίστωσες ότι η εταιρεία διαθέτει **open-source code**, μπορείς να το **αναλύσεις** και να αναζητήσεις **vulnerabilities** σε αυτό.

**Ανάλογα με τη γλώσσα**, υπάρχουν διαφορετικά **tools** που μπορείς να χρησιμοποιήσεις· δες τη λίστα με τα [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Υπάρχουν επίσης δωρεάν υπηρεσίες που σου επιτρέπουν να **σκανάρεις public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των vulnerabilities** που εντοπίζουν οι bug hunters βρίσκεται μέσα σε **web applications**, επομένως σε αυτό το σημείο θα ήθελα να μιλήσω για μια **web application testing methodology**, και μπορείς να [**βρεις αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική αναφορά στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρότι δεν θα πρέπει να περιμένεις να εντοπίσουν πολύ ευαίσθητα vulnerabilities, είναι χρήσιμα για την ενσωμάτωσή τους σε **workflows, ώστε να έχεις κάποιες αρχικές web πληροφορίες.**

## Recapitulation

> Συγχαρητήρια! Σε αυτό το σημείο έχεις ήδη ολοκληρώσει **όλο το βασικό enumeration**. Ναι, είναι βασικό, επειδή μπορεί να γίνει πολύ περισσότερο enumeration (θα δούμε περισσότερα tricks αργότερα).

Έχεις ήδη:

1. Εντοπίσει όλες τις **εταιρείες** μέσα στο scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και πραγματοποιήσει κάποιο vuln scan, αν περιλαμβάνεται στο scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει subdomain takeover;)
5. Εντοπίσει όλες τις **IPs** (από και **όχι από CDNs**) μέσα στο scope.
6. Εντοπίσει όλους τους **web servers** και πάρει ένα **screenshot** από αυτούς (υπάρχει κάτι περίεργο που αξίζει βαθύτερη εξέταση;)
7. Εντοπίσει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. Εντοπίσει **emails**, **credential leaks** και **secret leaks** που θα μπορούσαν να σου προσφέρουν ένα **μεγάλο κέρδος πολύ εύκολα**.
9. Πραγματοποιήσει **pentesting σε όλα τα webs που βρήκες**

## **Full Recon Automatic Tools**

Υπάρχουν αρκετά tools που πραγματοποιούν μέρος των προτεινόμενων ενεργειών απέναντι σε ένα δεδομένο scope.

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
{{#include ../../banners/hacktricks-training.md}}
