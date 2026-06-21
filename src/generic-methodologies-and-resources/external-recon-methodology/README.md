# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Ανακαλύψεις assets

> Άρα σου είπαν ότι ό,τι ανήκει σε κάποια εταιρεία είναι εντός του scope, και θέλεις να καταλάβεις τι πραγματικά κατέχει αυτή η εταιρεία.

Ο στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **companies owned by the main company** και μετά όλα τα **assets** αυτών των companies. Για να το πετύχουμε, θα κάνουμε τα εξής:

1. Θα βρούμε τις acquisitions της main company, αυτό θα μας δώσει τις companies μέσα στο scope.
2. Θα βρούμε το ASN (αν υπάρχει) κάθε company, αυτό θα μας δώσει τα IP ranges που ανήκουν σε κάθε company
3. Θα χρησιμοποιήσουμε reverse whois lookups για να ψάξουμε για άλλα entries (organisation names, domains...) που σχετίζονται με το πρώτο (αυτό μπορεί να γίνει αναδρομικά)
4. Θα χρησιμοποιήσουμε άλλες τεχνικές όπως shodan `org`and `ssl`filters για να ψάξουμε για άλλα assets (το `ssl` trick μπορεί να γίνει αναδρομικά).

### **Acquisitions**

Πρώτα απ’ όλα, πρέπει να ξέρουμε ποιες **other companies are owned by the main company**.\
Μια επιλογή είναι να επισκεφθείς το [https://www.crunchbase.com/](https://www.crunchbase.com), να **search** την **main company**, και να κάνεις **click** στο "**acquisitions**". Εκεί θα δεις άλλες companies που έχουν αποκτηθεί από τη main company.\
Άλλη επιλογή είναι να επισκεφθείς τη σελίδα **Wikipedia** της main company και να ψάξεις για **acquisitions**.\
Για δημόσιες εταιρείες, έλεγξε **SEC/EDGAR filings**, σελίδες **investor relations**, ή τοπικά corporate registries (π.χ. **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμια corporate trees και subsidiaries, δοκίμασε **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να ξέρεις όλες τις companies μέσα στο scope. Ας δούμε πώς θα βρούμε τα assets τους.

### **ASNs**

Ένας autonomous system number (**ASN**) είναι ένας **unique number** που αποδίδεται σε ένα **autonomous system** (AS) από το **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** από **IP addresses** τα οποία έχουν σαφώς ορισμένη πολιτική για πρόσβαση σε external networks και διαχειρίζονται από μία μόνο organisation, αλλά μπορεί να αποτελούνται από πολλούς operators.

Είναι ενδιαφέρον να βρεις αν η **company have assigned any ASN** για να εντοπίσεις τα **IP ranges** της. Θα ήταν χρήσιμο να πραγματοποιήσεις ένα **vulnerability test** σε όλους τους **hosts** μέσα στο **scope** και να **look for domains** μέσα σε αυτά τα IPs.\
Μπορείς να κάνεις **search** με βάση το **name** της company, το **IP** ή το **domain** στο [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή της company, αυτά τα links μπορεί να είναι χρήσιμα για να συγκεντρώσεις περισσότερα δεδομένα:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Σε κάθε περίπτωση, πιθανότατα όλες οι** useful information **(IP ranges and Whois)** εμφανίζονται ήδη στο πρώτο link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, το [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration συγκεντρώνει και συνοψίζει αυτόματα τα ASNs στο τέλος της σάρωσης.
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets μέσα στο scope**, οπότε αν επιτρέπεται, θα μπορούσες να εκτελέσεις κάποιον **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, θα μπορούσες να εκτελέσεις κάποια [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσεις services όπως** Shodan, Censys, ή ZoomEye **για να βρεις** open ports **και ανάλογα με το τι θα βρεις θα πρέπει** να ρίξεις μια ματιά σε αυτό το βιβλίο για το πώς να κάνεις pentest σε διάφορα πιθανά services που τρέχουν.\
**Επίσης, θα μπορούσε να αξίζει να αναφερθεί ότι μπορείς επίσης να προετοιμάσεις κάποιες** default username **και** passwords **λίστες και να προσπαθήσεις να** bruteforce services με [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες μέσα στο scope και τα assets τους, ήρθε η ώρα να βρούμε τα domains μέσα στο scope.

_Παρακαλώ, σημείωσε ότι στις παρακάτω προτεινόμενες τεχνικές μπορείς επίσης να βρεις subdomains και αυτή η πληροφορία δεν θα πρέπει να υποτιμάται._

Πρώτα απ’ όλα θα πρέπει να ψάξεις για το **main domain**(s) κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ θα είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχεις βρει όλα τα IP ranges των domains θα μπορούσες να προσπαθήσεις να κάνεις **reverse dns lookups** σε αυτά τα **IPs για να βρεις περισσότερα domains μέσα στο scope**. Δοκίμασε να χρησιμοποιήσεις κάποιο dns server του θύματος ή κάποιον γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο administrator πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείς επίσης να χρησιμοποιήσεις ένα online tool για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλα ranges, tools όπως [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για να αυτοματοποιήσεις reverse lookups και enrichment.

### **Reverse Whois (loop)**

Μέσα σε ένα **whois** μπορείς να βρεις πολλές ενδιαφέρουσες **information** όπως **organisation name**, **address**, **emails**, phone numbers... Αλλά αυτό που είναι ακόμα πιο ενδιαφέρον είναι ότι μπορείς να βρεις **περισσότερα assets related to the company** αν κάνεις **reverse whois lookups by any of those fields** (για παράδειγμα άλλα whois registries όπου εμφανίζεται το ίδιο email).\
Μπορείς να χρησιμοποιήσεις online tools όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, όχι free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (μόνο **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - not free (API)

Μπορείς να αυτοματοποιήσεις αυτή την εργασία χρησιμοποιώντας [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
Μπορείς επίσης να κάνεις κάποιο automatic reverse whois discovery με [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημείωσε ότι μπορείς να χρησιμοποιήσεις αυτή την technique για να ανακαλύπτεις περισσότερα domain names κάθε φορά που βρίσκεις ένα νέο domain.**

### **Trackers**

Αν βρεις το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες μπορείς να υποθέσεις ότι και οι **δύο σελίδες** είναι **managed by the same team**.\
Για παράδειγμα, αν δεις το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε πολλές σελίδες.

Υπάρχουν κάποιες σελίδες και tools που σου επιτρέπουν να ψάξεις με αυτά τα trackers και άλλα:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Ήξερες ότι μπορούμε να βρούμε related domains και subdomains στο target μας κοιτώντας το ίδιο favicon icon hash; Αυτό ακριβώς κάνει το tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) που δημιούργησε ο [@m4ll0k2](https://twitter.com/m4ll0k2). Δες πώς να το χρησιμοποιήσεις:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Απλά, το favihash θα μας επιτρέψει να ανακαλύψουμε domains που έχουν το ίδιο favicon icon hash με τον στόχο μας.

Επιπλέον, μπορείτε επίσης να αναζητήσετε τεχνολογίες χρησιμοποιώντας το favicon hash όπως εξηγείται σε [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Αυτό σημαίνει ότι αν γνωρίζετε το **hash του favicon μιας ευάλωτης έκδοσης μιας web tech** μπορείτε να ψάξετε στο shodan και να **βρείτε περισσότερα ευάλωτα σημεία**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Αυτός είναι ο τρόπος με τον οποίο μπορείτε να **υπολογίσετε το favicon hash** ενός web:
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
Μπορείς επίσης να πάρεις favicon hashes σε κλίμακα με [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και μετά να κάνεις pivot σε Shodan/Censys.

### **Copyright / Uniq string**

Αναζήτησε μέσα στις web pages **strings που θα μπορούσαν να μοιράζονται μεταξύ διαφορετικών webs στον ίδιο οργανισμό**. Το **copyright string** θα μπορούσε να είναι ένα καλό παράδειγμα. Έπειτα αναζήτησε εκείνο το string στο **google**, σε άλλους **browsers** ή ακόμα και στο **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. Αυτό σημαίνει ότι ακόμα κι αν η CA που χρησιμοποιείται γι’ αυτό δεν ορίζει τον χρόνο που δημιουργήθηκε στο χρόνο Validity, είναι δυνατό να **βρεθούν domains που ανήκουν στην ίδια εταιρεία στα certificate transparency logs**.\
Δείτε αυτό το [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Επίσης χρησιμοποιήστε απευθείας τα **certificate transparency** logs:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Μπορείτε να χρησιμοποιήσετε ένα web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ή ένα εργαλείο such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) για να βρείτε **domains and subdomain sharing the same dmarc information**.\
Άλλα χρήσιμα εργαλεία είναι τα [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Προφανώς είναι συνηθισμένο οι άνθρωποι να αντιστοιχούν subdomains σε IPs που ανήκουν σε cloud providers και κάποια στιγμή **χάνουν εκείνο το IP address αλλά ξεχνούν να αφαιρέσουν το DNS record**. Επομένως, απλώς **spawning a VM** σε ένα cloud (όπως Digital Ocean) θα **παίρνετε στην πραγματικότητα τον έλεγχο κάποιων subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) εξηγεί μια ιστορία about it και προτείνει ένα script που **spawns a VM in DigitalOcean**, **gets** το **IPv4** του νέου μηχανήματος, και **searches in Virustotal for subdomain records** που δείχνουν σε αυτό.

### **Other ways**

**Σημειώστε ότι μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

**Shodan**

Όπως ήδη ξέρετε το όνομα του οργανισμού που κατέχει το IP space. Μπορείτε να κάνετε αναζήτηση με αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τα hosts που βρέθηκαν για νέα απρόσμενα domains στο TLS certificate.

Θα μπορούσατε να αποκτήσετε το **TLS certificate** της κύριας web page, να πάρετε το **Organisation name** και μετά να αναζητήσετε αυτό το όνομα μέσα στα **TLS certificates** όλων των web pages που είναι γνωστές από το **shodan** με το φίλτρο : `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder)είναι ένα εργαλείο που αναζητά **domains related** με ένα main domain και τα **subdomains** τους, αρκετά εντυπωσιακό.

**Passive DNS / Historical DNS**

Τα δεδομένα passive DNS είναι εξαιρετικά για να βρείτε **old and forgotten records** που εξακολουθούν να επιλύονται ή που μπορούν να καταληφθούν. Δείτε τα:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Ελέγξτε για κάποιο [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία να **χρησιμοποιεί κάποιο domain** αλλά να **έχει χάσει την ownership**. Απλώς κάντε register it (αν είναι αρκετά φθηνό) και ενημερώστε την εταιρεία.

Αν βρείτε οποιοδήποτε **domain με IP διαφορετικό** από αυτά που ήδη βρήκατε στο assets discovery, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και ένα **port scan** με **nmap/masscan/shodan**. Ανάλογα με το ποιες υπηρεσίες τρέχουν μπορείτε να βρείτε σε **this book some tricks to "attack" them**.\
_Σημείωση ότι μερικές φορές το domain φιλοξενείται μέσα σε ένα IP που δεν ελέγχεται από τον client, οπότε δεν είναι μέσα στο scope, προσοχή._

## Subdomains

> Ξέρουμε όλες τις εταιρείες μέσα στο scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλα τα πιθανά subdomains κάθε domain που βρέθηκε.

> [!TIP]
> Σημειώστε ότι κάποια από τα εργαλεία και τις τεχνικές για να βρείτε domains μπορούν επίσης να βοηθήσουν να βρείτε subdomains

### **DNS**

Ας προσπαθήσουμε να πάρουμε **subdomains** από τα **DNS** records. Θα πρέπει επίσης να δοκιμάσουμε για **Zone Transfer** (Αν είναι ευάλωτο, θα πρέπει να το αναφέρετε).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο ταχύτερος τρόπος για να αποκτήσετε πολλά subdomains είναι να κάνετε αναζήτηση σε εξωτερικές πηγές. Τα πιο χρησιμοποιούμενα **tools** είναι τα ακόλουθα (για καλύτερα αποτελέσματα ρυθμίστε τα API keys):

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
Υπάρχουν **άλλα ενδιαφέροντα εργαλεία/APIs** που, ακόμη κι αν δεν είναι άμεσα εξειδικευμένα στην εύρεση subdomains, μπορεί να είναι χρήσιμα για να βρεις subdomains, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για να αποκτήσει subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** ανακτά γνωστά URLs από το Open Threat Exchange του AlienVault, το Wayback Machine και το Common Crawl για οποιοδήποτε δοσμένο domain.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Σαρώνουν το web αναζητώντας αρχεία JS και εξάγουν subdomains από αυτά.
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
- [**securitytrails.com**](https://securitytrails.com/) έχει ένα δωρεάν API για αναζήτηση subdomains και IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με bug-bounty programs**. Μπορείς να έχεις πρόσβαση σε αυτά τα δεδομένα επίσης χρησιμοποιώντας [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμα και να δεις το scope που χρησιμοποιεί αυτό το project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείς να βρεις μια **σύγκριση** πολλών από αυτά τα tools εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** κάνοντας brute-forcing σε DNS servers χρησιμοποιώντας πιθανά subdomain names.

Για αυτήν την ενέργεια θα χρειαστείς μερικές **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Και επίσης IPs από καλούς DNS resolvers. Για να δημιουργήσεις μια λίστα από trusted DNS resolvers μπορείς να κατεβάσεις τους resolvers από [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) και να χρησιμοποιήσεις [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρεις. Ή θα μπορούσες να χρησιμοποιήσεις: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο προτεινόμενα tools για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο tool που έκανε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί μόνο 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε go, που επιτρέπει να enumerate έγκυρα subdomains χρησιμοποιώντας active bruteforce, καθώς και να resolve subdomains με wildcard handling και εύκολη υποστήριξη input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Επίσης χρησιμοποιεί `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) χρησιμοποιεί asyncio για να κάνει brute force ονομάτων domain ασύγχρονα.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Δεύτερος Γύρος DNS Brute-Force

Αφού βρεθούν subdomains χρησιμοποιώντας ανοιχτές πηγές και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρέθηκαν για να προσπαθήσετε να βρείτε ακόμη περισσότερα. Αρκετά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Δεδομένων των domains και subdomains, δημιουργεί permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Δίνοντας τα domains και τα subdomains, δημιουργεί permutations.
- Μπορείς να πάρεις το **wordlist** των permutations του **goaltdns** [**εδώ**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Δεδομένων των domains και subdomains, δημιουργεί permutations. Αν δεν έχει οριστεί αρχείο permutations, το gotator θα χρησιμοποιήσει το δικό του.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από το να δημιουργεί permutations υποdomains, μπορεί επίσης να προσπαθήσει να τα επιλύσει (αλλά είναι καλύτερο να χρησιμοποιήσετε τα προηγούμενα σχολιασμένα tools).
- Μπορείτε να πάρετε το **wordlist** των permutations του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη εργαλείο για να πραγματοποιεί permutations, mutations και μεταβολές subdomains. Αυτό το εργαλείο θα κάνει brute force το αποτέλεσμα (δεν υποστηρίζει dns wild card).
- Μπορείτε να αποκτήσετε το dmut permutations wordlist [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **δημιουργεί νέα πιθανά ονόματα subdomains** βάσει καθορισμένων patterns για να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Για περισσότερες πληροφορίες διάβασε αυτό το [**post**](https://cramppet.github.io/regulator/index.html), αλλά βασικά θα πάρει τα **κύρια μέρη** από τα **discovered subdomains** και θα τα αναμείξει για να βρει περισσότερα subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ είναι ένα subdomain brute-force fuzzer σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από DNS απόκριση. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως ένα προσαρμοσμένο wordlist ή ιστορικά DNS/TLS records, για να συνθέτει με ακρίβεια περισσότερα αντίστοιχα domain names και να τα επεκτείνει ακόμη περισσότερο σε έναν βρόχο με βάση τις πληροφορίες που συλλέγονται κατά τη διάρκεια του DNS scan.
```
echo www | subzuf facebook.com
```
### **Ροή Εντοπισμού Subdomain**

Δες αυτό το blog post που έγραψα για το πώς να **αυτοματοποιήσεις το subdomain discovery** από ένα domain χρησιμοποιώντας **Trickest workflows** ώστε να μην χρειάζεται να εκκινώ χειροκίνητα ένα σωρό tools στον υπολογιστή μου:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Αν βρήκες ένα IP address που περιέχει **μία ή περισσότερες web pages** που ανήκουν σε subdomains, μπορείς να προσπαθήσεις να **βρεις άλλα subdomains με webs σε εκείνο το IP** κοιτάζοντας σε **OSINT sources** για domains σε ένα IP ή κάνοντας **brute-forcing VHost domain names σε εκείνο το IP**.

#### OSINT

Μπορείς να βρεις μερικά **VHosts σε IPs χρησιμοποιώντας** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεσαι ότι κάποιο subdomain μπορεί να είναι κρυμμένο σε έναν web server, μπορείς να δοκιμάσεις να το brute force:

Όταν το **IP ανακατευθύνει σε ένα hostname** (name-based vhosts), κάνε fuzz απευθείας το `Host` header και άφησε το ffuf να **auto-calibrate** ώστε να επισημάνει responses που διαφέρουν από το default vhost:
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
> Με αυτήν την τεχνική μπορείς ακόμη και να αποκτήσεις πρόσβαση σε εσωτερικά/κρυφά endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρεις σελίδες που επιστρέφουν μόνο το header _**Access-Control-Allow-Origin**_ όταν έχει οριστεί ένα έγκυρο domain/subdomain στο _**Origin**_ header. Σε αυτά τα σενάρια, μπορείς να εκμεταλλευτείς αυτή τη συμπεριφορά για να **ανακαλύψεις** νέα **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Κατά την αναζήτηση για **subdomains**, πρόσεχε αν κάποιο **δείχνει** σε οποιονδήποτε τύπο **bucket**, και σε αυτή την περίπτωση [**έλεγξε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, σε αυτό το σημείο θα γνωρίζεις όλα τα domains μέσα στο scope, οπότε δοκίμασε να [**brute force πιθανά bucket names και να ελέγξεις τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Μπορείς να **monitor** αν δημιουργούνται **νέα subdomains** ενός domain, παρακολουθώντας τα logs του **Certificate Transparency** όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Έλεγξε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**έλεγξε τα permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρεις οποιοδήποτε **subdomain με διαφορετικό IP** από αυτά που ήδη βρήκες στο assets discovery, θα πρέπει να κάνεις ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και ένα [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με το ποιες services τρέχουν, μπορείς να βρεις σε **αυτό το βιβλίο μερικά tricks για να τα "attack"**.\
_Σημείωση ότι μερικές φορές το subdomain φιλοξενείται μέσα σε ένα IP που δεν ελέγχεται από τον client, οπότε δεν είναι in the scope, πρόσεχε._

## IPs

Στα αρχικά βήματα μπορεί να έχεις **βρει κάποια IP ranges, domains και subdomains**.\
Ήρθε η ώρα να **συλλέξεις όλα τα IPs από αυτά τα ranges** και για τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας services από τα ακόλουθα **free apis** μπορείς επίσης να βρεις **προηγούμενα IPs που χρησιμοποιήθηκαν από domains και subdomains**. Αυτά τα IPs μπορεί να εξακολουθούν να ανήκουν στον client (και μπορεί να σου επιτρέψουν να βρεις [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείς επίσης να ελέγξεις για domains που δείχνουν σε μια συγκεκριμένη IP address χρησιμοποιώντας το tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Κάνε port scan όλα τα IPs που δεν ανήκουν σε CDNs** (καθώς πολύ πιθανό δεν θα βρεις κάτι ενδιαφέρον εκεί). Στα running services που θα εντοπιστούν, μπορεί να **είσαι σε θέση να βρεις vulnerabilities**.

**Βρες έναν** [**οδηγό**](../pentesting-network/index.html) **για το πώς να κάνεις scan hosts.**

## Web servers hunting

> Έχουμε βρει όλες τις companies και τα assets τους και ξέρουμε IP ranges, domains και subdomains μέσα στο scope. Ήρθε η ώρα να ψάξουμε για web servers.

Στα προηγούμενα βήματα πιθανότατα έχεις ήδη κάνει κάποιο **recon των IPs και domains που ανακαλύφθηκαν**, οπότε μπορεί να έχεις **ήδη βρει όλα τα πιθανά web servers**. Ωστόσο, αν δεν το έχεις κάνει, τώρα θα δούμε μερικά **γρήγορα tricks για να ψάξεις web servers** μέσα στο scope.

Παρακαλώ, σημείωσε ότι αυτό θα είναι **προσανατολισμένο στην ανακάλυψη web apps**, οπότε θα πρέπει να **κάνεις vulnerability** και **port scanning** επίσης (**αν επιτρέπεται** από το scope).

Ένας **γρήγορος τρόπος** για να ανακαλύψεις **open ports** σχετικούς με **web** servers χρησιμοποιώντας [**masscan** μπορεί να βρεθεί εδώ](../pentesting-network/index.html#http-port-discovery).\
Ένα άλλο φιλικό tool για να ψάξεις web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς περνάς μια λίστα από domains και θα προσπαθήσει να συνδεθεί στη port 80 (http) και 443 (https). Επιπλέον, μπορείς να ορίσεις να δοκιμάσει και άλλα ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Τώρα που έχεις ανακαλύψει **όλους τους web servers** που υπάρχουν στο scope (ανάμεσα στα **IPs** της εταιρείας και σε όλα τα **domains** και **subdomains**) πιθανότατα **δεν ξέρεις από πού να ξεκινήσεις**. Οπότε, ας το κάνουμε απλό και ας ξεκινήσουμε βγάζοντας screenshots από όλα αυτά. Μόνο με το να **ρίξεις μια ματιά** στην **κύρια σελίδα** μπορείς να βρεις **περίεργα** endpoints που είναι πιο **πιθανό** να είναι **ευάλωτα**.

Για να υλοποιήσεις την προτεινόμενη ιδέα μπορείς να χρησιμοποιήσεις [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, θα μπορούσες μετά να χρησιμοποιήσεις το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να τρέξεις όλα τα **screenshots** και να σου πει **ποιο είναι πιθανό να περιέχει vulnerabilities**, και ποιο όχι.

## Public Cloud Assets

Για να βρεις πιθανά cloud assets που ανήκουν σε μια εταιρεία θα πρέπει να **ξεκινήσεις με μια λίστα από keywords που αναγνωρίζουν αυτήν την εταιρεία**. Για παράδειγμα, για μια crypto εταιρεία μπορεί να χρησιμοποιήσεις λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείς επίσης wordlists με **συνηθισμένες λέξεις που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Έπειτα, με αυτές τις λέξεις θα πρέπει να δημιουργήσεις **permutations** (έλεγξε το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τις τελικές wordlists θα μπορούσες να χρησιμοποιήσεις εργαλεία όπως [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάσαι ότι όταν ψάχνεις για Cloud Assets θα πρέπει να ψάχνεις για κάτι περισσότερο από buckets στο AWS.

### **Looking for vulnerabilities**

Αν βρεις πράγματα όπως **open buckets ή cloud functions exposed** θα πρέπει να **τα προσπελάσεις** και να προσπαθήσεις να δεις τι σου προσφέρουν και αν μπορείς να τα καταχραστείς.

## Emails

Με τα **domains** και **subdomains** μέσα στο scope έχεις βασικά όλα όσα **χρειάζεσαι για να αρχίσεις να αναζητάς emails**. Αυτά είναι τα **APIs** και τα **tools** που μου έχουν δουλέψει καλύτερα για να βρω emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (free version)
- API του [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API του [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Τα emails θα φανούν χρήσιμα αργότερα για **brute-force web logins και auth services** (όπως το SSH). Επίσης, χρειάζονται για **phishings**. Επιπλέον, αυτά τα APIs θα σου δώσουν ακόμα περισσότερες **πληροφορίες για το άτομο** πίσω από το email, κάτι που είναι χρήσιμο για την phishing campaign.

## Credential Leaks

Με τα **domains,** **subdomains**, και **emails** μπορείς να αρχίσεις να ψάχνεις για credentials που έχουν leaked στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Αν βρεις **έγκυρα leaked** credentials, αυτό είναι ένα πολύ εύκολο win.

## Secrets Leaks

Τα credential leaks σχετίζονται με hacks εταιρειών όπου **ευαίσθητες πληροφορίες leaked και πουλήθηκαν**. Ωστόσο, οι εταιρείες μπορεί να επηρεάζονται και από **άλλα leaks** των οποίων οι πληροφορίες δεν βρίσκονται σε εκείνες τις βάσεις δεδομένων:

### Github Leaks

Credentials και APIs μπορεί να έχουν leaked στα **public repositories** της **εταιρείας** ή των **users** που εργάζονται σε εκείνη την github εταιρεία.\
Μπορείς να χρησιμοποιήσεις το **tool** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσεις** όλα τα **public repos** ενός **organization** και των **developers** του και να τρέξεις αυτόματα το [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω τους.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για να τρέξει το **gitleaks** agains όλα τα **text** που παρέχονται μέσω **URLs passed** σε αυτό, καθώς μερικές φορές οι **web pages also contains secrets**.

#### Github Dorks

Έλεγξε επίσης αυτή τη **σελίδα** για πιθανά **github dorks** που θα μπορούσες επίσης να αναζητήσεις στο organization που επιτίθεσαι:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Μερικές φορές attackers ή απλώς workers θα **δημοσιεύσουν company content σε ένα paste site**. Αυτό μπορεί να περιέχει ή να μη περιέχει **ευαίσθητες πληροφορίες**, αλλά αξίζει πολύ να το ψάξεις.\
Μπορείς να χρησιμοποιήσεις το tool [**Pastos**](https://github.com/carlospolop/Pastos) για να αναζητήσεις σε περισσότερα από 80 paste sites ταυτόχρονα.

### Google Dorks

Τα παλιά αλλά χρυσά google dorks είναι πάντα χρήσιμα για να βρεις **exposed information that shouldn't be there**. Το μόνο πρόβλημα είναι ότι η [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανές queries που δεν μπορείς να τρέξεις χειροκίνητα. Οπότε, μπορείς να πάρεις τα 10 αγαπημένα σου ή να χρησιμοποιήσεις ένα **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Σημείωσε ότι τα tools που περιμένουν να τρέξουν όλη τη database χρησιμοποιώντας τον κανονικό Google browser δεν θα τελειώσουν ποτέ, καθώς η google θα σε μπλοκάρει πολύ πολύ σύντομα._

### **Looking for vulnerabilities**

Αν βρεις **valid leaked** credentials ή API tokens, αυτό είναι ένα πολύ εύκολο win.

## Public Code Vulnerabilities

Αν βρήκες ότι η εταιρεία έχει **open-source code** μπορείς να το **αναλύσεις** και να ψάξεις για **vulnerabilities** σε αυτό.

**Ανάλογα με τη γλώσσα** υπάρχουν διαφορετικά **tools** που μπορείς να χρησιμοποιήσεις:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Υπάρχουν επίσης δωρεάν υπηρεσίες που επιτρέπουν να **σκανάρεις public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των vulnerabilities** που βρίσκουν οι bug hunters βρίσκεται μέσα σε **web applications**, οπότε σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία testing web applications**, και μπορείς να [**βρεις αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω μια ειδική αναφορά στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, αν και δεν πρέπει να περιμένεις ότι θα σου βρουν πολύ ευαίσθητα vulnerabilities, είναι χρήσιμα για να τα ενσωματώσεις σε **workflows ώστε να έχεις κάποια αρχική web information.**

## Recapitulation

> Συγχαρητήρια! Σε αυτό το σημείο έχεις ήδη πραγματοποιήσει **όλη τη βασική enumeration**. Ναι, είναι βασική επειδή μπορεί να γίνει πολύ περισσότερη enumeration (θα δούμε περισσότερα tricks αργότερα).

Οπότε έχεις ήδη:

1. Βρει όλες τις **companies** μέσα στο scope
2. Βρει όλα τα **assets** που ανήκουν στις companies (και να κάνεις κάποιο vuln scan αν είναι in scope)
3. Βρει όλα τα **domains** που ανήκουν στις companies
4. Βρει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover?)
5. Βρει όλα τα **IPs** (από και **όχι από CDNs**) μέσα στο scope.
6. Βρει όλους τους **web servers** και να τους έχεις βγάλει ένα **screenshot** (κάτι περίεργο που αξίζει πιο βαθύ έλεγχο?)
7. Βρει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. **Emails**, **credentials leaks**, και **secret leaks** που θα μπορούσαν να σου δώσουν ένα **μεγάλο win πολύ εύκολα**.
9. **Pentesting όλων των webs που βρήκες**

## **Full Recon Automatic Tools**

Υπάρχουν αρκετά tools εκεί έξω που θα εκτελέσουν μέρος των προτεινόμενων ενεργειών εναντίον ενός δεδομένου scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και όχι ενημερωμένο

## **References**

- Όλα τα δωρεάν courses του [**@Jhaddix**](https://twitter.com/Jhaddix) όπως το [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
