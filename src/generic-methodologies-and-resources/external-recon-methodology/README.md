# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Ανακάλυψη assets

> Σας είπαν λοιπόν ότι όλα όσα ανήκουν σε κάποια εταιρεία βρίσκονται εντός scope και θέλετε να εντοπίσετε τι ακριβώς κατέχει αυτή η εταιρεία.

Ο στόχος αυτής της φάσης είναι να εντοπίσουμε όλες τις **εταιρείες που ανήκουν στην κύρια εταιρεία** και στη συνέχεια όλα τα **assets** αυτών των εταιρειών. Για να το κάνουμε αυτό, θα:

1. Εντοπίσουμε τις εξαγορές της κύριας εταιρείας, ώστε να βρούμε τις εταιρείες που βρίσκονται εντός scope.
2. Εντοπίσουμε το ASN (αν υπάρχει) κάθε εταιρείας, ώστε να βρούμε τα IP ranges που ανήκουν σε κάθε εταιρεία.
3. Χρησιμοποιήσουμε reverse whois lookups για να αναζητήσουμε άλλες εγγραφές (ονόματα οργανισμών, domains...) που σχετίζονται με την πρώτη (αυτό μπορεί να γίνει recursively).
4. Χρησιμοποιήσουμε άλλες τεχνικές, όπως τα φίλτρα `org` και `ssl` του shodan, για να αναζητήσουμε άλλα assets (το `ssl` trick μπορεί να γίνει recursively).

### **Εξαγορές**

Πρώτα απ' όλα, πρέπει να γνωρίζουμε ποιες **άλλες εταιρείες ανήκουν στην κύρια εταιρεία**.\
Μια επιλογή είναι να επισκεφθείτε το [https://www.crunchbase.com/](https://www.crunchbase.com), να κάνετε **search** για την **κύρια εταιρεία** και να κάνετε **click** στο "**acquisitions**". Εκεί θα δείτε άλλες εταιρείες που εξαγοράστηκαν από την κύρια εταιρεία.\
Μια άλλη επιλογή είναι να επισκεφθείτε τη σελίδα **Wikipedia** της κύριας εταιρείας και να αναζητήσετε **acquisitions**.\
Για δημόσιες εταιρείες, ελέγξτε τα **SEC/EDGAR filings**, τις σελίδες **investor relations** ή τα τοπικά εταιρικά μητρώα (π.χ. το **Companies House** στο Ηνωμένο Βασίλειο).\
Για παγκόσμια εταιρικά trees και subsidiaries, δοκιμάστε το **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) και τη βάση δεδομένων **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Εντάξει, σε αυτό το σημείο θα πρέπει να γνωρίζετε όλες τις εταιρείες που βρίσκονται εντός scope. Ας δούμε πώς μπορούμε να εντοπίσουμε τα assets τους.

### **ASNs**

Ένας autonomous system number (**ASN**) είναι ένας **μοναδικός αριθμός** που εκχωρείται σε ένα **autonomous system** (AS) από την **Internet Assigned Numbers Authority (IANA)**.\
Ένα **AS** αποτελείται από **blocks** **IP addresses**, τα οποία διαθέτουν μια σαφώς καθορισμένη policy για την πρόσβαση σε external networks και διαχειρίζονται από έναν μόνο οργανισμό, αλλά μπορεί να αποτελούνται από πολλούς operators.

Είναι ενδιαφέρον να ελέγξετε αν η **εταιρεία έχει εκχωρημένο κάποιο ASN**, ώστε να βρείτε τα **IP ranges** της. Θα ήταν χρήσιμο να εκτελέσετε ένα **vulnerability test** σε όλους τους **hosts** εντός του **scope** και να **αναζητήσετε domains** μέσα σε αυτά τα IPs.\
Μπορείτε να κάνετε **search** με βάση το **όνομα εταιρείας**, το **IP** ή το **domain** στο [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ή** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Ανάλογα με την περιοχή στην οποία βρίσκεται η εταιρεία, αυτοί οι σύνδεσμοι μπορεί να είναι χρήσιμοι για τη συλλογή περισσότερων δεδομένων:** [**AFRINIC**](https://www.afrinic.net) **(Αφρική),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Βόρεια Αμερική),** [**APNIC**](https://www.apnic.net) **(Ασία),** [**LACNIC**](https://www.lacnic.net) **(Λατινική Αμερική),** [**RIPE NCC**](https://www.ripe.net) **(Ευρώπη).** Σε κάθε περίπτωση, πιθανότατα όλες οι **χρήσιμες πληροφορίες** (**IP ranges** και **Whois**) εμφανίζονται ήδη στον πρώτο σύνδεσμο.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Επίσης, η enumeration του [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** συγκεντρώνει και συνοψίζει αυτόματα τα ASNs στο τέλος του scan.
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

### **Αναζήτηση για vulnerabilities**

Σε αυτό το σημείο γνωρίζουμε **όλα τα assets μέσα στο scope**, επομένως, αν επιτρέπεται, θα μπορούσατε να εκτελέσετε κάποιο **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) σε όλους τους hosts.\
Επίσης, θα μπορούσατε να εκτελέσετε ορισμένα [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ή να χρησιμοποιήσετε services όπως** τα Shodan, Censys ή ZoomEye **για να βρείτε** ανοιχτές θύρες **και, ανάλογα με όσα βρείτε, θα πρέπει να** ρίξετε μια ματιά σε αυτό το βιβλίο για το πώς να κάνετε pentest σε διάφορα πιθανά services που εκτελούνται.\
**Επίσης, αξίζει να αναφερθεί ότι μπορείτε να προετοιμάσετε** λίστες με default usernames **και** passwords **και να δοκιμάσετε να κάνετε** bruteforce σε services με το [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Γνωρίζουμε όλες τις εταιρείες μέσα στο scope και τα assets τους· ήρθε η ώρα να βρούμε τα domains μέσα στο scope.

_Σημειώστε ότι με τις τεχνικές που προτείνονται παρακάτω μπορείτε επίσης να βρείτε subdomains και ότι αυτές οι πληροφορίες δεν θα πρέπει να υποτιμηθούν._

Αρχικά, θα πρέπει να αναζητήσετε το **κύριο domain**(s) κάθε εταιρείας. Για παράδειγμα, για την _Tesla Inc._ είναι το _tesla.com_.

### **Reverse DNS**

Αφού έχετε βρει όλα τα IP ranges των domains, θα μπορούσατε να δοκιμάσετε να εκτελέσετε **reverse dns lookups** σε αυτά τα **IPs για να βρείτε περισσότερα domains μέσα στο scope**. Δοκιμάστε να χρησιμοποιήσετε κάποιον dns server του θύματος ή κάποιον γνωστό dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Για να λειτουργήσει αυτό, ο administrator πρέπει να ενεργοποιήσει χειροκίνητα το PTR.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα online tool για αυτές τις πληροφορίες: [http://ptrarchive.com/](http://ptrarchive.com).\
Για μεγάλα ranges, εργαλεία όπως τα [**massdns**](https://github.com/blechschmidt/massdns) και [**dnsx**](https://github.com/projectdiscovery/dnsx) είναι χρήσιμα για την αυτοματοποίηση των reverse lookups και του enrichment.

### **Reverse Whois (loop)**

Μέσα σε ένα **whois** μπορείτε να βρείτε πολλές ενδιαφέρουσες **πληροφορίες**, όπως **όνομα organisation**, **διεύθυνση**, **emails**, αριθμούς τηλεφώνου... Ακόμη πιο ενδιαφέρον είναι ότι μπορείτε να βρείτε **περισσότερα assets που σχετίζονται με την εταιρεία**, αν εκτελέσετε **reverse whois lookups χρησιμοποιώντας οποιοδήποτε από αυτά τα πεδία** (για παράδειγμα, άλλα whois registries στα οποία εμφανίζεται το ίδιο email).\
Μπορείτε να χρησιμοποιήσετε online εργαλεία όπως:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web και API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, όχι free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (μόνο **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Μπορείτε να αυτοματοποιήσετε αυτή την εργασία χρησιμοποιώντας το [**DomLink** ](https://github.com/vysecurity/DomLink)(απαιτείται ένα whoxy API key).\
Μπορείτε επίσης να εκτελέσετε automatic reverse whois discovery με το [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτή την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

### **Trackers**

Αν βρείτε το **ίδιο ID του ίδιου tracker** σε 2 διαφορετικές σελίδες, μπορείτε να υποθέσετε ότι **και οι δύο σελίδες** είναι **διαχειριζόμενες από την ίδια ομάδα**.\
Για παράδειγμα, αν δείτε το ίδιο **Google Analytics ID** ή το ίδιο **Adsense ID** σε πολλές σελίδες.

Υπάρχουν ορισμένες σελίδες και εργαλεία που σας επιτρέπουν να κάνετε αναζήτηση με βάση αυτά τα trackers και άλλα:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (βρίσκει related sites με βάση shared analytics/trackers)

### **Favicon**

Γνωρίζατε ότι μπορούμε να βρούμε related domains και subdomains του target μας αναζητώντας το ίδιο favicon icon hash; Αυτό ακριβώς κάνει το tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), το οποίο δημιουργήθηκε από τον [@m4ll0k2](https://twitter.com/m4ll0k2). Δείτε πώς να το χρησιμοποιήσετε:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - ανακάλυψη domains με το ίδιο favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Με απλά λόγια, το favihash μας επιτρέπει να ανακαλύψουμε domains που έχουν το ίδιο favicon icon hash με το target μας.

Επιπλέον, μπορείτε επίσης να αναζητήσετε technologies χρησιμοποιώντας το favicon hash, όπως εξηγείται σε [**αυτό το blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Αυτό σημαίνει ότι, αν γνωρίζετε το **hash του favicon μιας ευάλωτης έκδοσης ενός web tech**, μπορείτε να κάνετε αναζήτηση στο shodan και να **βρείτε περισσότερα ευάλωτα σημεία**:
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
Μπορείτε επίσης να βρείτε favicon hashes σε κλίμακα με το [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) και στη συνέχεια να κάνετε pivot σε Shodan/Censys.

Χρήσιμα πράγματα που πρέπει να θυμάστε όταν χρησιμοποιείτε favicon fingerprints:<sup>[[3]](#references)[[4]](#references)</sup>

- **Αντιμετωπίζετε το hash ως ένδειξη, όχι ως απόδειξη**: το MMH3 είναι compact και είναι πιθανές οι collisions. Οι operators μπορούν επίσης να αντικαταστήσουν τα favicons ή να επαναχρησιμοποιήσουν σκόπιμα ένα παραπλανητικό icon.
- **Κάντε probe σε περισσότερα από** `/favicon.ico`: πολλά products εκθέτουν icons σε framework/build paths ή μέσω των `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URLs ή HTML tags `<link rel="icon">`. Το ίδιο το path μπορεί να κάνει fingerprint μια product family.
- **Τα static files είναι συχνά προσβάσιμα όταν η app δεν είναι**: οι έλεγχοι WAF/SSO/IdP μπορεί να προστατεύουν τα dynamic routes, αλλά να εκθέτουν ακόμη τα static icons. Να ζητάτε πάντα απευθείας το favicon και να ελέγχετε τα `ETag`, `Last-Modified`, redirects και cache headers για αδύναμες ενδείξεις version/build.
- **Επικυρώνετε τα matches με surrounding signals**: συγκρίνετε title, HTML/body hash, headers, TLS certificate subjects/SANs, Shodan/Censys components και exposed ports πριν καταλήξετε ότι ένα favicon αναγνωρίζει ένα product.
- **Κάντε cluster ανά HTML/body hash όταν κάνετε pivot σε κλίμακα**: αν οι περισσότεροι hosts που μοιράζονται ένα favicon συγκλίνουν σε ένα page template, το fingerprint είναι ισχυρότερο. Αν το ίδιο hash διαχωρίζεται σε πολλά άσχετα templates, προτιμήστε το "generic/shared/honeypot" αντί για product label.
- **Honeypot heuristic**: αν το ίδιο favicon hash εμφανίζεται σε πολλά άσχετα HTML signatures, random ports και conflicting products, αντιμετωπίστε το ως πιθανό honeypot ή generic placeholder και όχι ως πραγματικό product fingerprint.
- **Χρησιμοποιείτε ένα 404 probe σε ambiguous targets**: κάντε fetch μια πραγματική σελίδα και ένα nonexistent path όπως `/_favicon_probe_<8-hex>` σε browser. Matching hosting-provider/parking responses συχνά εξηγούν τα shared favicons καλύτερα από ένα πραγματικό product overlap.
- **Κάντε bootstrap τα mappings από detection rules**: τα Nuclei templates και τα public favicon datasets μπορούν να παρέχουν γνωστά mappings `favicon` ↔ `product` ↔ `CPE`, τα οποία είναι χρήσιμα για γρήγορο triage μετά από CVE disclosures.
- **Coverage caveat**: τα Shodan-style datasets είναι IP-centric. Οι CDN-fronted, SNI-routed, anycast και domain-only surfaces μπορεί να υποκαταγράφονται, επομένως ένα χαμηλό hit count **δεν** σημαίνει χαμηλή deployment σε πραγματικές συνθήκες.

### **Copyright / Uniq string**

Αναζητήστε μέσα στις web pages **strings που θα μπορούσαν να είναι κοινά μεταξύ διαφορετικών webs στον ίδιο οργανισμό**. Το **copyright string** θα μπορούσε να είναι ένα καλό παράδειγμα. Στη συνέχεια αναζητήστε αυτό το string στο **google**, σε άλλους **browsers** ή ακόμη και στο **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Είναι συνηθισμένο να υπάρχει ένα cron job όπως
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
για την ανανέωση όλων των domain certificates στον server. Αυτό σημαίνει ότι, ακόμη και αν η CA που χρησιμοποιείται για αυτό δεν ορίζει τον χρόνο δημιουργίας στο πεδίο Validity, είναι δυνατό να **βρεθούν domains που ανήκουν στην ίδια εταιρεία στα certificate transparency logs**.\
Δείτε αυτό το [**writeup για περισσότερες πληροφορίες**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Χρησιμοποιήστε επίσης απευθείας τα logs του **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Πληροφορίες Mail DMARC

Μπορείτε να χρησιμοποιήσετε ένα web εργαλείο, όπως το [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), ή ένα εργαλείο, όπως το [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), για να βρείτε **domains και subdomains που μοιράζονται τις ίδιες πληροφορίες dmarc**.\
Άλλα χρήσιμα εργαλεία είναι τα [**spoofcheck**](https://github.com/BishopFox/spoofcheck) και [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparently είναι συνηθισμένο να αντιστοιχίζονται subdomains σε IPs που ανήκουν σε cloud providers και κάποια στιγμή να **χάνεται αυτή η IP address, χωρίς να αφαιρείται η DNS record**. Επομένως, απλώς **δημιουργώντας ένα VM** σε ένα cloud, όπως το Digital Ocean, ουσιαστικά θα **αναλάβετε τον έλεγχο κάποιων subdomains**.

[**Αυτή η ανάρτηση**](https://kmsec.uk/blog/passive-takeover/) εξηγεί μια ιστορία σχετικά με αυτό και προτείνει ένα script που **δημιουργεί ένα VM στο DigitalOcean**, **λαμβάνει** τη **IPv4** του νέου machine και **αναζητά στο Virustotal records subdomains** που δείχνουν σε αυτήν.

### **Άλλοι τρόποι**

**Σημειώστε ότι μπορείτε να χρησιμοποιείτε αυτή την τεχνική για να ανακαλύπτετε περισσότερα domain names κάθε φορά που βρίσκετε ένα νέο domain.**

**Shodan**

Όπως ήδη γνωρίζετε το όνομα του οργανισμού που κατέχει το IP space. Μπορείτε να αναζητήσετε με βάση αυτά τα δεδομένα στο shodan χρησιμοποιώντας: `org:"Tesla, Inc."` Ελέγξτε τα hosts που βρέθηκαν για νέα, μη αναμενόμενα domains στο TLS certificate.

Μπορείτε να αποκτήσετε πρόσβαση στο **TLS certificate** της κύριας web σελίδας, να λάβετε το **Organisation name** και στη συνέχεια να αναζητήσετε αυτό το όνομα μέσα στα **TLS certificates** όλων των web σελίδων που είναι γνωστές από το **shodan**, με το filter: `ssl:"Tesla Motors"` ή να χρησιμοποιήσετε ένα εργαλείο όπως το [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

Το [**Assetfinder** ](https://github.com/tomnomnom/assetfinder) είναι ένα εργαλείο που αναζητά **domains που σχετίζονται** με ένα κύριο domain και τα **subdomains** τους, πραγματικά εκπληκτικό.

**Passive DNS / Historical DNS**

Τα δεδομένα του Passive DNS είναι εξαιρετικά χρήσιμα για την εύρεση **παλιών και ξεχασμένων records** που εξακολουθούν να κάνουν resolve ή μπορούν να γίνουν takeover. Δείτε:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Αναζήτηση για vulnerabilities**

Ελέγξτε για κάποιο [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Ίσως κάποια εταιρεία **χρησιμοποιεί ένα domain**, αλλά **έχει χάσει την ιδιοκτησία του**. Απλώς καταχωρίστε το, αν είναι αρκετά φθηνό, και ενημερώστε την εταιρεία.

Αν βρείτε οποιοδήποτε **domain με διαφορετική IP** από αυτές που έχετε ήδη βρει κατά το assets discovery, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** χρησιμοποιώντας Nessus ή OpenVAS και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε σε **αυτό το βιβλίο ορισμένα tricks για να τις "επιτεθείτε"**.\
_Σημειώστε ότι μερικές φορές το domain φιλοξενείται σε IP που δεν ελέγχεται από τον client, επομένως δεν βρίσκεται στο scope· να είστε προσεκτικοί._

## Subdomains

> Γνωρίζουμε όλες τις εταιρείες που βρίσκονται στο scope, όλα τα assets κάθε εταιρείας και όλα τα domains που σχετίζονται με τις εταιρείες.

Ήρθε η ώρα να βρούμε όλα τα πιθανά subdomains κάθε domain που βρέθηκε.

> [!TIP]
> Σημειώστε ότι ορισμένα από τα εργαλεία και τις τεχνικές για την εύρεση domains μπορούν επίσης να βοηθήσουν στην εύρεση subdomains

### **DNS**

Ας προσπαθήσουμε να λάβουμε **subdomains** από τα **DNS** records. Θα πρέπει επίσης να δοκιμάσουμε το **Zone Transfer**. (Αν είναι vulnerable, θα πρέπει να το αναφέρετε.)
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Ο γρηγορότερος τρόπος για να αποκτήσετε πολλά subdomains είναι να κάνετε αναζήτηση σε εξωτερικές πηγές. Τα πιο συχνά χρησιμοποιούμενα **εργαλεία** είναι τα εξής (για καλύτερα αποτελέσματα, διαμορφώστε τα API keys):

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
Υπάρχουν **άλλα ενδιαφέροντα tools/APIs** που, παρόλο που δεν είναι εξειδικευμένα στην άμεση εύρεση subdomains, θα μπορούσαν να φανούν χρήσιμα για την εύρεση subdomains, όπως:

- [**IP.THC.ORG**](https://ip.thc.org) δωρεάν API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Χρησιμοποιεί το API [https://sonar.omnisint.io](https://sonar.omnisint.io) για την απόκτηση subdomains
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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Συλλέγουν δεδομένα από τον ιστό αναζητώντας αρχεία JS και εξάγουν subdomains από αυτά.
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
- [**securitytrails.com**](https://securitytrails.com/) διαθέτει ένα δωρεάν API για αναζήτηση subdomains και ιστορικού IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Αυτό το project προσφέρει **δωρεάν όλα τα subdomains που σχετίζονται με bug-bounty programs**. Μπορείτε να αποκτήσετε πρόσβαση σε αυτά τα δεδομένα και μέσω του [chaospy](https://github.com/dr-0x0x/chaospy) ή ακόμη και να αποκτήσετε πρόσβαση στο scope που χρησιμοποιεί αυτό το project: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Μπορείτε να βρείτε μια **σύγκριση** πολλών από αυτά τα tools εδώ: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Ας προσπαθήσουμε να βρούμε νέα **subdomains** εκτελώντας brute-force σε DNS servers, χρησιμοποιώντας πιθανά ονόματα subdomains.

Για αυτή την ενέργεια θα χρειαστείτε μερικά **common subdomains wordlists, όπως**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Καθώς και IPs καλών DNS resolvers. Για να δημιουργήσετε μια λίστα αξιόπιστων DNS resolvers, μπορείτε να κατεβάσετε τους resolvers από το [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) και να χρησιμοποιήσετε το [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) για να τους φιλτράρετε. Εναλλακτικά, μπορείτε να χρησιμοποιήσετε το: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Τα πιο προτεινόμενα tools για DNS brute-force είναι:

- [**massdns**](https://github.com/blechschmidt/massdns): Αυτό ήταν το πρώτο tool που εκτέλεσε αποτελεσματικό DNS brute-force. Είναι πολύ γρήγορο, ωστόσο είναι επιρρεπές σε false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Αυτό νομίζω ότι χρησιμοποιεί μόνο 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- Το [**shuffledns**](https://github.com/projectdiscovery/shuffledns) είναι ένα wrapper γύρω από το `massdns`, γραμμένο σε go, που σας επιτρέπει να απαριθμείτε έγκυρα subdomains χρησιμοποιώντας active bruteforce, καθώς και να κάνετε resolve subdomains με χειρισμό wildcard και εύκολη υποστήριξη input-output.
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

Αφού εντοπίσετε subdomains μέσω open sources και brute-forcing, μπορείτε να δημιουργήσετε παραλλαγές των subdomains που βρέθηκαν, ώστε να προσπαθήσετε να εντοπίσετε ακόμη περισσότερα. Αρκετά εργαλεία είναι χρήσιμα για αυτόν τον σκοπό:

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
- [**altdns**](https://github.com/infosec-au/altdns): Εκτός από τη δημιουργία permutations για subdomains, μπορεί επίσης να προσπαθήσει να τα επιλύσει (αλλά είναι καλύτερο να χρησιμοποιήσετε τα προηγουμένως σχολιασμένα tools).
- Μπορείτε να βρείτε το **wordlist** των permutations του altdns [**εδώ**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ένα ακόμη tool για την εκτέλεση permutations, mutations και alteration σε subdomains. Αυτό το tool θα κάνει brute force το αποτέλεσμα (δεν υποστηρίζει dns wild card).
- Μπορείτε να βρείτε το dmut permutations wordlist [**εδώ**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Με βάση ένα domain, **generates new potential subdomains names** σύμφωνα με τα υποδεικνυόμενα patterns, ώστε να προσπαθήσει να ανακαλύψει περισσότερα subdomains.

#### Έξυπνη δημιουργία permutations

- [**regulator**](https://github.com/cramppet/regulator): Για περισσότερες πληροφορίες, διαβάστε αυτό το [**post**](https://cramppet.github.io/regulator/index.html), αλλά ουσιαστικά θα λάβει τα **βασικά μέρη** από τα **discovered subdomains** και θα τα συνδυάσει για να βρει περισσότερα subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** Το _subzuf_ είναι ένας fuzzer brute-force για subdomains, σε συνδυασμό με έναν εξαιρετικά απλό αλλά αποτελεσματικό αλγόριθμο καθοδηγούμενο από DNS responses. Χρησιμοποιεί ένα παρεχόμενο σύνολο δεδομένων εισόδου, όπως ένα προσαρμοσμένο wordlist ή ιστορικά DNS/TLS records, για να συνθέσει με ακρίβεια περισσότερα αντίστοιχα domain names και να τα επεκτείνει ακόμη περισσότερο σε loop, με βάση τις πληροφορίες που συλλέγονται κατά τη διάρκεια του DNS scan.
```
echo www | subzuf facebook.com
```
### **Ροή εργασίας ανακάλυψης subdomain**

Δείτε αυτό το blog post που έγραψα σχετικά με το πώς να **αυτοματοποιήσετε την ανακάλυψη subdomain** από ένα domain χρησιμοποιώντας **Trickest workflows**, ώστε να μη χρειάζεται να εκκινώ χειροκίνητα πολλά εργαλεία στον υπολογιστή μου:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Αν βρήκατε μια διεύθυνση IP που περιέχει **μία ή περισσότερες web σελίδες** οι οποίες ανήκουν σε subdomains, μπορείτε να προσπαθήσετε να **βρείτε άλλα subdomains με webs σε αυτή την IP**, αναζητώντας σε **OSINT sources** domains σε μια IP ή κάνοντας **brute-forcing ονομάτων domain VHost σε αυτή την IP**.

#### OSINT

Μπορείτε να βρείτε ορισμένα **VHosts σε IPs χρησιμοποιώντας** το [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ή άλλα APIs**.

**Brute Force**

Αν υποψιάζεστε ότι κάποιο subdomain μπορεί να είναι κρυφό σε έναν web server, μπορείτε να προσπαθήσετε να κάνετε brute force:

Όταν η **IP κάνει redirect σε ένα hostname** (name-based vhosts), κάντε fuzz απευθείας το `Host` header και αφήστε το ffuf να κάνει **auto-calibrate**, ώστε να επισημάνει τις responses που διαφέρουν από το default vhost:<sup>[[2]](#references)</sup>
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
> Με αυτή την τεχνική μπορεί ακόμη και να καταφέρετε να αποκτήσετε πρόσβαση σε internal/hidden endpoints.

### **CORS Brute Force**

Μερικές φορές θα βρείτε σελίδες που επιστρέφουν την κεφαλίδα _**Access-Control-Allow-Origin**_ μόνο όταν έχει οριστεί ένα έγκυρο domain/subdomain στην κεφαλίδα _**Origin**_. Σε αυτά τα σενάρια, μπορείτε να κάνετε abuse αυτής της συμπεριφοράς για να **ανακαλύψετε** νέα **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Κατά την αναζήτηση για **subdomains**, έχετε το νου σας για να δείτε αν **pointing** σε οποιονδήποτε τύπο **bucket** και, σε αυτήν την περίπτωση, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Επίσης, καθώς σε αυτό το σημείο θα γνωρίζετε όλα τα domains εντός του scope, δοκιμάστε να κάνετε [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Μπορείτε να **monitor** αν δημιουργούνται **new subdomains** ενός domain, παρακολουθώντας τα **Certificate Transparency** Logs, όπως κάνει το [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Αναζήτηση για vulnerabilities**

Ελέγξτε για πιθανά [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Αν το **subdomain** δείχνει σε κάποιο **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Αν βρείτε οποιοδήποτε **subdomain with an IP different** από αυτά που έχετε ήδη εντοπίσει κατά το assets discovery, θα πρέπει να εκτελέσετε ένα **basic vulnerability scan** (χρησιμοποιώντας Nessus ή OpenVAS) και κάποιο [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) με **nmap/masscan/shodan**. Ανάλογα με τις υπηρεσίες που εκτελούνται, μπορείτε να βρείτε σε **αυτό το βιβλίο κάποια tricks για να τα "attack"**.\
_Σημειώστε ότι μερικές φορές το subdomain φιλοξενείται σε μια IP που δεν ελέγχεται από τον client, επομένως δεν βρίσκεται στο scope· να είστε προσεκτικοί._

## IPs

Στα αρχικά βήματα μπορεί να έχετε **εντοπίσει ορισμένα IP ranges, domains και subdomains**.\
Ήρθε η ώρα να **συγκεντρώσετε όλες τις IPs από αυτά τα ranges** και για τα **domains/subdomains (DNS queries).**

Χρησιμοποιώντας υπηρεσίες από τα παρακάτω **free apis**, μπορείτε επίσης να βρείτε **previous IPs used by domains and subdomains**. Αυτές οι IPs μπορεί να ανήκουν ακόμη στον client (και ενδέχεται να σας επιτρέψουν να βρείτε [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Μπορείτε επίσης να ελέγξετε για domains που δείχνουν σε μια συγκεκριμένη IP address, χρησιμοποιώντας το εργαλείο [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Αναζήτηση για vulnerabilities**

Κάντε **Port scan σε όλες τις IPs που δεν ανήκουν σε CDNs** (καθώς κατά πάσα πιθανότητα δεν θα βρείτε κάτι ενδιαφέρον εκεί). Στις υπηρεσίες που εκτελούνται και εντοπίστηκαν, μπορεί να **είστε σε θέση να βρείτε vulnerabilities**.

**Βρείτε έναν** [**οδηγό**](../pentesting-network/index.html) **σχετικά με το πώς να κάνετε scan hosts.**

## Αναζήτηση web servers

> Έχουμε βρει όλες τις εταιρείες και τα assets τους και γνωρίζουμε τα IP ranges, τα domains και τα subdomains εντός του scope. Ήρθε η ώρα να αναζητήσουμε web servers.

Στα προηγούμενα βήματα πιθανότατα έχετε ήδη πραγματοποιήσει κάποιο **recon των IPs και των domains που εντοπίστηκαν**, επομένως μπορεί να έχετε **ήδη βρει όλους τους πιθανούς web servers**. Ωστόσο, αν δεν το έχετε κάνει, τώρα θα δούμε κάποια **γρήγορα tricks για την αναζήτηση web servers** εντός του scope.

Παρακαλούμε σημειώστε ότι αυτό θα είναι **προσανατολισμένο στο web apps discovery**, επομένως θα πρέπει να πραγματοποιήσετε επίσης **vulnerability** και **port scanning** (**αν επιτρέπεται** από το scope).

Μια **γρήγορη μέθοδος** για την ανακάλυψη **ports open** που σχετίζονται με **web** servers, χρησιμοποιώντας το [**masscan**, μπορεί να βρεθεί εδώ](../pentesting-network/index.html#http-port-discovery).\
Ένα ακόμη εύχρηστο εργαλείο για την αναζήτηση web servers είναι το [**httprobe**](https://github.com/tomnomnom/httprobe)**,** τα [**fprobe**](https://github.com/theblackturtle/fprobe) και [**httpx**](https://github.com/projectdiscovery/httpx). Απλώς του δίνετε μια λίστα από domains και θα προσπαθήσει να συνδεθεί στις ports 80 (http) και 443 (https). Επιπλέον, μπορείτε να ορίσετε να δοκιμάσει και άλλες ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Τώρα που ανακάλυψες **όλους τους web servers** που υπάρχουν στο scope (ανάμεσα στις **IP** της εταιρείας και σε όλα τα **domains** και **subdomains**), πιθανότατα **δεν γνωρίζεις από πού να ξεκινήσεις**. Ας το κάνουμε απλό και ας ξεκινήσουμε λαμβάνοντας screenshots όλων. Απλώς **κοιτάζοντας** την **κύρια σελίδα** μπορείς να βρεις **περίεργα** endpoints που είναι περισσότερο **πιθανό** να είναι **ευάλωτα**.

Για να υλοποιήσεις την προτεινόμενη ιδέα μπορείς να χρησιμοποιήσεις τα [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ή [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Επιπλέον, μπορείς στη συνέχεια να χρησιμοποιήσεις το [**eyeballer**](https://github.com/BishopFox/eyeballer) για να επεξεργαστείς όλα τα **screenshots**, ώστε να σου υποδείξει **τι είναι πιθανό να περιέχει vulnerabilities** και τι όχι.

## Public Cloud Assets

Για να βρεις πιθανά cloud assets που ανήκουν σε μια εταιρεία, θα πρέπει να **ξεκινήσεις με μια λίστα keywords που προσδιορίζουν την εταιρεία**. Για παράδειγμα, για μια crypto εταιρεία μπορείς να χρησιμοποιήσεις λέξεις όπως: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Θα χρειαστείς επίσης wordlists με **common words που χρησιμοποιούνται σε buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Στη συνέχεια, με αυτές τις λέξεις θα πρέπει να δημιουργήσεις **permutations** (έλεγξε το [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) για περισσότερες πληροφορίες).

Με τις wordlists που θα προκύψουν μπορείς να χρησιμοποιήσεις εργαλεία όπως τα [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ή** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Να θυμάσαι ότι όταν αναζητάς Cloud Assets θα πρέπει να **ψάχνεις για περισσότερα από buckets στο AWS**.

### **Looking for vulnerabilities**

Αν βρεις πράγματα όπως **open buckets ή cloud functions εκτεθειμένα**, θα πρέπει να **αποκτήσεις πρόσβαση σε αυτά** και να προσπαθήσεις να δεις τι σου προσφέρουν και αν μπορείς να τα κάνεις abuse.

## Emails

Με τα **domains** και τα **subdomains** που βρίσκονται μέσα στο scope, έχεις ουσιαστικά όλα όσα **χρειάζεσαι για να ξεκινήσεις την αναζήτηση emails**. Αυτά είναι τα **APIs** και τα **tools** που έχουν λειτουργήσει καλύτερα για εμένα στην εύρεση emails μιας εταιρείας:

- [**theHarvester**](https://github.com/laramies/theHarvester) - με APIs
- API του [**https://hunter.io/**](https://hunter.io/) (free version)
- API του [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API του [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Τα emails θα φανούν χρήσιμα αργότερα για **brute-force web logins και auth services** (όπως το SSH). Επίσης, χρειάζονται για **phishings**. Επιπλέον, αυτά τα APIs θα σου δώσουν ακόμη περισσότερες **πληροφορίες για το άτομο** πίσω από το email, κάτι χρήσιμο για την phishing campaign.

## Credential Leaks

Με τα **domains,** τα **subdomains** και τα **emails** μπορείς να ξεκινήσεις να αναζητάς credentials που έχουν γίνει leak στο παρελθόν και ανήκουν σε αυτά τα emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Αν βρεις **valid leaked** credentials, αυτό αποτελεί μια πολύ εύκολη νίκη.

## Secrets Leaks

Τα credential leaks σχετίζονται με hacks εταιρειών όπου **ευαίσθητες πληροφορίες έγιναν leak και πουλήθηκαν**. Ωστόσο, οι εταιρείες μπορεί να επηρεάζονται και από **άλλα leaks**, των οποίων οι πληροφορίες δεν υπάρχουν σε αυτές τις databases:

### Github Leaks

Credentials και APIs μπορεί να έχουν γίνει leak στα **public repositories** της **εταιρείας** ή των **users** που εργάζονται σε αυτή την εταιρεία του github.\
Μπορείς να χρησιμοποιήσεις το **tool** [**Leakos**](https://github.com/carlospolop/Leakos) για να **κατεβάσεις** όλα τα **public repos** ενός **organization** και των **developers** του και να εκτελέσεις αυτόματα το [**gitleaks**](https://github.com/zricethezav/gitleaks) πάνω σε αυτά.

Το **Leakos** μπορεί επίσης να χρησιμοποιηθεί για να εκτελέσει το **gitleaks** εναντίον όλου του **text** που παρέχεται από **URLs που περνάς** σε αυτό, καθώς μερικές φορές και οι **web pages περιέχουν secrets**.

#### Github Dorks

Έλεγξε επίσης αυτή τη **σελίδα** για πιθανά **github dorks** που μπορείς να αναζητήσεις και στο organization που επιτίθεσαι:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Μερικές φορές attackers ή απλώς εργαζόμενοι θα **δημοσιεύσουν περιεχόμενο της εταιρείας σε ένα paste site**. Αυτό μπορεί να περιέχει ή να μην περιέχει **ευαίσθητες πληροφορίες**, αλλά είναι πολύ ενδιαφέρον να το αναζητήσεις.\
Μπορείς να χρησιμοποιήσεις το tool [**Pastos**](https://github.com/carlospolop/Pastos) για να αναζητήσεις ταυτόχρονα σε περισσότερα από 80 paste sites.

### Google Dorks

Τα παλιά αλλά πολύτιμα google dorks είναι πάντα χρήσιμα για την εύρεση **εκτεθειμένων πληροφοριών που δεν θα έπρεπε να βρίσκονται εκεί**. Το μόνο πρόβλημα είναι ότι το [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) περιέχει αρκετές **χιλιάδες** πιθανές queries που δεν μπορείς να εκτελέσεις χειροκίνητα. Έτσι, μπορείς να πάρεις τα 10 αγαπημένα σου ή να χρησιμοποιήσεις ένα **tool όπως το** [**Gorks**](https://github.com/carlospolop/Gorks) **για να τα εκτελέσεις όλα**.

_Σημείωσε ότι τα tools που προσπαθούν να εκτελέσουν ολόκληρη τη database χρησιμοποιώντας τον κανονικό Google browser δεν θα ολοκληρώσουν ποτέ, καθώς η Google θα σε μπλοκάρει πολύ σύντομα._

### **Looking for vulnerabilities**

Αν βρεις **valid leaked** credentials ή API tokens, αυτό αποτελεί μια πολύ εύκολη νίκη.

## Public Code Vulnerabilities

Αν διαπίστωσες ότι η εταιρεία διαθέτει **open-source code**, μπορείς να το **αναλύσεις** και να αναζητήσεις **vulnerabilities** σε αυτό.

**Ανάλογα με τη γλώσσα** υπάρχουν διαφορετικά **tools** που μπορείς να χρησιμοποιήσεις:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Υπάρχουν επίσης δωρεάν services που επιτρέπουν να **σαρώνεις public repositories**, όπως:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Η **πλειονότητα των vulnerabilities** που εντοπίζονται από bug hunters βρίσκεται μέσα σε **web applications**, επομένως σε αυτό το σημείο θα ήθελα να μιλήσω για μια **μεθοδολογία testing web applications**, και μπορείς να [**βρεις αυτές τις πληροφορίες εδώ**](../../network-services-pentesting/pentesting-web/index.html).

Θέλω επίσης να κάνω ειδική αναφορά στην ενότητα [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), καθώς, παρόλο που δεν θα πρέπει να περιμένεις να εντοπίσουν πολύ ευαίσθητα vulnerabilities, είναι χρήσιμα για να τα ενσωματώσεις σε **workflows, ώστε να αποκτήσεις κάποιες αρχικές πληροφορίες για το web.**

## Recapitulation

> Συγχαρητήρια! Σε αυτό το σημείο έχεις ήδη πραγματοποιήσει **όλο το basic enumeration**. Ναι, είναι basic, επειδή μπορεί να γίνει πολύ περισσότερο enumeration (θα δούμε περισσότερα tricks αργότερα).

Έχεις ήδη:

1. Εντοπίσει όλες τις **εταιρείες** μέσα στο scope
2. Εντοπίσει όλα τα **assets** που ανήκουν στις εταιρείες (και πραγματοποιήσει κάποιο vuln scan, αν βρίσκεται εντός scope)
3. Εντοπίσει όλα τα **domains** που ανήκουν στις εταιρείες
4. Εντοπίσει όλα τα **subdomains** των domains (υπάρχει κάποιο subdomain takeover;)
5. Εντοπίσει όλες τις **IP** (από και **όχι από CDNs**) μέσα στο scope.
6. Εντοπίσει όλους τους **web servers** και λάβει ένα **screenshot** από αυτούς (υπάρχει κάτι περίεργο που αξίζει πιο λεπτομερή έλεγχο;)
7. Εντοπίσει όλα τα **πιθανά public cloud assets** που ανήκουν στην εταιρεία.
8. Εντοπίσει **emails**, **credential leaks** και **secret leaks** που θα μπορούσαν να σου προσφέρουν μια **μεγάλη νίκη πολύ εύκολα**.
9. Πραγματοποιήσει **Pentesting σε όλα τα webs που βρήκες**

## **Full Recon Automatic Tools**

Υπάρχουν αρκετά tools που θα εκτελέσουν μέρος των προτεινόμενων ενεργειών εναντίον ενός δεδομένου scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Λίγο παλιό και χωρίς updates

## References

- [1] Όλα τα δωρεάν courses του [**@Jhaddix**](https://twitter.com/Jhaddix), όπως το [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
