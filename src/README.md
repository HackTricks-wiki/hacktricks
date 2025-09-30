# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks λογότυπα & motion design από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτέλεση HackTricks τοπικά
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Η τοπική σας αντιγραφή του HackTricks θα είναι **διαθέσιμη στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (πρέπει να χτίσει το βιβλίο, να είστε υπομονετικοί).

## Εταιρικοί Χορηγοί

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας του οποίου το σύνθημα είναι **HACK THE UNHACKABLE**. Πραγματοποιούν τη δική τους έρευνα και αναπτύσσουν τα δικά τους hacking εργαλεία για να **προσφέρουν αρκετές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και εκπαίδευση.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** επίσης στηρίζει open source έργα κυβερνοασφάλειας όπως το HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) είναι το πιο σημαντικό event κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **την αποστολή προώθησης της τεχνικής γνώσης**, αυτό το συνέδριο αποτελεί ένα καυτό σημείο συνάντησης για επαγγελματίες της τεχνολογίας και της κυβερνοασφάλειας σε κάθε πειθαρχία.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** είναι η **Europe's #1** ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **sign up** για **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και ξεκινήστε να κερδίζετε bounties μέχρι **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργείτε εύκολα και να **αυτοματοποιείτε workflows** που τροφοδοτούνται από τα **πιο προηγμένα** community εργαλεία στον κόσμο.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Χρησιμοποιήστε τα 20+ custom εργαλεία μας για να χαρτογραφήσετε την attack surface, να εντοπίσετε θέματα ασφάλειας που επιτρέπουν escalation privileges, και να χρησιμοποιήσετε automated exploits για να συλλέξετε απαραίτητα αποδεικτικά στοιχεία, μετατρέποντας τη σκληρή δουλειά σας σε πειστικές αναφορές.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για να **access search engine results**. Κάνουν scraping σε search engines, διαχειρίζονται proxies, λύνουν captchas, και parse-άρουν όλα τα rich structured data για εσάς.

Μια συνδρομή σε ένα από τα σχέδια της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών search engines, συμπεριλαμβανομένων Google, Bing, Baidu, Yahoo, Yandex, και άλλα.\
Σε αντίθεση με άλλους providers, **SerpApi doesn’t just scrape organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλα τα ads, inline images και videos, knowledge graphs, και άλλα στοιχεία και features που υπάρχουν στα search results.

Οι τρέχοντες πελάτες της SerpApi περιλαμβάνουν **Apple, Shopify, and GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για να πραγματοποιήσετε vulnerability research, penetration testing, και reverse engineering για να προστατέψετε mobile applications και devices. **Master iOS and Android security** μέσω των on-demand courses μας και **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Άμστερνταμ** που βοηθά **να προστατέψει** επιχειρήσεις **σε όλο τον κόσμο** από τις τελευταίες απειλές κυβερνοασφάλειας παρέχοντας **offensive-security services** με μια **μοντέρνα** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφαλείας με γραφεία σε Amsterdam και Wyoming. Προσφέρουν **all-in-one security services** που σημαίνει ότι κάνουν σχεδόν τα πάντα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Ένα ακόμα καλό για τη WebSec είναι ότι σε αντίθεση με τον μέσο όρο της βιομηχανίας, η WebSec είναι **πολύ σίγουρη για τις δεξιότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**, στο site τους αναφέρεται "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες ρίξτε μια ματιά στο [**website**](https://websec.net/en/) και στο [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι επίσης **δέσμευση υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) είναι μια μηχανή αναζήτησης data breach (leak). \
Προσφέρουμε random string search (like google) πάνω σε όλα τα είδη data leaks μεγάλα και μικρά --όχι μόνο τα μεγάλα-- πάνω σε δεδομένα από πολλαπλές πηγές. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, όλα τα features που χρειάζεται ένας pentester.\
**HackTricks continues to be a great learning platform for us all and we're proud to be sponsoring it!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παραδίδει αποτελεσματική εκπαίδευση κυβερνοασφάλειας σχεδιασμένη και καθοδηγούμενη από industry experts. Τα προγράμματά τους ξεπερνούν τη θεωρία για να εξοπλίσουν ομάδες με βαθιά κατανόηση και εφαρμόσιμες δεξιότητες, χρησιμοποιώντας custom περιβάλλοντα που αντανακλούν πραγματικές απειλές. Για προσαρμοσμένες εκπαιδεύσεις, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι ξεχωρίζει την εκπαίδευσή τους:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Education** και **FinTech**, με έμφαση σε **penetration testing, cloud security assessments**, και **compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει επαγγελματίες πιστοποιημένους με **OSCP and CISSP**, φέρνοντας βαθιά τεχνική εξειδίκευση και γνώση βιομηχανικών προτύπων σε κάθε συνεργασία.

Προχωρούμε πέρα από τα automated scans με **manual, intelligence-driven testing** προσαρμοσμένο σε περιβάλλοντα υψηλού ρίσκου. Από την ασφάλεια των μαθητικών αρχείων μέχρι την προστασία χρηματοοικονομικών συναλλαγών, βοηθάμε οργανισμούς να υπερασπίζονται ό,τι έχει μεγαλύτερη σημασία.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Μείνετε ενημερωμένοι με τα τελευταία νέα στην κυβερνοασφάλεια επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps, και developers να διαχειρίζονται, να παρακολουθούν, και να ασφαλίζουν Kubernetes clusters αποδοτικά. Αξιοποιήστε τα AI-driven insights μας, το advanced security framework, και το ευχάριστο CloudMaps GUI για να οπτικοποιήσετε τα clusters σας, να κατανοήσετε την κατάσταση τους, και να δράσετε με αυτοπεποίθηση.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις κύριες kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
