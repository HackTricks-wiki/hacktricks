# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks λογότυπα και σχεδιασμός κίνησης από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Τρέξτε το HackTricks τοπικά
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
Η τοπική σας αντιγραφή του HackTricks θα είναι **διαθέσιμη στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (χρειάζεται να χτιστεί το βιβλίο, υπομονή).

## Εταιρικοί Χορηγοί

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας με το σύνθημα **HACK THE UNHACKABLE**. Πραγματοποιούν τη δική τους έρευνα και αναπτύσσουν τα δικά τους εργαλεία hacking για να **προσφέρουν πολλές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και εκπαίδευση.

Μπορείτε να ελέγξετε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** επίσης υποστηρίζει open source projects στον χώρο της κυβερνοασφάλειας όπως το HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) είναι το πιο σημαντικό event κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **την αποστολή της προώθησης τεχνικής γνώσης**, αυτό το συνέδριο είναι ένα δυναμικό σημείο συνάντησης για επαγγελματίες της τεχνολογίας και της κυβερνοασφάλειας σε κάθε ειδικότητα.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** είναι η **#1 πλατφόρμα** ethical hacking και **bug bounty** στην Ευρώπη.

Συμβουλή για bug bounty: **εγγραφείτε** στο **Intigriti**, μια premium **bug bounty πλατφόρμα φτιαγμένη από hackers, για hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και ξεκινήστε να κερδίζετε αμοιβές μέχρι **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε workflows** που τροφοδοτούνται από τα πιο **προηγμένα** εργαλεία της κοινότητας στον κόσμο.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Εμπλακείτε με περιεχόμενο που εμβαθύνει στον ενθουσιασμό και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνετε ενημερωμένοι με ταχύ ρυθμό για τον κόσμο του hacking μέσω real-time ειδήσεων και πληροφοριών
- **Latest Announcements:** Μείνετε ενήμεροι για τα πιο πρόσφατα bug bounties που ξεκινούν και κρίσιμες ενημερώσεις πλατφορμών

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Λάβετε την προοπτική ενός hacker στις web εφαρμογές, το δίκτυό σας και το cloud**

**Βρείτε και αναφέρετε κρίσιμες, εκμεταλλεύσιμες ευπάθειες με πραγματικό επιχειρηματικό αντίκτυπο.** Χρησιμοποιήστε τα 20+ προσαρμοσμένα εργαλεία μας για να χαρτογραφήσετε την επιφάνεια επίθεσης, να βρείτε θέματα ασφάλειας που επιτρέπουν την κλιμάκωση προνομίων, και να χρησιμοποιήσετε αυτοματοποιημένα exploits για να συλλέξετε κρίσιμα αποδεικτικά στοιχεία, μετατρέποντας τη σκληρή δουλειά σας σε πειστικές αναφορές.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για **πρόσβαση σε αποτελέσματα μηχανών αναζήτησης**. Σαρώνει μηχανές αναζήτησης, διαχειρίζεται proxies, λύνει captchas, και αναλύει όλα τα πλούσια δομημένα δεδομένα για εσάς.

Μια συνδρομή σε ένα από τα πλάνα της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφόρων μηχανών αναζήτησης, συμπεριλαμβανομένων Google, Bing, Baidu, Yahoo, Yandex, και άλλα.\
Σε αντίθεση με άλλους παρόχους, **η SerpApi δεν περιορίζεται στο scraping οργανικών αποτελεσμάτων**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις διαφημίσεις, inline εικόνες και βίντεο, knowledge graphs, και άλλα στοιχεία και χαρακτηριστικά που υπάρχουν στα αποτελέσματα αναζήτησης.

Οι τρέχοντες πελάτες της SerpApi περιλαμβάνουν τις **Apple, Shopify, και GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για την έρευνα ευπαθειών, penetration testing, και reverse engineering για να προστατεύσετε mobile εφαρμογές και συσκευές. **Κατακτήστε την ασφάλεια iOS και Android** μέσω των on-demand μαθημάτων μας και **πάρτε πιστοποίηση**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Άμστερνταμ** που βοηθά να **προστατεύει** επιχειρήσεις **σε όλο τον κόσμο** από τις τελευταίες απειλές κυβερνοασφάλειας παρέχοντας **offensive-security υπηρεσίες** με μια **μοντέρνα** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφάλειας με γραφεία στο Amsterdam και στο Wyoming. Προσφέρουν **all-in-one security services** που σημαίνει ότι τα κάνουν όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Ένα ακόμα δροσερό πράγμα για τη WebSec είναι ότι σε αντίθεση με το μέσο όρο της βιομηχανίας, η WebSec είναι **πολύ σίγουρη για τις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**, όπως αναγράφεται στην ιστοσελίδα τους "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες ρίξτε μια ματιά στην [**website**](https://websec.net/en/) και στο [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι επίσης **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική εκπαίδευση κυβερνοασφάλειας, σχεδιασμένη και καθοδηγούμενη από
ειδικούς του κλάδου. Τα προγράμματά τους υπερβαίνουν τη θεωρία για να εξοπλίσουν τις ομάδες με βαθιά
κατανόηση και εφαρμόσιμες δεξιότητες, χρησιμοποιώντας προσαρμοσμένα περιβάλλοντα που αντικατοπτρίζουν πραγματικές
απειλές. Για ερωτήματα σχετικά με προσαρμοσμένη εκπαίδευση, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι ξεχωρίζει την εκπαίδευσή τους:**
* Προσαρμοσμένο περιεχόμενο και εργαστήρια
* Υποστηρίζεται από κορυφαία εργαλεία και πλατφόρμες
* Σχεδιασμένο και διδασκόμενο από επPractitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Education** και **FinTech**, με έμφαση στο **penetration testing, cloud security assessments**, και **compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει επαγγελματίες με πιστοποιήσεις **OSCP και CISSP**, φέρνοντας βαθιά τεχνική εξειδίκευση και διορατικότητα σύμφωνα με τα βιομηχανικά πρότυπα σε κάθε συνεργασία.

Προχωράμε πέρα από τους αυτοματοποιημένους σαρωτές με **χειροκίνητο, intelligence-driven testing** προσαρμοσμένο σε περιβάλλοντα υψηλού ρίσκου. Από την ασφάλεια των αρχείων φοιτητών έως την προστασία των χρηματοοικονομικών συναλλαγών, βοηθάμε οργανισμούς να προστατεύσουν ό,τι έχει μεγαλύτερη σημασία.

_«Μια ποιοτική άμυνα απαιτεί να γνωρίζεις την επίθεση, παρέχουμε ασφάλεια μέσω της κατανόησης.»_

Μείνετε ενημερωμένοι για τα τελευταία νέα στην κυβερνοασφάλεια επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν Kubernetes clusters αποτελεσματικά. Εκμεταλλευτείτε τα AI-driven insights μας, το προηγμένο security framework, και το διαισθητικό CloudMaps GUI για να οπτικοποιήσετε τα clusters σας, να κατανοήσετε την κατάσταση τους, και να ενεργήσετε με εμπιστοσύνη.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις κύριες διανομές kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλα).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Άδεια & Αποποίηση

Δείτε τα εδώ:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Στατιστικά Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
