# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks λογότυπα & σχεδιασμός κίνησης από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Το τοπικό σας αντίγραφο του HackTricks θα είναι **available at [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (πρέπει να χτίσει το βιβλίο, να είστε υπομονετικοί).

## Χορηγοί

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας του οποίου το σλόγκαν είναι **HACK THE UNHACKABLE**. Εκτελούν δική τους έρευνα και αναπτύσσουν τα δικά τους hacking εργαλεία για να **προσφέρουν πολλές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και εκπαίδευση.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** υποστηρίζει επίσης open source έργα κυβερνοασφάλειας όπως το HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) είναι το πιο σημαντικό event κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **την αποστολή της προώθησης τεχνικής γνώσης**, αυτό το συνέδριο είναι ένα σημείο συνάντησης για επαγγελματίες της τεχνολογίας και της κυβερνοασφάλειας από κάθε τομέα.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** είναι η **Europe's #1** πλατφόρμα για ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **εγγραφείτε** στο **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και αρχίστε να κερδίζετε bounties έως **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** που τροφοδοτούνται από τα **πιο προηγμένα** community εργαλεία στον κόσμο.

Αποκτήστε Πρόσβαση Σήμερα:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Εμπλακείτε με περιεχόμενο που εμβαθύνει στη συγκίνηση και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνετε ενημερωμένοι για τον ταχύτατο κόσμο του hacking μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο
- **Latest Announcements:** Ενημερωθείτε για τα νεότερα bug bounties που ξεκινούν και κρίσιμες ενημερώσεις πλατφόρμας

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Λάβετε την προοπτική ενός hacker για τις web εφαρμογές, το δίκτυο και το cloud σας**

**Εντοπίστε και αναφέρετε κρίσιμες, εκμεταλλεύσιμες ευπάθειες με πραγματικό επιχειρησιακό αντίκτυπο.** Χρησιμοποιήστε τα 20+ custom εργαλεία μας για να χαρτογραφήσετε την attack surface, να βρείτε ζητήματα ασφαλείας που επιτρέπουν escalation privileges, και να χρησιμοποιήσετε automated exploits για να συλλέξετε απαραίτητα αποδεικτικά, μετατρέποντας τη σκληρή δουλειά σας σε πειστικές αναφορές.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για να **έχετε πρόσβαση σε αποτελέσματα μηχανών αναζήτησης**. Κάνουν scraping στις μηχανές αναζήτησης, διαχειρίζονται proxies, λύνουν captchas, και parse-άρουν όλα τα πλούσια δομημένα δεδομένα για εσάς.

Μια συνδρομή σε ένα από τα σχέδια της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών search engines, συμπεριλαμβανομένων Google, Bing, Baidu, Yahoo, Yandex, και άλλα.\
Σε αντίθεση με άλλους παρόχους, **η SerpApi δεν περιορίζεται μόνο στο scraping των organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν συστηματικά όλες τις διαφημίσεις, inline εικόνες και βίντεο, knowledge graphs, και άλλα στοιχεία και features που υπάρχουν στα αποτελέσματα αναζήτησης.

Τρέχοντες πελάτες της SerpApi περιλαμβάνουν **Apple, Shopify, και GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για να πραγματοποιείτε vulnerability research, penetration testing, και reverse engineering για να προστατεύετε mobile applications και συσκευές. **Κατακτήστε την ασφάλεια iOS και Android** μέσω των on-demand μαθημάτων μας και **πάρτε πιστοποίηση**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Amsterdam** που βοηθά στην **προστασία** επιχειρήσεων **σε όλον τον κόσμο** απέναντι στις πιο πρόσφατες απειλές κυβερνοασφάλειας προσφέροντας **offensive-security services** με μια **σύγχρονη** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφαλείας με γραφεία σε Amsterdam και Wyoming. Προσφέρουν **all-in-one security services** που σημαίνει ότι τα καλύπτουν όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Ένα ακόμα καλό στοιχείο για τη WebSec είναι ότι σε αντίθεση με το μέσο της βιομηχανίας η WebSec είναι **πολύ αυτοπεποίθηση στις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**, όπως αναφέρεται στην ιστοσελίδα τους "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες ρίξτε μια ματιά στην [**website**](https://websec.net/en/) και στο [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι επίσης **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) είναι μια μηχανή αναζήτησης για data breach (leak). \
Παρέχουμε random string search (σαν google) πάνω σε όλα τα είδη data leaks μεγάλα και μικρά --όχι μόνο τα μεγάλα-- πάνω σε δεδομένα από πολλαπλές πηγές. \
Αναζητήσεις ατόμων, αναζήτηση με AI, αναζήτηση οργανισμών, API (OpenAPI) πρόσβαση, theHarvester integration, όλα τα features που χρειάζεται ένας pentester.\
**Το HackTricks συνεχίζει να είναι μια εξαιρετική πλατφόρμα μάθησης για όλους μας και είμαστε περήφανοι που τη χορηγούμε!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική εκπαίδευση κυβερνοασφάλειας που δημιουργείται και διδάσκεται από
ειδικούς του κλάδου. Τα προγράμματά τους υπερβαίνουν τη θεωρία για να εξοπλίσουν ομάδες με βαθιά
κατανόηση και εφαρμόσιμες δεξιότητες, χρησιμοποιώντας προσαρμοσμένα περιβάλλοντα που αντικατοπτρίζουν πραγματικές
απειλές. Για ερωτήματα για custom training, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι ξεχωρίζει την εκπαίδευσή τους:**
* Προσαρμοσμένο περιεχόμενο και labs
* Υποστηρίζεται από κορυφαία εργαλεία και πλατφόρμες
* Σχεδιασμένο και διδασκόμενο από πρακτικούς επαγγελματίες

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Education** και **FinTech**, με έμφαση στο **penetration testing, cloud security assessments**, και **compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει επαγγελματίες με πιστοποιήσεις **OSCP και CISSP**, φέρνοντας βαθιά τεχνική εμπειρία και πληροφόρηση σύμφωνη με τα industry standards σε κάθε έργο.

Προχωράμε πέρα από τα automated scans με **manual, intelligence-driven testing** προσαρμοσμένο σε περιβάλλοντα υψηλού ρίσκου. Από την ασφάλιση αρχείων φοιτητών μέχρι την προστασία χρηματοοικονομικών συναλλαγών, βοηθούμε οργανισμούς να υπερασπιστούν ό,τι έχει μεγαλύτερη σημασία.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Μείνετε ενημερωμένοι με τα τελευταία στον τομέα της κυβερνοασφάλειας επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν Kubernetes clusters αποδοτικά. Αξιοποιήστε τα AI-driven insights μας, το προηγμένο security framework, και το διαισθητικό CloudMaps GUI για να οπτικοποιήσετε τα clusters σας, να κατανοήσετε την κατάστασή τους και να δράσετε με αυτοπεποίθηση.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις μεγάλες διανομές kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Άδεια & Αποποίηση

Δείτε τα εδώ:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Στατιστικά

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
