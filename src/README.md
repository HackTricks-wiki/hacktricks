# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Λογότυπα HackTricks & motion design από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Η τοπική σας αντιγραφή του HackTricks θα είναι **διαθέσιμη στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (πρέπει να χτίσει το βιβλίο, υπομονή).

## Εταιρικοί Χορηγοί

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας του οποίου το σύνθημα είναι **HACK THE UNHACKABLE**. Πραγματοποιούν τη δική τους έρευνα και αναπτύσσουν τα δικά τους εργαλεία hacking για να **προσφέρουν διάφορες πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και εκπαίδευση.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** υποστηρίζει επίσης ανοιχτού κώδικα έργα κυβερνοασφάλειας όπως το HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) είναι το πιο σημαντικό event κυβερνοασφάλειας στην **Spain** και ένα από τα πιο σημαντικά στην **Europe**. Με **αποστολή την προώθηση τεχνικής γνώσης**, αυτό το συνέδριο είναι ένα θερμό σημείο συνάντησης για επαγγελματίες της τεχνολογίας και της κυβερνοασφάλειας σε κάθε ειδικότητα.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** είναι η **Europe's #1** ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **sign up** για **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Εγγραφείτε στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και ξεκινήστε να κερδίζετε bounties μέχρι **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργείτε εύκολα και να **αυτοματοποιείτε workflows** τροφοδοτούμενες από τα **πιο προηγμένα** community εργαλεία στον κόσμο.

Αποκτήστε Πρόσβαση Σήμερα:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Γίνετε μέλος του [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Εμπλακείτε με περιεχόμενο που εξερευνά τον ενθουσιασμό και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνετε ενημερωμένοι για τον ταχέως εξελισσόμενο κόσμο του hacking μέσω ειδήσεων και ενημερώσεων σε πραγματικό χρόνο
- **Latest Announcements:** Μείνετε ενήμεροι για τα νεότερα bug bounties που ξεκινούν και τις κρίσιμες ενημερώσεις πλατφόρμας

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security παρέχει **πρακτική AI Security training** με μια **engineering-first, hands-on lab approach**. Τα μαθήματά μας έχουν σχεδιαστεί για security engineers, AppSec professionals και developers που θέλουν να **build, break, and secure real AI/LLM-powered applications**.

Η **AI Security Certification** εστιάζει σε δεξιότητες του πραγματικού κόσμου, συμπεριλαμβανομένων:
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

Όλα τα μαθήματα είναι **on-demand**, **lab-driven**, και σχεδιασμένα γύρω από **real-world security tradeoffs**, όχι μόνο θεωρία.

👉 More details on the AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για να **access search engine results**. Κάνουν scraping μηχανών αναζήτησης, διαχειρίζονται proxies, λύνουν captchas και αναλύουν όλα τα πλούσια δομημένα δεδομένα για εσάς.

Η συνδρομή σε ένα από τα πακέτα της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφόρων μηχανών αναζήτησης, συμπεριλαμβανομένων Google, Bing, Baidu, Yahoo, Yandex και άλλων.\
Σε αντίθεση με άλλους παρόχους, **SerpApi doesn’t just scrape organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις διαφημίσεις, inline εικόνες και βίντεο, knowledge graphs και άλλα στοιχεία και χαρακτηριστικά που εμφανίζονται στα αποτελέσματα αναζήτησης.

Μεταξύ των τρεχόντων πελατών της SerpApi είναι **Apple, Shopify, and GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για να εκτελέσετε vulnerability research, penetration testing και reverse engineering για να προστατέψετε mobile applications και συσκευές. **Master iOS and Android security** μέσω των on-demand μαθημάτων μας και **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Amsterdam** που βοηθά στην προστασία επιχειρήσεων **σε όλο τον κόσμο** από τις πιο πρόσφατες απειλές κυβερνοασφάλειας παρέχοντας **offensive-security services** με μια **σύγχρονη** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφάλειας με γραφεία στο Amsterdam και Wyoming. Προσφέρουν **all-in-one security services** που σημαίνει ότι τα κάνουν όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Ένα ακόμα θετικό της WebSec είναι ότι σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec είναι **πολύ σίγουρη για τις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**, όπως αναφέρεται στην ιστοσελίδα τους "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες ρίξτε μια ματιά στην [**website**](https://websec.net/en/) και στο [**blog**](https://websec.net/blog/)! 

Επιπλέον, η WebSec είναι επίσης **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική εκπαίδευση κυβερνοασφάλειας που σχεδιάζεται και διδάσκεται από industry experts. Τα προγράμματά τους ξεπερνούν τη θεωρία για να εξοπλίσουν τις ομάδες με βαθιά κατανόηση και πρακτικές δεξιότητες, χρησιμοποιώντας προσαρμοσμένα περιβάλλοντα που αντικατοπτρίζουν πραγματικές απειλές. Για προσαρμοσμένες εκπαιδευτικές αιτήσεις, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

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

Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Education** και **FinTech**, με έμφαση σε **penetration testing, cloud security assessments**, και **compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει επαγγελματίες με πιστοποιήσεις **OSCP and CISSP**, προσφέροντας βαθιά τεχνική εξειδίκευση και γνώση προτύπων του κλάδου σε κάθε συνεργασία.

Πηγαίνουμε πέρα από τους αυτοματοποιημένους σαρωτές με **χειροκίνητες, intelligence-driven δοκιμές** προσαρμοσμένες σε περιβάλλοντα υψηλού ρίσκου. Από την ασφάλιση των αρχείων των φοιτητών έως την προστασία χρηματοοικονομικών συναλλαγών, βοηθάμε οργανισμούς να υπερασπίζονται ό,τι έχει μεγαλύτερη σημασία.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Μείνετε ενημερωμένοι με τα τελευταία στον τομέα της κυβερνοασφάλειας επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν Kubernetes clusters αποτελεσματικά. Εκμεταλλευτείτε τα AI-driven insights μας, το προηγμένο security framework και το διαισθητικό CloudMaps GUI για να οπτικοποιήσετε τα clusters σας, να κατανοήσετε την κατάσταση τους και να δράσετε με αυτοπεποίθηση.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις κύριες διανομές kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

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
