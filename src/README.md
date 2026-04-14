# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Σχεδιασμός λογοτύπων & motion του HackTricks από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτελέστε το HackTricks τοπικά
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
Το τοπικό σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (χρειάζεται να χτιστεί το βιβλίο, κάντε υπομονή).

## Εταιρικοί Χορηγοί

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας με σύνθημα **HACK THE UNHACKABLE**. Πραγματοποιούν τη δική τους έρευνα και αναπτύσσουν τα δικά τους hacking εργαλεία για να **προσφέρουν διάφορες πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και training.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης έργα ανοιχτού κώδικα στον τομέα της κυβερνοασφάλειας όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι το **νούμερο 1 στην Ευρώπη** για ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **εγγραφείτε** στο **Intigriti**, μια premium **bug bounty platform που δημιουργήθηκε από hackers, για hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε bounties έως και **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Ελάτε στο server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Ασχοληθείτε με περιεχόμενο που εμβαθύνει στη συγκίνηση και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνετε ενημερωμένοι για τον γρήγορο κόσμο του hacking μέσω real-time ειδήσεων και insights
- **Latest Announcements:** Ενημερωθείτε για τα πιο πρόσφατα bug bounties που ξεκινούν και για κρίσιμες ενημερώσεις της πλατφόρμας

**Ελάτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε σήμερα με κορυφαίους hackers!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security προσφέρει **πρακτική εκπαίδευση στην AI Security** με μια **engineering-first, hands-on lab approach**. Τα μαθήματά μας είναι σχεδιασμένα για security engineers, AppSec professionals και developers που θέλουν να **χτίζουν, να σπάνε και να ασφαλίζουν πραγματικές εφαρμογές με AI/LLM**.

Η **AI Security Certification** εστιάζει σε πρακτικές δεξιότητες του πραγματικού κόσμου, όπως:
- Ασφάλιση εφαρμογών με LLM και AI
- Threat modeling για συστήματα AI
- Embeddings, vector databases και ασφάλεια RAG
- LLM attacks, abuse scenarios και πρακτικές άμυνες
- Secure design patterns και ζητήματα ανάπτυξης

Όλα τα μαθήματα είναι **on-demand**, **lab-driven** και σχεδιασμένα γύρω από **security tradeoffs του πραγματικού κόσμου**, όχι μόνο γύρω από τη θεωρία.

👉 Περισσότερες λεπτομέρειες για το μάθημα AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για να **έχετε πρόσβαση σε αποτελέσματα μηχανών αναζήτησης**. Κάνει scrape τις μηχανές αναζήτησης, διαχειρίζεται proxies, λύνει captchas και αναλύει για εσάς όλα τα πλούσια δομημένα δεδομένα.

Μια συνδρομή σε ένα από τα πλάνα της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών μηχανών αναζήτησης, συμπεριλαμβανομένων των Google, Bing, Baidu, Yahoo, Yandex και άλλων.\
Σε αντίθεση με άλλους παρόχους, η **SerpApi δεν κάνει απλώς scrape τα organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις διαφημίσεις, inline εικόνες και βίντεο, knowledge graphs και άλλα στοιχεία και δυνατότητες που υπάρχουν στα αποτελέσματα αναζήτησης.

Οι τρέχοντες πελάτες της SerpApi περιλαμβάνουν **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε έναν δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για να κάνετε vulnerability research, penetration testing και reverse engineering για να προστατεύετε mobile applications και συσκευές. **Κατακτήστε την ασφάλεια iOS και Android** μέσω των on-demand μαθημάτων μας και **λάβετε πιστοποίηση**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Άμστερνταμ** που βοηθά στην **προστασία** επιχειρήσεων **σε όλο τον κόσμο** απέναντι στις πιο πρόσφατες απειλές κυβερνοασφάλειας παρέχοντας **offensive-security services** με μια **μοντέρνα** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφάλειας με γραφεία στο Άμστερνταμ και το Wyoming. Προσφέρει **all-in-one security services** που σημαίνει ότι τα κάνει όλα· Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Άλλο ένα ωραίο πράγμα για την WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec είναι **πολύ σίγουρη για τις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**· αναφέρει στην ιστοσελίδα της "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες ρίξτε μια ματιά στο [**website**](https://websec.net/en/) και στο [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι επίσης ένας **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Χτισμένο για το πεδίο. Χτισμένο γύρω από εσάς.**\
Η [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική εκπαίδευση κυβερνοασφάλειας, σχεδιασμένη και καθοδηγούμενη από
ειδικούς του κλάδου. Τα προγράμματά τους ξεπερνούν τη θεωρία για να εξοπλίσουν τις ομάδες με βαθιά
κατανόηση και πρακτικές δεξιότητες, χρησιμοποιώντας προσαρμοσμένα περιβάλλοντα που αντικατοπτρίζουν απειλές
του πραγματικού κόσμου. Για αιτήματα προσαρμοσμένης εκπαίδευσης, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι ξεχωρίζει την εκπαίδευσή τους:**
* Περιεχόμενο και labs φτιαγμένα κατά παραγγελία
* Υποστηρίζεται από κορυφαία εργαλεία και πλατφόρμες
* Σχεδιασμένο και διδασκόμενο από practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Εκπαίδευσης** και **FinTech**,
με έμφαση στο **penetration testing, cloud security assessments**, και
**compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει **OSCP και CISSP
certified professionals**, φέρνοντας βαθιά τεχνική εμπειρία και insight επιπέδου κλάδου σε
κάθε συνεργασία.

Πηγαίνουμε πέρα από τα automated scans με **manual, intelligence-driven testing** προσαρμοσμένο σε
περιβάλλοντα υψηλού κινδύνου. Από την προστασία φοιτητικών αρχείων μέχρι την ασφάλεια χρηματοοικονομικών συναλλαγών,
βοηθάμε οργανισμούς να υπερασπιστούν ό,τι έχει τη μεγαλύτερη σημασία.

_“Μια ποιοτική άμυνα απαιτεί να γνωρίζεις την επίθεση, παρέχουμε ασφάλεια μέσω της κατανόησης.”_

Μείνετε ενημερωμένοι και up to date με τα τελευταία νέα στην κυβερνοασφάλεια επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog) μας.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE ενδυναμώνει DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν αποτελεσματικά Kubernetes clusters. Αξιοποιήστε τα AI-driven insights μας, το προηγμένο security framework και το διαισθητικό CloudMaps GUI για να οπτικοποιήσετε τα clusters σας, να κατανοήσετε την κατάστασή τους και να ενεργήσετε με σιγουριά.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις κύριες kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλα).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## Άδεια Χρήσης & Αποποίηση Ευθύνης

Δείτε τα στο:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Στατιστικά Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
