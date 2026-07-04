# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Σχεδιασμός λογοτύπων & motion του HackTricks από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτέλεση του HackTricks τοπικά
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
Η τοπική σας αντιγραφή του HackTricks θα είναι **διαθέσιμη στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (πρέπει να δημιουργηθεί το βιβλίο, κάντε υπομονή).

## Συνεργάτες HackTricks

---

## Φίλοι του HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας με σύνθημα **HACK THE UNHACKABLE**. Κάνουν τη δική τους έρευνα και αναπτύσσουν τα δικά τους hacking tools για να **προσφέρουν αρκετές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και training.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης open source projects κυβερνοασφάλειας όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι η **No.1 στην Ευρώπη** πλατφόρμα ethical hacking και **bug bounty.**

**Bug bounty tip**: **εγγραφείτε** στο **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε bounties έως **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Μπείτε στον server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Ασχοληθείτε με περιεχόμενο που εμβαθύνει στη συγκίνηση και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνετε ενημερωμένοι για τον γρήγορο κόσμο του hacking μέσω ειδήσεων και insights σε πραγματικό χρόνο
- **Latest Announcements:** Μείνετε ενήμεροι για τα πιο πρόσφατα bug bounties που ξεκινούν και για κρίσιμες ενημερώσεις της πλατφόρμας

**Ελάτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security παρέχει **πρακτική AI Security training** με προσέγγιση **engineering-first, hands-on lab**. Τα courses μας είναι φτιαγμένα για security engineers, AppSec professionals και developers που θέλουν να **χτίζουν, να σπάνε και να ασφαλίζουν πραγματικές AI/LLM-powered εφαρμογές**.

Η **AI Security Certification** εστιάζει σε δεξιότητες του πραγματικού κόσμου, όπως:
- Ασφάλιση LLM και AI-powered εφαρμογών
- Threat modeling για AI systems
- Embeddings, vector databases και RAG security
- LLM attacks, abuse scenarios και πρακτικές άμυνες
- Secure design patterns και ζητήματα deployment

Όλα τα courses είναι **on-demand**, **lab-driven** και σχεδιασμένα γύρω από **real-world security tradeoffs**, όχι μόνο τη θεωρία.

👉 Περισσότερες λεπτομέρειες για το AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για να **αποκτάτε αποτελέσματα μηχανών αναζήτησης**. Κάνει scraping στις search engines, χειρίζεται proxies, λύνει captchas και κάνει parsing όλα τα rich structured data για εσάς.

Μια συνδρομή σε ένα από τα πλάνα της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών search engines, όπως Google, Bing, Baidu, Yahoo, Yandex και άλλα.\
Σε αντίθεση με άλλους παρόχους, η **SerpApi δεν κάνει απλώς scraping των organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις διαφημίσεις, inline images και videos, knowledge graphs και άλλα στοιχεία και δυνατότητες που υπάρχουν στα αποτελέσματα αναζήτησης.

Οι τρέχοντες πελάτες της SerpApi περιλαμβάνουν τις **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε έναν δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για vulnerability research, penetration testing και reverse engineering, ώστε να προστατεύετε mobile applications και devices. **Γίνετε expert στην ασφάλεια iOS και Android** μέσω των on-demand courses μας και **αποκτήστε πιστοποίηση**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Η **NaxusAI** είναι μια πλατφόρμα ασφάλειας με AI-powered για να βρίσκει exploitable vulnerabilities πριν το κάνουν οι attackers.

**Code security tip**: εγγραφείτε στο NaxusAI, μια έξυπνη πλατφόρμα παρακολούθησης vulnerabilities φτιαγμένη για developers και security teams! Ελάτε μαζί μας σήμερα και αρχίστε να χρησιμοποιείτε AI για **εντοπισμό, επικύρωση και διόρθωση πραγματικών security risks πριν φτάσουν στην production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Amsterdam** που βοηθά στην **προστασία** επιχειρήσεων **σε όλο τον κόσμο** απέναντι στις πιο πρόσφατες απειλές κυβερνοασφάλειας παρέχοντας **offensive-security services** με μια **μοντέρνα** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφάλειας με γραφεία στο Amsterdam και το Wyoming. Προσφέρουν **all-in-one security services**, πράγμα που σημαίνει ότι τα κάνουν όλα· Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά ακόμη.

Άλλο ένα ωραίο πράγμα για τη WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec έχει **πολύ μεγάλη σιγουριά στις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**. Στον ιστότοπό της αναφέρει: "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες δείτε το [**website**](https://websec.net/en/) και το [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι επίσης ένας **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Φτιαγμένο για το πεδίο. Φτιαγμένο γύρω από εσάς.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική cybersecurity training, χτισμένη και καθοδηγούμενη από ειδικούς του κλάδου. Τα προγράμματά τους ξεπερνούν τη θεωρία και εξοπλίζουν τις ομάδες με βαθιά κατανόηση και εφαρμόσιμες δεξιότητες, χρησιμοποιώντας custom environments που αντικατοπτρίζουν πραγματικές απειλές. Για αιτήματα για custom training, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι κάνει τη training τους να ξεχωρίζει:**
* Custom-built content και labs
* Υποστηρίζεται από κορυφαία tools και platforms
* Σχεδιασμένο και διδασκόμενο από practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Εκπαίδευσης** και **FinTech**,
με έμφαση στο **penetration testing, cloud security assessments** και
**compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει επαγγελματίες με πιστοποιήσεις **OSCP και CISSP**,
φέροντας βαθιά τεχνική εμπειρία και insight σύμφωνα με τα πρότυπα του κλάδου σε
κάθε engagement.

Πηγαίνουμε πέρα από τα automated scans με **manual, intelligence-driven testing** προσαρμοσμένο σε
περιβάλλοντα υψηλού ρίσκου. Από την προστασία student records μέχρι την ασφάλεια financial transactions,
βοηθάμε οργανισμούς να υπερασπιστούν ό,τι έχει τη μεγαλύτερη σημασία.

_“Μια ποιοτική άμυνα απαιτεί να γνωρίζεις την επίθεση· παρέχουμε ασφάλεια μέσω της κατανόησης.”_

Μείνετε ενημερωμένοι και up to date με τα τελευταία νέα στην κυβερνοασφάλεια επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog) μας.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν αποτελεσματικά Kubernetes clusters. Αξιοποιήστε τα AI-driven insights μας, το προηγμένο security framework και το εύχρηστο CloudMaps GUI για να οπτικοποιήσετε τα clusters σας, να κατανοήσετε την κατάστασή τους και να δράσετε με αυτοπεποίθηση.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις κύριες διανομές kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλα).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Άδεια χρήσης & Αποποίηση ευθύνης

Δείτε τα στο:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
