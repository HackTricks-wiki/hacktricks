# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Τα λογότυπα & το motion design του Hacktricks από τον_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτέλεση του HackTricks Τοπικά
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
Ο τοπικός σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (χρειάζεται να κάνει build το βιβλίο, κάντε υπομονή).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία cybersecurity, με σύνθημα **HACK THE UNHACKABLE**. Κάνουν τη δική τους έρευνα και αναπτύσσουν τα δικά τους hacking tools για να **προσφέρουν αρκετές πολύτιμες υπηρεσίες cybersecurity** όπως pentesting, Red teams και training.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης έργα open source στον χώρο του cybersecurity όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι η **#1 στην Ευρώπη** πλατφόρμα ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **εγγραφείτε** στο **Intigriti**, μια premium **bug bounty platform που δημιουργήθηκε από hackers, για hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε bounties έως και **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security προσφέρει **πρακτική εκπαίδευση AI Security** με μια προσέγγιση **engineering-first, hands-on lab**. Τα μαθήματά μας είναι φτιαγμένα για security engineers, AppSec professionals και developers που θέλουν να **χτίζουν, σπάνε και ασφαλίζουν πραγματικές εφαρμογές με AI/LLM**.

Η **AI Security Certification** εστιάζει σε δεξιότητες του πραγματικού κόσμου, όπως:
- Ασφάλεια εφαρμογών με LLM και AI
- Threat modeling για AI συστήματα
- Embeddings, vector databases και RAG security
- LLM attacks, abuse scenarios και πρακτικές άμυνες
- Secure design patterns και ζητήματα deployment

Όλα τα μαθήματα είναι **on-demand**, **lab-driven** και σχεδιασμένα γύρω από **πραγματικά security tradeoffs**, όχι μόνο θεωρία.

👉 Περισσότερες λεπτομέρειες για το AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** προσφέρει γρήγορα και εύχρηστα real-time APIs για να **έχετε πρόσβαση στα αποτελέσματα των search engines**. Κάνουν scrape τα search engines, χειρίζονται proxies, λύνουν captchas και κάνουν parse όλα τα rich structured data για εσάς.

Μια συνδρομή σε ένα από τα πλάνα της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών search engines, όπως Google, Bing, Baidu, Yahoo, Yandex και άλλα.\
Σε αντίθεση με άλλους παρόχους, η **SerpApi δεν κάνει scrape μόνο τα organic results**. Τα responses της SerpApi περιλαμβάνουν σταθερά όλα τα ads, inline images και videos, knowledge graphs και άλλα στοιχεία και δυνατότητες που υπάρχουν στα search results.

Στους τωρινούς πελάτες της SerpApi περιλαμβάνονται οι **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Η **8kSec Academy** σας εκπαιδεύει σε offensive mobile και AI security, με διδασκαλία από ενεργούς ερευνητές – την ίδια ομάδα πίσω από τα CVE writeups και τις ομιλίες σε Black Hat, HITB και Zer0con. Τα μαθήματα είναι self-paced, βασισμένα σε labs σε πραγματικούς στόχους και υποστηρίζονται από hands-on certification.

Ο κατάλογος περιλαμβάνει δύο tracks:

**Mobile Security** – iOS και Android από το app layer και κάτω: reverse engineering με Ghidra και LLDB, ARM64 exploitation, kernel internals και σύγχρονες mitigations (PAC, MTE, SELinux), jailbreak και rooting mechanics.

**AI Security** – δύο πλήρη courses που καλύπτουν όλο το πεδίο. Το Practical AI Security καλύπτει πώς λειτουργούν τα LLMs, τα RAG pipelines, τα AI agents και το MCP, και πώς να τα attack και defend. Το Advanced AI Security είναι πιο build-heavy στο frontier: red teaming AI systems σε κλίμακα με Garak και PyRIT, exploiting MCP servers, planting και detecting model backdoors, καθώς και fine-tuning attacks και defenses σε Apple Silicon.

Courses και certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Η **NaxusAI** είναι μια πλατφόρμα security με AI-powered λειτουργίες για να εντοπίζει exploitable vulnerabilities πριν το κάνουν οι attackers.

**Code security tip**: εγγραφείτε στο NaxusAI, μια έξυπνη πλατφόρμα παρακολούθησης vulnerabilities φτιαγμένη για developers και security teams! Ελάτε μαζί μας σήμερα και αρχίστε να χρησιμοποιείτε AI για **ανίχνευση, validation και διόρθωση πραγματικών security risks πριν φτάσουν σε production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία cybersecurity με έδρα το **Amsterdam** που βοηθά στην **προστασία** επιχειρήσεων **σε όλο τον κόσμο** από τις πιο πρόσφατες απειλές cybersecurity, παρέχοντας **offensive-security services** με μια **μοντέρνα** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία security με γραφεία στο Amsterdam και το Wyoming. Προσφέρει **all-in-one security services**, που σημαίνει ότι τα κάνει όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Ένα άλλο ωραίο στοιχείο της WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec είναι **πολύ σίγουρη για τις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**, και αναφέρει στην ιστοσελίδα της: "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες δείτε το [**website**](https://websec.net/en/) και το [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι επίσης **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική εκπαίδευση cybersecurity, σχεδιασμένη και καθοδηγούμενη από ειδικούς του κλάδου. Τα προγράμματά τους ξεπερνούν τη θεωρία για να εξοπλίσουν ομάδες με βαθιά κατανόηση και εφαρμόσιμες δεξιότητες, χρησιμοποιώντας προσαρμοσμένα περιβάλλοντα που αντικατοπτρίζουν απειλές του πραγματικού κόσμου. Για αιτήματα για custom training, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες cybersecurity για ιδρύματα **Education** και **FinTech**
, με έμφαση σε **penetration testing, cloud security assessments** και
**compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει επαγγελματίες με πιστοποιήσεις **OSCP και CISSP**,
φέρνοντας βαθιά τεχνική τεχνογνωσία και insight επιπέδου βιομηχανίας σε
κάθε συνεργασία.

Προχωράμε πέρα από τα automated scans με **manual, intelligence-driven testing** προσαρμοσμένο σε
περιβάλλοντα υψηλού ρίσκου. Από την ασφάλεια student records μέχρι την προστασία financial transactions,
βοηθάμε οργανισμούς να υπερασπιστούν ό,τι έχει τη μεγαλύτερη σημασία.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Μείνετε ενημερωμένοι και up to date με τα τελευταία νέα στο cybersecurity επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog) μας.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν αποτελεσματικά Kubernetes clusters. Αξιοποιήστε τα AI-driven insights μας, το προηγμένο security framework και το διαισθητικό CloudMaps GUI για να οπτικοποιείτε τα clusters σας, να κατανοείτε την κατάστασή τους και να ενεργείτε με σιγουριά.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις κύριες kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλα).

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
