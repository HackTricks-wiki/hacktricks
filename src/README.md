# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Λογότυπα & motion design του HackTricks από τον_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Η τοπική σας αντιγραφή του HackTricks θα είναι **διαθέσιμη στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (χρειάζεται να χτιστεί το βιβλίο, κάντε υπομονή).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας με σύνθημα **HACK THE UNHACKABLE**. Πραγματοποιούν τη δική τους έρευνα και αναπτύσσουν τα δικά τους hacking εργαλεία για να **προσφέρουν αρκετές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και εκπαίδευση.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης έργα ανοιχτού κώδικα κυβερνοασφάλειας όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι η **νούμερο 1 στην Ευρώπη** ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **εγγραφείτε** στο **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε bounties έως **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Ελάτε στον server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Ασχοληθείτε με περιεχόμενο που εμβαθύνει στη συγκίνηση και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνετε ενημερωμένοι για τον γρήγορο ρυθμό του hacking κόσμου μέσω ειδήσεων και insights σε πραγματικό χρόνο
- **Latest Announcements:** Μείνετε ενήμεροι με τα νεότερα bug bounties που ξεκινούν και τις κρίσιμες ενημερώσεις της πλατφόρμας

**Ελάτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security παρέχει **πρακτική εκπαίδευση AI Security** με μια **engineering-first, hands-on lab approach**. Τα μαθήματά μας είναι φτιαγμένα για security engineers, AppSec επαγγελματίες και developers που θέλουν να **χτίσουν, σπάσουν και ασφαλίσουν πραγματικές AI/LLM-powered εφαρμογές**.

Η **AI Security Certification** εστιάζει σε δεξιότητες πραγματικού κόσμου, όπως:
- Ασφάλιση LLM και AI-powered εφαρμογών
- Threat modeling για AI συστήματα
- Embeddings, vector databases, και RAG security
- LLM attacks, abuse scenarios, και πρακτικές άμυνες
- Secure design patterns και ζητήματα deployment

Όλα τα μαθήματα είναι **on-demand**, **lab-driven**, και σχεδιασμένα γύρω από **security tradeoffs του πραγματικού κόσμου**, όχι μόνο θεωρία.

👉 Περισσότερες λεπτομέρειες για το AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για να **έχετε πρόσβαση στα αποτελέσματα των search engines**. Κάνουν scraping στα search engines, χειρίζονται proxies, λύνουν captchas και αναλύουν όλα τα εμπλουτισμένα δομημένα δεδομένα για εσάς.

Μια συνδρομή σε ένα από τα πλάνα της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών search engines, όπως Google, Bing, Baidu, Yahoo, Yandex και άλλα.\
Σε αντίθεση με άλλους παρόχους, η **SerpApi δεν κάνει απλώς scrape τα organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις διαφημίσεις, inline εικόνες και βίντεο, knowledge graphs και άλλα στοιχεία και δυνατότητες που υπάρχουν στα search results.

Τρέχοντες πελάτες της SerpApi περιλαμβάνουν **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Η **8kSec Academy** σας εκπαιδεύει σε offensive mobile και AI security, με διδασκαλία από ενεργούς ερευνητές – την ίδια ομάδα πίσω από τα CVE writeups και τις ομιλίες στο Black Hat, HITB και Zer0con. Τα μαθήματα είναι self-paced, βασισμένα σε labs πάνω σε πραγματικούς στόχους, και υποστηρίζονται από hands-on certification.

Ο κατάλογος καλύπτει δύο tracks:

**Mobile Security** – iOS και Android από το επίπεδο της εφαρμογής και κάτω: reverse engineering με Ghidra και LLDB, ARM64 exploitation, kernel internals και σύγχρονα mitigations (PAC, MTE, SELinux), μηχανισμοί jailbreak και rooting.

**AI Security** – δύο πλήρη μαθήματα που καλύπτουν όλο το πεδίο. Το Practical AI Security εξηγεί πώς λειτουργούν τα LLMs, τα RAG pipelines, οι AI agents και το MCP, και πώς να τα επιτεθείτε και να τα αμυνθείτε. Το Advanced AI Security είναι πιο build-heavy στην αιχμή: red teaming AI συστημάτων σε κλίμακα με Garak και PyRIT, exploitation MCP servers, τοποθέτηση και ανίχνευση model backdoors, και fine-tuning attacks και άμυνες σε Apple Silicon.

Μαθήματα και πιστοποιήσεις:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Η **NaxusAI** είναι μια AI-powered security platform για να βρίσκετε exploitable vulnerabilities πριν το κάνουν οι attackers.

**Code security tip**: εγγραφείτε στο NaxusAI, μια έξυπνη vulnerability monitoring platform φτιαγμένη για developers και security teams! Ελάτε μαζί μας σήμερα και αρχίστε να χρησιμοποιείτε AI για **ανίχνευση, επικύρωση και διόρθωση πραγματικών security risks πριν φτάσουν στην παραγωγή**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Άμστερνταμ** που βοηθά στην **προστασία** επιχειρήσεων **σε όλο τον κόσμο** από τις πιο πρόσφατες απειλές κυβερνοασφάλειας, παρέχοντας **offensive-security services** με μια **modern** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφάλειας με γραφεία στο Άμστερνταμ και το Wyoming. Προσφέρουν **all-in-one security services**, που σημαίνει ότι τα κάνουν όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά ακόμη.

Ένα ακόμη ωραίο στοιχείο της WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec είναι **πολύ σίγουρη για τις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**, και αναφέρει στον ιστότοπό της "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες δείτε το [**website**](https://websec.net/en/) και το [**blog**](https://websec.net/blog/) τους!

Εκτός από τα παραπάνω, η WebSec είναι επίσης **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική εκπαίδευση κυβερνοασφάλειας, χτισμένη και καθοδηγούμενη από ειδικούς του κλάδου. Τα προγράμματά τους ξεπερνούν τη θεωρία και εξοπλίζουν τις ομάδες με βαθιά κατανόηση και εφαρμόσιμες δεξιότητες, χρησιμοποιώντας προσαρμοσμένα περιβάλλοντα που αντικατοπτρίζουν πραγματικές απειλές. Για αιτήματα προσαρμοσμένης εκπαίδευσης, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Προσαρμοσμένο περιεχόμενο και labs
* Υποστηρίζεται από εργαλεία και πλατφόρμες κορυφαίου επιπέδου
* Σχεδιασμένο και διδασκόμενο από practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Εκπαίδευσης** και **FinTech**,
με έμφαση σε **penetration testing, cloud security assessments**, και
**compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει **OSCP και CISSP
πιστοποιημένους επαγγελματίες**, φέρνοντας βαθιά τεχνική εξειδίκευση και γνώση βιομηχανικών προτύπων σε
κάθε συνεργασία.

Πηγαίνουμε πέρα από τα αυτοματοποιημένα scans με **χειροκίνητο, intelligence-driven testing** προσαρμοσμένο σε
περιβάλλοντα υψηλού κινδύνου. Από την προστασία αρχείων φοιτητών έως την ασφάλιση χρηματοοικονομικών συναλλαγών,
βοηθάμε τους οργανισμούς να υπερασπίζονται ό,τι έχει τη μεγαλύτερη σημασία.

_“Μια ποιοτική άμυνα απαιτεί γνώση της επίθεσης· παρέχουμε ασφάλεια μέσω κατανόησης.”_

Μείνετε ενημερωμένοι και έχετε πρόσβαση στα τελευταία νέα της κυβερνοασφάλειας επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog) μας.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν Kubernetes clusters αποτελεσματικά. Αξιοποιήστε τα AI-driven insights μας, το προηγμένο security framework και το διαισθητικό CloudMaps GUI για να οπτικοποιείτε τα clusters σας, να κατανοείτε την κατάστασή τους και να ενεργείτε με αυτοπεποίθηση.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις κύριες kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλα).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Δείτε τα στο:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
