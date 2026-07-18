# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Τα λογότυπα και το motion design του HackTricks από τον_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτέλεση του HackTricks τοπικά
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Το τοπικό σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στη διεύθυνση [http://localhost:3337](http://localhost:3337)** σε λιγότερο από 5 λεπτά (χρειάζεται να γίνει build το βιβλίο, κάντε υπομονή).

Εναλλακτικά, αν έχετε Docker Compose, μπορείτε απλώς να εκτελέσετε τα παρακάτω από το repo root:
```bash
docker compose up
```
Αυτό χρησιμοποιεί το παρεχόμενο `docker-compose.yml` για να κάνει serve το branch που είναι αυτήν τη στιγμή checked out στο host στη διεύθυνση [http://localhost:3337](http://localhost:3337), με live reload. Για να αλλάξετε γλώσσα όταν χρησιμοποιείτε Compose, κάντε checkout το branch της επιθυμητής γλώσσας πριν ξεκινήσετε το service.

## Συνεργάτες του HackTricks

---

## Φίλοι του HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία cybersecurity με σύνθημα **HACK THE UNHACKABLE**. Πραγματοποιεί δική της έρευνα και αναπτύσσει τα δικά της hacking tools για να **προσφέρει αρκετές πολύτιμες υπηρεσίες cybersecurity**, όπως pentesting, Red teams και training.

Μπορείτε να δείτε το **blog** της στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης open source projects του cybersecurity χώρου, όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι η **#1 στην Ευρώπη** ethical hacking και **bug bounty platform.**

**Bug bounty tip**: Κάντε **sign up** στην **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και ξεκινήστε να κερδίζετε bounties έως και **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security παρέχει **πρακτικό AI Security training** με μια **engineering-first, hands-on προσέγγιση βασισμένη σε labs**. Τα courses μας απευθύνονται σε security engineers, επαγγελματίες του AppSec και developers που θέλουν να **δημιουργούν, να παραβιάζουν και να ασφαλίζουν πραγματικές εφαρμογές με AI/LLM**.

Η **AI Security Certification** εστιάζει σε δεξιότητες του πραγματικού κόσμου, όπως:
- Ασφάλιση εφαρμογών με LLM και AI
- Threat modeling για AI systems
- Embeddings, vector databases και RAG security
- LLM attacks, abuse scenarios και practical defenses
- Secure design patterns και ζητήματα deployment

Όλα τα courses είναι **on-demand**, **lab-driven** και σχεδιασμένα γύρω από **πραγματικούς συμβιβασμούς ασφάλειας**, όχι μόνο τη θεωρία.

👉 Περισσότερες λεπτομέρειες για το AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για **πρόσβαση σε αποτελέσματα search engine**. Κάνει scrape search engines, διαχειρίζεται proxies, επιλύει captchas και κάνει parse όλα τα rich structured data για εσάς.

Μια συνδρομή σε ένα από τα plans της SerpApi περιλαμβάνει πρόσβαση σε περισσότερα από 50 διαφορετικά APIs για scraping διαφορετικών search engines, όπως Google, Bing, Baidu, Yahoo, Yandex και άλλα.\
Σε αντίθεση με άλλους providers, η **SerpApi δεν κάνει απλώς scrape organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις διαφημίσεις, τα inline images και videos, τα knowledge graphs και άλλα στοιχεία και features που υπάρχουν στα search results.

Οι τρέχοντες πελάτες της SerpApi περιλαμβάνουν τις **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες, επισκεφθείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα example στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε έναν δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Η **8kSec Academy** σας εκπαιδεύει σε offensive mobile και AI security, με διδασκαλία από ενεργούς researchers – την ίδια ομάδα που βρίσκεται πίσω από τα CVE writeups και τις ομιλίες στα Black Hat, HITB και Zer0con. Τα courses είναι self-paced, βασίζονται σε labs με πραγματικούς στόχους και συνοδεύονται από hands-on certification.

Ο κατάλογος περιλαμβάνει δύο tracks:

**Mobile Security** – iOS και Android από το app layer έως τα χαμηλότερα επίπεδα: reverse engineering με Ghidra και LLDB, ARM64 exploitation, kernel internals και σύγχρονα mitigations (PAC, MTE, SELinux), jailbreak και rooting mechanics.

**AI Security** – δύο πλήρη courses που καλύπτουν τον τομέα. Το Practical AI Security εξηγεί πώς λειτουργούν τα LLMs, τα RAG pipelines, οι AI agents και το MCP, καθώς και πώς να τα επιτίθεστε και να τα αμύνεστε. Το Advanced AI Security εστιάζει έντονα στο build, στην αιχμή της τεχνολογίας: red teaming AI systems σε κλίμακα με Garak και PyRIT, exploitation MCP servers, planting και detecting model backdoors, καθώς και fine-tuning attacks και defenses σε Apple Silicon.

Courses και certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Το **NaxusAI** είναι μια AI-powered security platform για τον εντοπισμό exploitable vulnerabilities πριν από τους attackers.

**Code security tip**: Κάντε sign up στο NaxusAI, μια smart vulnerability monitoring platform σχεδιασμένη για developers και security teams! Ελάτε μαζί μας σήμερα και ξεκινήστε να χρησιμοποιείτε AI για **την ανίχνευση, την επικύρωση και τη διόρθωση πραγματικών security risks πριν φτάσουν στο production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία cybersecurity με έδρα το **Amsterdam**, η οποία βοηθά στην **προστασία** επιχειρήσεων **σε όλο τον κόσμο** από τις πιο πρόσφατες cybersecurity threats, παρέχοντας **offensive-security services** με **σύγχρονη** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία security με γραφεία στο Amsterdam και το Wyoming. Προσφέρει **all-in-one security services**, δηλαδή τα κάνει όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Ένα ακόμη ενδιαφέρον στοιχείο της WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec είναι **πολύ σίγουρη για τις ικανότητές της**, σε τέτοιο βαθμό ώστε να **εγγυάται τα καλύτερης ποιότητας αποτελέσματα**. Στον ιστότοπό της αναφέρει: "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες, δείτε το [**website**](https://websec.net/en/) και το [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι **σταθερός υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
Η [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματικό cybersecurity training, σχεδιασμένο και καθοδηγούμενο από
experts του κλάδου. Τα προγράμματά της ξεπερνούν τη θεωρία, εξοπλίζοντας τις ομάδες με βαθιά
κατανόηση και πρακτικές δεξιότητες, χρησιμοποιώντας custom environments που αντικατοπτρίζουν πραγματικές
threats. Για ερωτήσεις σχετικά με custom training, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι διαφοροποιεί το training τους:**
* Custom-built περιεχόμενο και labs
* Υποστηρίζεται από κορυφαία tools και platforms
* Σχεδιάζεται και διδάσκεται από practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες cybersecurity σε ιδρύματα **Education** και **FinTech**,
με έμφαση σε **penetration testing, cloud security assessments** και
**compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει **OSCP και CISSP
certified professionals**, προσφέροντας βαθιά τεχνική τεχνογνωσία και insights σύμφωνα με τα industry standards σε
κάθε engagement.

Ξεπερνάμε τα automated scans με **manual, intelligence-driven testing**, προσαρμοσμένο σε
περιβάλλοντα υψηλού ρίσκου. Από την ασφάλιση αρχείων φοιτητών έως την προστασία οικονομικών συναλλαγών,
βοηθάμε τους οργανισμούς να υπερασπίζονται ό,τι έχει τη μεγαλύτερη σημασία.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Μείνετε ενημερωμένοι για τις τελευταίες εξελίξεις στο cybersecurity, επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE επιτρέπει σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν Kubernetes clusters αποτελεσματικά. Αξιοποιήστε τα AI-driven insights, το advanced security framework και το intuitive CloudMaps GUI για να οπτικοποιείτε τα clusters σας, να κατανοείτε την κατάστασή τους και να ενεργείτε με σιγουριά.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλα).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Άδεια χρήσης και Αποποίηση ευθύνης

Δείτε τα στο:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
