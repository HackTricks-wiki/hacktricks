# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Λογότυπα και motion design του HackTricks από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Το τοπικό σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στη διεύθυνση [http://localhost:3337](http://localhost:3337)** σε λιγότερο από 5 λεπτά (χρειάζεται να γίνει build του βιβλίου, κάντε υπομονή).

Εναλλακτικά, αν έχετε Docker Compose, μπορείτε απλώς να εκτελέσετε τα παρακάτω από το root του repo:
```bash
docker compose up
```
Αυτό χρησιμοποιεί το συνοδευτικό `docker-compose.yml` για να σερβίρει το τοπικό checkout στη διεύθυνση [http://localhost:3337](http://localhost:3337) με live reload.

## Συνεργάτες του HackTricks

---

## Φίλοι του HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία cybersecurity με σύνθημα **HACK THE UNHACKABLE**. Πραγματοποιεί δική της έρευνα και αναπτύσσει δικά της hacking tools για να **προσφέρει αρκετές πολύτιμες υπηρεσίες cybersecurity**, όπως pentesting, Red teams και training.

Μπορείτε να δείτε το **blog** της στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης open source projects cybersecurity, όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι η **Νο. 1 στην Ευρώπη** ethical hacking και **bug bounty platform.**

**Bug bounty tip**: Κάντε **sign up** στην **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και ξεκινήστε να κερδίζετε bounties έως και **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security παρέχει **πρακτικό AI Security training** με **engineering-first, hands-on lab approach**. Τα courses μας απευθύνονται σε security engineers, επαγγελματίες AppSec και developers που θέλουν να **δημιουργούν, να επιτίθενται και να ασφαλίζουν πραγματικές εφαρμογές με AI/LLM**.

Η **AI Security Certification** εστιάζει σε δεξιότητες πραγματικού κόσμου, όπως:
- Ασφάλιση εφαρμογών με LLM και AI
- Threat modeling για AI systems
- Embeddings, vector databases και RAG security
- LLM attacks, abuse scenarios και πρακτικές άμυνες
- Secure design patterns και παράγοντες deployment

Όλα τα courses είναι **on-demand**, **lab-driven** και σχεδιασμένα γύρω από **πραγματικού κόσμου security tradeoffs**, όχι μόνο τη θεωρία.

👉 Περισσότερες λεπτομέρειες για το AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** προσφέρει γρήγορα και εύχρηστα real-time APIs για **πρόσβαση σε αποτελέσματα search engine**. Κάνει scrape search engines, χειρίζεται proxies, επιλύει captchas και αναλύει όλα τα rich structured data για εσάς.

Μια subscription σε ένα από τα plans της SerpApi περιλαμβάνει πρόσβαση σε περισσότερα από 50 διαφορετικά APIs για scraping διαφορετικών search engines, συμπεριλαμβανομένων των Google, Bing, Baidu, Yahoo, Yandex και άλλων.\
Σε αντίθεση με άλλους providers, η **SerpApi δεν κάνει απλώς scrape organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν με συνέπεια όλες τις διαφημίσεις, τα inline images και videos, τα knowledge graphs και άλλα στοιχεία και features που εμφανίζονται στα search results.

Οι τρέχοντες πελάτες της SerpApi περιλαμβάνουν τις **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες, επισκεφθείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα example στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε δωρεάν account** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Η **8kSec Academy** σας εκπαιδεύει σε offensive mobile και AI security, με διδασκαλία από ενεργούς researchers – την ίδια ομάδα που βρίσκεται πίσω από τα CVE writeups και τις ομιλίες στα Black Hat, HITB και Zer0con. Τα courses είναι self-paced, βασίζονται σε labs με πραγματικούς στόχους και συνοδεύονται από hands-on certification.

Ο κατάλογος περιλαμβάνει δύο tracks:

**Mobile Security** – iOS και Android από το επίπεδο της εφαρμογής έως το χαμηλότερο επίπεδο: reverse engineering με Ghidra και LLDB, ARM64 exploitation, kernel internals και σύγχρονες mitigations (PAC, MTE, SELinux), jailbreak και rooting mechanics.

**AI Security** – δύο πλήρη courses που καλύπτουν ολόκληρο το πεδίο. Το Practical AI Security εξηγεί πώς λειτουργούν τα LLMs, τα RAG pipelines, οι AI agents και το MCP, καθώς και πώς να τους επιτίθεστε και να τους αμύνεστε. Το Advanced AI Security είναι build-heavy και επικεντρώνεται στην αιχμή της τεχνολογίας: red teaming AI systems σε κλίμακα με Garak και PyRIT, exploitation MCP servers, εγκατάσταση και ανίχνευση model backdoors, καθώς και fine-tuning attacks και defenses σε Apple Silicon.

Courses και certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Το **NaxusAI** είναι μια AI-powered security platform για τον εντοπισμό exploitable vulnerabilities πριν το κάνουν οι attackers.

**Code security tip**: Κάντε sign up στο NaxusAI, μια έξυπνη vulnerability monitoring platform για developers και security teams! Ελάτε μαζί μας σήμερα και ξεκινήστε να χρησιμοποιείτε AI για **τον εντοπισμό, την επικύρωση και τη διόρθωση πραγματικών security risks πριν φτάσουν στο production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία cybersecurity με έδρα το **Amsterdam**, η οποία βοηθά **στην προστασία** επιχειρήσεων **σε όλο τον κόσμο** από τις πιο πρόσφατες απειλές cybersecurity, παρέχοντας **offensive-security services** με **σύγχρονη** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία security με γραφεία στο Amsterdam και στο Wyoming. Προσφέρει **all-in-one security services**, δηλαδή τα κάνει όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Ένα ακόμη ενδιαφέρον στοιχείο για τη WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του industry, η WebSec έχει **πολύ μεγάλη εμπιστοσύνη στις ικανότητές της**, σε τέτοιο βαθμό ώστε να **εγγυάται τα καλύτερης ποιότητας αποτελέσματα**. Στον ιστότοπό της αναφέρει: "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες, δείτε το [**website**](https://websec.net/en/) και το [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι **δεσμευμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
Η [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματικό cybersecurity training, το οποίο δημιουργείται και καθοδηγείται από experts του
industry. Τα programs της ξεπερνούν τη θεωρία, προσφέροντας στις ομάδες βαθιά
κατανόηση και actionable skills, με χρήση custom environments που αντικατοπτρίζουν απειλές
του πραγματικού κόσμου. Για ερωτήσεις σχετικά με custom training, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι διαφοροποιεί το training τους:**
* Custom-built content και labs
* Υποστηρίζεται από κορυφαία tools και platforms
* Σχεδιάζεται και διδάσκεται από practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες cybersecurity σε οργανισμούς **Education** και **FinTech**,
με έμφαση σε **penetration testing, cloud security assessments** και
**compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει **OSCP και CISSP
certified professionals**, προσφέροντας βαθιά τεχνική εξειδίκευση και γνώση σύμφωνα με τα πρότυπα του industry σε
κάθε συνεργασία.

Ξεπερνάμε τα automated scans με **manual, intelligence-driven testing**, προσαρμοσμένο σε
περιβάλλοντα υψηλού ρίσκου. Από την ασφάλιση των records των φοιτητών έως την προστασία
financial transactions, βοηθάμε τους οργανισμούς να υπερασπιστούν ό,τι έχει τη μεγαλύτερη σημασία.

_«Μια ποιοτική άμυνα απαιτεί γνώση της επίθεσης· παρέχουμε ασφάλεια μέσω της κατανόησης.»_

Μείνετε ενημερωμένοι για τις τελευταίες εξελίξεις στο cybersecurity επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog) μας.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE δίνει τη δυνατότητα σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν αποτελεσματικά Kubernetes clusters. Αξιοποιήστε τα AI-driven insights, το advanced security framework και το διαισθητικό CloudMaps GUI για να οπτικοποιείτε τα clusters σας, να κατανοείτε την κατάστασή τους και να ενεργείτε με σιγουριά.

Επιπλέον, το K8Studio είναι **συμβατό με όλες τις βασικές kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλες).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Άδεια χρήσης και Αποποίηση ευθύνης

Δείτε τα εδώ:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Στατιστικά GitHub

![Στατιστικά GitHub του HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
