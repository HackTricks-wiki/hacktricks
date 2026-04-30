# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτέλεσε το HackTricks τοπικά
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
Το τοπικό σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (πρέπει να γίνει build το βιβλίο, κάντε υπομονή).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας με σύνθημα **HACK THE UNHACKABLE**. Κάνουν δική τους έρευνα και αναπτύσσουν τα δικά τους hacking tools για να **προσφέρουν αρκετές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και training.

Μπορείτε να δείτε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης open source projects κυβερνοασφάλειας όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι η **#1 της Ευρώπης** για ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **εγγραφείτε** στο **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε bounties έως **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Ελάτε στον server του [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Ασχοληθείτε με περιεχόμενο που εμβαθύνει στη συγκίνηση και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνετε ενημερωμένοι για τον γρήγορο κόσμο του hacking μέσω ειδήσεων και insights σε πραγματικό χρόνο
- **Latest Announcements:** Μείνετε ενήμεροι για τα νεότερα bug bounties που ξεκινούν και για τις κρίσιμες ενημερώσεις της πλατφόρμας

**Ελάτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και ξεκινήστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security προσφέρει **πρακτική εκπαίδευση AI Security** με μια **engineering-first, hands-on lab approach**. Τα courses μας είναι φτιαγμένα για security engineers, AppSec professionals και developers που θέλουν να **build, break, and secure πραγματικές εφαρμογές με AI/LLM**.

Η **AI Security Certification** εστιάζει σε πραγματικές δεξιότητες, όπως:
- Securing LLM and AI-powered applications
- Threat modeling για AI systems
- Embeddings, vector databases και RAG security
- LLM attacks, abuse scenarios και πρακτικές άμυνες
- Secure design patterns και considerations για deployment

Όλα τα courses είναι **on-demand**, **lab-driven** και σχεδιασμένα γύρω από **real-world security tradeoffs**, όχι απλώς θεωρία.

👉 Περισσότερες λεπτομέρειες για το AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για **access search engine results**. Κάνει scrape τις search engines, χειρίζεται proxies, λύνει captchas και αναλύει για εσάς όλα τα rich structured data.

Μια συνδρομή σε ένα από τα πλάνα της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών search engines, συμπεριλαμβανομένων των Google, Bing, Baidu, Yahoo, Yandex και άλλων.\
Σε αντίθεση με άλλους παρόχους, η **SerpApi δεν κάνει απλώς scrape τα organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις ads, inline images και videos, knowledge graphs και άλλα στοιχεία και λειτουργίες που υπάρχουν στα search results.

Οι τρέχοντες πελάτες της SerpApi περιλαμβάνουν **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες δείτε το [**blog**](https://serpapi.com/blog/)**,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείτε να **δημιουργήσετε έναν δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για να κάνετε vulnerability research, penetration testing και reverse engineering για να προστατεύετε mobile applications και devices. **Master iOS and Android security** μέσα από τα on-demand courses μας και **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Η **NaxusAI** είναι μια AI-powered security platform για να βρίσκετε exploitable vulnerabilities πριν το κάνουν οι attackers.

**Code security tip**: εγγραφείτε στο NaxusAI, μια έξυπνη πλατφόρμα παρακολούθησης ευπαθειών φτιαγμένη για developers και security teams! Ελάτε μαζί μας σήμερα και αρχίστε να χρησιμοποιείτε AI για **detecting, validating, and fixing real security risks before they reach production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Amsterdam** που βοηθά στην **προστασία** επιχειρήσεων **σε όλο τον κόσμο** από τις πιο πρόσφατες απειλές κυβερνοασφάλειας, παρέχοντας **offensive-security services** με μια **modern** προσέγγιση.

Η WebSec είναι μια intenational security company με γραφεία στο Amsterdam και στο Wyoming. Προσφέρουν **all-in-one security services**, που σημαίνει ότι τα κάνουν όλα· Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Άλλο ένα ωραίο στοιχείο για την WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec είναι **πολύ σίγουρη για τις ικανότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**· αναφέρει στον ιστότοπό της "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες ρίξτε μια ματιά στο [**website**](https://websec.net/en/) και στο [**blog**](https://websec.net/blog/)!

Επιπλέον των παραπάνω, η WebSec είναι επίσης ένας **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Φτιαγμένο για το πεδίο. Φτιαγμένο γύρω από εσάς.**\
Η [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική εκπαίδευση κυβερνοασφάλειας, σχεδιασμένη και καθοδηγούμενη από ειδικούς του κλάδου. Τα προγράμματά τους ξεπερνούν τη θεωρία ώστε να εξοπλίζουν τις ομάδες με βαθιά κατανόηση και εφαρμόσιμες δεξιότητες, χρησιμοποιώντας custom environments που αντικατοπτρίζουν real-world threats. Για αιτήματα για custom training, επικοινωνήστε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι ξεχωρίζει την εκπαίδευσή τους:**
* Custom-built content and labs
* Υποστηρίζεται από κορυφαία tools και platforms
* Σχεδιασμένο και διδασκόμενο από practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Education** και **FinTech**,
με έμφαση στο **penetration testing, cloud security assessments**, και
στην **compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει **OSCP και CISSP
certified professionals**, προσφέροντας βαθιά τεχνική εξειδίκευση και insight επιπέδου κλάδου σε
κάθε engagement.

Πηγαίνουμε πέρα από τα automated scans με **manual, intelligence-driven testing** προσαρμοσμένο σε
περιβάλλοντα υψηλού ρίσκου. Από την προστασία student records έως την προστασία financial transactions,
βοηθάμε οργανισμούς να υπερασπιστούν ό,τι έχει τη μεγαλύτερη σημασία.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Μείνετε ενημερωμένοι και up to date με τα τελευταία στην κυβερνοασφάλεια επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE δίνει δύναμη σε DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν Kubernetes clusters αποτελεσματικά. Αξιοποιήστε τα AI-driven insights, το προηγμένο security framework και το διαισθητικό CloudMaps GUI για να οπτικοποιήσετε τα clusters σας, να κατανοήσετε την κατάστασή τους και να δράσετε με σιγουριά.

Επιπλέον, το K8Studio είναι **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift και άλλα).

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
