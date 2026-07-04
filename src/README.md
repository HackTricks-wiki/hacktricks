# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Το τοπικό σου αντίγραφο του HackTricks θα είναι **διαθέσιμο στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (χρειάζεται να χτίσει το βιβλίο, κάνε υπομονή).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η [**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας με σύνθημα **HACK THE UNHACKABLE**. Πραγματοποιούν τη δική τους έρευνα και αναπτύσσουν τα δικά τους hacking tools για να **προσφέρουν αρκετές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και training.

Μπορείς να δεις το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

Η **STM Cyber** υποστηρίζει επίσης open source projects κυβερνοασφάλειας όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η **Intigriti** είναι η **#1 της Ευρώπης** πλατφόρμα ethical hacking και **bug bounty platform.**

**Bug bounty tip**: **εγγράψου** στο **Intigriti**, μια premium **bug bounty platform created by hackers, for hackers**! Γίνε μέλος στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και άρχισε να κερδίζεις bounties έως **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Γίνε μέλος του server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσεις με έμπειρους hackers και bug bounty hunters!

- **Hacking Insights:** Ασχολήσου με περιεχόμενο που εξερευνά τη συγκίνηση και τις προκλήσεις του hacking
- **Real-Time Hack News:** Μείνε ενημερωμένος για τον γρήγορο κόσμο του hacking μέσω ειδήσεων και insights σε πραγματικό χρόνο
- **Latest Announcements:** Μείνε ενήμερος με τα πιο πρόσφατα bug bounties που ξεκινούν και με κρίσιμες ενημερώσεις της πλατφόρμας

**Γίνε μέλος μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και άρχισε να συνεργάζεσαι με κορυφαίους hackers σήμερα!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security προσφέρει **πρακτική AI Security training** με μια **engineering-first, hands-on lab approach**. Τα courses μας είναι φτιαγμένα για security engineers, AppSec professionals και developers που θέλουν να **χτίσουν, να σπάσουν και να ασφαλίσουν πραγματικές AI/LLM-powered applications**.

Η **AI Security Certification** εστιάζει σε πραγματικές δεξιότητες, όπως:
- Ασφάλεια LLM και AI-powered applications
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

Η **SerpApi** προσφέρει γρήγορα και εύκολα real-time APIs για να **αποκτάς search engine results**. Κάνουν scraping search engines, χειρίζονται proxies, λύνουν captchas και αναλύουν όλα τα rich structured data για εσένα.

Μια συνδρομή σε ένα από τα plans της SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών search engines, όπως Google, Bing, Baidu, Yahoo, Yandex και άλλα.\
Σε αντίθεση με άλλους providers, η **SerpApi δεν κάνει απλώς scrape τα organic results**. Οι απαντήσεις της SerpApi περιλαμβάνουν σταθερά όλες τις ads, inline images και videos, knowledge graphs και άλλα στοιχεία και features που υπάρχουν στα search results.

Στους τρέχοντες πελάτες της SerpApi περιλαμβάνονται οι **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες, δες το [**blog**](https://serpapi.com/blog/)**,** ή δοκίμασε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)**.**\
Μπορείς να **δημιουργήσεις έναν δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για vulnerability research, penetration testing και reverse engineering, ώστε να προστατεύεις mobile applications και devices. **Γνώρισε σε βάθος την ασφάλεια iOS και Android** μέσα από τα on-demand courses μας και **πάρε πιστοποίηση**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Η **NaxusAI** είναι μια AI-powered security platform για να βρίσκεις exploitable vulnerabilities πριν το κάνουν οι attackers.

**Code security tip**: εγγράψου στο NaxusAI, μια έξυπνη πλατφόρμα παρακολούθησης vulnerabilities χτισμένη για developers και security teams! Γίνε μέλος μας σήμερα και άρχισε να χρησιμοποιείς AI για **εντοπισμό, επικύρωση και διόρθωση πραγματικών security risks πριν φτάσουν στην παραγωγή**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η [**WebSec**](https://websec.net) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Άμστερνταμ**, που βοηθά στην **προστασία** επιχειρήσεων **σε όλο τον κόσμο** απέναντι στις πιο πρόσφατες απειλές κυβερνοασφάλειας, παρέχοντας **offensive-security services** με μια **μοντέρνα** προσέγγιση.

Η WebSec είναι μια διεθνής εταιρεία ασφάλειας με γραφεία στο Άμστερνταμ και το Wyoming. Προσφέρει **all-in-one security services**, που σημαίνει ότι τα κάνει όλα: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing και πολλά άλλα.

Άλλο ένα ωραίο στοιχείο για τη WebSec είναι ότι, σε αντίθεση με τον μέσο όρο του κλάδου, η WebSec είναι **πολύ σίγουρη για τις δεξιότητές της**, σε τέτοιο βαθμό ώστε **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**· αναφέρει στην ιστοσελίδα της "**If we can't hack it, You don't pay it!**". Για περισσότερες πληροφορίες, ρίξε μια ματιά στο [**website**](https://websec.net/en/) και στο [**blog**](https://websec.net/blog/)!

Επιπλέον, η WebSec είναι επίσης ένας **αφοσιωμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) αναπτύσσει και παρέχει αποτελεσματική cybersecurity training, χτισμένη και καθοδηγούμενη από
ειδικούς του κλάδου. Τα προγράμματά τους ξεπερνούν τη θεωρία και εξοπλίζουν τις ομάδες με βαθιά
κατανόηση και πρακτικές δεξιότητες, χρησιμοποιώντας custom environments που αντικατοπτρίζουν πραγματικές
απειλές. Για custom training inquiries, επικοινώνησε μαζί μας [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

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

Η Last Tower Solutions παρέχει εξειδικευμένες υπηρεσίες κυβερνοασφάλειας για ιδρύματα **Εκπαίδευσης** και **FinTech**, με έμφαση στο **penetration testing, cloud security assessments**, και
**compliance readiness** (SOC 2, PCI-DSS, NIST). Η ομάδα μας περιλαμβάνει **OSCP και CISSP certified professionals**, προσφέροντας βαθιά τεχνική εξειδίκευση και insight επιπέδου κλάδου σε
κάθε συνεργασία.

Προχωράμε πέρα από τα automated scans με **manual, intelligence-driven testing** προσαρμοσμένο σε
περιβάλλοντα υψηλού ρίσκου. Από την ασφάλεια student records μέχρι την προστασία financial transactions,
βοηθάμε οργανισμούς να υπερασπιστούν ό,τι έχει τη μεγαλύτερη σημασία.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Μείνε ενημερωμένος και up to date με τα τελευταία στην κυβερνοασφάλεια επισκεπτόμενος το [**blog**](https://www.lasttowersolutions.com/blog) μας.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio IDE ενδυναμώνει DevOps, DevSecOps και developers να διαχειρίζονται, να παρακολουθούν και να ασφαλίζουν Kubernetes clusters αποτελεσματικά. Αξιοποίησε τα AI-driven insights μας, το προηγμένο security framework και το διαισθητικό CloudMaps GUI για να οπτικοποιήσεις τα clusters σου, να κατανοήσεις την κατάστασή τους και να δράσεις με σιγουριά.

Επιπλέον, το K8Studio είναι **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Αυτό είναι ένα κείμενο για να παρουσιάσει το δωρεάν cybersecurity wiki: <b>Hacktricks Book </b>. Μάθε τώρα δωρεάν από αυτό όλα τα είδη hacking tricks!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Δες τα στο:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
