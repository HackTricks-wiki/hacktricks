# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Λογότυπα και σχεδιασμός κίνησης του Hacktricks από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτελέστε το HackTricks τοπικά

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
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Το τοπικό σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στη διεύθυνση [http://localhost:3337](http://localhost:3337)** σε <5 λεπτά (πρέπει να γίνει build του βιβλίου, κάντε υπομονή).

Εναλλακτικά, αν έχετε Docker Compose, μπορείτε απλώς να εκτελέσετε τα παρακάτω από τον ριζικό κατάλογο του repo:

```bash
docker compose up
```

Αυτό χρησιμοποιεί το ενσωματωμένο `docker-compose.yml` για να εμφανίζει το branch που είναι αυτήν τη στιγμή checked out στον host στη διεύθυνση [http://localhost:3337](http://localhost:3337), με live reload. Για να αλλάξετε γλώσσα όταν χρησιμοποιείτε Compose, κάντε checkout στο επιθυμητό branch γλώσσας πριν ξεκινήσετε την υπηρεσία.

## Συνεργάτες του HackTricks

---

## Φίλοι του HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η STM Cyber προσφέρει υπηρεσίες penetration testing, ελέγχους ασφαλείας, εργασίες exploit και έρευνας, εργαλεία και υπηρεσίες ευαισθητοποίησης σε θέματα ασφάλειας. Στον ιστότοπό της περιγράφεται μια ομάδα penetration testers, προγραμματιστών και ερευνητών ασφάλειας με εμπειρία άνω της δεκαετίας.<sup>[[1]](#references)</sup>

Μπορείτε να δείτε το **blog** τους στη διεύθυνση [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

Η **STM Cyber** υποστηρίζει επίσης open source έργα κυβερνοασφάλειας, όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η Intigriti είναι πάροχος ασφάλειας crowdsourced, που προσφέρει υπηρεσίες bug bounty και penetration testing μέσω μιας παγκόσμιας κοινότητας ερευνητών. Η πλατφόρμα της συνδυάζει συνεχή κάλυψη bug bounty με PTaaS κατά παραγγελία και διαχειριζόμενα προγράμματα γνωστοποίησης ευπαθειών.<sup>[[2]](#references)</sup>

**Συμβουλή για bug bounty**: Εγγραφείτε στην Intigriti μέσω του [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) και εξερευνήστε τα προγράμματα bug bounty της.

---

### [Modern Security – AI & Πλατφόρμα Εκπαίδευσης στην Ασφάλεια Εφαρμογών](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security προσφέρει αυτορυθμιζόμενη, πρακτική εκπαίδευση στην ασφάλεια AI για μηχανικούς ασφάλειας, επαγγελματίες AppSec και προγραμματιστές. Η πιστοποίηση AI Security καλύπτει τις βασικές αρχές των LLM και agents, τα RAG και vector databases, το threat modeling, τις επιθέσεις prompt injection και MCP, καθώς και την αμυντική αρχιτεκτονική.<sup>[[3]](#references)</sup>

👉 Περισσότερες πληροφορίες για το μάθημα AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** παρέχει APIs για την Google και άλλες μηχανές αναζήτησης, επιστρέφοντας δομημένα δεδομένα SERP με λειτουργίες όπως αποτελέσματα βάσει τοποθεσίας, Maps, Shopping και Knowledge Graph.<sup>[[4]](#references)</sup>

Για περισσότερες πληροφορίες, επισκεφθείτε το [**blog**](https://serpapi.com/blog/), δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground) ή [**δημιουργήστε έναν δωρεάν λογαριασμό**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Εξειδικευμένα Μαθήματα Ασφάλειας Κινητών Συσκευών και AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Η **8kSec Academy** προσφέρει αυτορυθμιζόμενα μαθήματα ασφάλειας κινητών συσκευών και AI. Ο κατάλογός της καλύπτει τον έλεγχο ασφάλειας και το reverse engineering εφαρμογών για κινητά με εργαλεία όπως τα Ghidra, Frida και LLDB, καθώς και εργαστήρια επιθέσεων και άμυνας AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Δείτε τον [κατάλογο μαθημάτων της 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Σαρωτής Ασφάλειας με AI](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Η **Naxus** προωθεί μια πλατφόρμα offensive AI που χαρτογραφεί κώδικα και υποδομές και στη συνέχεια χρησιμοποιεί static και dynamic agents για τον εντοπισμό και την επικύρωση εκμεταλλεύσιμων αδυναμιών, παρέχοντας αποδεικτικά στοιχεία proof-of-concept και οδηγίες αποκατάστασης.<sup>[[7]](#references)</sup>

**Συμβουλή για την ασφάλεια κώδικα**: Εξερευνήστε τη Naxus για τον εντοπισμό ευπαθειών σε κώδικα και υποδομές.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η WebSec παρέχει υπηρεσίες penetration testing, συνδρομές ασφάλειας, στελέχωση και αξιολογήσεις ευπαθειών. Σύμφωνα με τον ιστότοπό της, δραστηριοποιείται διεθνώς και καλύπτει την offensive security, την defensive security, καθώς και θέματα διακυβέρνησης, κινδύνου και συμμόρφωσης.<sup>[[8]](#references)</sup>

Για περισσότερες πληροφορίες, επισκεφθείτε τον [**ιστότοπό**](https://websec.net/en/) τους ή το [**blog**](https://websec.net/blog/).

Εκτός από τα παραπάνω, η WebSec είναι επίσης **σταθερός υποστηρικτής του HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Σχεδιασμένη για το πεδίο. Διαμορφωμένη γύρω από εσάς.**\
Η [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) προσφέρει εκπαίδευση στην κυβερνοασφάλεια από ειδικούς, με προσαρμοσμένο περιεχόμενο και εργαστήρια βασισμένα σε πραγματικές υποδομές. Τα προγράμματά της προσαρμόζονται στις ανάγκες κάθε οργανισμού και καλύπτουν τα πάντα, από την αξιολόγηση έως την υλοποίηση.<sup>[[9]](#references)</sup> Για ερωτήσεις σχετικά με προσαρμοσμένη εκπαίδευση, επικοινωνήστε [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι κάνει την εκπαίδευσή τους να ξεχωρίζει:**
* Προσαρμοσμένο περιεχόμενο και εργαστήρια
* Υποστηρίζεται από κορυφαία εργαλεία και πλατφόρμες
* Σχεδιάζεται και διδάσκεται από επαγγελματίες του χώρου

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions εστιάζει στη συμβουλευτική κυβερνοασφάλειας για τους κλάδους της **Εκπαίδευσης** και του **FinTech**, συμπεριλαμβανομένων αξιολογήσεων cloud, εσωτερικών και εξωτερικών penetration tests, αξιολογήσεων ευπαθειών και υποστήριξης συμμόρφωσης.<sup>[[10]](#references)</sup>

Ενημερωθείτε για τις τελευταίες εξελίξεις στην κυβερνοασφάλεια, επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog) μας.

---

### [K8Studio - Το Εξυπνότερο GUI για τη Διαχείριση του Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio είναι ένα IDE Kubernetes για desktop με οπτικοποίηση CloudMaps, πλοήγηση σε πολλαπλά clusters, RBAC, Helm, logs, YAML και προβολές terminal. Ο προμηθευτής αναφέρει ότι συνδέεται μέσω kubeconfig χωρίς εγκατάσταση agents και υποστηρίζει macOS, Windows, Linux και clusters σε απομονωμένα δίκτυα.<sup>[[11]](#references)</sup>

---

## Άδεια Χρήσης & Αποποίηση Ευθύνης

Δείτε την καταχώριση HackTricks Values & FAQ στην ενότητα References παρακάτω.

## Στατιστικά Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Πιστοποίηση AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Πρακτική Ασφάλεια AI: Επιθέσεις, Άμυνες και Εφαρμογές](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Παραπομπή Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Βίντεο χορηγίας της WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Μαθήματα Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Αξίες & Συχνές Ερωτήσεις του HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
