# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Λογότυπα και motion design του HackTricks από_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Το τοπικό σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στη διεύθυνση [http://localhost:3337](http://localhost:3337)** σε λιγότερο από 5 λεπτά (χρειάζεται να δημιουργηθεί το βιβλίο, παρακαλούμε περιμένετε).

Εναλλακτικά, αν διαθέτετε Docker Compose, μπορείτε απλώς να εκτελέσετε τα παρακάτω από τη ρίζα του repo:
```bash
docker compose up
```
Αυτό χρησιμοποιεί το ενσωματωμένο `docker-compose.yml` για να διαθέσει το branch που είναι αυτήν τη στιγμή checked out στον host στη διεύθυνση [http://localhost:3337](http://localhost:3337) με live reload. Για να αλλάξετε γλώσσα όταν χρησιμοποιείτε Compose, κάντε checkout το επιθυμητό language branch πριν ξεκινήσετε το service.

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

Η STM Cyber παρέχει penetration testing, security audits, exploit και research work, tools και υπηρεσίες security awareness. Ο ιστότοπός της περιγράφει μια ομάδα penetration testers, programmers και security researchers με περισσότερα από δέκα χρόνια εμπειρίας.<sup>[[1]](#references)</sup>

Μπορείτε να επισκεφθείτε το **blog** τους στη διεύθυνση [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

Η **STM Cyber** υποστηρίζει επίσης open source projects κυβερνοασφάλειας, όπως το HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Η Intigriti είναι πάροχος crowdsourced security που προσφέρει υπηρεσίες bug bounty και penetration testing μέσω μιας παγκόσμιας κοινότητας researchers. Η πλατφόρμα της συνδυάζει συνεχή κάλυψη bug bounty με on-demand PTaaS και managed vulnerability disclosure programs.<sup>[[2]](#references)</sup>

**Bug bounty tip**: Εγγραφείτε στην Intigriti μέσω του [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) και εξερευνήστε τα bug bounty programs της.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Η Modern Security προσφέρει self-paced, hands-on AI security training για security engineers, επαγγελματίες AppSec και developers. Η AI Security Certification καλύπτει τα fundamentals των LLM και agents, RAG και vector databases, threat modeling, prompt-injection και MCP attacks, καθώς και defensive architecture.<sup>[[3]](#references)</sup>

👉 Περισσότερες λεπτομέρειες για το AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

Η **SerpApi** παρέχει APIs για Google και άλλες search engines, επιστρέφοντας structured SERP data με features όπως location-aware results, Maps, Shopping και Knowledge Graph results.<sup>[[4]](#references)</sup>

Για περισσότερες πληροφορίες, δείτε το [**blog**](https://serpapi.com/blog/) τους, δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground) τους ή [**δημιουργήστε έναν δωρεάν λογαριασμό**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Σε βάθος Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Η **8kSec Academy** προσφέρει self-paced mobile και AI-security courses. Ο κατάλογός της καλύπτει mobile application auditing και reversing με εργαλεία όπως τα Ghidra, Frida και LLDB, καθώς και AI/LLM attack και defense labs.<sup>[[5]](#references)[[6]](#references)</sup>

Περιηγηθείτε στον [κατάλογο courses της 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

Η **Naxus** προωθεί μια offensive-AI πλατφόρμα που χαρτογραφεί κώδικα και infrastructure και στη συνέχεια χρησιμοποιεί static και dynamic agents για να εντοπίζει και να επικυρώνει exploitable weaknesses, παρέχοντας proof-of-concept evidence και remediation guidance.<sup>[[7]](#references)</sup>

**Code security tip**: Εξερευνήστε τη Naxus για vulnerability discovery με επίκεντρο τον κώδικα και το infrastructure.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

Η WebSec παρέχει penetration testing, security subscriptions, staffing και vulnerability-assessment services. Ο ιστότοπός της αναφέρει ότι δραστηριοποιείται διεθνώς και καλύπτει offensive security, defensive security και εργασίες governance, risk και compliance.<sup>[[8]](#references)</sup>

Για περισσότερες πληροφορίες, επισκεφθείτε το [**website**](https://websec.net/en/) ή το [**blog**](https://websec.net/blog/) τους.

Εκτός από τα παραπάνω, η WebSec είναι επίσης **σταθερός υποστηρικτής του HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Φτιαγμένο για το πεδίο. Φτιαγμένο γύρω από εσάς.**\
Η [**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) παρέχει cybersecurity training από experts, με custom-built content και labs που βασίζονται σε πραγματικά infrastructures. Τα προγράμματά της είναι προσαρμοσμένα στις ανάγκες των οργανισμών και καλύπτουν το assessment έως και την implementation.<sup>[[9]](#references)</sup> Για ερωτήσεις σχετικά με custom training, επικοινωνήστε [**εδώ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Τι ξεχωρίζει το training τους:**
* Custom-built content και labs
* Υποστηρίζεται από κορυφαία tools και platforms
* Σχεδιάζεται και διδάσκεται από practitioners

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Η Last Tower Solutions επικεντρώνεται σε cybersecurity consulting για τους τομείς **Education** και **FinTech**, συμπεριλαμβανομένων cloud assessments, internal και external penetration tests, vulnerability assessments και compliance support.<sup>[[10]](#references)</sup>

Μείνετε ενημερωμένοι για τις τελευταίες εξελίξεις στην κυβερνοασφάλεια, επισκεπτόμενοι το [**blog**](https://www.lasttowersolutions.com/blog) μας.

---

### [K8Studio - Το εξυπνότερο GUI για τη διαχείριση του Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Το K8Studio είναι ένα desktop Kubernetes IDE με visualization μέσω CloudMaps, multi-cluster navigation, RBAC, Helm, logs, YAML και terminal views. Ο vendor αναφέρει ότι συνδέεται μέσω kubeconfig χωρίς εγκατάσταση agents και υποστηρίζει macOS, Windows, Linux και air-gapped clusters.<sup>[[11]](#references)</sup>

---

## License & Disclaimer

Δείτε την καταχώριση HackTricks Values & FAQ στις References παρακάτω.

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Practical AI Security: Attacks, Defenses, and Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorship video](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
