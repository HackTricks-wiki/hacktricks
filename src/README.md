# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks λογότυπα & κίνηση σχεδίαση από_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Εκτέλεση του HackTricks Τοπικά
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks
# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Η τοπική σας αντίγραφο του HackTricks θα είναι **διαθέσιμο στο [http://localhost:3337](http://localhost:3337)** μετά από <5 λεπτά (χρειάζεται να κατασκευάσει το βιβλίο, να είστε υπομονετικοί).

## Χορηγοί Εταιρειών

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) είναι μια εξαιρετική εταιρεία κυβερνοασφάλειας της οποίας το σλόγκαν είναι **HACK THE UNHACKABLE**. Πραγματοποιούν τη δική τους έρευνα και αναπτύσσουν τα δικά τους εργαλεία hacking για να **προσφέρουν πολλές πολύτιμες υπηρεσίες κυβερνοασφάλειας** όπως pentesting, Red teams και εκπαίδευση.

Μπορείτε να ελέγξετε το **blog** τους στο [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** υποστηρίζει επίσης έργα ανοιχτού κώδικα κυβερνοασφάλειας όπως το HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) είναι η πιο σχετική εκδήλωση κυβερνοασφάλειας στην **Ισπανία** και μία από τις πιο σημαντικές στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένα καυτό σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε πειθαρχία.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** είναι η **νούμερο 1** ηθική πλατφόρμα hacking και **bug bounty στην Ευρώπη.**

**Συμβουλή bug bounty**: **εγγραφείτε** στο **Intigriti**, μια premium **πλατφόρμα bug bounty που δημιουργήθηκε από hackers, για hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε βραβεία έως **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.

Αποκτήστε πρόσβαση σήμερα:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Εγγραφείτε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για να επικοινωνήσετε με έμπειρους hackers και κυνηγούς bug bounty!

- **Ενημερώσεις Hacking:** Συμμετάσχετε σε περιεχόμενο που εξερευνά τη συγκίνηση και τις προκλήσεις του hacking
- **Ειδήσεις Hack σε Πραγματικό Χρόνο:** Μείνετε ενημερωμένοι με τον ταχύτατο κόσμο του hacking μέσω ειδήσεων και ενημερώσεων σε πραγματικό χρόνο
- **Τελευταίες Ανακοινώσεις:** Μείνετε ενημερωμένοι με τις πιο πρόσφατες εκκινήσεις bug bounty και κρίσιμες ενημερώσεις πλατφόρμας

**Ελάτε μαζί μας στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε να συνεργάζεστε με κορυφαίους hackers σήμερα!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Το απαραίτητο εργαλείο δοκιμών διείσδυσης

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Αποκτήστε την προοπτική ενός hacker για τις εφαρμογές σας, το δίκτυο και το cloud**

**Βρείτε και αναφέρετε κρίσιμες, εκμεταλλεύσιμες ευπάθειες με πραγματικό επιχειρηματικό αντίκτυπο.** Χρησιμοποιήστε τα 20+ προσαρμοσμένα εργαλεία μας για να χαρτογραφήσετε την επιφάνεια επίθεσης, να βρείτε ζητήματα ασφαλείας που σας επιτρέπουν να κλιμακώσετε προνόμια και να χρησιμοποιήσετε αυτοματοποιημένες εκμεταλλεύσεις για να συλλέξετε βασικά αποδεικτικά στοιχεία, μετατρέποντας τη σκληρή σας δουλειά σε πειστικές αναφορές.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** προσφέρει γρήγορες και εύκολες APIs σε πραγματικό χρόνο για **πρόσβαση στα αποτελέσματα μηχανών αναζήτησης**. Scrape-άρουν μηχανές αναζήτησης, χειρίζονται proxies, λύνουν captchas και αναλύουν όλα τα πλούσια δομημένα δεδομένα για εσάς.

Μια συνδρομή σε ένα από τα σχέδια του SerpApi περιλαμβάνει πρόσβαση σε πάνω από 50 διαφορετικά APIs για scraping διαφορετικών μηχανών αναζήτησης, συμπεριλαμβανομένων των Google, Bing, Baidu, Yahoo, Yandex και άλλων.\
Σε αντίθεση με άλλους παρόχους, **το SerpApi δεν scrape-άρει μόνο οργανικά αποτελέσματα**. Οι απαντήσεις του SerpApi περιλαμβάνουν σταθερά όλες τις διαφημίσεις, inline εικόνες και βίντεο, γραφήματα γνώσεων και άλλα στοιχεία και χαρακτηριστικά που υπάρχουν στα αποτελέσματα αναζήτησης.

Οι τρέχοντες πελάτες του SerpApi περιλαμβάνουν **Apple, Shopify και GrubHub**.\
Για περισσότερες πληροφορίες, ελέγξτε το [**blog**](https://serpapi.com/blog/)** τους,** ή δοκιμάστε ένα παράδειγμα στο [**playground**](https://serpapi.com/playground)** τους.**\
Μπορείτε να **δημιουργήσετε έναν δωρεάν λογαριασμό** [**εδώ**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Σε βάθος Μαθήματα Ασφαλείας Κινητών](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Μάθετε τις τεχνολογίες και τις δεξιότητες που απαιτούνται για να εκτελέσετε έρευνα ευπαθειών, δοκιμές διείσδυσης και αντίστροφη μηχανική για να προστατεύσετε τις κινητές εφαρμογές και τις συσκευές. **Κατακτήστε την ασφάλεια iOS και Android** μέσω των on-demand μαθημάτων μας και **λάβετε πιστοποίηση**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.nl/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.nl) είναι μια επαγγελματική εταιρεία κυβερνοασφάλειας με έδρα το **Άμστερνταμ** που βοηθά **στην προστασία** επιχειρήσεων **σε όλο τον κόσμο** από τις τελευταίες απειλές κυβερνοασφάλειας παρέχοντας **υπηρεσίες επιθετικής ασφάλειας** με **σύγχρονη** προσέγγιση.

Η WebSec είναι μια **ολιστική εταιρεία ασφάλειας**, που σημαίνει ότι τα κάνει όλα: Pentesting, **Ασφαλείς** Ελέγχους, Εκπαιδεύσεις Ευαισθητοποίησης, Καμπάνιες Phishing, Ανασκόπηση Κώδικα, Ανάπτυξη Εκμεταλλεύσεων, Εξωτερική Ανάθεση Ειδικών Ασφαλείας και πολλά άλλα.

Ένα άλλο ενδιαφέρον στοιχείο σχετικά με την WebSec είναι ότι, σε αντίθεση με τον μέσο όρο της βιομηχανίας, η WebSec είναι **πολύ σίγουρη για τις δεξιότητές της**, σε τέτοιο βαθμό που **εγγυάται τα καλύτερα ποιοτικά αποτελέσματα**, όπως δηλώνει στην ιστοσελίδα της "**Αν δεν μπορούμε να το χακάρουμε, δεν το πληρώνετε!**". Για περισσότερες πληροφορίες, ρίξτε μια ματιά στην [**ιστοσελίδα**](https://websec.nl/en/) και το [**blog**](https://websec.nl/blog/) τους!

Επιπλέον, η WebSec είναι επίσης **δεσμευμένος υποστηρικτής του HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

## Άδεια & Αποποίηση Ευθύνης

Ελέγξτε τους στο:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Στατιστικά Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
