# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

Καλώς ήρθατε στον ολοκληρωμένο οδηγό του HackTricks για το Threat Modeling! Ξεκινήστε την εξερεύνηση αυτής της κρίσιμης πτυχής της κυβερνοασφάλειας, όπου εντοπίζουμε, κατανοούμε και σχεδιάζουμε στρατηγικές αντιμετώπισης πιθανών ευπαθειών σε ένα σύστημα. Αυτό το νήμα λειτουργεί ως οδηγός βήμα προς βήμα, γεμάτος παραδείγματα από τον πραγματικό κόσμο, χρήσιμο λογισμικό και εύκολα κατανοητές επεξηγήσεις. Είναι ιδανικός τόσο για αρχάριους όσο και για έμπειρους επαγγελματίες που θέλουν να ενισχύσουν τις άμυνες κυβερνοασφάλειας.

### Συνήθως Χρησιμοποιούμενα Σενάρια

1. **Ανάπτυξη Λογισμικού**: Ως μέρος του Secure Software Development Life Cycle (SSDLC), το threat modeling βοηθά στον **εντοπισμό πιθανών πηγών ευπαθειών** στα πρώτα στάδια της ανάπτυξης.
2. **Penetration Testing**: Το πλαίσιο Penetration Testing Execution Standard (PTES) απαιτεί **threat modeling για την κατανόηση των ευπαθειών του συστήματος** πριν από την εκτέλεση του test.

### Το Threat Model με λίγα λόγια

Ένα Threat Model συνήθως αναπαρίσταται ως διάγραμμα, εικόνα ή κάποια άλλη μορφή οπτικής απεικόνισης που παρουσιάζει την προγραμματισμένη αρχιτεκτονική ή την υπάρχουσα υλοποίηση μιας εφαρμογής. Μοιάζει με **data flow diagram**, όμως η βασική διαφορά έγκειται στον σχεδιασμό του με επίκεντρο την ασφάλεια.

Τα threat models συχνά περιλαμβάνουν στοιχεία σημειωμένα με κόκκινο χρώμα, τα οποία συμβολίζουν πιθανές ευπάθειες, κινδύνους ή εμπόδια. Για την απλοποίηση της διαδικασίας εντοπισμού κινδύνων, χρησιμοποιείται η τριάδα CIA (Confidentiality, Integrity, Availability), η οποία αποτελεί τη βάση πολλών μεθοδολογιών threat modeling, με το STRIDE να είναι μία από τις πιο συνηθισμένες. Ωστόσο, η επιλεγμένη μεθοδολογία μπορεί να διαφέρει ανάλογα με το συγκεκριμένο πλαίσιο και τις απαιτήσεις.

### Η Τριάδα CIA

Η τριάδα CIA είναι ένα ευρέως αναγνωρισμένο μοντέλο στον τομέα της ασφάλειας πληροφοριών και αντιστοιχεί στα Confidentiality, Integrity και Availability. Αυτοί οι τρεις πυλώνες αποτελούν τη βάση πάνω στην οποία οικοδομούνται πολλά μέτρα και πολιτικές ασφάλειας, συμπεριλαμβανομένων των μεθοδολογιών threat modeling.

1. **Confidentiality**: Διασφάλιση ότι τα δεδομένα ή το σύστημα δεν είναι προσβάσιμα από μη εξουσιοδοτημένα άτομα. Πρόκειται για κεντρική πτυχή της ασφάλειας, η οποία απαιτεί κατάλληλους ελέγχους πρόσβασης, encryption και άλλα μέτρα για την αποτροπή data breaches.
2. **Integrity**: Η ακρίβεια, η συνέπεια και η αξιοπιστία των δεδομένων καθ' όλη τη διάρκεια του κύκλου ζωής τους. Αυτή η αρχή διασφαλίζει ότι τα δεδομένα δεν τροποποιούνται ή παραποιούνται από μη εξουσιοδοτημένα μέρη. Συχνά περιλαμβάνει checksums, hashing και άλλες μεθόδους επαλήθευσης δεδομένων.
3. **Availability**: Διασφαλίζει ότι τα δεδομένα και οι υπηρεσίες είναι προσβάσιμα στους εξουσιοδοτημένους χρήστες όταν απαιτείται. Αυτό συχνά περιλαμβάνει redundancy, fault tolerance και διαμορφώσεις high-availability, ώστε τα συστήματα να συνεχίζουν να λειτουργούν ακόμη και σε περίπτωση διακοπών.

### Μεθοδολογίες Threat Modeling

1. **STRIDE**: Αναπτύχθηκε από τη Microsoft και αποτελεί ακρωνύμιο των **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service και Elevation of Privilege**. Κάθε κατηγορία αντιπροσωπεύει έναν τύπο απειλής και αυτή η μεθοδολογία χρησιμοποιείται συνήθως στη φάση σχεδιασμού ενός προγράμματος ή συστήματος για τον εντοπισμό πιθανών απειλών.
2. **DREAD**: Πρόκειται για μια ακόμη μεθοδολογία της Microsoft που χρησιμοποιείται για την αξιολόγηση κινδύνων των εντοπισμένων απειλών. Το DREAD αντιστοιχεί στα **Damage potential, Reproducibility, Exploitability, Affected users και Discoverability**. Κάθε ένας από αυτούς τους παράγοντες βαθμολογείται και το αποτέλεσμα χρησιμοποιείται για την ιεράρχηση των εντοπισμένων απειλών.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Πρόκειται για μια μεθοδολογία επτά βημάτων, **επικεντρωμένη στον κίνδυνο**. Περιλαμβάνει τον καθορισμό και τον εντοπισμό στόχων ασφάλειας, τη δημιουργία τεχνικού πεδίου εφαρμογής, την αποδόμηση της εφαρμογής, την ανάλυση απειλών, την ανάλυση ευπαθειών και την αξιολόγηση κινδύνου/triage.
4. **Trike**: Πρόκειται για μια μεθοδολογία βασισμένη στον κίνδυνο, η οποία επικεντρώνεται στην προστασία assets. Ξεκινά από την οπτική του **risk management** και εξετάζει τις απειλές και τις ευπάθειες σε αυτό το πλαίσιο.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Αυτή η προσέγγιση στοχεύει να είναι πιο προσβάσιμη και ενσωματώνεται σε περιβάλλοντα Agile development. Συνδυάζει στοιχεία από τις άλλες μεθοδολογίες και επικεντρώνεται σε **οπτικές αναπαραστάσεις απειλών**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Αναπτύχθηκε από το CERT Coordination Center και αυτό το framework προορίζεται για **αξιολόγηση οργανωτικών κινδύνων αντί για συγκεκριμένα συστήματα ή λογισμικό**.

## Εργαλεία

Υπάρχουν αρκετά εργαλεία και software solutions που μπορούν να **βοηθήσουν** στη δημιουργία και διαχείριση threat models. Ακολουθούν μερικά που μπορείτε να εξετάσετε.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Ένα προηγμένο cross-platform και multi-feature GUI web spider/crawler για επαγγελματίες κυβερνοασφάλειας. Το Spider Suite μπορεί να χρησιμοποιηθεί για attack surface mapping και analysis.

**Χρήση**

1. Επιλέξτε ένα URL και κάντε Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Προβολή Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Ένα open-source project από το OWASP. Το Threat Dragon είναι web και desktop application που περιλαμβάνει system diagramming, καθώς και rule engine για την αυτόματη δημιουργία threats/mitigations.

**Χρήση**

1. Δημιουργία New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Μερικές φορές μπορεί να εμφανίζεται κάπως έτσι:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Εκκίνηση New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Αποθήκευση του New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Δημιουργήστε το model σας

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το SpiderSuite Crawler για να αντλήσετε έμπνευση. Ένα βασικό model θα μπορούσε να μοιάζει κάπως έτσι:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Μια σύντομη επεξήγηση των entities:

- Process (Η ίδια η entity, όπως Webserver ή web functionality)
- Actor (Ένα άτομο, όπως Website Visitor, User ή Administrator)
- Data Flow Line (Ένδειξη Interaction)
- Trust Boundary (Διαφορετικά network segments ή scopes.)
- Store (Στοιχεία στα οποία αποθηκεύονται δεδομένα, όπως Databases)

5. Δημιουργία Threat (Βήμα 1)

Αρχικά πρέπει να επιλέξετε το layer στο οποίο θέλετε να προσθέσετε ένα threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Τώρα μπορείτε να δημιουργήσετε το threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Λάβετε υπόψη ότι υπάρχει διαφορά μεταξύ Actor Threats και Process Threats. Αν προσθέτατε ένα threat σε έναν Actor, θα μπορούσατε να επιλέξετε μόνο "Spoofing" και "Repudiation". Ωστόσο, στο παράδειγμά μας προσθέτουμε threat σε μια Process entity, οπότε στο threat creation box θα εμφανιστεί το εξής:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Ολοκληρώθηκε

Τώρα το ολοκληρωμένο model σας θα πρέπει να μοιάζει κάπως έτσι. Με αυτόν τον τρόπο δημιουργείτε ένα απλό threat model με το OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Αυτό είναι ένα δωρεάν εργαλείο της Microsoft που βοηθά στον εντοπισμό απειλών στη φάση σχεδιασμού software projects. Χρησιμοποιεί τη μεθοδολογία STRIDE και είναι ιδιαίτερα κατάλληλο για όσους αναπτύσσουν στη Microsoft stack.

{{#include ../banners/hacktricks-training.md}}
