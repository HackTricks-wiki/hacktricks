# Threat Modeling

## Threat Modeling

Καλώς ήρθατε στον ολοκληρωμένο οδηγό του HackTricks για το Threat Modeling! Ξεκινήστε μια εξερεύνηση αυτού του κρίσιμου τομέα της κυβερνοασφάλειας, όπου εντοπίζουμε, κατανοούμε και στρατηγικά σχεδιάζουμε ενάντια σε πιθανές ευπάθειες σε ένα σύστημα. Αυτό το νήμα χρησιμεύει ως οδηγός βήμα προς βήμα γεμάτος με παραδείγματα από τον πραγματικό κόσμο, χρήσιμα λογισμικά και εύκολες προς κατανόηση εξηγήσεις. Ιδανικό για αρχάριους και έμπειρους επαγγελματίες που επιθυμούν να ενισχύσουν τις άμυνες της κυβερνοασφάλειάς τους.

### Commonly Used Scenarios

1. **Software Development**: Ως μέρος του Secure Software Development Life Cycle (SSDLC), το threat modeling βοηθά στην **ταυτοποίηση πιθανών πηγών ευπαθειών** στα πρώτα στάδια της ανάπτυξης.
2. **Penetration Testing**: Το Penetration Testing Execution Standard (PTES) απαιτεί **threat modeling για την κατανόηση των ευπαθειών του συστήματος** πριν από την εκτέλεση της δοκιμής.

### Threat Model in a Nutshell

Ένα Threat Model συνήθως απεικονίζεται ως διάγραμμα, εικόνα ή κάποια άλλη μορφή οπτικής απεικόνισης που απεικονίζει την προγραμματισμένη αρχιτεκτονική ή την υπάρχουσα κατασκευή μιας εφαρμογής. Έχει ομοιότητα με ένα **διάγραμμα ροής δεδομένων**, αλλά η βασική διάκριση έγκειται στον σχεδιασμό του που επικεντρώνεται στην ασφάλεια.

Τα threat models συχνά περιλαμβάνουν στοιχεία που σημειώνονται με κόκκινο, συμβολίζοντας πιθανές ευπάθειες, κινδύνους ή εμπόδια. Για να απλοποιηθεί η διαδικασία ταυτοποίησης κινδύνων, χρησιμοποιείται η τριάδα CIA (Confidentiality, Integrity, Availability), που αποτελεί τη βάση πολλών μεθοδολογιών threat modeling, με το STRIDE να είναι μία από τις πιο κοινές. Ωστόσο, η επιλεγμένη μεθοδολογία μπορεί να διαφέρει ανάλογα με το συγκεκριμένο πλαίσιο και τις απαιτήσεις.

### The CIA Triad

Η τριάδα CIA είναι ένα ευρέως αναγνωρισμένο μοντέλο στον τομέα της ασφάλειας πληροφοριών, που σημαίνει Confidentiality, Integrity και Availability. Αυτοί οι τρεις πυλώνες αποτελούν τη βάση πάνω στην οποία έχουν οικοδομηθεί πολλά μέτρα και πολιτικές ασφάλειας, συμπεριλαμβανομένων των μεθοδολογιών threat modeling.

1. **Confidentiality**: Διασφάλιση ότι τα δεδομένα ή το σύστημα δεν αποκτώνται από μη εξουσιοδοτημένα άτομα. Αυτό είναι ένα κεντρικό στοιχείο της ασφάλειας, απαιτώντας κατάλληλους ελέγχους πρόσβασης, κρυπτογράφηση και άλλα μέτρα για την αποτροπή διαρροών δεδομένων.
2. **Integrity**: Η ακρίβεια, η συνέπεια και η αξιοπιστία των δεδομένων κατά τη διάρκεια του κύκλου ζωής τους. Αυτή η αρχή διασφαλίζει ότι τα δεδομένα δεν τροποποιούνται ή παραποιούνται από μη εξουσιοδοτημένα μέρη. Συχνά περιλαμβάνει checksums, hashing και άλλες μεθόδους επαλήθευσης δεδομένων.
3. **Availability**: Αυτό διασφαλίζει ότι τα δεδομένα και οι υπηρεσίες είναι προσβάσιμα σε εξουσιοδοτημένους χρήστες όταν χρειάζεται. Αυτό συχνά περιλαμβάνει πλεονασμό, ανθεκτικότητα σε σφάλματα και ρυθμίσεις υψηλής διαθεσιμότητας για να διατηρούνται τα συστήματα σε λειτουργία ακόμη και μπροστά σε διαταραχές.

### Threat Modeling Methodlogies

1. **STRIDE**: Αναπτυγμένο από τη Microsoft, το STRIDE είναι ένα ακρωνύμιο για **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Κάθε κατηγορία αντιπροσωπεύει έναν τύπο απειλής, και αυτή η μεθοδολογία χρησιμοποιείται συνήθως στη φάση σχεδίασης ενός προγράμματος ή συστήματος για την ταυτοποίηση πιθανών απειλών.
2. **DREAD**: Αυτή είναι μια άλλη μεθοδολογία από τη Microsoft που χρησιμοποιείται για την αξιολόγηση κινδύνου των ταυτοποιημένων απειλών. Το DREAD σημαίνει **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Κάθε ένας από αυτούς τους παράγοντες βαθμολογείται, και το αποτέλεσμα χρησιμοποιείται για την προτεραιοποίηση των ταυτοποιημένων απειλών.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Αυτή είναι μια επταβάθμια, **risk-centric** μεθοδολογία. Περιλαμβάνει τον καθορισμό και την ταυτοποίηση των στόχων ασφάλειας, τη δημιουργία τεχνικού πεδίου, την αποσύνθεση εφαρμογών, την ανάλυση απειλών, την ανάλυση ευπαθειών και την αξιολόγηση κινδύνου/triage.
4. **Trike**: Αυτή είναι μια μεθοδολογία βασισμένη στον κίνδυνο που επικεντρώνεται στην άμυνα των περιουσιακών στοιχείων. Ξεκινά από μια **οπτική διαχείρισης κινδύνου** και εξετάζει τις απειλές και τις ευπάθειες σε αυτό το πλαίσιο.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Αυτή η προσέγγιση στοχεύει να είναι πιο προσβάσιμη και ενσωματώνεται σε περιβάλλοντα Agile ανάπτυξης. Συνδυάζει στοιχεία από τις άλλες μεθοδολογίες και επικεντρώνεται σε **οπτικές αναπαραστάσεις απειλών**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Αναπτυγμένο από το CERT Coordination Center, αυτό το πλαίσιο προορίζεται για **αξιολόγηση οργανωτικού κινδύνου παρά συγκεκριμένων συστημάτων ή λογισμικού**.

## Tools

Υπάρχουν αρκετά εργαλεία και λύσεις λογισμικού διαθέσιμα που μπορούν να **βοηθήσουν** στη δημιουργία και διαχείριση threat models. Ακολουθούν μερικά που μπορεί να εξετάσετε.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Ένας προηγμένος διασυνοριακός και πολυλειτουργικός GUI web spider/crawler για επαγγελματίες κυβερνοασφάλειας. Το Spider Suite μπορεί να χρησιμοποιηθεί για χαρτογράφηση και ανάλυση επιφάνειας επίθεσης.

**Usage**

1. Pick a URL and Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. View Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Ένα ανοιχτού κώδικα έργο από το OWASP, το Threat Dragon είναι τόσο μια διαδικτυακή όσο και μια επιτραπέζια εφαρμογή που περιλαμβάνει διαγράμματα συστημάτων καθώς και μια μηχανή κανόνων για αυτόματη δημιουργία απειλών/μετριασμών.

**Usage**

1. Create New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Sometimes it could look like this:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Launch New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Save The New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Create your model

You can use tools like SpiderSuite Crawler to give you inspiration, a basic model would look something like this

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Just a little bit of explanation about the entities:

- Process (The entity itself such as Webserver or web functionality)
- Actor (A Person such as a Website Visitor, User or Administrator)
- Data Flow Line (Indicator of Interaction)
- Trust Boundary (Different network segments or scopes.)
- Store (Things where data are stored at such as Databases)

5. Create a Threat (Step 1)

First you have to pick the layer you wish to add a threat to

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Now you can create the threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Keep in mind that there is a difference between Actor Threats and Process Threats. If you would add a threat to an Actor then you will only be able to choose "Spoofing" and "Repudiation. However in our example we add threat to a Process entity so we will see this in the threat creation box:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Done

Now your finished model should look something like this. And this is how you make a simple threat model with OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Αυτό είναι ένα δωρεάν εργαλείο από τη Microsoft που βοηθά στην εύρεση απειλών στη φάση σχεδίασης των έργων λογισμικού. Χρησιμοποιεί τη μεθοδολογία STRIDE και είναι ιδιαίτερα κατάλληλο για εκείνους που αναπτύσσουν στην πλατφόρμα της Microsoft.
