# Μοντελοποίηση Απειλών

{{#include ../banners/hacktricks-training.md}}

Καλώς ήρθατε στον ολοκληρωμένο οδηγό του HackTricks για τη Μοντελοποίηση Απειλών! Ξεκινήστε μια εξερεύνηση αυτής της κρίσιμης πτυχής της κυβερνοασφάλειας, όπου εντοπίζουμε, κατανοούμε και σχεδιάζουμε στρατηγικές αντιμετώπισης πιθανών ευπαθειών σε ένα σύστημα. Αυτό το thread λειτουργεί ως οδηγός βήμα προς βήμα, γεμάτος παραδείγματα από τον πραγματικό κόσμο, χρήσιμο software και εύκολες στην κατανόηση εξηγήσεις. Είναι ιδανικός τόσο για αρχάριους όσο και για έμπειρους επαγγελματίες που θέλουν να ενισχύσουν τις άμυνες κυβερνοασφάλειας.

### Συνήθεις περιπτώσεις χρήσης

1. **Ανάπτυξη Software**: Ως μέρος του Secure Software Development Life Cycle (SSDLC), η μοντελοποίηση απειλών βοηθά στον **εντοπισμό πιθανών πηγών ευπαθειών** στα πρώτα στάδια της ανάπτυξης.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Το Penetration Testing Execution Standard (PTES) θεωρεί τη μοντελοποίηση απειλών απαραίτητη για τη σωστή εκτέλεση και απαιτεί την τεκμηρίωση των business assets, των business processes, των threat communities και των δυνατοτήτων τους.<sup>[[2]](#references)</sup>

### Το Threat Model με λίγα λόγια

Ένα threat model αναπαρίσταται συνήθως ως διάγραμμα, εικόνα ή άλλη οπτική απεικόνιση μιας σχεδιαζόμενης αρχιτεκτονικής ή μιας υπάρχουσας εφαρμογής. Τα διαγράμματα ροής δεδομένων (DFDs) αποτελούν έναν συνηθισμένο τρόπο μοντελοποίησης ενός συστήματος και των αλληλεπιδράσεών του, ενώ η μοντελοποίηση απειλών προσθέτει μια ανάλυση με επίκεντρο την ασφάλεια.<sup>[[1]](#references)</sup>

Στο Microsoft's Threat Modeling Tool, οι κόκκινες διακεκομμένες γραμμές υποδεικνύουν trust boundaries· άλλα εργαλεία μπορεί να χρησιμοποιούν διαφορετικές οπτικές συμβάσεις.<sup>[[4]](#references)</sup> Για την απλοποίηση του εντοπισμού κινδύνων, οι ομάδες μπορούν να χρησιμοποιούν την τριάδα CIA (Confidentiality, Integrity, Availability) ή τις κατηγορίες απειλών STRIDE, όμως η κατάλληλη μεθοδολογία εξαρτάται από το πλαίσιο και τις απαιτήσεις του project.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Η τριάδα CIA

Η τριάδα CIA είναι ένα ευρέως αναγνωρισμένο μοντέλο ασφάλειας πληροφοριών που αντιστοιχεί στις έννοιες Confidentiality, Integrity και Availability. Αυτές οι ιδιότητες χρησιμοποιούνται συνήθως για την περιγραφή των στόχων ασφάλειας για δεδομένα και συστήματα.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Η διασφάλιση ότι τα δεδομένα ή το σύστημα δεν είναι προσβάσιμα από μη εξουσιοδοτημένα άτομα. Πρόκειται για κεντρική πτυχή της ασφάλειας, η οποία απαιτεί κατάλληλους μηχανισμούς ελέγχου πρόσβασης, κρυπτογράφηση και άλλα μέτρα για την αποτροπή data breaches.
2. **Integrity**: Η ακρίβεια, η συνέπεια και η αξιοπιστία των δεδομένων καθ' όλη τη διάρκεια του κύκλου ζωής τους. Αυτή η αρχή διασφαλίζει ότι τα δεδομένα δεν τροποποιούνται ή παραποιούνται από μη εξουσιοδοτημένα μέρη. Συχνά περιλαμβάνει checksums, hashing και άλλες μεθόδους επαλήθευσης δεδομένων.
3. **Availability**: Διασφαλίζει ότι τα δεδομένα και οι υπηρεσίες είναι προσβάσιμα σε εξουσιοδοτημένους χρήστες όταν απαιτείται. Αυτό συχνά περιλαμβάνει redundancy, fault tolerance και διαμορφώσεις high-availability, ώστε τα συστήματα να συνεχίζουν να λειτουργούν ακόμη και σε περίπτωση διακοπών.

### Μεθοδολογίες Μοντελοποίησης Απειλών

1. **STRIDE**: Η προσέγγιση STRIDE της Microsoft κατηγοριοποιεί τις απειλές software ως **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service και Elevation of Privilege**. Αυτές οι κατηγορίες βοηθούν τους αναλυτές να εντοπίζουν πιθανές απειλές σε κάθε ευάλωτο σημείο ενός design.<sup>[[5]](#references)</sup>
2. **DREAD**: Αυτή η προσέγγιση αξιολόγησης της Microsoft βαθμολογεί τις απειλές χρησιμοποιώντας τα **Damage, Reproducibility, Exploitability, Affected users και Discoverability**. Η προκύπτουσα βαθμολογία μπορεί να βοηθήσει στην ιεράρχηση των απειλών για mitigation.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Πρόκειται για μια μεθοδολογία επτά σταδίων, **risk-centric**, που καλύπτει τους στόχους, το technical scope, την αποσύνθεση της εφαρμογής, την ανάλυση απειλών, την ανάλυση ευπαθειών και αδυναμιών, το attack modeling και την ανάλυση κινδύνου/επιπτώσεων.<sup>[[8]](#references)</sup>
4. **Trike**: Αυτό το framework ελέγχου ασφάλειας προσεγγίζει τη μοντελοποίηση απειλών από μια **risk-management** και αμυντική σκοπιά.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Αυτή η μέθοδος δίνει έμφαση σε scalable και εύχρηστα threat models για application και operational views και μπορεί να ενσωματωθεί σε development και DevOps lifecycles.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Δημιουργήθηκε από το CERT Division του Software Engineering Institute του Carnegie Mellon. Το OCTAVE είναι μια στρατηγική μέθοδος αξιολόγησης και σχεδιασμού βασισμένη στον κίνδυνο, η οποία εστιάζει στον οργανωτικό κίνδυνο και όχι μόνο στην τεχνολογία.<sup>[[10]](#references)</sup>

## Εργαλεία

Υπάρχουν αρκετά εργαλεία και software solutions που μπορούν να **βοηθήσουν** στη δημιουργία και διαχείριση threat models. Ακολουθούν μερικά που μπορείτε να εξετάσετε.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Το SpiderSuite είναι ένα cross-platform web crawler για security professionals, το οποίο υποστηρίζει attack-surface mapping, endpoint discovery και web-application analysis.<sup>[[6]](#references)</sup>

**Χρήση**

1. Επιλέξτε ένα URL και εκτελέστε Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Προβάλετε το Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Το OWASP Threat Dragon είναι μια δωρεάν, open-source, cross-platform εφαρμογή threat modeling για τη δημιουργία διαγραμμάτων, την υπόδειξη απειλών και την καταγραφή mitigations. Διατίθεται ως web και desktop application.<sup>[[7]](#references)</sup>

**Χρήση**

1. Δημιουργήστε New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Μερικές φορές μπορεί να μοιάζει κάπως έτσι:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Εκκινήστε το New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Αποθηκεύστε το New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Δημιουργήστε το model σας

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το SpiderSuite Crawler για να πάρετε έμπνευση. Ένα βασικό model θα μπορούσε να μοιάζει κάπως έτσι:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Μια σύντομη εξήγηση για τα entities:

- Process (Η ίδια η entity, όπως ένας Webserver ή web functionality)
- Actor (Ένα άτομο, όπως ένας Website Visitor, User ή Administrator)
- Data Flow Line (Ένδειξη αλληλεπίδρασης)
- Trust Boundary (Διαφορετικά network segments ή scopes.)
- Store (Στοιχεία όπου αποθηκεύονται δεδομένα, όπως Databases)

5. Δημιουργήστε ένα Threat (Step 1)

Αρχικά πρέπει να επιλέξετε το layer στο οποίο θέλετε να προσθέσετε μια απειλή

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Τώρα μπορείτε να δημιουργήσετε την απειλή

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Λάβετε υπόψη ότι υπάρχει διαφορά μεταξύ Actor Threats και Process Threats. Αν προσθέσετε μια απειλή σε έναν Actor, θα μπορείτε να επιλέξετε μόνο τα "Spoofing" και "Repudiation". Ωστόσο, στο παράδειγμά μας προσθέτουμε απειλή σε μια Process entity, επομένως στο threat creation box θα δούμε τα εξής:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Ολοκληρώθηκε

Τώρα το ολοκληρωμένο model σας θα πρέπει να μοιάζει κάπως έτσι. Με αυτόν τον τρόπο δημιουργείτε ένα απλό threat model με το OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Το Microsoft's Threat Modeling Tool είναι ένα δωρεάν downloadable εργαλείο για την ανάλυση software design. Η ροή εργασίας του δημιουργεί ένα διάγραμμα, εντοπίζει απειλές και υποστηρίζει mitigation και validation χρησιμοποιώντας την προσέγγιση STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Cheat Sheet Μοντελοποίησης Απειλών](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Μοντελοποίηση Απειλών - Το Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Βασικές αρχές ασφάλειας - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Ξεκινώντας με το Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Μοντελοποίηση Απειλών για Drivers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Μοντελοποίηση Απειλών με PASTA: Τα 7 Στάδια εξηγημένα](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Έγγραφο Μεθοδολογίας Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Μοντελοποίηση Απειλών: Σύνοψη των διαθέσιμων μεθόδων](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
