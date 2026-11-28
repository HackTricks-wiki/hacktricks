# Αναγνώριση και APIs Πληροφοριών Απειλών

{{#include ../../banners/hacktricks-training.md}}

Αυτές οι υπηρεσίες υποστηρίζουν ροές εργασίας αναγνώρισης, αξιολόγησης φήμης, εντοπισμού διαρροών ή εμπλουτισμού δεδομένων. Τα API, τα όρια χρήσης, οι τιμές και οι επιτρεπόμενες χρήσεις αλλάζουν συχνά· πριν στείλετε αναγνωριστικά πελατών ή ευαίσθητα δεδομένα, επιβεβαιώστε την τρέχουσα τεκμηρίωση του παρόχου και την εξουσιοδότηση για την ανάθεση. Για την ακολουθία εντοπισμού assets, ανατρέξτε στη [Μεθοδολογία Εξωτερικής Αναγνώρισης](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP έχει συσχετιστεί με ύποπτη ή κακόβουλη δραστηριότητα. Ενδέχεται να απαιτείται λογαριασμός ή API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP, ένα όνομα χρήστη ή μια διεύθυνση email έχει συσχετιστεί με αυτοματοποιημένη εγγραφή λογαριασμών ή άλλη αναφερθείσα δραστηριότητα bot.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Εντοπίστε και επαληθεύστε επαγγελματικές διευθύνσεις email και μοτίβα επικοινωνίας που σχετίζονται με domains. Ελέγξτε το τρέχον πρόγραμμα για τα όρια αιτημάτων και τις επιτρεπόμενες χρήσεις.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Αναζητήστε δείκτες πληροφοριών απειλών και δραστηριότητες που σχετίζονται με διευθύνσεις IP και domains.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Εμπλουτίστε μια διεύθυνση email, ένα domain ή μια εταιρεία με διαθέσιμα επιχειρηματικά δεδομένα ή δεδομένα προφίλ. Η κάλυψη, η πρόσβαση και οι περιορισμοί απορρήτου εξαρτώνται από το τρέχον προϊόν και πρόγραμμα.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Εντοπίστε τεχνολογίες που έχουν παρατηρηθεί σε ιστοτόπους και λάβετε ιστορικά δεδομένα ή δεδομένα συσχετίσεων, εφόσον το επιτρέπει το επιλεγμένο πρόγραμμα.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP σχετίζεται με ύποπτη ή κακόβουλη δραστηριότητα. Επιβεβαιώστε τα τρέχοντα προγράμματα και όρια του API.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Αναζητήστε την κατηγοριοποίηση FortiGuard και πληροφορίες απειλών για domains, URLs ή διευθύνσεις IP. Η διαθεσιμότητα διαφέρει ανά υπηρεσία.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP έχει καταχωριστεί για αναφερθείσα δραστηριότητα spam.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Λάβετε τη φήμη ενός domain, βάσει της κοινότητας της υπηρεσίας και άλλων σημάτων.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Λάβετε γεωγραφική θέση, ASN, οργανισμό και σχετικά μεταδεδομένα για μια διεύθυνση IP. Ελέγξτε το τρέχον πρόγραμμα για τα όρια χρήσης.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Αυτή η πλατφόρμα παρέχει πληροφορίες DNS και υποδομών, όπως ιστορικές αναλύσεις, domains που σχετίζονται με IP ή name servers και συναφείς εγγραφές. Το ιστορικό DNS μπορεί να αποκαλύψει μια προηγούμενη διεύθυνση προέλευσης, αλλά δεν παρακάμπτει αξιόπιστα ένα CDN και πρέπει να επαληθεύεται.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Εμπλουτίστε μια διεύθυνση email, ένα domain ή ένα όνομα εταιρείας με διαθέσιμα χαρακτηριστικά ταυτότητας και επιχειρηματικά στοιχεία. Χειριστείτε προσωπικά δεδομένα σύμφωνα με τις απαιτήσεις εξουσιοδότησης και απορρήτου.

## RiskIQ / Microsoft Defender Threat Intelligence (παλαιότερη μετάβαση) <sup>[[14]](#references)</sup>

Οι δυνατότητες PassiveTotal της RiskIQ μεταφέρθηκαν στο Microsoft Defender Threat Intelligence. Η πρόσβαση στα προϊόντα, τα API και οι διαθέσιμες λειτουργίες έχουν αλλάξει, επομένως χρησιμοποιήστε την τρέχουσα τεκμηρίωση της Microsoft και όχι παλαιότερες παραδοχές για το PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Αναζητήστε domains, διευθύνσεις IP, διευθύνσεις email και δεδομένα ιστορικού ή διαρροών που έχουν ευρετηριαστεί, σύμφωνα με τους ελέγχους πρόσβασης της υπηρεσίας.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Αναζητήστε διευθύνσεις IP και άλλους δείκτες για δεδομένα πληροφοριών απειλών και φήμης.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Αναζητήστε διευθύνσεις IP ή εύρη διευθύνσεων για παρατηρήσεις διαδικτυακής σάρωσης και συνήθους δραστηριότητας υπηρεσιών. Ελέγξτε τους τρέχοντες όρους δοκιμαστικής και κοινοτικής πρόσβασης.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Λάβετε πληροφορίες διαδικτυακής σάρωσης και υπηρεσιών για μια διεύθυνση IP, ένα host ή ένα ερώτημα αναζήτησης. Η πρόσβαση στο API εξαρτάται από το πρόγραμμα του λογαριασμού.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Αναζητήστε σύνολα δεδομένων για hosts, πιστοποιητικά, domains και υπηρεσίες διαδικτύου· το μοντέλο δεδομένων και η κάλυψή του διαφέρουν από εκείνα του Shodan.

## [Αναζήτηση bucket στο GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Αναζητήστε με λέξεις-κλειδιά στο ευρετήριο του παρόχου για αντικείμενα και buckets αποθήκευσης cloud που έχουν παρατηρηθεί δημόσια.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Αναζητήστε σε ευρετηριασμένα δεδομένα διαρροών διευθύνσεις email, ονόματα χρηστών, domains και σχετικά αρχεία. Χρησιμοποιήστε την υπηρεσία μόνο με εξουσιοδότηση και αποφύγετε την περιττή έκθεση δεδομένων διαρροών.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Αναζητήστε σε ευρετηριασμένο περιεχόμενο paste την εμφάνιση μιας διεύθυνσης email ή άλλου όρου. Βεβαιωθείτε ότι η υπηρεσία εξακολουθεί να είναι διαθέσιμη πριν την ενσωματώσετε.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Λάβετε σήματα φήμης και κινδύνου για μια διεύθυνση email.

## GhostProject (ιστορικά) <sup>[[24]](#references)</sup>

Ιστορικά διαφημιζόταν ως υπηρεσία αναζήτησης σε δεδομένα διαρροών email/κωδικών πρόσβασης. Αντιμετωπίστε την υπηρεσία ως υψηλού κινδύνου για τη διαχείριση δεδομένων από τρίτους και επαληθεύστε τη διαθεσιμότητα, τη νομιμότητα και την εξουσιοδότηση πριν τη χρήση.

## BinaryEdge (διακοπή λειτουργίας) <sup>[[25]](#references)</sup>

Προσέφερε δεδομένα διαδικτυακής σάρωσης, έκθεσης και πληροφοριών απειλών για διευθύνσεις IP και σχετικά assets. Ο ιστότοπός του πλέον ανακατευθύνει σε ανακοίνωση μετάβασης της Coalition και το API απορρίπτει αιτήματα, επομένως θεωρήστε την υπηρεσία μη διαθέσιμη.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Ελέγξτε αν μια διεύθυνση email ή ένα επαληθευμένο domain εμφανίζεται σε γνωστές διαρροές. Η ξεχωριστή υπηρεσία Pwned Passwords ελέγχει hashes κωδικών πρόσβασης βάσει προθέματος· **δεν** αποκαλύπτει κωδικούς πρόσβασης σε απλό κείμενο.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Λάβετε γεωγραφική θέση IP, κέντρο δεδομένων, ASN, proxy/VPN και σχετικά πεδία εμπλουτισμού. Τα όρια χρήσης εξαρτώνται από το τρέχον πρόγραμμα.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Εμπλουτισμός γεωγραφικής θέσης IP και προσανατολισμένος στο OSINT, με επιλεγμένα σημεία δεδομένων. Ελέγξτε τους τρέχοντες όρους για εμπορική χρήση.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Αναζητήστε ένα domain (καταχωρητή, ημερομηνίες εγγραφής και λήξης, name servers, IP φιλοξενίας και χώρα) ή μια διεύθυνση IP (τα άλλα domains που φιλοξενούνται σε αυτήν) και ελέγξτε αν ένα domain ή IP περιλαμβάνεται στις δωρεάν λίστες παραβίασης της υπηρεσίας: domains phishing και sinkholed malware, καθώς και διευθύνσεις που επιτέθηκαν στους αισθητήρες honeypot της τις τελευταίες 48 ώρες. Οι διαδικτυακές αναζητήσεις και το API ελέγχου παραβίασης δεν απαιτούν λογαριασμό· η πρόσβαση API στις αναζητήσεις απαιτεί συνδρομή επί πληρωμή.


Το [DNSDumpster](https://dnsdumpster.com/) παρέχει αποτελέσματα αναγνώρισης DNS.<sup>[[29]](#references)</sup>

Το [Netcraft](https://www.netcraft.com/) παρέχει πληροφορίες για ιστοτόπους, φιλοξενία και διαδικτυακές υποδομές.<sup>[[30]](#references)</sup>

Το [NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) παρέχει διαδικτυακή διεπαφή εντοπισμού subdomain.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Έρευνα Cornell — Πρωτόκολλα ελέγχου παραβιασμένων διαπιστευτηρίων (περιλαμβάνει το GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Εύρεση subdomain NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [Τεκμηρίωση API NetAPI](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
