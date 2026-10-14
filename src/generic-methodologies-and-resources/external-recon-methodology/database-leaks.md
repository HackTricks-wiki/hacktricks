# Database leaks

{{#include ../../banners/hacktricks-training.md}}

## Μηχανές αναζήτησης παραβιάσεων δεδομένων

Για πρόσβαση μέσω API και επισημάνσεις ειδικές για κάθε υπηρεσία κατά την αναζήτηση δεδομένων παραβιάσεων ή φήμης, δείτε τον [κατάλογο API Αναγνώρισης και Πληροφοριών Απειλών](reconnaissance-and-threat-intelligence-apis.md).

- [GreyNoise Visualizer](https://viz.greynoise.io/) - Αναζητήστε IP και CIDR και ελέγξτε τη δραστηριότητα σαρωτών με βάση tags, CVE και μεταδεδομένα.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - Αναζητήστε εκτεθειμένα δεδομένα με βάση ονόματα χρηστών, διευθύνσεις email, διευθύνσεις IP και άλλα κριτήρια· διατίθενται επίσης παρακολούθηση και API.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Ελέγξτε αν μια διεύθυνση email εμφανίζεται σε γνωστές παραβιάσεις δεδομένων ή αρχεία paste· διατίθενται επίσης ειδοποιήσεις και API.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - Αναζητήστε αναφορές απατεώνων με βάση φωτογραφία προφίλ, email, όνομα χρήστη, αριθμό τηλεφώνου, διεύθυνση crypto ή ιστότοπο.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - Αναζητήστε κριτήρια όπως διευθύνσεις email, domains, URL, IP και CIDR σε ευρετηριασμένες πηγές.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - Ελέγξτε ένα εταιρικό email ή domain για εκτεθειμένα διαπιστευτήρια, ταυτότητες που έχουν μολυνθεί από infostealer και κλεμμένα session cookies.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - Αναζητήστε leaked βάσεις δεδομένων με βάση domains, ονόματα, email, ID, τηλέφωνα, IP, URL ή hashes.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - Ελέγξτε αν το email ή το όνομα χρήστη σας έχει παραβιαστεί.
- [LeakCheck](https://leakcheck.io/) - Αναζητήστε εκτεθειμένα δεδομένα email, ονόματος χρήστη, τηλεφώνου, hash ή domain και παρακολουθήστε για νέες καταχωρίσεις.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - Βρείτε διευθύνσεις email για μια συγκεκριμένη εταιρεία.
- [Library of Leaks](https://search.libraryofleaks.org/) - Αναζητήστε δημόσια έγγραφα, εταιρείες και άτομα, συμπεριλαμβανομένων συνόλων δεδομένων leak.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - Αναζητήστε leaked διαπιστευτήρια με βάση email, domain ή ακατέργαστη συμβολοσειρά και παρακολουθήστε νέες εκθέσεις.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - Αναζητήστε αρχεία καταγραφής infostealer από μολυσμένες συσκευές και παρακολουθήστε νέα δεδομένα.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - Αναζητήστε σε παραβιάσεις δεδομένων και παρακολουθήστε την έκθεση διαπιστευτηρίων.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - Μηχανή αναζήτησης παραβιάσεων βάσεων δεδομένων με συνεισφορές της κοινότητας.
- [Leaked.domains](https://leaked.domains/) - Αναζητήστε leaked διαπιστευτήρια και σχετικά αρχεία με βάση domain, email, όνομα χρήστη, κωδικό πρόσβασης, IP και άλλα κριτήρια.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - Παρακολουθήστε δραστηριότητα στο dark web, διαρροές διαπιστευτηρίων, δεδομένα infostealer και αναφορές σε επωνυμίες.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Πλατφόρμα αναζήτησης και παρακολούθησης dump του Pastebin.

## Εργαλεία καταγραφής data leaks

- [Leaker](https://github.com/vflame6/leaker) - Παθητικό CLI εντοπισμού leaks, το οποίο αναζητά σε πολλές διαδικτυακές πηγές με βάση email, όνομα χρήστη, domain, λέξη-κλειδί ή τηλέφωνο.<sup>[[15]](#references)</sup>

## References

- [1] [Χρήση του GreyNoise Visualizer](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Παγκόσμια βάση δεδομένων απατεώνων - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [Ελέγξτε την έκθεσή σας - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Μηχανή αναζήτησης παραβιάσεων δεδομένων - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - Μηχανή αναζήτησης παραβιάσεων δεδομένων](https://leak-lookup.com/)
- [13] [Leaked.Domains - Καθολική αναζήτηση](https://leaked.domains/)
- [14] [WhiteIntel - Πλατφόρμα πληροφοριών και παρακολούθησης του Dark Web](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
