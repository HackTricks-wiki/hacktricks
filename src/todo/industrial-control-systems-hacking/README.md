# Hacking Βιομηχανικών Συστημάτων Ελέγχου

{{#include ../../banners/hacktricks-training.md}}

## Σχετικά με αυτή την ενότητα

Αυτή η ενότητα παρουσιάζει τα components, τις αρχιτεκτονικές, τα πρωτόκολλα και τις μεθόδους αξιολόγησης ασφάλειας των industrial control systems (ICS). Το ICS αποτελεί μέρος του ευρύτερου domain της operational technology (OT): programmable systems και συσκευές που παρακολουθούν ή προκαλούν αλλαγές σε φυσικές διεργασίες. Συνήθη παραδείγματα περιλαμβάνουν συστήματα supervisory control and data acquisition (SCADA), distributed control systems (DCSs) και programmable logic controllers (PLCs).<sup>[[1]](#references)</sup>

Η εργασία ασφάλειας σε αυτά τα περιβάλλοντα πρέπει να λαμβάνει υπόψη απαιτήσεις που διαφέρουν από εκείνες του συμβατικού IT, όπως η ασφάλεια διεργασιών, η αξιοπιστία, η διαθεσιμότητα, η deterministic λειτουργία και οι κύκλοι ζωής του εξοπλισμού. Ένα τεχνικά έγκυρο security control μπορεί και πάλι να είναι ακατάλληλο αν διαταράξει τη φυσική διεργασία, επομένως το testing και το remediation πρέπει να συντονίζονται με τον ιδιοκτήτη του συστήματος και το προσωπικό operations.<sup>[[1]](#references)</sup>

## Προτεραιότητες Αξιολόγησης

Ξεκινήστε κατανοώντας την ελεγχόμενη διεργασία, τα όρια του συστήματος, την τοπολογία του δικτύου, τα assets, τις ροές δεδομένων, τις σχέσεις εμπιστοσύνης και τις εξωτερικές συνδέσεις. Παρόμοιοι τύποι συσκευών μπορεί να εξυπηρετούν διαφορετικές λειτουργίες σε διαφορετικές εγκαταστάσεις, επομένως αποφύγετε να υποθέσετε ότι η αρχιτεκτονική ή το μοντέλο επιπτώσεων μιας deployment ισχύει και για κάποια άλλη.<sup>[[1]](#references)</sup>

Προτιμήστε το passive discovery και την υπάρχουσα engineering τεκμηρίωση όπου είναι δυνατό. Οποιοδήποτε active scanning ή exploitation πρέπει να ακολουθεί ένα εγκεκριμένο test plan που καθορίζει περιορισμούς ασφάλειας, maintenance windows, διαδικασίες recovery και stop conditions. Τα findings πρέπει να αξιολογούνται τόσο ως προς τον αντίκτυπο στην cybersecurity όσο και ως προς τις πιθανές επιπτώσεις στη φυσική διεργασία.<sup>[[1]](#references)</sup>

Η ίδια αρχιτεκτονική γνώση υποστηρίζει defensive δραστηριότητες όπως το asset inventory, το network segmentation, το monitoring, το incident response και το risk-based vulnerability management.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Οδηγός για την ασφάλεια της Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
