# Άλλα Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Πολλές φορές το back-end εμπιστεύεται το **Host header** για την εκτέλεση ορισμένων ενεργειών. Για παράδειγμα, μπορεί να χρησιμοποιεί την τιμή του ως το **domain στο οποίο θα στείλει ένα password reset**. Έτσι, όταν λαμβάνεις ένα email με link για την επαναφορά του password σου, το domain που χρησιμοποιείται είναι αυτό που έβαλες στο Host header.Στη συνέχεια, μπορείς να ζητήσεις το password reset άλλων χρηστών και να αλλάξεις το domain σε ένα που ελέγχεις εσύ, ώστε να κλέψεις τους κωδικούς επαναφοράς του password τους. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Σημείωσε ότι ίσως να μην χρειάζεται καν να περιμένεις τον χρήστη να κάνει click στο link επαναφοράς του password για να λάβεις το token, καθώς μπορεί ακόμη και **τα spam filters ή άλλες ενδιάμεσες συσκευές/bots να κάνουν click σε αυτό για να το αναλύσουν**.

### Session booleans

Μερικές φορές, όταν ολοκληρώνεις σωστά κάποιο verification, το back-end **απλώς προσθέτει ένα boolean με την τιμή "True" σε ένα security attribute του session σου**. Στη συνέχεια, ένα διαφορετικό endpoint θα γνωρίζει αν πέρασες επιτυχώς αυτόν τον έλεγχο.\
Ωστόσο, αν **περάσεις τον έλεγχο** και στο session σου εκχωρηθεί αυτή η τιμή "True" στο security attribute, μπορείς να δοκιμάσεις να **αποκτήσεις πρόσβαση σε άλλους πόρους** που **εξαρτώνται από το ίδιο attribute**, αλλά στους οποίους **δεν θα έπρεπε να έχεις δικαιώματα πρόσβασης**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Δοκίμασε να κάνεις register ως ήδη υπάρχων χρήστης. Δοκίμασε επίσης να χρησιμοποιήσεις equivalent characters (τελείες, πολλά spaces και Unicode).

### Takeover emails

Κάνε register ένα email και, πριν το επιβεβαιώσεις, άλλαξε το email. Στη συνέχεια, αν το νέο confirmation email σταλεί στο πρώτο email που καταχωρίστηκε, μπορείς να κάνεις takeover οποιουδήποτε email. Ή, αν μπορείς να ενεργοποιήσεις το δεύτερο email επιβεβαιώνοντας το πρώτο, μπορείς επίσης να κάνεις takeover οποιουδήποτε account.

### Πρόσβαση στο Internal servicedesk εταιρειών που χρησιμοποιούν atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Οι developers μπορεί να ξεχάσουν να απενεργοποιήσουν διάφορες debugging options στο production environment. Για παράδειγμα, η HTTP `TRACE` method έχει σχεδιαστεί για διαγνωστικούς σκοπούς. Αν είναι ενεργοποιημένη, ο web server θα απαντά σε requests που χρησιμοποιούν τη `TRACE` method, επιστρέφοντας στην απόκριση το ακριβές request που ελήφθη. Αυτή η συμπεριφορά είναι συχνά ακίνδυνη, αλλά περιστασιακά οδηγεί σε information disclosure, όπως η αποκάλυψη του ονόματος εσωτερικών authentication headers που μπορεί να προστίθενται στα requests από reverse proxies.![Εικόνα για την ανάρτηση](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Εικόνα για την ανάρτηση](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Πώς κατάφερα να κάνω takeover οποιουδήποτε account χρήστη με Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Ένα λιγότερο γνωστό attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
