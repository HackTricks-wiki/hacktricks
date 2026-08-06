# Άλλα Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Πολλές φορές το back-end εμπιστεύεται το **Host header** για την εκτέλεση ορισμένων ενεργειών. Για παράδειγμα, μπορεί να χρησιμοποιεί την τιμή του ως το **domain στο οποίο θα στείλει ένα password reset**. Επομένως, όταν λαμβάνετε ένα email με σύνδεσμο για την επαναφορά του password σας, το domain που χρησιμοποιείται είναι αυτό που βάλατε στο Host header. Έπειτα, μπορείτε να ζητήσετε το password reset άλλων χρηστών και να αλλάξετε το domain σε ένα που ελέγχετε, ώστε να κλέψετε τους κωδικούς password reset. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Σημειώστε ότι είναι πιθανό να μη χρειάζεται καν να περιμένετε τον χρήστη να κάνει click στον σύνδεσμο reset password για να λάβετε το token, καθώς ίσως ακόμη και **spam filters ή άλλες ενδιάμεσες συσκευές/bots κάνουν click σε αυτόν για να τον αναλύσουν**.

### Session booleans

Μερικές φορές, όταν ολοκληρώνετε σωστά κάποιο verification, το back-end **απλώς προσθέτει ένα boolean με την τιμή "True" σε ένα security attribute του session σας**. Έπειτα, ένα διαφορετικό endpoint θα γνωρίζει αν περάσατε επιτυχώς αυτόν τον έλεγχο.\
Ωστόσο, αν **περάσετε τον έλεγχο** και στο session σας εκχωρηθεί η τιμή "True" στο security attribute, μπορείτε να δοκιμάσετε να **αποκτήσετε πρόσβαση σε άλλους πόρους** που **εξαρτώνται από το ίδιο attribute**, αλλά στους οποίους **δεν θα έπρεπε να έχετε permissions**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Λειτουργία εγγραφής

Δοκιμάστε να εγγραφείτε ως ένας ήδη υπάρχων χρήστης. Δοκιμάστε επίσης να χρησιμοποιήσετε ισοδύναμους χαρακτήρες (τελείες, πολλά κενά και Unicode).

### Κατάληψη email

Κάντε register ένα email και, πριν το επιβεβαιώσετε, αλλάξτε το email. Έπειτα, αν το νέο email επιβεβαίωσης σταλεί στο πρώτο email που καταχωρίστηκε, μπορείτε να κάνετε takeover οποιουδήποτε email. Ή, αν μπορείτε να ενεργοποιήσετε το δεύτερο email επιβεβαιώνοντας το πρώτο, μπορείτε επίσης να κάνετε takeover οποιουδήποτε account.

### Πρόσβαση στο Internal servicedesk εταιρειών που χρησιμοποιούν Atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Οι developers μπορεί να ξεχάσουν να απενεργοποιήσουν διάφορες επιλογές debugging στο production environment. Για παράδειγμα, η HTTP `TRACE` method έχει σχεδιαστεί για διαγνωστικούς σκοπούς. Αν είναι ενεργοποιημένη, ο web server θα απαντά σε requests που χρησιμοποιούν τη `TRACE` method, επιστρέφοντας στην response το ακριβές request που έλαβε. Αυτή η συμπεριφορά είναι συνήθως ακίνδυνη, αλλά περιστασιακά οδηγεί σε disclosure πληροφοριών, όπως το όνομα εσωτερικών authentication headers που μπορεί να προστίθενται στα requests από reverse proxies.![Εικόνα για την ανάρτηση](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Εικόνα για την ανάρτηση](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
