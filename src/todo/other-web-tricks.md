# Άλλα Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

Τα back ends μερικές φορές εμπιστεύονται το πεδίο HTTP `Host` κατά τη δημιουργία absolute links. Αν ένα email επαναφοράς κωδικού πρόσβασης χρησιμοποιεί host που παρέχεται από attacker, η αίτηση επαναφοράς για ένα θύμα μπορεί να στείλει ένα link που περιέχει token μέσω ενός domain που ελέγχεται από τον attacker. Επίσης, ελέγξτε τα forwarded-host fields, τη διαχείριση διπλότυπων Host και τα request targets σε absolute-form σε κάθε proxy hop.<sup>[[1]](#references)</sup>

> [!WARNING]
> Ένα click από τον χρήστη μπορεί να μην είναι απαραίτητο: **mail security scanners, preview services ή άλλοι intermediaries μπορούν να ζητήσουν αυτόματα το link που ελέγχεται από τον attacker**, αποκαλύπτοντας το reset token.

## Session booleans

Ορισμένες εφαρμογές καταγράφουν μια ολοκληρωμένη verification ως boolean στο session και στη συνέχεια επιτρέπουν σε ένα διαφορετικό endpoint να βασιστεί σε αυτό το flag. Αφού περάσετε νόμιμα τον έλεγχο για ένα resource, ελέγξτε αν το ίδιο flag παρέχει εσφαλμένα authorization σε διαφορετικό user, object ή workflow. Αυτό είναι flaw δεύτερης τάξης στο authorization/state-reuse και όχι απλώς ένα IDOR.<sup>[[2]](#references)</sup>

## Registration functionality

Δοκιμάστε να κάνετε register ως ήδη υπάρχων user. Δοκιμάστε επίσης equivalent characters (τελείες, πολλά spaces και Unicode).

## Email-change state confusion

Κάντε register μια email address και αλλάξτε την πριν από την επιβεβαίωση. Ελέγξτε αν η confirmation για τη νέα address αποστέλλεται στην παλιά address ή αν η επιβεβαίωση του παλιού token ενεργοποιεί τη νέα address. Τα confirmation tokens πρέπει να συνδέονται με το ακριβές account, την pending address, τον σκοπό και την τρέχουσα κατάσταση.

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

Η HTTP μέθοδος `TRACE` ζητά loop-back του request που ελήφθη για σκοπούς diagnostics. Το RFC 9110 απαιτεί από τους recipients να παραλείπουν sensitive fields, όπως credentials και cookies, από το reflected content, όμως μη ασφαλείς implementations ή headers που προστέθηκαν από intermediaries μπορεί να αποκαλύψουν μετασχηματισμούς του internal request. Τα browsers αποτρέπουν TRACE requests που δημιουργούνται από scripts, επομένως η ιστορική cross-site tracing attack εξαρτάται επίσης από έναν ξεχωριστό τρόπο εισαγωγής protected fields.<sup>[[3]](#references)</sup>![Image που δείχνει μια TRACE response](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image για post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Πώς κατάφερα να πάρω τον έλεγχο οποιουδήποτε user account με Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Ένα λιγότερο γνωστό attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
