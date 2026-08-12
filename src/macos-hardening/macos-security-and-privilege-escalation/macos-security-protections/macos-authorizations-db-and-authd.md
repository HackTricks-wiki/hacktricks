# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Βάση δεδομένων Authorization

Το Security framework's Authorization Services επιτρέπει σε privileged helpers και άλλα components να αξιολογούν named authorization rights. Σε τρέχουσες εκδόσεις του macOS, πολλοί από αυτούς τους κανόνες αποθηκεύονται στο `/var/db/auth.db` και αξιολογούνται από το `authd`. Αυτό το αρχείο και το SQLite schema του αποτελούν implementation details και ενδέχεται να αλλάζουν μεταξύ εκδόσεων.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Τα system defaults παραδοσιακά αρχικοποιούνται από το `/System/Library/Security/authorization.plist`, ενώ installers ή privileged services μπορούν να προσθέσουν named rights. Προτιμήστε το υποστηριζόμενο interface `security authorizationdb read|write|remove` αντί για άμεση επεξεργασία της βάσης δεδομένων.<sup>[[3]](#references)</sup>

Ο πίνακας `rules` που παρατηρήθηκε στο τεκμηριωμένο build περιέχει τις ακόλουθες στήλες. Αντιμετωπίστε το ως forensic map και όχι ως σταθερό public schema:

- **id**: Ένα μοναδικό αναγνωριστικό για κάθε κανόνα, το οποίο αυξάνεται αυτόματα και λειτουργεί ως primary key.
- **name**: Το μοναδικό όνομα του κανόνα, που χρησιμοποιείται για την αναγνώριση και την αναφορά σε αυτόν μέσα στο authorization system.
- **type**: Καθορίζει τον τύπο του κανόνα και περιορίζεται στις τιμές 1 ή 2 για τον ορισμό της authorization logic.
- **class**: Κατηγοριοποιεί τον κανόνα σε συγκεκριμένη κλάση και πρέπει να είναι θετικός ακέραιος.
- Οι συνήθεις rule classes περιλαμβάνουν τις `allow`, `deny`, `user`, `rule` και `evaluate-mechanisms`. Τα mechanisms μπορεί να είναι built-ins ή Security Agent plug-ins στο `/System/Library/CoreServices/SecurityAgentPlugins/` ή στο `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Υποδεικνύει την ομάδα χρηστών που σχετίζεται με τον κανόνα για authorization βάσει ομάδας.
- **kofn**: Αναπαριστά την παράμετρο "k-of-n", η οποία καθορίζει πόσοι subrules πρέπει να ικανοποιούνται από ένα συνολικό πλήθος.
- **timeout**: Καθορίζει τη διάρκεια σε δευτερόλεπτα πριν λήξει το authorization που χορηγήθηκε από τον κανόνα.
- **flags**: Περιέχει διάφορα flags που τροποποιούν τη συμπεριφορά και τα χαρακτηριστικά του κανόνα.
- **tries**: Περιορίζει τον αριθμό των επιτρεπόμενων authorization attempts για ενίσχυση της ασφάλειας.
- **version**: Παρακολουθεί την έκδοση του κανόνα για version control και updates.
- **created**: Καταγράφει το timestamp δημιουργίας του κανόνα για auditing purposes.
- **modified**: Αποθηκεύει το timestamp της τελευταίας τροποποίησης του κανόνα.
- **hash**: Περιέχει μια τιμή hash του κανόνα για τη διασφάλιση της ακεραιότητάς του και τον εντοπισμό tampering.
- **identifier**: Παρέχει ένα μοναδικό string identifier, όπως ένα UUID, για external references στον κανόνα.
- **requirement**: Περιέχει serialized data που ορίζει τις συγκεκριμένες authorization requirements και mechanisms του κανόνα.
- **comment**: Παρέχει μια human-readable περιγραφή ή σχόλιο σχετικά με τον κανόνα για documentation και σαφήνεια.

### Παράδειγμα
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Ο ακόλουθος αποκωδικοποιημένος κανόνας απεικονίζει το `authenticate-admin-nonshared` σε μια τεκμηριωμένη έκδοση του macOS:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

Το `authd` είναι η υπηρεσία XPC που αξιολογεί αιτήματα των Authorization Services. Στις τρέχουσες εκδόσεις του macOS, το bundle της μπορεί να εξεταστεί στη διαδρομή `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`. Η διαδρομή αποτελεί implementation detail και ενδέχεται να διαφέρει μεταξύ εκδόσεων. Οι παλαιότερες εκδόσεις έγραφαν στο `/var/log/authd.log`, ενώ οι τρέχουσες εκδόσεις χρησιμοποιούν κυρίως το unified logging system, το οποίο μπορεί να αναζητηθεί με `log show`/`log stream` χρησιμοποιώντας predicate για τη διεργασία `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Το εργαλείο `security` παρέχει αρκετές λειτουργίες των Authorization Services. Ένα ιστορικό παράδειγμα καλεί το `AuthorizationExecuteWithPrivileges` με `security execute-with-privileges /bin/ls`. Η Apple κατέστησε αυτό το API deprecated στο macOS 10.7. Οι σύγχρονοι privileged helpers θα πρέπει να χρησιμοποιούν helper υπό τη διαχείριση του launchd και authorization μέσω XPC.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Στις εκδόσεις που εξακολουθούν να το υποστηρίζουν, αυτό χρησιμοποιεί το `/usr/libexec/security_authtrampoline` και εμφανίζει ένα authorization prompt πριν εκτελέσει την εντολή ως root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Επισκόπηση του macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Οδηγός προγραμματισμού Apple Authorization Services (archive)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Σελίδα εγχειριδίου macOS για το `security(1)`](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Οδηγός προγραμματισμού Daemons and Services: Δημιουργία jobs του launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Έργο Security ανοιχτού κώδικα της Apple - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
