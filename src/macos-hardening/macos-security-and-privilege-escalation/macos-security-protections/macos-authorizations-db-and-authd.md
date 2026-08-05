# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Βάση δεδομένων Authorizations**

Η βάση δεδομένων που βρίσκεται στο `/var/db/auth.db` χρησιμοποιείται για την αποθήκευση δικαιωμάτων εκτέλεσης ευαίσθητων ενεργειών. Αυτές οι ενέργειες εκτελούνται πλήρως σε **user space** και συνήθως χρησιμοποιούνται από **XPC services**, τα οποία πρέπει να ελέγξουν **αν ο client που καλεί είναι εξουσιοδοτημένος** να εκτελέσει μια συγκεκριμένη ενέργεια, ελέγχοντας αυτήν τη βάση δεδομένων.

Αρχικά, αυτή η βάση δεδομένων δημιουργείται από το περιεχόμενο του `/System/Library/Security/authorization.plist`. Στη συνέχεια, ορισμένα services ενδέχεται να προσθέσουν ή να τροποποιήσουν αυτήν τη βάση δεδομένων, ώστε να προσθέσουν και άλλα permissions σε αυτήν.

Οι κανόνες αποθηκεύονται στον πίνακα `rules` μέσα στη βάση δεδομένων και περιέχουν τις ακόλουθες στήλες:

- **id**: Ένα μοναδικό αναγνωριστικό για κάθε κανόνα, το οποίο αυξάνεται αυτόματα και λειτουργεί ως primary key.
- **name**: Το μοναδικό όνομα του κανόνα, το οποίο χρησιμοποιείται για την αναγνώριση και την αναφορά σε αυτόν μέσα στο authorization system.
- **type**: Καθορίζει τον τύπο του κανόνα και περιορίζεται στις τιμές 1 ή 2, ώστε να ορίζει τη λογική του authorization.
- **class**: Κατηγοριοποιεί τον κανόνα σε μια συγκεκριμένη κλάση, διασφαλίζοντας ότι είναι θετικός ακέραιος.
- "allow" για allow, "deny" για deny, "user" αν η ιδιότητα group υποδεικνύει μια ομάδα, η συμμετοχή στην οποία επιτρέπει την πρόσβαση, "rule" υποδεικνύει σε έναν πίνακα έναν κανόνα που πρέπει να ικανοποιηθεί, "evaluate-mechanisms" ακολουθούμενο από έναν πίνακα `mechanisms`, τα στοιχεία του οποίου είναι είτε builtins είτε ένα όνομα bundle μέσα στο `/System/Library/CoreServices/SecurityAgentPlugins/` ή στο `/Library/Security//SecurityAgentPlugins`
- **group**: Υποδεικνύει την ομάδα χρηστών που σχετίζεται με τον κανόνα για authorization βάσει ομάδας.
- **kofn**: Αντιπροσωπεύει την παράμετρο "k-of-n", καθορίζοντας πόσοι subrules πρέπει να ικανοποιούνται από ένα συνολικό πλήθος.
- **timeout**: Καθορίζει τη διάρκεια σε δευτερόλεπτα πριν λήξει το authorization που χορηγήθηκε από τον κανόνα.
- **flags**: Περιέχει διάφορες σημαίες που τροποποιούν τη συμπεριφορά και τα χαρακτηριστικά του κανόνα.
- **tries**: Περιορίζει τον αριθμό των επιτρεπόμενων προσπαθειών authorization για ενίσχυση της ασφάλειας.
- **version**: Παρακολουθεί την έκδοση του κανόνα για version control και updates.
- **created**: Καταγράφει το timestamp δημιουργίας του κανόνα για σκοπούς auditing.
- **modified**: Αποθηκεύει το timestamp της τελευταίας τροποποίησης του κανόνα.
- **hash**: Περιέχει μια τιμή hash του κανόνα, ώστε να διασφαλίζεται η ακεραιότητά του και να εντοπίζεται tampering.
- **identifier**: Παρέχει ένα μοναδικό string identifier, όπως ένα UUID, για εξωτερικές αναφορές στον κανόνα.
- **requirement**: Περιέχει serialized δεδομένα που ορίζουν τις συγκεκριμένες απαιτήσεις και τους μηχανισμούς authorization του κανόνα.
- **comment**: Παρέχει μια περιγραφή ή ένα σχόλιο σε μορφή κατανοητή από τον άνθρωπο σχετικά με τον κανόνα, για documentation και σαφήνεια.

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
Επιπλέον, στο [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) είναι δυνατό να δει κανείς τη σημασία του `authenticate-admin-nonshared`:<sup>[[1]](#references)</sup>
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

Είναι ένα daemon που λαμβάνει αιτήματα για την εξουσιοδότηση clients ώστε να εκτελούν ευαίσθητες ενέργειες. Λειτουργεί ως υπηρεσία XPC που ορίζεται μέσα στον φάκελο `XPCServices/` και χρησιμοποιεί το `/var/log/authd.log` για την καταγραφή των logs του.

Επιπλέον, χρησιμοποιώντας το security tool, είναι δυνατή η δοκιμή πολλών APIs του `Security.framework`. Για παράδειγμα, η εκτέλεση του `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

Αυτό θα κάνει fork και exec το `/usr/libexec/security_authtrampoline /bin/ls` ως root, το οποίο θα ζητήσει δικαιώματα μέσω prompt για την εκτέλεση του ls ως root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
