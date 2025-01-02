# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Athorizarions DB**

Η βάση δεδομένων που βρίσκεται στο `/var/db/auth.db` είναι η βάση δεδομένων που χρησιμοποιείται για την αποθήκευση αδειών για την εκτέλεση ευαίσθητων λειτουργιών. Αυτές οι λειτουργίες εκτελούνται εντελώς σε **user space** και συνήθως χρησιμοποιούνται από **XPC services** που χρειάζονται να ελέγξουν **αν ο καλών πελάτης είναι εξουσιοδοτημένος** να εκτελέσει συγκεκριμένη ενέργεια ελέγχοντας αυτή τη βάση δεδομένων.

Αρχικά, αυτή η βάση δεδομένων δημιουργείται από το περιεχόμενο του `/System/Library/Security/authorization.plist`. Στη συνέχεια, ορισμένες υπηρεσίες μπορεί να προσθέσουν ή να τροποποιήσουν αυτή τη βάση δεδομένων για να προσθέσουν άλλες άδειες σε αυτήν.

Οι κανόνες αποθηκεύονται στον πίνακα `rules` μέσα στη βάση δεδομένων και περιέχουν τις εξής στήλες:

- **id**: Ένας μοναδικός αναγνωριστικός αριθμός για κάθε κανόνα, αυτόματα αυξανόμενος και λειτουργώντας ως το κύριο κλειδί.
- **name**: Το μοναδικό όνομα του κανόνα που χρησιμοποιείται για την αναγνώριση και αναφορά του μέσα στο σύστημα εξουσιοδότησης.
- **type**: Προσδιορίζει τον τύπο του κανόνα, περιορισμένο σε τιμές 1 ή 2 για να καθορίσει τη λογική εξουσιοδότησής του.
- **class**: Κατηγοριοποιεί τον κανόνα σε μια συγκεκριμένη κατηγορία, διασφαλίζοντας ότι είναι θετικός ακέραιος.
- "allow" για επιτρεπόμενο, "deny" για απορριπτέο, "user" αν η ιδιότητα ομάδας υποδεικνύει μια ομάδα της οποίας η συμμετοχή επιτρέπει την πρόσβαση, "rule" υποδεικνύει σε έναν πίνακα έναν κανόνα που πρέπει να εκπληρωθεί, "evaluate-mechanisms" ακολουθούμενο από έναν πίνακα `mechanisms` που είναι είτε ενσωματωμένα είτε ένα όνομα ενός bundle μέσα στο `/System/Library/CoreServices/SecurityAgentPlugins/` ή /Library/Security//SecurityAgentPlugins
- **group**: Υποδεικνύει την ομάδα χρηστών που σχετίζεται με τον κανόνα για εξουσιοδότηση βάσει ομάδας.
- **kofn**: Αντιπροσωπεύει την παράμετρο "k-of-n", καθορίζοντας πόσοι υποκανόνες πρέπει να ικανοποιηθούν από τον συνολικό αριθμό.
- **timeout**: Ορίζει τη διάρκεια σε δευτερόλεπτα πριν η εξουσιοδότηση που χορηγείται από τον κανόνα λήξει.
- **flags**: Περιέχει διάφορες σημαίες που τροποποιούν τη συμπεριφορά και τα χαρακτηριστικά του κανόνα.
- **tries**: Περιορίζει τον αριθμό των επιτρεπόμενων προσπαθειών εξουσιοδότησης για την ενίσχυση της ασφάλειας.
- **version**: Παρακολουθεί την έκδοση του κανόνα για έλεγχο εκδόσεων και ενημερώσεις.
- **created**: Καταγράφει την χρονική σήμανση όταν δημιουργήθηκε ο κανόνας για σκοπούς ελέγχου.
- **modified**: Αποθηκεύει την χρονική σήμανση της τελευταίας τροποποίησης που έγινε στον κανόνα.
- **hash**: Περιέχει μια τιμή hash του κανόνα για να διασφαλίσει την ακεραιότητά του και να ανιχνεύσει παραβιάσεις.
- **identifier**: Παρέχει έναν μοναδικό αναγνωριστικό συμβολοσειράς, όπως ένα UUID, για εξωτερικές αναφορές στον κανόνα.
- **requirement**: Περιέχει σειριοποιημένα δεδομένα που καθορίζουν τις συγκεκριμένες απαιτήσεις και μηχανισμούς εξουσιοδότησης του κανόνα.
- **comment**: Προσφέρει μια περιγραφή ή σχόλιο που είναι κατανοητό από τον άνθρωπο σχετικά με τον κανόνα για τεκμηρίωση και σαφήνεια.

### Example
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
Επιπλέον, στο [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) είναι δυνατή η προβολή της σημασίας του `authenticate-admin-nonshared`:
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

Είναι ένας δαίμονας που θα λαμβάνει αιτήματα για να εξουσιοδοτήσει πελάτες να εκτελούν ευαίσθητες ενέργειες. Λειτουργεί ως υπηρεσία XPC που ορίζεται μέσα στον φάκελο `XPCServices/` και χρησιμοποιεί για να γράφει τα αρχεία καταγραφής του στο `/var/log/authd.log`.

Επιπλέον, χρησιμοποιώντας το εργαλείο ασφαλείας, είναι δυνατόν να δοκιμάσετε πολλές APIs του `Security.framework`. Για παράδειγμα, η `AuthorizationExecuteWithPrivileges` εκτελώντας: `security execute-with-privileges /bin/ls`

Αυτό θα δημιουργήσει και θα εκτελέσει το `/usr/libexec/security_authtrampoline /bin/ls` ως root, το οποίο θα ζητήσει άδειες σε ένα παράθυρο διαλόγου για να εκτελέσει το ls ως root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
