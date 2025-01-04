# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Κάθε **χρήστης που έχει συνδεθεί** στο σύστημα **κατέχει ένα access token με πληροφορίες ασφαλείας** για αυτή τη συνεδρία σύνδεσης. Το σύστημα δημιουργεί ένα access token όταν ο χρήστης συνδέεται. **Κάθε διαδικασία που εκτελείται** εκ μέρους του χρήστη **έχει ένα αντίγραφο του access token**. Το token προσδιορίζει τον χρήστη, τις ομάδες του χρήστη και τα δικαιώματα του χρήστη. Ένα token περιέχει επίσης ένα logon SID (Security Identifier) που προσδιορίζει την τρέχουσα συνεδρία σύνδεσης.

Μπορείτε να δείτε αυτές τις πληροφορίες εκτελώντας `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
ή χρησιμοποιώντας το _Process Explorer_ από τη Sysinternals (επιλέξτε τη διαδικασία και αποκτήστε πρόσβαση στην καρτέλα "Security"):

![](<../../images/image (772).png>)

### Τοπικός διαχειριστής

Όταν ένας τοπικός διαχειριστής συνδέεται, **δημιουργούνται δύο διαπιστευτήρια πρόσβασης**: Ένα με δικαιώματα διαχειριστή και ένα άλλο με κανονικά δικαιώματα. **Από προεπιλογή**, όταν αυτός ο χρήστης εκτελεί μια διαδικασία, χρησιμοποιείται το **κανονικό** (μη διαχειριστή) **δικαίωμα**. Όταν αυτός ο χρήστης προσπαθεί να **εκτελέσει** οτιδήποτε **ως διαχειριστής** ("Εκτέλεση ως διαχειριστής" για παράδειγμα), θα χρησιμοποιηθεί το **UAC** για να ζητήσει άδεια.\
Αν θέλετε να [**μάθετε περισσότερα για το UAC διαβάστε αυτή τη σελίδα**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

### Υποκατάσταση ταυτοτήτων χρηστών

Αν έχετε **έγκυρα διαπιστευτήρια οποιουδήποτε άλλου χρήστη**, μπορείτε να **δημιουργήσετε** μια **νέα συνεδρία σύνδεσης** με αυτά τα διαπιστευτήρια:
```
runas /user:domain\username cmd.exe
```
Το **access token** έχει επίσης μια **αναφορά** των συνεδριών σύνδεσης μέσα στο **LSASS**, αυτό είναι χρήσιμο αν η διαδικασία χρειάζεται να έχει πρόσβαση σε κάποια αντικείμενα του δικτύου.\
Μπορείτε να εκκινήσετε μια διαδικασία που **χρησιμοποιεί διαφορετικά διαπιστευτήρια για την πρόσβαση σε υπηρεσίες δικτύου** χρησιμοποιώντας:
```
runas /user:domain\username /netonly cmd.exe
```
Αυτό είναι χρήσιμο αν έχετε χρήσιμα διαπιστευτήρια για πρόσβαση σε αντικείμενα στο δίκτυο, αλλά αυτά τα διαπιστευτήρια δεν είναι έγκυρα μέσα στον τρέχοντα υπολογιστή, καθώς θα χρησιμοποιηθούν μόνο στο δίκτυο (στον τρέχοντα υπολογιστή θα χρησιμοποιηθούν τα δικαιώματα του τρέχοντος χρήστη σας).

### Τύποι διακριτικών

Υπάρχουν δύο τύποι διακριτικών διαθέσιμα:

- **Πρωτεύον Διακριτικό**: Λειτουργεί ως αναπαράσταση των διαπιστευτηρίων ασφαλείας μιας διαδικασίας. Η δημιουργία και η συσχέτιση πρωτευόντων διακριτικών με διαδικασίες είναι ενέργειες που απαιτούν ανυψωμένα δικαιώματα, τονίζοντας την αρχή του διαχωρισμού των δικαιωμάτων. Συνήθως, μια υπηρεσία πιστοποίησης είναι υπεύθυνη για τη δημιουργία διακριτικών, ενώ μια υπηρεσία σύνδεσης χειρίζεται τη συσχέτισή τους με το περιβάλλον λειτουργικού συστήματος του χρήστη. Αξιοσημείωτο είναι ότι οι διαδικασίες κληρονομούν το πρωτεύον διακριτικό της γονικής τους διαδικασίας κατά τη δημιουργία.
- **Διακριτικό Υποκατάστασης**: Δίνει τη δυνατότητα σε μια εφαρμογή διακομιστή να υιοθετήσει προσωρινά την ταυτότητα του πελάτη για πρόσβαση σε ασφαλή αντικείμενα. Αυτός ο μηχανισμός είναι διαστρωμένος σε τέσσερα επίπεδα λειτουργίας:
- **Ανώνυμο**: Παρέχει πρόσβαση στο διακομιστή παρόμοια με αυτήν ενός μη αναγνωρίσιμου χρήστη.
- **Ταυτοποίηση**: Επιτρέπει στο διακομιστή να επαληθεύσει την ταυτότητα του πελάτη χωρίς να τη χρησιμοποιήσει για πρόσβαση σε αντικείμενα.
- **Υποκατάσταση**: Δίνει τη δυνατότητα στο διακομιστή να λειτουργεί υπό την ταυτότητα του πελάτη.
- **Ανάθεση**: Παρόμοιο με την Υποκατάσταση, αλλά περιλαμβάνει τη δυνατότητα να επεκτείνει αυτήν την υπόθεση ταυτότητας σε απομακρυσμένα συστήματα με τα οποία αλληλεπιδρά ο διακομιστής, διασφαλίζοντας τη διατήρηση των διαπιστευτηρίων.

#### Υποκατάσταση Διακριτικών

Χρησιμοποιώντας το _**incognito**_ module του metasploit, αν έχετε αρκετά δικαιώματα, μπορείτε εύκολα να **καταγράψετε** και να **υποκαταστήσετε** άλλα **διακριτικά**. Αυτό θα μπορούσε να είναι χρήσιμο για να εκτελέσετε **ενέργειες σαν να ήσασταν ο άλλος χρήστης**. Μπορείτε επίσης να **ανυψώσετε δικαιώματα** με αυτήν την τεχνική.

### Δικαιώματα Διακριτικών

Μάθετε ποια **δικαιώματα διακριτικών μπορούν να καταχραστούν για να ανυψωθούν τα δικαιώματα:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Ρίξτε μια ματιά σε [**όλα τα πιθανά δικαιώματα διακριτικών και μερικούς ορισμούς σε αυτήν την εξωτερική σελίδα**](https://github.com/gtworek/Priv2Admin).

## Αναφορές

Μάθετε περισσότερα για τα διακριτικά σε αυτά τα σεμινάρια: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) και [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
