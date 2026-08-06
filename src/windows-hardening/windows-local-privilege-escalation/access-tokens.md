# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Κάθε **χρήστης που έχει συνδεθεί** στο σύστημα **διαθέτει ένα access token με πληροφορίες ασφαλείας** για τη συγκεκριμένη περίοδο σύνδεσης. Το σύστημα δημιουργεί ένα access token όταν ο χρήστης συνδέεται. **Κάθε διεργασία που εκτελείται** για λογαριασμό του χρήστη **διαθέτει ένα αντίγραφο του access token**. Το token προσδιορίζει τον χρήστη, τις ομάδες του χρήστη και τα δικαιώματα του χρήστη. Ένα token περιέχει επίσης ένα logon SID (Security Identifier), το οποίο προσδιορίζει την τρέχουσα περίοδο σύνδεσης.

Μπορείτε να δείτε αυτές τις πληροφορίες εκτελώντας την εντολή `whoami /all`
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
ή χρησιμοποιώντας το _Process Explorer_ από το Sysinternals (επιλέξτε τη διεργασία και ανοίξτε την καρτέλα "Security"):

![Access Tokens - Access Tokens: ή χρησιμοποιώντας το Process Explorer από το Sysinternals (επιλέξτε τη διεργασία και ανοίξτε την καρτέλα "Security")](<../../images/image (772).png>)

### Τοπικός administrator

Όταν ένας τοπικός administrator κάνει login, **δημιουργούνται δύο access tokens**: Ένα με δικαιώματα administrator και ένα άλλο με κανονικά δικαιώματα. **Από προεπιλογή**, όταν αυτός ο χρήστης εκτελεί μια διεργασία, χρησιμοποιείται εκείνη με **κανονικά** (μη-administrator) **δικαιώματα**. Όταν αυτός ο χρήστης προσπαθεί να **εκτελέσει** οτιδήποτε **ως administrator** (για παράδειγμα, με την επιλογή "Run as Administrator"), θα χρησιμοποιηθεί το **UAC** για να ζητήσει άδεια.\
Αν θέλετε να [**μάθετε περισσότερα για το UAC, διαβάστε αυτή τη σελίδα**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Στην πράξη, αυτό σημαίνει ότι ένα **μη-elevated admin shell συνήθως εκτελείται με filtered token**. Γι' αυτό το `whoami /groups` συχνά εμφανίζει το **`BUILTIN\Administrators` ως `Deny only`** μέχρι να γίνει elevate η διεργασία. Εσωτερικά, τα Windows διατηρούν ένα **linked elevated token** (`TokenLinkedToken`) και παρακολουθούν την κατάσταση με πεδία όπως το `TokenElevationType`.

### Impersonation χρήστη με credentials

Αν διαθέτετε **έγκυρα credentials οποιουδήποτε άλλου χρήστη**, μπορείτε να **δημιουργήσετε** ένα **νέο logon session** με αυτά τα credentials:
```
runas /user:domain\username cmd.exe
```
Το **access token** περιέχει επίσης μια **reference** των sessions σύνδεσης μέσα στο **LSASS**, κάτι που είναι χρήσιμο αν η διεργασία χρειάζεται να αποκτήσει πρόσβαση σε ορισμένα αντικείμενα του network.\
Μπορείτε να εκκινήσετε μια διεργασία που **χρησιμοποιεί διαφορετικά credentials για πρόσβαση σε network services** χρησιμοποιώντας:
```
runas /user:domain\username /netonly cmd.exe
```
Αυτό είναι χρήσιμο αν έχετε έγκυρα credentials για πρόσβαση σε objects του network, αλλά αυτά τα credentials δεν είναι valid μέσα στο current host, καθώς πρόκειται να χρησιμοποιηθούν μόνο στο network (στο current host θα χρησιμοποιηθούν τα privileges του current user).

#### Λεπτομέρειες του `runas /netonly`

Το `runas /netonly` (και C2 helpers όπως το `make_token`) δημιουργεί ένα **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Αυτό είναι πολύ χρήσιμο για την κατανόηση του lateral movement, επειδή:<sup>[[3]](#references)</sup>

- **Τοπικά**, το νέο process διατηρεί την **ίδια local identity**, τα groups, το integrity level και τις περισσότερες ίδιες access decisions με το current token.
- **Απομακρυσμένα**, το outbound authentication μπορεί να χρησιμοποιήσει τα **supplied credentials** για SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Επομένως, το `whoami` μπορεί να εξακολουθεί να εμφανίζει τον **αρχικό local user**, ενώ η network access πραγματοποιείται ως ο **alternate account**.

Αυτή είναι μια εξαιρετική επιλογή όταν τα credentials είναι valid στο domain ή σε κάποιο άλλο host, αλλά ο user **δεν μπορεί ή δεν πρέπει να κάνει log on locally** στο current machine.

### Τύποι tokens

Υπάρχουν δύο διαθέσιμοι τύποι tokens:

- **Primary Token**: Λειτουργεί ως αναπαράσταση των security credentials ενός process. Η δημιουργία και η συσχέτιση primary tokens με processes είναι ενέργειες που απαιτούν elevated privileges, τονίζοντας την αρχή του privilege separation. Συνήθως, μια authentication service είναι υπεύθυνη για τη δημιουργία του token, ενώ μια logon service χειρίζεται τη συσχέτισή του με το operating system shell του user. Αξίζει να σημειωθεί ότι τα processes κληρονομούν το primary token του parent process κατά τη δημιουργία τους.
- **Impersonation Token**: Επιτρέπει σε μια server application να υιοθετεί προσωρινά την identity του client για την πρόσβαση σε secure objects. Αυτός ο μηχανισμός χωρίζεται σε τέσσερα levels λειτουργίας:
- **Anonymous**: Παρέχει στον server access παρόμοια με αυτήν ενός unidentified user.
- **Identification**: Επιτρέπει στον server να επαληθεύσει την identity του client χωρίς να τη χρησιμοποιεί για object access.
- **Impersonation**: Επιτρέπει στον server να λειτουργεί υπό την identity του client.
- **Delegation**: Παρόμοιο με το Impersonation, αλλά περιλαμβάνει τη δυνατότητα επέκτασης αυτής της identity assumption σε remote systems με τα οποία αλληλεπιδρά ο server, διασφαλίζοντας τη διατήρηση των credentials.

#### Impersonate Tokens

Χρησιμοποιώντας το _**incognito**_ module του metasploit, αν έχετε επαρκή privileges, μπορείτε εύκολα να κάνετε **list** και **impersonate** άλλα **tokens**. Αυτό μπορεί να είναι χρήσιμο για την εκτέλεση **actions σαν να ήσασταν ο άλλος user**. Θα μπορούσατε επίσης να κάνετε **escalate privileges** με αυτήν την technique.

Μερικές πρακτικές σημειώσεις που είναι εύκολο να ξεχαστούν κατά το operation:<sup>[[1]](#references)</sup>

- Το **`CreateProcessWithTokenW`** απαιτεί **`SeImpersonatePrivilege`** από τον caller και το νέο process θα εκτελεστεί στο **session του caller**.
- Το **`CreateProcessAsUserW`** είναι το συνηθισμένο fallback όταν το `CreateProcessWithTokenW` αποτυγχάνει με `1314` ή όταν χρειάζεται να γίνει launch στο **session που αναφέρεται από το token**.
- Αν ένα token προέρχεται από το **`LogonUser(LOGON32_LOGON_NETWORK)`**, συνήθως είναι **impersonation token**, επομένως χρειάζεται **`DuplicateTokenEx(..., TokenPrimary, ...)`** πριν προσπαθήσετε να κάνετε spawn ένα process με αυτό.
- Δεν είναι όλα τα impersonation tokens εξίσου χρήσιμα: το **`SecurityIdentification`** σάς επιτρέπει να επιθεωρείτε τον user, αλλά **όχι να ενεργείτε ως αυτός**. Αν ένα coercion primitive ή ένας pipe/RPC client σάς παρέχει μόνο token επιπέδου identification, ελέγξτε το **`TokenImpersonationLevel`** και χρησιμοποιήστε ένα primitive που παρέχει **`SecurityImpersonation`** ή ανώτερο level.

#### Token theft χωρίς να αγγίξετε το LSASS

Αν έχετε ήδη context ενός **service** ή του **SYSTEM** και ένας **privileged user είναι logged on**, η κλοπή ή η αντιγραφή του token αυτού του user είναι συχνά πιο αθόρυβη από το dumping του **LSASS**. Σε πολλές πραγματικές intrusions, αυτό αρκεί για να:<sup>[[2]](#references)</sup>

- εκτελέσετε local actions ως αυτός ο user
- αποκτήσετε πρόσβαση σε remote resources ως αυτός ο user
- εκτελέσετε AD operations χωρίς να εξαγάγετε πρώτα reusable credentials

Για παραδείγματα **session/user token hijacking** από privileged context, δείτε το [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Έχετε υπόψη ότι APIs όπως το **`WTSQueryUserToken`** προορίζονται για **highly trusted services** και κανονικά απαιτούν **`LocalSystem` + `SeTcbPrivilege`**, επομένως είναι κυρίως χρήσιμα όταν έχετε ήδη τον έλεγχο ενός service-level context. Για privilege-specific τρόπους απόκτησης του **SYSTEM** αρχικά, δείτε τις παρακάτω σελίδες.

### Privileges των tokens

Μάθετε ποια **token privileges μπορούν να γίνουν abuse για privilege escalation:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Δείτε [**όλα τα πιθανά token privileges και ορισμένους ορισμούς σε αυτήν την external page**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
