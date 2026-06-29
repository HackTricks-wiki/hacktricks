# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Κάθε **χρήστης που είναι συνδεδεμένος** στο σύστημα **κατέχει ένα access token με πληροφορίες ασφαλείας** για εκείνη τη logon session. Το σύστημα δημιουργεί ένα access token όταν ο χρήστης συνδέεται. **Κάθε process που εκτελείται** εκ μέρους του χρήστη **έχει ένα αντίγραφο του access token**. Το token αναγνωρίζει τον χρήστη, τα groups του χρήστη και τα privileges του χρήστη. Ένα token περιέχει επίσης ένα logon SID (Security Identifier) που αναγνωρίζει την τρέχουσα logon session.

Μπορείς να δεις αυτές τις πληροφορίες εκτελώντας `whoami /all`
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
ή χρησιμοποιώντας το _Process Explorer_ από το Sysinternals (επιλέξτε process και ανοίξτε την καρτέλα "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

Όταν ένας local administrator κάνει login, **δημιουργούνται δύο access tokens**: Ένα με admin rights και ένα άλλο με normal rights. **By default**, όταν αυτός ο user εκτελεί ένα process χρησιμοποιείται το ένα με τα **regular** (non-administrator) **rights**. Όταν αυτός ο user προσπαθεί να **εκτελέσει** οτιδήποτε **ως administrator** ("Run as Administrator" για example), θα χρησιμοποιηθεί το **UAC** για να ζητήσει permission.\
Αν θέλετε να [**μάθετε περισσότερα για το UAC διαβάστε αυτή τη σελίδα**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Στην πράξη, αυτό σημαίνει ότι ένα **non-elevated admin shell συνήθως εκτελείται με filtered token**. Γι' αυτό το `whoami /groups` συχνά δείχνει το **`BUILTIN\Administrators` ως `Deny only`** μέχρι το process να γίνει elevated. Εσωτερικά, τα Windows διατηρούν ένα **linked elevated token** (`TokenLinkedToken`) και παρακολουθούν την κατάσταση με πεδία όπως το `TokenElevationType`.

### Credentials user impersonation

Αν έχετε **valid credentials οποιουδήποτε άλλου user**, μπορείτε να **δημιουργήσετε** μια **νέα logon session** με αυτά τα credentials :
```
runas /user:domain\username cmd.exe
```
Το **access token** έχει επίσης μια **reference** των logon sessions μέσα στο **LSASS**, κάτι που είναι χρήσιμο αν η διεργασία χρειάζεται να προσπελάσει κάποια objects του network.\
Μπορείς να εκκινήσεις μια διεργασία που **χρησιμοποιεί διαφορετικά credentials για πρόσβαση σε network services** χρησιμοποιώντας:
```
runas /user:domain\username /netonly cmd.exe
```
Αυτό είναι χρήσιμο αν έχεις χρήσιμα credentials για να αποκτήσεις πρόσβαση σε objects στο network, αλλά αυτά τα credentials δεν είναι valid μέσα στο current host, καθώς θα χρησιμοποιηθούν μόνο στο network (στο current host θα χρησιμοποιηθούν τα current user privileges σου).

#### `runas /netonly` details

Το `runas /netonly` (και C2 helpers όπως το `make_token`) δημιουργεί ένα **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Αυτό είναι πολύ χρήσιμο να το καταλάβεις κατά το lateral movement επειδή:

- **Τοπικά**, το νέο process διατηρεί την **ίδια local identity**, groups, integrity level και τις περισσότερες από τις ίδιες access decisions όπως το current token.
- **Απομακρυσμένα**, η outbound authentication μπορεί να χρησιμοποιήσει τα **credentials που δόθηκαν** για SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Επομένως το `whoami` μπορεί να εξακολουθεί να δείχνει τον **αρχικό local user** ενώ η network access γίνεται ως ο **εναλλακτικός account**.

Αυτή είναι μια εξαιρετική επιλογή όταν τα credentials είναι valid στο domain ή σε άλλο host, αλλά ο user **δεν μπορεί ή δεν πρέπει να κάνει log on locally** στο current machine.

### Types of tokens

Υπάρχουν δύο τύποι tokens διαθέσιμοι:

- **Primary Token**: Λειτουργεί ως αναπαράσταση των security credentials μιας process. Η δημιουργία και η συσχέτιση primary tokens με processes είναι ενέργειες που απαιτούν elevated privileges, υπογραμμίζοντας την αρχή του privilege separation. Συνήθως, μια authentication service είναι υπεύθυνη για token creation, ενώ μια logon service χειρίζεται τη συσχέτισή του με το OS shell του user. Αξίζει να σημειωθεί ότι τα processes κληρονομούν το primary token του parent process τους κατά τη δημιουργία.
- **Impersonation Token**: Δίνει τη δυνατότητα σε μια server application να υιοθετήσει προσωρινά την ταυτότητα του client για πρόσβαση σε secure objects. Αυτός ο μηχανισμός διακρίνεται σε τέσσερα levels λειτουργίας:
- **Anonymous**: Παρέχει server access παρόμοια με αυτήν ενός unidentified user.
- **Identification**: Επιτρέπει στον server να επαληθεύσει την ταυτότητα του client χωρίς να τη χρησιμοποιήσει για object access.
- **Impersonation**: Επιτρέπει στον server να λειτουργεί υπό την ταυτότητα του client.
- **Delegation**: Παρόμοιο με το Impersonation αλλά περιλαμβάνει τη δυνατότητα να επεκταθεί αυτή η ανάληψη ταυτότητας σε remote systems με τα οποία αλληλεπιδρά ο server, διασφαλίζοντας τη διατήρηση των credentials.

#### Impersonate Tokens

Χρησιμοποιώντας το _**incognito**_ module του metasploit, αν έχεις αρκετά privileges μπορείς εύκολα να **list** και να **impersonate** άλλα **tokens**. Αυτό μπορεί να είναι χρήσιμο για να εκτελέσεις **actions σαν να ήσουν ο άλλος user**. Μπορείς επίσης να **escalate privileges** με αυτήν την τεχνική.

Κάποιες πρακτικές σημειώσεις που είναι εύκολο να ξεχαστούν κατά τη διάρκεια της operation:

- Το **`CreateProcessWithTokenW`** απαιτεί **`SeImpersonatePrivilege`** στον caller και το νέο process θα εκτελεστεί στο **session του caller**.
- Το **`CreateProcessAsUserW`** είναι το συνήθες fallback όταν το `CreateProcessWithTokenW` αποτυγχάνει με `1314`, ή όταν χρειάζεται να κάνεις launch στο **session που αναφέρεται από το token**.
- Αν ένα token προέρχεται από **`LogonUser(LOGON32_LOGON_NETWORK)`**, συνήθως είναι **impersonation token**, οπότε χρειάζεσαι **`DuplicateTokenEx(..., TokenPrimary, ...)`** πριν προσπαθήσεις να δημιουργήσεις process με αυτό.
- Δεν είναι όλα τα impersonation tokens εξίσου χρήσιμα: το **`SecurityIdentification`** σου επιτρέπει να επιθεωρήσεις τον user αλλά **όχι να ενεργήσεις ως αυτός**. Αν ένα coercion primitive ή pipe/RPC client σου δίνει μόνο identification-level token, έλεγξε το **`TokenImpersonationLevel`** και άλλαξε σε ένα primitive που δίνει **`SecurityImpersonation`** ή καλύτερο.

#### Token theft without touching LSASS

Αν ήδη έχεις context **service** ή **SYSTEM** και ένας **privileged user είναι logged on**, το να κλέψεις ή να αντιγράψεις το token αυτού του user είναι συχνά πιο αθόρυβο από το να κάνεις dump το **LSASS**. Σε πολλές πραγματικές intrusions αυτό αρκεί για να:

- εκτελέσεις local actions ως αυτός ο user
- αποκτήσεις πρόσβαση σε remote resources ως αυτός ο user
- εκτελέσεις AD operations χωρίς να εξάγεις πρώτα reusable credentials

Για παραδείγματα **session/user token hijacking** από privileged context, δες [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Θυμήσου ότι APIs όπως το **`WTSQueryUserToken`** προορίζονται για **highly trusted services** και συνήθως απαιτούν **`LocalSystem` + `SeTcbPrivilege`**, οπότε είναι κυρίως χρήσιμα αφού ήδη ελέγχεις ένα service-level context. Για privilege-specific τρόπους να αποκτήσεις πρώτα **SYSTEM**, δες τις παρακάτω σελίδες.

### Token Privileges

Μάθε ποια **token privileges μπορούν να abused to escalate privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Δες [**όλα τα πιθανά token privileges και μερικούς ορισμούς σε αυτήν την external page**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
