# Διακριτικά πρόσβασης

{{#include ../../banners/hacktricks-training.md}}

## Διακριτικά πρόσβασης

Κάθε διεργασία έχει ένα **πρωτεύον διακριτικό πρόσβασης** που καθορίζει το πλαίσιο ασφαλείας της. Ένα νήμα χρησιμοποιεί κανονικά αυτό το διακριτικό, αλλά μπορεί επίσης να έχει προσωρινά ένα **διακριτικό πλαστοπροσωπίας**. Τα διακριτικά περιέχουν το SID του χρήστη, SID ομάδων, προνόμια, πληροφορίες ακεραιότητας και ένα SID σύνδεσης για την περίοδο σύνδεσης. Οι διεργασίες συνήθως κληρονομούν μια αναφορά στο πρωτεύον διακριτικό της γονικής διεργασίας· δεν λαμβάνουν ανεξάρτητο αντίγραφο του περιεχομένου του.<sup>[[4]](#references)</sup>

Μπορείτε να δείτε αυτές τις πληροφορίες εκτελώντας το `whoami /all`

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

ή χρησιμοποιώντας το _Process Explorer_ από το Sysinternals (επιλέξτε τη διεργασία και ανοίξτε την καρτέλα «Security»):

![Access Tokens - Access Tokens: ή χρησιμοποιώντας το Process Explorer από το Sysinternals (επιλέξτε τη διεργασία και ανοίξτε την καρτέλα «Security»)](<../../images/image (772).png>)

### Τοπικός διαχειριστής

Όταν εφαρμόζεται το **UAC Admin Approval Mode** σε έναν διαχειριστή, η διαδραστική σύνδεση δημιουργεί ένα πλήρες token διαχειριστή και ένα φιλτραρισμένο token. Από προεπιλογή, ο Explorer και οι συνήθεις θυγατρικές διεργασίες χρησιμοποιούν το φιλτραρισμένο token. Ένα αίτημα ανύψωσης, όπως **Εκτέλεση ως διαχειριστής**, ζητά από το UAC να εκκινήσει το πρόγραμμα με το πλήρες token. Η ακριβής συμπεριφορά διαφέρει για τον ενσωματωμένο λογαριασμό Administrator και όταν το Admin Approval Mode είναι απενεργοποιημένο.<sup>[[5]](#references)</sup>

Διαβάστε την ειδική [**σελίδα UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) για τεχνικές παράκαμψης και λεπτομέρειες πολιτικής.

Στην πράξη, αυτό σημαίνει ότι ένα **μη ανυψωμένο κέλυφος διαχειριστή συνήθως εκτελείται με φιλτραρισμένο token**. Γι’ αυτό η εντολή `whoami /groups` εμφανίζει συχνά το **`BUILTIN\Administrators` ως `Deny only`** μέχρι να ανυψωθεί η διεργασία. Εσωτερικά, τα Windows διατηρούν ένα **συνδεδεμένο ανυψωμένο token** (`TokenLinkedToken`) και παρακολουθούν την κατάσταση με πεδία όπως το `TokenElevationType`.

### Impersonation χρήστη μέσω διαπιστευτηρίων

Αν έχετε **έγκυρα διαπιστευτήρια οποιουδήποτε άλλου χρήστη**, μπορείτε να **δημιουργήσετε** μια **νέα περίοδο σύνδεσης** με αυτά τα διαπιστευτήρια:

```
runas /user:domain\username cmd.exe
```

Το **access token** περιέχει επίσης μια **αναφορά** στις περιόδους σύνδεσης μέσα στο **LSASS**. Αυτό είναι χρήσιμο αν η διεργασία χρειάζεται να αποκτήσει πρόσβαση σε ορισμένα αντικείμενα του δικτύου.\
Μπορείτε να εκκινήσετε μια διεργασία που **χρησιμοποιεί διαφορετικά διαπιστευτήρια για την πρόσβαση σε υπηρεσίες δικτύου** με:

```
runas /user:domain\username /netonly cmd.exe
```

Αυτό είναι χρήσιμο αν έχετε διαπιστευτήρια που παρέχουν πρόσβαση σε αντικείμενα στο δίκτυο, αλλά αυτά τα διαπιστευτήρια δεν είναι έγκυρα στον τρέχοντα host, καθώς θα χρησιμοποιηθούν μόνο στο δίκτυο (στον τρέχοντα host θα χρησιμοποιηθούν τα προνόμια του τρέχοντος χρήστη).

#### Λεπτομέρειες για το `runas /netonly`

Το `runas /netonly` (και βοηθητικά εργαλεία C2 όπως το `make_token`) δημιουργεί ένα token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Είναι πολύ χρήσιμο να το κατανοήσετε κατά τη μετακίνηση πλευρικά, επειδή:<sup>[[3]](#references)</sup>

- **Τοπικά**, η νέα διεργασία διατηρεί την **ίδια τοπική ταυτότητα**, τις ομάδες, το επίπεδο ακεραιότητας και τις περισσότερες από τις ίδιες αποφάσεις πρόσβασης με το τρέχον token.
- **Απομακρυσμένα**, ο εξερχόμενος έλεγχος ταυτότητας μπορεί να χρησιμοποιεί τα **παρεχόμενα διαπιστευτήρια** για SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Επομένως, το `whoami` μπορεί να εξακολουθεί να εμφανίζει τον **αρχικό τοπικό χρήστη**, ενώ η πρόσβαση στο δίκτυο γίνεται ως ο **εναλλακτικός λογαριασμός**.

Αυτή είναι μια πολύ καλή επιλογή όταν τα διαπιστευτήρια είναι έγκυρα στον τομέα ή σε άλλον host, αλλά ο χρήστης **δεν μπορεί ή δεν πρέπει να συνδεθεί τοπικά** στο τρέχον μηχάνημα.

### Τύποι token

Υπάρχουν δύο διαθέσιμοι τύποι token:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Αντιπροσωπεύει το πλαίσιο ασφαλείας μιας διεργασίας. Μια θυγατρική διεργασία συνήθως κληρονομεί το primary token της γονικής διεργασίας, ενώ τα API δημιουργίας διεργασιών με ρητό token επιβάλλουν τις δικές τους απαιτήσεις πρόσβασης στο token και προνομίων του καλούντος.
- **Impersonation token**: Επιτρέπει σε ένα νήμα διακομιστή να χρησιμοποιεί προσωρινά το πλαίσιο ασφαλείας ενός πελάτη για ελέγχους πρόσβασης. Έχει τέσσερα επίπεδα:
  - **Anonymous**: Παρέχει στον διακομιστή πρόσβαση αντίστοιχη με εκείνη ενός μη αναγνωρισμένου χρήστη.
  - **Identification**: Επιτρέπει στον διακομιστή να επαληθεύσει την ταυτότητα του πελάτη χωρίς να τη χρησιμοποιήσει για πρόσβαση σε αντικείμενα.
  - **Impersonation**: Επιτρέπει στον διακομιστή να ενεργεί με την ταυτότητα του πελάτη.
  - **Delegation**: Επιτρέπει στον διακομιστή να κάνει impersonate τον πελάτη σε απομακρυσμένα συστήματα, όταν ο μηχανισμός ελέγχου ταυτότητας και οι ρυθμίσεις του λογαριασμού υποστηρίζουν delegation.

#### Αξιολογήστε ένα token που αποκτήσατε πριν το χρησιμοποιήσετε

Μην επιλέγετε token μόνο βάσει του ονόματος χρήστη. Ο ίδιος λογαριασμός μπορεί να έχει πολλά token με διαφορετικές περιόδους σύνδεσης, service SID, προνόμια, επίπεδα ακεραιότητας, περιορισμούς και διαπιστευτήρια δικτύου.<sup>[[9]](#references)</sup> Αναζητήστε τουλάχιστον τα **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** και **`TokenStatistics.AuthenticationId`** με το `GetTokenInformation`.<sup>[[7]](#references)</sup>

Ένα περιορισμένο token μπορεί να περιέχει SID με δικαιώματα μόνο άρνησης, αφαιρεμένα προνόμια και SID περιορισμού. Όταν υπάρχουν SID περιορισμού, τα Windows εκτελούν έναν έλεγχο πρόσβασης με τα ενεργοποιημένα SID και έναν δεύτερο με τα SID περιορισμού· **και οι δύο έλεγχοι πρέπει να επιτρέπουν την πρόσβαση**. Επομένως, ένα ελκυστικό SID χρήστη ή μια ενεργοποιημένη ομάδα στην έξοδο δεν αποδεικνύει από μόνο του ότι το token μπορεί να αποκτήσει πρόσβαση στο αντικείμενο-στόχο.<sup>[[8]](#references)</sup>

Χρησιμοποιήστε αυτή τη ροή αποφάσεων για τις τεκμηριωμένες απαιτήσεις token και δημιουργίας διεργασιών:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Ένα **primary token** χρειάζεται ένα handle με `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` προτού δοθεί στο `CreateProcessWithTokenW` ή στο `CreateProcessAsUserW`.
2. Μετατρέψτε ένα **impersonation token** με `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Τα token επιπέδου Identification μπορούν να αποκαλύψουν δεδομένα ταυτότητας, αλλά δεν μπορούν να εκτελέσουν ελέγχους πρόσβασης ως εκείνος ο πελάτης.
3. Το `CreateProcessWithTokenW` απαιτεί το `SeImpersonatePrivilege` και εκκινεί τη θυγατρική διεργασία στην περίοδο σύνδεσης του καλούντος. Αντίθετα, το `CreateProcessAsUserW` χρησιμοποιεί την περίοδο σύνδεσης του token, αλλά συνήθως απαιτεί το `SeIncreaseQuotaPrivilege` και ενδέχεται να απαιτεί το `SeAssignPrimaryTokenPrivilege`. Αν υπάρχουν διαθέσιμα διαπιστευτήρια και λείπουν αυτά τα προνόμια, η τεκμηριωμένη εναλλακτική είναι το `CreateProcessWithLogonW`.

#### Αναζητήστε handles token, όχι μόνο κατόχους διεργασιών

Το άνοιγμα του primary token κάθε διεργασίας μπορεί να παραβλέψει **impersonation token που διατηρούνται ως συνηθισμένα handles** μέσα σε υπηρεσίες και διεργασίες broker. Μια επαναχρησιμοποιήσιμη ροή εργασίας για τον πίνακα handles είναι να απαριθμήσετε τα handles του συστήματος, να φιλτράρετε τα αντικείμενα token, να ανοίξετε κάθε κάτοχο με `PROCESS_DUP_HANDLE`, να αντιγράψετε το υποψήφιο handle στην τρέχουσα διεργασία και, στη συνέχεια, να ελέγξετε τα παραπάνω πεδία. Επιβεβαιώστε ότι το διπλότυπο handle περιλαμβάνει τα `TOKEN_QUERY` και `TOKEN_DUPLICATE`· το ότι εντοπίστηκε ένα handle token δεν σημαίνει ότι μπορεί να αντιγραφεί σε ένα αξιοποιήσιμο primary token. Οι προστατευμένες διεργασίες και οι DACL διεργασιών εξακολουθούν να μπορούν να εμποδίσουν το handle της διεργασίας-κατόχου.<sup>[[11]](#references)[[12]](#references)</sup>

Το `SharpToken` αυτοματοποιεί την απαρίθμηση τόσο των primary token διεργασιών όσο και των διατηρούμενων handles token. Το `list_token` διατηρεί έναν προτιμώμενο υποψήφιο ανά όνομα χρήστη, ενώ το `list_all_token` εμφανίζει όλους τους υποψηφίους. Ένα PID περιορίζει την απαρίθμηση σε μία διεργασία-κάτοχο.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Για μη αυτόματο έλεγχο και επαλήθευση πρόσβασης, το **TokenUniverse** μπορεί να ανοίγει tokens διεργασιών/νημάτων, να αναζητά υπάρχοντα handles tokens, να επιθεωρεί περιορισμούς και logon sessions, να αντιγράφει tokens και να δοκιμάζει διάφορες μεθόδους δημιουργίας διεργασιών.<sup>[[13]](#references)</sup> Για το υποκείμενο primitive handles μεταξύ διεργασιών, δείτε:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

Χρησιμοποιώντας το module _**incognito**_ του metasploit, αν έχετε αρκετά προνόμια, μπορείτε εύκολα να **εμφανίσετε** και να **προσποιηθείτε** άλλα **tokens**. Αυτό μπορεί να είναι χρήσιμο για να εκτελείτε **ενέργειες σαν να ήσασταν ο άλλος χρήστης**. Θα μπορούσατε επίσης να **κλιμακώσετε προνόμια** με αυτήν την τεχνική.

Μερικές πρακτικές σημειώσεις που είναι εύκολο να ξεχαστούν κατά τη χρήση:<sup>[[1]](#references)</sup>

- Το **`CreateProcessWithTokenW`** απαιτεί **`SeImpersonatePrivilege`** από τον caller και η νέα διεργασία θα εκτελεστεί στο **session του caller**.
- Το **`CreateProcessAsUserW`** είναι πιθανή εναλλακτική όταν το `CreateProcessWithTokenW` αποτυγχάνει με `1314`, μόνο αν ο caller πληροί τις απαιτήσεις προνομίων του. Είναι επίσης η σωστή επιλογή όταν η θυγατρική διεργασία πρέπει να εκτελεστεί στο **session που αναφέρεται από το token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Αν ένα token προέρχεται από **`LogonUser(LOGON32_LOGON_NETWORK)`**, συνήθως είναι **impersonation token**, οπότε χρειάζεται **`DuplicateTokenEx(..., TokenPrimary, ...)`** πριν επιχειρήσετε να εκκινήσετε διεργασία με αυτό.
- Δεν είναι όλα τα impersonation tokens εξίσου χρήσιμα: το **`SecurityIdentification`** σάς επιτρέπει να επιθεωρήσετε τον χρήστη, αλλά **όχι να ενεργήσετε ως αυτός**. Αν ένα coercion primitive ή ένας client pipe/RPC σάς δώσει μόνο token επιπέδου identification, ελέγξτε το **`TokenImpersonationLevel`** και επιλέξτε primitive που παρέχει **`SecurityImpersonation`** ή ανώτερο επίπεδο.

#### Κλοπή token χωρίς πρόσβαση στο LSASS

Αν έχετε ήδη context **service** ή **SYSTEM** και είναι συνδεδεμένος ένας **προνομιούχος χρήστης**, η κλοπή ή αντιγραφή του token αυτού του χρήστη είναι συχνά πιο διακριτική από την εξαγωγή δεδομένων από το **LSASS**. Σε πολλές πραγματικές εισβολές, αυτό αρκεί για να:<sup>[[2]](#references)</sup>

- εκτελείτε τοπικές ενέργειες ως αυτός ο χρήστης
- αποκτάτε πρόσβαση σε απομακρυσμένους πόρους ως αυτός ο χρήστης
- εκτελείτε λειτουργίες AD χωρίς να εξαγάγετε πρώτα επαναχρησιμοποιήσιμα credentials

Για παραδείγματα **παραβίασης session/user token** από προνομιούχο context, δείτε το [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Να θυμάστε ότι API όπως το **`WTSQueryUserToken`** προορίζονται για **υπηρεσίες υψηλής εμπιστοσύνης** και συνήθως απαιτούν **`LocalSystem` + `SeTcbPrivilege`**, επομένως είναι κυρίως χρήσιμα αφού αποκτήσετε ήδη έλεγχο σε context επιπέδου service. Για τρόπους απόκτησης **SYSTEM** που απαιτούν συγκεκριμένα προνόμια, δείτε τις παρακάτω σελίδες.

### Token Privileges

Μάθετε ποια **token privileges μπορούν να χρησιμοποιηθούν για κλιμάκωση προνομίων:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Δείτε [**όλα τα πιθανά token privileges και ορισμένους ορισμούς σε αυτήν την εξωτερική σελίδα**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Κατανόηση και κατάχρηση Access Tokens — Μέρος II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Κατάχρηση των Windows tokens για παραβίαση του Active Directory χωρίς πρόσβαση στο LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Αποσαφήνιση της εντολής "make_token" του Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Πώς λειτουργεί το User Account Control - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Επίπεδα Impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Απαρίθμηση TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Περιορισμένα Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Συνάρτηση CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Συνάρτηση CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Συνάρτηση DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
