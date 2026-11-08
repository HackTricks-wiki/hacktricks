# Tokens πρόσβασης

{{#include ../../banners/hacktricks-training.md}}

## Tokens πρόσβασης

Κάθε διεργασία έχει ένα **κύριο token πρόσβασης** που καθορίζει το πλαίσιο ασφαλείας της. Ένα νήμα χρησιμοποιεί κανονικά αυτό το token, αλλά μπορεί επίσης να έχει προσωρινά ένα **token πλαστοπροσωπίας**. Τα tokens περιέχουν το SID του χρήστη, SID ομάδων, προνόμια, πληροφορίες ακεραιότητας και ένα SID σύνδεσης για την περίοδο σύνδεσης. Οι διεργασίες συνήθως κληρονομούν μια αναφορά στο κύριο token της γονικής διεργασίας· δεν λαμβάνουν ανεξάρτητο αντίγραφο του περιεχομένου του.<sup>[[4]](#references)</sup>

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

### Τοπικός διαχειριστής

Όταν εφαρμόζεται το **UAC Admin Approval Mode** σε έναν διαχειριστή, η διαδραστική σύνδεση δημιουργεί ένα πλήρες διακριτικό διαχειριστή και ένα φιλτραρισμένο διακριτικό. Ο Explorer και οι συνήθεις θυγατρικές διεργασίες χρησιμοποιούν από προεπιλογή το φιλτραρισμένο διακριτικό. Ένα αίτημα ανύψωσης, όπως το **Run as administrator**, ζητά από το UAC να εκκινήσει το πρόγραμμα με το πλήρες διακριτικό. Η ακριβής συμπεριφορά διαφέρει για τον ενσωματωμένο λογαριασμό Administrator και όταν είναι απενεργοποιημένο το Admin Approval Mode.<sup>[[5]](#references)</sup>

Διαβάστε την ειδική [**σελίδα UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) για τεχνικές παράκαμψης και λεπτομέρειες πολιτικής.

Στην πράξη, αυτό σημαίνει ότι ένα **μη ανυψωμένο admin shell συνήθως εκτελείται με φιλτραρισμένο διακριτικό**. Γι' αυτό η εντολή `whoami /groups` εμφανίζει συχνά το **`BUILTIN\Administrators` ως `Deny only`** μέχρι να ανυψωθεί η διεργασία. Εσωτερικά, τα Windows διατηρούν ένα **συνδεδεμένο ανυψωμένο διακριτικό** (`TokenLinkedToken`) και παρακολουθούν την κατάσταση με πεδία όπως το `TokenElevationType`.

### Πλαστοπροσωπία χρήστη με διαπιστευτήρια

Εάν έχετε **έγκυρα διαπιστευτήρια οποιουδήποτε άλλου χρήστη**, μπορείτε να **δημιουργήσετε** μια **νέα περίοδο σύνδεσης** με αυτά τα διαπιστευτήρια :

```
runas /user:domain\username cmd.exe
```

Το **access token** περιέχει επίσης μια **αναφορά** στις περιόδους σύνδεσης μέσα στο **LSASS**· αυτό είναι χρήσιμο αν η διεργασία χρειάζεται να αποκτήσει πρόσβαση σε ορισμένα αντικείμενα του δικτύου.\
Μπορείτε να εκκινήσετε μια διεργασία που **χρησιμοποιεί διαφορετικά διαπιστευτήρια για την πρόσβαση σε υπηρεσίες δικτύου** χρησιμοποιώντας:

```
runas /user:domain\username /netonly cmd.exe
```

Αυτό είναι χρήσιμο αν έχετε credentials για πρόσβαση σε αντικείμενα στο δίκτυο, αλλά αυτά τα credentials δεν είναι έγκυρα στον τρέχοντα host, καθώς θα χρησιμοποιηθούν μόνο στο δίκτυο (στον τρέχοντα host θα χρησιμοποιηθούν τα τρέχοντα προνόμια του χρήστη σας).

#### Λεπτομέρειες του `runas /netonly`

Το `runas /netonly` (και βοηθητικά εργαλεία C2 όπως το `make_token`) δημιουργεί ένα token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Αυτό είναι πολύ χρήσιμο να το κατανοήσετε κατά τη διάρκεια lateral movement, επειδή:<sup>[[3]](#references)</sup>

- **Τοπικά**, η νέα διεργασία διατηρεί την **ίδια τοπική ταυτότητα**, τις ομάδες, το επίπεδο ακεραιότητας και τις περισσότερες από τις ίδιες αποφάσεις πρόσβασης με το τρέχον token.
- **Απομακρυσμένα**, ο εξερχόμενος authentication μπορεί να χρησιμοποιήσει τα **παρεχόμενα credentials** για SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Επομένως, το `whoami` μπορεί να εξακολουθεί να εμφανίζει τον **αρχικό τοπικό χρήστη**, ενώ η πρόσβαση στο δίκτυο γίνεται ως ο **εναλλακτικός λογαριασμός**.

Αυτή είναι μια πολύ καλή επιλογή όταν τα credentials είναι έγκυρα στο domain ή σε κάποιον άλλο host, αλλά ο χρήστης **δεν μπορεί ή δεν πρέπει να συνδεθεί τοπικά** στον τρέχοντα υπολογιστή.

### Τύποι token

Υπάρχουν δύο διαθέσιμοι τύποι token:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Αντιπροσωπεύει το πλαίσιο ασφαλείας μιας διεργασίας. Μια θυγατρική διεργασία συνήθως κληρονομεί το primary token της γονικής διεργασίας, ενώ τα API δημιουργίας διεργασιών με ρητό token επιβάλλουν τις δικές τους απαιτήσεις πρόσβασης στο token και προνομίων του caller.
- **Impersonation token**: Επιτρέπει σε ένα thread διακομιστή να χρησιμοποιεί προσωρινά το πλαίσιο ασφαλείας ενός client για ελέγχους πρόσβασης. Τα τέσσερα επίπεδά του είναι:
  - **Anonymous**: Παρέχει στον server πρόσβαση αντίστοιχη με εκείνη ενός μη ταυτοποιημένου χρήστη.
  - **Identification**: Επιτρέπει στον server να επαληθεύσει την ταυτότητα του client χωρίς να τη χρησιμοποιήσει για πρόσβαση σε αντικείμενα.
  - **Impersonation**: Επιτρέπει στον server να λειτουργεί με την ταυτότητα του client.
  - **Delegation**: Επιτρέπει στον server να κάνει impersonation του client σε απομακρυσμένα συστήματα, όταν ο μηχανισμός authentication και η διαμόρφωση του λογαριασμού υποστηρίζουν delegation.

#### Αξιολογήστε ένα captured token πριν το χρησιμοποιήσετε

Μην επιλέγετε token μόνο με βάση το username. Ο ίδιος λογαριασμός μπορεί να έχει πολλά token με διαφορετικά logon sessions, service SID, privileges, επίπεδα ακεραιότητας, περιορισμούς και network credentials.<sup>[[9]](#references)</sup> Ανακτήστε τουλάχιστον τα **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** και **`TokenStatistics.AuthenticationId`** με το `GetTokenInformation`.<sup>[[7]](#references)</sup>

Ένα restricted token μπορεί να περιέχει SID μόνο για άρνηση, αφαιρεμένα privileges και περιοριστικά SID. Όταν υπάρχουν περιοριστικά SID, τα Windows εκτελούν έναν έλεγχο πρόσβασης με τα ενεργοποιημένα SID και έναν δεύτερο με τα περιοριστικά SID· **και οι δύο έλεγχοι πρέπει να επιτρέπουν την πρόσβαση**. Επομένως, ένα ελκυστικό user SID ή μια ενεργοποιημένη ομάδα στην έξοδο δεν αποδεικνύει από μόνο του ότι το token μπορεί να αποκτήσει πρόσβαση στο αντικείμενο-στόχο.<sup>[[8]](#references)</sup>

Χρησιμοποιήστε αυτή τη ροή αποφάσεων για τις τεκμηριωμένες απαιτήσεις token και δημιουργίας διεργασιών:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Ένα **primary token** χρειάζεται ένα handle με `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` προτού μπορέσει να δοθεί στα `CreateProcessWithTokenW` ή `CreateProcessAsUserW`.
2. Μετατρέψτε ένα **impersonation token** με `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Τα token επιπέδου Identification μπορούν να αποκαλύψουν δεδομένα ταυτότητας, αλλά δεν μπορούν να εκτελέσουν ελέγχους πρόσβασης ως ο συγκεκριμένος client.
3. Το `CreateProcessWithTokenW` χρειάζεται το `SeImpersonatePrivilege` και ξεκινά τη θυγατρική διεργασία στο session του caller. Αντίθετα, το `CreateProcessAsUserW` χρησιμοποιεί το session του token, αλλά συνήθως χρειάζεται το `SeIncreaseQuotaPrivilege` και μπορεί να χρειαστεί το `SeAssignPrimaryTokenPrivilege`. Αν υπάρχουν διαθέσιμα credentials και λείπουν αυτά τα privileges, η τεκμηριωμένη εναλλακτική είναι το `CreateProcessWithLogonW`.

#### Αναζητήστε handles token, όχι μόνο owners διεργασιών

Το άνοιγμα του primary token κάθε διεργασίας μπορεί να παραλείψει **impersonation token που διατηρούνται ως συνηθισμένα handles** μέσα σε υπηρεσίες και broker διεργασίες. Μια επαναχρησιμοποιήσιμη ροή εργασίας για τον πίνακα handles είναι να απαριθμήσετε τα system handles, να φιλτράρετε τα token objects, να ανοίξετε κάθε owner με `PROCESS_DUP_HANDLE`, να αντιγράψετε το υποψήφιο handle στην τρέχουσα διεργασία και, στη συνέχεια, να ανακτήσετε τα πεδία που αναφέρθηκαν παραπάνω. Επιβεβαιώστε ότι το αντιγραμμένο handle περιλαμβάνει τα `TOKEN_QUERY` και `TOKEN_DUPLICATE`· η εύρεση ενός token handle δεν σημαίνει ότι μπορεί να αντιγραφεί σε ένα αξιοποιήσιμο primary token. Τα protected processes και τα DACL των διεργασιών εξακολουθούν να μπορούν να εμποδίσουν το handle προς τη διεργασία-owner.<sup>[[11]](#references)[[12]](#references)</sup>

Το `SharpToken` αυτοματοποιεί τόσο την απαρίθμηση primary token διεργασιών όσο και τη διατήρηση token handle. Το `list_token` διατηρεί έναν προτιμώμενο υποψήφιο ανά username, ενώ το `list_all_token` εμφανίζει όλους τους υποψηφίους. Ένα PID περιορίζει την απαρίθμηση σε μία διεργασία-owner.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Για χειροκίνητο έλεγχο και επαλήθευση πρόσβασης, το **TokenUniverse** μπορεί να ανοίγει tokens διεργασιών/νημάτων, να αναζητά υπάρχοντα handles tokens, να ελέγχει περιορισμούς και logon sessions, να αντιγράφει tokens και να δοκιμάζει διάφορες μεθόδους δημιουργίας διεργασιών.<sup>[[13]](#references)</sup> Για το υποκείμενο primitive handles μεταξύ διεργασιών, δείτε:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Εντοπισμός ενεργών tokens impersonation νημάτων

Ένα νήμα υπηρεσίας μπορεί προσωρινά να κάνει impersonation ενός client, ακόμη κι όταν το **primary token της διεργασίας** ανήκει στον λογαριασμό της υπηρεσίας. Έτσι, οι σαρώσεις του κατόχου διεργασιών μπορεί να μη βρουν το context του client.<sup>[[4]](#references)</sup> Το TokenUniverse μπορεί να εμφανίζει προσβάσιμα tokens διεργασιών/νημάτων. Στο System Informer, ελέγξτε την καρτέλα **Threads** μιας διεργασίας και τη στήλη **Impersonation** για να εντοπίσετε πιθανά νήματα.<sup>[[13]](#references)[[14]](#references)</sup>

Για στοχευμένο έλεγχο μέσω API, λάβετε ένα snapshot `TH32CS_SNAPTHREAD`, φιλτράρετε το `THREADENTRY32.th32OwnerProcessID` με βάση το PID της υπηρεσίας και, στη συνέχεια, καλέστε `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` και `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` για κάθε προσβάσιμο νήμα.<sup>[[15]](#references)[[16]](#references)</sup> Η τιμή `TRUE` κάνει τον έλεγχο πρόσβασης κατά το άνοιγμα του token να χρησιμοποιεί το context **της διεργασίας** του caller. Αυτό έχει σημασία αν ο scanner κάνει ο ίδιος impersonation στο επίπεδο identification.<sup>[[17]](#references)</sup> Ελέγξτε τον χρήστη, τον τύπο, το επίπεδο impersonation και το logon ID του token πριν δοκιμάσετε τη ροή αντιγραφής και δημιουργίας διεργασίας που περιγράφεται παραπάνω.<sup>[[7]](#references)</sup> Ένα νήμα μπορεί να σταματήσει το impersonation μεταξύ της απαρίθμησης και του ανοίγματός του. Η απουσία token, τα anonymous tokens, τα προστατευμένα νήματα, τα DACL νημάτων και τα DACL tokens μπορούν να εμποδίσουν τη συλλογή.<sup>[[16]](#references)[[17]](#references)</sup> Σε αντίθεση με τη σάρωση των διατηρούμενων handles tokens μιας υπηρεσίας, αυτός ο έλεγχος εξετάζει το **token που έχει εκχωρηθεί αυτήν τη στιγμή στο νήμα**.

Για μια διαδρομή επίθεσης που αποκτά token νήματος κάνοντας έναν privileged client να συνδεθεί στο pipe σας, αντί να σαρώσει υπάρχοντα νήματα, δείτε το [named-pipe client impersonation](named-pipe-client-impersonation.md).

#### Impersonate Tokens

Χρησιμοποιώντας το module _**incognito**_ του metasploit, αν έχετε αρκετά δικαιώματα, μπορείτε εύκολα να **εμφανίσετε** και να κάνετε **impersonation** άλλων **tokens**. Αυτό μπορεί να είναι χρήσιμο για την εκτέλεση **ενεργειών σαν να ήσασταν ο άλλος χρήστης**. Μπορείτε επίσης να **κλιμακώσετε τα δικαιώματά σας** με αυτήν την τεχνική.

Ορισμένες πρακτικές λεπτομέρειες που είναι εύκολο να ξεχάσετε κατά τη χρήση:<sup>[[1]](#references)</sup>

- Το **`CreateProcessWithTokenW`** απαιτεί **`SeImpersonatePrivilege`** από τον caller, και η νέα διεργασία θα εκτελεστεί στο **session του caller**.
- Το **`CreateProcessAsUserW`** είναι πιθανή εναλλακτική λύση όταν το `CreateProcessWithTokenW` αποτυγχάνει με `1314`, μόνο αν ο caller πληροί τις απαιτήσεις δικαιωμάτων του. Είναι επίσης η σωστή επιλογή όταν η child διεργασία πρέπει να εκτελεστεί στο **session που αναφέρεται από το token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Το **`LogonUser(LOGON32_LOGON_NETWORK)`** επιστρέφει ένα **impersonation token**. Μετατρέψτε το με `DuplicateTokenEx(..., TokenPrimary, ...)` πριν από τη δημιουργία διεργασίας. Ακόμη και μετά τη μετατροπή, η διεργασία που προκύπτει δεν μπορεί να χρησιμοποιήσει αυτό το network logon για πρόσβαση σε απομακρυσμένα shares ή printers που απαιτούν authentication: αυτός ο τύπος logon δεν αποθηκεύει credentials. Αν έχετε credentials και χρειάζεστε περαιτέρω πρόσβαση στο δίκτυο, χρησιμοποιήστε interactive ή network-cleartext logon. Μην το συγχέετε με το `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), το οποίο διατηρεί την τοπική ταυτότητα ενώ παρέχει credentials για εξερχόμενες συνδέσεις.<sup>[[18]](#references)</sup>
- Δεν είναι εξίσου χρήσιμα όλα τα impersonation tokens: το **`SecurityIdentification`** σάς επιτρέπει να ελέγξετε τον χρήστη, αλλά **όχι να ενεργήσετε ως αυτός**. Αν ένα coercion primitive ή ένας client pipe/RPC σάς δώσει μόνο token επιπέδου identification, ελέγξτε το **`TokenImpersonationLevel`** και χρησιμοποιήστε primitive που παρέχει **`SecurityImpersonation`** ή ανώτερο επίπεδο.

#### Κλοπή token χωρίς πρόσβαση στο LSASS

Αν έχετε ήδη context **service** ή **SYSTEM** και είναι συνδεδεμένος ένας **privileged user**, η κλοπή ή αντιγραφή του token αυτού του χρήστη είναι συχνά πιο διακριτική από την απόρριψη περιεχομένου του **LSASS**. Σε πολλές πραγματικές εισβολές, αυτό αρκεί για να:<sup>[[2]](#references)</sup>

- εκτελέσετε τοπικές ενέργειες ως αυτός ο χρήστης
- αποκτήσετε πρόσβαση σε απομακρυσμένους πόρους ως αυτός ο χρήστης
- εκτελέσετε λειτουργίες AD χωρίς να εξαγάγετε πρώτα credentials που μπορούν να επαναχρησιμοποιηθούν

Για παραδείγματα **session/user token hijacking** από privileged context, δείτε το [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Να θυμάστε ότι API όπως το **`WTSQueryUserToken`** προορίζονται για **υπηρεσίες υψηλής εμπιστοσύνης** και συνήθως απαιτούν **`LocalSystem` + `SeTcbPrivilege`**. Επομένως, είναι κυρίως χρήσιμα όταν έχετε ήδη τον έλεγχο context επιπέδου service. Για τρόπους απόκτησης **SYSTEM** με συγκεκριμένα δικαιώματα, δείτε τις παρακάτω σελίδες.

### Δικαιώματα Token

Μάθετε ποια **δικαιώματα token μπορούν να χρησιμοποιηθούν για κλιμάκωση δικαιωμάτων:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Ρίξτε μια ματιά στη [**σελίδα με όλα τα πιθανά δικαιώματα token και ορισμένους ορισμούς**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Κατανόηση και κατάχρηση των Access Tokens — Μέρος II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
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
- [14] [Αίτημα προσθήκης δυνατότητας thread-token στο System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Διάσχιση της λίστας νημάτων - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
