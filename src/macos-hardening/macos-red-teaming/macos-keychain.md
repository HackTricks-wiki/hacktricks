# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Κύρια Keychains

- Το **User Keychain** (`~/Library/Keychains/login.keychain-db`), το οποίο χρησιμοποιείται για την αποθήκευση **user-specific credentials**, όπως passwords εφαρμογών, internet passwords, certificates που δημιουργούνται από τον χρήστη, network passwords και public/private keys που δημιουργούνται από τον χρήστη.
- Το **System Keychain** (`/Library/Keychains/System.keychain`), το οποίο αποθηκεύει **system-wide credentials**, όπως passwords WiFi, system root certificates, system private keys και system application passwords.<sup>[[1]](#references)</sup>
- Είναι δυνατό να βρεθούν και άλλα components, όπως certificates, στο `/System/Library/Keychains/*`
- Στο **iOS** υπάρχει μόνο ένα **Keychain**, το οποίο βρίσκεται στο `/private/var/Keychains/`. Αυτός ο φάκελος περιέχει επίσης databases για το `TrustStore`, certificate authorities (`caissuercache`) και OSCP entries (`ocspache`).
- Οι εφαρμογές περιορίζονται στο private area τους μέσα στο keychain, με βάση το application identifier τους.

### Password Keychain Access

Αυτά τα αρχεία, παρότι δεν διαθέτουν εγγενή προστασία και μπορούν να **downloaded**, είναι encrypted και απαιτούν το **plaintext password του χρήστη για να γίνει decrypt**. Ένα tool όπως το [**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για decryption.<sup>[[1]](#references)</sup>

## Προστασίες Keychain Entries

### ACLs

Κάθε entry στο keychain διέπεται από **Access Control Lists (ACLs)**, οι οποίες καθορίζουν ποιος μπορεί να εκτελεί διάφορες ενέργειες στο keychain entry, όπως:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Επιτρέπει στον holder να λάβει το clear text του secret.
- **ACLAuhtorizationExportWrapped**: Επιτρέπει στον holder να λάβει το clear text encrypted με άλλο password που παρέχεται.
- **ACLAuhtorizationAny**: Επιτρέπει στον holder να εκτελεί οποιαδήποτε ενέργεια.

Τα ACLs συνοδεύονται επιπλέον από μια **list trusted applications**, οι οποίες μπορούν να εκτελούν αυτές τις ενέργειες χωρίς prompt. Αυτή μπορεί να είναι:<sup>[[1]](#references)</sup>

- **N`il`** (δεν απαιτείται authorization, **everyone is trusted**)
- Μια **empty** list (**nobody** is trusted)
- **List** συγκεκριμένων **applications**.

Επίσης, το entry μπορεί να περιέχει το key **`ACLAuthorizationPartitionID`,** το οποίο χρησιμοποιείται για την αναγνώριση των **teamid, apple,** και **cdhash.**<sup>[[1]](#references)</sup>

- Αν καθορίζεται το **teamid**, τότε για να γίνει **access στο entry** value **without** **prompt**, η εφαρμογή που χρησιμοποιείται πρέπει να έχει το **ίδιο teamid**.
- Αν καθορίζεται το **apple**, τότε η εφαρμογή πρέπει να είναι **signed** από την **Apple**.
- Αν υποδεικνύεται το **cdhash**, τότε η **app** πρέπει να έχει το συγκεκριμένο **cdhash**.

### Δημιουργία Keychain Entry

Όταν δημιουργείται ένα **new** **entry** μέσω του **`Keychain Access.app`**, ισχύουν οι ακόλουθοι κανόνες:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κάνουν encrypt.
- **Καμία εφαρμογή** δεν μπορεί να κάνει export/decrypt (χωρίς prompt προς τον χρήστη).
- Όλες οι εφαρμογές μπορούν να δουν το integrity check.
- Καμία εφαρμογή δεν μπορεί να αλλάξει τα ACLs.
- Το **partitionID** ορίζεται σε **`apple`**.

Όταν μια **εφαρμογή δημιουργεί ένα entry στο keychain**, οι κανόνες είναι ελαφρώς διαφορετικοί:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κάνουν encrypt.
- Μόνο η **εφαρμογή που το δημιούργησε** (ή οποιεσδήποτε άλλες εφαρμογές έχουν προστεθεί ρητά) μπορεί να κάνει export/decrypt (χωρίς prompt προς τον χρήστη).
- Όλες οι εφαρμογές μπορούν να δουν το integrity check.
- Καμία εφαρμογή δεν μπορεί να αλλάξει τα ACLs.
- Το **partitionID** ορίζεται σε **`teamid:[teamID here]`**.

## Πρόσβαση στο Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> Η **keychain enumeration and dumping** μυστικών που **δεν θα δημιουργήσουν prompt** μπορεί να γίνει με το εργαλείο [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Άλλα API endpoints μπορούν να βρεθούν στον πηγαίο κώδικα του [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Κάντε list και λάβετε **info** για κάθε καταχώριση keychain χρησιμοποιώντας το **Security Framework** ή μπορείτε επίσης να ελέγξετε το open source cli tool της Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Μερικά παραδείγματα API:<sup>[[1]](#references)</sup>

- Το API **`SecItemCopyMatching`** παρέχει info για κάθε καταχώριση και υπάρχουν ορισμένα attributes που μπορείτε να ορίσετε όταν το χρησιμοποιείτε:
- **`kSecReturnData`**: Αν είναι true, θα προσπαθήσει να αποκρυπτογραφήσει τα δεδομένα (ορίστε το σε false για να αποφύγετε πιθανά pop-ups)
- **`kSecReturnRef`**: Λάβετε επίσης reference στο keychain item (ορίστε το σε true σε περίπτωση που αργότερα δείτε ότι μπορείτε να το αποκρυπτογραφήσετε χωρίς pop-up)
- **`kSecReturnAttributes`**: Λάβετε metadata για τις καταχωρίσεις
- **`kSecMatchLimit`**: Πόσα αποτελέσματα θα επιστραφούν
- **`kSecClass`**: Τι είδους keychain entry είναι

Λάβετε τα **ACLs** κάθε καταχώρισης:<sup>[[1]](#references)</sup>

- Με το API **`SecAccessCopyACLList`** μπορείτε να λάβετε το **ACL για το keychain item**, και θα επιστρέψει μια λίστα από ACLs (όπως τα `ACLAuhtorizationExportClear` και τα υπόλοιπα που αναφέρθηκαν προηγουμένως), όπου κάθε λίστα περιέχει:
- Περιγραφή
- **Trusted Application List**. Αυτή μπορεί να είναι:
- Ένα app: /Applications/Slack.app
- Ένα binary: /usr/libexec/airportd
- Ένα group: group://AirPort

Κάντε export τα δεδομένα:<sup>[[1]](#references)</sup>

- Το API **`SecKeychainItemCopyContent`** λαμβάνει το plaintext
- Το API **`SecItemExport`** κάνει export τα keys και τα certificates, αλλά ενδέχεται να χρειαστεί να ορίσετε passwords για να κάνετε export το περιεχόμενο κρυπτογραφημένο

Και αυτές είναι οι **προϋποθέσεις** για να μπορείτε να κάνετε **export ένα secret χωρίς prompt**:<sup>[[1]](#references)</sup>

- Αν αναφέρονται **1+ trusted** apps:
- Χρειάζονται τα κατάλληλα **authorizations** (**`Nil`** ή να είστε **μέρος** της επιτρεπόμενης λίστας apps στην authorization για πρόσβαση στο secret info)
- Η code signature πρέπει να ταιριάζει με το **PartitionID**
- Η code signature πρέπει να ταιριάζει με εκείνη ενός **trusted app** (ή να είστε μέλος του σωστού KeychainAccessGroup)
- Αν **όλες οι εφαρμογές είναι trusted**:
- Χρειάζονται τα κατάλληλα **authorizations**
- Η code signature πρέπει να ταιριάζει με το **PartitionID**
- Αν δεν υπάρχει **PartitionID**, αυτό δεν απαιτείται

> [!CAUTION]
> Επομένως, αν αναφέρεται **1 application**, χρειάζεται να κάνετε **inject code σε αυτή την εφαρμογή**.
>
> Αν στο **partitionID** αναφέρεται το **apple**, θα μπορούσατε να αποκτήσετε πρόσβαση με το **`osascript`**, επομένως οτιδήποτε εμπιστεύεται όλες τις εφαρμογές με το apple στο partitionID. Για αυτό θα μπορούσε επίσης να χρησιμοποιηθεί **`Python`**.

### Δύο επιπλέον attributes

- **Invisible**: Είναι ένα boolean flag για να **κρύβει** την καταχώριση από το **UI** Keychain app<sup>[[1]](#references)</sup>
- **General**: Χρησιμοποιείται για την αποθήκευση **metadata** (επομένως ΔΕΝ ΕΙΝΑΙ ΚΡΥΠΤΟΓΡΑΦΗΜΕΝΟ)<sup>[[1]](#references)</sup>
- Η Microsoft αποθήκευε σε plain text όλα τα refresh tokens για πρόσβαση σε sensitive endpoint.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
