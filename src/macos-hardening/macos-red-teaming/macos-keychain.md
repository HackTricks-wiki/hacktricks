# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Κύρια Keychains

- Το **User Keychain** (`~/Library/Keychains/login.keychain-db`), το οποίο χρησιμοποιείται για την αποθήκευση **διαπιστευτηρίων συγκεκριμένων χρηστών**, όπως κωδικοί εφαρμογών, κωδικοί internet, πιστοποιητικά που δημιουργούνται από χρήστες, κωδικοί δικτύων και δημόσια/ιδιωτικά κλειδιά που δημιουργούνται από χρήστες.
- Το **System Keychain** (`/Library/Keychains/System.keychain`), το οποίο αποθηκεύει **διαπιστευτήρια σε επίπεδο συστήματος**, όπως κωδικούς WiFi, system root certificates, system private keys και κωδικούς system εφαρμογών.<sup>[[1]](#references)</sup>
- Είναι δυνατό να βρεθούν άλλα στοιχεία, όπως certificates, στο `/System/Library/Keychains/*`
- Στο **iOS** υπάρχει μόνο ένα **Keychain**, το οποίο βρίσκεται στο `/private/var/Keychains/`. Αυτός ο φάκελος περιέχει επίσης databases για το `TrustStore`, certificate authorities (`caissuercache`) και OSCP entries (`ocspache`).
- Οι εφαρμογές περιορίζονται στο Keychain μόνο στη δική τους ιδιωτική περιοχή, με βάση το application identifier.

### Πρόσβαση στο Password Keychain

Αυτά τα αρχεία, παρόλο που δεν διαθέτουν εγγενή προστασία και μπορούν να **ληφθούν**, είναι κρυπτογραφημένα και απαιτούν το **plaintext password του χρήστη για να αποκρυπτογραφηθούν**. Ένα tool όπως το [**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για την αποκρυπτογράφηση.<sup>[[1]](#references)</sup>

## Προστασίες των Keychain Entries

### ACLs

Κάθε entry στο Keychain διέπεται από **Access Control Lists (ACLs)**, οι οποίες καθορίζουν ποιος μπορεί να εκτελεί διάφορες ενέργειες στο Keychain entry, όπως:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Επιτρέπει στον κάτοχο να λάβει το secret σε clear text.
- **ACLAuthorizationExportWrapped**: Επιτρέπει στον κάτοχο να λάβει το clear text κρυπτογραφημένο με άλλο παρεχόμενο password.
- **ACLAuthorizationAny**: Επιτρέπει στον κάτοχο να εκτελέσει οποιαδήποτε ενέργεια.

Οι ACLs συνοδεύονται επιπλέον από μια **λίστα trusted applications** που μπορούν να εκτελούν αυτές τις ενέργειες χωρίς prompt. Αυτή μπορεί να είναι:<sup>[[1]](#references)</sup>

- **N`il`** (δεν απαιτείται authorization, **όλοι είναι trusted**)
- Μια **κενή** λίστα (**κανείς** δεν είναι trusted)
- **Λίστα** συγκεκριμένων **εφαρμογών**.

Επίσης, το entry μπορεί να περιέχει το key **`ACLAuthorizationPartitionID`,** το οποίο χρησιμοποιείται για την αναγνώριση των **teamid, apple** και **cdhash**.<sup>[[1]](#references)</sup>

- Αν έχει καθοριστεί το **teamid**, η εφαρμογή πρέπει να έχει το **ίδιο teamid** για να **αποκτήσει πρόσβαση** στην τιμή του **entry** χωρίς **prompt**.
- Αν έχει καθοριστεί το **apple**, τότε η εφαρμογή πρέπει να είναι **υπογεγραμμένη** από την **Apple**.
- Αν υποδεικνύεται το **cdhash**, τότε η **εφαρμογή** πρέπει να έχει το συγκεκριμένο **cdhash**.

### Δημιουργία Keychain Entry

Όταν δημιουργείται ένα **νέο** **entry** με χρήση του **`Keychain Access.app`**, ισχύουν οι παρακάτω κανόνες:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κάνουν encrypt.
- **Καμία εφαρμογή** δεν μπορεί να κάνει export/decrypt (χωρίς prompt στον χρήστη).
- Όλες οι εφαρμογές μπορούν να δουν το integrity check.
- Καμία εφαρμογή δεν μπορεί να αλλάξει τα ACLs.
- Το **partitionID** ορίζεται σε **`apple`**.

Όταν μια **εφαρμογή δημιουργεί ένα entry στο Keychain**, οι κανόνες διαφέρουν ελαφρώς:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κάνουν encrypt.
- Μόνο η **εφαρμογή που το δημιούργησε** (ή οποιεσδήποτε άλλες εφαρμογές έχουν προστεθεί ρητά) μπορεί να κάνει export/decrypt (χωρίς prompt στον χρήστη).
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> Το **keychain enumeration and dumping** των secrets που **δεν θα δημιουργήσουν prompt** μπορεί να γίνει με το εργαλείο [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Άλλα API endpoints μπορούν να βρεθούν στον πηγαίο κώδικα του [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Παραθέστε και λάβετε **info** για κάθε καταχώριση keychain χρησιμοποιώντας το **Security Framework** ή μπορείτε επίσης να ελέγξετε το open source CLI tool της Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Μερικά παραδείγματα API:<sup>[[1]](#references)</sup>

- Το API **`SecItemCopyMatching`** παρέχει πληροφορίες για κάθε καταχώριση και υπάρχουν ορισμένα attributes που μπορείτε να ορίσετε κατά τη χρήση του:
- **`kSecReturnData`**: Αν είναι true, θα προσπαθήσει να κάνει decrypt τα δεδομένα (ορίστε το σε false για να αποφύγετε πιθανά pop-ups)
- **`kSecReturnRef`**: Λαμβάνει επίσης reference στο keychain item (ορίστε το σε true σε περίπτωση που αργότερα δείτε ότι μπορείτε να κάνετε decrypt χωρίς pop-up)
- **`kSecReturnAttributes`**: Λαμβάνει metadata για τις καταχωρίσεις
- **`kSecMatchLimit`**: Πόσα αποτελέσματα θα επιστραφούν
- **`kSecClass`**: Τι είδους keychain entry είναι

Λάβετε τα **ACLs** κάθε καταχώρισης:<sup>[[1]](#references)</sup>

- Με το API **`SecAccessCopyACLList`** μπορείτε να λάβετε το **ACL για το keychain item**. Επιστρέφει μια λίστα από ACLs (όπως τα `ACLAuthorizationExportClear` και τα άλλα που αναφέρθηκαν προηγουμένως), όπου κάθε καταχώριση έχει:
- Περιγραφή
- **Trusted Application List**. Αυτή μπορεί να είναι:
- Μια εφαρμογή: /Applications/Slack.app
- Ένα binary: /usr/libexec/airportd
- Ένα group: group://AirPort

Κάντε export τα δεδομένα:<sup>[[1]](#references)</sup>

- Το API **`SecKeychainItemCopyContent`** λαμβάνει το plaintext
- Το API **`SecItemExport`** κάνει export τα keys και τα certificates, αλλά ίσως χρειαστεί να ορίσετε passwords για να κάνετε export το content encrypted

Και αυτές είναι οι **απαιτήσεις** για να μπορείτε να κάνετε **export ένα secret χωρίς prompt**:<sup>[[1]](#references)</sup>

- Αν αναφέρονται **1+ trusted** apps:
- Χρειάζεστε τις κατάλληλες **authorizations** (**`Nil`** ή να είστε **μέρος** της επιτρεπόμενης λίστας εφαρμογών στην authorization για πρόσβαση στις πληροφορίες του secret)
- Η code signature πρέπει να ταιριάζει με το **PartitionID**
- Η code signature πρέπει να ταιριάζει με εκείνη μίας **trusted app** (ή να είστε μέλος του σωστού KeychainAccessGroup)
- Αν **όλες οι εφαρμογές είναι trusted**:
- Χρειάζεστε τις κατάλληλες **authorizations**
- Η code signature πρέπει να ταιριάζει με το **PartitionID**
- Αν δεν υπάρχει **PartitionID**, τότε αυτό δεν απαιτείται

> [!CAUTION]
> Επομένως, αν υπάρχει **1 εφαρμογή στη λίστα**, χρειάζεται να κάνετε **inject code σε αυτή την εφαρμογή**.
>
> Αν αναφέρεται το **apple** στο **partitionID**, θα μπορούσατε να αποκτήσετε πρόσβαση με το **`osascript`**, επομένως οτιδήποτε εμπιστεύεται όλες τις εφαρμογές με το apple στο partitionID. Για αυτό μπορεί επίσης να χρησιμοποιηθεί **`Python`**.

### Δύο επιπλέον attributes

- **Invisible**: Είναι ένα boolean flag για την **απόκρυψη** της καταχώρισης από το **UI** Keychain app<sup>[[1]](#references)</sup>
- **General**: Χρησιμοποιείται για την αποθήκευση **metadata** (άρα ΔΕΝ ΕΙΝΑΙ ENCRYPTED)<sup>[[1]](#references)</sup>
- Η Microsoft αποθήκευε σε plain text όλα τα refresh tokens για την πρόσβαση σε sensitive endpoint.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Παραβίαση του macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
