# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Κύρια Keychains

- Το **User Keychain** (`~/Library/Keychains/login.keychain-db`), το οποίο χρησιμοποιείται για την αποθήκευση **user-specific credentials**, όπως κωδικοί εφαρμογών, internet passwords, certificates που δημιουργούνται από τον χρήστη, network passwords και public/private keys που δημιουργούνται από τον χρήστη.
- Το **System Keychain** (`/Library/Keychains/System.keychain`), το οποίο αποθηκεύει **system-wide credentials**, όπως κωδικούς WiFi, system root certificates, system private keys και system application passwords.<sup>[1]</sup>
- Είναι πιθανό να βρεθούν και άλλα components, όπως certificates, στο `/System/Library/Keychains/*`
- Στο **iOS** υπάρχει μόνο ένα **Keychain**, το οποίο βρίσκεται στο `/private/var/Keychains/`. Αυτός ο φάκελος περιέχει επίσης databases για το `TrustStore`, certificate authorities (`caissuercache`) και OSCP entries (`ocspache`).
- Οι εφαρμογές περιορίζονται στο Keychain μόνο στη private περιοχή τους, με βάση το application identifier.

### Πρόσβαση με κωδικό στο Keychain

Αυτά τα αρχεία, παρότι δεν διαθέτουν εγγενή προστασία και μπορούν να **downloaded**, είναι encrypted και απαιτούν το **plaintext password του χρήστη για να decrypted**. Ένα tool όπως το [**Chainbreaker**](https://github.com/n0fate/chainbreaker) θα μπορούσε να χρησιμοποιηθεί για decryption.<sup>[1]</sup>

## Προστασίες των Keychain Entries

### ACLs

Κάθε entry στο Keychain διέπεται από **Access Control Lists (ACLs)**, οι οποίες καθορίζουν ποιος μπορεί να εκτελεί διάφορες ενέργειες στο Keychain entry, όπως:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Επιτρέπει στον κάτοχο να λάβει το clear text του secret.
- **ACLAuhtorizationExportWrapped**: Επιτρέπει στον κάτοχο να λάβει το clear text encrypted με άλλο παρεχόμενο password.
- **ACLAuhtorizationAny**: Επιτρέπει στον κάτοχο να εκτελέσει οποιαδήποτε ενέργεια.

Τα ACLs συνοδεύονται επίσης από μια **list trusted applications**, οι οποίες μπορούν να εκτελούν αυτές τις ενέργειες χωρίς prompt. Αυτή μπορεί να είναι:<sup>[1]</sup>

- **N`il`** (δεν απαιτείται authorization, **όλοι είναι trusted**)
- Μια **empty** list (**κανείς** δεν είναι trusted)
- **List** συγκεκριμένων **applications**.

Επίσης, το entry μπορεί να περιέχει το key **`ACLAuthorizationPartitionID`,** το οποίο χρησιμοποιείται για την αναγνώριση των **teamid, apple** και **cdhash.**<sup>[1]</sup>

- Αν έχει καθοριστεί το **teamid**, τότε για **access στο entry** value **χωρίς** **prompt**, η χρησιμοποιούμενη εφαρμογή πρέπει να έχει το **ίδιο teamid**.
- Αν έχει καθοριστεί το **apple**, τότε η εφαρμογή πρέπει να είναι **signed** από την **Apple**.
- Αν υποδεικνύεται το **cdhash**, τότε η **app** πρέπει να διαθέτει το συγκεκριμένο **cdhash**.

### Δημιουργία Keychain Entry

Όταν δημιουργείται ένα **new** **entry** με χρήση του **`Keychain Access.app`**, εφαρμόζονται οι ακόλουθοι κανόνες:<sup>[1]</sup>

- Όλες οι apps μπορούν να κάνουν encrypt.
- **Καμία app** δεν μπορεί να κάνει export/decrypt (χωρίς prompt προς τον χρήστη).
- Όλες οι apps μπορούν να δουν το integrity check.
- Καμία app δεν μπορεί να αλλάξει τα ACLs.
- Το **partitionID** ορίζεται σε **`apple`**.

Όταν μια **application δημιουργεί ένα entry στο Keychain**, οι κανόνες είναι ελαφρώς διαφορετικοί:<sup>[1]</sup>

- Όλες οι apps μπορούν να κάνουν encrypt.
- Μόνο η **creating application** (ή οποιεσδήποτε άλλες apps έχουν προστεθεί ρητά) μπορεί να κάνει export/decrypt (χωρίς prompt προς τον χρήστη).
- Όλες οι apps μπορούν να δουν το integrity check.
- Καμία app δεν μπορεί να αλλάξει τα ACLs.
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
> Το **keychain enumeration and dumping** των secrets που **δεν θα δημιουργήσουν prompt** μπορεί να γίνει με το tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Άλλα API endpoints μπορούν να βρεθούν στον source code του [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Κάντε list και λάβετε **info** για κάθε keychain entry χρησιμοποιώντας το **Security Framework** ή μπορείτε επίσης να ελέγξετε το open source cli tool της Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Μερικά API examples:<sup>[1]</sup>

- Το API **`SecItemCopyMatching`** παρέχει info για κάθε entry και υπάρχουν ορισμένα attributes που μπορείτε να ορίσετε κατά τη χρήση του:
- **`kSecReturnData`**: Αν είναι true, θα προσπαθήσει να κάνει decrypt τα δεδομένα (ορίστε το σε false για να αποφύγετε πιθανά pop-ups)
- **`kSecReturnRef`**: Λάβετε επίσης reference στο keychain item (ορίστε το σε true σε περίπτωση που αργότερα διαπιστώσετε ότι μπορείτε να κάνετε decrypt χωρίς pop-up)
- **`kSecReturnAttributes`**: Λάβετε metadata για τα entries
- **`kSecMatchLimit`**: Πόσα results θα επιστραφούν
- **`kSecClass`**: Τι είδους keychain entry είναι

Λάβετε τα **ACLs** κάθε entry:<sup>[1]</sup>

- Με το API **`SecAccessCopyACLList`** μπορείτε να λάβετε το **ACL για το keychain item** και θα επιστρέψει μια λίστα από ACLs (όπως τα `ACLAuhtorizationExportClear` και τα άλλα που αναφέρθηκαν προηγουμένως), όπου κάθε λίστα περιλαμβάνει:
- Description
- **Trusted Application List**. Αυτό μπορεί να είναι:
- Ένα app: /Applications/Slack.app
- Ένα binary: /usr/libexec/airportd
- Ένα group: group://AirPort

Κάντε export τα δεδομένα:<sup>[1]</sup>

- Το API **`SecKeychainItemCopyContent`** λαμβάνει το plaintext
- Το API **`SecItemExport`** κάνει export τα keys και τα certificates, αλλά ίσως χρειαστεί να ορίσετε passwords για να κάνετε export το content encrypted

Και αυτές είναι οι **requirements** για να μπορείτε να κάνετε **export ένα secret χωρίς prompt**:<sup>[1]</sup>

- Αν αναφέρονται **1+ trusted** apps:
- Χρειάζεστε τα κατάλληλα **authorizations** (**`Nil`** ή να είστε **μέρος** της allowed list των apps στο authorization για πρόσβαση στο secret info)
- Το code signature πρέπει να ταιριάζει με το **PartitionID**
- Το code signature πρέπει να ταιριάζει με αυτό ενός **trusted app** (ή να είστε member του σωστού KeychainAccessGroup)
- Αν **όλες οι applications είναι trusted**:
- Χρειάζεστε τα κατάλληλα **authorizations**
- Το code signature πρέπει να ταιριάζει με το **PartitionID**
- Αν δεν υπάρχει **PartitionID**, αυτό δεν χρειάζεται

> [!CAUTION]
> Επομένως, αν υπάρχει **1 application listed**, χρειάζεται να κάνετε **inject code σε αυτή την application**.
>
> Αν αναφέρεται το **apple** στο **partitionID**, θα μπορούσατε να αποκτήσετε πρόσβαση με το **`osascript`**, επομένως οτιδήποτε εμπιστεύεται όλες τις applications με apple στο partitionID. Για αυτό θα μπορούσε επίσης να χρησιμοποιηθεί το **`Python`**.

### Δύο επιπλέον attributes

- **Invisible**: Είναι ένα boolean flag για να **κρύβει** το entry από το **UI** Keychain app<sup>[1]</sup>
- **General**: Χρησιμοποιείται για την αποθήκευση **metadata** (επομένως ΔΕΝ ΕΙΝΑΙ ENCRYPTED)<sup>[1]</sup>
- Η Microsoft αποθήκευε σε plain text όλα τα refresh tokens για πρόσβαση σε sensitive endpoint.<sup>[1]</sup>

## Αναφορές

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
