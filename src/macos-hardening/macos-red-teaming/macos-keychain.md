# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Κύρια Keychains

- Το **User Keychain** (`~/Library/Keychains/login.keychain-db`), το οποίο χρησιμοποιείται για την αποθήκευση **διαπιστευτηρίων συγκεκριμένων χρηστών**, όπως κωδικοί εφαρμογών, κωδικοί Internet, πιστοποιητικά που δημιουργούνται από τον χρήστη, κωδικοί δικτύων και δημόσια/ιδιωτικά κλειδιά που δημιουργούνται από τον χρήστη.
- Το **System Keychain** (`/Library/Keychains/System.keychain`), το οποίο αποθηκεύει **διαπιστευτήρια σε επίπεδο συστήματος**, όπως κωδικούς WiFi, πιστοποιητικά ρίζας συστήματος, ιδιωτικά κλειδιά συστήματος και κωδικούς εφαρμογών συστήματος.<sup>[[1]](#references)</sup>
  - Είναι δυνατό να βρεθούν και άλλα στοιχεία, όπως πιστοποιητικά, στο `/System/Library/Keychains/*`
- Το **data protection keychain** ανά χρήστη εμφανίζεται ως **Local Items** ή **iCloud** στο Keychain Access. Είναι ξεχωριστό από το `login.keychain-db` και περιλαμβάνει τόσο στοιχεία που είναι διαθέσιμα μόνο τοπικά όσο και στοιχεία που συγχρονίζονται· το `security` είναι κυρίως εργαλείο για file-based keychains, επομένως ένα σύντομο αποτέλεσμα `dump-keychain` δεν αποκλείει την ύπαρξη διαπιστευτηρίων εδώ.<sup>[[5]](#references)</sup>
- Στο **iOS** υπάρχει μόνο ένα **Keychain**, το οποίο βρίσκεται στο `/private/var/Keychains/`. Αυτός ο φάκελος περιέχει επίσης βάσεις δεδομένων για το `TrustStore`, τις αρχές πιστοποίησης (`caissuercache`) και τις εγγραφές OSCP (`ocspache`).
  - Στο keychain, οι εφαρμογές περιορίζονται μόνο στην ιδιωτική τους περιοχή, με βάση το αναγνωριστικό της εφαρμογής τους.

### Πρόσβαση στο Password Keychain

Ένα αντιγραμμένο **file-based** keychain δεν είναι plaintext. Η offline αποκρυπτογράφηση των προστατευμένων στοιχείων του απαιτεί τον κωδικό πρόσβασης του keychain ή ισοδύναμο κλειδικό υλικό· το [**Chainbreaker**](https://github.com/n0fate/chainbreaker) στοχεύει αυτή τη μορφή.<sup>[[1]](#references)</sup> Αυτό διαφέρει από τη ζωντανή ανάγνωση σε μια ξεκλείδωτη συνεδρία χρήστη, όπου οι έλεγχοι πρόσβασης των στοιχείων ενδέχεται να επιτρέπουν την ανάγνωση ή να προκαλούν προτροπή, χωρίς να απαιτείται ξανά ο κωδικός σύνδεσης. Το data protection keychain διαθέτει διαφορετικό μοντέλο προστασίας και ομάδων πρόσβασης.<sup>[[5]](#references)</sup>

## Προστασίες των εγγραφών Keychain

### ACLs των file-based keychains

Οι κανόνες `SecAccess` ACL και partition-list παρακάτω περιγράφουν **file-based** keychains. Τα στοιχεία του data protection keychain χρησιμοποιούν ομάδες πρόσβασης code-signing και προαιρετικές συνθήκες `SecAccessControl`· μην συμπεραίνετε την προσβασιμότητά τους από ένα dump file-based ACL.<sup>[[5]](#references)</sup>

Κάθε εγγραφή σε ένα file-based keychain διέπεται από **λίστες ελέγχου πρόσβασης (ACLs)**, οι οποίες καθορίζουν ποιος μπορεί να εκτελεί διάφορες ενέργειες στην εγγραφή του keychain, όπως:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Επιτρέπει στον κάτοχο να λάβει το μυστικό σε μορφή απλού κειμένου.
- **`kSecACLAuthorizationExportWrapped`**: Επιτρέπει στον κάτοχο να λάβει το απλό κείμενο κρυπτογραφημένο με άλλον παρεχόμενο κωδικό πρόσβασης.
- **`kSecACLAuthorizationAny`**: Επιτρέπει στον κάτοχο να εκτελεί οποιαδήποτε ενέργεια.

Οι ACLs συνοδεύονται επιπλέον από μια **λίστα έμπιστων εφαρμογών** που μπορούν να εκτελούν αυτές τις ενέργειες χωρίς προτροπή. Αυτή μπορεί να είναι:<sup>[[1]](#references)</sup>

- **N`il`** (δεν απαιτείται εξουσιοδότηση, **όλοι είναι έμπιστοι**)
- Μια **κενή** λίστα (**κανείς** δεν είναι έμπιστος)
- **Λίστα** συγκεκριμένων **εφαρμογών**.

Επίσης, η εγγραφή μπορεί να περιέχει το κλειδί **`kSecACLAuthorizationPartitionID`,** το οποίο χρησιμοποιείται για τον προσδιορισμό των **teamid, apple** και **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Αν έχει καθοριστεί το **teamid**, η εφαρμογή πρέπει να έχει το **ίδιο teamid** για να **προσπελάσει** την τιμή της **εγγραφής** **χωρίς** **προτροπή**.
- Αν έχει καθοριστεί το **apple**, τότε η εφαρμογή πρέπει να είναι **υπογεγραμμένη** από την **Apple**.
- Αν έχει καθοριστεί το **cdhash**, τότε η **εφαρμογή** πρέπει να έχει το συγκεκριμένο **cdhash**.

### Δημιουργία εγγραφής σε file-based keychain

Κατά τη δημιουργία μιας **νέας** **εγγραφής** μέσω του **`Keychain Access.app`**, ισχύουν οι ακόλουθοι κανόνες:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κρυπτογραφούν.
- **Καμία εφαρμογή** δεν μπορεί να εξαγάγει/αποκρυπτογραφήσει (χωρίς να προτρέψει τον χρήστη).
- Όλες οι εφαρμογές μπορούν να δουν τον έλεγχο ακεραιότητας.
- Καμία εφαρμογή δεν μπορεί να αλλάξει τις ACLs.
- Το **partitionID** ορίζεται σε **`apple`**.

Όταν μια **εφαρμογή δημιουργεί μια εγγραφή στο keychain**, οι κανόνες είναι ελαφρώς διαφορετικοί:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κρυπτογραφούν.
- Μόνο η **εφαρμογή που τη δημιούργησε** (ή οποιεσδήποτε άλλες εφαρμογές έχουν προστεθεί ρητά) μπορεί να εξαγάγει/αποκρυπτογραφήσει (χωρίς να προτρέψει τον χρήστη).
- Όλες οι εφαρμογές μπορούν να δουν τον έλεγχο ακεραιότητας.
- Καμία εφαρμογή δεν μπορεί να αλλάξει τις ACLs.
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
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` ορίζει τη λίστα partition του στοιχείου, ενώ το `-k` παρέχει τον τρέχοντα κωδικό πρόσβασης του Keychain που απαιτείται για αυτή την αλλαγή· η σημαία που δέχεται κωδικό πρόσβασης έχει αποσυρθεί.<sup>[[4]](#references)</sup> Μια επιτυχημένη ενημέρωση δεν αποδεικνύει ότι μια μεταγενέστερη ανάγνωση θα γίνει χωρίς ειδοποίηση: σε ένα παρατηρημένο, απενεργοποιημένο prototype, εξακολουθούσε να εμφανίζεται μήνυμα επιβεβαίωσης όταν γινόταν ερώτημα για το στοιχείο μέσω του `Security.framework`. Ένα matching partition ID αποτελεί μόνο ένα μέρος των ελέγχων ACL και trusted-application που περιγράφονται παραπάνω, επομένως επαληθεύστε την πραγματική διαδρομή ανάγνωσης.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> Η **απαρίθμηση και εξαγωγή των secrets από το Keychain** που **δεν προκαλεί εμφάνιση prompt** μπορεί να γίνει με το εργαλείο [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Άλλα API endpoints βρίσκονται στον πηγαίο κώδικα του [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Χρησιμοποιήστε το **Security Framework** για να καταγράψετε και να λάβετε **πληροφορίες** για κάθε καταχώριση του Keychain ή ελέγξτε επίσης το open source εργαλείο cli της Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Μερικά παραδείγματα API:<sup>[[1]](#references)</sup>

- Το API **`SecItemCopyMatching`** παρέχει πληροφορίες για κάθε καταχώριση και επιτρέπει να ορίσετε ορισμένα attributes κατά τη χρήση του:
  - **`kSecReturnData`**: Αν είναι true, θα επιχειρήσει να αποκρυπτογραφήσει τα δεδομένα (ορίστε το σε false για να αποφύγετε πιθανά pop-up)
  - **`kSecReturnRef`**: Λάβετε μια αναφορά αντικειμένου για ένα key, certificate ή identity· τα στοιχεία κωδικών πρόσβασης δεν έχουν αυτή την αναπαράσταση αντικειμένου. Χρησιμοποιήστε το `kSecReturnPersistentRef` για να προσδιορίσετε έναν κωδικό πρόσβασης σε μεταγενέστερο, στοχευμένο ερώτημα.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Λάβετε metadata για τις καταχωρίσεις
  - **`kSecMatchLimit`**: Πόσα αποτελέσματα να επιστραφούν
  - **`kSecClass`**: Τι είδους καταχώριση Keychain

Λάβετε τα **ACL** κάθε καταχώρισης:<sup>[[1]](#references)</sup>

- Με το API **`SecAccessCopyACLList`** μπορείτε να λάβετε το **ACL για το στοιχείο του Keychain**. Επιστρέφει μια λίστα ACL (όπως τα `kSecACLAuthorizationExportClear` και τα υπόλοιπα που αναφέρθηκαν προηγουμένως), όπου κάθε καταχώριση έχει:<sup>[[1]](#references)[[2]](#references)</sup>
  - Περιγραφή
  - **Λίστα Trusted Application**. Μπορεί να είναι:
    - Μια εφαρμογή: /Applications/Slack.app
    - Ένα binary: /usr/libexec/airportd
    - Μια ομάδα: group://AirPort

Εξαγωγή των δεδομένων:<sup>[[1]](#references)</sup>

- Το API **`SecKeychainItemCopyContent`** λαμβάνει το plaintext
- Το API **`SecItemExport`** εξάγει τα keys και τα certificates, αλλά ενδέχεται να χρειαστεί να ορίσετε κωδικούς πρόσβασης για την εξαγωγή του κρυπτογραφημένου περιεχομένου

Και αυτές είναι οι **προϋποθέσεις** για να μπορείτε να **εξαγάγετε ένα secret χωρίς prompt**:<sup>[[1]](#references)</sup>

- Αν αναφέρονται **1+ trusted** εφαρμογές:
  - Χρειάζονται οι κατάλληλες **εξουσιοδοτήσεις** (**`Nil`** ή να είστε **μέρος** της λίστας επιτρεπόμενων εφαρμογών στην εξουσιοδότηση για πρόσβαση στις ευαίσθητες πληροφορίες)
  - Η υπογραφή κώδικα πρέπει να ταιριάζει με το **PartitionID**
  - Η υπογραφή κώδικα πρέπει να ταιριάζει με εκείνη μιας **trusted app** (ή να είστε μέλος του κατάλληλου KeychainAccessGroup)
- Αν είναι trusted **όλες οι εφαρμογές**:
  - Χρειάζονται οι κατάλληλες **εξουσιοδοτήσεις**
  - Η υπογραφή κώδικα πρέπει να ταιριάζει με το **PartitionID**
    - Αν δεν υπάρχει **PartitionID**, αυτό δεν απαιτείται

> [!CAUTION]
> Επομένως, αν αναφέρεται **1 εφαρμογή**, πρέπει να κάνετε **inject code σε αυτή την εφαρμογή**.
>
> Αν στο **partitionID** αναφέρεται το **apple**, μπορείτε να αποκτήσετε πρόσβαση με το **`osascript`** σε οτιδήποτε εμπιστεύεται όλες τις εφαρμογές με το apple στο partitionID. Μπορεί να χρησιμοποιηθεί και το **`Python`**.

### Δύο επιπλέον attributes

- **Invisible**: Είναι μια boolean σημαία για την **απόκρυψη** της καταχώρισης από την εφαρμογή Keychain του **UI**<sup>[[1]](#references)</sup>
- **General**: Χρησιμοποιείται για την αποθήκευση **metadata** (επομένως ΔΕΝ ΕΙΝΑΙ ΚΡΥΠΤΟΓΡΑΦΗΜΕΝΑ)<sup>[[1]](#references)</sup>
  - Η Microsoft αποθήκευε σε plain text όλα τα refresh tokens για πρόσβαση σε ευαίσθητο endpoint.<sup>[[1]](#references)</sup>

### Data protection keychain: απαρίθμηση και έπειτα ερώτημα για ένα στοιχείο

Εκτελέστε το `SecItemCopyMatching` από μια **υπογεγραμμένη εφαρμογή στο login context του χρήστη-στόχου** με `kSecUseDataProtectionKeychain: true`· μην υποθέτετε ότι το `security dump-keychain` ή ένα προεπιλεγμένο SecItem query αναζήτησε αυτό το store. Ο caller βλέπει μόνο τις εξουσιοδοτημένες ομάδες πρόσβασής του.<sup>[[5]](#references)</sup>

Αν ο κώδικας δοκιμής εκτελείται μέσα σε άλλη διεργασία, η πρόσβασή του στο data protection keychain ακολουθεί τα entitlements του εκτελέσιμου αρχείου host. Ελέγξτε τα πραγματικά signed entitlements με `codesign -d --entitlements - /path/to/Target.app` και δείτε τα [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) για σχετικούς ελέγχους.<sup>[[7]](#references)</sup>

Αρχικά ζητήστε **μόνο attributes** για μία κλάση στοιχείων. Το `kSecAttrSynchronizableAny` περιλαμβάνει αντιστοιχίες τόσο τοπικές όσο και συγχρονιζόμενες με iCloud· αν παραλειφθεί, εξαιρούνται τα συγχρονιζόμενα στοιχεία.<sup>[[8]](#references)</sup> Το `kSecUseAuthenticationUISkip` αποφεύγει το authentication UI κατά την ευρεία απαρίθμηση, με τίμημα την παράλειψη προστατευμένων αντιστοιχιών.<sup>[[9]](#references)</sup> Επαναλάβετε με `kSecClassInternetPassword` αν χρειάζεται.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Για μια επιτρεπόμενη ανάγνωση secret, δημιουργήστε ένα **νέο**, περιορισμένο query για το επιλεγμένο item (για παράδειγμα, class, service και account), ορίστε `kSecReturnData: true` και `kSecMatchLimit: kSecMatchLimitOne` και αναμένετε authentication για το συγκεκριμένο item ή κάποιο σφάλμα. Μην συνδυάζετε το `kSecReturnData` με το `kSecMatchLimitAll` για password items.<sup>[[10]](#references)</sup> Το αποτέλεσμα `errSecItemNotFound` μπορεί επίσης να οφείλεται σε λάθος store, sync filter ή έλλειψη entitlement για το access group και όχι στην απουσία credential.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "Παραβίαση της macOS Keychain με Lock Picking" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Μια νέα έκδοση του macOS stealer MacSync στοχεύει λάτρεις των crypto και developers](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) mirror της man page](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Σχετικά με τα API και τις υλοποιήσεις του Mac keychain](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Βασικές αρχές](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Συνήθη σφάλματα και βέλτιστες πρακτικές](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Πρόσβαση σε items του Keychain με Face ID ή Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
