# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Κύρια Keychain

- Το **User Keychain** (`~/Library/Keychains/login.keychain-db`), που χρησιμοποιείται για την αποθήκευση **διαπιστευτηρίων συγκεκριμένων χρηστών**, όπως κωδικών πρόσβασης εφαρμογών, κωδικών πρόσβασης στο διαδίκτυο, πιστοποιητικών που δημιουργούνται από τον χρήστη, κωδικών πρόσβασης δικτύου και δημόσιων/ιδιωτικών κλειδιών που δημιουργούνται από τον χρήστη.
- Το **System Keychain** (`/Library/Keychains/System.keychain`), που αποθηκεύει **διαπιστευτήρια σε επίπεδο συστήματος**, όπως κωδικούς πρόσβασης WiFi, πιστοποιητικά ρίζας συστήματος, ιδιωτικά κλειδιά συστήματος και κωδικούς πρόσβασης εφαρμογών συστήματος.<sup>[[1]](#references)</sup>
  - Είναι πιθανό να βρείτε άλλα στοιχεία, όπως πιστοποιητικά, στη διαδρομή `/System/Library/Keychains/*`
- Στο **iOS** υπάρχει μόνο ένα **Keychain**, το οποίο βρίσκεται στη διαδρομή `/private/var/Keychains/`. Αυτός ο φάκελος περιέχει επίσης βάσεις δεδομένων για το `TrustStore`, τις αρχές πιστοποίησης (`caissuercache`) και τις εγγραφές OSCP (`ocspache`).
  - Οι εφαρμογές περιορίζονται στην ιδιωτική τους περιοχή στο Keychain, βάσει του αναγνωριστικού εφαρμογής τους.

### Πρόσβαση στο Keychain με κωδικό πρόσβασης

Αυτά τα αρχεία, παρότι δεν προστατεύονται εγγενώς και μπορούν να **ληφθούν**, είναι κρυπτογραφημένα και απαιτούν τον **κωδικό πρόσβασης του χρήστη σε απλό κείμενο για να αποκρυπτογραφηθούν**. Για την αποκρυπτογράφηση θα μπορούσε να χρησιμοποιηθεί ένα εργαλείο όπως το [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Προστασίες εγγραφών Keychain

### ACLs

Κάθε εγγραφή στο Keychain διέπεται από **Access Control Lists (ACLs)**, οι οποίες καθορίζουν ποιος μπορεί να εκτελεί διάφορες ενέργειες στην εγγραφή, όπως:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Επιτρέπει στον κάτοχο να λάβει το μυστικό σε απλό κείμενο.
- **`kSecACLAuthorizationExportWrapped`**: Επιτρέπει στον κάτοχο να λάβει το μυστικό σε απλό κείμενο, κρυπτογραφημένο με έναν άλλο παρεχόμενο κωδικό πρόσβασης.
- **`kSecACLAuthorizationAny`**: Επιτρέπει στον κάτοχο να εκτελέσει οποιαδήποτε ενέργεια.

Οι ACLs συνοδεύονται επίσης από μια **λίστα αξιόπιστων εφαρμογών** που μπορούν να εκτελούν αυτές τις ενέργειες χωρίς να εμφανίζεται προτροπή. Αυτή μπορεί να είναι:<sup>[[1]](#references)</sup>

- **N`il`** (δεν απαιτείται εξουσιοδότηση, **όλοι είναι αξιόπιστοι**)
- Μια **κενή** λίστα (**κανείς** δεν είναι αξιόπιστος)
- Μια **λίστα** συγκεκριμένων **εφαρμογών**.

Επίσης, η εγγραφή μπορεί να περιέχει το κλειδί **`kSecACLAuthorizationPartitionID`,** το οποίο χρησιμοποιείται για τον προσδιορισμό των **teamid, apple,** και **cdhash.**<sup>[[1]](#references)[[2]](#references)</sup>

- Αν καθορίζεται το **teamid**, η εφαρμογή πρέπει να έχει το **ίδιο teamid** για να **προσπελάσει την τιμή της εγγραφής** **χωρίς** να εμφανιστεί **προτροπή**.
- Αν καθορίζεται το **apple**, η εφαρμογή πρέπει να είναι **υπογεγραμμένη** από την **Apple**.
- Αν υποδεικνύεται το **cdhash**, η **εφαρμογή** πρέπει να έχει το συγκεκριμένο **cdhash**.

### Δημιουργία εγγραφής Keychain

Όταν δημιουργείται μια **νέα** **εγγραφή** μέσω του **`Keychain Access.app`**, ισχύουν οι ακόλουθοι κανόνες:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κρυπτογραφούν.
- **Καμία εφαρμογή** δεν μπορεί να εξαγάγει/αποκρυπτογραφήσει δεδομένα (χωρίς να εμφανιστεί προτροπή στον χρήστη).
- Όλες οι εφαρμογές μπορούν να δουν τον έλεγχο ακεραιότητας.
- Καμία εφαρμογή δεν μπορεί να αλλάξει τις ACLs.
- Το **partitionID** ορίζεται σε **`apple`**.

Όταν μια **εφαρμογή δημιουργεί μια εγγραφή στο Keychain**, οι κανόνες διαφέρουν ελαφρώς:<sup>[[1]](#references)</sup>

- Όλες οι εφαρμογές μπορούν να κρυπτογραφούν.
- Μόνο η **εφαρμογή που δημιούργησε την εγγραφή** (ή άλλες εφαρμογές που προστέθηκαν ρητά) μπορεί να εξαγάγει/αποκρυπτογραφήσει δεδομένα (χωρίς να εμφανιστεί προτροπή στον χρήστη).
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

`-S` ορίζει τη λίστα partition του στοιχείου, ενώ το `-k` παρέχει τον τρέχοντα κωδικό πρόσβασης του Keychain που απαιτείται για να γίνει αυτή η αλλαγή· η σημαία που δέχεται κωδικό πρόσβασης είναι deprecated.<sup>[[4]](#references)</sup> Μια επιτυχής ενημέρωση δεν αποδεικνύει ότι μια μεταγενέστερη ανάγνωση θα γίνει χωρίς προτροπή: ένα παρατηρημένο, απενεργοποιημένο prototype εξακολουθούσε να εμφανίζει προτροπή επιβεβαίωσης όταν ζητούσε το στοιχείο μέσω του `Security.framework`. Ένα ID partition που ταιριάζει αποτελεί μόνο ένα μέρος των ελέγχων ACL και trusted-application που περιγράφονται παραπάνω, γι' αυτό επαληθεύστε την πραγματική διαδρομή ανάγνωσης.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> Η **enumeration και το dumping** των secrets του Keychain που **δεν εμφανίζουν προτροπή** μπορούν να γίνουν με το εργαλείο [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Άλλα API endpoints βρίσκονται στον πηγαίο κώδικα του [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Καταγράψτε και λάβετε **πληροφορίες** για κάθε καταχώριση του Keychain χρησιμοποιώντας το **Security Framework** ή ελέγξτε το open source εργαλείο cli της Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Μερικά παραδείγματα API:<sup>[[1]](#references)</sup>

- Το API **`SecItemCopyMatching`** παρέχει πληροφορίες για κάθε καταχώριση και διαθέτει ορισμένα attributes που μπορείτε να ορίσετε κατά τη χρήση του:
  - **`kSecReturnData`**: Αν είναι true, θα προσπαθήσει να αποκρυπτογραφήσει τα δεδομένα (ορίστε το σε false για να αποφύγετε πιθανά αναδυόμενα παράθυρα)
  - **`kSecReturnRef`**: Λαμβάνει επίσης αναφορά στο στοιχείο του Keychain (ορίστε το σε true αν αργότερα διαπιστώσετε ότι μπορείτε να αποκρυπτογραφήσετε χωρίς αναδυόμενο παράθυρο)
  - **`kSecReturnAttributes`**: Λαμβάνει metadata για τις καταχωρίσεις
  - **`kSecMatchLimit`**: Πόσα αποτελέσματα θα επιστραφούν
  - **`kSecClass`**: Τι είδους καταχώριση Keychain είναι

Λάβετε τα **ACLs** κάθε καταχώρισης:<sup>[[1]](#references)</sup>

- Με το API **`SecAccessCopyACLList`** μπορείτε να λάβετε το **ACL για το στοιχείο του Keychain**. Επιστρέφει μια λίστα ACL (όπως τα `kSecACLAuthorizationExportClear` και τα υπόλοιπα που αναφέρθηκαν προηγουμένως), όπου κάθε καταχώριση περιλαμβάνει:<sup>[[1]](#references)[[2]](#references)</sup>
  - Περιγραφή
  - **Trusted Application List**. Μπορεί να είναι:
    - Μια εφαρμογή: /Applications/Slack.app
    - Ένα binary: /usr/libexec/airportd
    - Μια ομάδα: group://AirPort

Εξαγωγή των δεδομένων:<sup>[[1]](#references)</sup>

- Το API **`SecKeychainItemCopyContent`** λαμβάνει το plaintext
- Το API **`SecItemExport`** εξάγει τα κλειδιά και τα πιστοποιητικά, αλλά ίσως χρειαστεί να ορίσετε κωδικούς πρόσβασης για να εξαγάγετε το περιεχόμενο κρυπτογραφημένο

Και αυτές είναι οι **απαιτήσεις** για να μπορέσετε να **εξαγάγετε ένα secret χωρίς προτροπή**:<sup>[[1]](#references)</sup>

- Αν αναφέρονται **1+ trusted** εφαρμογές:
  - Χρειάζονται οι κατάλληλες **εξουσιοδοτήσεις** (**`Nil`** ή να είστε **μέρος** της λίστας επιτρεπόμενων εφαρμογών στην εξουσιοδότηση πρόσβασης στα ευαίσθητα δεδομένα)
  - Η υπογραφή κώδικα πρέπει να ταιριάζει με το **PartitionID**
  - Η υπογραφή κώδικα πρέπει να ταιριάζει με εκείνη μίας **trusted app** (ή να είστε μέλος του σωστού KeychainAccessGroup)
- Αν είναι trusted **όλες οι εφαρμογές**:
  - Χρειάζονται οι κατάλληλες **εξουσιοδοτήσεις**
  - Η υπογραφή κώδικα πρέπει να ταιριάζει με το **PartitionID**
    - Αν δεν υπάρχει **PartitionID**, τότε αυτό δεν απαιτείται

> [!CAUTION]
> Επομένως, αν αναφέρεται **1 εφαρμογή**, πρέπει να κάνετε **inject code σε αυτή την εφαρμογή**.
>
> Αν στο **partitionID** αναφέρεται το **apple**, μπορείτε να αποκτήσετε πρόσβαση με το **`osascript`**, επομένως αυτό ισχύει για οτιδήποτε εμπιστεύεται όλες τις εφαρμογές με apple στο partitionID. Μπορεί επίσης να χρησιμοποιηθεί η **`Python`**.

### Δύο επιπλέον attributes

- **Invisible**: Boolean flag για την **απόκρυψη** της καταχώρισης από την εφαρμογή Keychain του **UI**<sup>[[1]](#references)</sup>
- **General**: Χρησιμοποιείται για την αποθήκευση **metadata** (άρα ΔΕΝ ΕΙΝΑΙ ΚΡΥΠΤΟΓΡΑΦΗΜΕΝΑ)<sup>[[1]](#references)</sup>
  - Η Microsoft αποθήκευε σε plain text όλα τα refresh tokens για πρόσβαση σε ευαίσθητο endpoint.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: «Παραβιάζοντας το Keychain του macOS» - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Νέα έκδοση του macOS stealer MacSync στοχεύει λάτρεις των crypto και developers](https://securelist.com/macsync-new-version/121383/)
- [4] [Αντίγραφο της σελίδας man του Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
