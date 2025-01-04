# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwords

### Shadow Passwords

Shadow password उपयोगकर्ता की कॉन्फ़िगरेशन के साथ **`/var/db/dslocal/nodes/Default/users/`** में स्थित plists में संग्रहीत होता है।\
निम्नलिखित एकल पंक्ति का उपयोग **उपयोगकर्ताओं के बारे में सभी जानकारी** (हैश जानकारी सहित) को डंप करने के लिए किया जा सकता है:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**इस तरह के स्क्रिप्ट**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) या [**इस एक**](https://github.com/octomagon/davegrohl.git) का उपयोग हैश को **hashcat** **फॉर्मेट** में बदलने के लिए किया जा सकता है।

एक वैकल्पिक वन-लाइनर जो hashcat फॉर्मेट `-m 7100` (macOS PBKDF2-SHA512) में सभी गैर-सेवा खातों के क्रेड्स को डंप करेगा:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Another way to obtain the `ShadowHashData` of a user is by using `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

यह फ़ाइल **केवल उपयोग की जाती है** जब सिस्टम **सिंगल-यूजर मोड** में चल रहा हो (इसलिए बहुत बार नहीं)।

### Keychain Dump

ध्यान दें कि जब सुरक्षा बाइनरी का उपयोग करके **डिक्रिप्ट किए गए पासवर्ड्स को डंप** किया जाता है, तो कई प्रॉम्प्ट उपयोगकर्ता से इस ऑपरेशन की अनुमति देने के लिए पूछेंगे।
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
> इस टिप्पणी के आधार पर [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) ऐसा लगता है कि ये उपकरण अब Big Sur में काम नहीं कर रहे हैं।

### Keychaindump Overview

**keychaindump** नामक एक उपकरण macOS की कीचेन से पासवर्ड निकालने के लिए विकसित किया गया है, लेकिन यह Big Sur जैसे नए macOS संस्करणों पर सीमाओं का सामना करता है, जैसा कि एक [चर्चा](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) में बताया गया है। **keychaindump** का उपयोग करने के लिए हमलावर को **root** तक पहुंच प्राप्त करनी और विशेषाधिकार बढ़ाने की आवश्यकता होती है। यह उपकरण इस तथ्य का लाभ उठाता है कि कीचेन उपयोगकर्ता लॉगिन पर डिफ़ॉल्ट रूप से अनलॉक होता है, जिससे अनुप्रयोगों को इसे बार-बार उपयोगकर्ता का पासवर्ड मांगे बिना एक्सेस करने की अनुमति मिलती है। हालाँकि, यदि कोई उपयोगकर्ता प्रत्येक उपयोग के बाद अपनी कीचेन को लॉक करने का विकल्प चुनता है, तो **keychaindump** अप्रभावी हो जाता है।

**Keychaindump** एक विशिष्ट प्रक्रिया **securityd** को लक्षित करके काम करता है, जिसे Apple द्वारा प्राधिकरण और क्रिप्टोग्राफिक संचालन के लिए एक डेमन के रूप में वर्णित किया गया है, जो कीचेन तक पहुँचने के लिए महत्वपूर्ण है। निष्कर्षण प्रक्रिया में उपयोगकर्ता के लॉगिन पासवर्ड से निकाली गई **Master Key** की पहचान करना शामिल है। यह कुंजी कीचेन फ़ाइल को पढ़ने के लिए आवश्यक है। **Master Key** को खोजने के लिए, **keychaindump** `vmmap` कमांड का उपयोग करके **securityd** की मेमोरी हीप को स्कैन करता है, संभावित कुंजियों को `MALLOC_TINY` के रूप में चिह्नित क्षेत्रों में देखता है। इन मेमोरी स्थानों का निरीक्षण करने के लिए निम्नलिखित कमांड का उपयोग किया जाता है:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
संभावित मास्टर कुंजियों की पहचान करने के बाद, **keychaindump** एक विशिष्ट पैटर्न (`0x0000000000000018`) के लिए हीप के माध्यम से खोज करता है जो मास्टर कुंजी के लिए एक उम्मीदवार को इंगित करता है। इस कुंजी का उपयोग करने के लिए आगे के कदम, जिसमें डिओबफस्केशन शामिल है, आवश्यक हैं, जैसा कि **keychaindump** के स्रोत कोड में वर्णित है। इस क्षेत्र पर ध्यान केंद्रित करने वाले विश्लेषकों को यह ध्यान रखना चाहिए कि कुंजीचेन को डिक्रिप्ट करने के लिए महत्वपूर्ण डेटा **securityd** प्रक्रिया की मेमोरी में संग्रहीत होता है। **keychaindump** चलाने के लिए एक उदाहरण कमांड है:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) का उपयोग OSX कीचेन से फोरेंसिक रूप से सही तरीके से निम्नलिखित प्रकार की जानकारी निकालने के लिए किया जा सकता है:

- हैश किया गया कीचेन पासवर्ड, [hashcat](https://hashcat.net/hashcat/) या [John the Ripper](https://www.openwall.com/john/) के साथ क्रैक करने के लिए उपयुक्त
- इंटरनेट पासवर्ड
- सामान्य पासवर्ड
- निजी कुंजी
- सार्वजनिक कुंजी
- X509 प्रमाणपत्र
- सुरक्षित नोट्स
- Appleshare पासवर्ड

कीचेन अनलॉक पासवर्ड, [volafox](https://github.com/n0fate/volafox) या [volatility](https://github.com/volatilityfoundation/volatility) का उपयोग करके प्राप्त मास्टर कुंजी, या SystemKey जैसे अनलॉक फ़ाइल के साथ, Chainbreaker भी प्लेनटेक्स्ट पासवर्ड प्रदान करेगा।

इनमें से किसी एक कीचेन को अनलॉक करने के तरीकों के बिना, Chainbreaker सभी अन्य उपलब्ध जानकारी प्रदर्शित करेगा।

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey के साथ कीचेन कुंजी (पासवर्ड के साथ) डंप करें**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **कीचेन कुंजी (पासवर्ड के साथ) को डंप करना हैश को क्रैक करके**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **कीचेन कुंजियों (पासवर्ड के साथ) को मेमोरी डंप के साथ डंप करें**

[इन चरणों का पालन करें](../index.html#dumping-memory-with-osxpmem) एक **मेमोरी डंप** करने के लिए
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **उपयोगकर्ता के पासवर्ड का उपयोग करके कीचेन कुंजियाँ (पासवर्ड के साथ) डंप करें**

यदि आप उपयोगकर्ता का पासवर्ड जानते हैं, तो आप इसका उपयोग **उपयोगकर्ता के स्वामित्व वाले कीचेन को डंप और डिक्रिप्ट करने** के लिए कर सकते हैं।
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** फ़ाइल एक फ़ाइल है जो **उपयोगकर्ता का लॉगिन पासवर्ड** रखती है, लेकिन केवल तभी जब सिस्टम के मालिक ने **स्वचालित लॉगिन** सक्षम किया हो। इसलिए, उपयोगकर्ता बिना पासवर्ड पूछे स्वचालित रूप से लॉगिन हो जाएगा (जो बहुत सुरक्षित नहीं है)।

पासवर्ड फ़ाइल **`/etc/kcpassword`** में **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** कुंजी के साथ XOR किया गया है। यदि उपयोगकर्ता का पासवर्ड कुंजी से लंबा है, तो कुंजी का पुन: उपयोग किया जाएगा।\
यह पासवर्ड को पुनर्प्राप्त करना काफी आसान बनाता है, उदाहरण के लिए [**इस स्क्रिप्ट**](https://gist.github.com/opshope/32f65875d45215c3677d) का उपयोग करके।

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

आप Notifications डेटा को `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` में पा सकते हैं।

सबसे दिलचस्प जानकारी **blob** में होगी। इसलिए आपको उस सामग्री को **extract** करना होगा और उसे **human** **readable** में **transform** करना होगा या **`strings`** का उपयोग करना होगा। इसे एक्सेस करने के लिए आप कर सकते हैं:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notes

उपयोगकर्ताओं के **notes** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` में पाए जा सकते हैं।
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferences

macOS ऐप्स में प्राथमिकताएँ **`$HOME/Library/Preferences`** में स्थित होती हैं और iOS में ये `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` में होती हैं।

macOS में cli टूल **`defaults`** का उपयोग **Preferences फ़ाइल को संशोधित करने** के लिए किया जा सकता है।

**`/usr/sbin/cfprefsd`** XPC सेवाओं `com.apple.cfprefsd.daemon` और `com.apple.cfprefsd.agent` का दावा करता है और इसे प्राथमिकताएँ संशोधित करने जैसी क्रियाएँ करने के लिए बुलाया जा सकता है।

## OpenDirectory permissions.plist

फ़ाइल `/System/Library/OpenDirectory/permissions.plist` नोड विशेषताओं पर लागू की गई अनुमतियों को शामिल करती है और इसे SIP द्वारा सुरक्षित किया गया है।\
यह फ़ाइल UUID द्वारा विशिष्ट उपयोगकर्ताओं को अनुमतियाँ प्रदान करती है (और uid द्वारा नहीं) ताकि वे `ShadowHashData`, `HeimdalSRPKey` और `KerberosKeys` जैसी विशिष्ट संवेदनशील जानकारी तक पहुँच सकें।
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
## सिस्टम सूचनाएँ

### डार्विन सूचनाएँ

सूचनाओं के लिए मुख्य डेमन **`/usr/sbin/notifyd`** है। सूचनाएँ प्राप्त करने के लिए, क्लाइंट को `com.apple.system.notification_center` मच पोर्ट के माध्यम से पंजीकरण कराना होगा (इन्हें `sudo lsmp -p <pid notifyd>` के साथ जांचें)। डेमन को फ़ाइल `/etc/notify.conf` के साथ कॉन्फ़िगर किया जा सकता है।

सूचनाओं के लिए उपयोग किए जाने वाले नाम अद्वितीय रिवर्स DNS नोटेशन हैं और जब इनमें से किसी को सूचना भेजी जाती है, तो वे क्लाइंट जो इसे संभालने के लिए संकेतित हैं, इसे प्राप्त करेंगे।

वर्तमान स्थिति को डंप करना संभव है (और सभी नामों को देखना) notifyd प्रक्रिया को SIGUSR2 सिग्नल भेजकर और उत्पन्न फ़ाइल पढ़कर: `/var/run/notifyd_<pid>.status`:
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

The **Distributed Notification Center** जिसका मुख्य बाइनरी **`/usr/sbin/distnoted`** है, सूचनाएँ भेजने का एक और तरीका है। यह कुछ XPC सेवाओं को उजागर करता है और यह क्लाइंट्स को सत्यापित करने के लिए कुछ जांच करता है।

### Apple Push Notifications (APN)

इस मामले में, एप्लिकेशन **topics** के लिए पंजीकरण कर सकते हैं। क्लाइंट **`apsd`** के माध्यम से Apple के सर्वरों से संपर्क करके एक टोकन उत्पन्न करेगा।\
फिर, प्रदाता भी एक टोकन उत्पन्न करेंगे और Apple के सर्वरों से जुड़कर क्लाइंट्स को संदेश भेजने में सक्षम होंगे। ये संदेश स्थानीय रूप से **`apsd`** द्वारा प्राप्त किए जाएंगे जो इसे प्रतीक्षा कर रहे एप्लिकेशन को सूचना भेजेगा।

प्राथमिकताएँ `/Library/Preferences/com.apple.apsd.plist` में स्थित हैं।

macOS में संदेशों का एक स्थानीय डेटाबेस `/Library/Application\ Support/ApplePushService/aps.db` में और iOS में `/var/mobile/Library/ApplePushService` में स्थित है। इसमें 3 तालिकाएँ हैं: `incoming_messages`, `outgoing_messages` और `channel`।
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
यह भी संभव है कि आप डेमन और कनेक्शनों के बारे में जानकारी प्राप्त कर सकें:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

ये सूचनाएँ हैं जो उपयोगकर्ता को स्क्रीन पर देखनी चाहिए:

- **`CFUserNotification`**: ये API स्क्रीन पर एक संदेश के साथ पॉप-अप दिखाने का एक तरीका प्रदान करती है।
- **The Bulletin Board**: यह iOS में एक बैनर दिखाता है जो गायब हो जाता है और नोटिफिकेशन सेंटर में संग्रहीत होता है।
- **`NSUserNotificationCenter`**: यह MacOS में iOS का बुलेटिन बोर्ड है। नोटिफिकेशनों के साथ डेटाबेस `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` में स्थित है।

{{#include ../../../banners/hacktricks-training.md}}
