# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwords

### Shadow Passwords

Shadow password inahifadhiwa na usanidi wa mtumiaji katika plists zilizoko **`/var/db/dslocal/nodes/Default/users/`**.\
Mfuatano huu wa moja unaweza kutumika kutoa **habari zote kuhusu watumiaji** (ikiwemo taarifa za hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts kama hii**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) au [**hii**](https://github.com/octomagon/davegrohl.git) zinaweza kutumika kubadilisha hash kuwa **hashcat** **format**.

Mstari mbadala mmoja ambao utatoa creds za akaunti zote zisizo za huduma katika format ya hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Njia nyingine ya kupata `ShadowHashData` ya mtumiaji ni kwa kutumia `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Faili hii inatumika **tu** wakati mfumo unafanya kazi katika **mode ya mtumiaji mmoja** (hivyo si mara nyingi sana).

### Keychain Dump

Kumbuka kwamba unapokuwa unatumia binary ya usalama **kudondosha nywila zilizofichuliwa**, maelekezo kadhaa yatauliza mtumiaji kuruhusu operesheni hii.
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
> Kulingana na maoni haya [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) inaonekana kwamba zana hizi hazifanyi kazi tena katika Big Sur.

### Muhtasari wa Keychaindump

Zana inayoitwa **keychaindump** imeandaliwa kutoa nywila kutoka kwa keychains za macOS, lakini inakabiliwa na vizuizi katika matoleo mapya ya macOS kama Big Sur, kama ilivyoelezwa katika [majadiliano](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Matumizi ya **keychaindump** yanahitaji mshambuliaji kupata ufikiaji na kupandisha mamlaka hadi **root**. Zana hii inatumia ukweli kwamba keychain imefunguliwa kwa default wakati wa kuingia kwa mtumiaji kwa urahisi, ikiruhusu programu kufikia bila kuhitaji nywila ya mtumiaji mara kwa mara. Hata hivyo, ikiwa mtumiaji atachagua kufunga keychain yao baada ya kila matumizi, **keychaindump** inakuwa isiyo na ufanisi.

**Keychaindump** inafanya kazi kwa kulenga mchakato maalum unaoitwa **securityd**, ambayo Apple inaelezea kama daemon kwa ajili ya mamlaka na operesheni za kificho, muhimu kwa ufikiaji wa keychain. Mchakato wa kutoa nywila unahusisha kutambua **Master Key** inayotokana na nywila ya kuingia ya mtumiaji. Key hii ni muhimu kwa kusoma faili ya keychain. Ili kupata **Master Key**, **keychaindump** inachanganua heap ya kumbukumbu ya **securityd** kwa kutumia amri ya `vmmap`, ikitafuta funguo zinazoweza kuwa ndani ya maeneo yaliyoashiriwa kama `MALLOC_TINY`. Amri ifuatayo inatumika kukagua maeneo haya ya kumbukumbu:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Baada ya kubaini funguo kuu zinazoweza kuwa, **keychaindump** inatafuta kupitia heaps kwa mfano maalum (`0x0000000000000018`) unaoashiria mgombea wa funguo kuu. Hatua zaidi, ikiwa ni pamoja na deobfuscation, zinahitajika ili kutumia funguo hii, kama ilivyoainishwa katika ms source code ya **keychaindump**. Wanalizi wanaolenga eneo hili wanapaswa kuzingatia kwamba data muhimu ya kufichua funguo za keychain inahifadhiwa ndani ya kumbukumbu ya mchakato wa **securityd**. Mfano wa amri ya kuendesha **keychaindump** ni:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kutoa aina zifuatazo za taarifa kutoka kwa OSX keychain kwa njia ya forensically sound:

- Nenosiri la Keychain lililohashwa, linalofaa kwa ajili ya kuvunja kwa kutumia [hashcat](https://hashcat.net/hashcat/) au [John the Ripper](https://www.openwall.com/john/)
- Nenosiri za Mtandao
- Nenosiri za Kawaida
- Funguo Binafsi
- Funguo za Umma
- Vyeti vya X509
- Maelezo Salama
- Nenosiri za Appleshare

Ikiwa kuna nenosiri la kufungua keychain, funguo kuu iliyopatikana kwa kutumia [volafox](https://github.com/n0fate/volafox) au [volatility](https://github.com/volatilityfoundation/volatility), au faili ya kufungua kama SystemKey, Chainbreaker pia itatoa nenosiri za maandiko.

Bila moja ya hizi mbinu za kufungua Keychain, Chainbreaker itaonyesha taarifa nyingine zote zinazopatikana.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dondoa funguo za keychain (pamoja na nywila) kwa kutumia SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kutoa funguo za keychain (pamoja na nywila) kuvunja hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dondoa funguo za keychain (pamoja na nywila) kwa kutumia memory dump**

[Fuata hatua hizi](../index.html#dumping-memory-with-osxpmem) ili kufanya **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dondoa funguo za keychain (pamoja na nywila) kwa kutumia nywila ya mtumiaji**

Ikiwa unajua nywila ya mtumiaji unaweza kuitumia **dondoa na kufichua keychains zinazomilikiwa na mtumiaji**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Faili la **kcpassword** ni faili linaloshikilia **nenosiri la kuingia la mtumiaji**, lakini tu ikiwa mmiliki wa mfumo ame **wezeshwa kuingia kiotomatiki**. Hivyo, mtumiaji ataingia kiotomatiki bila kuulizwa nenosiri (ambayo si salama sana).

Nenosiri linahifadhiwa katika faili **`/etc/kcpassword`** xored na ufunguo **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ikiwa nenosiri la watumiaji ni refu zaidi ya ufunguo, ufunguo utarudiwa.\
Hii inafanya nenosiri kuwa rahisi kurejesha, kwa mfano kwa kutumia scripts kama [**hii**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Taarifa za Kuvutia katika Maktaba

### Ujumbe
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Unaweza kupata data za Notifications katika `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Mengi ya habari za kuvutia yatakuwa katika **blob**. Hivyo utahitaji **kutoa** yaliyomo hayo na **kubadilisha** kuwa **yanayosomwa** na **binadamu** au tumia **`strings`**. Ili kuyafikia unaweza kufanya:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notes

Watumiaji **notes** wanaweza kupatikana katika `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferences

Katika programu za macOS, mapendeleo yanapatikana katika **`$HOME/Library/Preferences`** na katika iOS yanapatikana katika `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Katika macOS, zana ya cli **`defaults`** inaweza kutumika kubadilisha **faili za Mapendeleo**.

**`/usr/sbin/cfprefsd`** inadai huduma za XPC `com.apple.cfprefsd.daemon` na `com.apple.cfprefsd.agent` na inaweza kuitwa kufanya vitendo kama kubadilisha mapendeleo.

## OpenDirectory permissions.plist

Faili `/System/Library/OpenDirectory/permissions.plist` ina ruhusa zinazotumika kwenye sifa za node na inalindwa na SIP.\
Faili hii inatoa ruhusa kwa watumiaji maalum kwa UUID (na si uid) ili waweze kufikia taarifa nyeti maalum kama `ShadowHashData`, `HeimdalSRPKey` na `KerberosKeys` miongoni mwa zingine:
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

Daemoni kuu wa arifa ni **`/usr/sbin/notifyd`**. Ili kupokea arifa, wateja lazima wajisajili kupitia bandari ya Mach `com.apple.system.notification_center` (angalia kwa `sudo lsmp -p <pid notifyd>`). Daemoni inaweza kubadilishwa kwa faili `/etc/notify.conf`.

Majina yanayotumika kwa arifa ni alama za kipekee za DNS za kinyume na wakati arifa inatumwa kwa moja yao, mteja(wateja) ambao wameonyesha wanaweza kushughulikia hiyo watapokea.

Inawezekana kutoa hali ya sasa (na kuona majina yote) kwa kutuma ishara SIGUSR2 kwa mchakato wa notifyd na kusoma faili iliyozalishwa: `/var/run/notifyd_<pid>.status`:
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

The **Distributed Notification Center** whose main binary is **`/usr/sbin/distnoted`**, ni njia nyingine ya kutuma arifa. Inatoa baadhi ya huduma za XPC na inafanya baadhi ya ukaguzi kujaribu kuthibitisha wateja.

### Apple Push Notifications (APN)

Katika kesi hii, programu zinaweza kujiandikisha kwa **topics**. Mteja atazalisha token kwa kuwasiliana na seva za Apple kupitia **`apsd`**.\
Kisha, watoa huduma, watakuwa pia wamezalisha token na wataweza kuungana na seva za Apple kutuma ujumbe kwa wateja. Ujumbe huu utapokelewa kwa ndani na **`apsd`** ambayo itapeleka arifa kwa programu inayosubiri hiyo.

Mipangilio iko katika `/Library/Preferences/com.apple.apsd.plist`.

Kuna database ya ndani ya ujumbe iliyoko macOS katika `/Library/Application\ Support/ApplePushService/aps.db` na katika iOS katika `/var/mobile/Library/ApplePushService`. Ina meza 3: `incoming_messages`, `outgoing_messages` na `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Inawezekana pia kupata taarifa kuhusu daemon na muunganisho kwa kutumia:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Hizi ni arifa ambazo mtumiaji anapaswa kuona kwenye skrini:

- **`CFUserNotification`**: API hii inatoa njia ya kuonyesha kwenye skrini pop-up yenye ujumbe.
- **The Bulletin Board**: Hii inaonyesha kwenye iOS bendera inayotoweka na itahifadhiwa katika Kituo cha Arifa.
- **`NSUserNotificationCenter`**: Hii ni bodi ya matangazo ya iOS katika MacOS. Hifadhidata yenye arifa iko katika `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
