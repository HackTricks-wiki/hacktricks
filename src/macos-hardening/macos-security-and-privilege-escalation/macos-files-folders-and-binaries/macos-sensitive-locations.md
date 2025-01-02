# macOS Sensitiewe Lokasies & Interessante Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Wagwoorde

### Skadu Wagwoorde

Skadu wagwoord word gestoor saam met die gebruiker se konfigurasie in plists geleë in **`/var/db/dslocal/nodes/Default/users/`**.\
Die volgende eenlynopdrag kan gebruik word om **alle inligting oor die gebruikers** (insluitend hash-inligting) te dump:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte soos hierdie een**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) of [**hierdie een**](https://github.com/octomagon/davegrohl.git) kan gebruik word om die hash na **hashcat** **formaat** te transformeer.

'n Alternatiewe een-liner wat die kredensiale van alle nie-diens rekeninge in hashcat formaat `-m 7100` (macOS PBKDF2-SHA512) sal dump:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
'n Ander manier om die `ShadowHashData` van 'n gebruiker te verkry, is deur `dscl` te gebruik: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Hierdie lêer word **slegs gebruik** wanneer die stelsel in **enkele-gebruiker modus** loop (dus nie baie gereeld nie).

### Sleutelhouer Dump

Let daarop dat wanneer die sekuriteit binêre gebruik word om die **ontsleutelde wagwoorde** te **dump**, verskeie vrae die gebruiker sal vra om hierdie operasie toe te laat.
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
> Gebaseer op hierdie kommentaar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) lyk dit of hierdie gereedskap nie meer werk in Big Sur nie.

### Keychaindump Oorsig

'n Gereedskap genaamd **keychaindump** is ontwikkel om wagwoorde uit macOS sleutelhouers te onttrek, maar dit ondervind beperkings op nuwer macOS weergawes soos Big Sur, soos aangedui in 'n [diskussie](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Die gebruik van **keychaindump** vereis dat die aanvaller toegang verkry en voorregte tot **root** verhoog. Die gereedskap benut die feit dat die sleutelhouer standaard ontgrendel is by gebruikersaanmelding vir gerief, wat toelaat dat toepassings toegang daartoe verkry sonder om die gebruiker se wagwoord herhaaldelik te vereis. As 'n gebruiker egter kies om hul sleutelhouer na elke gebruik te vergrendel, word **keychaindump** ondoeltreffend.

**Keychaindump** werk deur 'n spesifieke proses genaamd **securityd** te teiken, wat deur Apple beskryf word as 'n daemon vir magtiging en kriptografiese operasies, wat noodsaaklik is vir toegang tot die sleutelhouer. Die onttrekkingsproses behels die identifisering van 'n **Master Key** wat afgelei is van die gebruiker se aanmeldwagwoord. Hierdie sleutel is noodsaaklik om die sleutelhouer lêer te lees. Om die **Master Key** te vind, skandeer **keychaindump** die geheuehoop van **securityd** met behulp van die `vmmap` opdrag, op soek na potensiële sleutels binne areas wat as `MALLOC_TINY` gemerk is. Die volgende opdrag word gebruik om hierdie geheue plekke te ondersoek:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Na die identifisering van potensiële meester sleutels, **keychaindump** soek deur die hoop vir 'n spesifieke patroon (`0x0000000000000018`) wat 'n kandidaat vir die meester sleutel aandui. Verdere stappe, insluitend deobfuscation, is nodig om hierdie sleutel te benut, soos uiteengesit in **keychaindump** se bronkode. Ontleders wat op hierdie gebied fokus, moet oplet dat die belangrike data vir die ontsleuteling van die sleutelring binne die geheue van die **securityd** proses gestoor is. 'n Voorbeeldopdrag om **keychaindump** te loop is:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word om die volgende tipes inligting uit 'n OSX sleutelketting op 'n forensies-korrekte manier te onttrek:

- Gehashde Sleutelkettingswagwoord, geskik vir kraken met [hashcat](https://hashcat.net/hashcat/) of [John the Ripper](https://www.openwall.com/john/)
- Internet Wagwoorde
- Generiese Wagwoorde
- Privaat Sleutels
- Publieke Sleutels
- X509 Sertifikate
- Veilige Aantekeninge
- Appleshare Wagwoorde

Gegewe die sleutelkettingsontsluitwagwoord, 'n meester sleutel verkry met behulp van [volafox](https://github.com/n0fate/volafox) of [volatility](https://github.com/volatilityfoundation/volatility), of 'n ontsluitlêer soos SystemKey, sal Chainbreaker ook plattekswagwoorde verskaf.

Sonder een van hierdie metodes om die Sleutelketing te ontsluit, sal Chainbreaker al die ander beskikbare inligting vertoon.

#### **Dump sleutelkettingsleutels**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) met SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) om die hash te kraak**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) met geheue-aflaai**

[Volg hierdie stappe](../#dumping-memory-with-osxpmem) om 'n **geheue-aflaai** uit te voer
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump sleutelring sleutels (met wagwoorde) met die gebruiker se wagwoord**

As jy die gebruiker se wagwoord ken, kan jy dit gebruik om **sleutelrings wat aan die gebruiker behoort te dump en te ontsleutel**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Die **kcpassword** lêer is 'n lêer wat die **gebruikers se aanmeldwagwoord** bevat, maar slegs as die stelselaanvaarder **outomatiese aanmelding** geaktiveer het. Daarom sal die gebruiker outomaties aangemeld word sonder om vir 'n wagwoord gevra te word (wat nie baie veilig is nie).

Die wagwoord word in die lêer **`/etc/kcpassword`** xored met die sleutel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. As die gebruiker se wagwoord langer is as die sleutel, sal die sleutel hergebruik word.\
Dit maak die wagwoord redelik maklik om te herstel, byvoorbeeld met behulp van skripte soos [**hierdie een**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interessante Inligting in Databasisse

### Berigte
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Kennisgewings

Jy kan die Kennisgewings data vind in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meeste van die interessante inligting gaan in **blob** wees. So jy sal daardie inhoud moet **onttrek** en **transformeer** na **mens** **leesbaar** of gebruik **`strings`**. Om toegang te verkry kan jy doen:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Aantekeninge

Die gebruikers **aantekeninge** kan gevind word in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Voorkeure

In macOS toepassings is voorkeure geleë in **`$HOME/Library/Preferences`** en in iOS is dit in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kan die cli-gereedskap **`defaults`** gebruik word om die **Voorkeure-lêer** te **wysig**.

**`/usr/sbin/cfprefsd`** eis die XPC dienste `com.apple.cfprefsd.daemon` en `com.apple.cfprefsd.agent` en kan geroep word om aksies uit te voer soos om voorkeure te wysig.

## OpenDirectory permissions.plist

Die lêer `/System/Library/OpenDirectory/permissions.plist` bevat toestemmings wat op knoopattributen toegepas word en is beskerm deur SIP.\
Hierdie lêer verleen toestemmings aan spesifieke gebruikers deur UUID (en nie uid) sodat hulle toegang kan verkry tot spesifieke sensitiewe inligting soos `ShadowHashData`, `HeimdalSRPKey` en `KerberosKeys` onder andere:
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
## Stelselskennisgewings

### Darwin Kennisgewings

Die hoof daemon vir kennisgewings is **`/usr/sbin/notifyd`**. Om kennisgewings te ontvang, moet kliënte registreer deur die `com.apple.system.notification_center` Mach-poort (kontroleer dit met `sudo lsmp -p <pid notifyd>`). Die daemon is konfigureerbaar met die lêer `/etc/notify.conf`.

Die name wat vir kennisgewings gebruik word, is unieke omgekeerde DNS-notasies en wanneer 'n kennisgewing na een van hulle gestuur word, sal die kliënt(e) wat aangedui het dat hulle dit kan hanteer, dit ontvang.

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
### Verspreide Kennisgewing Sentrum

Die **Verspreide Kennisgewing Sentrum** waarvan die hoof binêre **`/usr/sbin/distnoted`** is, is 'n ander manier om kennisgewings te stuur. Dit stel 'n paar XPC dienste bloot en dit voer 'n paar kontroles uit om te probeer om kliënte te verifieer.

### Apple Push Kennisgewings (APN)

In hierdie geval kan toepassings registreer vir **onderwerpe**. Die kliënt sal 'n token genereer deur Apple se bedieners te kontak deur **`apsd`**.\
Dan sal verskaffers ook 'n token genereer en in staat wees om met Apple se bedieners te verbind om boodskappe aan die kliënte te stuur. Hierdie boodskappe sal plaaslik deur **`apsd`** ontvang word wat die kennisgewing aan die toepassing wat daarop wag, sal oordra.

Die voorkeure is geleë in `/Library/Preferences/com.apple.apsd.plist`.

Daar is 'n plaaslike databasis van boodskappe geleë in macOS in `/Library/Application\ Support/ApplePushService/aps.db` en in iOS in `/var/mobile/Library/ApplePushService`. Dit het 3 tabelle: `incoming_messages`, `outgoing_messages` en `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Dit is ook moontlik om inligting oor die daemon en verbindings te verkry met:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Gebruiker Kennisgewings

Dit is kennisgewings wat die gebruiker op die skerm moet sien:

- **`CFUserNotification`**: Hierdie API bied 'n manier om 'n pop-up met 'n boodskap op die skerm te wys.
- **Die Bulletinbord**: Dit wys in iOS 'n banner wat verdwyn en in die Kennisgewing Sentrum gestoor sal word.
- **`NSUserNotificationCenter`**: Dit is die iOS bulletinbord in MacOS. Die databasis met die kennisgewings is geleë in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
