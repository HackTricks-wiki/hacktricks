# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Lozinke

### Shadow Lozinke

Shadow lozinka se čuva sa korisničkom konfiguracijom u plists koji se nalaze u **`/var/db/dslocal/nodes/Default/users/`**.\
Sledeći oneliner se može koristiti za ispis **sve informacije o korisnicima** (uključujući informacije o hash-u):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripti poput ovog**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ili [**ovog**](https://github.com/octomagon/davegrohl.git) mogu se koristiti za transformaciju heša u **hashcat** **format**.

Alternativni jedan-liner koji će izbaciti kredencijale svih ne-servisnih naloga u hashcat formatu `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Drugi način da se dobije `ShadowHashData` korisnika je korišćenjem `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ova datoteka se **koristi samo** kada sistem radi u **jednokorisničkom režimu** (dakle, ne vrlo često).

### Keychain Dump

Imajte na umu da prilikom korišćenja sigurnosne binarne datoteke za **izvlačenje dekriptovanih lozinki**, nekoliko upita će tražiti od korisnika da dozvoli ovu operaciju.
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
> Na osnovu ovog komentara [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), izgleda da ovi alati više ne funkcionišu u Big Sur.

### Pregled Keychaindump-a

Alat pod nazivom **keychaindump** razvijen je za ekstrakciju lozinki iz macOS keychain-a, ali se suočava sa ograničenjima na novijim verzijama macOS-a kao što je Big Sur, kako je naznačeno u [diskusiji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Korišćenje **keychaindump** zahteva od napadača da dobije pristup i eskalira privilegije na **root**. Alat koristi činjenicu da je keychain po defaultu otključan prilikom prijave korisnika radi pogodnosti, omogućavajući aplikacijama da mu pristupe bez ponovnog traženja lozinke korisnika. Međutim, ako korisnik odluči da zaključa svoj keychain nakon svake upotrebe, **keychaindump** postaje neefikasan.

**Keychaindump** funkcioniše tako što cilja specifičan proces nazvan **securityd**, koji Apple opisuje kao demon za autorizaciju i kriptografske operacije, ključan za pristup keychain-u. Proces ekstrakcije uključuje identifikaciju **Master Key**-a dobijenog iz lozinke za prijavu korisnika. Ovaj ključ je neophodan za čitanje datoteke keychain-a. Da bi locirao **Master Key**, **keychaindump** skenira memorijski heap **securityd** koristeći komandu `vmmap`, tražeći potencijalne ključeve unutar oblasti označenih kao `MALLOC_TINY`. Sledeća komanda se koristi za inspekciju ovih memorijskih lokacija:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nakon identifikacije potencijalnih master ključeva, **keychaindump** pretražuje hrpe za specifičnim obrascem (`0x0000000000000018`) koji ukazuje na kandidata za master ključ. Dalji koraci, uključujući deobfuskaciju, su potrebni za korišćenje ovog ključa, kao što je navedeno u izvor kodu **keychaindump**. Analitičari koji se fokusiraju na ovu oblast treba da primete da su ključni podaci za dekripciju keychain-a smešteni unutar memorije **securityd** procesa. Primer komande za pokretanje **keychaindump** je:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za ekstrakciju sledećih tipova informacija iz OSX keychain-a na forenzički ispravan način:

- Hashovana lozinka za keychain, pogodna za razbijanje sa [hashcat](https://hashcat.net/hashcat/) ili [John the Ripper](https://www.openwall.com/john/)
- Internet lozinke
- Generičke lozinke
- Privatni ključevi
- Javni ključevi
- X509 sertifikati
- Sigurne beleške
- Appleshare lozinke

Ukoliko je dostupna lozinka za otključavanje keychain-a, master ključ dobijen korišćenjem [volafox](https://github.com/n0fate/volafox) ili [volatility](https://github.com/volatilityfoundation/volatility), ili datoteka za otključavanje kao što je SystemKey, Chainbreaker će takođe pružiti lozinke u običnom tekstu.

Bez jedne od ovih metoda otključavanja Keychain-a, Chainbreaker će prikazati sve druge dostupne informacije.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Izvuci ključeve iz keychain-a (sa lozinkama) pomoću SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Ispisivanje ključeva iz keychain-a (sa lozinkama) razbijanje heša**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Izvuci ključeve iz keychain-a (sa lozinkama) pomoću dump-a memorije**

[Pratite ove korake](../index.html#dumping-memory-with-osxpmem) da izvršite **dump memorije**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Ispusti ključeve iz keychain-a (sa lozinkama) koristeći korisničku lozinku**

Ako znate korisničku lozinku, možete je koristiti da **ispustite i dekriptujete keychain-e koji pripadaju korisniku**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Fajl **kcpassword** je fajl koji sadrži **lozinku za prijavu korisnika**, ali samo ako je vlasnik sistema **omogućio automatsku prijavu**. Stoga, korisnik će biti automatski prijavljen bez traženja lozinke (što nije baš sigurno).

Lozinka se čuva u fajlu **`/etc/kcpassword`** xored sa ključem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ako je lozinka korisnika duža od ključa, ključ će se ponovo koristiti.\
To čini lozinku prilično lakom za oporavak, na primer koristeći skripte kao [**ovu**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Možete pronaći podatke o obaveštenjima u `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Većina zanimljivih informacija će biti u **blob**. Tako da ćete morati da **izvučete** taj sadržaj i **transformišete** ga u **čitljiv** **format** ili koristite **`strings`**. Da biste mu pristupili, možete uraditi:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Beleške

Korisničke **beleške** se mogu naći u `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferences

U macOS aplikacijama, podešavanja se nalaze u **`$HOME/Library/Preferences`**, a u iOS-u su u `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

U macOS-u, cli alat **`defaults`** može da se koristi za **modifikovanje Preferences datoteke**.

**`/usr/sbin/cfprefsd`** zahteva XPC usluge `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i može se pozvati da izvrši radnje kao što su modifikovanje podešavanja.

## OpenDirectory permissions.plist

Datoteka `/System/Library/OpenDirectory/permissions.plist` sadrži dozvole primenjene na atribute čvora i zaštićena je SIP-om.\
Ova datoteka dodeljuje dozvole specifičnim korisnicima po UUID (a ne uid) kako bi mogli da pristupe specifičnim osetljivim informacijama kao što su `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys` među ostalima:
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
## Sistemske Notifikacije

### Darwin Notifikacije

Glavni daemon za notifikacije je **`/usr/sbin/notifyd`**. Da bi primali notifikacije, klijenti moraju da se registruju preko `com.apple.system.notification_center` Mach porta (proverite ih sa `sudo lsmp -p <pid notifyd>`). Daemon se može konfigurisati sa datotekom `/etc/notify.conf`.

Imena koja se koriste za notifikacije su jedinstvene obrnute DNS notacije i kada se notifikacija pošalje jednom od njih, klijent(i) koji su naznačili da mogu da je obrade će je primiti.

Moguće je dumpovati trenutni status (i videti sva imena) slanjem signala SIGUSR2 procesu notifyd i čitanjem generisane datoteke: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center** čija je glavna binarna datoteka **`/usr/sbin/distnoted`**, je još jedan način za slanje obaveštenja. Izlaže neke XPC usluge i vrši neke provere kako bi pokušao da verifikuje klijente.

### Apple Push Notifications (APN)

U ovom slučaju, aplikacije se mogu registrovati za **teme**. Klijent će generisati token kontaktirajući Apple-ove servere putem **`apsd`**.\
Zatim, provajderi će takođe generisati token i moći će da se povežu sa Apple-ovim serverima kako bi slali poruke klijentima. Ove poruke će lokalno primiti **`apsd`** koji će proslediti obaveštenje aplikaciji koja ga čeka.

Podešavanja se nalaze u `/Library/Preferences/com.apple.apsd.plist`.

Postoji lokalna baza podataka poruka koja se nalazi u macOS-u u `/Library/Application\ Support/ApplePushService/aps.db` i u iOS-u u `/var/mobile/Library/ApplePushService`. Ima 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Takođe je moguće dobiti informacije o daemon-u i vezama koristeći:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Obaveštenja korisnika

Ovo su obaveštenja koja korisnik treba da vidi na ekranu:

- **`CFUserNotification`**: Ovaj API pruža način da se na ekranu prikaže iskačuća poruka.
- **Oglasna tabla**: Ovo prikazuje u iOS-u baner koji nestaje i biće sačuvan u Centru za obaveštenja.
- **`NSUserNotificationCenter`**: Ovo je oglasna tabla iOS-a u MacOS-u. Baza podataka sa obaveštenjima se nalazi u `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
