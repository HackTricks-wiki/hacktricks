# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Autorisierungs-DB**

Die Datenbank, die sich in `/var/db/auth.db` befindet, ist eine Datenbank, die verwendet wird, um Berechtigungen für die Durchführung sensibler Operationen zu speichern. Diese Operationen werden vollständig im **Benutzermodus** durchgeführt und werden normalerweise von **XPC-Diensten** verwendet, die überprüfen müssen, **ob der aufrufende Client autorisiert ist**, um eine bestimmte Aktion durchzuführen, indem sie diese Datenbank abfragen.

Ursprünglich wird diese Datenbank aus dem Inhalt von `/System/Library/Security/authorization.plist` erstellt. Dann können einige Dienste diese Datenbank hinzufügen oder ändern, um weitere Berechtigungen hinzuzufügen.

Die Regeln werden in der `rules`-Tabelle innerhalb der Datenbank gespeichert und enthalten die folgenden Spalten:

- **id**: Ein eindeutiger Identifikator für jede Regel, der automatisch inkrementiert wird und als Primärschlüssel dient.
- **name**: Der eindeutige Name der Regel, der verwendet wird, um sie im Autorisierungssystem zu identifizieren und darauf zu verweisen.
- **type**: Gibt den Typ der Regel an, der auf die Werte 1 oder 2 beschränkt ist, um ihre Autorisierungslogik zu definieren.
- **class**: Kategorisiert die Regel in eine spezifische Klasse und stellt sicher, dass es sich um eine positive Ganzzahl handelt.
- "allow" für erlauben, "deny" für verweigern, "user" wenn die Gruppen-Eigenschaft eine Gruppe angibt, deren Mitgliedschaft den Zugriff erlaubt, "rule" zeigt in einem Array eine Regel an, die erfüllt werden muss, "evaluate-mechanisms" gefolgt von einem `mechanisms`-Array, das entweder integrierte Mechanismen oder den Namen eines Bundles innerhalb von `/System/Library/CoreServices/SecurityAgentPlugins/` oder /Library/Security//SecurityAgentPlugins enthält.
- **group**: Gibt die Benutzergruppe an, die mit der Regel für gruppenbasierte Autorisierung verbunden ist.
- **kofn**: Stellt den "k-of-n"-Parameter dar, der bestimmt, wie viele Unterregeln aus einer Gesamtzahl erfüllt sein müssen.
- **timeout**: Definiert die Dauer in Sekunden, bevor die durch die Regel gewährte Autorisierung abläuft.
- **flags**: Enthält verschiedene Flags, die das Verhalten und die Eigenschaften der Regel ändern.
- **tries**: Begrenzung der Anzahl der erlaubten Autorisierungsversuche zur Verbesserung der Sicherheit.
- **version**: Verfolgt die Version der Regel für die Versionskontrolle und Updates.
- **created**: Protokolliert den Zeitstempel, wann die Regel erstellt wurde, zu Prüfungszwecken.
- **modified**: Speichert den Zeitstempel der letzten Änderung an der Regel.
- **hash**: Enthält einen Hash-Wert der Regel, um ihre Integrität sicherzustellen und Manipulationen zu erkennen.
- **identifier**: Bietet einen eindeutigen String-Identifikator, wie eine UUID, für externe Verweise auf die Regel.
- **requirement**: Enthält serialisierte Daten, die die spezifischen Autorisierungsanforderungen und -mechanismen der Regel definieren.
- **comment**: Bietet eine für Menschen lesbare Beschreibung oder einen Kommentar zur Regel für Dokumentations- und Klarheitszwecke.

### Beispiel
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Darüber hinaus ist es möglich, die Bedeutung von `authenticate-admin-nonshared` unter [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) zu sehen:
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

Es ist ein Daemon, der Anfragen erhält, um Clients zu autorisieren, sensible Aktionen durchzuführen. Es funktioniert als XPC-Dienst, der im `XPCServices/`-Ordner definiert ist, und schreibt seine Protokolle in `/var/log/authd.log`.

Darüber hinaus ist es mit dem Sicherheitstool möglich, viele `Security.framework`-APIs zu testen. Zum Beispiel `AuthorizationExecuteWithPrivileges`, das ausgeführt wird mit: `security execute-with-privileges /bin/ls`

Das wird `/usr/libexec/security_authtrampoline /bin/ls` als root fork und exec, was um Erlaubnis in einem Prompt bittet, um ls als root auszuführen:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
