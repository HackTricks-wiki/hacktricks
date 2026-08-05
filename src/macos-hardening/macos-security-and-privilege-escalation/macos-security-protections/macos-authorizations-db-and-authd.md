# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Autorisierungsdatenbank**

Die in `/var/db/auth.db` befindliche Datenbank wird zum Speichern von Berechtigungen für die Ausführung sensibler Vorgänge verwendet. Diese Vorgänge werden vollständig im **user space** ausgeführt und normalerweise von **XPC services** verwendet, die anhand dieser Datenbank prüfen müssen, **ob der aufrufende Client autorisiert ist**, eine bestimmte Aktion auszuführen.

Anfangs wird diese Datenbank aus dem Inhalt von `/System/Library/Security/authorization.plist` erstellt. Anschließend können einige Services diese Datenbank ergänzen oder ändern, um weitere Berechtigungen hinzuzufügen.

Die Regeln werden in der Tabelle `rules` innerhalb der Datenbank gespeichert und enthalten die folgenden Spalten:

- **id**: Eine eindeutige Kennung für jede Regel, die automatisch erhöht wird und als Primärschlüssel dient.
- **name**: Der eindeutige Name der Regel, der dazu verwendet wird, sie innerhalb des Autorisierungssystems zu identifizieren und zu referenzieren.
- **type**: Gibt den Typ der Regel an. Zulässig sind die Werte 1 oder 2, die deren Autorisierungslogik definieren.
- **class**: Kategorisiert die Regel in eine bestimmte Klasse und stellt sicher, dass es sich um eine positive Ganzzahl handelt.
- "allow" für allow, "deny" für deny, "user", wenn die Eigenschaft group eine Gruppe angibt, deren Mitgliedschaft den Zugriff erlaubt, "rule" gibt in einem Array eine zu erfüllende Regel an, "evaluate-mechanisms", gefolgt von einem `mechanisms`-Array, dessen Elemente entweder builtins oder der Name eines Bundles innerhalb von `/System/Library/CoreServices/SecurityAgentPlugins/` oder `/Library/Security//SecurityAgentPlugins` sind
- **group**: Gibt die mit der Regel verbundene Benutzergruppe für die gruppenbasierte Autorisierung an.
- **kofn**: Repräsentiert den Parameter „k-of-n“ und bestimmt, wie viele Unterregeln aus einer Gesamtanzahl erfüllt sein müssen.
- **timeout**: Definiert die Dauer in Sekunden, bevor die von der Regel erteilte Autorisierung abläuft.
- **flags**: Enthält verschiedene Flags, die das Verhalten und die Eigenschaften der Regel verändern.
- **tries**: Begrenzt die Anzahl der zulässigen Autorisierungsversuche, um die Sicherheit zu erhöhen.
- **version**: Verfolgt die Version der Regel zur Versionsverwaltung und für Aktualisierungen.
- **created**: Speichert den Zeitstempel, zu dem die Regel erstellt wurde, für Auditing-Zwecke.
- **modified**: Speichert den Zeitstempel der letzten Änderung an der Regel.
- **hash**: Enthält einen Hash-Wert der Regel, um deren Integrität sicherzustellen und Manipulationen zu erkennen.
- **identifier**: Stellt eine eindeutige Zeichenkettenkennung, beispielsweise eine UUID, für externe Referenzen auf die Regel bereit.
- **requirement**: Enthält serialisierte Daten, die die spezifischen Autorisierungsanforderungen und Mechanismen der Regel definieren.
- **comment**: Bietet eine für Menschen lesbare Beschreibung oder einen Kommentar zur Regel für Dokumentations- und Verständniszwecke.

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
Darüber hinaus ist unter [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) die Bedeutung von `authenticate-admin-nonshared` zu sehen:<sup>[1]</sup>
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

Es handelt sich um einen Daemon, der Anfragen zur Autorisierung von Clients für die Ausführung sensibler Aktionen empfängt. Er arbeitet als XPC service, das im Ordner `XPCServices/` definiert ist, und schreibt seine Logs in `/var/log/authd.log`.

Außerdem ist es mit dem security tool möglich, viele `Security.framework`-APIs zu testen. Zum Beispiel kann `AuthorizationExecuteWithPrivileges` wie folgt ausgeführt werden: `security execute-with-privileges /bin/ls`

Dadurch wird `/usr/libexec/security_authtrampoline /bin/ls` als root geforkt und ausgeführt. Anschließend wird in einer Eingabeaufforderung nach den Berechtigungen gefragt, um ls als root auszuführen:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
