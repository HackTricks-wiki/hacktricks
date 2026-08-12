# macOS-Autorisierungsdatenbank & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Autorisierungsdatenbank

Die Authorization Services des Security-Frameworks ermöglichen es privilegierten Helfern und anderen Komponenten, benannte Autorisierungsrechte auszuwerten. In aktuellen macOS-Versionen werden viele dieser Regeln in `/var/db/auth.db` gespeichert und von `authd` ausgewertet; diese Datei und ihr SQLite-Schema sind Implementierungsdetails und können sich zwischen Releases ändern.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Systemstandardwerte wurden in der Vergangenheit aus `/System/Library/Security/authorization.plist` übernommen, und Installer oder privilegierte Services können benannte Rechte hinzufügen. Verwende bevorzugt die unterstützte Schnittstelle `security authorizationdb read|write|remove`, anstatt die Datenbank direkt zu bearbeiten.<sup>[[3]](#references)</sup>

Die in dem dokumentierten Build beobachtete Tabelle `rules` enthält die folgenden Spalten. Betrachte dies als forensische Übersicht und nicht als stabiles öffentliches Schema:

- **id**: Eine eindeutige Kennung für jede Regel, die automatisch inkrementiert wird und als Primärschlüssel dient.
- **name**: Der eindeutige Name der Regel, der verwendet wird, um sie innerhalb des Autorisierungssystems zu identifizieren und zu referenzieren.
- **type**: Gibt den Regeltyp an und ist auf die Werte 1 oder 2 beschränkt, um die Autorisierungslogik zu definieren.
- **class**: Kategorisiert die Regel in eine bestimmte Klasse und muss eine positive Ganzzahl sein.
- Zu den gängigen Regelklassen gehören `allow`, `deny`, `user`, `rule` und `evaluate-mechanisms`. Mechanismen können integrierte Mechanismen oder Security Agent-Plug-ins unter `/System/Library/CoreServices/SecurityAgentPlugins/` oder `/Library/Security/SecurityAgentPlugins/` sein.<sup>[[2]](#references)</sup>
- **group**: Gibt die Benutzergruppe an, die für die gruppenbasierte Autorisierung mit der Regel verknüpft ist.
- **kofn**: Stellt den Parameter „k-of-n“ dar und bestimmt, wie viele Unterregeln von einer Gesamtanzahl erfüllt sein müssen.
- **timeout**: Definiert die Dauer in Sekunden, bevor die von der Regel gewährte Autorisierung abläuft.
- **flags**: Enthält verschiedene Flags, die das Verhalten und die Eigenschaften der Regel ändern.
- **tries**: Begrenzt die Anzahl der zulässigen Autorisierungsversuche, um die Sicherheit zu erhöhen.
- **version**: Verfolgt die Version der Regel zur Versionskontrolle und für Aktualisierungen.
- **created**: Zeichnet den Zeitstempel der Regelerstellung zu Audit-Zwecken auf.
- **modified**: Speichert den Zeitstempel der letzten Änderung an der Regel.
- **hash**: Enthält einen Hashwert der Regel, um ihre Integrität sicherzustellen und Manipulationen zu erkennen.
- **identifier**: Stellt eine eindeutige String-Kennung, beispielsweise eine UUID, für externe Referenzen auf die Regel bereit.
- **requirement**: Enthält serialisierte Daten, die die spezifischen Autorisierungsanforderungen und Mechanismen der Regel definieren.
- **comment**: Bietet eine für Menschen lesbare Beschreibung oder einen Kommentar zur Regel für Dokumentation und bessere Verständlichkeit.

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
Die folgende dekodierte Regel veranschaulicht `authenticate-admin-nonshared` auf einer dokumentierten macOS-Version:<sup>[[1]](#references)</sup>
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

`authd` ist der XPC service, der Anfragen an die Authorization Services auswertet. In aktuellen macOS-Builds kann sein Bundle unter `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc` untersucht werden; der Pfad ist ein Implementierungsdetail und kann sich zwischen Releases unterscheiden. Ältere Releases schrieben nach `/var/log/authd.log`; aktuelle Releases verwenden hauptsächlich das unified logging system, das mit `log show`/`log stream` unter Verwendung eines `authd`-Prozessprädikats abgefragt werden kann.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Das `security`-Tool stellt mehrere Authorization Services-Operationen bereit. Ein historisches Beispiel ruft `AuthorizationExecuteWithPrivileges` mit `security execute-with-privileges /bin/ls` auf. Apple hat diese API in macOS 10.7 deprecated; moderne privilegierte Helfer sollten stattdessen einen von launchd verwalteten Helfer und eine XPC authorization verwenden.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Auf Releases, die dies noch unterstützen, verwendet dies `/usr/libexec/security_authtrampoline` und zeigt vor der Ausführung des Befehls als root eine authorization prompt an:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Übersicht über das macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (Archiv)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS-Handbuchseite](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: Erstellen von launchd-Jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple Open-Source-Security-Projekt - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
