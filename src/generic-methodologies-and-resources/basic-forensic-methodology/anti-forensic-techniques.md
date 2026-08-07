# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Зловмисник може бути зацікавлений у **зміні часових міток файлів**, щоб уникнути виявлення.\
Часові мітки можна знайти всередині MFT в атрибутах `$STANDARD_INFORMATION` \_\_ та \_\_ `$FILE_NAME`.

Обидва атрибути мають 4 часові мітки: **Modification**, **access**, **creation** і **MFT registry modification** (MACE або MACB).

**Windows explorer** та інші інструменти відображають інформацію з **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Цей інструмент **змінює** інформацію про часові мітки всередині **`$STANDARD_INFORMATION`**, але **не** інформацію всередині **`$FILE_NAME`**. Тому можна **виявити** **підозрілу** **активність**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) — це функція NTFS (Windows NT file system), яка відстежує зміни тома. Інструмент [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) дає змогу досліджувати ці зміни.

![TimeStomp - Anti-forensic Tool - Usnjrnl: The USN Journal (Update Sequence Number Journal) is a feature of the NTFS (Windows NT file system) that keeps track of volume changes. The...](<../../images/image (801).png>)

На попередньому зображенні показано **вивід**, відображений **інструментом**, де можна побачити, що до файлу **було внесено деякі зміни**.

### $LogFile

**Усі зміни метаданих файлової системи записуються** в процесі, відомому як [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Записані метадані зберігаються у файлі `**$LogFile**`, розташованому в кореневому каталозі файлової системи NTFS. Для аналізу цього файлу та виявлення змін можна використовувати такі інструменти, як [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: All metadata changes to a file system are logged in a process known as write-ahead logging. The logged metadata is kept in a file named $LogFile , located in the root...](<../../images/image (137).png>)

Знову ж таки, у виводі інструмента можна побачити, що **було внесено деякі зміни**.

За допомогою того самого інструмента можна визначити, **коли саме були змінені часові мітки**:

![Usnjrnl - $LogFile: Using the same tool it's possible to identify to which time the timestamps were modified](<../../images/image (1089).png>)

- CTIME: Час створення файлу
- ATIME: Час модифікації файлу
- MTIME: Час модифікації реєстру MFT файлу
- RTIME: Час доступу до файлу

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

Ще одним способом виявлення підозрілих змінених файлів є порівняння часу в обох атрибутах у пошуках **невідповідностей**.

### Nanoseconds

Часові мітки **NTFS** мають **точність** **100 наносекунд**. Тому пошук файлів із часовими мітками на кшталт 2010-10-10 10:10:**00.000:0000 є дуже підозрілим**.

### SetMace - Anti-forensic Tool

Цей інструмент може змінювати обидва атрибути — `$STARNDAR_INFORMATION` і `$FILE_NAME`. Однак починаючи з Windows Vista для зміни цієї інформації необхідна запущена OS.

## Data Hiding

NFTS використовує кластери та мінімальний розмір інформації. Це означає, що якщо файл займає один із половиною кластера, **половина, що залишилася, ніколи не використовуватиметься**, доки файл не буде видалено. Отже, **у цьому slack space можна приховати дані**.

Існують такі інструменти, як slacker, що дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз `$logfile` і `$usnjrnl` може показати, що деякі дані було додано:

![SetMace - Anti-forensic Tool - Data Hiding: There are tools like slacker that allow hiding data in this "hidden" space. However, an analysis of the $logfile and $usnjrnl can show that...](<../../images/image (1060).png>)

Після цього slack space можна отримати за допомогою таких інструментів, як FTK Imager. Зверніть увагу, що цей тип інструментів може зберігати вміст в obfuscated або навіть encrypted вигляді.

## UsbKill

Це інструмент, який **вимикає комп’ютер, якщо виявлено будь-яку зміну** в USB-портах.\
Щоб виявити його, можна перевірити запущені процеси та **переглянути кожен запущений python script**.

## Live Linux Distributions

Ці distros **виконуються в оперативній пам’яті**. Єдиний спосіб їх виявити — **якщо файлова система NTFS змонтована з правами на запис**. Якщо її змонтовано лише з правами на читання, виявити intrusion буде неможливо.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Можна вимкнути кілька методів logging у Windows, щоб значно ускладнити forensic investigation.

### Disable Timestamps - UserAssist

Це registry key, який зберігає дати й час запуску кожного executable користувачем.

Вимкнення UserAssist потребує двох кроків:

1. Встановіть два registry keys — `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` і `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` — обидва в нуль, щоб вказати, що UserAssist потрібно вимкнути.
2. Очистіть піддерева registry, що мають вигляд `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Це зберігає інформацію про запущені applications з метою підвищення продуктивності Windows system. Однак ця інформація також може бути корисною для forensic practices.

- Запустіть `regedit`
- Виберіть шлях до файлу `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Клацніть правою кнопкою миші на `EnablePrefetcher` і `EnableSuperfetch`
- Виберіть Modify для кожного параметра та змініть значення з 1 (або 3) на 0
- Перезапустіть system

### Disable Timestamps - Last Access Time

Щоразу, коли папку відкривають із тому NTFS на Windows NT server, system оновлює поле часової мітки в кожній папці зі списку, яке називається часом останнього доступу. На інтенсивно використовуваному томі NTFS це може впливати на продуктивність.

1. Відкрийте Registry Editor (Regedit.exe).
2. Перейдіть до `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Знайдіть `NtfsDisableLastAccessUpdate`. Якщо цього параметра немає, додайте цей DWORD і встановіть його значення 1, що вимкне цей процес.
4. Закрийте Registry Editor і перезавантажте server.

### Delete USB History

Усі **USB Device Entries** зберігаються в Windows Registry у registry key **USBSTOR**, який містить sub keys, що створюються щоразу, коли ви підключаєте USB Device до PC або Laptop. Цей key можна знайти тут: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Видаливши його**, ви видалите USB history.\
Також можна скористатися інструментом [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), щоб переконатися, що їх було видалено (і видалити їх).

Ще одним файлом, що зберігає інформацію про USB, є `setupapi.dev.log` у `C:\Windows\INF`. Його також слід видалити.

### Disable Shadow Copies

**Переглянути список** shadow copies можна за допомогою `vssadmin list shadowstorage`\
**Видалити** їх можна командою `vssadmin delete shadow`

Також їх можна видалити через GUI, виконавши кроки, описані в [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Щоб вимкнути shadow copies, виконайте [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Відкрийте програму Services, ввівши «services» у поле текстового пошуку після натискання кнопки запуску Windows.
2. У списку знайдіть «Volume Shadow Copy», виберіть його та відкрийте Properties, клацнувши правою кнопкою миші.
3. У спадному меню «Startup type» виберіть Disabled, а потім підтвердьте зміну, натиснувши Apply і OK.

Також можна змінити конфігурацію файлів, які копіюватимуться в shadow copy, у registry за адресою `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Можна використати **Windows tool**: `cipher /w:C`. Це вкаже cipher видалити всі дані з доступного невикористаного дискового простору на диску C.
- Також можна використовувати такі інструменти, як [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> розгорніть «Windows Logs» --> клацніть правою кнопкою миші кожну категорію та виберіть «Clear Log»
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- У розділі services вимкніть service «Windows Event Log»
- `WEvtUtil.exec clear-log` або `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Recent versions of Windows 10/11 and Windows Server зберігають **насичені PowerShell forensic artifacts** у
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Attackers можуть вимкнути або стерти їх on-the-fly:
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

Продукти безпеки кінцевих точок значною мірою покладаються на ETW. Популярний метод ухилення у 2024 році полягає в тому, щоб пропатчити `ntdll!EtwEventWrite`/`EtwEventWriteFull` у пам'яті, щоб кожен виклик ETW повертав `STATUS_SUCCESS`, не генеруючи подію:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) implement the same primitive in PowerShell or C++.
Because the patch is **process-local**, EDRs running inside other processes may miss it.<sup>[[5]](#references)</sup>
Detection: compare `ntdll` in memory vs. on disk, or hook before user-mode.

### Відродження Alternate Data Streams (ADS)

У 2023 році було помічено, як malware campaigns (наприклад, **FIN12** loaders) розміщують бінарні файли другого етапу
в ADS, щоб залишатися непомітними для традиційних сканерів:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Перелічити streams за допомогою `dir /R`, `Get-Item -Stream *` або Sysinternals `streams64.exe`.
Копіювання host-файлу на FAT/exFAT або через SMB видалить прихований stream, що може бути використано
дослідниками для відновлення payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver тепер регулярно використовується для **anti-forensics** під час атак
ransomware.
Open-source tool **AuKill** завантажує підписаний, але вразливий driver (`procexp152.sys`), щоб
призупинити або завершити EDR і forensic sensors **до шифрування та знищення log-файлів**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Драйвер згодом видаляється, залишаючи мінімум артефактів.<sup>[[1]](#references)</sup>
Заходи пом'якшення: увімкніть Microsoft vulnerable-driver blocklist (HVCI/SAC)
і налаштуйте сповіщення про створення kernel-service з user-writable paths.

---

## Linux Anti-Forensics: Self-Patching і Cloud C2 (2023–2025)

### Self‑patching скомпрометованих сервісів для зменшення виявлення (Linux)
Зловмисники дедалі частіше виконують “self‑patch” сервісу одразу після його експлуатації, щоб одночасно запобігти повторній експлуатації та придушити vulnerability-based detections. Ідея полягає в заміні вразливих компонентів найновішими легітимними upstream-бінарними файлами/JAR-файлами, щоб сканери повідомляли, що host пропатчений, тоді як persistence і C2 залишаються.<sup>[[3]](#references)</sup>

Приклад: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Після exploitation attackers завантажили легітимні JAR-файли з Maven Central (repo1.maven.org), видалили вразливі JAR-файли з інсталяції ActiveMQ і перезапустили broker.
- Це усунуло початковий RCE, зберігши інші footholds (cron, зміни конфігурації SSH, окремі C2 implants).

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
Криміналістичні поради та поради щодо hunting
- Перевірте директорії сервісів на наявність незапланованих замін бінарних файлів/JAR:
- Debian/Ubuntu: `dpkg -V activemq` і порівняйте хеші/шляхи файлів із дзеркалами репозиторію.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Шукайте версії JAR, наявні на диску, які не належать package manager, або символічні посилання, оновлені поза штатним процесом.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` для кореляції ctime/mtime з періодом компрометації.
- Shell history/process telemetry: ознаки використання `curl`/`wget` для звернення до `repo1.maven.org` або інших artifact CDN одразу після первинної експлуатації.
- Change management: перевірте, хто і навіщо застосував “patch”, а не лише наявність patched version.

### C2 через cloud-сервіси з bearer tokens і anti-analysis stagers
Спостережуваний tradecraft поєднував кілька довготривалих шляхів C2 та anti-analysis пакування:<sup>[[3]](#references)</sup>
- Захищені паролем PyInstaller ELF loaders для ускладнення sandboxing і static analysis (наприклад, зашифрований PYZ, тимчасове розпакування в `/_MEI*`).
- Indicators: збіги `strings`, такі як `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: розпакування до `/tmp/_MEI*` або custom `--runtime-tmpdir` paths.
- C2 через Dropbox із hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` з `Authorization: Bearer <token>`.
- Виконуйте hunting у proxy/NetFlow/Zeek/Suricata для виявлення вихідного HTTPS до доменів Dropbox із server workloads, які зазвичай не синхронізують файли.
- Parallel/backup C2 через tunneling (наприклад, Cloudflare Tunnel `cloudflared`), щоб зберегти control, якщо один канал заблоковано.
- Host IOCs: процеси/units `cloudflared`, config у `~/.cloudflared/*.json`, вихідні з’єднання через 443 до Cloudflare edges.

### Persistence і “hardening rollback” для збереження доступу (приклади Linux)
Attackers часто поєднують self-patching зі стійкими шляхами доступу:<sup>[[3]](#references)</sup>
- Cron/Anacron: зміни у stub `0anacron` у кожній директорії `/etc/cron.*/` для періодичного виконання.
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
- Random, short-named beacon artifacts (8 alphabetical chars), записані на диск, які також встановлюють з’єднання з cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders повинні корелювати ці artifacts із зовнішньою експозицією та подіями patching сервісів, щоб виявити anti-forensic self-remediation, використану для приховування первинної експлуатації.

## References

- [1] [Sophos X-Ops – AuKill: зброєнізований вразливий драйвер для вимкнення EDR (березень 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite для stealth: Detection & Hunting (червень 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching для persistence: як Linux malware DripDropper переміщується через cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)

{{#include ../../banners/hacktricks-training.md}}
