# Антифорензичні техніки

{{#include ../../banners/hacktricks-training.md}}

## Мітки часу

Зловмисник може захотіти **змінити мітки часу файлів**, щоб уникнути виявлення.\
Мітки часу можна знайти в MFT в атрибутах `$STANDARD_INFORMATION` \_\_ і \_\_ `$FILE_NAME`.

Обидва атрибути містять 4 мітки часу: **модифікації**, **доступу**, **створення** та **модифікації запису MFT** (MACE або MACB).

**Windows Explorer** та інші інструменти показують інформацію з **`$STANDARD_INFORMATION`**.

### TimeStomp - Антифорензичний інструмент

Цей інструмент **змінює** інформацію про мітки часу в **`$STANDARD_INFORMATION`**, **але** **не** інформацію в **`$FILE_NAME`**. Тому можна **виявити** **підозрілу** **активність**.

### Usnjrnl

**Журнал USN** (журнал номерів послідовності оновлень) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тому. Інструмент [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) дає змогу досліджувати ці зміни.

![TimeStomp - Антифорензичний інструмент - Usnjrnl: Журнал USN (журнал номерів послідовності оновлень) — це функція NTFS (файлової системи Windows NT), яка відстежує зміни тому. Інструмент...](<../../images/image (801).png>)

На попередньому зображенні показано **вивід** інструмента, де можна побачити, що у файлі **було виконано певні зміни**.

### $LogFile

**Усі зміни метаданих файлової системи реєструються** в процесі, відомому як [журналювання з випереджальним записом](https://en.wikipedia.org/wiki/Write-ahead_logging). Зареєстровані метадані зберігаються у файлі `**$LogFile**`, розташованому в кореневому каталозі файлової системи NTFS. Для аналізу цього файлу та виявлення змін можна використовувати такі інструменти, як [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: Усі зміни метаданих файлової системи реєструються в процесі, відомому як журналювання з випереджальним записом. Зареєстровані метадані зберігаються у файлі $LogFile , розташованому в кореневому...](<../../images/image (137).png>)

Знову ж таки, у виводі інструмента можна побачити, що **було виконано певні зміни**.

За допомогою того самого інструмента можна визначити, **на який час змінили мітки часу**:

![Usnjrnl - $LogFile: За допомогою того самого інструмента можна визначити, на який час змінили мітки часу](<../../images/image (1089).png>)

- CTIME: час створення файлу
- ATIME: час модифікації файлу
- MTIME: час модифікації запису MFT файлу
- RTIME: час доступу до файлу

### Порівняння `$STANDARD_INFORMATION` і `$FILE_NAME`

Інший спосіб виявити підозрілі змінені файли — порівняти час в обох атрибутах і знайти **невідповідності**.

### Наносекунди

Мітки часу **NTFS** мають **точність** до **100 наносекунд**. Тому файли з мітками часу на кшталт 2010-10-10 10:10:**00.000:0000 є дуже підозрілими**.

### SetMace - Антифорензичний інструмент

Цей інструмент може змінювати обидва атрибути: `$STARNDAR_INFORMATION` і `$FILE_NAME`. Однак починаючи з Windows Vista для зміни цієї інформації потрібна запущена ОС.

## Приховування даних

NFTS використовує кластери та мінімальний розмір інформації. Це означає, що якщо файл займає півтора кластера, **друга половина не використовуватиметься**, доки файл не буде видалено. Тоді **в цьому невикористаному просторі можна приховати дані**.

Існують інструменти на кшталт slacker, які дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз `$logfile` і `$usnjrnl` може показати, що було додано дані:

![SetMace - Антифорензичний інструмент - Приховування даних: Існують інструменти на кшталт slacker, які дають змогу приховувати дані в цьому «прихованому» просторі. Однак аналіз $logfile і $usnjrnl може показати, що...](<../../images/image (1060).png>)

Потім невикористаний простір можна отримати за допомогою таких інструментів, як FTK Imager. Зверніть увагу, що такі інструменти можуть зберегти вміст в обфускованому або навіть зашифрованому вигляді.

## UsbKill

Цей інструмент **вимикає комп’ютер, якщо виявляє будь-які зміни в USB-портах**.\
Щоб виявити його, можна перевірити запущені процеси та **переглянути кожен запущений скрипт Python**.

## Live-дистрибутиви Linux

Ці дистрибутиви **запускаються в оперативній пам’яті**. Виявити їх можна лише **якщо файлова система NTFS змонтована з правами на запис**. Якщо її змонтовано лише з правами на читання, виявити вторгнення буде неможливо.

## Безпечне видалення

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Відкладене самовидалення у Windows

Запущений образ Windows може бути заблокований, поки активний відповідний процес. Процес може доручити видалення дочірньому `cmd.exe`, використати `choice` як таймер і завершитися до того, як оболонка дійде до `del`. Затримка дає початковому процесу змогу звільнити дескриптор образу; якщо повний шлях містить пробіли, його потрібно брати в лапки.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Коли цей рядок передається безпосередньо як аргумент `cmd.exe`, а не вводиться з іншого інтерактивного запрошення `cmd`, використовуйте `&` замість `^&` і `>nul` замість `^>nul`. Це видаляє запис каталогу; це **не безпечне стирання** і воно не видаляє сліди виконання, завдань, журналу файлової системи чи інші криміналістичні сліди. Шукайте короткочасні дочірні процеси `cmd.exe`, у командному рядку яких поєднано `choice /T`, `Del` і шлях до образу батьківського процесу.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Конфігурація Windows

Можна вимкнути кілька методів журналювання Windows, щоб значно ускладнити криміналістичне розслідування.

### Вимкнення часових міток — UserAssist

Цей розділ реєстру зберігає дати й час запуску користувачем кожного виконуваного файла.

Щоб вимкнути UserAssist, виконайте два кроки:

1. Установіть для обох розділів реєстру `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` і `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` значення нуль, щоб вимкнути UserAssist.
2. Очистьте підрозділи реєстру на кшталт `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Вимкнення часових міток — Prefetch

Тут зберігається інформація про запущені програми, щоб підвищити продуктивність системи Windows. Водночас ці дані можуть бути корисними для криміналістичного аналізу.

- Запустіть `regedit`
- Перейдіть до шляху реєстру `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Клацніть правою кнопкою миші `EnablePrefetcher` і `EnableSuperfetch`
- Для кожного з них виберіть «Змінити» та змініть значення з 1 (або 3) на 0
- Перезавантажте комп’ютер

### Вимкнення часових міток — час останнього доступу

Щоразу, коли в папці на томі NTFS сервера Windows NT відкривають файл, система оновлює **поле часової мітки в кожній папці зі списку** — час останнього доступу. На інтенсивно використовуваному томі NTFS це може вплинути на продуктивність.

1. Відкрийте редактор реєстру (Regedit.exe).
2. Перейдіть до `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Знайдіть `NtfsDisableLastAccessUpdate`. Якщо цього параметра немає, створіть DWORD і задайте йому значення 1, щоб вимкнути цей процес.
4. Закрийте редактор реєстру та перезавантажте сервер.

### Видалення історії USB

Усі **записи про USB-пристрої** зберігаються в реєстрі Windows у розділі **USBSTOR**, який містить підрозділи, що створюються щоразу, коли ви під’єднуєте USB-пристрій до ПК або ноутбука. Цей розділ розташовано тут: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Якщо видалити його**, буде видалено історію USB.\
Також можна скористатися інструментом [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), щоб переконатися, що записи видалено (і видалити їх).

Ще один файл, у якому зберігається інформація про USB-пристрої, — `setupapi.dev.log` у `C:\Windows\INF`. Його також слід видалити.

### Вимкнення тіньових копій

**Перегляньте список** тіньових копій за допомогою `vssadmin list shadowstorage`\
**Видаліть** їх командою `vssadmin delete shadow`

Їх також можна видалити через графічний інтерфейс, виконавши кроки з [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Щоб вимкнути тіньові копії, виконайте [кроки звідси](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Відкрийте програму «Служби»: натисніть кнопку «Пуск» у Windows і введіть "services" у поле пошуку.
2. У списку знайдіть "Volume Shadow Copy", виберіть його та відкрийте «Властивості», клацнувши правою кнопкою миші.
3. Виберіть «Вимкнено» зі списку «Тип запуску», а потім підтвердьте зміни, натиснувши «Застосувати» та «OK».

Також можна змінити в реєстрі конфігурацію файлів, які копіюватимуться до тіньової копії: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Перезапис видалених файлів

- Можна скористатися **інструментом Windows**: `cipher /w:C`. Це вкаже cipher видалити всі дані з доступного невикористаного дискового простору на диску C.
- Також можна скористатися інструментами на кшталт [**Eraser**](https://eraser.heidi.ie)

### Видалення журналів подій Windows

- Windows + R --> eventvwr.msc --> розгорніть "Журнали Windows" --> клацніть правою кнопкою миші кожну категорію та виберіть "Очистити журнал"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Вимкнення журналів подій Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- У розділі служб вимкніть службу "Windows Event Log"
- `WEvtUtil.exec clear-log` або `WEvtUtil.exe cl`

### Вимкнення $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Розширене журналювання та підробка слідів (2023-2025)

### Журналювання PowerShell ScriptBlock/Module

У новіших версіях Windows 10/11 і Windows Server зберігаються **детальні криміналістичні артефакти PowerShell** у розділі
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

Продукти endpoint security значною мірою покладаються на ETW. Популярний метод обходу захисту у 2024 році — патчити `ntdll!EtwEventWrite`/`EtwEventWriteFull` у пам’яті, щоб кожен виклик ETW повертав `STATUS_SUCCESS`, не генеруючи подію:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Публічні PoC (наприклад, `EtwTiSwallow`) реалізують той самий примітив на PowerShell або C++.  
Оскільки патч діє **лише в межах процесу**, EDR, що працюють в інших процесах, можуть його не виявити.<sup>[[5]](#references)</sup>
Виявлення: порівнюйте `ntdll` у пам’яті з файлом на диску або встановлюйте hook до переходу в user-mode.

### Відродження Alternate Data Streams (ADS)

У 2023 році помічали кампанії шкідливого ПЗ (наприклад, лоадери **FIN12**), які розміщували бінарні файли другого етапу в ADS, щоб залишатися непомітними для традиційних сканерів:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Перелічіть потоки за допомогою `dir /R`, `Get-Item -Stream *` або Sysinternals `streams64.exe`.
Копіювання файла-хоста на FAT/exFAT або через SMB видалить прихований потік, тож слідчі зможуть відновити payload.

### BYOVD і «AuKill» (2023)

Bring-Your-Own-Vulnerable-Driver регулярно використовують для **anti-forensics** під час атак із використанням ransomware.  
Інструмент із відкритим кодом **AuKill** завантажує підписаний, але вразливий драйвер (`procexp152.sys`), щоб призупинити роботу або завершити процеси EDR і криміналістичних сенсорів **до шифрування й знищення журналів**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Драйвер згодом видаляють, залишаючи мінімум артефактів.<sup>[[1]](#references)</sup>  
Заходи захисту: увімкніть список блокування вразливих драйверів Microsoft (HVCI/SAC)
і налаштуйте сповіщення про створення kernel-служб із доступних для запису користувачем шляхів.

---

## Антифорензика Linux: Self‑patching і Cloud C2 (2023–2025)

### Self‑patching скомпрометованих сервісів для зниження ймовірності виявлення (Linux)
Зловмисники дедалі частіше виконують «self-patch» сервісу одразу після його експлуатації, щоб запобігти повторній експлуатації та приглушити виявлення на основі вразливостей. Ідея полягає в заміні вразливих компонентів на найновіші легітимні upstream-бінарні файли/JAR-файли, щоб сканери вважали хост виправленим, а persistence і C2 залишалися.<sup>[[3]](#references)</sup>

Приклад: RCE в Apache ActiveMQ OpenWire (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Після експлуатації зловмисники завантажували легітимні JAR-файли з Maven Central (repo1.maven.org), видаляли вразливі JAR-файли з інсталяції ActiveMQ і перезапускали брокер.
- Це усувало початкову RCE, водночас зберігаючи інші точки доступу (cron, зміни конфігурації SSH, окремі C2-імпланти).

Приклад з практики (для ілюстрації)
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

Криміналістичні поради та поради з пошуку загроз
- Перевірте каталоги сервісів на наявність незапланованої заміни бінарних файлів/JAR:
  - Debian/Ubuntu: `dpkg -V activemq` і порівняйте хеші/шляхи файлів із дзеркалами репозиторіїв.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Шукайте версії JAR на диску, які не належать менеджеру пакетів, або символічні посилання, оновлені поза штатним процесом.
- Часова шкала: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`, щоб зіставити ctime/mtime з періодом компрометації.
- Історія оболонки/телеметрія процесів: шукайте свідчення використання `curl`/`wget` для завантаження з `repo1.maven.org` чи інших CDN артефактів одразу після початкової експлуатації.
- Керування змінами: з’ясуйте, хто і навіщо застосував «патч», а не лише перевірте наявність пропатченої версії.

### C2 через хмарні сервіси з bearer-токенами та stager-ами, стійкими до аналізу
Зафіксована тактика поєднувала кілька довготривалих каналів C2 та пакування, що перешкоджає аналізу:<sup>[[3]](#references)</sup>
- Захищені паролем ELF-завантажувачі PyInstaller, що ускладнюють аналіз у sandbox і статичний аналіз (наприклад, зашифрований PYZ, тимчасове розпакування в `/_MEI*`).
  - Індикатори: збіги `strings`, як-от `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Артефакти під час виконання: розпакування в `/tmp/_MEI*` або користувацькі шляхи `--runtime-tmpdir`.
- C2 через Dropbox із жорстко закодованими OAuth Bearer-токенами
  - Мережеві маркери: `api.dropboxapi.com` / `content.dropboxapi.com` із `Authorization: Bearer <token>`.
  - Шукайте в proxy/NetFlow/Zeek/Suricata вихідний HTTPS-трафік до доменів Dropbox із серверних робочих навантажень, які зазвичай не синхронізують файли.
- Паралельний/резервний C2 через тунелювання (наприклад, Cloudflare Tunnel `cloudflared`), щоб зберегти контроль, якщо один канал заблоковано.
  - IOC на хості: процеси/служби `cloudflared`, конфігурація в `~/.cloudflared/*.json`, вихідні з’єднання через 443 до вузлів Cloudflare.

### Закріплення та «відкат посилення безпеки» для збереження доступу (приклади для Linux)
Зловмисники часто поєднують самостійне виправлення з надійними шляхами доступу:<sup>[[3]](#references)</sup>
- Cron/Anacron: зміни заглушки `0anacron` у кожному каталозі `/etc/cron.*/` для періодичного виконання.
  - Пошук:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Відкат посилення конфігурації SSH: увімкнення входу root і зміна оболонок за замовчуванням для облікових записів із низькими привілеями.
  - Пошук увімкнення входу root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Шукайте підозрілі інтерактивні оболонки в системних облікових записах (наприклад, `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Випадкові beacon-артефакти з короткими назвами (8 літер латиниці), записані на диск і такі, що зв’язуються з cloud C2:
  - Пошук:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Захисники мають зіставляти ці артефакти з даними про зовнішню доступність і події встановлення виправлень для сервісів, щоб виявляти самостійне усунення слідів після експлуатації, спрямоване на приховування початкового проникнення.

## Виконання вбудованої оболонки у статичному бінарному файлі

Обгортка скрипту з вбудованим інтерпретатором і реалізаціями команд може виконувати підтримувані операції shell в одному виконуваному файлі замість запуску `/bin/sh` і окремих процесів утиліт. HimitsuShell створює такий статичний бінарний файл на musl. На відміну від [обгорток SHc](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), його вбудовані команди не потребують запуску системної оболонки чи окремого процесу утиліти. Непідтримувані команди можуть виконуватися системною оболонкою.<sup>[[9]](#references)</sup>

Це зменшує видимість процесів оболонки та дочірніх викликів `execve`.<sup>[[9]](#references)</sup> Процес-обгортка та його системні виклики залишаються видимими через точки трасування ядра, тому твердження проєкту, що його неможливо виявити навіть за допомогою трасування ядра, не слід сприймати буквально.<sup>[[9]](#references)[[11]](#references)</sup>

Для задокументованої збірки x86_64 залиште вхідний файл із назвою `launcher.sh` і скопіюйте його в контейнер перед компіляцією. Результат матиме назву `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Публічний `compile.sh` шифрує скрипт за допомогою AES-256-CTR, шифрує значення строку дії та проміжні ключі/IV за допомогою AES-256-CBC, перетворює зашифровані файли на масиви C за допомогою `xxd -i` і зв’язує їх із `lib.bc`, використовуючи `-static -s`. Фінальний ключ шифрування та IV також вбудовані, тож це захист від поверхневого статичного вилучення, а не секрет, який неможливо відновити.<sup>[[10]](#references)</sup>

Типові LLVM passes — `-sobf` і `-sub`. Перед збіркою відредагуйте `/var/work/compile.sh`, щоб увімкнути документовані альтернативи, як-от control-flow flattening (`fla`) або bogus control flow (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Перевірте сумісність скриптів, перш ніж покладатися на цю обгортку: проєкт використовує синтаксис POSIX shell і попереджає, що скрипти Bash/Zsh можуть не працювати; також зазначено, що команди поза вбудованим набором виконуються системною оболонкою.<sup>[[9]](#references)</sup>

Про аналіз сплощеного потоку керування див. [обхід сплощеного потоку керування за допомогою вузького зрізу виконання](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: озброєний вразливий драйвер для вимкнення EDR (березень 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Патчинг EtwEventWrite для прихованості: виявлення та пошук загроз (червень 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Патчинг для закріплення: як шкідливе ПЗ DripDropper для Linux переміщується хмарою](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE в Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Приховування вашого .NET — ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Виявлення варіанта SectopRAT, вбудованого в легітимне програмне забезпечення](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – команда choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – команда del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [README HimitsuShell](https://github.com/HimitsuShell/HimitsuShell)
- [10] [Скрипт збірки HimitsuShell](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Гістограми подій ядра Linux і трасування системних викликів](https://docs.kernel.org/trace/histogram.html)
