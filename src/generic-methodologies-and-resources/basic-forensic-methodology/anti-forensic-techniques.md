# Анти-слідчі техніки

{{#include ../../banners/hacktricks-training.md}}

## Часові мітки

Атакуючий може бути зацікавлений у **зміні часових міток файлів**, щоб уникнути виявлення.\
Можна знайти часові мітки всередині MFT в атрибутах `$STANDARD_INFORMATION` \_\_ та \_\_ `$FILE_NAME`.

Обидва атрибути мають 4 часові мітки: **Зміна**, **доступ**, **створення** та **зміна реєстрації MFT** (MACE або MACB).

**Windows explorer** та інші інструменти показують інформацію з **`$STANDARD_INFORMATION`**.

### TimeStomp - Анти-слідчий інструмент

Цей інструмент **модифікує** інформацію про часові мітки всередині **`$STANDARD_INFORMATION`**, **але** **не** інформацію всередині **`$FILE_NAME`**. Тому можливо **виявити** **підозрілу** **активність**.

### Usnjrnl

**USN Journal** (Журнал номерів послідовності оновлень) є функцією NTFS (файлова система Windows NT), яка відстежує зміни обсягу. Інструмент [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) дозволяє досліджувати ці зміни.

![](<../../images/image (801).png>)

Попереднє зображення є **виходом**, показаним **інструментом**, де можна спостерігати, що деякі **зміни були виконані** до файлу.

### $LogFile

**Всі зміни метаданих файлової системи реєструються** в процесі, відомому як [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Зареєстровані метадані зберігаються у файлі з назвою `**$LogFile**`, розташованому в кореневому каталозі файлової системи NTFS. Інструменти, такі як [LogFileParser](https://github.com/jschicht/LogFileParser), можуть бути використані для парсингу цього файлу та виявлення змін.

![](<../../images/image (137).png>)

Знову ж таки, у виході інструмента можна побачити, що **деякі зміни були виконані**.

Використовуючи той же інструмент, можна визначити, **коли були змінені часові мітки**:

![](<../../images/image (1089).png>)

- CTIME: Час створення файлу
- ATIME: Час зміни файлу
- MTIME: Зміна реєстрації MFT файлу
- RTIME: Час доступу до файлу

### Порівняння `$STANDARD_INFORMATION` та `$FILE_NAME`

Ще один спосіб виявити підозрілі змінені файли - це порівняти час на обох атрибутах, шукаючи **невідповідності**.

### Наносекунди

**NTFS** часові мітки мають **точність** **100 наносекунд**. Тому знаходження файлів з часовими мітками, такими як 2010-10-10 10:10:**00.000:0000, є дуже підозрілим**.

### SetMace - Анти-слідчий інструмент

Цей інструмент може модифікувати обидва атрибути `$STARNDAR_INFORMATION` та `$FILE_NAME`. Однак, починаючи з Windows Vista, для зміни цієї інформації необхідна активна ОС.

## Сховані дані

NFTS використовує кластер і мінімальний розмір інформації. Це означає, що якщо файл займає кластер і півтора, **залишкова половина ніколи не буде використана**, поки файл не буде видалено. Тоді можливо **сховати дані в цьому слек-просторі**.

Існують інструменти, такі як slacker, які дозволяють ховати дані в цьому "схованому" просторі. Однак аналіз `$logfile` та `$usnjrnl` може показати, що деякі дані були додані:

![](<../../images/image (1060).png>)

Тоді можливо відновити слек-простір, використовуючи інструменти, такі як FTK Imager. Зверніть увагу, що цей тип інструменту може зберігати вміст в обфусцированому або навіть зашифрованому вигляді.

## UsbKill

Це інструмент, який **вимкне комп'ютер, якщо буде виявлено будь-які зміни в USB** портах.\
Спосіб виявлення цього - перевірити запущені процеси та **переглянути кожен запущений python-скрипт**.

## Живі дистрибутиви Linux

Ці дистрибутиви **виконуються в пам'яті RAM**. Єдиний спосіб виявити їх - **якщо файлову систему NTFS змонтовано з правами на запис**. Якщо вона змонтована лише з правами на читання, виявити вторгнення не вдасться.

## Безпечне видалення

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Налаштування Windows

Можна вимкнути кілька методів ведення журналів Windows, щоб ускладнити слідчу перевірку.

### Вимкнути часові мітки - UserAssist

Це ключ реєстру, який зберігає дати та години, коли кожен виконуваний файл був запущений користувачем.

Вимкнення UserAssist вимагає двох кроків:

1. Встановіть два ключі реєстру, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` та `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, обидва на нуль, щоб сигналізувати, що ми хочемо вимкнути UserAssist.
2. Очистіть свої піддерева реєстру, які виглядають як `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Вимкнути часові мітки - Prefetch

Це зберігатиме інформацію про виконувані програми з метою покращення продуктивності системи Windows. Однак це також може бути корисним для слідчих практик.

- Виконайте `regedit`
- Виберіть шлях файлу `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Клацніть правою кнопкою миші на `EnablePrefetcher` та `EnableSuperfetch`
- Виберіть Змінити для кожного з них, щоб змінити значення з 1 (або 3) на 0
- Перезавантажте

### Вимкнути часові мітки - Час останнього доступу

Кожного разу, коли папка відкривається з обсягу NTFS на сервері Windows NT, система витрачає час на **оновлення поля часової мітки для кожної вказаної папки**, яке називається часом останнього доступу. На сильно завантаженому обсязі NTFS це може вплинути на продуктивність.

1. Відкрийте Редактор реєстру (Regedit.exe).
2. Перейдіть до `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Знайдіть `NtfsDisableLastAccessUpdate`. Якщо його немає, додайте цей DWORD і встановіть його значення на 1, що вимкне процес.
4. Закрийте Редактор реєстру та перезавантажте сервер.

### Видалити історію USB

Всі **USB Device Entries** зберігаються в реєстрі Windows під ключем **USBSTOR**, який містить підключі, які створюються щоразу, коли ви підключаєте USB-пристрій до свого ПК або ноутбука. Ви можете знайти цей ключ тут H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Видаливши це**, ви видалите історію USB.\
Ви також можете використовувати інструмент [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), щоб переконатися, що ви їх видалили (і щоб видалити їх).

Ще один файл, який зберігає інформацію про USB, - це файл `setupapi.dev.log` всередині `C:\Windows\INF`. Цей файл також слід видалити.

### Вимкнути тіньові копії

**Список** тіньових копій за допомогою `vssadmin list shadowstorage`\
**Видалити** їх, запустивши `vssadmin delete shadow`

Ви також можете видалити їх через GUI, дотримуючись кроків, запропонованих у [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Щоб вимкнути тіньові копії, [кроки звідси](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Відкрийте програму Служби, ввівши "services" у текстовому полі пошуку після натискання кнопки "Пуск" Windows.
2. У списку знайдіть "Volume Shadow Copy", виберіть його, а потім отримайте доступ до Властивостей, клацнувши правою кнопкою миші.
3. Виберіть Вимкнено з випадаючого меню "Тип запуску", а потім підтвердіть зміну, натиснувши Застосувати та ОК.

Також можливо змінити конфігурацію, які файли будуть копіюватися в тіньову копію в реєстрі `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Перезаписати видалені файли

- Ви можете використовувати **інструмент Windows**: `cipher /w:C`. Це вказує шифрувати, щоб видалити будь-які дані з доступного невикористаного дискового простору всередині диска C.
- Ви також можете використовувати інструменти, такі як [**Eraser**](https://eraser.heidi.ie)

### Видалити журнали подій Windows

- Windows + R --> eventvwr.msc --> Розгорніть "Журнали Windows" --> Клацніть правою кнопкою миші на кожній категорії та виберіть "Очистити журнал"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Вимкнути журнали подій Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- У розділі служб вимкніть службу "Windows Event Log"
- `WEvtUtil.exec clear-log` або `WEvtUtil.exe cl`

### Вимкнути $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Розширене ведення журналів та підробка трас (2023-2025)

### Ведення журналів PowerShell ScriptBlock/Module

Останні версії Windows 10/11 та Windows Server зберігають **багаті слідчі артефакти PowerShell** під
`Microsoft-Windows-PowerShell/Operational` (події 4104/4105/4106).
Атакуючі можуть вимкнути або стерти їх на льоту:
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
Захисники повинні стежити за змінами в цих ключах реєстру та за великим обсягом видалення подій PowerShell.

### ETW (Event Tracing for Windows) Патч

Продукти безпеки кінцевих точок сильно покладаються на ETW. Популярний метод ухилення 2024 року полягає в патчуванні `ntdll!EtwEventWrite`/`EtwEventWriteFull` в пам'яті, щоб кожен виклик ETW повертав `STATUS_SUCCESS` без виведення події:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) реалізують ту ж саму примітиву в PowerShell або C++.  
Оскільки патч є **локальним для процесу**, EDR, що працюють в інших процесах, можуть його пропустити.  
Виявлення: порівняйте `ntdll` в пам'яті з диском або перехопіть перед режимом користувача.

### Відродження альтернативних потоків даних (ADS)

Кампанії шкідливого ПЗ у 2023 році (наприклад, **FIN12** завантажувачі) були помічені, коли другорядні бінарні файли розміщувалися всередині ADS, щоб залишитися поза увагою традиційних сканерів:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Перерахуйте потоки за допомогою `dir /R`, `Get-Item -Stream *` або Sysinternals `streams64.exe`. Копіювання файлу хоста на FAT/exFAT або через SMB видалить прихований потік і може бути використано слідчими для відновлення вантажу.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver тепер регулярно використовується для **антифорензіки** в атаках програм-вимагачів. Відкритий інструмент **AuKill** завантажує підписаний, але вразливий драйвер (`procexp152.sys`), щоб призупинити або завершити EDR та судово-слідчі датчики **перед шифруванням та знищенням журналів**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Драйвер видаляється після цього, залишаючи мінімальні артефакти.  
Заходи пом'якшення: увімкніть чорний список вразливих драйверів Microsoft (HVCI/SAC)  
та сповіщайте про створення служб ядра з шляхів, доступних для запису користувачем.

---

## Посилання

- Sophos X-Ops – “AuKill: Зброя для вразливого драйвера для відключення EDR” (березень 2023)  
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr  
- Red Canary – “Виправлення EtwEventWrite для прихованості: Виявлення та полювання” (червень 2024)  
https://redcanary.com/blog/etw-patching-detection  

{{#include ../../banners/hacktricks-training.md}}
