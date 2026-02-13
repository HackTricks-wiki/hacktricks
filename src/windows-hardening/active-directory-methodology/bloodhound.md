# BloodHound & その他の Active Directory Enumeration ツール

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: このページは Active Directory のリレーションシップを **enumerate** および **visualise** するための、最も有用なユーティリティをまとめたものです。ステルスな **Active Directory Web Services (ADWS)** チャネル経由での収集については上の参照を確認してください。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) は高度な **AD viewer & editor** で、以下を可能にします:

* GUI を使ったディレクトリツリーの閲覧
* オブジェクト属性 & セキュリティ記述子の編集
* オフライン分析のためのスナップショット作成 / 比較

### Quick usage

1. ツールを起動し、任意のドメイン資格情報で `dc01.corp.local` に接続します。
2. メニューから `File ➜ Create Snapshot` を選んでオフラインスナップショットを作成します。
3. 権限の変化を見つけるために、`File ➜ Compare` で2つのスナップショットを比較します。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) はドメインから多くのアーティファクト (ACLs, GPOs, trusts, CA templates …) を抽出し、**Excel report** を生成します。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (グラフ可視化)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) はグラフ理論 + Neo4j を使って on-prem AD & Azure AD 内の隠れた権限関係を明らかにします。

### 展開 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### コレクター

* `SharpHound.exe` / `Invoke-BloodHound` – ネイティブまたはPowerShell版
* `AzureHound` – Azure AD 列挙
* **SoaPy + BOFHound** – ADWS 収集 (上のリンク参照)

#### 一般的な SharpHound モード
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
コレクタはJSONを生成し、それがBloodHound GUIによって取り込まれます。

### 権限とログオン権利の収集

Windowsのtoken privileges（例：`SeBackupPrivilege`、`SeDebugPrivilege`、`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`）はDACLチェックをバイパスできるため、ドメイン全体でこれらをマッピングするとACLのみのグラフが見落とすローカルLPEエッジが明らかになります。Logon rights（`SeInteractiveLogonRight`、`SeRemoteInteractiveLogonRight`、`SeNetworkLogonRight`、`SeServiceLogonRight`、`SeBatchLogonRight`および対応する`SeDeny*`）はトークンが生成される前にLSAによって強制され、denyが優先されるため、横移動（RDP/SMB/スケジュールされたタスクやサービスのログオン）に実質的な制約を与えます。

可能ならコレクタは昇格して実行してください：UACは対話型管理者に対してフィルタされたトークンを作成し（`NtFilterToken`経由）、敏感な特権を削ぎ、管理者SIDをdeny-onlyとしてマークします。非昇格シェルから特権を列挙すると、高価値の特権が見えず、BloodHoundはそれらのエッジを取り込みません。

現在、SharpHoundには2つの補完的な収集戦略があります:

- **GPO/SYSVOL parsing (ステルス, 低権限):**
1. LDAP経由でGPOを列挙し（`(objectCategory=groupPolicyContainer)`）、各`gPCFileSysPath`を読みます。
2. SYSVOLから`MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`を取得し、privilege/logon-right名をSIDにマップする`[Privilege Rights]`セクションを解析します。
3. OU/サイト/ドメイン上の`gPLink`でGPOリンクを解決し、リンク先コンテナ内のコンピュータを列挙して、そのホストに権利を帰属させます。
4. 利点：通常のユーザで動作し静か。欠点：GPO経由で配布された権利のみを検出し、ローカルの調整は見逃されます。

- **LSA RPC enumeration (ノイジー, 正確):**
- 対象でローカル管理者権限を持つコンテキストからローカルセキュリティポリシーを開き、各privilege/logon rightについて`LsaEnumerateAccountsWithUserRight`を呼び出して、RPC経由で割り当てられた主体を列挙します。
- 利点：ローカルやGPO外で設定された権利も取得可能。欠点：ネットワークトラフィックが目立ち、各ホストで管理者権限が必要。

これらのエッジで明らかになる悪用パスの例：`CanRDP` ➜ あなたのユーザが`SeBackupPrivilege`も持っているホスト ➜ フィルタされたトークンを避けるために昇格シェルを起動 ➜ バックアップのセマンティクスを使って厳しいDACLにもかかわらず`SAM`と`SYSTEM`ハイブを読み出す ➜ exfiltrateして`secretsdump.py`をオフラインで実行し、ローカルAdministratorのNTハッシュを回収して横移動/特権昇格に利用する。

### BloodHoundでのKerberoastingの優先化

グラフのコンテキストを利用してKerberoastingの対象を絞り込みます:

1. ADWS互換のコレクタで一度収集し、オフラインで作業する:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIPをインポートし、侵害した主体をownedとしてマーク、組み込みクエリ（*Kerberoastable Users*、*Shortest Paths to Domain Admins*）を実行して管理者/インフラ権限を持つSPNアカウントを抽出します。
3. SPNはblast radius（影響範囲）で優先順位付けし、クラック前に`pwdLastSet`、`lastLogon`、および許可されている暗号化タイプを確認します。
4. 選択したチケットだけを要求してオフラインでクラックし、新しいアクセスでBloodHoundを再クエリします:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r)は**Group Policy Objects**を列挙し、誤設定をハイライトします。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) は Active Directory の**ヘルスチェック**を行い、リスク評価付きの HTML レポートを生成します。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 参考文献

- [HackTheBox Mirage: NFS Leaksの連鎖、Dynamic DNS Abuse、NATS Credential Theft、JetStream Secrets、および Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: BloodHound を使った Windows Privilege Escalation Paths のマッピング](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
