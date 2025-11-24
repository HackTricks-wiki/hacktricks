# BloodHound & その他の Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> 注: このページは Active Directory の関係を **enumerate** および **visualise** する最も有用なユーティリティをまとめたものです。 隠密な **Active Directory Web Services (ADWS)** チャネル経由での収集については上の参照を確認してください。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) は高度な **AD viewer & editor** で、次のことを行えます:

* ディレクトリツリーの GUI ブラウズ
* オブジェクト属性および security descriptors の編集
* オフライン解析用の Snapshot 作成 / 比較

### Quick usage

1. ツールを起動し、任意のドメイン資格情報で `dc01.corp.local` に接続します。
2. `File ➜ Create Snapshot` でオフラインスナップショットを作成します。
3. `File ➜ Compare` で 2 つのスナップショットを比較し、権限の変化を見つけます。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) はドメインから多数のアーティファクト（ACLs、GPOs、trusts、CA templates …）を抽出し、**Excel report** を生成します。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (グラフ可視化)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) はグラフ理論と Neo4j を利用して、on-prem AD および Azure AD 内の隠れた特権関係を明らかにします。

### 展開 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 収集ツール

* `SharpHound.exe` / `Invoke-BloodHound` – ネイティブまたはPowerShell版
* `AzureHound` – Azure AD 列挙
* **SoaPy + BOFHound** – ADWS 収集 (上のリンク参照)

#### 一般的な SharpHound モード
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
コレクタはJSONを生成し、それがBloodHound GUIを介して取り込まれます。

---

## BloodHound での Kerberoasting の優先順位付け

Graph のコンテキストは、ノイズの多い無差別な roasting を避けるために重要です。軽量なワークフロー:

1. **一度だけすべてを収集する** ADWS-compatible collector (e.g. RustHound-CE) を使用して、オフラインで作業し、再度 DC に触れることなく経路を検証できるようにする:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **ZIPをインポートし、侵害されたプリンシパルを所有済みとしてマーク**したら、組み込みクエリ（例: *Kerberoastable Users*、*Shortest Paths to Domain Admins*）を実行します。これにより、Exchange、IT、tier0 service accountsなどの有用なグループメンバーシップを持つSPN保有アカウントが即座に強調表示されます。
3. **被害範囲（blast radius）で優先順位を付ける** – 共有インフラを制御しているか管理権限を持つSPNに注力し、クラック作業に取り掛かる前に `pwdLastSet`、`lastLogon`、および許可されている暗号化タイプを確認します。
4. **必要なチケットのみを要求する**。NetExecのようなツールは選択した `sAMAccountName`s をターゲットにできるため、各LDAP ROAST request に明確な正当化を持たせることができます:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, その後すぐに BloodHound に再照会して、新しい権限で post-exploitation を計画します。

この方法は信号対雑音比を高く維持し、検知されるトラフィック量を減らします（大量の SPN リクエストは行いません）。また、すべての cracked ticket が意味のある privilege escalation の手順につながることを保証します。

## Group3r

[Group3r](https://github.com/Group3r/Group3r) は **Group Policy Objects** を列挙し、誤設定を強調します。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) は Active Directory の**ヘルスチェック**を実行し、リスクスコアを付けた HTML レポートを生成します。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 参考文献

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
