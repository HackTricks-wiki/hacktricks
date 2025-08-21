# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: このページでは、Active Directoryの関係を**列挙**し、**視覚化**するための最も便利なユーティリティのいくつかをまとめています。 ステルスの**Active Directory Web Services (ADWS)** チャネルを介した収集については、上記のリファレンスを確認してください。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) は、高度な**ADビューワーおよびエディター**で、以下を可能にします：

* ディレクトリツリーのGUIブラウジング
* オブジェクト属性およびセキュリティ記述子の編集
* オフライン分析のためのスナップショット作成/比較

### Quick usage

1. ツールを起動し、任意のドメイン資格情報で `dc01.corp.local` に接続します。
2. `File ➜ Create Snapshot` を介してオフラインスナップショットを作成します。
3. `File ➜ Compare` を使用して2つのスナップショットを比較し、権限の変化を特定します。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) は、ドメインから大量のアーティファクト（ACL、GPO、信頼関係、CAテンプレートなど）を抽出し、**Excelレポート**を生成します。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (グラフ視覚化)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) は、グラフ理論 + Neo4j を使用して、オンプレミスの AD および Azure AD 内の隠れた特権関係を明らかにします。

### デプロイメント (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### コレクター

* `SharpHound.exe` / `Invoke-BloodHound` – ネイティブまたはPowerShellバリアント
* `AzureHound` – Azure AD列挙
* **SoaPy + BOFHound** – ADWSコレクション（リンクは上部を参照）

#### 一般的なSharpHoundモード
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
コレクターはJSONを生成し、BloodHound GUIを介して取り込まれます。

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) は **Group Policy Objects** を列挙し、誤設定を強調表示します。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) は、Active Directory の **ヘルスチェック** を実行し、リスクスコアを含む HTML レポートを生成します。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
