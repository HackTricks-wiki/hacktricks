# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Managed Service Accounts are domain principals intended to run services without an administrator handling a long-lived password:

1. **gMSA** (group Managed Service Account) can be used by the computers authorised through `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) was introduced in **Windows Server 2025**. It binds normal authentication to authorised machine identities and can replace a legacy service account through a migration workflow.

Do not confuse **Golden dMSA** with **BadSuccessor**. Golden dMSA requires compromise of KDS root-key material and derives managed-account keys; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) instead abuses control of a dMSA object and its migration attributes.

A DC does not store an independently generated clear-text password for every gMSA. It derives the account password from a **KDS root key**, a time-indexed Group Key Distribution Protocol (GKDI) key, and the account SID. The root-key objects are `msKds-ProvRootKey` objects below `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; the sensitive value is `msKds-RootKeyData`. `msDS-ManagedPasswordId` is **not a GUID**: it is a binary key identifier containing the KDS root-key GUID, the GKDI `L0`/`L1`/`L2` indexes, and domain/forest metadata. The DC applies the KDF with the label `GMSA PASSWORD` and the binary SID as context, then exposes an `MSDS-MANAGEDPASSWORD_BLOB` only to principals authorised to retrieve a gMSA password.<sup>[[2]](#references)</sup>

A dMSA normally differs operationally: its secret is meant to remain on the DC and the KDC issues credentials to an authorised machine. However, dMSAs reuse the underlying KDS/GKDI password derivation. Golden dMSA reconstructs that secret directly and therefore bypasses the intended machine-bound flow and Credential Guard on the service host.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

After extracting a KDS root key, an attacker can derive passwords for accounts tied to that key without reading `msDS-ManagedPassword`. This bypasses the per-account password-retrieval ACL and survives ordinary managed-password rotations while the compromised root key remains in use. For gMSAs, the readable `msDS-ManagedPasswordId` normally supplies the exact key identifier. For ACL-restricted dMSAs, Golden dMSA reduces the missing identifier to only **1,024 candidates**.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

* The relevant KDS root-key object, usually obtained with Enterprise Admin / forest-root Domain Admin rights, `SYSTEM` on a DC, or from an exposed DC database or backup.<sup>[[1]](#references)[[2]](#references)</sup>
* The target account's SID, DNS domain, forest name, and `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* For direct gMSA computation, its base64-encoded `msDS-ManagedPasswordId`; for Golden dMSA this can instead be guessed.<sup>[[1]](#references)[[2]](#references)</sup>
* An x64 Windows host with .NET Framework 4.7.2 for [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Phase 1 - Extract the KDS root key

`GoldenDMSA` and [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) export the root-key object fields as a base64 blob. Without a domain argument, the tools query the forest root and require suitable privileged directory access. With the domain/forest argument, `SYSTEM` on a DC can query that DC's local Configuration naming-context replica.<sup>[[1]](#references)[[2]](#references)</sup>

```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```

Record both the root-key GUID and the base64 root-key blob. A registry `SECURITY`/`SYSTEM` hive export is not by itself the KDS root key: the authoritative material is in the AD Configuration partition.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - Enumerate gMSA / dMSA objects

For gMSAs, obtain `sAMAccountName`, `objectSid`, and the binary `msDS-ManagedPasswordId`. The latter is normally readable even when the caller is not allowed to retrieve `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>

```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
    Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```

A dMSA's default ACL can prevent low-privileged LDAP enumeration. `GoldenDMSA info` can either query LDAP or enumerate candidate RIDs and resolve SIDs through `LsaLookupSids` over `\PIPE\lsarpc`, then distinguish dMSAs from computer accounts and gMSAs.<sup>[[1]](#references)[[3]](#references)</sup>

```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```

### Phase 3 - Reconstruct or guess `msDS-ManagedPasswordId`

The key identifier includes `L0Index`, `L1Index`, and `L2Index`, not an account-creation timestamp followed by random bits. Semperis found that the password-generation path does not consume the candidate `L0Index`, while `L1Index` and `L2Index` are each limited to values `0..31`. Consequently, an attacker who knows the root-key GUID, domain, forest, and SID can construct all `32 * 32 = 1,024` candidate identifiers.<sup>[[1]](#references)</sup>

```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```

The derivations are offline, but identifying the live candidate usually requires authentication attempts. This can produce a burst of failed Kerberos pre-authentication or NTLM validation before the valid key is found. For AES Kerberos keys, the managed-account salt used by the tool is `UPPERCASE.DNS.DOMAIN` + `host` + the lower-case account UPN without the trailing `$` (for example, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Phase 4 - Compute and use the password

If the exact identifier is known, compute the 256-byte password buffer and convert it to NTLM/AES material. The base64 value printed by these tools is the encoded password buffer, **not** the LDAP `MSDS-MANAGEDPASSWORD_BLOB` itself.<sup>[[2]](#references)[[3]](#references)</sup>

```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```

The NTLM result can be used where NTLM is accepted; the AES key can be used for overpass-the-hash / TGT requests where the managed account is AES-only. This gives the privileges, SPNs, delegation configuration, and resource access of the compromised managed service account without adding the attacker's machine to `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Cross-domain Configuration-partition abuse

KDS root-key objects live in the forest Configuration naming context, which is replicated to DCs in child domains. Consequently, `SYSTEM` on a child-domain DC can read the forest-root KDS material from the child DC's local replica, even though child Domain Admins cannot read the object from a forest-root DC directly. If the attacker can also read a parent-domain gMSA's `msDS-ManagedPasswordId`, GoldenGMSA can calculate that parent account's password; SID filtering does not prevent this cryptographic attack.<sup>[[5]](#references)</sup>

```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```

## Detection, Containment and Recovery

* Configure a SACL on the **Master Root Keys** container, inherited by `msKds-ProvRootKey` objects, for successful reads of `msKds-RootKeyData`. With Directory Service Access auditing enabled, an online extraction produces Security event **4662**; investigate subjects that are not expected DCs or Tier-0 operators. Also audit changes to these SACLs and root-key object ACLs.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* A child-to-parent attack reads the KDS object from the compromised child DC's local replica, so the forest-root domain might not observe that read. In the parent domain, audit successful reads of `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) on `msDS-GroupManagedServiceAccount` objects and investigate reads by principals from another domain.<sup>[[5]](#references)</sup>
* Correlate KDS-object access with unusual logons by managed accounts and bursts of Kerberos/NTLM failures for `$`-suffixed service accounts. Offline computation after prior database/backup theft is not visible to a live DC.<sup>[[1]](#references)[[3]](#references)</sup>
* Ordinary password rotation is not sufficient after root-key exposure. Microsoft's current recovery procedure creates a new KDS root key, restarts KDS on all relevant DCs, and moves affected accounts to that key. If the exposure scope/time is unknown and waiting for a safe roll is unacceptable, replace every gMSA that used the compromised key; if the scope is known, Microsoft documents an authoritative-restore workflow to force safe rolling. Validate the new key GUID in `msDS-ManagedPasswordId` before deleting the old key.<sup>[[4]](#references)</sup>
* Treat DC database and backup access, Configuration-partition replication, and KDS root-key administration as Tier-0. Reducing `ManagedPasswordIntervalInDays` limits some recovery windows but does not revoke an already compromised root key.<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration, identifier generation, 1,024-candidate validation, password computation, and NTLM/AES conversion.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration and online, offline, and cross-domain password computation.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) and [`Impacket`](https://github.com/fortra/impacket) - use or validate the derived NTLM/AES keys in authorised testing.



## References

- [1] [Golden dMSA - authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - How to recover from a Golden gMSA attack](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter as security boundary between domains? Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
