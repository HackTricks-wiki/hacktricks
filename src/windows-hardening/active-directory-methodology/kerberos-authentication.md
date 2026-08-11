# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

For a protocol-level walkthrough of the exchanges summarized below, see Tarlogic's Kerberos article.<sup>[[3]](#references)</sup>

## TL;DR for attackers
- Kerberos is the default AD auth protocol; most lateral-movement chains will touch it.
- Think in **three operator phases**:<sup>[[3]](#references)</sup>
  - **AS-REQ / AS-REP** → password/hash/certificate to obtain a **TGT**. This is where **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, and **PKINIT** live.
  - **TGS-REQ / TGS-REP** → use a TGT to obtain **service tickets**. This is where **Kerberoasting**, **S4U abuse**, **delegation abuse**, and most **ticket-forging tradecraft** become relevant.
  - **AP-REQ / AP-REP** → present the ticket to the service. This is where **pass-the-ticket** and service-specific lateral movement happen.
- For hands-on cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.) see:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Use this page as the **overview / “what changed recently”** index, then jump to the dedicated pages for [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), or [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening changed the defaults, not Kerberos itself** – modern DC hardening focuses on the **default assumed encryption types** for accounts that do **not** explicitly set `msDS-SupportedEncryptionTypes`. After the 2026 rollout, those accounts increasingly default to **AES-only** on patched DCs, so blind `/rc4` Kerberoast assumptions fail more often. However, **explicitly RC4-enabled service accounts remain excellent offline-crack targets**.<sup>[[1]](#references)</sup>
- **PAC validation enforcement matters for forged tickets** – 2024 PAC-signature hardening means that **golden/diamond/sapphire/extraSID-style abuses** need more realistic PAC data and the correct signing context. Unpatched domains or domains left in compatibility/audit-style deployments stay softer targets.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos changed twice**:
  - **Strong certificate binding** (KB5014754 timeline) makes sloppy certificate-to-account mappings less reliable in fully enforced environments.
  - **CVE-2025-26647** added another hardening layer around `altSecurityIdentities` mappings that use a certificate's Subject Key Identifier. Patch level, enforcement or audit state, and explicit mapping configuration therefore matter when evaluating pass-the-certificate and related certificate-based paths.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> For PKINIT, the KDC also validates the certificate path and checks that the issuer is trusted through the NTAuth store.<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuse is still very alive** – Windows supports modern cross-realm **S4U2Self/S4U2Proxy** flows, so writable delegation attributes in another domain are still valuable. The blocker is usually tooling fidelity and trust/policy details, not protocol support.
- **Recursive multi-domain RBCD matters operationally** – in 3+ domain forests, **S4U2Self/S4U2Proxy** can recurse through trust referrals, and **SPN-less** abuse may require a final **`S4U2Self+U2U`** hop plus RC4-dependent ticket handling. See [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 introduced delegated Managed Service Accounts (dMSAs)** and their migration logic. If you see delegated rights over OUs or service-account objects in a 2025 domain, check the dedicated [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) instead of treating it like “just another gMSA”.<sup>[[7]](#references)</sup>

## Fast operator checks in modern domains

Before choosing a Kerberos attack path, quickly answer four questions:

1. **Which accounts are still RC4-friendly?**
2. **Which users do not require pre-auth?**
3. **Which objects expose delegation abuse?**
4. **Which parts of the domain are new enough to enforce recent hardening?**

```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
  -Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
  -Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
  -Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
  -Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
  $_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```

Practical interpretation:
- If **interesting SPN accounts are explicitly RC4-capable**, Kerberoasting stays cheap and fast.
- If most service accounts have **no explicit etype configuration**, expect **AES-only** behavior on updated 2026 DCs and plan for slower offline cracking or a different path.
- If **RBCD / KCD / unconstrained delegation** is present, S4U often beats brute-force.
- If **certificate auth** is in play, remember that a failed PKINIT path does **not** always mean the cert is useless; in many environments the same cert still works for **Schannel/LDAPS** abuse (see [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → The target account / DC will not use the encryption type you asked for. Stop retrying with RC4 only; supply **AES keys** or request **AES** roast material instead.
- **`KRB_AP_ERR_MODIFIED`** → You likely have the **wrong service key**, the **wrong SPN**, or a forged ticket that does not match the service account actually decrypting it.
- **`KRB_AP_ERR_SKEW`** → Your time is off. Sync to the DC before debugging anything else.
- **`KDC_ERR_BADOPTION`** during S4U / delegation flows → frequently means **sensitive/not-delegable users**, the wrong delegation model, or that you are trying to do **classic KCD** where only **RBCD** would accept a non-forwardable S4U2Self ticket.

## References
- [1] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - KB5014754 certificate-based authentication changes](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Kerberos certificate mapping vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Smart-card certificate requirements and KDC validation](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)

{{#include ../../banners/hacktricks-training.md}}
