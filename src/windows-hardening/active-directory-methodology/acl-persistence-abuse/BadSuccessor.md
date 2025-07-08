# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSAs**) are a brand‑new AD principal type introduced with **Windows Server 2025**. They are designed to replace legacy service accounts by allowing a one‑click “migration” that automatically copies the old account’s Service Principal Names (SPNs), group memberships, delegation settings, and even cryptographic keys into the new dMSA, giving applications a seamless cut‑over and eliminating Kerberoasting risk.

Akamai researchers found that a single attribute — **`msDS‑ManagedAccountPrecededByLink`** — tells the KDC which legacy account a dMSA “succeeds”. If an attacker can write that attribute (and toggle **`msDS‑DelegatedMSAState` → 2**), the KDC will happily build a PAC that **inherits every SID of the chosen victim**, effectively allowing the dMSA to impersonate any user, including Domain Admins. 

## What exactly is a dMSA?

* Built on top of **gMSA** technology but stored as the new AD class **`msDS‑DelegatedManagedServiceAccount`**.  
* Supports an **opt‑in migration**: calling `Start‑ADServiceAccountMigration` links the dMSA to the legacy account, grants the legacy account write access to `msDS‑GroupMSAMembership`, and flips `msDS‑DelegatedMSAState` = 1.  
* After `Complete‑ADServiceAccountMigration`, the superseded account is disabled and the dMSA becomes fully functional; any host that previously used the legacy account is automatically authorised to pull the dMSA’s password.  
* During authentication, the KDC embeds a **KERB‑SUPERSEDED‑BY‑USER** hint so Windows 11/24H2 clients transparently retry with the dMSA.


## Requirements to attack
1. **At least one Windows Server 2025 DC** so that the dMSA LDAP class and KDC logic exist.  
2. **Any object‑creation or attribute‑write rights on an OU** (any OU) – e.g. `Create msDS‑DelegatedManagedServiceAccount` or simply **Create All Child Objects**. Akamai found 91 % of real‑world tenants grant such “benign” OU permissions to non‑admins.  
3. Ability to run tooling (PowerShell/Rubeus) from any domain‑joined host to request Kerberos tickets.  
*No control over the victim user is required; the attack never touches the target account directly.*

## Step‑by‑step: BadSuccessor*privilege escalation

1. **Locate or create a dMSA you control**  
   ```bash
   New‑ADServiceAccount Attacker_dMSA `
       ‑DNSHostName ad.lab `
       ‑Path "OU=temp,DC=lab,DC=local"
    ```

Because you created the object inside an OU you can write to, you automatically own all its attributes .

2. **Simulate a “completed migration” in two LDAP writes**:
    - Set `msDS‑ManagedAccountPrecededByLink = DN` of any victim (e.g. `CN=Administrator,CN=Users,DC=lab,DC=local`).
    - Set `msDS‑DelegatedMSAState = 2` (migration‑completed).

Tools like **Set‑ADComputer, ldapmodify**, or even **ADSI Edit** work; no domain‑admin rights are needed.

3. **Request a TGT for the dMSA** — Rubeus supports the `/dmsa` flag:

    ```bash
    Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
    ```

The returned PAC now contains the SID 500 (Administrator) plus Domain Admins/Enterprise Admins groups.

## Gather all the users passwords

During legitimate migrations the KDC must let the new dMSA decrypt **tickets issued to the old account before cut‑over**. To avoid breaking live sessions it places both current‑keys and previous‑keys inside a new ASN.1 blob called **`KERB‑DMSA‑KEY‑PACKAGE`**.

Because our fake migration claims the dMSA succeeds the victim, the KDC dutifully copies the victim’s RC4‑HMAC key into the **previous‑keys** list – even if the dMSA never had a “previous” password. That RC4 key is unsalted, so it is effectively the victim’s NT hash, giving the attacker **offline cracking or “pass‑the‑hash”** capability.

Therefore, mass‑linking thousands of users lets an attacker dump hashes “at scale,” turning **BadSuccessor into both a privilege‑escalation and credential‑compromise primitive**.

## Tools

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## References

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)


{{#include ../../../banners/hacktricks-training.md}}
