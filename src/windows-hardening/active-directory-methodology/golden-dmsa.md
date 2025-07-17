# Golden gMSA/dMSA (KDS Root Key Authentication Bypass)

{{#include ../../banners/hacktricks-training.md}}

## Overview

A **Golden dMSA / Golden gMSA** attack allows an adversary that has obtained the **KDS root key** of an Active Directory forest to **derive the current (and future) passwords** of every **group Managed Service Account (gMSA)** and the brand-new **delegated Managed Service Account (dMSA)** completely **offline**.

Because Windows only uses two 5-bit time indexes (``L1Index`` & ``L2Index``) when creating each account’s ``msDS-ManagedPasswordId`` value, the attacker only needs to test **1 024 possible vectors** per account to recover its password.  Once the clear-text password is known it can be converted to **NTLM** or **AES-256** Kerberos keys and abused with Pass-the-Hash, Over-Pass-the-Hash or forged tickets – bypassing protections such as **Credential Guard** and any ACLs that block reading the accounts in LDAP.

> [!TIP]
> This technique is the service-account equivalent to a **Golden Ticket**, but it works **without touching Kerberos on a Domain Controller** after the initial key dump.

---

## 1.  Dump the KDS root key

The **KDS root key** never expires and is replicated to every Domain Controller.  SYSTEM or Enterprise-Admin rights on **any** DC are enough to retrieve it:

```powershell
# PowerShell (run as SYSTEM / EA)
Import-Module ActiveDirectory
Get-ADObject -SearchBase 'CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=corp,DC=local' \
  -LDAPFilter '(objectClass=msKds-ProvRootKey)' -Properties msKds-RootKeyData |
  Select-Object Name,msKds-RootKeyData
```

```bash
# Offline – NTDS.dit + SYSTEM hive
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```

Save the **Base64** value of ``msKds-RootKeyData`` – that is the master key the KDC uses for every (d)MSA.

---

## 2.  Enumerate service accounts without LDAP rights

Default ACLs completely hide **dMSA** objects.  Two practical approaches exist:

1. **SID brute-force + LSA RPC** – identical to Impacket’s ``lookupsid.py``
```c
// LSA RPC pseudo-code
LsaOpenPolicy(NULL, POLICY_LOOKUP_NAMES, &hPolicy);
LsaLookupSids(hPolicy, count, sidArray, &domainList, &nameList);
```
   • Filter returned names that **end with “$”**.
   • Exclude computer accounts (``<hostname>$``) and any ``...$`` that already have an ``msDS-GroupMSAMembership`` attribute (=> gMSA) → the rest are **dMSAs**.

2. **Direct LDAP search** against the **CN=DelegatedManagedServiceAccounts** container (if readable) and then combine the results with technique 1 to obtain the SID.

These methods work **across trust boundaries**, so compromising one domain is enough to inventory the entire forest.

---

## 3.  Rebuild the ``ManagedPasswordId`` vector

A ``msDS-ManagedPasswordId`` blob contains:
* Version, reserved, ``isPublicKey`` (constant)
* **``L0Index``**, **``L1Index``**, **``L2Index``** – three time based counters
* ``RootKeyIdentifier`` – GUID of the KDS root key
* Encoded domain & forest names

Reverse engineering ``KdsCli.dll`` shows that **only ``L1Index`` & ``L2Index`` are consumed** by ``GetKey()`` and each is limited to **0-31**.

That means: ``32 × 32 = 1 024`` possible combinations per account.

---

## 4.  Offline brute-force & password extraction

For every candidate ``(L1,L2)`` pair:
1. Build a fake ``ManagedPasswordId`` (any ``L0Index`` is accepted).
2. Call the same KDS provider routines used by Windows:
   ``GetgMSAPasswordBlob() → GetPasswordBasedOnTimestamp() → GetKey()``
3. Validate the returned blob; on success extract the **current password**.

The procedure is automated by the open-source **[GoldenDMSA](https://github.com/Semperis/GoldenDMSA)** tool:
```bash
python goldenDMSA.py dumpkds ‑-dc 192.168.100.10         # phase 1
python goldenDMSA.py enum ‑-domain corp.local             # phase 2
python goldenDMSA.py bruteforce ‑-sid S-1-5-21-…-1234-1105 # phases 3-4
```

### Converting to hashes / tickets

* **NTLM**: ``md4(UNICODE(PASSWORD))``
* **AES-256** (recommended by dMSA): use the salt
  ``<DOMAIN_UPPER>host<UPN_without_$>``

```bash
python getTGT.py -aes256 <hash> -user dmsa-demo$ -dc 192.168.100.10
```

The resulting **TGT / service ticket** can be injected with **Rubeus** or **klist** exactly like any other Kerberos credential.

---

## 5.  Impact

•  Immediate **lateral movement** as any service account across the forest.
•  **Persistent backdoor** – the KDS root key never rotates by default, so future (d)MSAs are compromised automatically.
•  Bypasses **Credential Guard** because authentication happens fully offline.

---

## Detection & Mitigation

1. **Audit reads of the KDS root key**: add a **SACL** on the object to trigger Event **4662** (``msDS-ProvRootKey``) whenever ``msKds-RootKeyData`` is read.
2. Monitor abnormal volumes of **AS-REQ / PREAUTH_FAILED (24)** for accounts ending in ``$``.
3. Watch for unusual TGT requests for service accounts originating from user workstations.
4. **Rotate / add a new KDS root key** after a domain-wide compromise.

Defenders can also use Semperis **Directory Services Protector – “KDS root key ACL modified”** indicator.

---

## Tools

* [GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
* [GoldenGMSA](https://github.com/Semperis/GoldenGMSA) – original gMSA PoC
* [Impacket lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)

---

## References

- [Semperis – Golden dMSA: What Is dMSA Authentication Bypass?](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [GoldenDMSA GitHub](https://github.com/Semperis/GoldenDMSA)
- [Microsoft – msKds-ProvRootKey documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)

{{#include ../../banners/hacktricks-training.md}}