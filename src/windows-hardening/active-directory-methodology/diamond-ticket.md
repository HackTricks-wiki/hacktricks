# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (with optional `/ldapuser` & `/ldappassword`) queries AD and SYSVOL to mirror the target user's PAC policy data.
- `/opsec` forces a Windows-like AS-REQ retry, zeroing noisy flags and sticking to AES256.
- `/tgtdeleg` keeps your hands off the cleartext password or NTLM/AES key of the victim while still returning a decryptable TGT.

### Service-ticket recutting

The same Rubeus refresh added the ability to apply the diamond technique to TGS blobs. By feeding `diamond` a **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**, you can mint realistic service tickets without touching the KDC—effectively a stealthier silver ticket.

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combines Diamond's "real TGT" base with **S4U2self+U2U** to steal a privileged PAC and drop it into your own TGT. Instead of inventing extra SIDs, you request a U2U S4U2self ticket for a high-privilege user, extract that PAC, and splice it into your legitimate TGT before re-signing with the krbtgt key. Because U2U sets `ENC-TKT-IN-SKEY`, the resulting wire flow looks like a legitimate user-to-user exchange.

Minimal Linux-side reproduction with Impacket's patched `ticketer.py` (adds sapphire support):

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
  --u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & detection notes

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **PAC content or group mapping looks impossible**. Populate every PAC field (logon hours, user profile paths, device IDs) so automated comparisons do not immediately flag the forgery.
- **Do not oversubscribe groups/RIDs**. If you only need `512` (Domain Admins) and `519` (Enterprise Admins), stop there and make sure the target account plausibly belongs to those groups elsewhere in AD. Excessive `ExtraSids` is a giveaway.
- Sapphire-style swaps leave U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` in 4769, and a follow-up 4624 logon sourced from the forged ticket. Correlate those fields instead of only looking for no-AS-REQ gaps.
- Microsoft started phasing out **RC4 service ticket issuance** because of CVE-2026-20833; enforcing AES-only etypes on the KDC both hardens the domain and aligns with diamond/sapphire tooling (/opsec already forces AES). Mixing RC4 into forged PACs will increasingly stick out.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Replaying that dataset (or generating your own with the commands above) helps validate SOC coverage for T1558.001 while giving you concrete alert logic to evade.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
