# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **pristupiti bilo kojoj usluzi kao bilo koji korisnik**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Potražite TGS-REQs koji nemaju odgovarajući AS-REQ.
- Potražite TGTs koji imaju neprirodne vrednosti, kao što je podrazumevano Mimikatz-ovo 10-godišnje vreme trajanja.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Requirements & workflow

- **Kriptografski materijal**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Kontekstni podaci**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
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
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (sa opcionim `/ldapuser` & `/ldappassword`) vrši upit nad AD i SYSVOL kako bi preslikao PAC policy podatke ciljnog korisnika.
- `/opsec` prisiljava Windows-like AS-REQ retry, resetujući bučne zastavice i držeći se AES256.
- `/tgtdeleg` drži vas podalje od lozinke u cleartextu ili NTLM/AES ključa žrtve, a ipak vraća dešifrovatljiv TGT.

### Service-ticket recutting

Isto ažuriranje Rubeus-a dodalo je mogućnost primene diamond tehnike na TGS blobove. Dajući `diamond` a **base64-encoded TGT** (iz `asktgt`, `/tgtdeleg`, ili prethodno falsifikovanog TGT), **service SPN**, i **service AES key**, možete izraditi realistične service tickets bez diranja KDC-a—efektivno diskretniji silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### OPSEC & napomene za detekciju

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **PAC content or group mapping looks impossible**. Popunite svako PAC polje (logon hours, user profile paths, device IDs) tako da automatska poređenja ne označe falsifikat odmah.
- **Do not oversubscribe groups/RIDs**. Ako su vam potrebni samo `512` (Domain Admins) i `519` (Enterprise Admins), završite na tome i proverite da ciljnom nalogu verovatno pripadaju te grupe negde drugde u AD. Prekomerni `ExtraSids` lako otkrivaju forgeriju.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Reprodukcija tog dataset-a (ili generisanje sopstvenog pomoću komandi iznad) pomaže da se validira SOC coverage za T1558.001 i pruža konkretnu logiku alert-a koju treba izbeći.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
