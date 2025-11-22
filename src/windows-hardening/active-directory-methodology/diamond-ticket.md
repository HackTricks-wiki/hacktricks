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

### Requisiti e workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u`, o esportando i ticket dalla memoria.
- **Dati di contesto**: il RID dell'utente target, RIDs/SIDs dei gruppi e (opzionalmente) attributi PAC derivati da LDAP.
- **Service keys** (solo se prevedi di re-cut service tickets): chiave AES del service SPN da impersonare.

1. Ottieni un TGT per qualsiasi utente controllato tramite AS-REQ (Rubeus `/tgtdeleg` è comodo perché costringe il client a eseguire il Kerberos GSS-API dance senza credenziali).
2. Decifra il TGT restituito con la chiave krbtgt, modifica gli attributi PAC (user, groups, logon info, SIDs, device claims, ecc.).
3. Ricrittografa/firma nuovamente il ticket con la stessa chiave krbtgt e iniettalo nella sessione di logon corrente (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Facoltativamente, ripeti il processo su un service ticket fornendo un blob TGT valido più la chiave del servizio target per rimanere stealthy on the wire.

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
- `/ldap` (con opzionali `/ldapuser` & `/ldappassword`) interroga AD e SYSVOL per replicare i dati della policy PAC dell'utente target.
- `/opsec` forza un ritentativo AS-REQ in stile Windows, azzerando flag rumorosi e utilizzando solo AES256.
- `/tgtdeleg` evita di toccare la password in chiaro o la chiave NTLM/AES della vittima pur restituendo un TGT decrittabile.

### Ritaglio dei service-ticket

Lo stesso aggiornamento di Rubeus ha aggiunto la possibilità di applicare la diamond technique ai TGS blobs. Alimentando `diamond` con un **base64-encoded TGT** (da `asktgt`, `/tgtdeleg` o un precedente forged TGT), il **service SPN**, e la **service AES key**, puoi coniare ticket di servizio realistici senza toccare il KDC — in pratica uno silver ticket più stealthy.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Questo workflow è ideale quando controlli già la chiave di un service account (es., ottenuta con `lsadump::lsa /inject` o `secretsdump.py`) e vuoi forgiare una TGS una tantum che corrisponda perfettamente alle policy AD, alle tempistiche e ai dati PAC senza generare nuovo traffico AS/TGS.

### OPSEC & note di rilevamento

- Le tradizionali hunter heuristics (TGS without AS, decade-long lifetimes) si applicano ancora ai golden tickets, ma i diamond tickets emergono soprattutto quando il **contenuto del PAC o il mapping dei gruppi appare impossibile**. Popola ogni campo del PAC (logon hours, user profile paths, device IDs) in modo che i confronti automatizzati non segnalino immediatamente la falsificazione.
- **Non sovraccaricare groups/RIDs**. Se ti servono solo `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account target appartenga plausibilmente a quei gruppi anche altrove in AD. `ExtraSids` eccessivi sono un indizio.
- Il progetto Splunk's Security Content distribuisce telemetria di attack-range per diamond tickets e rilevazioni come *Windows Domain Admin Impersonation Indicator*, che correla sequenze insolite di Event ID 4768/4769/4624 e cambiamenti dei gruppi nel PAC. Riprodurre quel dataset (o generarne uno proprio con i comandi sopra) aiuta a validare la copertura SOC per T1558.001 fornendoti logiche di allerta concrete da eludere.

## Riferimenti

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
