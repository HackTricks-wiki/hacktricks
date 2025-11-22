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

### Requisiti e flusso di lavoro

- **Materiale crittografico**: la chiave krbtgt AES256 (preferita) o l'hash NTLM per decifrare e ri-firmare il TGT.
- **Blob TGT legittimo**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u`, o esportando i ticket dalla memoria.
- **Dati di contesto**: il RID dell'utente target, i RID/SID dei gruppi e (opzionalmente) attributi PAC derivati da LDAP.
- **Service keys** (solo se prevedi di rigenerare service tickets): la chiave AES del servizio SPN da impersonare.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Tradecraft Rubeus aggiornato (2024+)

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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) interroga AD e SYSVOL per rispecchiare i dati della policy PAC dell'utente target.
- `/opsec` forza un tentativo AS-REQ in stile Windows, azzerando flag rumorosi e attenendosi ad AES256.
- `/tgtdeleg` evita di toccare la password in chiaro o la chiave NTLM/AES della vittima, restituendo comunque un TGT decrittabile.

### Ritaglio del service-ticket

Lo stesso refresh di Rubeus ha aggiunto la possibilità di applicare la tecnica diamond ai blob TGS. Fornendo a `diamond` un **base64-encoded TGT** (da `asktgt`, `/tgtdeleg`, o un TGT precedentemente forgiato), il **service SPN**, e la **service AES key**, puoi coniare service ticket realistici senza toccare il KDC — efficacemente un silver ticket più stealth.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Questo workflow è ideale quando si controlla già una service account key (es., dumpata con `lsadump::lsa /inject` o `secretsdump.py`) e si vuole creare un TGS ad hoc che corrisponda perfettamente alla policy AD, alle timeline e ai dati PAC senza generare nuovo traffico AS/TGS.

### Note OPSEC e di rilevamento

- Le euristiche tradizionali dei cacciatori (TGS senza AS, durate dell'ordine di un decennio) si applicano ancora ai golden tickets, ma i diamond tickets emergono principalmente quando il contenuto del PAC o la mappatura dei gruppi sembra impossibile. Popola ogni campo del PAC (orari di accesso, percorsi del profilo utente, ID del dispositivo) in modo che i confronti automatici non segnalino immediatamente la falsificazione.
- **Non sovra-assegnare gruppi/RID**. Se ti servono solo `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account target plausibilmente appartenga a quegli stessi gruppi in altre parti di AD. Eccessivi `ExtraSids` sono un indizio evidente.
- Il progetto Security Content di Splunk distribuisce telemetria di attack-range per diamond tickets oltre a rilevazioni come *Windows Domain Admin Impersonation Indicator*, che correla sequenze insolite di Event ID 4768/4769/4624 e cambiamenti nei gruppi PAC. Riprodurre quel dataset (o generarne uno proprio con i comandi sopra) aiuta a convalidare la copertura SOC per T1558.001 fornendoti al contempo logiche di allerta concrete da eludere.

## Riferimenti

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
