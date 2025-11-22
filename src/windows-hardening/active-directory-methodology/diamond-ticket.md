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
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (z opcjonalnymi `/ldapuser` & `/ldappassword`) pyta AD i SYSVOL, aby odzwierciedlić dane polityki PAC docelowego użytkownika.
- `/opsec` wymusza powtórkę AS-REQ w stylu Windows, zerując głośne flagi i trzymając się AES256.
- `/tgtdeleg` pozwala uniknąć dostępu do hasła w postaci jawnej lub klucza NTLM/AES ofiary, a jednocześnie zwraca odszyfrowywalny TGT.

### Ponowne tworzenie ticketów usługowych

Ten sam refresh Rubeus dodał możliwość zastosowania techniki diamond do TGS blobs. Przekazując `diamond` a **base64-encoded TGT** (z `asktgt`, `/tgtdeleg`, lub wcześniej sfałszowanego TGT), **service SPN**, oraz **service AES key**, możesz wygenerować realistyczne service tickets bez dotykania KDC — w praktyce daje to bardziej ukryty silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ten workflow jest idealny, gdy już kontrolujesz klucz konta usługi (np. zrzutowany za pomocą `lsadump::lsa /inject` lub `secretsdump.py`) i chcesz wygenerować jednorazowy TGS, który idealnie pasuje do polityki AD, przedziałów czasowych i danych PAC bez wysyłania żadnego nowego ruchu AS/TGS.

### Uwagi OPSEC i dotyczące wykrywania

- Tradycyjne heurystyki hunterów (TGS bez AS, dziesięcioletnie lifetimes) nadal mają zastosowanie do golden tickets, ale diamond tickets pojawiają się głównie wtedy, gdy **zawartość PAC lub mapowanie grup wygląda na niemożliwe**. Wypełnij każde pole PAC (logon hours, user profile paths, device IDs), aby automatyczne porównania nie oznaczyły fałszerstwa od razu.
- **Nie przypisuj grup/RID-ów nadmiernie**. Jeśli potrzebujesz tylko `512` (Domain Admins) i `519` (Enterprise Admins), ogranicz się do nich i upewnij się, że konto docelowe plausybilnie należy do tych grup gdzie indziej w AD. Nadmierne `ExtraSids` jest łatwo wykrywalne.
- Projekt Splunk Security Content udostępnia telemetrykę attack-range dla diamond tickets oraz wykrycia, takie jak *Windows Domain Admin Impersonation Indicator*, które korelują nietypowe sekwencje Event ID 4768/4769/4624 i zmiany grup w PAC. Odtworzenie tego zestawu danych (lub wygenerowanie własnego za pomocą powyższych poleceń) pomaga zweryfikować pokrycie SOC dla T1558.001, a także dostarcza konkretnej logiki alertów, którą można testować/omijać.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
