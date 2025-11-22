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

### Anforderungen & Ablauf

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Aktualisierte Rubeus tradecraft (2024+)

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
- `/ldap` (mit optionalen `/ldapuser` & `/ldappassword`) fragt AD und SYSVOL ab, um die PAC policy data des Zielbenutzers zu spiegeln.
- `/opsec` erzwingt einen Windows-ähnlichen AS-REQ-Neuversuch, setzt noisy flags auf null und beschränkt sich auf AES256.
- `/tgtdeleg` vermeidet Zugriff auf das cleartext password oder den NTLM/AES key des Opfers, liefert dabei trotzdem ein decryptable TGT.

### Service-ticket-Neuzuschnitt

Das gleiche Rubeus-Refresh fügte die Möglichkeit hinzu, die diamond technique auf TGS blobs anzuwenden. Indem man `diamond` eine **base64-encoded TGT** (aus `asktgt`, `/tgtdeleg` oder einem zuvor gefälschten TGT), den **service SPN** und den **service AES key** zufüttert, kann man realistische Service-Tickets erzeugen, ohne den KDC zu berühren — effektiv ein unauffälligeres silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Dieser Workflow ist ideal, wenn Sie bereits einen service account key kontrollieren (z. B. gedumpt mit `lsadump::lsa /inject` oder `secretsdump.py`) und ein einmaliges TGS erstellen möchten, das AD-Richtlinie, Zeitfenster und PAC-Daten perfekt erfüllt, ohne neuen AS/TGS-Verkehr zu erzeugen.

### OPSEC & Erkennungsnotizen

- Die traditionellen Hunter-Heuristiken (TGS ohne AS, jahrzehntelange Lebensdauern) gelten weiterhin für golden tickets, aber diamond tickets treten hauptsächlich zutage, wenn der **PAC-Inhalt oder die Gruppenabbildung unmöglich erscheint**. Füllen Sie jedes PAC-Feld aus (Anmeldezeiten, Benutzerprofilpfade, Geräte-IDs), damit automatisierte Vergleiche die Fälschung nicht sofort markieren.
- **Gruppen/RIDs nicht übermäßig zuweisen**. Wenn Sie nur `512` (Domain Admins) und `519` (Enterprise Admins) benötigen, belassen Sie es dabei und stellen Sie sicher, dass das Zielkonto plausibel auch anderswo in AD zu diesen Gruppen gehört. Übermäßige `ExtraSids` verraten die Fälschung.
- Das Splunk Security Content-Projekt stellt Attack-Range-Telemetrie für diamond tickets sowie Erkennungen wie *Windows Domain Admin Impersonation Indicator* bereit, die ungewöhnliche Event ID 4768/4769/4624-Sequenzen und PAC-Gruppenänderungen korrelieren. Das Abspielen dieses Datensatzes (oder das Erzeugen eines eigenen mit den oben genannten Befehlen) hilft, die SOC-Abdeckung für T1558.001 zu validieren und liefert konkrete Alarmlogik, die zum Umgehen genutzt werden kann.

## Referenzen

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
