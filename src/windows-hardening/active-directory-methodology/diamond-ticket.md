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

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now pulls real PAC context by querying LDAP **and** mounting SYSVOL to extract account/group attributes plus Kerberos/password policy (e.g., `GptTmpl.inf`), while `/opsec` makes the AS-REQ/AS-REP flow match Windows by doing the two-step preauth exchange and enforcing AES-only + realistic KDCOptions. This dramatically reduces obvious indicators such as missing PAC fields or policy-mismatched lifetimes.
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
- `/ldap` (mit optionalen `/ldapuser` & `/ldappassword`) fragt AD und SYSVOL ab, um die PAC-Richtliniendaten des Zielbenutzers zu spiegeln.
- `/opsec` erzwingt einen Windows-ähnlichen AS-REQ-Retry, nullt störende Flags und verwendet ausschließlich AES256.
- `/tgtdeleg` hält Ihre Hände vom cleartext password oder NTLM/AES key des Opfers fern, liefert dabei aber trotzdem ein entschlüsselbares TGT.

### Service-ticket recutting

Die gleiche Rubeus-Aktualisierung fügte die Fähigkeit hinzu, die diamond-Technik auf TGS-Blobs anzuwenden. Indem man `diamond` ein **base64-encoded TGT** (aus `asktgt`, `/tgtdeleg`, oder einem zuvor gefälschten TGT), die **service SPN**, und den **service AES key** übergibt, kann man realistische service tickets erstellen, ohne den KDC zu berühren — effektiv ein unauffälligerer silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Dieser Workflow ist ideal, wenn Sie bereits einen Service-Account-Key kontrollieren (z. B. ausgelesen mit `lsadump::lsa /inject` oder `secretsdump.py`) und ein einmaliges TGS erstellen möchten, das genau der AD-Policy, den Zeitvorgaben und den PAC-Daten entspricht, ohne neuen AS/TGS-Verkehr zu erzeugen.

### Sapphire-style PAC swaps (2025)

Ein neuerer Twist, manchmal als **sapphire ticket** bezeichnet, kombiniert Diamond's "real TGT" base mit **S4U2self+U2U**, um einen privilegierten PAC zu stehlen und in Ihr eigenes TGT einzupflegen. Anstatt zusätzliche SIDs zu erfinden, fordern Sie ein U2U S4U2self-Ticket für einen hoch-privilegierten Benutzer an, bei dem das `sname` auf den niedrig-privilegierten Requester zielt; die KRB_TGS_REQ trägt das TGT des Requesters in `additional-tickets` und setzt `ENC-TKT-IN-SKEY`, wodurch das service ticket mit dem Schlüssel dieses Benutzers entschlüsselt werden kann. Anschließend extrahieren Sie den privilegierten PAC und fügen ihn in Ihr legitimes TGT ein, bevor Sie dieses mit dem krbtgt key neu signieren.

Impacket's `ticketer.py` bietet jetzt sapphire-Unterstützung über `-impersonate` + `-request` (Live-KDC-Austausch):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` akzeptiert einen Benutzernamen oder SID; `-request` erfordert live user creds plus krbtgt key material (AES/NTLM), um Tickets zu entschlüsseln/patchen.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & detection notes

- Die traditionellen Hunter-Heuristiken (TGS without AS, decade-long lifetimes) gelten weiterhin für golden tickets, aber diamond tickets treten hauptsächlich zutage, wenn der **PAC content or group mapping looks impossible**. Fülle jedes PAC-Feld (Anmeldezeiten, Benutzerprofilpfade, Geräte-IDs) aus, damit automatisierte Vergleiche die Fälschung nicht sofort markieren.
- **Do not oversubscribe groups/RIDs**. Wenn du nur `512` (Domain Admins) und `519` (Enterprise Admins) brauchst, belasse es dabei und stelle sicher, dass das Zielkonto plausibel an anderer Stelle in AD zu diesen Gruppen gehört. Übermäßige `ExtraSids` sind ein Hinweis.
- Sapphire-style swaps hinterlassen U2U-Fingerabdrücke: `ENC-TKT-IN-SKEY` + `additional-tickets` plus ein `sname`, das in 4769 auf einen Benutzer (oft den Anfragenden) zeigt, und ein anschließender 4624-Logon, der vom gefälschten Ticket stammt. Korrreliere diese Felder, anstatt nur nach no-AS-REQ-Lücken zu suchen.
- Microsoft hat begonnen, die Ausgabe von **RC4 service ticket issuance** wegen CVE-2026-20833 auslaufen zu lassen; das Erzwingen von AES-only etypes auf dem KDC härtet die Domain und stimmt mit diamond/sapphire-Tooling überein (/opsec erzwingt AES bereits). Das Mischen von RC4 in gefälschte PACs wird zunehmend auffallen.
- Splunk's Security Content project verteilt attack-range telemetry für diamond tickets sowie Erkennungen wie *Windows Domain Admin Impersonation Indicator*, die ungewöhnliche Event ID 4768/4769/4624-Sequenzen und PAC-Gruppenänderungen korreliert. Das Abspielen dieses Datensatzes (oder das Erzeugen eines eigenen mit den oben genannten Befehlen) hilft, die SOC-Abdeckung für T1558.001 zu validieren und liefert konkrete Alert-Logik, die es zu umgehen gilt.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
