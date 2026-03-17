# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

Postoje dve uobičajene tehnike za detekciju upotrebe golden tickets:

- Potražite TGS-REQ-ove koji nemaju odgovarajući AS-REQ.
- Potražite TGT-ove koji imaju neobične vrednosti, kao što je podrazumevano 10-godišnje trajanje iz Mimikatz-a.

A **diamond ticket** nastaje **izmenom polja legitimnog TGT-a koji je izdao DC**. Ovo se postiže **zahtevanjem** **TGT-a**, **dešifrovanjem** istog pomoću krbtgt hasha domena, **izmenom** željenih polja tiketa, i zatim **ponovnim šifrovanjem**. Ovo **prevazilazi prethodno navedene dve slabosti** golden ticketa zato što:

- TGS-REQ-ovi će imati prethodni AS-REQ.
- TGT je izdao DC, što znači da će imati sve ispravne detalje iz Kerberos politike domena. Iako se ovo može tačno falsifikovati u golden ticket-u, to je komplikovanije i podložno greškama.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Dobijte TGT za bilo kog kontrolisanog korisnika putem AS-REQ (Rubeus `/tgtdeleg` je pogodan jer primorava klijenta da izvede Kerberos GSS-API razmenu bez kredencijala).
2. Dešifrujte vraćeni TGT pomoću krbtgt ključa, izmenite PAC atribute (korisnik, grupe, informacije o prijavi, SID-ovi, zahtevi uređaja, itd.).
3. Ponovo šifrujte/potpíšite tiket istim krbtgt ključem i ubrizgajte ga u trenutnu sesiju prijave (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opcionalno, ponovite proces nad service ticket-om tako što ćete obezbediti validan TGT blob plus ciljni service key da biste ostali prikriveni na mrežnom saobraćaju.

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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) izvlači podatke iz AD i SYSVOL da bi preslikao PAC policy data ciljanog korisnika.
- `/opsec` primorava Windows-sličan AS-REQ retry, resetuje noisy flags i drži se AES256.
- `/tgtdeleg` ostavlja vas bez direktnog pristupa cleartext password ili NTLM/AES key žrtve, dok i dalje vraća decryptable TGT.

### Service-ticket recutting

Isti Rubeus refresh je dodao mogućnost primene diamond technique na TGS blobs. Davanjem `diamond` **base64-encoded TGT** (iz `asktgt`, `/tgtdeleg`, ili prethodno forged TGT), **service SPN**, i **service AES key**, možete proizvesti realistične service tickets bez diranja KDC — efektivno prikriveniji silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ovaj postupak je idealan kada već kontrolišete ključ servisnog naloga (npr. izvučen sa `lsadump::lsa /inject` ili `secretsdump.py`) i želite da napravite jednokratni TGS koji savršeno odgovara AD politici, vremenskim okvirima i PAC podacima bez slanja bilo kakvog novog AS/TGS saobraćaja.

### Sapphire-style PAC swaps (2025)

Novija varijanta, ponekad nazvana **sapphire ticket**, kombinuje Diamond-ovu "real TGT" osnovu sa **S4U2self+U2U** kako bi ukrala privilegovani PAC i ubacila ga u vaš sopstveni TGT. Umesto izmišljanja dodatnih SID-ova, zatražite U2U S4U2self tiket za korisnika sa visokim privilegijama gde `sname` cilja niskopravnog podnosioca zahteva; KRB_TGS_REQ nosi TGT podnosioca zahteva u `additional-tickets` i postavlja `ENC-TKT-IN-SKEY`, što omogućava dešifrovanje service tiketa korisnikovim ključem. Zatim izvučete privilegovani PAC i uklopite ga u svoj legitimni TGT pre ponovnog potpisivanja krbtgt ključem.

Impacket-ov `ticketer.py` sada uključuje podršku za sapphire putem `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accepts a username or SID; `-request` requires live user creds plus krbtgt key material (AES/NTLM) to decrypt/patch tickets.

Ključni OPSEC indikatori pri korišćenju ove varijante:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC i napomene za detekciju

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **PAC content or group mapping looks impossible**. Populate every PAC field (logon hours, user profile paths, device IDs) so automated comparisons do not immediately flag the forgery.
- **Do not oversubscribe groups/RIDs**. If you only need `512` (Domain Admins) and `519` (Enterprise Admins), stop there and make sure the target account plausibly belongs to those groups elsewhere in AD. Excessive `ExtraSids` is a giveaway.
- Sapphire-style swaps leave U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets` plus a `sname` that points at a user (often the requester) in 4769, and a follow-up 4624 logon sourced from the forged ticket. Correlate those fields instead of only looking for no-AS-REQ gaps.
- Microsoft started phasing out **RC4 service ticket issuance** because of CVE-2026-20833; enforcing AES-only etypes on the KDC both hardens the domain and aligns with diamond/sapphire tooling (/opsec already forces AES). Mixing RC4 into forged PACs will increasingly stick out.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Replaying that dataset (or generating your own with the commands above) helps validate SOC coverage for T1558.001 while giving you concrete alert logic to evade.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
