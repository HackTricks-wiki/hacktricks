# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Kao zlatna karta**, dijamantska karta je TGT koja se može koristiti za **pristup bilo kojoj usluzi kao bilo koji korisnik**. Zlatna karta se potpuno falsifikuje van mreže, enkriptovana je sa krbtgt hash-om te domene, a zatim se koristi u sesiji prijavljivanja. Pošto kontroleri domena ne prate TGT-ove koje su legitimno izdale, rado će prihvatiti TGT-ove koji su enkriptovani sa vlastitim krbtgt hash-om.

Postoje dve uobičajene tehnike za otkrivanje korišćenja zlatnih karata:

- Tražite TGS-REQ-ove koji nemaju odgovarajući AS-REQ.
- Tražite TGT-ove koji imaju smešne vrednosti, kao što je podrazumevani vek trajanja od 10 godina u Mimikatz-u.

**Dijamantska karta** se pravi **modifikovanjem polja legitimnog TGT-a koji je izdao DC**. To se postiže **zahtevom** za **TGT**, **dekripcijom** sa krbtgt hash-om domene, **modifikovanjem** željenih polja karte, a zatim **ponovnim enkriptovanjem**. Ovo **prevazilazi dva prethodno pomenuta nedostatka** zlatne karte jer:

- TGS-REQ-ovi će imati prethodni AS-REQ.
- TGT je izdao DC što znači da će imati sve tačne detalje iz Kerberos politike domene. Iako se ovi detalji mogu tačno falsifikovati u zlatnoj karti, to je složenije i otvoreno za greške.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
