# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Wie ein goldenes Ticket** ist ein Diamantticket ein TGT, das verwendet werden kann, um **auf jeden Dienst als jeder Benutzer zuzugreifen**. Ein goldenes Ticket wird vollständig offline gefälscht, mit dem krbtgt-Hash dieser Domäne verschlüsselt und dann in eine Anmeldesitzung übergeben. Da Domänencontroller TGTs, die sie (oder sie) legitim ausgestellt haben, nicht verfolgen, akzeptieren sie gerne TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt sind.

Es gibt zwei gängige Techniken, um die Verwendung von goldenen Tickets zu erkennen:

- Suchen Sie nach TGS-REQs, die kein entsprechendes AS-REQ haben.
- Suchen Sie nach TGTs, die absurde Werte haben, wie zum Beispiel die Standardlebensdauer von 10 Jahren von Mimikatz.

Ein **Diamantticket** wird erstellt, indem **die Felder eines legitimen TGTs, das von einem DC ausgestellt wurde, modifiziert werden**. Dies wird erreicht, indem ein **TGT angefordert**, es mit dem krbtgt-Hash der Domäne **entschlüsselt**, die gewünschten Felder des Tickets **modifiziert** und dann **wieder verschlüsselt** wird. Dies **überwindet die beiden oben genannten Mängel** eines goldenen Tickets, weil:

- TGS-REQs ein vorhergehendes AS-REQ haben werden.
- Das TGT wurde von einem DC ausgestellt, was bedeutet, dass es alle korrekten Details aus der Kerberos-Richtlinie der Domäne haben wird. Auch wenn diese in einem goldenen Ticket genau gefälscht werden können, ist es komplexer und anfälliger für Fehler.
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
