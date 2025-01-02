# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Comme un golden ticket**, un diamond ticket est un TGT qui peut être utilisé pour **accéder à n'importe quel service en tant que n'importe quel utilisateur**. Un golden ticket est forgé complètement hors ligne, crypté avec le hash krbtgt de ce domaine, puis passé dans une session de connexion pour utilisation. Parce que les contrôleurs de domaine ne suivent pas les TGT qu'ils (ou ils) ont légitimement émis, ils accepteront volontiers les TGT qui sont cryptés avec leur propre hash krbtgt.

Il existe deux techniques courantes pour détecter l'utilisation de golden tickets :

- Rechercher des TGS-REQs qui n'ont pas de AS-REQ correspondant.
- Rechercher des TGTs qui ont des valeurs absurdes, comme la durée de vie par défaut de 10 ans de Mimikatz.

Un **diamond ticket** est créé en **modifiant les champs d'un TGT légitime qui a été émis par un DC**. Cela est réalisé en **demandant** un **TGT**, en **le décryptant** avec le hash krbtgt du domaine, en **modifiant** les champs souhaités du ticket, puis en **le recryptant**. Cela **surmonte les deux inconvénients mentionnés précédemment** d'un golden ticket parce que :

- Les TGS-REQs auront un AS-REQ précédent.
- Le TGT a été émis par un DC, ce qui signifie qu'il aura tous les détails corrects de la politique Kerberos du domaine. Même si ceux-ci peuvent être forgés avec précision dans un golden ticket, c'est plus complexe et sujet à des erreurs.
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
