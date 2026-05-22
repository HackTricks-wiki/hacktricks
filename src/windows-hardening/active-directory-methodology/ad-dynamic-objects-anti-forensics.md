# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mecánica y conceptos básicos de detección

- Cualquier objeto creado con la clase auxiliar **`dynamicObject`** obtiene **`entryTTL`** (cuenta regresiva en segundos) y **`msDS-Entry-Time-To-Die`** (expiración absoluta). Cuando `entryTTL` llega a 0, el **Garbage Collector** lo elimina sin tombstone/recycle-bin, borrando creator/timestamps e impidiendo la recuperación.
- **`entryTTL` es un atributo operacional/construct**: solicítalo explícitamente en consultas LDAP. El TTL puede refrescarse ya sea actualizando `entryTTL` antes de que expire o mediante el OID de refresh TTL de LDAP **`1.3.6.1.4.1.1466.101.119.1`**.
- El TTL mínimo/por defecto se aplica en **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documenta **86400s** como TTL por defecto y **900s** como TTL mínimo válido por defecto; ambos soportan **1s–1y**. Los objetos dinámicos **no están soportados en las particiones Configuration/Schema**.
- **No existe conversión estática→dinámica** y no hay fase de tombstone tras la expiración. Los equipos de IR no pueden confiar en los controles de deleted-object ni en Recycle Bin; deben capturar el objeto vivo/metadata antes de que GC lo elimine.
- El refresh es **sensible a la réplica**: si el TTL se renueva demasiado cerca de la expiración, otra réplica escribible o GC puede borrar el objeto localmente antes de que el refresh se replique. Por tanto, los TTL muy cortos funcionan mejor cuando el atacante sabe qué DC atenderá el abuso, mientras que los defensores deberían consultar **todos los naming contexts / réplicas** durante el triage.
- La eliminación puede retrasarse unos minutos en DCs con uptime corto (<24h), dejando una ventana estrecha de respuesta para consultar/respaldar atributos. Detecta esto **alertando sobre nuevos objetos que lleven `entryTTL`/`msDS-Entry-Time-To-Die`** y correlacionando con orphan SIDs/broken links.

## Enumeración rápida / Triage en vivo

- Consulta **todos los `namingContexts` desde RootDSE**, no solo el domain NC. El abuso dinámico puede vivir en **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o en particiones de aplicación.
- Mientras el objeto siga vivo, vuelca inmediatamente la **replication metadata** y cualquier atributo enlazado/ACLs. Tras la expiración puede que solo queden **valores rotos de `gPLink`, orphan SIDs o DNS answers cacheadas**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion with Self-Deleting Computers

- El predeterminado **`ms-DS-MachineAccountQuota` = 10** permite a cualquier usuario autenticado crear equipos. Añade `dynamicObject` durante la creación para que el equipo se autodestruya y **libere la ranura de cuota** mientras borra evidencias.
- Ajuste de Powermad dentro de `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Si el TTL solicitado está **por debajo de `DynamicObjectMinTTL`**, espera un ajuste del lado del servidor o un rechazo según la ruta de creación; en muchos dominios el mínimo efectivo es **900s** y el valor de fallback/predeterminado sigue siendo **86400s**. ADUC puede ocultar `entryTTL`, pero las consultas LDP/LDAP lo revelan.
- Mientras el objeto existe, los defensores aún pueden recuperar el creador sin privilegios desde **`msDS-CreatorSID`** en el objeto computer. Una vez expira el computer dinámico, esa atribución desaparece junto con el objeto.

## Stealth Primary Group Membership

- Crea un **dynamic security group**, luego establece el **`primaryGroupID`** de un usuario al RID de ese grupo para obtener pertenencia efectiva que **no aparece en `memberOf`** pero sí se respeta en Kerberos/access tokens.
- La expiración del TTL **borra el grupo a pesar de la protección de borrado del primary-group**, dejando al usuario con un `primaryGroupID` corrupto que apunta a un RID inexistente y sin tombstone para investigar cómo se concedió el privilegio.
- El reporting depende de la herramienta: **`Get-ADGroupMember` / `net group`** suelen resolver la pertenencia derivada del primary-group, mientras que **`memberOf`** y **`Get-ADGroup -Properties member`** no lo hacen. Para un tradecraft más amplio de `primaryGroupID`, consulta [this other page about DCShadow and PGID abuse](dcshadow.md).
- Para objetivos **no protegidos por AdminSDHolder**, los atacantes pueden combinar el truco del dynamic-group con un **DACL deny on reading `primaryGroupID`** (o el atributo `member` del grupo) para ocultar el enlace de muchos flujos de trabajo LDAP/PowerShell incluso antes de que el grupo expire.

## AdminSDHolder Orphan-SID Pollution

- Añade ACEs para un **dynamic user/group** de corta duración a **`CN=AdminSDHolder,CN=System,...`**. Tras expirar el TTL, el SID se vuelve **no resoluble (“Unknown SID”)** en el ACL de la plantilla, y **SDProp (~60 min)** propaga ese orphan SID a través de todos los objetos protegidos Tier-0.
- La forensics pierde atribución porque el principal desaparece (sin DN de objeto eliminado). Vigila **nuevos dynamic principals + orphan SIDs repentinos en AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Crea un objeto **dynamic `groupPolicyContainer`** con un **`gPCFileSysPath`** malicioso (p. ej., SMB share al estilo GPODDITY) y **vincúlalo mediante `gPLink`** a una OU objetivo.
- Los clientes procesan la policy y extraen contenido desde el SMB del atacante. Cuando expira el TTL, el objeto GPO (y `gPCFileSysPath`) desaparece; solo queda un **broken `gPLink`** GUID, eliminando la evidencia LDAP del payload ejecutado.
- Operativamente es más limpio que la limpieza clásica estilo **GPODDITY**: en lugar de restaurar tú mismo el `gPCFileSysPath` original, AD elimina automáticamente el GPC malicioso cuando expira el temporizador.

## Ephemeral AD-Integrated DNS Redirection

- Los registros DNS de AD son objetos **`dnsNode`** en **DomainDnsZones/ForestDnsZones**. Crearlos como **dynamic objects** permite redirección temporal de hosts (credential capture/MITM). Los clientes cachean la respuesta A/AAAA maliciosa; el registro luego se autodestruye, así que la zona parece limpia (DNS Manager puede necesitar recargar la zona para refrescar la vista).
- Detección: alerta sobre **cualquier registro DNS que lleve `dynamicObject`/`entryTTL`** mediante logs de replicación/eventos; los registros transitorios rara vez aparecen en los logs DNS estándar.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync depende de **tombstones** para detectar borrados. Un **dynamic on-prem user** puede sincronizarse a Entra ID, expirar y borrarse sin tombstone—delta sync no eliminará la cuenta cloud, dejando un **orphaned active Entra user** hasta que se fuerce un **initial/full sync** o una limpieza manual en la nube.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
