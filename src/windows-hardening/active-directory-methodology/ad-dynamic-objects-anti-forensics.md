# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mecánica y fundamentos de detección

- Cualquier objeto creado con la clase auxiliar **`dynamicObject`** obtiene **`entryTTL`** (cuenta atrás en segundos) y **`msDS-Entry-Time-To-Die`** (expiración absoluta). Cuando **`entryTTL`** llega a 0, el **Garbage Collector** lo elimina sin tombstone/recycle-bin, borrando el creador y las marcas de tiempo e impidiendo su recuperación.
- **`entryTTL` es un atributo operativo/constructed**: solicítalo explícitamente en las consultas LDAP. El TTL puede renovarse actualizando **`entryTTL`** antes de su expiración o mediante el OID de renovación de TTL de LDAP **`1.3.6.1.4.1.1466.101.119.1`**.
- Los valores mínimo/predeterminado del TTL se aplican en **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documenta **86400s** como TTL predeterminado y **900s** como TTL mínimo válido predeterminado; ambos admiten valores de **1s–1y**. Los objetos dinámicos no son compatibles con las particiones Configuration/Schema.
- No existe **conversión static→dynamic** ni una fase de tombstone tras la expiración. Los equipos de IR no pueden depender de los controles de objetos eliminados ni de Recycle Bin; deben capturar el objeto activo y sus metadatos antes de que el GC lo elimine.
- La renovación depende de la réplica: si el TTL se renueva demasiado cerca de la expiración, otra réplica con capacidad de escritura o el GC aún puede eliminar localmente el objeto antes de que la renovación se replique. Por tanto, los TTL muy cortos funcionan mejor cuando el atacante sabe qué DC atenderá el abuso, mientras que los defensores deben consultar **todos los naming contexts / réplicas** durante el triage.
- La eliminación puede retrasarse unos minutos en DCs con un tiempo de actividad corto (<24h), dejando una estrecha ventana de respuesta para consultar/hacer backup de los atributos. Detecta esto mediante **alertas sobre nuevos objetos que contengan `entryTTL`/`msDS-Entry-Time-To-Die`** y correlación con SIDs huérfanos/enlaces rotos.<sup>[[1]](#references)</sup>

## Enumeración rápida / Triage en vivo

- Consulta **todos los `namingContexts` desde RootDSE**, no solo el NC del dominio. El abuso de objetos dinámicos puede residir en **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o en particiones de aplicación.
- Mientras el objeto siga activo, vuelca inmediatamente los **metadatos de replicación** y cualquier atributo enlazado/ACL. Tras la expiración, es posible que solo queden **valores `gPLink` rotos, SIDs huérfanos o respuestas DNS almacenadas en caché**.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasión de MAQ con equipos que se eliminan automáticamente

- El valor predeterminado de **`ms-DS-MachineAccountQuota` = 10** permite que cualquier usuario autenticado cree equipos. Añade `dynamicObject` durante la creación para que el equipo se elimine automáticamente y **libere el espacio de cuota**, mientras borra las evidencias.
- Ajuste de Powermad dentro de `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Si el TTL solicitado es **inferior a `DynamicObjectMinTTL`**, espera un ajuste o rechazo por parte del servidor, según el método de creación; en muchos dominios, el límite efectivo es de **900 s** y el fallback/valor predeterminado sigue siendo **86400 s**. ADUC puede ocultar `entryTTL`, pero las consultas LDP/LDAP lo revelan.
- Mientras el objeto exista, los defensores todavía pueden identificar al creador sin privilegios mediante **`msDS-CreatorSID`** en el objeto de equipo. Cuando el equipo dynamic expire, esa atribución desaparece junto con el objeto.<sup>[[1]](#references)</sup>

## Membresía sigilosa en el grupo principal

- Crea un **grupo de seguridad dynamic** y establece el **`primaryGroupID`** de un usuario al RID de ese grupo para obtener una membresía efectiva que **no aparece en `memberOf`**, pero que se respeta en Kerberos/tokens de acceso.<sup>[[1]](#references)</sup>
- La expiración del TTL **elimina el grupo a pesar de la protección contra la eliminación del grupo principal**, dejando al usuario con un `primaryGroupID` corrupto que apunta a un RID inexistente y sin un tombstone que permita investigar cómo se concedió el privilegio.
- Los informes dependen de la herramienta: **`Get-ADGroupMember` / `net group`** normalmente resuelven la membresía derivada del grupo principal, mientras que **`memberOf`** y **`Get-ADGroup -Properties member`** no lo hacen. Para obtener más información sobre el tradecraft de `primaryGroupID`, consulta [esta otra página sobre el abuso de DCShadow y PGID](dcshadow.md).
- Para objetivos **no protegidos por AdminSDHolder**, los atacantes pueden combinar el truco del grupo dynamic con un **DACL deny sobre la lectura de `primaryGroupID`** (o del atributo `member` del grupo) para ocultar el vínculo a muchos flujos de trabajo LDAP/PowerShell incluso antes de que expire el grupo.<sup>[[2]](#references)</sup>

## Contaminación de SID huérfanos en AdminSDHolder

- Añade ACEs para un **usuario/grupo dynamic de corta duración** a **`CN=AdminSDHolder,CN=System,...`**. Tras la expiración del TTL, el SID se vuelve **irresoluble (“Unknown SID”)** en la ACL de la plantilla, y **SDProp (~60 min)** propaga ese SID huérfano a todos los objetos Tier-0 protegidos.
- Los análisis forenses pierden la atribución porque la entidad principal ya no existe (no hay DN de objeto eliminado). Supervisa la aparición de **nuevas entidades principales dynamic + SIDs huérfanos repentinos en las ACL de AdminSDHolder/privilegiadas**.<sup>[[1]](#references)</sup>

## Ejecución de GPO dynamic con evidencias que se autodestruyen

- Crea un objeto **`groupPolicyContainer` dynamic** con un **`gPCFileSysPath`** malicioso (por ejemplo, un recurso compartido SMB al estilo de GPODDITY) y **vincúlalo mediante `gPLink`** a una OU objetivo.
- Los clientes procesan la política y descargan el contenido desde el SMB del atacante. Cuando expira el TTL, el objeto GPO (y `gPCFileSysPath`) desaparece; solo queda un GUID de **`gPLink` roto**, eliminando la evidencia LDAP del payload ejecutado.
- Esto es operativamente más limpio que la limpieza clásica al estilo **GPODDITY**: en lugar de restaurar tú mismo el `gPCFileSysPath` original, AD elimina automáticamente el GPC malicioso cuando expira el temporizador.<sup>[[1]](#references)</sup>

## Redirección efímera de DNS integrado en AD

- Los registros DNS de AD son objetos **`dnsNode`** en **DomainDnsZones/ForestDnsZones**. Crearlos como objetos **dynamic** permite una redirección temporal de hosts (captura de credenciales/MITM). Los clientes almacenan en caché la respuesta A/AAAA maliciosa; posteriormente, el registro se elimina automáticamente para que la zona parezca limpia (puede ser necesario recargar la zona en DNS Manager para actualizar la vista).
- Detección: genera una alerta ante **cualquier registro DNS que contenga `dynamicObject`/`entryTTL`** mediante logs de replicación/eventos; los registros transitorios rara vez aparecen en los logs DNS estándar.<sup>[[1]](#references)</sup>

## Brecha de Delta-Sync híbrida de Entra ID (nota)

- Entra Connect delta sync depende de **tombstones** para detectar eliminaciones. Un **usuario on-prem dynamic** puede sincronizarse con Entra ID, expirar y eliminarse sin tombstone; delta sync no eliminará la cuenta cloud, dejando un **usuario de Entra activo y huérfano** hasta que se fuerce una **sincronización inicial/completa** o una limpieza manual en cloud.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
