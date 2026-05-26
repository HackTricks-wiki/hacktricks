# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Any object created with the auxiliary class **`dynamicObject`** gains **`entryTTL`** (countdown en segundos) and **`msDS-Entry-Time-To-Die`** (caducidad absoluta). Cuando `entryTTL` llega a 0, el **Garbage Collector lo elimina sin tombstone/recycle-bin**, borrando los datos del creador y las marcas de tiempo y bloqueando la recuperación.
- **`entryTTL` es un atributo operacional/constructed**: solicítalo explícitamente en consultas LDAP. El TTL puede refrescarse actualizando `entryTTL` antes de la caducidad o mediante el OID de refresh TTL de LDAP **`1.3.6.1.4.1.1466.101.119.1`**.
- Los mínimos/default de TTL se aplican en **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documenta **86400s** como el TTL por defecto y **900s** como el mínimo válido por defecto; ambos soportan **1s–1y**. Los dynamic objects **no están soportados en las particiones Configuration/Schema**.
- No existe conversión estática→dynamic y no hay fase de tombstone tras la caducidad. Los equipos de IR no pueden depender de los controles de deleted-object ni de Recycle Bin; deben capturar el objeto vivo/metadata antes de que el GC lo elimine.
- El refresh es **sensible a la réplica**: si el TTL se renueva demasiado cerca de la caducidad, otra réplica writable o GC aún puede eliminar el objeto localmente antes de que el refresh se replique. Por eso, los TTL muy cortos funcionan mejor cuando el atacante sabe qué DC servirá el abuso, mientras que los defensores deberían consultar **todos los naming contexts / replicas** durante el triage.
- La eliminación puede retrasarse unos minutos en DCs con uptime corto (<24h), dejando una ventana estrecha de respuesta para consultar/respaldar atributos. Detecta esto **alertando sobre nuevos objetos que lleven `entryTTL`/`msDS-Entry-Time-To-Die`** y correlacionando con orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Consulta **todos los `namingContexts` desde RootDSE**, no solo el domain NC. El abuso dinámico puede vivir en **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o en application partitions.
- Mientras el objeto siga vivo, vuelca de inmediato la **replication metadata** y cualquier linked attributes/ACLs. Tras la caducidad, puede que solo queden **broken `gPLink` values, orphan SIDs, o cached DNS answers**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasión de MAQ con Computers que se Autodestruyen

- El valor predeterminado **`ms-DS-MachineAccountQuota` = 10** permite que cualquier usuario autenticado cree computers. Añade `dynamicObject` durante la creación para que el computer se autodestruya y **libere la cuota** mientras borra evidencias.
- Ajuste de Powermad dentro de `New-MachineAccount` (lista `objectClass`):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Si el `TTL` solicitado está **por debajo de `DynamicObjectMinTTL`**, espera ajuste del lado del servidor o rechazo según la ruta de creación; en muchos dominios el mínimo efectivo es **900s** y el valor de respaldo/predeterminado sigue siendo **86400s**. ADUC puede ocultar `entryTTL`, pero las consultas LDP/LDAP lo revelan.
- Mientras el objeto existe, los defensores aún pueden recuperar al creador sin privilegios desde **`msDS-CreatorSID`** en el objeto computer. Una vez que el dynamic computer expira, esa atribución desaparece con el objeto.

## Membresía de Primary Group Sigilosa

- Crea un **dynamic security group**, luego establece el **`primaryGroupID`** de un usuario al RID de ese grupo para obtener una membresía efectiva que **no aparece en `memberOf`** pero sí es respetada en Kerberos/access tokens.
- La expiración del `TTL` **elimina el grupo a pesar de la protección de borrado del primary group**, dejando al usuario con un `primaryGroupID` corrupto apuntando a un RID inexistente y sin tombstone para investigar cómo se concedió el privilegio.
- El reporting depende de la herramienta: **`Get-ADGroupMember` / `net group`** normalmente resuelven la membresía derivada del primary group, mientras que **`memberOf`** y **`Get-ADGroup -Properties member`** no. Para un tradecraft más amplio con `primaryGroupID`, consulta [esta otra página sobre DCShadow y abuso de PGID](dcshadow.md).
- Para objetivos **no protegidos por AdminSDHolder**, los atacantes pueden combinar el truco del dynamic group con un **DACL deny sobre la lectura de `primaryGroupID`** (o del atributo `member` del grupo) para ocultar el vínculo de muchos workflows LDAP/PowerShell incluso antes de que el grupo expire.

## Contaminación de SID Huérfano en AdminSDHolder

- Añade ACEs para un **dynamic user/group de vida corta** a **`CN=AdminSDHolder,CN=System,...`**. Tras expirar el `TTL`, el SID se vuelve **no resoluble (“Unknown SID”)** en la ACL de la plantilla, y **SDProp (~60 min)** propaga ese SID huérfano a todos los objetos protegidos de Tier-0.
- La forensia pierde atribución porque el principal ya no existe (sin DN de objeto borrado). Vigila **nuevos principals dinámicos + aparición repentina de SID huérfanos en AdminSDHolder/ACLs privilegiadas**.

## Ejecución Dinámica de GPO con Evidencias Autodestructivas

- Crea un objeto **dynamic `groupPolicyContainer`** con un **`gPCFileSysPath`** malicioso (por ejemplo, una SMB share al estilo GPODDITY) y **vincúlalo mediante `gPLink`** a una OU objetivo.
- Los clientes procesan la policy y descargan contenido desde SMB del atacante. Cuando expira el `TTL`, el objeto GPO (y `gPCFileSysPath`) desaparece; solo queda un **`gPLink`** GUID roto, eliminando la evidencia LDAP del payload ejecutado.
- Operativamente esto es más limpio que la limpieza clásica al estilo **GPODDITY**: en lugar de restaurar tú mismo el `gPCFileSysPath` original, AD elimina automáticamente el GPC malicioso cuando expira el temporizador.

## Redirección Efímera de DNS Integrado en AD

- Los registros DNS de AD son objetos **`dnsNode`** en **DomainDnsZones/ForestDnsZones**. Crearlos como objetos dinámicos permite redirección temporal de hosts (credential capture/MITM). Los clientes cachean la respuesta A/AAAA maliciosa; el registro luego se autodestruye, dejando la zona limpia (DNS Manager puede necesitar recargar la zona para actualizar la vista).
- Detección: alerta sobre **cualquier registro DNS que lleve `dynamicObject`/`entryTTL`** mediante logs de replicación/eventos; los registros transitorios rara vez aparecen en los logs DNS estándar.

## Brecha Hybrid Entra ID Delta-Sync (Nota)

- Entra Connect delta sync depende de **tombstones** para detectar borrados. Un **dynamic on-prem user** puede sincronizarse con Entra ID, expirar y borrarse sin tombstone—delta sync no eliminará la cuenta cloud, dejando un **orphaned active Entra user** hasta que se fuerce un **initial/full sync** o una limpieza manual en cloud.

## Referencias

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
