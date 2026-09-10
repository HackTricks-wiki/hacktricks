# Objetos dinámicos de AD (dynamicObject): Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mecánica y conceptos básicos de detección

- Cualquier objeto creado con la clase auxiliar **`dynamicObject`** obtiene **`entryTTL`** (cuenta atrás en segundos) y **`msDS-Entry-Time-To-Die`** (expiración absoluta). Cuando `entryTTL` llega a 0 **y el objeto no tiene descendientes**, el Garbage Collector lo elimina sin tombstone/recycle-bin, borrando el creador y las marcas de tiempo, e impidiendo su recuperación.<sup>[[4]](#references)</sup>
- **`entryTTL` es un atributo operativo/construido**: solicítalo explícitamente en las consultas LDAP. El TTL puede actualizarse modificando `entryTTL` antes de su expiración o mediante el OID de actualización de TTL de LDAP **`1.3.6.1.4.1.1466.101.119.1`**.
- Los valores mínimo/predeterminado del TTL son AVA de todo el forest en **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` y `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft documenta **86400s** como TTL predeterminado y **900s** como TTL mínimo válido predeterminado; el rango del esquema de `entryTTL` es de **1–31557600s** (un segundo a un año).<sup>[[3]](#references)</sup> Los objetos dinámicos **no son compatibles con las particiones Configuration/Schema**.
- **No existe conversión de static a dynamic** ni una fase de tombstone después de la expiración. Los equipos de IR no pueden depender de los controles de objetos eliminados ni de Recycle Bin; deben capturar el objeto activo y sus metadatos antes de que el GC lo elimine.
- La actualización es **sensible a la réplica**: si el TTL se renueva demasiado cerca de su expiración, otra réplica writable o el GC todavía pueden eliminar localmente el objeto antes de que la actualización se replique. Por ello, los TTL muy cortos funcionan mejor cuando el atacante sabe qué DC atenderá el abuso, mientras que los defensores deberían consultar **todos los naming contexts / réplicas** durante el triage.
- La eliminación puede retrasarse algunos minutos en DCs con un tiempo de actividad corto (<24h), dejando una estrecha ventana de respuesta para consultar o respaldar atributos. Detecta esta actividad mediante **alertas sobre nuevos objetos que contengan `entryTTL`/`msDS-Entry-Time-To-Die`** y correlación con SIDs huérfanos/enlaces rotos.<sup>[[1]](#references)</sup>

### Grafo de expiración y casos extremos de limpieza de referencias

- Cada descendiente bajo un objeto dinámico debe ser también dinámico. Un padre dinámico expirado solo se recolecta mediante garbage collection después de convertirse en una hoja; si un descendiente tiene un `msDS-Entry-Time-To-Die` posterior, el DC prolonga la expiración del padre más allá de la expiración máxima de los descendientes. En consecuencia, un subtree dinámico writable puede **fijar/prolongar un padre que parece estar a punto de desaparecer**: enumera todo su subtree y no uses el `entryTTL` observado del padre como fecha límite de limpieza.<sup>[[4]](#references)</sup>
- La limpieza de la expiración tiene en cuenta los **schema-links**. Las réplicas eliminan los valores de atributos linked que hacen referencia al objeto dinámico eliminado, pero conservan los valores nonlinked. Espera que la pertenencia ordinaria de forward/back-links se limpie, mientras que las referencias de tipo integer/SID/string, como `primaryGroupID`, los SIDs incrustados en `nTSecurityDescriptor` o el texto de `gPLink`, puedan sobrevivir como residuos forenses.<sup>[[4]](#references)</sup>

## Enumeración rápida / Triage en vivo

- Consulta **todos los `namingContexts` de RootDSE**, no solo el domain NC. El abuso de objetos dinámicos puede encontrarse en **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o en application partitions.
- Mientras el objeto siga activo, extrae inmediatamente los **metadatos de replicación** y cualquier atributo linked/ACL. Tras la expiración, es posible que solo queden **valores `gPLink` rotos, SIDs huérfanos o respuestas DNS en caché**.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasión de MAQ con equipos que se eliminan automáticamente

- El valor predeterminado **`ms-DS-MachineAccountQuota` = 10** permite que cualquier usuario autenticado cree equipos. Añade `dynamicObject` durante la creación para que el equipo se elimine automáticamente y **libere el espacio de cuota** mientras borra las evidencias.
- Ajuste de Powermad dentro de `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Si el TTL solicitado está **por debajo de `DynamicObjectMinTTL`**, espera un ajuste o rechazo del servidor dependiendo de la ruta de creación; en muchos dominios el límite efectivo es **900s** y el fallback/valor predeterminado sigue siendo **86400s**. ADUC puede ocultar `entryTTL`, pero las consultas LDP/LDAP lo revelan.
- Mientras el objeto exista, los defensores aún pueden recuperar el creador sin privilegios de **`msDS-CreatorSID`** en el objeto de equipo. Una vez que el equipo dinámico expire, esa atribución desaparece junto con el objeto.<sup>[[1]](#references)</sup>

## Membresía sigilosa del grupo principal

- Crea un **dynamic security group** y, a continuación, establece el **`primaryGroupID`** de un usuario en el RID de ese grupo para obtener una membresía efectiva que **no aparece en `memberOf`**, pero que se respeta en Kerberos/tokens de acceso.<sup>[[1]](#references)</sup>
- La expiración del TTL **elimina el grupo a pesar de la protección contra la eliminación del grupo principal**, dejando al usuario con un **`primaryGroupID`** corrupto que apunta a un RID inexistente y sin un tombstone que permita investigar cómo se concedió el privilegio.
- Los informes dependen de la herramienta: **`Get-ADGroupMember` / `net group`** normalmente resuelven la membresía derivada del grupo principal, mientras que **`memberOf`** y **`Get-ADGroup -Properties member`** no lo hacen. Para obtener más información sobre el tradecraft de `primaryGroupID`, consulta [esta otra página sobre el abuso de DCShadow y PGID](dcshadow.md).
- Para objetivos **no protegidos por AdminSDHolder**, los atacantes pueden combinar el truco del grupo dinámico con un **DACL deny** sobre la lectura de **`primaryGroupID`** (o del atributo `member` del grupo) para ocultar el vínculo de muchos flujos de trabajo LDAP/PowerShell incluso antes de que expire el grupo.<sup>[[2]](#references)</sup>

## Contaminación de SID huérfanos de AdminSDHolder

- Añade ACEs para un **usuario/grupo dinámico de corta duración** a **`CN=AdminSDHolder,CN=System,...`**. Después de que expire el TTL, el SID se vuelve **irresoluble (“Unknown SID”)** en la ACL de la plantilla, y **SDProp (~60 min)** propaga ese SID huérfano por todos los objetos protegidos de Tier-0.
- El análisis forense pierde la atribución porque la entidad de seguridad ha desaparecido (no existe un DN de objeto eliminado). Supervisa la aparición de **nuevas entidades de seguridad dinámicas + SIDs huérfanos repentinos en AdminSDHolder/ACLs privilegiadas**.<sup>[[1]](#references)</sup>

## Ejecución de GPO dinámica con evidencias que se autodestruyen

- Crea un objeto **`groupPolicyContainer` dinámico** con un **`gPCFileSysPath`** malicioso (por ejemplo, un recurso compartido SMB al estilo de GPODDITY) y **vincúlalo mediante `gPLink`** a una OU objetivo.
- Los clientes procesan la política y extraen el contenido del SMB del atacante. Cuando expira el TTL, el objeto GPO (y `gPCFileSysPath`) desaparece; solo queda un GUID de **`gPLink` roto**, eliminando las evidencias LDAP del payload ejecutado.
- Esto es operativamente más limpio que la limpieza clásica **al estilo GPODDITY**: en lugar de restaurar manualmente el `gPCFileSysPath` original, AD elimina automáticamente el GPC malicioso cuando expira el temporizador.<sup>[[1]](#references)</sup> Consulta [abuso de persistencia de ACL](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) para conocer los detalles del protocolo y las herramientas, en lugar de duplicarlos aquí.

## Redirección efímera de DNS integrado en AD

- Los registros DNS de AD son objetos **`dnsNode`** en **DomainDnsZones/ForestDnsZones**. Crearlos como **dynamic objects** permite una redirección temporal de hosts (captura de credenciales/MITM). Los clientes almacenan en caché la respuesta A/AAAA maliciosa; posteriormente, el registro se elimina automáticamente para que la zona parezca limpia (puede ser necesario recargar la zona en DNS Manager para actualizar la vista).
- Detección: genera una alerta para **cualquier registro DNS que contenga `dynamicObject`/`entryTTL`** mediante logs de replicación/eventos; los registros transitorios rara vez aparecen en los logs DNS estándar.<sup>[[1]](#references)</sup>

## Brecha de delta-sync híbrida de Entra ID (nota)

- La sincronización delta de Entra Connect depende de **tombstones** para detectar eliminaciones. Un **usuario dinámico local** puede sincronizarse con Entra ID, expirar y eliminarse sin tombstone; la sincronización delta no eliminará la cuenta cloud, dejando un **usuario activo huérfano de Entra** hasta que se fuerce una **sincronización inicial/completa** o una limpieza manual en cloud.<sup>[[1]](#references)</sup>



## References

- [1] [Objetos dinámicos en Active Directory: la amenaza sigilosa](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Aventuras en el comportamiento, los informes y la explotación del grupo principal](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configuración de los límites de TTL](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: Requisitos de DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
