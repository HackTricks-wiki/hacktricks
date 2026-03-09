# Objetos dinámicos de AD (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mecánica y detección — conceptos básicos

- Cualquier objeto creado con la clase auxiliar **`dynamicObject`** obtiene **`entryTTL`** (cuenta regresiva en segundos) y **`msDS-Entry-Time-To-Die`** (expiración absoluta). Cuando `entryTTL` llega a 0 el Garbage Collector lo elimina sin tombstone/recycle-bin, borrando el creador/marcas de tiempo y bloqueando la recuperación.
- El TTL puede refrescarse actualizando `entryTTL`; los valores mínimos/por defecto se imponen en **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (soporta 1s–1y pero comúnmente por defecto es 86,400s/24h). Los objetos dinámicos no son compatibles en las particiones Configuration/Schema.
- La eliminación puede retrasarse unos minutos en DCs con poco tiempo de actividad (<24h), dejando una ventana estrecha para consultar/hacer backup de atributos. Detectar alertando sobre **nuevos objetos que lleven `entryTTL`/`msDS-Entry-Time-To-Die`** y correlacionando con SIDs huérfanos/enlaces rotos.

## Evasión de MAQ con equipos autodestructivos

- El valor por defecto **`ms-DS-MachineAccountQuota` = 10** permite que cualquier usuario autenticado cree equipos. Añadir `dynamicObject` durante la creación hace que el equipo se autodetruya y **libere la ranura de cuota** mientras borra evidencia.
- Ajuste en Powermad dentro de `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Un TTL corto (p. ej., 60s) a menudo falla para usuarios estándar; AD recurre a **`DynamicObjectDefaultTTL`** (ejemplo: 86,400s). ADUC puede ocultar `entryTTL`, pero consultas LDP/LDAP lo revelan.

## Pertenencia sigilosa al primary group

- Crea un **grupo de seguridad dinámico**, luego establece el **`primaryGroupID`** de un usuario al RID de ese grupo para obtener membresía efectiva que **no aparece en `memberOf`** pero sí se respeta en tokens de Kerberos/acceso.
- Al expirar el TTL **el grupo se elimina a pesar de la protección por primary-group**, dejando al usuario con un `primaryGroupID` corrupto apuntando a un RID inexistente y sin tombstone para investigar cómo se otorgó el privilegio.

## Contaminación de SID huérfano en AdminSDHolder

- Añade ACEs para un **usuario/grupo dinámico de corta duración** a **`CN=AdminSDHolder,CN=System,...`**. Tras la expiración del TTL el SID se vuelve **irresoluble (“Unknown SID”)** en el ACL plantilla, y **SDProp (~60 min)** propaga ese SID huérfano por todos los objetos protegidos Tier-0.
- La forense pierde atribución porque el principal ha desaparecido (sin DN de objeto eliminado). Monitorizar **nuevos principals dinámicos + SIDs huérfanos repentinos en AdminSDHolder/ACLs privilegiadas**.

## Ejecución dinámica de GPO con evidencia autodestructiva

- Crea un objeto **`groupPolicyContainer`** dinámico con un malicioso **`gPCFileSysPath`** (p. ej., share SMB al estilo GPODDITY) y **enlázalo vía `gPLink`** a una OU objetivo.
- Los clientes procesan la policy y obtienen contenido desde el SMB del atacante. Cuando el TTL expira, el objeto GPO (y `gPCFileSysPath`) desaparece; solo queda un **`gPLink`** GUID roto, eliminando evidencia LDAP del payload ejecutado.

## Redirección DNS efímera integrada en AD

- Los registros DNS de AD son objetos **`dnsNode`** en **DomainDnsZones/ForestDnsZones**. Crearlos como **dynamic objects** permite redirecciones temporales de host (captura de credenciales/MITM). Los clientes cachean la respuesta A/AAAA maliciosa; luego el registro se autodestruye y la zona parece limpia (DNS Manager puede necesitar recargar la zona para refrescar la vista).
- Detección: alertar sobre **cualquier registro DNS que lleve `dynamicObject`/`entryTTL`** vía replicación/logs de eventos; los registros transitorios raramente aparecen en logs DNS estándar.

## Brecha en delta-sync híbrido con Entra ID (Nota)

- Entra Connect delta sync depende de **tombstones** para detectar eliminaciones. Un **usuario on-prem dinámico** puede sincronizarse a Entra ID, expirar y eliminarse sin tombstone: el delta sync no eliminará la cuenta cloud, dejando un **usuario Entra huérfano y activo** hasta forzar un **full sync** manual.

## Referencias

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
