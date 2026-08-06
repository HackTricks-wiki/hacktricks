# Windows Service Triggers: Enumeración y abuso

{{#include ../../banners/hacktricks-training.md}}

Los Windows Service Triggers permiten al Service Control Manager (SCM) iniciar/detener un servicio cuando ocurre una condición (por ejemplo, cuando una dirección IP está disponible, se intenta realizar una conexión a una named pipe o se publica un evento ETW). Incluso cuando no tienes derechos `SERVICE_START` sobre un servicio objetivo, es posible que aún puedas iniciarlo provocando que su trigger se active.<sup>[[1]](#references)</sup>

Esta página se centra en la enumeración orientada al atacante y en formas sencillas de activar triggers comunes.

> Consejo: Iniciar un servicio integrado privilegiado (por ejemplo, RemoteRegistry, WebClient/WebDAV o EFS) puede exponer nuevos listeners RPC/named-pipe y permitir cadenas de abuso adicionales.

## Enumeración de Service Triggers

- sc.exe (local)
- Listar los triggers de un servicio: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Los triggers se encuentran en: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Volcado recursivo: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Llamar a QueryServiceConfig2 con SERVICE_CONFIG_TRIGGER_INFO (8) para recuperar SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] y SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC mediante MS-SCMR (remoto)
- El SCM puede consultarse remotamente para obtener información de los triggers mediante MS-SCMR. Titanis de TrustedSec expone esta funcionalidad: `Scm.exe qtriggers`.
- Impacket define las estructuras en msrpc MS-SCMR; puedes implementar una consulta remota usando estas estructuras.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (enumeración masiva)
- Lista rápidamente cada servicio que expone una clave `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programático)
- El módulo `NtObjectManager` de James Forshaw expone `Get-Win32ServiceTrigger` para analizar los metadatos de los triggers sin extraer la salida de `sc.exe`.

## Tipos de triggers de alto valor y cómo activarlos

### Triggers de Network Endpoint

Estos inician un servicio cuando un cliente intenta comunicarse con un endpoint IPC. Son útiles para usuarios con pocos privilegios porque el SCM inicia automáticamente el servicio antes de que tu cliente pueda conectarse realmente.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Comportamiento: Un intento de conexión de un cliente a \\.\pipe\<PipeName> hace que el SCM inicie el servicio para que pueda comenzar a escuchar.
- Activación (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Nota interna: los named-pipe triggers utilizan `npsvctrig.sys`, un minifilter del sistema de archivos que supervisa las aperturas contra los nombres de pipes registrados en los triggers. Por eso el intento de apertura puede iniciar el servicio incluso antes de que el propio servicio haya creado o esté escuchando en la pipe.<sup>[[5]](#references)</sup>
- Consulta también: Named Pipe Client Impersonation para el abuso posterior al inicio.

- RPC endpoint trigger (Endpoint Mapper)
- Comportamiento: Consultar el Endpoint Mapper (EPM, TCP/135) para obtener un UUID de interfaz asociado a un servicio hace que el SCM lo inicie para que pueda registrar su endpoint.
- Activación (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Triggers personalizados (ETW)

Un servicio puede registrar un trigger asociado a un proveedor/evento ETW. Si no se configuran filtros adicionales (keyword/level/binary/string), cualquier evento de ese proveedor iniciará el servicio.<sup>[[1]](#references)</sup>

- Ejemplo (WebClient/WebDAV): proveedor {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Listar el trigger: `sc.exe qtriggerinfo webclient`
- Verificar que el proveedor esté registrado: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitir eventos coincidentes normalmente requiere código que registre eventos en ese proveedor; si no hay filtros, cualquier evento será suficiente.
- Forma mínima en C para activar el proveedor (cuando no hay filtros ETW adicionales configurados):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Triggers de Group Policy

Subtipos: Machine/User. En hosts unidos a un dominio donde exista la política correspondiente, el trigger se ejecuta durante el arranque. `gpupdate` por sí solo no lo activará si no hay cambios, pero:<sup>[[1]](#references)</sup>

- Activación: `gpupdate /force`
- Si existe el tipo de política relevante, esto provoca de forma fiable que el trigger se active e inicie el servicio.

### Dirección IP disponible

Se activa cuando se obtiene la primera IP (o se pierde la última). A menudo se activa durante el arranque.<sup>[[1]](#references)</sup>

- Activación: Alternar la conectividad para volver a activarlo, por ejemplo:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Llegada de una Device Interface

Inicia un servicio cuando llega una device interface coincidente. Si no se especifica ningún elemento de datos, cualquier dispositivo que coincida con el GUID del subtipo del trigger activará el trigger. Se evalúa durante el arranque y al conectar dispositivos en caliente.<sup>[[1]](#references)</sup>

- Activación: Conecta o inserta un dispositivo (físico o virtual) que coincida con la clase/ID de hardware especificado por el subtipo del trigger.

### Estado de unión al dominio

A pesar de la confusa redacción de MSDN, esto evalúa el estado del dominio durante el arranque:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → iniciar el servicio si está unido a un dominio
- DOMAIN_LEAVE_GUID → iniciar el servicio solo si NO está unido a un dominio

### Cambio de estado del sistema – WNF (no documentado)

Algunos servicios utilizan triggers WNF no documentados (`SERVICE_TRIGGER_TYPE 0x7`). La activación requiere publicar el estado WNF relevante; los detalles dependen del nombre del estado. Contexto de investigación: Windows Notification Facility internals.

### Aggregate Service Triggers (no documentados)

Observados en Windows 11 en algunos servicios (por ejemplo, CDPSvc). La configuración agregada se almacena en:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

El valor Trigger de un servicio es un GUID; la subclave con ese GUID define el evento agregado. Activar cualquiera de los eventos constituyentes inicia el servicio.<sup>[[1]](#references)</sup>

### Firewall Port Event (particularidades y riesgo de DoS)

Se ha observado que un trigger asociado a un puerto/protocolo específico se activa ante cualquier cambio en una regla del firewall (deshabilitar/eliminar/añadir), no solo ante el puerto especificado. Además, configurar un puerto sin un protocolo puede corromper el inicio de BFE tras los reinicios, provocando numerosos fallos de servicios e interrumpiendo la administración del firewall. Trátalo con extrema precaución.<sup>[[1]](#references)</sup>

## Flujo de trabajo práctico

1) Enumera los triggers de servicios interesantes (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Si existe un Network Endpoint trigger:
- Named pipe → intenta abrirla como cliente mediante \\.\pipe\<PipeName>
- RPC endpoint → realiza una búsqueda en el Endpoint Mapper para el UUID de interfaz

3) Si existe un trigger ETW:
- Comprueba el proveedor y los filtros con `sc.exe qtriggerinfo`; si no hay filtros, cualquier evento de ese proveedor iniciará el servicio

4) Para triggers de Group Policy/IP/Device/Domain:
- Utiliza palancas del entorno: `gpupdate /force`, alternar NICs, conectar dispositivos en caliente, etc.

## Relacionado

- Después de iniciar un servicio privilegiado mediante un Named Pipe trigger, es posible que puedas suplantarlo:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Resumen rápido de comandos

- Listar triggers (local): `sc.exe qtriggerinfo <Service>`
- Vista del Registry: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remoto (Titanis): `Scm.exe qtriggers`
- Comprobación del proveedor ETW (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Notas para operadores

- Comprueba primero el tipo de inicio del servicio con `sc.exe qc <Service>`. Si es `DISABLED`, activar el trigger no es suficiente; primero debes encontrar una forma de cambiar la configuración.
- Los servicios iniciados mediante triggers pueden detenerse de nuevo cuando quedan inactivos. Si tu acción posterior depende de un listener de corta duración (RPC/named pipe/WebDAV), activa el trigger y consúmelo inmediatamente.
- `sc.exe qtriggerinfo` no comprende completamente todos los tipos de triggers no documentados. Para los aggregate triggers en versiones más recientes de Windows, confirma el GUID subyacente y los eventos constituyentes en `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Notas de detección y hardening

- Crea una línea base y audita `TriggerInfo` en todos los servicios. Revisa también `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` para detectar aggregate triggers.
- Supervisa las búsquedas EPM sospechosas de UUIDs de servicios privilegiados y los intentos de conexión a named pipes que precedan al inicio de servicios.
- Restringe quién puede modificar los triggers de los servicios; considera sospechosos los fallos inesperados de BFE posteriores a cambios en los triggers.

## Referencias
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
