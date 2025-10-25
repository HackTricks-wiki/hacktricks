# Desencadenadores de Servicios de Windows: Enumeración y Abuso

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers permiten al Service Control Manager (SCM) iniciar/detener un servicio cuando ocurre una condición (p. ej., una dirección IP se vuelve disponible, se intenta una conexión a un named pipe, se publica un evento ETW). Incluso cuando no tienes derechos SERVICE_START sobre un servicio objetivo, aún puedes ser capaz de iniciarlo provocando que su trigger se dispare.

Esta página se centra en la enumeración amigable para el atacante y en formas de baja fricción para activar triggers comunes.

> Tip: Starting a privileged built-in service (e.g., RemoteRegistry, WebClient/WebDAV, EFS) can expose new RPC/named-pipe listeners and unlock further abuse chains.

## Enumeración de Desencadenadores de Servicios

- sc.exe (local)
- List a service's triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers live under: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump recursively: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Call QueryServiceConfig2 with SERVICE_CONFIG_TRIGGER_INFO (8) to retrieve SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- El SCM puede consultarse de forma remota para obtener información de triggers usando MS‑SCMR. TrustedSec’s Titanis expone esto: `Scm.exe qtriggers`.
- Impacket defines the structures in msrpc MS-SCMR; you can implement a remote query using those.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Estos inician un servicio cuando un cliente intenta comunicarse con un endpoint IPC. Útil para usuarios de bajos privilegios porque el SCM arrancará automáticamente el servicio antes de que tu cliente pueda realmente conectarse.

- Named pipe trigger
- Behavior: A client connection attempt to \\.\pipe\<PipeName> causes the SCM to start the service so it can begin listening.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Querying the Endpoint Mapper (EPM, TCP/135) for an interface UUID associated with a service causes the SCM to start it so it can register its endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Un servicio puede registrar un trigger ligado a un proveedor/evento ETW. Si no hay filtros adicionales (keyword/level/binary/string), cualquier evento de ese proveedor iniciará el servicio.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitting matching events typically requires code that logs to that provider; if no filters are present, any event suffices.

### Group Policy Triggers

Subtipos: Machine/User. En equipos unidos al dominio donde exista la política correspondiente, el trigger se ejecuta al arranque. `gpupdate` por sí solo no activará sin cambios, pero:

- Activation: `gpupdate /force`
- Si el tipo de política relevante existe, esto causa de forma fiable que el trigger se dispare y arranque el servicio.

### IP Address Available

Se dispara cuando se obtiene la primera IP (o se pierde la última). A menudo se activa en el arranque.

- Activation: Toggle connectivity to retrigger, e.g.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Inicia un servicio cuando llega una interfaz de dispositivo coincidente. Si no se especifica un data item, cualquier dispositivo que coincida con el GUID de subtipo del trigger lo disparará. Evaluado en el arranque y al hacer hot‑plug.

- Activation: Attach/insert a device (physical or virtual) that matches the class/hardware ID specified by the trigger subtype.

### Domain Join State

A pesar de la redacción confusa en MSDN, esto evalúa el estado de dominio en el arranque:
- DOMAIN_JOIN_GUID → start the service if domain-joined
- DOMAIN_LEAVE_GUID → start the service only if NOT domain-joined

### System State Change – WNF (undocumented)

Algunos servicios usan triggers basados en WNF no documentados (SERVICE_TRIGGER_TYPE 0x7). La activación requiere publicar el estado WNF relevante; los detalles dependen del nombre del estado. Antecedentes de investigación: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Observado en Windows 11 para algunos servicios (p. ej., CDPSvc). La configuración agregada se almacena en:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

El valor Trigger de un servicio es un GUID; la subclave con ese GUID define el evento agregado. Disparar cualquiera de los eventos constituyentes inicia el servicio.

### Firewall Port Event (quirks and DoS risk)

Un trigger limitado a un puerto/protocolo específico se ha observado que se inicia con cualquier cambio en reglas de firewall (disable/delete/add), no solo en el puerto especificado. Peor aún, configurar un puerto sin protocolo puede corromper el inicio de BFE a través de reboots, provocando una cascada de fallos en muchos servicios y rompiendo la gestión del firewall. Tratar con extrema precaución.

## Flujo de trabajo práctico

1) Enumera triggers en servicios interesantes (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Si existe un Network Endpoint trigger:
- Named pipe → intenta abrir un cliente a \\.\pipe\<PipeName>
- RPC endpoint → realiza una consulta del Endpoint Mapper para el interface UUID

3) Si existe un ETW trigger:
- Comprueba el provider y los filtros con `sc.exe qtriggerinfo`; si no hay filtros, cualquier evento de ese provider iniciará el servicio

4) Para triggers de Group Policy/IP/Device/Domain:
- Usa palancas ambientales: `gpupdate /force`, toggle de NICs, hot‑plug de dispositivos, etc.

## Related

- After starting a privileged service via a Named Pipe trigger, you may be able to impersonate it:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Resumen rápido de comandos

- List triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Notas de detección y hardening

- Baseline y audita TriggerInfo a través de los servicios. También revisa HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents para triggers agregados.
- Monitoriza búsquedas sospechosas al EPM por UUIDs de servicios privilegiados y intentos de conexión a named‑pipe que precedan a inicios de servicios.
- Restringe quién puede modificar service triggers; trata fallos inesperados de BFE tras cambios de triggers como algo sospechoso.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
