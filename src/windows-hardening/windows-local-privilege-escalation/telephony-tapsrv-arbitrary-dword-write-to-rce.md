# Escritura arbitraria de DWORD de tapsrv de Telephony a RCE (modo TAPI server)

{{#include ../../banners/hacktricks-training.md}}

Cuando el servicio Windows Telephony (TapiSrv, `tapisrv.dll`) está configurado como un **TAPI server**, expone la interfaz **`tapsrv` MSRPC a través de la named pipe `\pipe\tapsrv`** a clientes SMB autenticados. Un error de diseño en la entrega de eventos asíncronos para clientes remotos permite a un atacante convertir un handle de mailslot en una **escritura controlada de 4 bytes en cualquier archivo existente con permisos de escritura para `NETWORK SERVICE`**. Esta primitiva puede encadenarse para sobrescribir la lista de administradores de Telephony y abusar de una **carga arbitraria de DLL exclusiva para administradores** para ejecutar código como `NETWORK SERVICE`.<sup>[[1]](#references)</sup>

## Superficie de ataque

- **Exposición remota solo cuando está habilitada**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` debe permitir el uso compartido (o configurarse mediante `TapiMgmt.msc` / `tcmsetup /c <server>`). De forma predeterminada, `tapsrv` solo está disponible localmente.
- Interfaz: MS-TRP (`tapsrv`) a través de **SMB named pipe**, por lo que el atacante necesita una autenticación SMB válida.
- Cuenta del servicio: `NETWORK SERVICE` (inicio manual, bajo demanda).<sup>[[1]](#references)</sup>

## Primitiva: confusión de la ruta del mailslot → escritura arbitraria de DWORD
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicializa la entrega de eventos asíncronos. En modo pull, el servicio hace lo siguiente:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sin validar que `pszDomainUser` sea una ruta de mailslot (`\\*\MAILSLOT\...`). Se acepta cualquier **ruta del sistema de archivos existente** en la que `NETWORK SERVICE` tenga permisos de escritura.
- Cada escritura de evento asíncrono almacena un único **`DWORD` = `InitContext`** (controlado por el atacante en la solicitud `Initialize` posterior) en el handle abierto, lo que proporciona una primitiva **write-what/write-where de 4 bytes**.<sup>[[1]](#references)</sup>

## Forzar escrituras deterministas
1. **Abrir el archivo objetivo**: ejecutar `ClientAttach` con `pszDomainUser = <existing writable path>` (por ejemplo, `C:\Windows\TAPI\tsec.ini`).
2. Para cada `DWORD` que se quiera escribir, ejecutar esta secuencia RPC contra `ClientRequest`:
- `Initialize` (`Req_Func 47`): establecer `InitContext = <4-byte value>` y `pszModuleName = DIALER.EXE` (u otra entrada superior de la lista de prioridades por usuario).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registra la aplicación de línea y recalcula el recipient de mayor prioridad).
- `TRequestMakeCall` (`Req_Func 121`): fuerza `NotifyHighestPriorityRequestRecipient`, generando el evento asíncrono.
- `GetAsyncEvents` (`Req_Func 0`): extrae y completa la escritura.
- Ejecutar de nuevo `LRegisterRequestRecipient` con `bEnable = 0` (anular el registro).
- `Shutdown` (`Req_Func 86`) para desmontar la aplicación de línea.
- Control de prioridad: el recipient de “mayor prioridad” se elige comparando `pszModuleName` con `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (que se lee mientras se suplanta al cliente). Si es necesario, insertar el nombre del módulo mediante `LSetAppPriority` (`Req_Func 69`).
- El archivo **debe existir previamente** porque se utiliza `OPEN_EXISTING`. Candidatos comunes con permisos de escritura para `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## De la escritura de DWORD a RCE dentro de TapiSrv
1. **Concederse privilegios de “administrador” de Telephony**: seleccionar como objetivo `C:\Windows\TAPI\tsec.ini` y añadir `[TapiAdministrators]\r\n<DOMAIN\\user>=1` mediante las escrituras de 4 bytes anteriores. Iniciar una sesión nueva (`ClientAttach`) para que el servicio vuelva a leer el INI y establezca `ptClient->dwFlags |= 9` para la cuenta.
2. **Carga de DLL exclusiva para administradores**: enviar `GetUIDllName` con `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` y proporcionar una ruta mediante `dwProviderFilenameOffset`. Para los administradores, el servicio ejecuta `LoadLibrary(path)` y después llama al export `TSPI_providerUIIdentify`:
- Funciona con rutas UNC a un recurso compartido SMB real de Windows; algunos servidores SMB del atacante fallan con `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: colocar lentamente una DLL local mediante la misma primitiva de escritura de 4 bytes y cargarla después.
3. **Payload**: el export se ejecuta como `NETWORK SERVICE`. Una DLL mínima puede ejecutar `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` y devolver un valor distinto de cero (por ejemplo, `0x1337`) para que el servicio descargue la DLL, confirmando la ejecución.<sup>[[1]](#references)</sup>

## Notas de hardening / detección
- Deshabilitar el modo TAPI server salvo que sea necesario; bloquear el acceso remoto a `\pipe\tapsrv`.
- Aplicar la validación del namespace de mailslot (`\\*\MAILSLOT\`) antes de abrir rutas proporcionadas por el cliente.
- Restringir las ACL de `C:\Windows\TAPI\tsec.ini` y monitorizar los cambios; generar alertas ante llamadas a `GetUIDllName` que carguen rutas no predeterminadas.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
