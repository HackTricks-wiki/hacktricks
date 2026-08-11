# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Cuando el servicio Windows Telephony (TapiSrv, `tapisrv.dll`) está configurado como un **TAPI server**, expone la interfaz **`tapsrv` MSRPC a través de la named pipe `\pipe\tapsrv`** a clientes SMB autenticados. CVE-2026-20931 en la entrega de eventos asíncronos permite a un atacante convertir un supuesto handle de mailslot en una **escritura controlada de 4 bytes en un archivo preexistente con permisos de escritura para `NETWORK SERVICE`**. La cadena publicada sobrescribe la lista de administradores de Telephony, alcanza una carga de DLL exclusiva para administradores y ejecuta código como `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Superficie de ataque

- **Exposición remota solo cuando está habilitada**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` debe permitir el uso compartido (o configurarse mediante `TapiMgmt.msc` / `tcmsetup /c <server>`). De forma predeterminada, `tapsrv` solo está disponible localmente.
- Interfaz: MS-TRP (`tapsrv`) a través de **SMB named pipe**, por lo que el atacante necesita autenticación SMB válida.
- Cuenta del servicio: `NETWORK SERVICE` (inicio manual, bajo demanda).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicializa la entrega de eventos asíncronos. En pull mode, el servicio ejecuta:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sin validar que `pszDomainUser` sea una ruta de mailslot (`\\*\MAILSLOT\...`). Se acepta cualquier **ruta existente del sistema de archivos** en la que `NETWORK SERVICE` tenga permisos de escritura.
- Cada escritura de evento asíncrono almacena un único **`DWORD` = `InitContext`** (controlado por el atacante en la solicitud `Initialize` posterior) en el handle abierto, lo que proporciona una primitiva **write-what/write-where de 4 bytes**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Abrir el archivo objetivo**: ejecutar `ClientAttach` con `pszDomainUser = <existing writable path>` (por ejemplo, `C:\Windows\TAPI\tsec.ini`).
2. Para cada `DWORD` que se quiera escribir, ejecutar esta secuencia RPC contra `ClientRequest`:
- `Initialize` (`Req_Func 47`): establecer `InitContext = <4-byte value>` y `pszModuleName = DIALER.EXE` (u otra entrada superior de la priority list por usuario).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registra la line app y recalcula el recipient de mayor prioridad).
- `TRequestMakeCall` (`Req_Func 121`): fuerza `NotifyHighestPriorityRequestRecipient`, generando el evento asíncrono.
- `GetAsyncEvents` (`Req_Func 0`): extrae y completa la escritura.
- Ejecutar de nuevo `LRegisterRequestRecipient` con `bEnable = 0` (anular el registro).
- `Shutdown` (`Req_Func 86`) para cerrar la line app.
- Control de prioridad: el recipient de “highest priority” se selecciona comparando `pszModuleName` con `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (leído mientras se suplanta al cliente). Si es necesario, insertar el nombre del módulo mediante `LSetAppPriority` (`Req_Func 69`).
- El archivo **debe existir previamente** porque se utiliza `OPEN_EXISTING`. Candidatos comunes con permisos de escritura para `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Concederse permisos de Telephony “admin”**: seleccionar como objetivo `C:\Windows\TAPI\tsec.ini` y añadir `[TapiAdministrators]\r\n<DOMAIN\\user>=1` mediante las escrituras de 4 bytes anteriores. Iniciar una **nueva sesión** (`ClientAttach`) para que el servicio vuelva a leer el INI y establezca `ptClient->dwFlags |= 9` para la cuenta.
2. **Carga de DLL exclusiva para administradores**: enviar `GetUIDllName` con `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` y proporcionar una ruta mediante `dwProviderFilenameOffset`. Para los administradores, el servicio ejecuta `LoadLibrary(path)` y después llama al export `TSPI_providerUIIdentify`:
- Funciona con rutas UNC hacia un recurso compartido SMB real de Windows; algunos servidores SMB del atacante fallan con `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: depositar lentamente una DLL local mediante la misma primitive de escritura de 4 bytes y después cargarla.
3. **Payload**: el export se ejecuta bajo `NETWORK SERVICE`. Una DLL mínima puede ejecutar `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` y devolver un valor distinto de cero (por ejemplo, `0x1337`) para que el servicio descargue la DLL, confirmando la ejecución.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Instalar la actualización de seguridad de Microsoft para CVE-2026-20931. Deshabilitar de forma independiente el TAPI server mode salvo que sea necesario y bloquear el acceso remoto a `\pipe\tapsrv`.
- Aplicar la validación del namespace de mailslot (`\\*\MAILSLOT\`) antes de abrir rutas proporcionadas por el cliente.
- Restringir las ACL de `C:\Windows\TAPI\tsec.ini` y supervisar los cambios; generar alertas ante llamadas a `GetUIDllName` que carguen rutas no predeterminadas.<sup>[[1]](#references)</sup>

## References

- [1] [¿Quién está al teléfono? Explotando RCE en Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
