# Inyección de aplicaciones .Net

{{#include ../../../banners/hacktricks-training.md}}

**Este es un resumen del post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). ¡Consúltalo para obtener más detalles!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 y posteriores admiten la variable de entorno `DOTNET_STARTUP_HOOKS`. Cada ruta debe identificar un ensamblado administrado que contenga un tipo global `StartupHook` con un método `public static void Initialize()`. El host carga los ensamblados y llama a sus inicializadores de forma síncrona antes del punto de entrada `Main` de la aplicación, lo que proporciona control del entorno y un primitive directo de ejecución de código pre-main mediante una DLL legible.<sup>[[2]](#references)</sup>
```csharp
// StartupHook.cs — compile as a class-library assembly.
using System.IO;

internal class StartupHook
{
public static void Initialize()
{
File.WriteAllText("/tmp/dotnet-startup-hook-executed", "executed\n");
}
}
```

```bash
dotnet new classlib -n StartupHookPayload -f net8.0
cp StartupHook.cs StartupHookPayload/Class1.cs
dotnet build StartupHookPayload -c Release

DOTNET_STARTUP_HOOKS="$PWD/StartupHookPayload/bin/Release/net8.0/StartupHookPayload.dll" \
dotnet /path/to/TargetApplication.dll
```
El hook assembly debe ser compatible con el runtime y las dependencias de la aplicación. Las rutas relativas que contienen separadores de directorios se rechazan; usa una ruta absoluta o un nombre de assembly resoluble desde el contexto de carga predeterminado. Los startup hooks están deshabilitados de forma predeterminada en aplicaciones trimmed, y los hosts nativos personalizados pueden proporcionar directamente las propiedades del runtime en lugar de heredarlas del entorno.<sup>[[2]](#references)</sup>

Los launchers defensivos deben borrar `DOTNET_STARTUP_HOOKS`, impedir escrituras no confiables en las rutas de la aplicación y de los assemblies compartidos, y probar por separado los despliegues self-contained y trimmed.

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Establecimiento de una sesión de debugging** <a href="#net-core-debugging" id="net-core-debugging"></a>

La gestión de la comunicación entre el debugger y el debuggee en .NET está a cargo de [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Este componente configura dos named pipes por cada proceso .NET, como se observa en [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), que se inician mediante [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Estos pipes llevan los sufijos **`-in`** y **`-out`**.

Al visitar el **`$TMPDIR`** del usuario, se pueden encontrar FIFOs de debugging disponibles para depurar aplicaciones .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) se encarga de gestionar la comunicación desde un debugger. Para iniciar una nueva sesión de debugging, un debugger debe enviar un mensaje mediante el pipe `out` que comience con una estructura `MessageHeader`, detallada en el código fuente de .NET:
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
Para solicitar una nueva sesión, esta estructura se completa de la siguiente manera, estableciendo el tipo de mensaje en `MT_SessionRequest` y la versión del protocolo en la versión actual:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Este encabezado se envía después al objetivo mediante la syscall `write`, seguido de la estructura `sessionRequestData` que contiene un GUID para la sesión:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Una operación de lectura en la pipe `out` confirma el éxito o el fracaso del establecimiento de la sesión de debugging:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Reading Memory

Una vez establecida una sesión de debugging, la memoria se puede leer mediante el tipo de mensaje [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La función readMemory se detalla a continuación y realiza los pasos necesarios para enviar una solicitud de lectura y recuperar la respuesta:
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
La prueba de concepto (POC) completa está disponible [aquí](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Escritura de memoria

De forma similar, se puede escribir en la memoria usando la función `writeMemory`. El proceso consiste en establecer el tipo de mensaje en `MT_WriteMemory`, especificar la dirección y la longitud de los datos y, a continuación, enviar los datos:
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
El POC asociado está disponible [aquí](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Para ejecutar código, es necesario identificar una región de memoria con permisos rwx, lo que se puede hacer mediante vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Es necesario localizar un lugar donde sobrescribir un puntero de función y, en .NET Core, esto puede hacerse apuntando a la **Dynamic Function Table (DFT)**. Esta tabla, detallada en [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), es utilizada por el runtime para las funciones auxiliares de compilación JIT.

En sistemas x64, puede utilizarse signature hunting para encontrar una referencia al símbolo `_hlpDynamicFuncTable` en `libcorclr.dll`.

La función de depuración `MT_GetDCB` proporciona información útil, incluida la dirección de una función auxiliar, `m_helperRemoteStartAddr`, que indica la ubicación de `libcorclr.dll` en la memoria del proceso. Esta dirección se utiliza para iniciar una búsqueda de la DFT y sobrescribir un puntero de función con la dirección del shellcode.

El código POC completo para la inyección en PowerShell está disponible [aquí](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - Inyección en macOS mediante Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Diseño del host startup hook de .NET runtime](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
