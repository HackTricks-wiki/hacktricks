# Inyección de Aplicaciones .Net en macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>

**Este es un resumen del post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). ¡Consultalo para más detalles!**

## Depuración de .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Estableciendo una Sesión de Depuración** <a href="#net-core-debugging" id="net-core-debugging"></a>

El manejo de la comunicación entre el depurador y el depurado en .NET es gestionado por [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Este componente establece dos named pipes por proceso .NET como se ve en [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), que son iniciados a través de [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Estos pipes tienen los sufijos **`-in`** y **`-out`**.

Al visitar el directorio **`$TMPDIR`** del usuario, se pueden encontrar FIFOs de depuración disponibles para depurar aplicaciones .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) es responsable de gestionar la comunicación desde un depurador. Para iniciar una nueva sesión de depuración, un depurador debe enviar un mensaje a través del pipe `out` comenzando con una estructura `MessageHeader`, detallada en el código fuente de .NET:
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
Este encabezado se envía al objetivo utilizando la llamada al sistema `write`, seguido por la estructura `sessionRequestData` que contiene un GUID para la sesión:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Una operación de lectura en la tubería `out` confirma el éxito o fracaso del establecimiento de la sesión de depuración:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Leyendo la memoria
Una vez que se establece una sesión de depuración, la memoria se puede leer utilizando el tipo de mensaje [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La función readMemory está detallada, realizando los pasos necesarios para enviar una solicitud de lectura y recuperar la respuesta:
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
El concepto de prueba completo (POC) está disponible [aquí](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Escribiendo en la memoria

De manera similar, la memoria puede ser escrita utilizando la función `writeMemory`. El proceso implica establecer el tipo de mensaje en `MT_WriteMemory`, especificar la dirección y longitud de los datos, y luego enviar los datos:
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

## Ejecución de código en .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Para ejecutar código, es necesario identificar una región de memoria con permisos rwx, lo cual se puede hacer utilizando vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Encontrar un lugar para sobrescribir un puntero de función es necesario, y en .NET Core, esto se puede hacer apuntando a la **Tabla de Funciones Dinámicas (DFT)**. Esta tabla, detallada en [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), es utilizada por el tiempo de ejecución para funciones auxiliares de compilación JIT.

Para sistemas x64, la caza de firmas se puede utilizar para encontrar una referencia al símbolo `_hlpDynamicFuncTable` en `libcorclr.dll`.

La función de depuración `MT_GetDCB` proporciona información útil, incluida la dirección de una función auxiliar, `m_helperRemoteStartAddr`, que indica la ubicación de `libcorclr.dll` en la memoria del proceso. Esta dirección se utiliza luego para iniciar la búsqueda de la DFT y sobrescribir un puntero de función con la dirección del shellcode.

El código POC completo para la inyección en PowerShell es accesible [aquí](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Referencias

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>
