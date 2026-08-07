# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

I/O Kit es un **framework de controladores de dispositivos** de código abierto y orientado a objetos dentro del kernel XNU, que gestiona **controladores de dispositivos cargados dinámicamente**. Permite añadir código modular al kernel sobre la marcha, proporcionando compatibilidad con hardware diverso.

Los controladores de IOKit básicamente **exportan funciones desde el kernel**. Los **tipos** de parámetros de estas funciones están **predefinidos** y se verifican. Además, al igual que XPC, IOKit es simplemente otra capa **sobre los mensajes de Mach**.

El **código del kernel XNU de IOKit** está disponible como código abierto por parte de Apple en [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Además, los componentes de IOKit en el espacio de usuario también están disponibles como código abierto en [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Sin embargo, **ningún controlador de IOKit** está disponible como código abierto. Aun así, ocasionalmente una versión de un controlador puede incluir símbolos que facilitan su depuración. Consulta cómo [**obtener las extensiones del controlador desde el firmware aquí**](#ipsw)**.**

Está escrito en **C++**. Puedes obtener símbolos C++ desmanglados con:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Las **funciones expuestas** de IOKit podrían realizar **comprobaciones de seguridad adicionales** cuando un cliente intenta llamar a una función, pero ten en cuenta que las aplicaciones normalmente están **limitadas** por el **sandbox** en cuanto a las funciones de IOKit con las que pueden interactuar.

## Drivers

En macOS se encuentran en:

- **`/System/Library/Extensions`**
- Archivos KEXT integrados en el sistema operativo OS X.
- **`/Library/Extensions`**
- Archivos KEXT instalados por software de terceros

En iOS se encuentran en:

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Hasta el número 9, los drivers listados están **cargados en la dirección 0**. Esto significa que no son drivers reales, sino que forman **parte del kernel y no se pueden descargar**.

Para encontrar extensiones específicas puedes usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para cargar y descargar extensiones del kernel, usa:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

El **IORegistry** es una parte crucial del framework IOKit en macOS e iOS que funciona como una base de datos para representar la configuración y el estado del hardware del sistema. Es una **colección jerárquica de objetos que representan todo el hardware y los drivers** cargados en el sistema, así como sus relaciones entre sí.

Puedes obtener el IORegistry usando el CLI **`ioreg`** para inspeccionarlo desde la consola (especialmente útil para iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Puedes descargar **`IORegistryExplorer`** desde **Xcode Additional Tools** en [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e inspeccionar el **IORegistry de macOS** mediante una interfaz **gráfica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

En IORegistryExplorer, los «planes» se utilizan para organizar y mostrar las relaciones entre diferentes objetos del IORegistry. Cada plano representa un tipo específico de relación o una vista concreta de la configuración del hardware y los drivers del sistema. Estos son algunos de los planos comunes que puedes encontrar en IORegistryExplorer:

1. **IOService Plane**: Es el plano más general y muestra los objetos de servicio que representan drivers y nubs (canales de comunicación entre drivers). Muestra las relaciones proveedor-cliente entre estos objetos.
2. **IODeviceTree Plane**: Este plano representa las conexiones físicas entre los dispositivos tal como están conectados al sistema. Se utiliza habitualmente para visualizar la jerarquía de dispositivos conectados mediante buses como USB o PCI.
3. **IOPower Plane**: Muestra los objetos y sus relaciones en términos de gestión de energía. Puede mostrar qué objetos afectan al estado de energía de otros, lo que resulta útil para depurar problemas relacionados con la energía.
4. **IOUSB Plane**: Se centra específicamente en los dispositivos USB y sus relaciones, y muestra la jerarquía de los hubs USB y los dispositivos conectados.
5. **IOAudio Plane**: Este plano sirve para representar los dispositivos de audio y sus relaciones dentro del sistema.
6. ...

## Ejemplo de código de comunicación con un driver

El siguiente código se conecta al servicio de IOKit `YourServiceNameHere` y llama al selector 0:

- Primero llama a **`IOServiceMatching`** y **`IOServiceGetMatchingServices`** para obtener el servicio.
- Después establece una conexión llamando a **`IOServiceOpen`**.
- Finalmente llama a una función con **`IOConnectCallScalarMethod`**, indicando el selector 0 (el selector es el número asignado a la función que quieres llamar).

<details>
<summary>Ejemplo de llamada desde el espacio de usuario a un selector de un driver</summary>
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
</details>

Hay **otras** funciones que se pueden utilizar para llamar a funciones de IOKit aparte de **`IOConnectCallScalarMethod`**, como **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing del entrypoint del driver

Podrías obtenerlos, por ejemplo, de una [**imagen de firmware (ipsw)**](#ipsw). Luego, cárgala en tu decompiler favorito.

Podrías comenzar a decompilar la función **`externalMethod`**, ya que esta es la función del driver que recibirá la llamada y llamará a la función correcta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Esa horrible llamada demangled significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Observa que en la definición anterior falta el parámetro **`self`**; la definición correcta sería:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
En realidad, puedes encontrar la definición real en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Con esta información puedes reescribir Ctrl+Right -> `Edit function signature` y establecer los tipos conocidos:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

El nuevo código decompilado se verá así:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Para el siguiente paso necesitamos tener definida la struct **`IOExternalMethodDispatch2022`**. Es opensource en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), podrías definirla así:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Ahora, siguiendo `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, puedes ver muchos datos:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Cambia el tipo de datos a **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

después del cambio:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Y como ahora sabemos que ahí tenemos un **array de 7 elementos** (comprueba el código decompilado final), haz clic para crear un array de 7 elementos:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Después de crear el array, puedes ver todas las funciones exportadas:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si lo recuerdas, para **llamar** a una función **exportada** desde user space no necesitamos llamar al nombre de la función, sino al **número del selector**. Aquí puedes ver que el selector **0** es la función **`initializeDecoder`**, el selector **1** es **`startDecoder`** y el selector **2** es **`initializeEncoder`**...

## Superficie de ataque reciente de IOKit (2023–2025)

- **Captura de pulsaciones mediante IOHIDFamily** – CVE-2024-27799 (14.5) mostró que un cliente `IOHIDSystem` permisivo podía capturar eventos HID incluso con secure input; asegúrate de que los handlers de `externalMethod` hagan cumplir los entitlements en lugar de basarse únicamente en el tipo de user-client.<sup>[[2]](#references)</sup>
- **Corrupción de memoria en IOGPUFamily** – CVE-2024-44197 y CVE-2025-24257 corrigieron escrituras OOB accesibles desde apps sandboxed que pasaban datos de longitud variable malformados a user clients de GPU; el bug habitual consiste en una validación deficiente de los límites alrededor de los argumentos de `IOConnectCallStructMethod`.<sup>[[1]](#references)</sup>
- **Monitorización de pulsaciones heredada** – CVE-2023-42891 (14.2) confirmó que los user clients HID siguen siendo un vector de sandbox-escape; aplica fuzzing a cualquier driver que exponga colas de teclado/eventos.<sup>[[3]](#references)</sup>

### Consejos rápidos de triage y fuzzing

- Enumera todos los métodos externos de un user client desde userland para preparar un fuzzer:
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- Al hacer reversing, presta atención a los recuentos de `IOExternalMethodDispatch2022`. Un patrón de bug común en CVE recientes es la incoherencia entre `structureInputSize`/`structureOutputSize` y la longitud real de `copyin`, lo que provoca un heap OOB en `IOConnectCallStructMethod`.
- La reachability desde el Sandbox sigue dependiendo de los entitlements. Antes de dedicar tiempo a un target, comprueba si el cliente está permitido desde una app de terceros:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Para bugs de GPU/iomfb, pasar arrays sobredimensionados mediante `IOConnectCallMethod` suele bastar para activar límites incorrectos. Harness mínimo (selector X) para activar una confusión de tamaños:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Drivers en espacio de usuario

### Información básica

**DriverKit** es el reemplazo en espacio de usuario de Apple para las extensiones del kernel (kexts), introducido en macOS 10.15. Los binarios de DriverKit (bundles `.dext`) se ejecutan como procesos en espacio de usuario, pero se comunican directamente con el kernel mediante una interfaz IOKit privilegiada.<sup>[[4]](#references)</sup>

Las extensiones de DriverKit gestionan hardware:
- Controladores y dispositivos **USB**
- Dispositivos **Thunderbolt** / PCIe
- Dispositivos **HID** (teclados, ratones y mandos de juego)
- Hardware de **Audio**
- Interfaces de **Networking**
- Dispositivos **Serial** y de **Block Storage**

A diferencia de los kexts (que requerían arrancar con SIP deshabilitado o notarización), las extensiones de DriverKit se instalan mediante `SystemExtensions.framework` y solo requieren una **aprobación del usuario** única.<sup>[[5]](#references)</sup>

### Descubrimiento y enumeración
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### Implicaciones de seguridad

> [!WARNING]
> Los binarios de DriverKit tienen un **canal de comunicación directo con el kernel**. Enviar mensajes malformados a través de este canal puede activar vulnerabilidades del kernel. Cada driver registra clases user-client específicas, y las llamadas `IOConnectCallMethod` malformadas pueden provocar corrupción de memoria del kernel.

**Superficie de ataque:**
1. **Fuzzing de mensajes IOKit del kernel** — Cada user-client de DriverKit expone selectores invocables desde el espacio de usuario. Los argumentos malformados activan bugs del kernel.
2. **Suplantación de dispositivos USB** — Un binario de DriverKit USB comprometido puede presentar un perfil de dispositivo USB malicioso (por ejemplo, emular un teclado para realizar HID injection).
3. **Ataques DMA** — Las extensiones DriverKit de PCIe/Thunderbolt tienen acceso DMA potencial a la memoria física.
4. **Persistencia** — Una vez instalados como system extension, los binarios de DriverKit persisten tras los reinicios y las actualizaciones de la app.

### Fuzzing de User-Client de DriverKit IOKit
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### CVEs de DriverKit

| CVE | Descripción |
|---|---|
| CVE-2022-26766 | Vulnerabilidad en la pila USB de DriverKit — ejecución de código en el kernel |
| CVE-2021-30838 | Confusión de tipos en el user-client de IOKit en controladores gráficos |
| CVE-2024-44197 | Escritura OOB en IOGPUFamily mediante argumentos de DriverKit malformados |

## Referencias

- [1] [Actualizaciones de seguridad de Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – resumen de IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Actualizaciones de seguridad de Apple – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
