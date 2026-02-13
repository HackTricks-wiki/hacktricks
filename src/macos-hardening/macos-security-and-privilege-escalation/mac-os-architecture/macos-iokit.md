# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

El I/O Kit es un **framework de controladores de dispositivo** de código abierto y orientado a objetos en el kernel XNU; maneja **controladores de dispositivo cargados dinámicamente**. Permite añadir código modular al kernel sobre la marcha, soportando hardware diverso.

Los drivers IOKit básicamente **exportan funciones desde el kernel**. Los **tipos** de parámetros de esas funciones están **predefinidos** y son verificados. Además, al igual que XPC, IOKit es solo otra capa encima de los **Mach messages**.

El **código IOKit del kernel XNU** es de código abierto por Apple en [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Además, los componentes de espacio de usuario de IOKit también son de código abierto [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Sin embargo, **ningún driver IOKit** es de código abierto. De todos modos, de vez en cuando una versión de un driver puede venir con símbolos que facilitan su depuración. Check how to [**get the driver extensions from the firmware here**](#ipsw)**.**

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
> Las **funciones expuestas** de IOKit podrían realizar **controles de seguridad adicionales** cuando un cliente intenta llamar a una función, pero tenga en cuenta que las aplicaciones suelen estar **limitadas** por la **sandbox** respecto a con qué funciones de IOKit pueden interactuar.

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
Hasta el número 9, los controladores listados están **cargados en la dirección 0**. Esto significa que esos no son controladores reales sino **parte del kernel y no pueden ser descargados**.

Para encontrar extensiones específicas puedes usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para cargar y descargar extensiones del kernel, ejecute:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

El **IORegistry** es una parte crucial del framework IOKit en macOS e iOS que sirve como una base de datos para representar la configuración y el estado del hardware del sistema. Es una **colección jerárquica de objetos que representan todo el hardware y los controladores** cargados en el sistema, y sus relaciones entre sí.

Puedes obtener el IORegistry usando la cli **`ioreg`** para inspeccionarlo desde la consola (especialmente útil para iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Puedes descargar **`IORegistryExplorer`** desde **Xcode Additional Tools** en [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e inspeccionar el **macOS IORegistry** a través de una interfaz **gráfica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

En IORegistryExplorer, los "planos" se usan para organizar y mostrar las relaciones entre los distintos objetos en el IORegistry. Cada plano representa un tipo específico de relación o una vista particular de la configuración de hardware y drivers del sistema. Aquí hay algunos de los planos habituales que puedes encontrar en IORegistryExplorer:

1. **IOService Plane**: Este es el plano más general, que muestra los objetos de servicio que representan drivers y nubs (canales de comunicación entre drivers). Muestra las relaciones proveedor-cliente entre estos objetos.
2. **IODeviceTree Plane**: Este plano representa las conexiones físicas entre dispositivos tal como están conectados al sistema. A menudo se usa para visualizar la jerarquía de dispositivos conectados vía buses como USB o PCI.
3. **IOPower Plane**: Muestra objetos y sus relaciones en términos de gestión de energía. Puede mostrar qué objetos están afectando el estado de energía de otros, útil para depurar problemas relacionados con energía.
4. **IOUSB Plane**: Enfocado específicamente en dispositivos USB y sus relaciones, mostrando la jerarquía de hubs USB y dispositivos conectados.
5. **IOAudio Plane**: Este plano sirve para representar dispositivos de audio y sus relaciones dentro del sistema.
6. ...

## Ejemplo de código de comunicación con el driver

El siguiente código se conecta al servicio IOKit `YourServiceNameHere` y llama al selector 0:

- Primero llama a **`IOServiceMatching`** y **`IOServiceGetMatchingServices`** para obtener el servicio.
- Luego establece una conexión llamando a **`IOServiceOpen`**.
- Y finalmente llama a una función con **`IOConnectCallScalarMethod`** indicando el selector 0 (el selector es el número que la función que quieres llamar tiene asignado).

<details>
<summary>Ejemplo de llamada en espacio de usuario a un selector de driver</summary>
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

Existen **otras** funciones que se pueden usar para llamar funciones de IOKit además de **`IOConnectCallScalarMethod`**, como **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Revirtiendo el punto de entrada del driver

Puedes obtenerlos, por ejemplo, de una [**firmware image (ipsw)**](#ipsw). Luego, cárgalo en tu decompilador favorito.

Puedes empezar a descompilar la función **`externalMethod`**, ya que es la función del driver que recibirá la llamada y llamará a la función correcta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Esa horrible llamada demagled significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Observa cómo en la definición anterior falta el parámetro **`self`**; la definición correcta sería:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
En realidad, puedes encontrar la definición real en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Con esta info puedes reescribir Ctrl+Right -> `Edit function signature` y establecer los tipos conocidos:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

El nuevo código decompilado se verá así:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Para el siguiente paso necesitamos tener definida la estructura **`IOExternalMethodDispatch2022`**. Está en opensource en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), podrías definirla:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Ahora, siguiendo `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` puedes ver mucha información:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Cambie el tipo de datos a **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

después del cambio:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Y como ahora estamos ahí tenemos un **arreglo de 7 elementos** (revisa el código decompilado final); haz clic para crear un arreglo de 7 elementos:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Después de crear el arreglo puedes ver todas las funciones exportadas:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si recuerdas, para **call** una función **exported** desde user space no necesitamos invocar el nombre de la función, sino el **selector number**. Aquí puedes ver que el selector **0** es la función **`initializeDecoder`**, el selector **1** es **`startDecoder`**, el selector **2** **`initializeEncoder`**...

## Superficie de ataque reciente de IOKit (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) mostró que un cliente permisivo `IOHIDSystem` podía capturar eventos HID incluso con secure input; asegúrate de que los handlers `externalMethod` hagan cumplir los entitlements en lugar de basarse únicamente en el tipo de user-client.
- **IOGPUFamily memory corruption** – CVE-2024-44197 y CVE-2025-24257 corrigieron OOB writes accesibles desde sandboxed apps que pasan datos de longitud variable malformados a GPU user clients; el fallo habitual son límites pobres alrededor de los argumentos de `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) confirmó que los HID user clients siguen siendo un vector de sandbox-escape; fuzz cualquier driver que exponga keyboard/event queues.

### Consejos rápidos de triage & fuzzing

- Enumera todos los external methods para un user client desde userland para seed a fuzzer:
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
- Cuando hagas reversing, presta atención a los conteos de `IOExternalMethodDispatch2022`. Un patrón de bug común en CVEs recientes es la inconsistencia entre `structureInputSize`/`structureOutputSize` y la longitud real de `copyin`, lo que conduce a heap OOB en `IOConnectCallStructMethod`.
- El acceso al Sandbox sigue dependiendo de los entitlements. Antes de dedicar tiempo a un objetivo, comprueba si el cliente está permitido desde una app de terceros:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Para bugs de GPU/iomfb, pasar oversized arrays mediante `IOConnectCallMethod` suele ser suficiente para provocar bad bounds. Minimal harness (selector X) to trigger size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Referencias

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
