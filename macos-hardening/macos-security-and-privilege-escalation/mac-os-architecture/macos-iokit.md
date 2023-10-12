# macOS IOKit

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the official [**PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

IOKit es el marco de controladores de dispositivos de código abierto, orientado a objetos, en el kernel XNU y es responsable de la adición y gestión de controladores de dispositivos cargados dinámicamente. Estos controladores permiten agregar código modular al kernel de forma dinámica para su uso con diferentes hardware, por ejemplo.

Los controladores de IOKit básicamente **exportan funciones desde el kernel**. Estos tipos de parámetros de función están **predefinidos** y se verifican. Además, al igual que XPC, IOKit es solo otra capa **encima de los mensajes Mach**.

El código del kernel IOKit XNU es de código abierto por Apple en [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Además, los componentes de IOKit en el espacio de usuario también son de código abierto [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Sin embargo, **no hay controladores de IOKit** de código abierto. De todos modos, de vez en cuando una versión de un controlador puede venir con símbolos que facilitan su depuración. Consulta cómo [**obtener las extensiones de controlador desde el firmware aquí**](./#ipsw)**.**

Está escrito en **C++**. Puedes obtener símbolos C++ desenmascarados con:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Las funciones expuestas de IOKit podrían realizar verificaciones de seguridad adicionales cuando un cliente intenta llamar a una función, pero tenga en cuenta que las aplicaciones suelen estar limitadas por el sandbox con respecto a las funciones de IOKit con las que pueden interactuar.
{% endhint %}

## Controladores

En macOS se encuentran en:

* **`/System/Library/Extensions`**
* Archivos KEXT integrados en el sistema operativo OS X.
* **`/Library/Extensions`**
* Archivos KEXT instalados por software de terceros.

En iOS se encuentran en:

* **`/System/Library/Extensions`**
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
Hasta el número 9, los controladores enumerados se **cargan en la dirección 0**. Esto significa que no son controladores reales, sino **parte del kernel y no se pueden descargar**.

Para encontrar extensiones específicas, puedes usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para cargar y descargar extensiones del kernel, haz lo siguiente:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

El **IORegistry** es una parte crucial del marco de trabajo IOKit en macOS e iOS que sirve como una base de datos para representar la configuración y el estado del hardware del sistema. Es una **colección jerárquica de objetos que representan todo el hardware y los controladores** cargados en el sistema, y sus relaciones entre sí.&#x20;

Puedes obtener el IORegistry utilizando la línea de comandos **`ioreg`** para inspeccionarlo desde la consola (especialmente útil para iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Puedes descargar **`IORegistryExplorer`** desde **Xcode Additional Tools** en [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e inspeccionar el **IORegistry de macOS** a través de una interfaz **gráfica**.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

En IORegistryExplorer, se utilizan "planos" para organizar y mostrar las relaciones entre diferentes objetos en el IORegistry. Cada plano representa un tipo específico de relación o una vista particular de la configuración de hardware y controladores del sistema. Aquí tienes algunos de los planos comunes que puedes encontrar en IORegistryExplorer:

1. **Plano IOService**: Este es el plano más general, muestra los objetos de servicio que representan controladores y nubs (canales de comunicación entre controladores). Muestra las relaciones proveedor-cliente entre estos objetos.
2. **Plano IODeviceTree**: Este plano representa las conexiones físicas entre dispositivos a medida que se conectan al sistema. Se utiliza a menudo para visualizar la jerarquía de dispositivos conectados a través de buses como USB o PCI.
3. **Plano IOPower**: Muestra objetos y sus relaciones en términos de administración de energía. Puede mostrar qué objetos están afectando el estado de energía de otros, útil para depurar problemas relacionados con la energía.
4. **Plano IOUSB**: Enfocado específicamente en dispositivos USB y sus relaciones, muestra la jerarquía de concentradores USB y dispositivos conectados.
5. **Plano IOAudio**: Este plano representa dispositivos de audio y sus relaciones dentro del sistema.
6. ...

## Ejemplo de código de comunicación del controlador

El siguiente código se conecta al servicio IOKit `"YourServiceNameHere"` y llama a la función dentro del selector 0. Para ello:

* primero llama a **`IOServiceMatching`** y **`IOServiceGetMatchingServices`** para obtener el servicio.
* Luego establece una conexión llamando a **`IOServiceOpen`**.
* Y finalmente llama a una función con **`IOConnectCallScalarMethod`** indicando el selector 0 (el selector es el número asignado a la función que deseas llamar).
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
Hay **otras** funciones que se pueden utilizar para llamar a funciones de IOKit aparte de **`IOConnectCallScalarMethod`** como **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversando el punto de entrada del controlador

Puedes obtener estos, por ejemplo, desde una [**imagen de firmware (ipsw)**](./#ipsw). Luego, cárgalo en tu descompilador favorito.

Puedes comenzar a descompilar la función **`externalMethod`** ya que esta es la función del controlador que recibirá la llamada y llamará a la función correcta:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Esa horrible llamada demanglada significa:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Observa cómo en la definición anterior falta el parámetro **`self`**, la definición correcta sería:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

En realidad, puedes encontrar la definición real en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Con esta información puedes reescribir Ctrl+Right -> `Editar firma de función` y establecer los tipos conocidos:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

El nuevo código descompilado se verá así:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Para el siguiente paso necesitamos haber definido la estructura **`IOExternalMethodDispatch2022`**. Es de código abierto en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), puedes definirla así:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Ahora, siguiendo `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` puedes ver muchos datos:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Cambia el tipo de datos a **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

después del cambio:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

Y como ahora sabemos que tenemos una **matriz de 7 elementos** (verifica el código descompilado final), haz clic para crear una matriz de 7 elementos:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Después de crear la matriz puedes ver todas las funciones exportadas:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Si recuerdas, para **llamar** una función **exportada** desde el espacio de usuario no necesitamos llamar al nombre de la función, sino al **número de selector**. Aquí puedes ver que el selector **0** es la función **`initializeDecoder`**, el selector **1** es **`startDecoder`**, el selector **2** es **`initializeEncoder`**...
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
