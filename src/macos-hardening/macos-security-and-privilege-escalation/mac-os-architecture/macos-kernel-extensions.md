# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

Las extensiones del kernel (Kexts) son **paquetes** con una **extensión `.kext`** que se **cargan directamente en el espacio del kernel de macOS**, proporcionando funcionalidad adicional al sistema operativo principal.

### Requisitos

Obviamente, esto es tan poderoso que es **complicado cargar una extensión del kernel**. Estos son los **requisitos** que una extensión del kernel debe cumplir para ser cargada:

- Al **ingresar al modo de recuperación**, las **extensiones del kernel deben ser permitidas** para ser cargadas:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- La extensión del kernel debe estar **firmada con un certificado de firma de código del kernel**, que solo puede ser **otorgado por Apple**. Quien revisará en detalle la empresa y las razones por las que se necesita.
- La extensión del kernel también debe estar **notarizada**, Apple podrá verificarla en busca de malware.
- Luego, el usuario **root** es quien puede **cargar la extensión del kernel** y los archivos dentro del paquete deben **pertenecer a root**.
- Durante el proceso de carga, el paquete debe estar preparado en una **ubicación protegida no root**: `/Library/StagedExtensions` (requiere el otorgamiento de `com.apple.rootless.storage.KernelExtensionManagement`).
- Finalmente, al intentar cargarlo, el usuario [**recibirá una solicitud de confirmación**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) y, si se acepta, la computadora debe ser **reiniciada** para cargarlo.

### Proceso de Carga

En Catalina fue así: Es interesante notar que el proceso de **verificación** ocurre en **userland**. Sin embargo, solo las aplicaciones con el otorgamiento de **`com.apple.private.security.kext-management`** pueden **solicitar al kernel que cargue una extensión**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** el proceso de **verificación** para cargar una extensión
- Se comunicará con **`kextd`** enviando usando un **servicio Mach**.
2. **`kextd`** verificará varias cosas, como la **firma**
- Se comunicará con **`syspolicyd`** para **verificar** si la extensión puede ser **cargada**.
3. **`syspolicyd`** **solicitará** al **usuario** si la extensión no ha sido cargada previamente.
- **`syspolicyd`** informará el resultado a **`kextd`**
4. **`kextd`** finalmente podrá **decirle al kernel que cargue** la extensión

Si **`kextd`** no está disponible, **`kextutil`** puede realizar las mismas verificaciones.

### Enumeración (kexts cargados)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> Aunque se espera que las extensiones del kernel estén en `/System/Library/Extensions/`, si vas a esta carpeta **no encontrarás ningún binario**. Esto se debe al **kernelcache** y para revertir un `.kext` necesitas encontrar una manera de obtenerlo.

El **kernelcache** es una **versión precompilada y preenlazada del kernel XNU**, junto con controladores de dispositivo esenciales y **extensiones del kernel**. Se almacena en un formato **comprimido** y se descomprime en la memoria durante el proceso de arranque. El kernelcache facilita un **tiempo de arranque más rápido** al tener una versión lista para ejecutar del kernel y controladores cruciales disponibles, reduciendo el tiempo y los recursos que de otro modo se gastarían en cargar y enlazar dinámicamente estos componentes en el momento del arranque.

### Kernelcache Local

En iOS se encuentra en **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** en macOS puedes encontrarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
En mi caso en macOS lo encontré en:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

El formato de archivo IMG4 es un formato contenedor utilizado por Apple en sus dispositivos iOS y macOS para **almacenar y verificar de manera segura** componentes de firmware (como el **kernelcache**). El formato IMG4 incluye un encabezado y varias etiquetas que encapsulan diferentes piezas de datos, incluyendo la carga útil real (como un kernel o cargador de arranque), una firma y un conjunto de propiedades de manifiesto. El formato admite verificación criptográfica, permitiendo que el dispositivo confirme la autenticidad e integridad del componente de firmware antes de ejecutarlo.

Generalmente está compuesto por los siguientes componentes:

- **Carga útil (IM4P)**:
- A menudo comprimido (LZFSE4, LZSS, …)
- Opcionalmente cifrado
- **Manifiesto (IM4M)**:
- Contiene firma
- Diccionario adicional de clave/valor
- **Información de restauración (IM4R)**:
- También conocido como APNonce
- Previene la repetición de algunas actualizaciones
- OPCIONAL: Generalmente esto no se encuentra

Descomprimir el Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Descargar

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

En [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) es posible encontrar todos los kits de depuración del kernel. Puedes descargarlo, montarlo, abrirlo con la herramienta [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), acceder a la carpeta **`.kext`** y **extraerlo**.

Verifícalo en busca de símbolos con:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

A veces Apple lanza **kernelcache** con **símbolos**. Puedes descargar algunos firmwares con símbolos siguiendo los enlaces en esas páginas. Los firmwares contendrán el **kernelcache** entre otros archivos.

Para **extraer** los archivos, comienza cambiando la extensión de `.ipsw` a `.zip` y **descomprímelo**.

Después de extraer el firmware, obtendrás un archivo como: **`kernelcache.release.iphone14`**. Está en formato **IMG4**, puedes extraer la información interesante con:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspeccionando kernelcache

Verifica si el kernelcache tiene símbolos con
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Con esto ahora podemos **extraer todas las extensiones** o la **que te interese:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Depuración

## Referencias

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
