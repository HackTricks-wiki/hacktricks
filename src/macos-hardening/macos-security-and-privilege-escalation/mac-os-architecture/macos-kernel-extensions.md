# Kernel Extensions y Kernelcaches de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Las kernel extensions (Kexts) son **paquetes** con una extensión **`.kext`** que se **cargan directamente en el espacio del kernel de macOS**, proporcionando funcionalidad adicional al sistema operativo principal.

### Estado de deprecated y DriverKit / System Extensions
A partir de **macOS Catalina (10.15)**, Apple marcó la mayoría de los KPI heredados como *deprecated* e introdujo los frameworks **System Extensions y DriverKit**, que se ejecutan en el **espacio de usuario**. Desde **macOS Big Sur (11)**, el sistema operativo se *negará a cargar* kexts de terceros que dependan de KPI deprecated, a menos que la máquina se inicie en modo **Reduced Security**. En Apple Silicon, habilitar kexts requiere además que el usuario:

1. Reinicie en **Recovery** → *Startup Security Utility*.
2. Seleccione **Reduced Security** y marque **“Allow user management of kernel extensions from identified developers”**.
3. Reinicie y apruebe el kext desde **System Settings → Privacy & Security**.

Los drivers en espacio de usuario escritos con DriverKit/System Extensions **reducen drásticamente la attack surface**, porque los crashes o la corrupción de memoria quedan confinados a un proceso aislado en lugar del espacio del kernel.<sup>[[1]](#references)</sup>

> 📝 Desde macOS Sequoia (15), Apple ha eliminado por completo varios KPI heredados de networking y USB; la única solución compatible con el futuro para los vendors es migrar a System Extensions.

### Requisitos

Obviamente, esto es tan potente que **cargar una kernel extension es complicado**. Estos son los **requisitos** que debe cumplir una kernel extension para poder cargarse:

- Al **entrar en recovery mode**, se debe permitir la carga de **kernel extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- La kernel extension debe estar **firmada con un certificado de firma de código del kernel**, que solo puede ser **otorgado por Apple**. Apple revisará detalladamente la empresa y los motivos por los que se necesita.
- La kernel extension también debe estar **notarized**; Apple podrá comprobar si contiene malware.
- Después, el usuario **root** es quien puede **cargar la kernel extension**, y los archivos dentro del paquete deben **pertenecer a root**.
- Durante el proceso de upload, el paquete debe prepararse en una ubicación **protegida que no sea root**: `/Library/StagedExtensions` (requiere el grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Finalmente, al intentar cargarla, el usuario [**recibirá una solicitud de confirmación**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) y, si la acepta, el ordenador deberá **reiniciarse** para cargarla.

### Proceso de carga

En Catalina era así: es interesante observar que el proceso de **verificación** ocurre en userland. Sin embargo, solo las aplicaciones con el grant **`com.apple.private.security.kext-management`** pueden **solicitar al kernel que cargue una extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`**, la cli, **inicia** el proceso de **verificación** para cargar una extension
- Se comunicará con **`kextd`** enviando una solicitud mediante un **Mach service**.
2. **`kextd`** comprobará varias cosas, como la **firma**
- Se comunicará con **`syspolicyd`** para **comprobar** si la extension puede **cargarse**.
3. **`syspolicyd`** solicitará confirmación al **usuario** si la extension no se ha cargado anteriormente.
- **`syspolicyd`** comunicará el resultado a **`kextd`**
4. **`kextd`** finalmente podrá **indicar al kernel que cargue** la extension

Si **`kextd`** no está disponible, **`kextutil`** puede realizar las mismas comprobaciones.

### Enumeración y gestión (kexts cargadas)

`kextstat` era la herramienta histórica, pero está **deprecated** en las versiones recientes de macOS. La interfaz moderna es **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
La sintaxis antigua sigue disponible como referencia:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` también puede utilizarse para **dump el contenido de una Kernel Collection (KC)** o verificar que un kext resuelva todas las dependencias de símbolos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Aunque se espera que las kernel extensions estén en `/System/Library/Extensions/`, si accedes a esta carpeta **no encontrarás ningún binario**. Esto se debe al **kernelcache** y, para hacer reverse engineering de una `.kext`, necesitas encontrar una forma de obtenerlo.

El **kernelcache** es una **versión precompilada y preenlazada del kernel XNU**, junto con los **drivers** de dispositivos esenciales y las **kernel extensions**. Se almacena en un formato **comprimido** y se descomprime en memoria durante el proceso de arranque. El kernelcache facilita un **arranque más rápido** al disponer de una versión del kernel y de los drivers esenciales lista para ejecutarse, lo que reduce el tiempo y los recursos que, de otro modo, se emplearían en cargar y enlazar dinámicamente estos componentes durante el arranque.

Las principales ventajas del kernelcache son la **velocidad de carga** y que todos los módulos están preenlazados (sin impedimentos durante la carga). Además, una vez que todos los módulos han sido preenlazados, KXLD puede eliminarse de la memoria, por lo que **XNU no puede cargar nuevas KEXTs.**

> [!TIP]
> La herramienta [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) descifra los contenedores AEA (Apple Encrypted Archive / AEA asset) de Apple —el formato de contenedor cifrado que Apple utiliza para los assets OTA y algunas partes de IPSW— y puede generar el archivo `.dmg`/asset subyacente, que después puedes extraer con las herramientas aastuff proporcionadas.


### Kerlnelcache local

En iOS se encuentra en **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; en macOS puedes encontrarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
En mi caso, en macOS lo encontré en:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Encuentra también aquí el [**kernelcache de la versión 14 con símbolos**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) comprimido

El formato de archivo IMG4 es un formato de contenedor utilizado por Apple en sus dispositivos iOS y macOS para **almacenar y verificar de forma segura componentes del firmware** (como el **kernelcache**). El formato IMG4 incluye una cabecera y varias etiquetas que encapsulan distintas partes de los datos, incluida la carga útil real (como un kernel o bootloader), una firma y un conjunto de propiedades del manifiesto. El formato admite verificación criptográfica, lo que permite al dispositivo confirmar la autenticidad e integridad del componente del firmware antes de ejecutarlo.

Normalmente está compuesto por los siguientes componentes:

- **Payload (IM4P)**:
- A menudo comprimido (LZFSE4, LZSS, …)
- Opcionalmente cifrado
- **Manifest (IM4M)**:
- Contiene la firma
- Diccionario adicional de clave/valor
- **Restore Info (IM4R)**:
- También conocido como APNonce
- Impide reproducir algunas actualizaciones
- OPCIONAL: Normalmente no se encuentra

Descomprime el Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Desarmar símbolos para el kernel

**`Disarm`** permite symbolicate funciones del kernelcache mediante matchers. Estos matchers son simplemente reglas de patrones (líneas de texto) que indican a disarm cómo reconocer y hacer auto-symbolicate de funciones, argumentos y cadenas de panic/log dentro de un binario.

Básicamente, indicas la cadena que utiliza una función y disarm la encontrará y la **symbolicate**.

Puedes encontrar algunos `xnu.matchers` en [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), en la sección **`Matchers`**. También puedes crear tus propios matchers.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Descarga

Un **IPSW (iPhone/iPad Software)** es el formato de paquete de firmware de Apple utilizado para restaurar y actualizar dispositivos, así como para incluir paquetes de firmware completos. Entre otras cosas, contiene el **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

En [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) es posible encontrar todos los kits de depuración del kernel. Puedes descargarlo, montarlo, abrirlo con la herramienta [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), acceder a la carpeta **`.kext`** y **extraerla**.

Comprueba si contiene símbolos con:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

A veces Apple publica **kernelcache** con **symbols**. Puedes descargar algunos firmwares con symbols siguiendo los enlaces de esas páginas. Los firmwares contendrán el **kernelcache**, entre otros archivos.

Para **extract** el kernel cache puedes hacer lo siguiente:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Otra opción para **extraer** los archivos es empezar cambiando la extensión de `.ipsw` a `.zip` y **descomprimirlo**.

Después de extraer el firmware, obtendrás un archivo como: **`kernelcache.release.iphone14`**. Está en formato **IMG4**; puedes extraer la información interesante con:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspeccionando kernelcache

Comprueba si el kernelcache tiene símbolos con
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Con esto ahora podemos **extraer todas las extensiones** o **la que te interese:**
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
## Vulnerabilidades recientes y técnicas de explotación

| Año | CVE | Resumen |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Un fallo lógico en **`storagekitd`** permitió que un atacante *root* registrara un bundle malicioso del sistema de archivos que finalmente cargaba un **kext sin firmar**, **evadiendo System Integrity Protection (SIP)** y permitiendo rootkits persistentes. Corregido en macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Se podía abusar de un daemon de instalación con el entitlement `com.apple.rootless.install` para ejecutar scripts post-instalación arbitrarios, deshabilitar SIP y cargar kexts arbitrarios. <sup>[[3]](#references)</sup> |

**Conclusiones para red-teamers**

1. **Busca daemons con entitlements (`codesign -dvv /path/bin | grep entitlements`) que interactúen con Disk Arbitration, Installer o Kext Management.**
2. **Abusar de los bypasses de SIP casi siempre concede la capacidad de cargar un kext → ejecución de código en el kernel**.

**Consejos defensivos**

*Mantén SIP habilitado*, monitoriza las invocaciones de `kmutil load`/`kmutil create -n aux` provenientes de binarios que no sean de Apple y genera alertas ante cualquier escritura en `/Library/Extensions`. Los eventos de Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` proporcionan visibilidad casi en tiempo real.

## Depuración del kernel y los kexts de macOS

El flujo de trabajo recomendado por Apple consiste en crear un **Kernel Debug Kit (KDK)** que coincida con el build en ejecución y, posteriormente, conectarse mediante **LLDB** a través de una sesión de red **KDP (Kernel Debugging Protocol)**.

### Depuración local puntual de un panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Depuración remota en vivo desde otro Mac

1. Descarga e instala la versión exacta de **KDK** para la máquina objetivo.
2. Conecta el Mac objetivo y el Mac host con un **cable USB-C o Thunderbolt**.
3. En el **Mac objetivo**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. En el **host**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Adjuntar LLDB a un kext específico cargado
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP solo expone una interfaz de **solo lectura**. Para realizar instrumentación dinámica, deberás parchear el binario en disco, utilizar **kernel function hooking** (por ejemplo, `mach_override`) o migrar el driver a un **hypervisor** para obtener acceso completo de lectura/escritura.

## Referencias

- [1] [Seguridad de DriverKit para macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Análisis de CVE-2024-44243, un bypass de macOS System Integrity Protection mediante kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft descubre una nueva vulnerabilidad de macOS, Shrootless, que podría evadir System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
