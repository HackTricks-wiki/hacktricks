# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) son **paquetes** con la extensión **`.kext`** que se **cargan directamente en el espacio del kernel de macOS**, proporcionando funcionalidad adicional al sistema operativo principal.

### Deprecation status & DriverKit / System Extensions
A partir de **macOS Catalina (10.15)** Apple marcó la mayoría de las KPIs heredadas como *deprecated* e introdujo los frameworks **System Extensions & DriverKit** que se ejecutan en **espacio de usuario**. Desde **macOS Big Sur (11)** el sistema operativo *se negará a cargar* kexts de terceros que dependan de KPIs obsoletas a menos que la máquina se inicie en modo **Reduced Security**. En Apple Silicon, habilitar kexts además requiere que el usuario:

1. Reinicie en **Recovery** → *Startup Security Utility*.
2. Seleccione **Reduced Security** y marque **“Allow user management of kernel extensions from identified developers”**.
3. Reinicie y apruebe el kext en **System Settings → Privacy & Security**.

Los drivers en espacio de usuario escritos con DriverKit/System Extensions reducen drásticamente la **superficie de ataque** porque fallos o corrupciones de memoria quedan confinados a un proceso sandboxeado en lugar del kernel.

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### Requirements

Obviamente, esto es tan potente que es **complicado cargar una kernel extension**. Estos son los **requisitos** que debe cumplir una kernel extension para poder cargarse:

- Cuando **se entra en modo de recuperación**, las **extensiones del kernel deben estar permitidas** para cargarse:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- La kernel extension debe estar **firmada con un certificado de firma de código de kernel**, que sólo puede ser **concedido por Apple**. Apple revisará en detalle la empresa y las razones por las que se necesita.
- La kernel extension también debe estar **notarizada**, Apple podrá comprobarla en busca de malware.
- Entonces, el usuario **root** es quien puede **cargar la kernel extension** y los archivos dentro del paquete deben **pertenecer a root**.
- Durante el proceso de subida, el paquete debe prepararse en una **ubicación protegida que no sea root**: `/Library/StagedExtensions` (requiere el grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Finalmente, al intentar cargarla, el usuario [**recibirá una solicitud de confirmación**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) y, si la acepta, el equipo debe **reiniciarse** para cargarla.

### Loading process

En Catalina era así: Es interesante notar que el proceso de **verificación** ocurre en **userland**. Sin embargo, sólo las aplicaciones con el grant **`com.apple.private.security.kext-management`** pueden **solicitar al kernel que cargue una extensión**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** el proceso de **verificación** para cargar una extensión
- Se comunicará con **`kextd`** mediante una **Mach service**.
2. **`kextd`** comprobará varias cosas, como la **firma**
- Se comunicará con **`syspolicyd`** para **verificar** si la extensión puede ser **cargada**.
3. **`syspolicyd`** **pedirá confirmación** al **usuario** si la extensión no se ha cargado previamente.
- **`syspolicyd`** informará el resultado a **`kextd`**
4. **`kextd`** finalmente podrá **indicar al kernel que cargue** la extensión

Si **`kextd`** no está disponible, **`kextutil`** puede realizar las mismas comprobaciones.

### Enumeration & management (loaded kexts)

`kextstat` fue la herramienta histórica pero está **deprecated** en las versiones recientes de macOS. La interfaz moderna es **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
La sintaxis anterior aún está disponible como referencia:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` también se puede usar para **dump the contents of a Kernel Collection (KC)** o verificar que un kext resuelva todas las dependencias de símbolos:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Even though the kernel extensions are expected to be in `/System/Library/Extensions/`, if you go to this folder you **won't find any binary**. This is because of the **kernelcache** and in order to reverse one `.kext` you need to find a way to obtain it.

El **kernelcache** es una **versión precompilada y preenlazada del kernel XNU**, junto con los controladores de dispositivo esenciales y las **extensiones del kernel**. Se almacena en un formato **comprimido** y se descomprime en memoria durante el proceso de arranque. El kernelcache facilita un **arranque más rápido** al disponer de una versión lista para ejecutarse del kernel y de los controladores críticos, reduciendo el tiempo y los recursos que de otro modo se gastarían en cargar y enlazar dinámicamente estos componentes en el arranque.

Los principales beneficios del kernelcache son la **velocidad de carga** y que todos los módulos están preenlazados (sin impedimento por tiempo de carga). Además, una vez que todos los módulos han sido preenlazados, KXLD puede eliminarse de la memoria, por lo que **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.


### Local Kerlnelcache

En iOS se encuentra en **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** en macOS puedes encontrarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
En mi caso en macOS lo encontré en:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

El formato de archivo IMG4 es un formato contenedor usado por Apple en sus dispositivos iOS y macOS para **almacenar y verificar firmware** de forma segura (como el **kernelcache**). El formato IMG4 incluye una cabecera y varias etiquetas que encapsulan diferentes piezas de datos incluyendo la carga útil real (como un kernel o bootloader), una firma y un conjunto de propiedades en el manifiesto. El formato soporta verificación criptográfica, permitiendo al dispositivo confirmar la autenticidad e integridad del componente de firmware antes de ejecutarlo.

Normalmente está compuesto por los siguientes componentes:

- **Payload (IM4P)**:
- Often compressed (LZFSE4, LZSS, …)
- Optionally encrypted
- **Manifest (IM4M)**:
- Contains Signature
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- Also known as APNonce
- Prevents replaying of some updates
- OPTIONAL: Usually this isn't found

Decompress the Kernelcache:
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
#### Disarm símbolos para el kernel

**`Disarm`** permite symbolicate funciones del kernelcache usando matchers.

Estos matchers son reglas de patrón simples (líneas de texto) que le dicen a disarm cómo reconocer & auto-symbolicate funciones, argumentos y cadenas de panic/log dentro de un binario.

Básicamente indicas la cadena que usa una función y disarm la encontrará y **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Ir a /tmp/extracted donde disarm extrajo los filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# Instalar la herramienta ipsw
brew install blacktop/tap/ipsw

# Extraer solo el kernelcache del IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Deberías obtener algo como:
#   out/Firmware/kernelcache.release.iPhoneXX
#   o un IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Si obtienes un IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

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

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# Listar todas las extensiones
kextex -l kernelcache.release.iphone14.e
## Extraer com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extraer todo
kextex_all kernelcache.release.iphone14.e

# Comprobar la extensión en busca de símbolos
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Crear un symbolication bundle para el panic más reciente
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # obtener backtrace en el contexto del kernel
```

### Attaching LLDB to a specific loaded kext

```bash
# Identificar la dirección de carga del kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Adjuntar
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
