# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Los binarios de Mac OS normalmente se compilan como **universal binaries**. Un **universal binary** puede **soportar múltiples arquitecturas en el mismo archivo**.

Estos binarios siguen la **estructura Mach-O**, que básicamente está compuesta por:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Busca el archivo con: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu specifier (int) */
cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
uint32_t	offset;		/* file offset to this object file */
uint32_t	size;		/* size of this object file */
uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

El header tiene los bytes **magic** seguidos por el **número** de **archs** que **contiene** el archivo (`nfat_arch`) y cada arch tendrá una struct `fat_arch`.

Compruébalo con:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

o usando la herramienta [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Como quizá estés pensando, normalmente un universal binary compilado para 2 arquitecturas **duplica el tamaño** de uno compilado para solo 1 arch.

> [!TIP]
> Cuando analices malware o apps sospechosas, no te detengas después de que `file` reporte la "mejor" arquitectura. Un universal binary puede ocultar diferentes imports, load commands o metadatos del compilador en cada slice, así que enumera **todos** los slices primero y luego inspecciónalos de forma independiente:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Los SDK recientes de macOS también exponen helpers como `macho_for_each_slice()` y `macho_best_slice()` en `<mach-o/utils.h>`. Esta última es útil para emular lo que cargaría dyld/kernel, pero los scanners deberían seguir iterando cada slice para evitar perder contenido específico de cada arch.

## **Mach-O Header**

El header contiene información básica sobre el archivo, como los magic bytes para identificarlo como un archivo Mach-O y la información sobre la target architecture. Puedes encontrarlo en: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Tipos de archivo Mach-O

Hay diferentes tipos de archivo, puedes encontrarlos definidos en el [**código fuente por ejemplo aquí**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Los más importantes son:

- `MH_OBJECT`: Archivo objeto relocatable (productos intermedios de la compilación, aún no ejecutables).
- `MH_EXECUTE`: Archivos ejecutables.
- `MH_FVMLIB`: Archivo de biblioteca de VM fija.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Archivo ejecutable precargado (ya no soportado en XNU)
- `MH_DYLIB`: Bibliotecas dinámicas
- `MH_DYLINKER`: Enlazador dinámico
- `MH_BUNDLE`: "Archivos de plugin". Generados usando -bundle en gcc y cargados explícitamente por `NSBundle` o `dlopen`.
- `MH_DYSM`: Archivo `.dSym` compañero (archivo con símbolos para depuración).
- `MH_KEXT_BUNDLE`: Extensiones del kernel.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
O usando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

El código fuente también define varias flags útiles para cargar libraries:

- `MH_NOUNDEFS`: No undefined references (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: File splits r/o and r/w segments.
- `MH_WEAK_DEFINES`: Binary has weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary uses weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Make the stack executable
- `MH_NO_REEXPORTED_DYLIBS`: Library not LC_REEXPORT commands
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: There is a section with thread local variables
- `MH_NO_HEAP_EXECUTION`: No execution for heap/data pages
- `MH_HAS_OBJC`: Binary has oBject-C sections
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Used on dylibs/frameworks in shared library cache.

## **Mach-O Load commands**

El **layout del archivo en memoria** se especifica aquí, detallando la **ubicación de la symbol table**, el contexto del main thread al iniciar la ejecución y las **shared libraries** requeridas. Se proporcionan instrucciones al dynamic loader **(dyld)** sobre el proceso de carga del binary en memoria.

The uses the **load_command** structure, defined in the mentioned **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Hay alrededor de **50 tipos diferentes de load commands** que el sistema maneja de forma distinta. Los más comunes son: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` y `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Básicamente, este tipo de Load Command define **cómo cargar los segmentos \_\_TEXT** (código ejecutable) **y \_\_DATA** (datos para el proceso) **según los offsets indicados en la sección Data** cuando el binario se ejecuta.

Estos comandos **definen segmentos** que se **mapean** en el **espacio de memoria virtual** de un proceso cuando se ejecuta.

Existen **distintos tipos** de segmentos, como el segmento **\_\_TEXT**, que contiene el código ejecutable de un programa, y el segmento **\_\_DATA**, que contiene datos usados por el proceso. Estos **segmentos están ubicados en la sección de datos** del archivo Mach-O.

**Cada segmento** puede a su vez **dividirse** en múltiples **secciones**. La **estructura del load command** contiene **información** sobre **estas secciones** dentro del segmento respectivo.

En el encabezado primero encuentras el **segment header**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* includes sizeof section_64 structs */
char		segname[16];	/* segment name */
uint64_t	vmaddr;		/* memory address of this segment */
uint64_t	vmsize;		/* memory size of this segment */
uint64_t	fileoff;	/* file offset of this segment */
uint64_t	filesize;	/* amount to map from the file */
int32_t		maxprot;	/* maximum VM protection */
int32_t		initprot;	/* initial VM protection */
<strong>	uint32_t	nsects;		/* number of sections in segment */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Ejemplo de segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Este header define el **número de secciones cuyos headers aparecen después** de él:
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
Ejemplo de **encabezado de sección**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Si **añades** el **desplazamiento de la sección** (0x37DC) + el **desplazamiento** donde **empieza la arch**, en este caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

También es posible obtener **información de los encabezados** desde la **línea de comandos** con:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Instruye al kernel a **mapear** el **address zero** para que **no pueda ser leído, escrito ni ejecutado**. Las variables maxprot y minprot en la estructura se establecen en cero para indicar que **no hay permisos read-write-execute en esta page**.
- Esta asignación es importante para **mitigate NULL pointer dereference vulnerabilities**. Esto se debe a que XNU aplica una hard page zero que asegura que la primera página (solo la primera) de memoria sea inaccesible (excepto en i386). Un binary podría cumplir con este requisito creando un pequeño \_\_PAGEZERO (usando `-pagezero_size`) para cubrir los primeros 4k y dejando el resto de la memoria de 32bit accesible tanto en user como en kernel mode.
- **`__TEXT`**: Contiene **code** **executive** con permisos de **read** y **execute** (no writable)**.** Common sections of this segment:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
- `__unwind_info`: Stack unwind data.
- Note that all this content is signed but also marked as executable (creating more options for exploitation of sections that doesn't necessarily need this privilege, like string dedicated sections).
- **`__DATA`**: Contiene datos que son **readable** y **writable** (no executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Information used by the Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const no está garantizado que sea constant (write permissions), ni tampoco otros pointers y el GOT. Esta section hace que `__const`, algunos initializers y la tabla GOT (una vez resuelta) sean **read only** usando `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Común en binarios recientes de Apple Silicon. Estos segments contienen pointers que deben ser authenticated en load o use time (por ejemplo `__auth_got`). Si un rebinding, hook o import-patching trick solo comprueba las secciones legacy `__got` / `__la_symbol_ptr`, puede pasar por alto los reales call sites en binarios modernos `arm64e`. Para más detalles sobre estas secciones consulta [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contiene información para el linker (dyld) como entradas de symbol, string y relocation table. Es un contenedor genérico para contenidos que no están ni en `__TEXT` ni en `__DATA` y su contenido se describe en otros load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Contiene información usada por el runtime de Objective-C. Aunque esta información también puede encontrarse en el segment \_\_DATA, dentro de varias secciones \_\_objc\_\*.
- **`__RESTRICT`**: Un segment sin content con una sola section llamada **`__restrict`** (también vacía) que asegura que, al ejecutar el binary, ignorará las variables de entorno de DYLD.

Como se pudo ver en el code, **segments también soportan flags** (aunque no se usan mucho):

- `SG_HIGHVM`: Solo Core (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene el entrypoint en el atributo **entryoff.** En tiempo de carga, **dyld** simplemente **suma** este valor a la **base of the binary** (en memoria), y luego **salta** a esta instrucción para iniciar la ejecución del code del binary.

**`LC_UNIXTHREAD`** contiene los valores que el register debe tener al iniciar el main thread. Esto ya estaba deprecated pero **`dyld`** aún lo usa. Es posible ver los values de los registers establecidos por esto con:
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Contiene información sobre la **firma de código del archivo Macho-O**. Solo contiene un **offset** que **apunta** al **signature blob**. Normalmente está al final del archivo.\
Sin embargo, puedes encontrar algo de información sobre esta sección en [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) y estos [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Soporte para cifrado de binarios. Sin embargo, por supuesto, si un atacante logra comprometer el proceso, podrá volcar la memoria sin cifrar.

### **`LC_LOAD_DYLINKER`**

Contiene la **ruta al ejecutable del dynamic linker** que mapea las shared libraries dentro del espacio de direcciones del proceso. El **valor siempre se establece en `/usr/lib/dyld`**. Es importante señalar que en macOS, el mapeo de dylib ocurre en **modo usuario**, no en modo kernel.

### **`LC_IDENT`**

Obsoleto, pero cuando se configura para geenrate dumps on panic, se crea un Mach-O core dump y la versión del kernel se establece en el comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatorio. No es útil directamente para nada, pero XNU lo almacena en caché junto con el resto de la información del proceso. Puede usarse en crash reports.

### **`LC_BUILD_VERSION`**

Los binarios modernos suelen incluir este comando para declarar la **target platform**, la **minimum OS version**, la **SDK version**, y opcionalmente las **tool versions** usadas para compilar esa slice. Desde una perspectiva ofensiva/reversing, esto es muy útil para fingerprint cómo se construyó una muestra y para detectar rápidamente universal binaries extraños donde una slice fue compilada con un SDK o deployment target diferente. Los binarios antiguos pueden seguir usando `LC_VERSION_MIN_*` en su lugar.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variables de entorno a dyld antes de que el proceso se ejecute. Esto puede ser muy peligroso, ya que puede permitir ejecutar código arbitrario dentro del proceso, por lo que este load command solo se usa en builds de dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` y además restringe el procesamiento solo a variables con la forma `DYLD_..._PATH` que especifican rutas de carga.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Los toolchains recientes suelen almacenar metadatos de export/bind/rebase en estos comandos en lugar de depender solo de los viejos opcodes `LC_DYLD_INFO[_ONLY]`. Ambos son entradas `linkedit_data_command` que apuntan dentro de **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: trie compacto con los símbolos exportados por la imagen.
- **`LC_DYLD_CHAINED_FIXUPS`**: cadenas de fixup por segmento usadas por dyld para aplicar rebases y binds. En Apple Silicon, aquí también encontrarás muchos fixups modernos de authenticated pointer.

Estos metadatos son muy útiles al reconstruir imports/exports, entender por qué una dependencia cargada con `@rpath` se resolvió de la forma en que lo hizo, o averiguar por qué un intento de hook/rebinding falló en un target moderno `arm64e`. `dyld_info` también puede usarse contra rutas de dylib de **cache-only** que no existen como archivos independientes en disco, lo cual es muy útil en macOS moderno, donde muchas librerías del sistema viven solo en el shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Este comando de carga moderno es más relevante al inspeccionar **kernel collections / kernelcache-style filesets**. En lugar de representar una sola imagen independiente, el Mach-O externo actúa como un contenedor y cada `LC_FILESET_ENTRY` apunta a un Mach-O incrustado con su propio **entry id** similar a una ruta, dirección VM y desplazamiento de archivo. Si estás haciendo reversing de componentes modernos del kernel de macOS/iOS, este comando suele ser el puente entre el contenedor de nivel superior y la imagen real que quieres extraer o desensamblar.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Este comando de carga describe una dependencia de **biblioteca** **dinámica** que **instruye** al **loader** (dyld) a **cargar y enlazar dicha biblioteca**. Hay un comando de carga `LC_LOAD_DYLIB` **para cada biblioteca** que el binario Mach-O requiere.

- Este comando de carga es una estructura de tipo **`dylib_command`** (que contiene una struct dylib, describiendo la biblioteca dinámica dependiente real):
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / número de compatibilidad de la biblioteca /](<../../../images/image (486).png>)

También podrías obtener esta información desde la cli con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algunas bibliotecas relacionadas con malware son:

- **DiskArbitration**: Monitorización de unidades USB
- **AVFoundation:** Captura de audio y video
- **CoreWLAN**: Escaneos de Wifi.

> [!TIP]
> Un binario Mach-O puede contener uno o **más** **constructors**, que se **ejecutarán** **antes** de la dirección especificada en **LC_MAIN**.\
> Los offsets de cualquier constructor se guardan en la sección **\_\_mod_init_func** del segmento **\_\_DATA_CONST**.

## **Mach-O Data**

En el núcleo del archivo se encuentra la región de datos, que está compuesta por varios segmentos según se define en la región de load-commands. **Dentro de cada segmento puede haber una variedad de secciones de datos**, y cada sección **contiene código o datos** específicos de un tipo.

> [!TIP]
> Los datos son básicamente la parte que contiene toda la **información** que se carga mediante los load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Esto incluye:

- **Function table:** Que contiene información sobre las funciones del programa.
- **Symbol table**: Que contiene información sobre la función externa usada por el binario
- También podría contener funciones internas, nombres de variables y más.

Para comprobarlo puedes usar la herramienta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

O desde la cli:
```bash
size -m /bin/ls
```
## Secciones Comunes de Objective-C

En el segmento `__TEXT` (r-x):

- `__objc_classname`: Nombres de clase (strings)
- `__objc_methname`: Nombres de métodos (strings)
- `__objc_methtype`: Tipos de métodos (strings)

En el segmento `__DATA` (rw-):

- `__objc_classlist`: Pointers a todas las clases de Objetive-C
- `__objc_nlclslist`: Pointers a clases Objective-C Non-Lazy
- `__objc_catlist`: Pointer to Categories
- `__objc_nlcatlist`: Pointer to Non-Lazy Categories
- `__objc_protolist`: Lista de protocolos
- `__objc_const`: Datos constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Referencias

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
