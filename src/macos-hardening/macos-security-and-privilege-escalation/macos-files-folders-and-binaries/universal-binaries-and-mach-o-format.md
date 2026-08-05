# Binaries universales de macOS y formato Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Los binarios de Mac OS normalmente se compilan como **binaries universales**. Un **universal binary** puede **admitir varias arquitecturas en el mismo archivo**.

Estos binarios siguen la **estructura Mach-O**, que básicamente está compuesta por:

- Encabezado
- Load Commands
- Datos

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

El encabezado contiene los bytes **magic**, seguidos por el **número** de **archs** que **contiene** el archivo (`nfat_arch`), y cada arch tendrá una estructura `fat_arch`.

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

o utilizando la herramienta [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Como probablemente estés pensando, normalmente un universal binary compilado para 2 arquitecturas **duplica el tamaño** de uno compilado para una sola arch.

> [!TIP]
> Al analizar malware o apps sospechosas, no te detengas después de que `file` informe de la arquitectura "mejor". Un universal binary puede ocultar diferentes imports, load commands o metadatos del compilador en cada slice, así que enumera primero **todas** las slices y después inspecciónalas de forma independiente:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Los SDKs recientes de macOS también exponen helpers como `macho_for_each_slice()` y `macho_best_slice()` en `<mach-o/utils.h>`. Este último resulta útil para emular lo que cargaría dyld/kernel, pero los scanners aún deberían iterar sobre cada slice para evitar omitir contenido específico de una arquitectura.<sup>[[1]](#references)</sup>

## **Cabecera Mach-O**

La cabecera contiene información básica sobre el archivo, como los magic bytes para identificarlo como un archivo Mach-O y datos sobre la arquitectura de destino. Puedes encontrarla mediante: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Tipos de archivos Mach-O

Hay diferentes tipos de archivos; puedes encontrarlos definidos en el [**código fuente, por ejemplo aquí**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Los más importantes son:

- `MH_OBJECT`: archivo de objeto reubicable (productos intermedios de la compilación, todavía no son ejecutables).
- `MH_EXECUTE`: archivos ejecutables.
- `MH_FVMLIB`: archivo de biblioteca VM fija.
- `MH_CORE`: volcados de código.
- `MH_PRELOAD`: archivo ejecutable precargado (ya no compatible con XNU).
- `MH_DYLIB`: bibliotecas dinámicas.
- `MH_DYLINKER`: dynamic linker.
- `MH_BUNDLE`: "archivos de plugin". Generados mediante -bundle en gcc y cargados explícitamente por `NSBundle` o `dlopen`.
- `MH_DYSM`: archivo `.dSym` complementario (archivo con símbolos para debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
O usando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flags de Mach-O**

El código fuente también define varios flags útiles para cargar libraries:

- `MH_NOUNDEFS`: Sin referencias no definidas (completamente enlazado)
- `MH_DYLDLINK`: Enlazado mediante Dyld
- `MH_PREBOUND`: Referencias dinámicas prebound.
- `MH_SPLIT_SEGS`: El archivo divide los segmentos r/o y r/w.
- `MH_WEAK_DEFINES`: El binario tiene símbolos definidos weak
- `MH_BINDS_TO_WEAK`: El binario utiliza símbolos weak
- `MH_ALLOW_STACK_EXECUTION`: Hace que el stack sea ejecutable
- `MH_NO_REEXPORTED_DYLIBS`: La library no tiene comandos LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Hay una sección con variables locales del thread
- `MH_NO_HEAP_EXECUTION`: No permite la ejecución de páginas del heap/data
- `MH_HAS_OBJC`: El binario tiene secciones de oBject-C
- `MH_SIM_SUPPORT`: Soporte para Simulator
- `MH_DYLIB_IN_CACHE`: Se utiliza en dylibs/frameworks de la shared library cache.

## **Load commands de Mach-O**

La **disposición del archivo en memoria** se especifica aquí, detallando la **ubicación de la tabla de símbolos**, el contexto del thread principal al inicio de la ejecución y las **shared libraries** necesarias. Se proporcionan instrucciones al loader dinámico **(dyld)** sobre el proceso de carga del binario en memoria.

El archivo utiliza la estructura **load_command**, definida en el **`loader.h`** mencionado:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Hay aproximadamente **50 tipos diferentes de load commands** que el sistema maneja de forma distinta. Los más comunes son: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` y `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Básicamente, este tipo de Load Command define **cómo cargar los segmentos \_\_TEXT** (código ejecutable) **y \_\_DATA** (datos del proceso) **según los offsets indicados en la sección Data** cuando se ejecuta el binario.

Estos comandos **definen segmentos** que se **mapean** en el **espacio de memoria virtual** de un proceso cuando se ejecuta.

Existen **diferentes tipos** de segmentos, como el segmento **\_\_TEXT**, que contiene el código ejecutable de un programa, y el segmento **\_\_DATA**, que contiene los datos utilizados por el proceso. Estos **segmentos se encuentran en la sección Data** del archivo Mach-O.

**Cada segmento** puede dividirse aún más en múltiples **secciones**. La **estructura del load command** contiene **información** sobre **estas secciones** dentro del segmento correspondiente.

En la cabecera primero se encuentra la **cabecera del segmento**:

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

Ejemplo de una cabecera de segmento:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Esta cabecera define el **número de secciones cuyos encabezados aparecen después** de ella:
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

Si **añades** el **desplazamiento de la sección** (0x37DC) + el **desplazamiento donde comienza la arquitectura**, en este caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

También es posible obtener **información de los encabezados** desde la **línea de comandos** con:
```bash
otool -lv /bin/ls
```
Segmentos comunes cargados por este cmd:

- **`__PAGEZERO`:** Indica al kernel que debe **mapear** la **dirección cero** para que no pueda leerse, escribirse ni ejecutarse. Las variables maxprot y minprot de la estructura se establecen en cero para indicar que **no existen permisos de lectura-escritura-ejecución en esta página**.
- Esta asignación es importante para **mitigar vulnerabilidades de desreferencia de punteros NULL**. Esto se debe a que XNU impone un page zero estricto que garantiza que la primera página (solo la primera) de memoria sea inaccesible (excepto en i386). Un binario podría cumplir este requisito creando un \_\_PAGEZERO pequeño (mediante `-pagezero_size`) para cubrir los primeros 4k y haciendo que el resto de la memoria de 32 bits sea accesible tanto en modo usuario como en modo kernel.
- **`__TEXT`**: Contiene **código** **ejecutable** con permisos de **lectura** y **ejecución** (no de escritura)**.** Secciones comunes de este segmento:
- `__text`: Código binario compilado
- `__const`: Datos constantes (solo lectura)
- `__[c/u/os_log]string`: Constantes de cadenas C, Unicode o os logs
- `__stubs` y `__stubs_helper`: Participan durante el proceso de carga de las dynamic libraries
- `__unwind_info`: Datos para desenrollar el stack.
- Ten en cuenta que todo este contenido está firmado, pero también marcado como ejecutable (lo que crea más opciones para la explotación de secciones que no necesitan necesariamente este privilegio, como las secciones dedicadas a strings).
- **`__DATA`**: Contiene datos **legibles** y **modificables** (no ejecutables)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Puntero a símbolos no lazy (bind al cargar)
- `__la_symbol_ptr`: Puntero a símbolos lazy (bind al utilizarse)
- `__const`: Debería contener datos de solo lectura (en realidad no)
- `__cfstring`: Cadenas de CoreFoundation
- `__data`: Variables globales (que han sido inicializadas)
- `__bss`: Variables estáticas (que no han sido inicializadas)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Información utilizada por el runtime de Objective-C
- **`__DATA_CONST`**: No se garantiza que \_\_DATA.\_\_const sea constante (tiene permisos de escritura), ni tampoco otros punteros y la GOT. Esta sección hace que `__const`, algunos inicializadores y la tabla GOT (una vez resuelta) sean de **solo lectura** mediante `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Comunes en binarios recientes de Apple Silicon. Estos segmentos contienen punteros que deben autenticarse durante la carga o el uso (por ejemplo, `__auth_got`). Si una técnica de rebinding, hook o import-patching solo comprueba las secciones heredadas `__got` / `__la_symbol_ptr`, podría pasar por alto los call sites reales en binarios `arm64e` modernos. Para obtener más información sobre estas secciones, consulta [esta página](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contiene información para el linker (dyld), como entradas de las tablas de símbolos, strings y relocations. Es un contenedor genérico para contenidos que no están en `__TEXT` ni en `__DATA`, y su contenido se describe en otros load commands.
- Información de dyld: opcodes de Rebase, binding Non-lazy/lazy/weak e información de exportación
- Function starts: Tabla de direcciones iniciales de las funciones
- Data In Code: Islas de datos en \_\_text
- Symbol Table: Símbolos del binario
- Indirect Symbol Table: Símbolos de punteros/stubs
- String Table
- Code Signature
- **`__OBJC`**: Contiene información utilizada por el runtime de Objective-C. Aunque esta información también puede encontrarse en el segmento \_\_DATA, dentro de varias secciones \_\_objc\_\*.
- **`__RESTRICT`**: Un segmento sin contenido con una única sección llamada **`__restrict`** (también vacía) que garantiza que, al ejecutar el binario, se ignoren las variables de entorno de DYLD.

Como se podía observar en el código, los **segmentos también admiten flags** (aunque no se utilizan demasiado):

- `SG_HIGHVM`: Solo Core (no utilizado)
- `SG_FVMLIB`: No utilizado
- `SG_NORELOC`: El segmento no tiene relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Utilizado, por ejemplo, por Finder para cifrar el segmento de texto `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene el entrypoint en el **atributo entryoff.** Durante la carga, **dyld** simplemente **suma** este valor a la **base (en memoria) del binario** y, a continuación, **salta** a esta instrucción para comenzar la ejecución del código del binario.

**`LC_UNIXTHREAD`** contiene los valores que deben tener los registros al iniciar el thread principal. Esto ya estaba deprecated, pero **`dyld`** todavía lo utiliza. Es posible ver los valores de los registros establecidos mediante esto con:
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


Contiene información sobre la **firma de código del archivo Mach-O**. Solo contiene un **offset** que **apunta** al **blob de firma**. Normalmente se encuentra al final del archivo.\
Sin embargo, puedes encontrar información sobre esta sección en [**esta publicación de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) y en estos [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Soporte para el cifrado de binarios. Sin embargo, por supuesto, si un atacante consigue comprometer el proceso, podrá volcar la memoria sin cifrar.

### **`LC_LOAD_DYLINKER`**

Contiene la **ruta al ejecutable del dynamic linker** que mapea las bibliotecas compartidas en el espacio de direcciones del proceso. El **valor siempre se establece en `/usr/lib/dyld`**. Es importante señalar que, en macOS, el mapeo de dylib ocurre en **user mode**, no en **kernel mode**.

### **`LC_IDENT`**

Obsoleto, pero cuando se configura la generación de dumps tras un panic, se crea un core dump de Mach-O y la versión del kernel se establece en el comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatorio. No es útil directamente para nada, pero XNU lo almacena en caché junto con el resto de la información del proceso. Puede utilizarse en los crash reports.

### **`LC_BUILD_VERSION`**

Los binarios modernos normalmente incluyen este comando para declarar la **plataforma de destino**, la **versión mínima del sistema operativo**, la **versión del SDK** y, opcionalmente, las **versiones de las herramientas** utilizadas para compilar ese slice. Desde una perspectiva de offensive/reversing, esto resulta muy útil para identificar cómo se compiló una muestra y detectar rápidamente universal binaries extraños en los que un slice se compiló con un SDK o deployment target diferente. Los binarios más antiguos todavía pueden utilizar `LC_VERSION_MIN_*` en su lugar.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variables de entorno a dyld antes de que se ejecute el proceso. Esto puede ser muy peligroso, ya que puede permitir ejecutar código arbitrario dentro del proceso, por lo que este load command solo se utiliza en compilaciones de dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` y restringe aún más el procesamiento a variables con el formato `DYLD_..._PATH` que especifican rutas de carga.

### **`LC_DYLD_EXPORTS_TRIE` y `LC_DYLD_CHAINED_FIXUPS`**

Las toolchains recientes suelen almacenar los metadatos de export/bind/rebase en estos comandos en lugar de depender únicamente de los opcodes antiguos `LC_DYLD_INFO[_ONLY]`. Ambos son entradas `linkedit_data_command` que apuntan dentro de **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Trie compacto con los símbolos exportados por la imagen.
- **`LC_DYLD_CHAINED_FIXUPS`**: Cadenas de fixups por segmento utilizadas por dyld para aplicar rebases y binds. En Apple Silicon, aquí también encontrarás muchos fixups modernos de punteros autenticados.

Estos metadatos son muy útiles para reconstruir imports/exports, entender por qué una dependencia cargada mediante `@rpath` se resolvió de esa manera o averiguar por qué un intento de hook/rebinding falló en un objetivo moderno `arm64e`. `dyld_info` también puede utilizarse con **rutas de dylib que solo existen en la cache** y que no existen como archivos independientes en el disco, lo cual resulta muy útil en macOS moderno, donde muchas bibliotecas del sistema solo viven en la shared cache.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Este comando de carga moderno es principalmente relevante al inspeccionar **kernel collections / kernelcache-style filesets**. En lugar de representar una imagen independiente, el Mach-O externo actúa como un contenedor y cada `LC_FILESET_ENTRY` apunta a un Mach-O integrado con su propio **entry id** similar a una ruta, dirección de VM y desplazamiento en el archivo. Si estás haciendo reversing de componentes del kernel moderno de macOS/iOS, este comando suele ser el puente entre el contenedor de nivel superior y la imagen real que quieres extraer o desensamblar.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Para flujos de extracción prácticos, consulta [esta otra página sobre las extensiones del kernel de macOS y kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Este comando de carga describe una dependencia de **biblioteca** **dinámica** que **indica al cargador** (dyld) que **cargue y enlace dicha biblioteca**. Existe un comando de carga `LC_LOAD_DYLIB` **por cada biblioteca** que requiere el binario Mach-O.

- Este comando de carga es una estructura de tipo **`dylib_command`** (que contiene una estructura dylib, que describe la biblioteca dinámica dependiente concreta):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t versión de compatibilidad; / número de versión de compatibilidad de la library /](<../../../images/image (486).png>)

También puedes obtener esta información desde la CLI con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algunas bibliotecas potencialmente relacionadas con malware son:

- **DiskArbitration**: Monitorización de unidades USB
- **AVFoundation:** Captura de audio y vídeo
- **CoreWLAN**: Escaneos de Wi-Fi.

> [!TIP]
> Un binario Mach-O puede contener uno o **más** **constructors**, que se **ejecutarán** **antes** de la dirección especificada en **LC_MAIN**.\
> Los offsets de cualquier constructor se almacenan en la sección **\_\_mod_init_func** del segmento **\_\_DATA_CONST**.

## **Datos de Mach-O**

En el núcleo del archivo se encuentra la región de datos, que está compuesta por varios segmentos, tal como se define en la región de load-commands. **Cada segmento puede contener diversas secciones de datos**, y cada sección **contiene código o datos** específicos de un tipo.

> [!TIP]
> Los datos son básicamente la parte que contiene toda la **información** cargada por los load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Esto incluye:

- **Tabla de funciones:** Contiene información sobre las funciones del programa.
- **Tabla de símbolos**: Contiene información sobre la función externa utilizada por el binario.
- También podría contener nombres de funciones internas, variables y mucho más.

Para comprobarlo, puedes utilizar la herramienta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

O desde la cli:
```bash
size -m /bin/ls
```
## Secciones comunes de Objective-C

En el segmento `__TEXT` (r-x):

- `__objc_classname`: Nombres de clases (cadenas)
- `__objc_methname`: Nombres de métodos (cadenas)
- `__objc_methtype`: Tipos de métodos (cadenas)

En el segmento `__DATA` (rw-):

- `__objc_classlist`: Punteros a todas las clases de Objective-C
- `__objc_nlclslist`: Punteros a clases de Objective-C Non-Lazy
- `__objc_catlist`: Puntero a Categories
- `__objc_nlcatlist`: Punteros a Categories Non-Lazy
- `__objc_protolist`: Lista de Protocols
- `__objc_const`: Datos constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Referencias

- [1] [Las slices de Mach-O no son tan sencillas como podrías pensar](https://objective-see.org/blog/blog_0x80.html)
- [2] [Página del manual de dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Lectura de tus propios Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
