# macOS Binarios universales & Formato Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Los binarios de macOS normalmente se compilan como **binarios universales**. Un **binario universal** puede **soportar múltiples arquitecturas en el mismo archivo**.

Estos binarios siguen la **estructura Mach-O**, que básicamente se compone de:

- Encabezado
- Comandos de carga
- Datos

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Encabezado Fat

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

La cabecera tiene los bytes **magic** seguidos por el **número** de **arquitecturas** que el archivo **contiene** (`nfat_arch`) y cada arquitectura tendrá una estructura `fat_arch`.

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

Como puedes imaginar, normalmente un binario universal compilado para 2 arquitecturas **duplica el tamaño** de uno compilado sólo para 1 arquitectura.

## **Cabecera Mach-O**

La cabecera contiene información básica sobre el archivo, como los bytes magic para identificarlo como un archivo Mach-O y la información sobre la arquitectura objetivo. Puedes encontrarla en: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Hay diferentes tipos de archivo, puedes encontrarlos definidos en el [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Los más importantes son:

- `MH_OBJECT`: Archivo objeto reubicable (productos intermedios de la compilación, aún no ejecutables).
- `MH_EXECUTE`: Archivos ejecutables.
- `MH_FVMLIB`: Archivo de biblioteca de VM fija.
- `MH_CORE`: Volcados de código
- `MH_PRELOAD`: Archivo ejecutable precargado (ya no es compatible en XNU)
- `MH_DYLIB`: Bibliotecas dinámicas
- `MH_DYLINKER`: Enlazador dinámico
- `MH_BUNDLE`: "Plugin files". Generados usando -bundle en gcc y cargados explícitamente por `NSBundle` o `dlopen`.
- `MH_DYSM`: Archivo complementario `.dSym` (archivo con símbolos para depuración).
- `MH_KEXT_BUNDLE`: Extensiones del kernel.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

El código fuente también define varias flags útiles para cargar librerías:

- `MH_NOUNDEFS`: Sin referencias indefinidas (completamente enlazado)
- `MH_DYLDLINK`: Enlazado por dyld
- `MH_PREBOUND`: Referencias dinámicas preenlazadas.
- `MH_SPLIT_SEGS`: El archivo divide segmentos r/o y r/w.
- `MH_WEAK_DEFINES`: El binario tiene símbolos definidos como débiles
- `MH_BINDS_TO_WEAK`: El binario utiliza símbolos débiles
- `MH_ALLOW_STACK_EXECUTION`: Hacer la pila ejecutable
- `MH_NO_REEXPORTED_DYLIBS`: La librería no tiene comandos LC_REEXPORT
- `MH_PIE`: Ejecutable independiente de posición
- `MH_HAS_TLV_DESCRIPTORS`: Hay una sección con variables locales por hilo
- `MH_NO_HEAP_EXECUTION`: No ejecución en páginas de heap/datos
- `MH_HAS_OBJC`: El binario tiene secciones Objective-C
- `MH_SIM_SUPPORT`: Soporte para simulador
- `MH_DYLIB_IN_CACHE`: Usado en dylibs/frameworks en la caché de librerías compartidas.

## **Mach-O Load commands**

El diseño del archivo en memoria se especifica aquí, detallando la ubicación de la tabla de símbolos, el contexto del hilo principal al iniciar la ejecución y las librerías compartidas requeridas. Se proporcionan instrucciones al cargador dinámico (dyld) sobre el proceso de carga del binario en memoria.

Esto usa la estructura `load_command`, definida en el mencionado `loader.h`:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Hay alrededor de **50 diferentes tipos de load commands** que el sistema maneja de forma distinta. Los más comunes son: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, y `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Básicamente, este tipo de Load Command define **cómo cargar los \_\_TEXT** (código ejecutable) **y \_\_DATA** (datos para el proceso) **segments** de acuerdo con los **offsets indicados en la sección de datos** cuando el binario se ejecuta.

Estos comandos **definen segmentos** que se **mapean** en el **espacio de memoria virtual** de un proceso cuando se ejecuta.

Hay **diferentes tipos** de segmentos, como el segmento **\_\_TEXT**, que contiene el código ejecutable de un programa, y el segmento **\_\_DATA**, que contiene los datos usados por el proceso. Estos **segmentos están ubicados en la sección de datos** del archivo Mach-O.

**Cada segmento** puede ser a su vez **dividido** en múltiples **secciones**. La **estructura del load command** contiene **información** sobre **estas secciones** dentro del segmento correspondiente.

En el encabezado primero encuentras la **cabecera del segmento**:

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

Ejemplo de cabecera de segmento:

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

Si **sumas** el **offset de sección** (0x37DC) + el **offset** donde **empieza la arch**, en este caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

También es posible obtener la **información de encabezados** desde la **línea de comandos** con:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Indica al kernel que **mapee** la **dirección cero** para que **no pueda ser leída, escrita ni ejecutada**. Las variables maxprot y minprot en la estructura se establecen a cero para indicar que **no hay permisos de lectura-escritura-ejecución en esta página**.
- Esta asignación es importante para **mitigar vulnerabilidades por desreferencia de puntero NULL**. Esto es porque XNU aplica una página cero estricta que asegura que la primera página (solo la primera) de la memoria sea inaccesible (excepto en i386). Un binario podría cumplir este requisito creando un pequeño \_\_PAGEZERO (usando `-pagezero_size`) para cubrir los primeros 4k y haciendo que el resto de la memoria de 32 bits sea accesible tanto en modo usuario como en modo kernel.
- **`__TEXT`**: Contiene **código** **ejecutable** con permisos de **lectura** y **ejecución** (no escribible)**.** Secciones comunes de este segmento:
- `__text`: Código binario compilado
- `__const`: Datos constantes (solo lectura)
- `__[c/u/os_log]string`: Constantes de cadenas C, Unicode u os_log
- `__stubs` and `__stubs_helper`: Involucradas durante el proceso de carga de librerías dinámicas
- `__unwind_info`: Datos para unwind del stack.
- Ten en cuenta que todo este contenido está firmado pero además marcado como ejecutable (creando más opciones para la explotación de secciones que no necesitan necesariamente este privilegio, como secciones dedicadas a cadenas).
- **`__DATA`**: Contiene datos que son **legibles** y **escribibles** (no ejecutables)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Puntero a símbolo non-lazy (bind al cargar)
- `__la_symbol_ptr`: Puntero a símbolo lazy (bind al usar)
- `__const`: Debería ser datos de solo lectura (no siempre lo es)
- `__cfstring`: Cadenas de CoreFoundation
- `__data`: Variables globales (que han sido inicializadas)
- `__bss`: Variables estáticas (que no han sido inicializadas)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Información usada por el runtime de Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const no está garantizado como constante (tiene permisos de escritura), ni lo están otros punteros y la GOT. Esta sección hace que `__const`, algunos inicializadores y la tabla GOT (una vez resuelta) sean **solo lectura** usando `mprotect`.
- **`__LINKEDIT`**: Contiene información para el linker (dyld) como tablas de símbolos, cadenas y entradas de relocación. Es un contenedor genérico para contenidos que no están en `__TEXT` ni en `__DATA` y su contenido se describe en otros load commands.
- Información de dyld: Rebase, opcodes de enlace Non-lazy/lazy/weak e información de exportación
- Functions starts: Tabla de direcciones de inicio de funciones
- Data In Code: Islas de datos en \_\_text
- SYmbol Table: Símbolos en el binario
- Indirect Symbol Table: Símbolos puntero/stub
- String Table
- Code Signature
- **`__OBJC`**: Contiene información usada por el runtime de Objective-C. Aunque esta información también puede encontrarse en el segmento \_\_DATA, dentro de varias secciones \_\_objc\_\*.
- **`__RESTRICT`**: Un segmento sin contenido con una sola sección llamada **`__restrict`** (también vacía) que asegura que al ejecutar el binario, se ignorarán las variables de entorno de DYLD.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contains the entrypoint in the **entryoff attribute.** At load time, **dyld** simply **adds** this value to the (in-memory) **base of the binary**, then **jumps** to this instruction to start execution of the binary’s code.

**`LC_UNIXTHREAD`** contains the values the register must have when starting the main thread. This was already deprecated but **`dyld`** still uses it. It's possible to see the vlaues of the registers set by this with:
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


Contiene información sobre la **code signature del archivo Mach-O**. Solo contiene un **offset** que **apunta** al **signature blob**. Esto típicamente está al final del archivo.\
Sin embargo, puedes encontrar algo de información sobre esta sección en [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) y en este [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Soporte para binary encryption. Sin embargo, claro, si un atacante logra comprometer el proceso, podrá dump the memory sin cifrar.

### **`LC_LOAD_DYLINKER`**

Contiene el **path to the dynamic linker executable** que mapea shared libraries en el espacio de direcciones del proceso. El **valor siempre está establecido en `/usr/lib/dyld`**. Es importante notar que en macOS, el dylib mapping ocurre en **user mode**, no en kernel mode.

### **`LC_IDENT`**

Obsoleto, pero cuando está configurado para generar dumps on panic, se crea un Mach-O core dump y la versión del kernel se establece en el comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatorio. No es particularmente útil por sí solo, pero XNU lo cachea con el resto de la información del proceso. Puede usarse en crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Permite indicar environment variables to the dyld antes de que el proceso sea ejecutado. Esto puede ser muy peligroso, ya que puede permitir la ejecución de código arbitrario dentro del proceso, por lo que este load command solo se usa en builds de dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` y además restringe el procesamiento solo a variables de la forma `DYLD_..._PATH` que especifican load paths.

### **`LC_LOAD_DYLIB`**

Este load command describe una dependencia de **dynamic library** que **instruciona** al **loader** (dyld) para **load and link dicha librería**. Existe un `LC_LOAD_DYLIB` load command **por cada librería** que el binary Mach-O requiere.

- Este load command es una estructura del tipo **`dylib_command`** (que contiene un struct dylib, describiendo la actual dynamic library dependiente):
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
![](<../../../images/image (486).png>)

También puedes obtener esta información desde la CLI con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algunas librerías relacionadas con malware potencial son:

- **DiskArbitration**: Monitoreo de unidades USB
- **AVFoundation:** Capturar audio y vídeo
- **CoreWLAN**: Escaneos de Wi‑Fi.

> [!TIP]
> Un binario Mach-O puede contener uno o **más** **constructores**, que serán **ejecutados** **antes** de la dirección especificada en **LC_MAIN**.\
> Los offsets de cualquier constructor se almacenan en la sección **\_\_mod_init_func** del segmento **\_\_DATA_CONST**.

## **Datos Mach-O**

En el núcleo del archivo se encuentra la región de datos, que está compuesta por varios segmentos según se definen en la región de load-commands. **Una variedad de secciones de datos puede alojarse dentro de cada segmento**, con cada sección **conteniendo código o datos** específicos de un tipo.

> [!TIP]
> Los datos son básicamente la parte que contiene toda la **información** que es cargada por los load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Esto incluye:

- **Function table:** Que contiene información sobre las funciones del programa.
- **Symbol table**: Que contiene información sobre las funciones externas usadas por el binario
- También podría contener funciones internas, nombres de variables y más.

Para comprobarlo puedes usar la herramienta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

O desde la cli:
```bash
size -m /bin/ls
```
## Secciones comunes de Objective-C

En el segmento `__TEXT` (r-x):

- `__objc_classname`: Nombres de clase (cadenas)
- `__objc_methname`: Nombres de método (cadenas)
- `__objc_methtype`: Tipos de método (cadenas)

En el segmento `__DATA` (rw-):

- `__objc_classlist`: Punteros a todas las clases de Objective-C
- `__objc_nlclslist`: Punteros a Non-Lazy Objective-C classes
- `__objc_catlist`: Puntero a Categories
- `__objc_nlcatlist`: Puntero a Non-Lazy Categories
- `__objc_protolist`: Lista de protocolos
- `__objc_const`: Datos constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
