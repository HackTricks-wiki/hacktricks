# Binarios universales de macOS y formato Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

macOS usa el formato ejecutable **Mach-O**. Un binario **universal**, o fat, contiene varios slices de Mach-O específicos para cada arquitectura en un mismo archivo. Los encabezados de código abierto `fat.h` y `loader.h` de Apple definen las estructuras y constantes descritas en esta página. <sup>[[5]](#references)</sup>

Una imagen Mach-O se compone de:

- Encabezado
- Load Commands
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

El encabezado contiene los bytes **magic**, seguidos del **número** de **arquitecturas** que **contiene** el archivo (`nfat_arch`); cada arquitectura tendrá una estructura `fat_arch`.

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

o con la herramienta [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Como quizá estés pensando, normalmente un binario universal compilado para 2 arquitecturas **duplica el tamaño** de uno compilado para una sola arquitectura.

> [!TIP]
> Al analizar malware o aplicaciones sospechosas, no te detengas cuando `file` informe de la arquitectura «más adecuada». Un binario universal puede ocultar imports, load commands o metadatos del compilador distintos en cada slice, así que primero enumera **todos** los slices y luego inspecciónalos de forma independiente:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Los SDK recientes de macOS también incluyen funciones auxiliares como `macho_for_each_slice()` y `macho_best_slice()` en `<mach-o/utils.h>`. La segunda resulta útil para emular lo que cargaría dyld/kernel, pero los escáneres deberían seguir iterando por todos los slices para evitar pasar por alto contenido específico de una arquitectura.<sup>[[1]](#references)</sup>

## **Mach-O Header**

El header contiene información básica sobre el archivo, como bytes mágicos para identificarlo como un archivo Mach-O e información sobre la arquitectura de destino. Puedes encontrarlo con: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

- `MH_OBJECT`: Archivo objeto reubicable (productos intermedios de la compilación; todavía no son ejecutables).
- `MH_EXECUTE`: Archivos ejecutables.
- `MH_FVMLIB`: Archivo de biblioteca VM fija.
- `MH_CORE`: Volcados de código
- `MH_PRELOAD`: Archivo ejecutable precargado (ya no es compatible con XNU).
- `MH_DYLIB`: Bibliotecas dinámicas
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Archivos de plugin". Se generan usando -bundle en gcc y se cargan explícitamente mediante `NSBundle` o `dlopen`.
- `MH_DYSM`: Archivo `.dSym` complementario (archivo con símbolos para depuración).
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

## **Flags de Mach-O**

El código fuente también define varios flags útiles para cargar bibliotecas:

- `MH_NOUNDEFS`: Sin referencias no definidas (enlazado por completo)
- `MH_DYLDLINK`: Enlazado de Dyld
- `MH_PREBOUND`: Referencias dinámicas preenlazadas.
- `MH_SPLIT_SEGS`: El archivo divide los segmentos de solo lectura y de lectura/escritura.
- `MH_WEAK_DEFINES`: El binario tiene símbolos definidos débiles
- `MH_BINDS_TO_WEAK`: El binario usa símbolos débiles
- `MH_ALLOW_STACK_EXECUTION`: Hace que la pila sea ejecutable
- `MH_NO_REEXPORTED_DYLIBS`: La biblioteca no tiene comandos LC_REEXPORT
- `MH_PIE`: Ejecutable independiente de la posición
- `MH_HAS_TLV_DESCRIPTORS`: Hay una sección con variables locales al hilo
- `MH_NO_HEAP_EXECUTION`: No permite la ejecución en páginas del heap/datos
- `MH_HAS_OBJC`: El binario tiene secciones de Objective-C
- `MH_SIM_SUPPORT`: Compatibilidad con el simulador
- `MH_DYLIB_IN_CACHE`: Se usa en dylibs/frameworks de la caché de bibliotecas compartidas.

## **Comandos de carga de Mach-O**

Aquí se especifica la **disposición del archivo en memoria**, con detalles sobre la **ubicación de la tabla de símbolos**, el contexto del hilo principal al inicio de la ejecución y las **bibliotecas compartidas** necesarias. Se proporcionan instrucciones al cargador dinámico **(dyld)** sobre el proceso de carga del binario en memoria.

Se utiliza la estructura **load_command**, definida en el archivo mencionado **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Básicamente, este tipo de comando de carga define **cómo cargar los segmentos \_\_TEXT** (código ejecutable) **y \_\_DATA** (datos del proceso) **de acuerdo con los offsets indicados en la sección Data** cuando se ejecuta el binario.

Estos comandos **definen segmentos** que se **mapean** en el **espacio de memoria virtual** de un proceso cuando se ejecuta.

Hay **diferentes tipos** de segmentos, como el segmento **\_\_TEXT**, que contiene el código ejecutable de un programa, y el segmento **\_\_DATA**, que contiene datos utilizados por el proceso. Estos **segmentos se encuentran en la sección de datos** del archivo Mach-O.

Cada **segmento** puede **dividirse** a su vez en múltiples **secciones**. La **estructura del comando de carga** contiene **información** sobre **estas secciones** dentro del segmento correspondiente.

En el encabezado primero se encuentra el **encabezado del segmento**:

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

Ejemplo de encabezado de segmento:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Este encabezado define el **número de secciones cuyos encabezados aparecen después**:

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

Si **sumas** el **desplazamiento de sección** (0x37DC) + el **desplazamiento** donde **empieza la arquitectura**, en este caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

También es posible obtener **información de los encabezados** desde la **línea de comandos** con:

```bash
otool -lv /bin/ls
```

Segmentos comunes cargados por este comando:

- **`__PAGEZERO`:** Indica al kernel que **mapee** la **dirección cero** para que no se pueda **leer, escribir ni ejecutar**. Las variables maxprot y minprot de la estructura se establecen en cero para indicar que **esta página no tiene permisos de lectura, escritura ni ejecución**.
  - Esta asignación es importante para **mitigar las vulnerabilidades de desreferencia de punteros NULL**. Esto se debe a que XNU aplica una página cero protegida que garantiza que la primera página (y solo la primera) de memoria sea inaccesible (excepto en i386). Un binario podría cumplir este requisito creando un \_\_PAGEZERO pequeño (mediante `-pagezero_size`) que cubra los primeros 4k y dejando el resto de la memoria de 32 bits accesible tanto en modo de usuario como de kernel.
- **`__TEXT`**: Contiene **código** **ejecutable** con permisos de **lectura** y **ejecución** (sin escritura)**.** Secciones comunes de este segmento:
  - `__text`: Código binario compilado
  - `__const`: Datos constantes (solo lectura)
  - `__[c/u/os_log]string`: Constantes de cadenas de C, Unicode o logs de os
  - `__stubs` y `__stubs_helper`: Intervienen durante el proceso de carga de bibliotecas dinámicas
  - `__unwind_info`: Datos para desenrollar la pila.
  - Ten en cuenta que todo este contenido está firmado, pero también marcado como ejecutable (lo que crea más opciones para explotar secciones que no necesariamente necesitan este privilegio, como las secciones dedicadas a cadenas).
- **`__DATA`**: Contiene datos **legibles** y **modificables** (no ejecutables)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Puntero a símbolos no perezosos (se enlazan al cargar)
  - `__la_symbol_ptr`: Puntero a símbolos perezosos (se enlazan al usarlos)
  - `__const`: Debería ser de solo lectura (en realidad no lo es)
  - `__cfstring`: Cadenas de CoreFoundation
  - `__data`: Variables globales (que se han inicializado)
  - `__bss`: Variables estáticas (que no se han inicializado)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc.): Información utilizada por el runtime de Objective-C
- **`__DATA_CONST`**: No se garantiza que \_\_DATA.\_\_const sea constante (tiene permisos de escritura), ni tampoco otros punteros y la GOT. Este segmento hace que `__const`, algunos inicializadores y la tabla GOT (una vez resuelta) sean **de solo lectura** mediante `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Comunes en binarios recientes de Apple Silicon. Estos segmentos contienen punteros que deben autenticarse al cargar o usar (por ejemplo, `__auth_got`). Si una técnica de rebinding, hook o modificación de imports solo comprueba las secciones heredadas `__got` / `__la_symbol_ptr`, podría pasar por alto los puntos de llamada reales en los binarios modernos `arm64e`. Para más detalles sobre estas secciones, consulta [esta página](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contiene información para el enlazador (dyld), como entradas de las tablas de símbolos, cadenas y reubicaciones. Es un contenedor genérico para contenido que no está en `__TEXT` ni en `__DATA`; su contenido se describe en otros comandos de carga.
  - Información de dyld: Rebase, opcodes de enlace no perezoso/perezoso/débil e información de exportación
  - Inicios de funciones: Tabla de direcciones de inicio de funciones
  - Data In Code: Islas de datos en \_\_text
  - Tabla de símbolos: Símbolos del binario
  - Tabla de símbolos indirectos: Símbolos de punteros/stubs
  - Tabla de cadenas
  - Firma de código
- **`__OBJC`**: Contiene información utilizada por el runtime de Objective-C. Sin embargo, esta información también podría encontrarse en el segmento \_\_DATA, dentro de varias secciones \_\_objc\_\*.
- **`__RESTRICT`**: Un segmento sin contenido que tiene una única sección llamada **`__restrict`** (también vacía), que garantiza que, al ejecutar el binario, se ignoren las variables de entorno de DYLD.

Como se podía ver en el código, **los segmentos también admiten flags** (aunque no se usan mucho):

- `SG_HIGHVM`: Solo Core (no se usa)
- `SG_FVMLIB`: No se usa
- `SG_NORELOC`: El segmento no tiene reubicaciones
- `SG_PROTECTED_VERSION_1`: Cifrado. Finder lo usa, por ejemplo, para cifrar el segmento de texto `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene el punto de entrada en el atributo **entryoff.** Al cargar, **dyld** simplemente **suma** este valor a la **base del binario** (en memoria) y luego **salta** a esta instrucción para iniciar la ejecución del código del binario.

**`LC_UNIXTHREAD`** contiene los valores que deben tener los registros al iniciar el hilo principal. Esto ya estaba obsoleto, pero **`dyld`** todavía lo usa. Es posible ver los valores de los registros establecidos mediante esto con:

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


Contiene información sobre la **firma de código del archivo Macho-O**. Solo contiene un **desplazamiento** que **apunta** al **blob de firma**. Normalmente, este se encuentra al final del archivo.\
Puedes encontrar más información sobre esta sección en [**esta publicación del blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) y [**este gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Compatibilidad con el cifrado de binarios. Sin embargo, por supuesto, si un atacante consigue comprometer el proceso, podrá volcar la memoria sin cifrar.

### **`LC_LOAD_DYLINKER`**

Contiene la **ruta al ejecutable del enlazador dinámico**, que asigna bibliotecas compartidas al espacio de direcciones del proceso. El **valor siempre es `/usr/lib/dyld`**. Es importante tener en cuenta que, en macOS, la asignación de dylib ocurre en **modo usuario**, no en modo kernel.

### **`LC_IDENT`**

Está obsoleto, pero cuando se configura para generar volcados durante un panic, se crea un volcado de núcleo Mach-O y la versión del kernel se establece en el comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatorio. No es útil para nada directamente, pero XNU lo almacena en caché junto con el resto de la información del proceso. Puede utilizarse en informes de fallos.

### **`LC_BUILD_VERSION`**

Los binarios modernos suelen incluir este comando para declarar la **plataforma de destino**, la **versión mínima del sistema operativo**, la **versión del SDK** y, opcionalmente, las **versiones de las herramientas** utilizadas para compilar esa slice. Desde una perspectiva ofensiva/de reversing, esto resulta muy útil para identificar cómo se compiló una muestra y detectar rápidamente binarios universales inusuales en los que una slice se compiló con un SDK o un deployment target diferente. Los binarios más antiguos pueden seguir usando `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variables de entorno a dyld antes de que se ejecute el proceso. Esto puede ser muy peligroso, ya que puede permitir ejecutar código arbitrario dentro del proceso, por lo que este comando de carga solo se usa en compilaciones de dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` y restringe aún más el procesamiento a variables con el formato `DYLD_..._PATH` que especifican rutas de carga.

### **`LC_DYLD_EXPORTS_TRIE` y `LC_DYLD_CHAINED_FIXUPS`**

Las toolchains recientes suelen almacenar metadatos de exportación, vinculación y rebase en estos comandos, en vez de depender únicamente de los opcodes más antiguos de `LC_DYLD_INFO[_ONLY]`. Ambos son entradas `linkedit_data_command` que apuntan a **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Trie compacto con los símbolos exportados por la imagen.
- **`LC_DYLD_CHAINED_FIXUPS`**: Cadenas de fixups por segmento que dyld utiliza para aplicar rebases y vinculaciones. En Apple Silicon, aquí también encontrarás muchos fixups modernos de punteros autenticados.

Estos metadatos son muy útiles para reconstruir importaciones y exportaciones, entender por qué una dependencia cargada mediante `@rpath` se resolvió de determinada forma o averiguar por qué falló un intento de hook/rebinding en un destino `arm64e` moderno. También se puede usar `dyld_info` con **rutas de dylib que solo existen en la caché** y no como archivos independientes en el disco, algo muy práctico en macOS moderno, donde muchas bibliotecas del sistema solo existen en la caché compartida.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Este comando de carga moderno es especialmente relevante al inspeccionar **kernel collections / filesets de tipo kernelcache**. En lugar de representar una imagen independiente, el Mach-O externo actúa como contenedor y cada `LC_FILESET_ENTRY` apunta a un Mach-O incrustado con su propio **entry id** similar a una ruta, dirección VM y desplazamiento en el archivo. Si estás haciendo reverse engineering de componentes modernos del kernel de macOS/iOS, este comando suele ser el puente entre el contenedor de nivel superior y la imagen que quieres extraer o desensamblar.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Para workflows prácticos de extracción, consulta [esta otra página sobre las extensiones del kernel de macOS y kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Este comando de carga describe una dependencia de una **biblioteca** **dinámica** que **indica** al **loader** (dyld) que **cargue y vincule dicha biblioteca**. Hay un comando de carga `LC_LOAD_DYLIB` **por cada biblioteca** que requiere el binario Mach-O.

- Este comando de carga es una estructura de tipo **`dylib_command`** (que contiene una estructura dylib que describe la biblioteca dinámica dependiente):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t versión de compatibilidad; / número de versión de compatibilidad de la biblioteca /](<../../../images/image (486).png>)

También puedes obtener esta información desde la CLI con:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Algunas bibliotecas potencialmente relacionadas con malware son:

- **DiskArbitration**: supervisa unidades USB
- **AVFoundation:** captura audio y video
- **CoreWLAN**: realiza escaneos de Wifi.

> [!TIP]
> Un binario Mach-O puede contener uno o **más** **constructores**, que se **ejecutarán** **antes** de la dirección especificada en **LC_MAIN**.\
> Los offsets de los constructores se encuentran en la sección **\_\_mod_init_func** del segmento **\_\_DATA_CONST**.

## **Datos de Mach-O**

En el núcleo del archivo se encuentra la región de datos, compuesta por varios segmentos, tal como se definen en la región de load commands. **Cada segmento puede contener una variedad de secciones de datos**, y cada sección **contiene código o datos** específicos de un tipo.

> [!TIP]
> Los datos son básicamente la parte que contiene toda la **información** cargada por los load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Esto incluye:

- **Tabla de funciones:** contiene información sobre las funciones del programa.
- **Tabla de símbolos**: contiene información sobre las funciones externas utilizadas por el binario.
- También puede contener nombres de funciones y variables internas, entre otros.

Para comprobarlo, puedes usar la herramienta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

O desde la CLI:

```bash
size -m /bin/ls
```

### Datos añadidos y overlays analizados en sentido inverso

Un loader puede almacenar la configuración en datos añadidos en lugar de en una sección Mach-O con nombre. Luego, un parser inverso se ancla en un marcador final, lee un tamaño almacenado justo antes de este y usa ese valor para localizar y descifrar el blob precedente. Un loader universal observado usaba este diseño para una URL de downloader cifrada con XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Al analizar mediante ingeniería inversa un binario desconocido, inspecciona los bytes alrededor de marcadores de fin reconocibles y sigue cada cálculo de tamaño hacia atrás antes de asumir que las cadenas o la configuración deben pertenecer a una sección de comandos de carga. El marcador y la clave XOR son específicos de la muestra; la técnica reutilizable es el tráiler autodescriptivo.

## Secciones comunes de Objective-C

En el segmento `__TEXT` (r-x):

- `__objc_classname`: Nombres de clases (cadenas)
- `__objc_methname`: Nombres de métodos (cadenas)
- `__objc_methtype`: Tipos de métodos (cadenas)

En el segmento `__DATA` (rw-):

- `__objc_classlist`: Punteros a todas las clases de Objective-C
- `__objc_nlclslist`: Punteros a las clases de Objective-C Non-Lazy
- `__objc_catlist`: Puntero a las categorías
- `__objc_nlcatlist`: Punteros a las categorías Non-Lazy
- `__objc_protolist`: Lista de protocolos
- `__objc_const`: Datos constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Consulta también: [Carga reflectiva de Mach-O](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Los segmentos de Mach-O no son tan sencillos como podrías pensar](https://objective-see.org/blog/blog_0x80.html)
- [2] [Página man de dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Cómo leer tus propios entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source: `fat.h` y `loader.h` de Mach-O](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist: Una nueva versión del stealer MacSync para macOS apunta a entusiastas de las criptomonedas y desarrolladores](https://securelist.com/macsync-new-version/121383/)
