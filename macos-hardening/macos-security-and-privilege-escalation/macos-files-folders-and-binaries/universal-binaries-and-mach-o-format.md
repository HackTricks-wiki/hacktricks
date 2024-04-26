# Binarios universales de macOS y Formato Mach-O

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Información Básica

Los binarios de Mac OS generalmente se compilan como **binarios universales**. Un **binario universal** puede **soportar múltiples arquitecturas en el mismo archivo**.

Estos binarios siguen la estructura **Mach-O** que básicamente se compone de:

* Encabezado
* Comandos de carga
* Datos

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (467).png>)

## Encabezado Fat

Busca el archivo con: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* número de estructuras que siguen */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* especificador de CPU (int) */
cpu_subtype_t	cpusubtype;	/* especificador de máquina (int) */
uint32_t	offset;		/* desplazamiento de archivo a este archivo de objeto */
uint32_t	size;		/* tamaño de este archivo de objeto */
uint32_t	align;		/* alineación como una potencia de 2 */
};
</code></pre>

El encabezado tiene los bytes **mágicos** seguidos del **número** de **arquitecturas** que el archivo **contiene** (`nfat_arch`) y cada arquitectura tendrá una estructura `fat_arch`.

Verifícalo con:

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

<figure><img src="../../../.gitbook/assets/image (1091).png" alt=""><figcaption></figcaption></figure>

Como estarás pensando, generalmente un binario universal compilado para 2 arquitecturas **duplica el tamaño** de uno compilado para solo 1 arquitectura.

## **Encabezado Mach-O**

El encabezado contiene información básica sobre el archivo, como bytes mágicos para identificarlo como un archivo Mach-O e información sobre la arquitectura objetivo. Puedes encontrarlo en: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Tipos de Archivos Mach-O

Existen diferentes tipos de archivos, puedes encontrar su definición en el [**código fuente, por ejemplo aquí**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). Los más importantes son:

* `MH_OBJECT`: Archivo de objeto relocatable (productos intermedios de la compilación, aún no son ejecutables).
* `MH_EXECUTE`: Archivos ejecutables.
* `MH_FVMLIB`: Archivo de biblioteca VM fija.
* `MH_CORE`: Volcados de código.
* `MH_PRELOAD`: Archivo ejecutable precargado (ya no es compatible en XNU).
* `MH_DYLIB`: Bibliotecas dinámicas.
* `MH_DYLINKER`: Enlazador dinámico.
* `MH_BUNDLE`: Archivos "plugin". Generados usando -bundle en gcc y cargados explícitamente por `NSBundle` o `dlopen`.
* `MH_DYSM`: Archivo compañero `.dSym` (archivo con símbolos para depuración).
* `MH_KEXT_BUNDLE`: Extensiones de kernel.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
O utilizando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1130).png" alt=""><figcaption></figcaption></figure>

## **Banderas Mach-O**

El código fuente también define varias banderas útiles para cargar bibliotecas:

* `MH_NOUNDEFS`: Sin referencias indefinidas (totalmente enlazado)
* `MH_DYLDLINK`: Enlace Dyld
* `MH_PREBOUND`: Referencias dinámicas preenlazadas.
* `MH_SPLIT_SEGS`: Archivo divide segmentos de solo lectura y lectura/escritura.
* `MH_WEAK_DEFINES`: Binario tiene símbolos débilmente definidos
* `MH_BINDS_TO_WEAK`: Binario utiliza símbolos débiles
* `MH_ALLOW_STACK_EXECUTION`: Hacer la pila ejecutable
* `MH_NO_REEXPORTED_DYLIBS`: Biblioteca sin comandos LC\_REEXPORT
* `MH_PIE`: Ejecutable de posición independiente
* `MH_HAS_TLV_DESCRIPTORS`: Hay una sección con variables locales de subprocesos
* `MH_NO_HEAP_EXECUTION`: Sin ejecución para páginas de montón/datos
* `MH_HAS_OBJC`: Binario tiene secciones de Objective-C
* `MH_SIM_SUPPORT`: Soporte para simulador
* `MH_DYLIB_IN_CACHE`: Usado en dylibs/frameworks en caché de biblioteca compartida.

## **Comandos de Carga Mach-O**

La **disposición del archivo en memoria** se especifica aquí, detallando la **ubicación de la tabla de símbolos**, el contexto del hilo principal al inicio de la ejecución, y las **bibliotecas compartidas** requeridas. Se proporcionan instrucciones al cargador dinámico **(dyld)** sobre el proceso de carga del binario en memoria.

Se utiliza la estructura **load\_command**, definida en el mencionado **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Hay alrededor de **50 tipos diferentes de comandos de carga** que el sistema maneja de manera diferente. Los más comunes son: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` y `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Básicamente, este tipo de Comando de Carga define **cómo cargar los segmentos \_\_TEXT** (código ejecutable) **y \_\_DATA** (datos para el proceso) **según los desplazamientos indicados en la sección de Datos** cuando se ejecuta el binario.
{% endhint %}

Estos comandos **definen segmentos** que se **mapean** en el **espacio de memoria virtual** de un proceso cuando se ejecuta.

Existen **diferentes tipos** de segmentos, como el segmento **\_\_TEXT**, que contiene el código ejecutable de un programa, y el segmento **\_\_DATA**, que contiene datos utilizados por el proceso. Estos **segmentos se encuentran en la sección de datos** del archivo Mach-O.

**Cada segmento** puede dividirse aún más en múltiples **secciones**. La **estructura del comando de carga** contiene **información** sobre **estas secciones** dentro del segmento respectivo.

En el encabezado primero se encuentra el **encabezado del segmento**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* para arquitecturas de 64 bits */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* incluye el tamaño de las estructuras section_64 */
char		segname[16];	/* nombre del segmento */
uint64_t	vmaddr;		/* dirección de memoria de este segmento */
uint64_t	vmsize;		/* tamaño de memoria de este segmento */
uint64_t	fileoff;	/* desplazamiento en el archivo de este segmento */
uint64_t	filesize;	/* cantidad a mapear desde el archivo */
int32_t		maxprot;	/* protección VM máxima */
int32_t		initprot;	/* protección VM inicial */
<strong>	uint32_t	nsects;		/* número de secciones en el segmento */
</strong>	uint32_t	flags;		/* banderas */
};
</code></pre>

Ejemplo de encabezado de segmento:

<figure><img src="../../../.gitbook/assets/image (1123).png" alt=""><figcaption></figcaption></figure>

Este encabezado define el **número de secciones cuyos encabezados aparecen después** de él:
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

<figure><img src="../../../.gitbook/assets/image (1105).png" alt=""><figcaption></figcaption></figure>

Si **sumas** el **desplazamiento de la sección** (0x37DC) + el **desplazamiento** donde **comienza la arquitectura**, en este caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

También es posible obtener **información de encabezados** desde la **línea de comandos** con:
```bash
otool -lv /bin/ls
```
```markdown
Segmentos comunes cargados por este cmd:

* **`__PAGEZERO`:** Instruye al kernel a **mapear** la **dirección cero** para que **no se pueda leer, escribir o ejecutar**. Las variables maxprot y minprot en la estructura se establecen en cero para indicar que no hay **derechos de lectura-escritura-ejecución en esta página**.
* Esta asignación es importante para **mitigar vulnerabilidades de referencia nula de puntero**. Esto se debe a que XNU hace cumplir una página cero dura que asegura que la primera página (solo la primera) de memoria sea inaccesible (excepto en i386). Un binario podría cumplir con estos requisitos creando un pequeño \_\_PAGEZERO (usando `-pagezero_size`) para cubrir los primeros 4k y teniendo el resto de la memoria de 32 bits accesible tanto en modo usuario como en modo kernel.
* **`__TEXT`**: Contiene **código ejecutable** con permisos de **lectura** y **ejecución** (no escritura)**.** Secciones comunes de este segmento:
* `__text`: Código binario compilado
* `__const`: Datos constantes (solo lectura)
* `__[c/u/os_log]string`: Constantes de cadena de C, Unicode u os logs
* `__stubs` y `__stubs_helper`: Involucrados durante el proceso de carga de bibliotecas dinámicas
* `__unwind_info`: Datos de desenrollado de pila.
* Tenga en cuenta que todo este contenido está firmado pero también marcado como ejecutable (creando más opciones para la explotación de secciones que no necesariamente necesitan este privilegio, como secciones dedicadas a cadenas).
* **`__DATA`**: Contiene datos que son **legibles** y **escribibles** (no ejecutables)**.**
* `__got:` Tabla de Desplazamiento Global
* `__nl_symbol_ptr`: Puntero de símbolo no perezoso (vinculado en la carga)
* `__la_symbol_ptr`: Puntero de símbolo perezoso (vinculado en uso)
* `__const`: Debería ser datos de solo lectura (no realmente)
* `__cfstring`: Cadenas de CoreFoundation
* `__data`: Variables globales (que han sido inicializadas)
* `__bss`: Variables estáticas (que no han sido inicializadas)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Información utilizada por el tiempo de ejecución de Objective-C
* **`__DATA_CONST`**: \_\_DATA.\_\_const no está garantizado que sea constante (permisos de escritura), al igual que otros punteros y la GOT. Esta sección hace que `__const`, algunos inicializadores y la tabla GOT (una vez resuelta) sean **solo lectura** usando `mprotect`.
* **`__LINKEDIT`**: Contiene información para el enlazador (dyld) como, símbolos, cadenas y entradas de tabla de reubicación. Es un contenedor genérico para contenidos que no están ni en `__TEXT` ni en `__DATA` y su contenido se describe en otros comandos de carga.
* Información de dyld: Rebase, opcodes de enlace no perezoso/perezoso/débil e información de exportación
* Inicio de funciones: Tabla de direcciones de inicio de funciones
* Datos en Código: Islas de datos en \_\_text
* Tabla de Símbolos: Símbolos en binario
* Tabla de Símbolos Indirectos: Símbolos de puntero/stub
* Tabla de Cadenas
* Firma de Código
* **`__OBJC`**: Contiene información utilizada por el tiempo de ejecución de Objective-C. Aunque esta información también se puede encontrar en el segmento \_\_DATA, dentro de varias secciones en \_\_objc\_\*.
* **`__RESTRICT`**: Un segmento sin contenido con una sola sección llamada **`__restrict`** (también vacía) que asegura que al ejecutar el binario, ignorará las variables de entorno de DYLD.

Como se pudo ver en el código, **los segmentos también admiten banderas** (aunque no se usan mucho):

* `SG_HIGHVM`: Solo núcleo (no utilizado)
* `SG_FVMLIB`: No utilizado
* `SG_NORELOC`: El segmento no tiene reubicación
* `SG_PROTECTED_VERSION_1`: Cifrado. Utilizado, por ejemplo, por Finder para cifrar el segmento de texto `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene el punto de entrada en el atributo **entryoff**. En el momento de carga, **dyld** simplemente **agrega** este valor a la **base del binario** (en memoria), luego **salta** a esta instrucción para comenzar la ejecución del código del binario.

**`LC_UNIXTHREAD`** contiene los valores que deben tener los registros al iniciar el hilo principal. Esto ya fue desaprobado pero **`dyld`** todavía lo utiliza. Es posible ver los valores de los registros establecidos por esto con:
```
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

Contiene información sobre la **firma de código del archivo Mach-O**. Solo contiene un **desplazamiento** que **apunta** al **bloque de firma**. Esto suele estar al final del archivo.\
Sin embargo, puedes encontrar información sobre esta sección en [**esta publicación de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) y en este [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Soporte para encriptación binaria. Sin embargo, si un atacante logra comprometer el proceso, podrá volcar la memoria sin cifrar.

### **`LC_LOAD_DYLINKER`**

Contiene la **ruta al ejecutable del enlazador dinámico** que mapea bibliotecas compartidas en el espacio de direcciones del proceso. El **valor siempre está configurado en `/usr/lib/dyld`**. Es importante tener en cuenta que en macOS, el mapeo de dylib ocurre en **modo de usuario**, no en modo kernel.

### **`LC_IDENT`**

Obsoleto, pero cuando se configura para generar volcados en caso de fallo, se crea un volcado central Mach-O y se establece la versión del kernel en el comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatorio. No es útil directamente, pero XNU lo almacena en caché con el resto de la información del proceso. Puede ser utilizado en informes de fallos.

### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variables de entorno al dyld antes de que se ejecute el proceso. Esto puede ser muy peligroso, ya que puede permitir ejecutar código arbitrario dentro del proceso, por lo que este comando de carga solo se utiliza en dyld construido con `#define SUPPORT_LC_DYLD_ENVIRONMENT` y restringe aún más el procesamiento solo a variables de la forma `DYLD_..._PATH` especificando rutas de carga.

### **`LC_LOAD_DYLIB`**

Este comando de carga describe una **dependencia de biblioteca dinámica** que **instruye** al **cargador** (dyld) a **cargar y enlazar dicha biblioteca**. Hay un comando de carga `LC_LOAD_DYLIB` **para cada biblioteca** que el binario Mach-O requiere.

* Este comando de carga es una estructura de tipo **`dylib_command`** (que contiene una estructura dylib, describiendo la biblioteca dinámica dependiente real):
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
![](<../../../.gitbook/assets/image (483).png>)

También puedes obtener esta información desde la línea de comandos con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algunas bibliotecas potencialmente relacionadas con malware son:

- **DiskArbitration**: Monitoreo de unidades USB
- **AVFoundation**: Captura de audio y video
- **CoreWLAN**: Escaneos de Wifi.

{% hint style="info" %}
Un binario Mach-O puede contener uno o **más constructores**, que se **ejecutarán antes** de la dirección especificada en **LC\_MAIN**.\
Los desplazamientos de cualquier constructor se encuentran en la sección **\_\_mod\_init\_func** del segmento **\_\_DATA\_CONST**.
{% endhint %}

## **Datos Mach-O**

En el núcleo del archivo se encuentra la región de datos, que está compuesta por varios segmentos definidos en la región de comandos de carga. **Una variedad de secciones de datos pueden estar alojadas dentro de cada segmento**, con cada sección **conteniendo código o datos** específicos de un tipo.

{% hint style="success" %}
Los datos son básicamente la parte que contiene toda la **información** que es cargada por los comandos de carga **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Esto incluye:

- **Tabla de funciones:** Que contiene información sobre las funciones del programa.
- **Tabla de símbolos**: Que contiene información sobre la función externa utilizada por el binario
- También podría contener funciones internas, nombres de variables y más.

Para verificarlo, puedes usar la herramienta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

O desde la línea de comandos:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
