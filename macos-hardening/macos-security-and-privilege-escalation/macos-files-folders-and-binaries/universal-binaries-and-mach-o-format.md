# Binarios universales de macOS & Formato Mach-O

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Los binarios de Mac OS suelen compilarse como **binarios universales**. Un **binario universal** puede **soportar múltiples arquitecturas en el mismo archivo**.

Estos binarios siguen la **estructura Mach-O**, que básicamente está compuesta por:

* Encabezado
* Comandos de Carga
* Datos

![](<../../../.gitbook/assets/image (559).png>)

## Encabezado Fat

Busca el archivo con: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC o FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* número de estructuras que siguen */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* especificador de cpu (int) */
cpu_subtype_t	cpusubtype;	/* especificador de máquina (int) */
uint32_t	offset;		/* desplazamiento en el archivo a este archivo objeto */
uint32_t	size;		/* tamaño de este archivo objeto */
uint32_t	align;		/* alineación como potencia de 2 */
};
</code></pre>

El encabezado tiene los bytes **magic** seguidos por el **número** de **archs** que el archivo **contiene** (`nfat_arch`) y cada arch tendrá una estructura `fat_arch`.

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

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Como podrías estar pensando, usualmente un binario universal compilado para 2 arquitecturas **duplica el tamaño** de uno compilado solo para 1 arquitectura.

## **Encabezado Mach-O**

El encabezado contiene información básica sobre el archivo, como los bytes mágicos para identificarlo como un archivo Mach-O e información sobre la arquitectura objetivo. Puedes encontrarlo en: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Tipos de archivos**:

* MH\_EXECUTE (0x2): Ejecutable Mach-O estándar
* MH\_DYLIB (0x6): Biblioteca vinculada dinámicamente Mach-O (p. ej. .dylib)
* MH\_BUNDLE (0x8): Un paquete Mach-O (p. ej. .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
O utilizando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Comandos de carga Mach-O**

Esto especifica el **diseño del archivo en memoria**. Contiene la **ubicación de la tabla de símbolos**, el contexto del hilo principal al inicio de la ejecución y qué **bibliotecas compartidas** se requieren.\
Los comandos básicamente instruyen al cargador dinámico **(dyld) cómo cargar el binario en memoria.**

Todos los comandos de carga comienzan con una estructura **load\_command**, definida en el anteriormente mencionado **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Hay alrededor de **50 tipos diferentes de comandos de carga** que el sistema maneja de manera diferente. Los más comunes son: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` y `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Básicamente, este tipo de Comando de Carga define **cómo cargar los segmentos \_\_TEXT** (código ejecutable) **y \_\_DATA** (datos para el proceso) según los **desplazamientos indicados en la sección de Datos** cuando se ejecuta el binario.
{% endhint %}

Estos comandos **definen segmentos** que se **mapean** en el **espacio de memoria virtual** de un proceso cuando se ejecuta.

Hay **diferentes tipos** de segmentos, como el segmento **\_\_TEXT**, que contiene el código ejecutable de un programa, y el segmento **\_\_DATA**, que contiene datos utilizados por el proceso. Estos **segmentos se encuentran en la sección de datos** del archivo Mach-O.

**Cada segmento** puede dividirse aún más en múltiples **secciones**. La **estructura del comando de carga** contiene **información** sobre **estas secciones** dentro del segmento respectivo.

En el encabezado primero encuentras el **encabezado del segmento**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* para arquitecturas de 64 bits */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* incluye sizeof section_64 structs */
char		segname[16];	/* nombre del segmento */
uint64_t	vmaddr;		/* dirección de memoria de este segmento */
uint64_t	vmsize;		/* tamaño de memoria de este segmento */
uint64_t	fileoff;	/* desplazamiento del archivo de este segmento */
uint64_t	filesize;	/* cantidad a mapear desde el archivo */
int32_t		maxprot;	/* máxima protección de VM */
int32_t		initprot;	/* protección inicial de VM */
<strong>	uint32_t	nsects;		/* número de secciones en el segmento */
</strong>	uint32_t	flags;		/* banderas */
};
</code></pre>

Ejemplo de encabezado de segmento:

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Si **añades** el **desplazamiento de la sección** (0x37DC) + el **desplazamiento** donde **comienza la arquitectura**, en este caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

También es posible obtener **información de los encabezados** desde la **línea de comandos** con:
```bash
otool -lv /bin/ls
```
Segmentos comunes cargados por este cmd:

* **`__PAGEZERO`:** Instruye al kernel para **mapear** la **dirección cero** de modo que **no se pueda leer, escribir o ejecutar**. Las variables maxprot y minprot en la estructura se establecen en cero para indicar que **no hay derechos de lectura-escritura-ejecución en esta página**.
* Esta asignación es importante para **mitigar vulnerabilidades de desreferenciación de punteros NULL**.
* **`__TEXT`**: Contiene **código ejecutable** con permisos de **lectura** y **ejecución** (no escribible). Secciones comunes de este segmento:
* `__text`: Código binario compilado
* `__const`: Datos constantes
* `__cstring`: Constantes de cadena
* `__stubs` y `__stubs_helper`: Involucrados durante el proceso de carga de bibliotecas dinámicas
* **`__DATA`**: Contiene datos que son **legibles** y **escribibles** (no ejecutables).
* `__data`: Variables globales (que han sido inicializadas)
* `__bss`: Variables estáticas (que no han sido inicializadas)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Información utilizada por el tiempo de ejecución de Objective-C
* **`__LINKEDIT`**: Contiene información para el enlazador (dyld) como, "entradas de tabla de símbolos, cadenas y reubicación."
* **`__OBJC`**: Contiene información utilizada por el tiempo de ejecución de Objective-C. Aunque esta información también puede encontrarse en el segmento \_\_DATA, dentro de varias secciones en \_\_objc\_\*.

### **`LC_MAIN`**

Contiene el punto de entrada en el **atributo entryoff.** En el momento de la carga, **dyld** simplemente **suma** este valor a la **base (en memoria) del binario**, y luego **salta** a esta instrucción para comenzar la ejecución del código del binario.

### **LC\_CODE\_SIGNATURE**

Contiene información sobre la **firma de código del archivo Mach-O**. Solo contiene un **desplazamiento** que **apunta** al **blob de firma**. Esto está típicamente al final del archivo.\
Sin embargo, puedes encontrar información sobre esta sección en [**este post del blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) y en estos [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Contiene la **ruta al ejecutable del enlazador dinámico** que mapea las bibliotecas compartidas en el espacio de direcciones del proceso. El **valor siempre se establece en `/usr/lib/dyld`**. Es importante notar que en macOS, el mapeo de dylib ocurre en **modo usuario**, no en modo kernel.

### **`LC_LOAD_DYLIB`**

Este comando de carga describe una dependencia de **biblioteca dinámica** que **instruye** al **cargador** (dyld) para **cargar y enlazar dicha biblioteca**. Hay un comando de carga LC\_LOAD\_DYLIB **para cada biblioteca** que el binario Mach-O requiere.

* Este comando de carga es una estructura de tipo **`dylib_command`** (que contiene una struct dylib, describiendo la biblioteca dinámica dependiente real):
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
También puedes obtener esta información desde la CLI con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algunas bibliotecas potencialmente relacionadas con malware son:

* **DiskArbitration**: Monitoreo de unidades USB
* **AVFoundation:** Captura de audio y video
* **CoreWLAN**: Escaneos de Wifi.

{% hint style="info" %}
Un binario Mach-O puede contener uno o **más** **constructores**, que se **ejecutarán** **antes** de la dirección especificada en **LC\_MAIN**.\
Los desplazamientos de cualquier constructor se encuentran en la sección **\_\_mod\_init\_func** del segmento **\_\_DATA\_CONST**.
{% endhint %}

## **Datos de Mach-O**

El corazón del archivo es la región final, los datos, que consiste en una serie de segmentos dispuestos en la región de comandos de carga. **Cada segmento puede contener varias secciones de datos**. Cada una de estas secciones **contiene código o datos** de un tipo particular.

{% hint style="success" %}
Los datos son básicamente la parte que contiene toda la **información** que es cargada por los comandos de carga **LC\_SEGMENTS\_64**
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

Esto incluye:&#x20;

* **Tabla de funciones:** Que contiene información sobre las funciones del programa.
* **Tabla de símbolos**: Que contiene información sobre la función externa utilizada por el binario
* También podría contener nombres de funciones internas, variables y más.

Para verificarlo, podrías usar la herramienta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

O desde la cli:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
