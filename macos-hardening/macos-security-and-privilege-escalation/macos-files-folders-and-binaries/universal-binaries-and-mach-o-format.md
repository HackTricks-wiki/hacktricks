# Binarios universales de macOS y formato Mach-O

## Información básica

Los binarios de Mac OS generalmente se compilan como **binarios universales**. Un **binario universal** puede **soportar múltiples arquitecturas en el mismo archivo**.

Estos binarios siguen la estructura **Mach-O** que básicamente está compuesta por:

* Encabezado
* Comandos de carga
* Datos

![](<../../../.gitbook/assets/image (559).png>)

## Encabezado Fat

Busque el archivo con: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

El encabezado tiene los bytes **magic** seguidos del **número** de **archivos** que el archivo **contiene** (`nfat_arch`) y cada archivo tendrá una estructura `fat_arch`.

Verifíquelo con:

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

<figure><img src="../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

Como puede estar pensando, por lo general, un binario universal compilado para 2 arquitecturas **duplica el tamaño** de uno compilado para solo 1 arquitectura.

## Encabezado Mach-O

El encabezado contiene información básica sobre el archivo, como bytes mágicos para identificarlo como un archivo Mach-O e información sobre la arquitectura de destino. Puede encontrarlo en: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Tipos de archivo**:

* MH\_EXECUTE (0x2): Ejecutable Mach-O estándar
* MH\_DYLIB (0x6): Una biblioteca dinámica Mach-O (es decir, .dylib)
* MH\_BUNDLE (0x8): Un paquete Mach-O (es decir, .bundle)
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

Esto especifica la **disposición del archivo en memoria**. Contiene la **ubicación de la tabla de símbolos**, el contexto del hilo principal al comienzo de la ejecución y qué **bibliotecas compartidas** son necesarias.\
Los comandos básicamente instruyen al cargador dinámico **(dyld) cómo cargar el binario en memoria.**

Los comandos de carga comienzan todos con una estructura **load\_command**, definida en el **`loader.h`** mencionado anteriormente:
```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```
Hay alrededor de **50 tipos diferentes de comandos de carga** que el sistema maneja de manera diferente. Los más comunes son: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` y `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Básicamente, este tipo de comando de carga define **cómo cargar las secciones** que se almacenan en DATA cuando se ejecuta el binario.
{% endhint %}

Estos comandos **definen segmentos** que se **mapean** en el **espacio de memoria virtual** de un proceso cuando se ejecuta.

Existen **diferentes tipos** de segmentos, como el segmento **\_\_TEXT**, que contiene el código ejecutable de un programa, y el segmento **\_\_DATA**, que contiene datos utilizados por el proceso. Estos **segmentos se encuentran en la sección de datos** del archivo Mach-O.

**Cada segmento** se puede dividir aún más en múltiples **secciones**. La **estructura del comando de carga** contiene **información** sobre **estas secciones** dentro del segmento respectivo.

En el encabezado primero se encuentra el **encabezado del segmento**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* para arquitecturas de 64 bits */
	uint32_t	cmd;		/* LC_SEGMENT_64 */
	uint32_t	cmdsize;	/* incluye el tamaño de las estructuras section_64 */
	char		segname[16];	/* nombre del segmento */
	uint64_t	vmaddr;		/* dirección de memoria de este segmento */
	uint64_t	vmsize;		/* tamaño de memoria de este segmento */
	uint64_t	fileoff;	/* desplazamiento del archivo de este segmento */
	uint64_t	filesize;	/* cantidad a mapear desde el archivo */
	int32_t		maxprot;	/* protección VM máxima */
	int32_t		initprot;	/* protección VM inicial */
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

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Si **agregas** el **desplazamiento de sección** (0x37DC) + el **desplazamiento** donde comienza la **arquitectura**, en este caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

También es posible obtener **información de encabezado** desde la **línea de comandos** con:
```bash
otool -lv /bin/ls
```
Segmentos comunes cargados por este cmd:

* **`__PAGEZERO`:** Instruye al kernel a **mapear** la **dirección cero** para que **no se pueda leer, escribir o ejecutar**. Las variables maxprot y minprot en la estructura se establecen en cero para indicar que no hay **derechos de lectura-escritura-ejecución en esta página**. 
  * Esta asignación es importante para **mitigar vulnerabilidades de referencia de puntero nulo**.
* **`__TEXT`**: Contiene **código ejecutable** y **datos** que son **solo de lectura**. Secciones comunes de este segmento:
  * `__text`: Código binario compilado
  * `__const`: Datos constantes
  * `__cstring`: Constantes de cadena
  * `__stubs` y `__stubs_helper`: Involucrados durante el proceso de carga de bibliotecas dinámicas
* **`__DATA`**: Contiene datos que son **escribibles**.
  * `__data`: Variables globales (que han sido inicializadas)
  * `__bss`: Variables estáticas (que no han sido inicializadas)
  * `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Información utilizada por el tiempo de ejecución de Objective-C
* **`__LINKEDIT`**: Contiene información para el enlazador (dyld) como, "símbolo, cadena y entradas de tabla de reubicación".
* **`__OBJC`**: Contiene información utilizada por el tiempo de ejecución de Objective-C. Aunque esta información también se puede encontrar en el segmento \_\_DATA, dentro de varias secciones en \_\_objc\_\*.

### **`LC_MAIN`**

Contiene el punto de entrada en el atributo **entryoff**. En el momento de la carga, **dyld** simplemente **agrega** este valor a la **base del binario en memoria**, luego **salta** a esta instrucción para comenzar la ejecución del código binario.

### **LC\_CODE\_SIGNATURE**

Contiene información sobre la **firma de código del archivo Macho-O**. Solo contiene un **desplazamiento** que **apunta** al **bloque de firma**. Esto suele estar al final del archivo.

### **LC\_LOAD\_DYLINKER**

Contiene la **ruta al ejecutable del enlazador dinámico** que mapea bibliotecas compartidas en el espacio de direcciones del proceso. El **valor siempre se establece en `/usr/lib/dyld`**. Es importante tener en cuenta que en macOS, el mapeo de dylib ocurre en **modo de usuario**, no en modo kernel.

### **`LC_LOAD_DYLIB`**

Este comando de carga describe una **dependencia de biblioteca dinámica** que **instruye** al **cargador** (dyld) a **cargar y enlazar dicha biblioteca**. Hay un comando de carga LC\_LOAD\_DYLIB **para cada biblioteca** que requiere el binario Mach-O.

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
También puedes obtener esta información desde la línea de comandos con:
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

## **Datos Mach-O**

El corazón del archivo es la región final, los datos, que consta de varios segmentos como se describe en la región de comandos de carga. **Cada segmento puede contener varias secciones de datos**. Cada una de estas secciones **contiene código o datos** de un tipo particular.

{% hint style="success" %}
Los datos son básicamente la parte que contiene toda la información cargada por los comandos de carga LC\_SEGMENTS\_64
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

Esto incluye:&#x20;

* **Tabla de funciones:** Que contiene información sobre las funciones del programa.
* **Tabla de símbolos**: Que contiene información sobre las funciones externas utilizadas por el binario.
* También podría contener nombres de funciones internas, variables y más.

Para verificarlo, se puede utilizar la herramienta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

O desde la línea de comandos:
```bash
size -m /bin/ls
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
