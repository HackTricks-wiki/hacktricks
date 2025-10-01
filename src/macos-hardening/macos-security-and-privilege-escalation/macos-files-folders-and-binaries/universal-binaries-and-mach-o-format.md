# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I binari di macOS vengono solitamente compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

Questi binari seguono la **struttura Mach-O** che è sostanzialmente composta da:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Cerca il file con: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

L'header contiene i byte di **magic** seguiti dal **numero** di **archs** che il file **contiene** (`nfat_arch`) e ogni arch avrà una struttura `fat_arch`.

Verificalo con:

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

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Come potresti pensare, di solito un universal binary compilato per 2 architetture **raddoppia la dimensione** rispetto a uno compilato per una sola arch.

## **Mach-O Header**

L'header contiene informazioni di base sul file, come i magic bytes per identificarlo come file Mach-O e informazioni sull'architettura target. Puoi trovarlo in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Tipi di file Mach-O

Ci sono diversi tipi di file, puoi trovarli definiti nel [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). I più importanti sono:

- `MH_OBJECT`: Relocatable object file (prodotti intermedi della compilazione, non ancora eseguibili).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (no longer supported in XNU)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Linker dinamico
- `MH_BUNDLE`: "Plugin files". Generated using -bundle in gcc and explicitly loaded by `NSBundle` or `dlopen`.
- `MH_DYSM`: Companion `.dSym` file (file con i simboli per il debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flag di Mach-O**

Il codice sorgente definisce anche diversi flag utili per il caricamento delle librerie:

- `MH_NOUNDEFS`: Nessun riferimento indefinito (tutti i riferimenti risolti)
- `MH_DYLDLINK`: Collegamento dyld
- `MH_PREBOUND`: Riferimenti dinamici preassegnati.
- `MH_SPLIT_SEGS`: File con segmenti r/o e r/w separati.
- `MH_WEAK_DEFINES`: Il binario ha simboli definiti debolmente
- `MH_BINDS_TO_WEAK`: Il binario usa simboli deboli
- `MH_ALLOW_STACK_EXECUTION`: Rendere lo stack eseguibile
- `MH_NO_REEXPORTED_DYLIBS`: La libreria non ha comandi LC_REEXPORT
- `MH_PIE`: Eseguibile indipendente dalla posizione (PIE)
- `MH_HAS_TLV_DESCRIPTORS`: Presenza di una sezione con variabili locali al thread
- `MH_NO_HEAP_EXECUTION`: Nessuna esecuzione per le pagine heap/data
- `MH_HAS_OBJC`: Il binario contiene sezioni Objective-C
- `MH_SIM_SUPPORT`: Supporto al simulatore
- `MH_DYLIB_IN_CACHE`: Usato per dylibs/frameworks nella cache delle librerie condivise.

## **Comandi di caricamento Mach-O**

La **disposizione del file in memoria** viene specificata qui, dettagliando la **posizione della tabella dei simboli**, il contesto del main thread all'avvio dell'esecuzione, e le **librerie condivise** richieste. Vengono fornite istruzioni al dynamic loader **(dyld)** sul processo di caricamento del binario in memoria.

Viene utilizzata la struttura **load_command**, definita nel già citato **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Esistono circa **50 diversi tipi di load commands** che il sistema gestisce in modo differente. I più comuni sono: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> In pratica, questo tipo di Load Command definisce **come caricare i \_\_TEXT** (codice eseguibile) **e i \_\_DATA** (dati per il processo) **segments** in base agli **offset indicati nella Data section** quando il binario viene eseguito.

Questi comandi **definiscono segmenti** che vengono **mappati** nello **spazio di memoria virtuale** di un processo quando viene eseguito.

Esistono **diversi tipi** di segmenti, come il segmento **\_\_TEXT**, che contiene il codice eseguibile di un programma, e il segmento **\_\_DATA**, che contiene i dati utilizzati dal processo. Questi **segmenti sono situati nella Data section** del file Mach-O.

**Ogni segmento** può essere ulteriormente **diviso** in più **sezioni**. La **struttura del load command** contiene **informazioni** su **queste sezioni** all'interno del rispettivo segmento.

In the header first you find the **segment header**:

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

Example of segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Questo header definisce il **numero di sezioni i cui header appaiono dopo** di esso:
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
Esempio di **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Se **sommi** il **section offset** (0x37DC) + l'**offset** in cui inizia l'**arch**, in questo caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

È inoltre possibile ottenere le **headers information** dalla **command line** con:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Istruisce il kernel a **mappare** l'**indirizzo zero** così che **non possa essere letto, scritto o eseguito**. Le variabili maxprot e minprot nella struttura sono impostate a zero per indicare che **non ci sono diritti di lettura-scrittura-esecuzione su questa pagina**.
- Questa allocazione è importante per **mitigare vulnerabilità di dereferenziazione di puntatore NULL**. Questo perché XNU impone una hard page zero che assicura che la prima pagina (solo la prima) di memoria sia inaccessibile (eccetto in i386). Un binary potrebbe soddisfare questo requisito creando un piccolo \_\_PAGEZERO (usando il `-pagezero_size`) per coprire i primi 4k e rendendo il resto della memoria a 32 bit accessibile sia in user che in kernel mode.
- **`__TEXT`**: Contiene **codice** **eseguibile** con permessi di **lettura** e **esecuzione** (non scrivibile).
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
- `__unwind_info`: Stack unwind data.
- Nota che tutto questo contenuto è firmato ma anche marcato come eseguibile (creando più opzioni per lo sfruttamento di sezioni che non necessitano necessariamente di tale privilegio, come le sezioni dedicate alle stringhe).
- **`__DATA`**: Contiene dati che sono **leggibili** e **scrivibili** (non eseguibili).
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Information used by the Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const non è garantito come costante (permessi di scrittura), né lo sono altri puntatori e la GOT. Questa sezione rende `__const`, alcuni inizializzatori e la tabella GOT (una volta risolta) **sola lettura** usando `mprotect`.
- **`__LINKEDIT`**: Contiene informazioni per il linker (dyld) come tabelle di simboli, stringhe e voci di relocazione. È un contenitore generico per contenuti che non sono né in `__TEXT` né in `__DATA` e il suo contenuto è descritto in altri load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Contiene informazioni usate dal runtime Objective-C. Sebbene queste informazioni possano anche trovarsi nel segmento \_\_DATA, all'interno delle varie sezioni \_\_objc\_\*.
- **`__RESTRICT`**: Un segmento senza contenuto con una singola sezione chiamata **`__restrict`** (anch'essa vuota) che assicura che, all'esecuzione del binary, verranno ignorate le variabili ambientali DYLD.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene l'entrypoint nell'attributo **entryoff.** Al momento del load, **dyld** semplicemente **aggiunge** questo valore alla **base del binary** (in memoria), poi **salta** a questa istruzione per avviare l'esecuzione del codice del binary.

**`LC_UNIXTHREAD`** contiene i valori che i registri devono avere all'avvio del thread principale. Questo è già deprecato ma **`dyld`** lo usa ancora. È possibile vedere i valori dei registri impostati da questo con:
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


Contiene informazioni sulla **code signature del file Macho-O**. Contiene solo un **offset** che **punta** al **signature blob**. Tipicamente si trova alla fine del file.\
Tuttavia, puoi trovare alcune informazioni su questa sezione in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e in questo [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Supporta la cifratura del binario. Tuttavia, ovviamente, se un attacker riesce a compromettere il processo, potrà effettuare il dump della memoria non cifrata.

### **`LC_LOAD_DYLINKER`**

Contiene il **percorso all'eseguibile del dynamic linker** che mappa le shared libraries nello spazio degli indirizzi del processo. Il **valore è sempre impostato a `/usr/lib/dyld`**. È importante notare che in macOS, il mapping dei dylib avviene in **modalità utente**, non in modalità kernel.

### **`LC_IDENT`**

Obsoleto, ma quando configurato per generare dump su panic, viene creato un core dump Mach-O e la versione del kernel viene impostata nel comando `LC_IDENT`.

### **`LC_UUID`**

UUID casuale. Non è utile direttamente, ma XNU lo memorizza nella cache insieme al resto delle informazioni del processo. Può essere usato nei crash report.

### **`LC_DYLD_ENVIRONMENT`**

Permette di indicare variabili d'ambiente a dyld prima che il processo venga eseguito. Questo può essere molto pericoloso in quanto può permettere di eseguire codice arbitrario all'interno del processo, quindi questo load command è usato solo nelle build di dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` e limita ulteriormente l'elaborazione solo a variabili della forma `DYLD_..._PATH` che specificano load paths.

### **`LC_LOAD_DYLIB`**

This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to **load and link said library**. There is a `LC_LOAD_DYLIB` load command **for each library** that the Mach-O binary requires.

- Questo load command è una struttura di tipo **`dylib_command`** (che contiene una struct dylib, descrivendo la libreria dinamica dipendente reale):
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

Puoi anche ottenere queste informazioni dalla cli con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Alcune librerie potenzialmente correlate a malware sono:

- **DiskArbitration**: Monitoring USB drives
- **AVFoundation:** Capture audio and video
- **CoreWLAN**: Wifi scans.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

Al centro del file si trova la regione dati, che è composta da diversi segmenti come definiti nella regione load-commands. **Una varietà di data sections può essere ospitata all'interno di ogni segmento**, con ogni sezione **contenente code or data** specifici di un tipo.

> [!TIP]
> I dati sono fondamentalmente la parte che contiene tutte le **informazioni** che vengono caricate dai load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Questo include:

- **Function table:** Which holds information about the program functions.
- **Symbol table**: Which contains information about the external function used by the binary
- It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C Sezioni comuni

Nel segmento `__TEXT` (r-x):

- `__objc_classname`: Nomi delle classi (stringhe)
- `__objc_methname`: Nomi dei metodi (stringhe)
- `__objc_methtype`: Tipi dei metodi (stringhe)

Nel segmento `__DATA` (rw-):

- `__objc_classlist`: Puntatori a tutte le classi Objetive-C
- `__objc_nlclslist`: Puntatori alle classi Objective-C Non-Lazy
- `__objc_catlist`: Puntatore alle categorie
- `__objc_nlcatlist`: Puntatore a categorie Non-Lazy
- `__objc_protolist`: Elenco dei protocolli
- `__objc_const`: Dati costanti
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
