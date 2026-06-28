# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

I binari di Mac OS di solito sono compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

Questi binari seguono la **struttura Mach-O** che, in pratica, è composta da:

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

L'header ha i byte **magic** seguiti dal **numero** di **archs** che il file **contiene** (`nfat_arch`) e ogni arch avrà una struct `fat_arch`.

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

oppure usando lo strumento [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Come puoi immaginare, di solito un universal binary compilato per 2 architetture **raddoppia la dimensione** di uno compilato per 1 sola arch.

> [!TIP]
> Quando analizzi malware o app sospette, non fermarti dopo che `file` riporta la "best" architecture. Un universal binary può nascondere import diversi, load commands o metadati del compilatore in ogni slice, quindi enumera prima **tutte** le slice e poi ispezionale singolarmente:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Recenti macOS SDK espongono anche helper come `macho_for_each_slice()` e `macho_best_slice()` in `<mach-o/utils.h>`. Quest'ultimo è utile per emulare ciò che caricherebbe dyld/kernel, ma gli scanner dovrebbero comunque iterare ogni slice per evitare di perdere contenuto specifico dell'architettura.

## **Mach-O Header**

L'header contiene informazioni di base sul file, come i magic bytes per identificarlo come file Mach-O e informazioni sull'architettura di destinazione. Puoi trovarlo in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Ci sono diversi tipi di file, puoi trovarli definiti nel [**source code per esempio qui**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). I più importanti sono:

- `MH_OBJECT`: File oggetto relocabile (prodotti intermedi della compilazione, non ancora eseguibili).
- `MH_EXECUTE`: File eseguibili.
- `MH_FVMLIB`: File di libreria VM fissa.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: File eseguibile precaricato (non più supportato in XNU)
- `MH_DYLIB`: Librerie dinamiche
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Generati usando -bundle in gcc e caricati esplicitamente da `NSBundle` o `dlopen`.
- `MH_DYSM`: File `.dSym` associato (file con simboli per il debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oppure usando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Il codice sorgente definisce anche diversi flag utili per il caricamento delle librerie:

- `MH_NOUNDEFS`: Nessun riferimento non definito (completamente collegato)
- `MH_DYLDLINK`: Collegamento Dyld
- `MH_PREBOUND`: Riferimenti dinamici precollegati.
- `MH_SPLIT_SEGS`: Il file divide i segmenti r/o e r/w.
- `MH_WEAK_DEFINES`: Il binario ha simboli definiti weak
- `MH_BINDS_TO_WEAK`: Il binario usa simboli weak
- `MH_ALLOW_STACK_EXECUTION`: Rende lo stack eseguibile
- `MH_NO_REEXPORTED_DYLIBS`: La libreria non ha comandi LC_REEXPORT
- `MH_PIE`: Eseguibile indipendente dalla posizione
- `MH_HAS_TLV_DESCRIPTORS`: Esiste una sezione con variabili thread local
- `MH_NO_HEAP_EXECUTION`: Nessuna esecuzione per le pagine heap/data
- `MH_HAS_OBJC`: Il binario ha sezioni oBject-C
- `MH_SIM_SUPPORT`: Supporto per simulator
- `MH_DYLIB_IN_CACHE`: Usato su dylib/framework nella shared library cache.

## **Mach-O Load commands**

Il **layout del file in memoria** è specificato qui, dettagliando la **posizione della symbol table**, il contesto del thread principale all'inizio dell'esecuzione e le **shared libraries** richieste. Vengono fornite istruzioni al dynamic loader **(dyld)** sul processo di caricamento del binario in memoria.

Usa la struttura **load_command**, definita nel menzionato **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Ci sono circa **50 diversi tipi di load commands** che il sistema gestisce in modo differente. I più comuni sono: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, e `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> In pratica, questo tipo di Load Command definisce **come caricare i segmenti \_\_TEXT** (codice eseguibile) **e \_\_DATA** (dati per il processo) **in base agli offset indicati nella sezione Data** quando il binario viene eseguito.

Questi comandi **definiscono segmenti** che vengono **mappati** nello **spazio di memoria virtuale** di un processo quando viene eseguito.

Esistono **diversi tipi** di segmenti, come il segmento **\_\_TEXT**, che contiene il codice eseguibile di un programma, e il segmento **\_\_DATA**, che contiene i dati usati dal processo. Questi **segmenti si trovano nella sezione data** del file Mach-O.

**Ogni segmento** può essere ulteriormente **diviso** in più **section**. La **struttura del load command** contiene **informazioni** su **queste section** all'interno del rispettivo segmento.

Nell'header per primo trovi l'**header del segmento**:

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

Esempio di header del segmento:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Questo header definisce il **numero di section i cui header compaiono dopo** di esso:
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
Esempio di **intestazione di sezione**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Se **aggiungi** il **section offset** (0x37DC) + l'**offset** in cui inizia l'**arch**, in questo caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

È anche possibile ottenere le **informazioni sugli header** dalla **command line** con:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Instructs the kernel to **mappare** the **address zero** so che **non possa essere letta, scritta o eseguita**. Le variabili maxprot e minprot nella struttura sono impostate a zero per indicare che **non ci sono diritti di read-write-execute su questa pagina**.
- Questa allocazione è importante per **mitigare vulnerabilità di NULL pointer dereference**. Questo perché XNU impone una hard page zero che garantisce che la prima pagina (solo la prima) di memoria sia inaccessibile (tranne in i386). Un binary potrebbe soddisfare questo requisito creando un piccolo \_\_PAGEZERO (usando `-pagezero_size`) per coprire i primi 4k e avere il resto della memoria 32bit accessibile sia in user che in kernel mode.
- **`__TEXT`**: Contiene **code** **eseguibile** con permessi di **read** e **execute** (non writable)**.** Sezioni comuni di questo segment:
- `__text`: Codice binary compilato
- `__const`: Dati costanti (read only)
- `__[c/u/os_log]string`: stringhe costanti C, Unicode o os logs
- `__stubs` e `__stubs_helper`: Coinvolti durante il processo di caricamento delle librerie dinamiche
- `__unwind_info`: Dati di stack unwind.
- Nota che tutto questo contenuto è signed ma anche marcato come executable (creando più opzioni per l'exploitation di sezioni che non necessariamente hanno bisogno di questo privilegio, come le sezioni dedicate alle stringhe).
- **`__DATA`**: Contiene dati che sono **readable** e **writable** (no executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: puntatore a simbolo Non lazy (bind at load)
- `__la_symbol_ptr`: puntatore a simbolo Lazy (bind on use)
- `__const`: Dovrebbe essere dati read-only (non davvero)
- `__cfstring`: stringhe CoreFoundation
- `__data`: variabili globali (che sono state inizializzate)
- `__bss`: variabili statiche (che non sono state inizializzate)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informazioni usate dal runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const non è garantito che sia costante (write permissions), né lo sono altri puntatori e la GOT. Questa sezione rende `__const`, alcuni initializer e la tabella GOT (una volta risolta) **read only** usando `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Comuni nei binary recenti Apple Silicon. Questi segment contengono puntatori che devono essere authenticated al load o al momento dell'uso (ad esempio `__auth_got`). Se un trucco di rebinding, hook o import-patching controlla solo le vecchie sezioni `__got` / `__la_symbol_ptr`, può perdere i veri call sites nei moderni binary `arm64e`. Per maggiori dettagli su queste sezioni controlla [questa pagina](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contiene informazioni per il linker (dyld) come entry di symbol, string e relocation table. È un contenitore generico per contenuti che non sono né in `__TEXT` né in `__DATA` e il suo contenuto è descritto in altri load commands.
- informazioni dyld: Rebase, opcodes di Non-lazy/lazy/weak binding e info di export
- Functions starts: tabella degli indirizzi di inizio delle functions
- Data In Code: isole di data in \_\_text
- SYmbol Table: symbols nel binary
- Indirect Symbol Table: pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Contiene informazioni usate dal runtime Objective-C. Anche se queste informazioni potrebbero essere trovate anche nel segment \_\_DATA, all'interno di varie sezioni \_\_objc\_\*.
- **`__RESTRICT`**: Un segment senza contenuto con una singola sezione chiamata **`__restrict`** (anch'essa vuota) che garantisce che, quando il binary viene eseguito, ignorerà le variabili ambientali DYLD.

Come si è potuto vedere nel code, **i segments supportano anche flags** (anche se non sono usati molto):

- `SG_HIGHVM`: Solo Core (non usato)
- `SG_FVMLIB`: Non usato
- `SG_NORELOC`: Il segment non ha relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Usato per esempio da Finder per encryptare il segment `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene l'entrypoint nell'attributo **entryoff.** Al load time, **dyld** semplicemente **aggiunge** questo valore alla **base del binary** (in memory), poi **salta** a questa istruzione per iniziare l'esecuzione del code del binary.

**`LC_UNIXTHREAD`** contiene i valori che il register deve avere quando si avvia il main thread. Questo era già deprecato ma **`dyld`** lo usa ancora. È possibile vedere i valori dei register impostati da questo con:
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


Contiene informazioni sulla **code signature del file Macho-O**. Contiene solo un **offset** che **punta** al **signature blob**. Questo si trova in genere alla fine del file.\
Tuttavia, puoi trovare alcune informazioni su questa sezione in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e in questi [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Supporto per la binary encryption. Tuttavia, ovviamente, se un attacker riesce a compromettere il processo, potrà fare dump della memoria non crittografata.

### **`LC_LOAD_DYLINKER`**

Contiene il **path all'eseguibile dynamic linker** che mappa le shared libraries nello spazio di indirizzamento del processo. Il **valore è sempre impostato su `/usr/lib/dyld`**. È importante notare che in macOS, il mapping delle dylib avviene in **user mode**, non in kernel mode.

### **`LC_IDENT`**

Obsoleto, ma quando configurato per generare dump in caso di panic, viene creato un Mach-O core dump e la versione del kernel viene impostata nel comando `LC_IDENT`.

### **`LC_UUID`**

UUID casuale. Non è utile direttamente per nulla, ma XNU lo memorizza nella cache insieme al resto delle informazioni del processo. Può essere usato nei crash reports.

### **`LC_BUILD_VERSION`**

I binary moderni di solito includono questo comando per dichiarare la **target platform**, la **minimum OS version**, la **SDK version** e, opzionalmente, le **tool versions** usate per costruire quella slice. Da una prospettiva offensive/reversing, questo è molto utile per fare fingerprint di come è stato costruito un sample e per individuare rapidamente strani universal binaries in cui una slice è stata compilata con un SDK o un deployment target diverso. I binary più vecchi possono ancora usare invece `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Permette di indicare variabili d'ambiente a dyld prima che il processo venga eseguito. Questo può essere molto pericoloso perché può consentire di eseguire codice arbitrario all'interno del processo, quindi questo load command è usato solo in build di dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` e restringe ulteriormente l'elaborazione solo a variabili del tipo `DYLD_..._PATH` che specificano i load path.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

I toolchain recenti spesso memorizzano i metadata di export/bind/rebase in questi command invece di affidarsi solo ai vecchi opcode di `LC_DYLD_INFO[_ONLY]`. Entrambi sono entry `linkedit_data_command` che puntano dentro **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: trie compatto con i simboli esportati dall'immagine.
- **`LC_DYLD_CHAINED_FIXUPS`**: catene di fixup per segmento usate da dyld per applicare rebase e bind. Su Apple Silicon qui incontrerai anche molti moderni fixup di authenticated pointer.

Questi metadata sono molto utili quando ricostruisci import/export, capisci perché una dipendenza caricata con `@rpath` si è risolta in un certo modo, o capisci perché un tentativo di hook/rebinding è fallito su un target moderno `arm64e`. `dyld_info` può anche essere usato contro i percorsi di dylib del **cache-only** che non esistono come file standalone su disco, il che è molto utile su macOS moderno dove molte librerie di sistema vivono solo nella shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Questo moderno load command è rilevante soprattutto quando si ispezionano **kernel collections / kernelcache-style filesets**. Invece di rappresentare una singola immagine autonoma, il Mach-O esterno agisce come un contenitore e ogni `LC_FILESET_ENTRY` punta a un Mach-O incorporato con un proprio **entry id** simile a un path, un indirizzo VM e un offset nel file. Se stai facendo reverse di moderni componenti kernel di macOS/iOS, questo comando è spesso il ponte tra il container di alto livello e la vera immagine che vuoi estrarre o disassemblare.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Per workflow di estrazione pratici, controlla [questa altra pagina sulle estensioni del kernel di macOS e kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Questo load command descrive una dipendenza da una **libreria** **dinamica** che **istruisce** il **loader** (dyld) a **caricare e linkare la suddetta libreria**. Esiste un load command `LC_LOAD_DYLIB` **per ogni libreria** richiesta dal binario Mach-O.

- Questo load command è una struttura di tipo **`dylib_command`** (che contiene una struct dylib, che descrive la libreria dinamica dipendente reale):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / library's compatibility vers number /](<../../../images/image (486).png>)

Puoi anche ottenere queste informazioni dal cli con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: Monitoring USB drives
- **AVFoundation:** Capture audio and video
- **CoreWLAN**: Wifi scans.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

At the core of the file lies the data region, which is composed of several segments as defined in the load-commands region. **A variety of data sections can be housed within each segment**, with each section **holding code or data** specific to a type.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Which holds information about the program functions.
- **Symbol table**: Which contains information about the external function used by the binary
- It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Sezioni comuni di Objetive-C

Nel segmento `__TEXT` (r-x):

- `__objc_classname`: Nomi delle classi (stringhe)
- `__objc_methname`: Nomi dei metodi (stringhe)
- `__objc_methtype`: Tipi dei metodi (stringhe)

Nel segmento `__DATA` (rw-):

- `__objc_classlist`: Puntatori a tutte le classi Objetive-C
- `__objc_nlclslist`: Puntatori alle classi Objective-C Non-Lazy
- `__objc_catlist`: Puntatore a Categories
- `__objc_nlcatlist`: Puntatore a Non-Lazy Categories
- `__objc_protolist`: Lista dei protocolli
- `__objc_const`: Dati costanti
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Riferimenti

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
