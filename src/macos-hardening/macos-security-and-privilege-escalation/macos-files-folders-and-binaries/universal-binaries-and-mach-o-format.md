# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I binari di Mac OS sono solitamente compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

Questi binari seguono la struttura **Mach-O**, che è sostanzialmente composta da:

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

L'header contiene i byte **magic**, seguiti dal **numero** di **architetture** che il file **contiene** (`nfat_arch`), e ogni architettura avrà una struct `fat_arch`.

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

Come forse stai pensando, solitamente un universal binary compilato per 2 architetture ha una **dimensione doppia** rispetto a uno compilato per una sola architettura.

> [!TIP]
> Quando analizzi malware o app sospette, non fermarti dopo che `file` ha indicato l'architettura "migliore". Un universal binary può nascondere importazioni, load commands o metadati del compilatore diversi in ogni slice, quindi enumera prima **tutte** le slice e poi analizzale indipendentemente:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
I macOS SDK recenti espongono anche helper come `macho_for_each_slice()` e `macho_best_slice()` in `<mach-o/utils.h>`. Quest'ultimo è utile per emulare ciò che dyld/kernel caricherebbe, ma gli scanner dovrebbero comunque analizzare ogni slice per evitare di perdere contenuti specifici per l'architettura.<sup>[1]</sup>

## **Header Mach-O**

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

Esistono diversi tipi di file, definiti nel [**codice sorgente, ad esempio qui**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). I più importanti sono:

- `MH_OBJECT`: File oggetto rilocabile (prodotti intermedi della compilazione, non ancora eseguibili).
- `MH_EXECUTE`: File eseguibili.
- `MH_FVMLIB`: File di libreria VM fissa.
- `MH_CORE`: Dump del codice.
- `MH_PRELOAD`: File eseguibile precaricato (non più supportato in XNU).
- `MH_DYLIB`: Librerie dinamiche.
- `MH_DYLINKER`: Dynamic Linker.
- `MH_BUNDLE`: "File di plugin". Generati usando -bundle in gcc e caricati esplicitamente da `NSBundle` o `dlopen`.
- `MH_DYSM`: File `.dSym` associato (file contenente i simboli per il debugging).
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

## **Flag Mach-O**

Il codice sorgente definisce anche diversi flag utili per il caricamento delle librerie:

- `MH_NOUNDEFS`: Nessun riferimento non definito (completamente linked)
- `MH_DYLDLINK`: Linking tramite Dyld
- `MH_PREBOUND`: Riferimenti dinamici prebound.
- `MH_SPLIT_SEGS`: Il file separa i segmenti r/o e r/w.
- `MH_WEAK_DEFINES`: Il binary contiene simboli definiti deboli
- `MH_BINDS_TO_WEAK`: Il binary utilizza simboli deboli
- `MH_ALLOW_STACK_EXECUTION`: Rende lo stack eseguibile
- `MH_NO_REEXPORTED_DYLIBS`: La libreria non contiene comandi LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: È presente una sezione con variabili locali al thread
- `MH_NO_HEAP_EXECUTION`: Nessuna esecuzione per le pagine heap/data
- `MH_HAS_OBJC`: Il binary contiene sezioni oBject-C
- `MH_SIM_SUPPORT`: Supporto per il simulatore
- `MH_DYLIB_IN_CACHE`: Utilizzato per dylib/framework nella shared library cache.

## **Comandi di caricamento Mach-O**

Il **layout del file in memoria** è specificato qui, descrivendo la **posizione della symbol table**, il contesto del thread principale all'avvio dell'esecuzione e le **shared libraries** richieste. Vengono fornite istruzioni al dynamic loader **(dyld)** sul processo di caricamento del binary in memoria.

Il file utilizza la struttura **load_command**, definita nel già menzionato **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Esistono circa **50 tipi diversi di load commands** che il sistema gestisce in modo differente. I più comuni sono: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` e `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> In pratica, questo tipo di Load Command definisce **come caricare i segmenti \_\_TEXT** (codice eseguibile) **e \_\_DATA** (dati del processo) in base agli **offset indicati nella sezione Data** quando il binary viene eseguito.

Questi comandi **definiscono segmenti** che vengono **mappati** nello **spazio di memoria virtuale** di un processo quando questo viene eseguito.

Esistono **diversi tipi** di segmenti, come il segmento **\_\_TEXT**, che contiene il codice eseguibile di un programma, e il segmento **\_\_DATA**, che contiene i dati utilizzati dal processo. Questi **segmenti si trovano nella sezione data** del file Mach-O.

**Ogni segmento** può essere ulteriormente **suddiviso** in più **sezioni**. La **struttura del load command** contiene **informazioni** su **queste sezioni** all'interno del segmento corrispondente.

Nell'header si trova innanzitutto l'**header del segmento**:

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

Questo header definisce il **numero di sezioni i cui header compaiono dopo** di esso:
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
Esempio di **intestazione della sezione**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Se **aggiungi** il **section offset** (0x37DC) + l'**offset** dove inizia l'**arch**, in questo caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

È anche possibile ottenere **informazioni sugli header** dalla **riga di comando** con:
```bash
otool -lv /bin/ls
```
Common segments caricati da questo cmd:

- **`__PAGEZERO`:** Istruisce il kernel a **mappare** l’**indirizzo zero** in modo che non possa essere letto, scritto o eseguito. Le variabili maxprot e minprot nella struttura sono impostate a zero per indicare che su questa pagina **non sono presenti permessi di lettura-scrittura-esecuzione**.
- Questa allocazione è importante per **mitigare le vulnerabilità di dereferenziazione di puntatori NULL**. Questo perché XNU impone una hard page zero che garantisce che la prima pagina (solo la prima) della memoria sia inaccessibile (tranne in i386). Un binary potrebbe soddisfare questo requisito creando un \_\_PAGEZERO di piccole dimensioni (usando `-pagezero_size`) per coprire i primi 4k e rendendo il resto della memoria a 32 bit accessibile sia in user mode che in kernel mode.
- **`__TEXT`**: Contiene **codice** **eseguibile** con permessi di **lettura** ed **esecuzione** (non scrivibile)**.** Sezioni comuni di questo segmento:
- `__text`: Codice compilato del binary
- `__const`: Dati costanti (sola lettura)
- `__[c/u/os_log]string`: Costanti stringa C, Unicode o degli os log
- `__stubs` e `__stubs_helper`: Coinvolti durante il processo di caricamento delle dynamic library
- `__unwind_info`: Dati per lo stack unwind.
- Si noti che tutto questo contenuto è signed, ma anche marcato come eseguibile (creando più opzioni per l’exploitation di sezioni che non necessitano necessariamente di questo privilegio, come le sezioni dedicate alle stringhe).
- **`__DATA`**: Contiene dati **leggibili** e **scrivibili** (non eseguibili)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Puntatore a simboli non lazy (bind al caricamento)
- `__la_symbol_ptr`: Puntatore a simboli lazy (bind all’utilizzo)
- `__const`: Dovrebbe contenere dati di sola lettura (non realmente)
- `__cfstring`: Stringhe CoreFoundation
- `__data`: Variabili globali (inizializzate)
- `__bss`: Variabili statiche (non inizializzate)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, ecc.): Informazioni utilizzate dal runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const non è garantito essere costante (permessi di scrittura), così come gli altri puntatori e la GOT. Questa sezione rende `__const`, alcuni initializer e la tabella GOT (una volta risolta) **di sola lettura** usando `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Comuni nei binary recenti Apple Silicon. Questi segmenti contengono puntatori che devono essere autenticati al momento del caricamento o dell’utilizzo (per esempio `__auth_got`). Se un rebinding, hook o import-patching trick controlla solo le sezioni legacy `__got` / `__la_symbol_ptr`, potrebbe non individuare i reali call site nei binary moderni `arm64e`. Per maggiori dettagli su queste sezioni, consulta [questa pagina](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contiene informazioni per il linker (dyld), come le entry delle tabelle dei simboli, delle stringhe e delle relocation. È un contenitore generico per i contenuti che non si trovano né in `__TEXT` né in `__DATA`, e il cui contenuto è descritto in altri load command.
- Informazioni dyld: Opcode di rebase, binding non-lazy/lazy/weak e informazioni sulle export
- Inizio delle funzioni: Tabella degli indirizzi iniziali delle funzioni
- Data In Code: Data islands in \_\_text
- SYmbol Table: Simboli nel binary
- Indirect Symbol Table: Simboli di puntatori/stub
- String Table
- Code Signature
- **`__OBJC`**: Contiene informazioni utilizzate dal runtime Objective-C. Anche se queste informazioni potrebbero trovarsi nel segmento \_\_DATA, all’interno di varie sezioni \_\_objc\_\*.
- **`__RESTRICT`**: Un segmento senza contenuto con una singola sezione chiamata **`__restrict`** (anch’essa vuota), che garantisce che, durante l’esecuzione del binary, le variabili d’ambiente DYLD vengano ignorate.

Come era possibile vedere nel codice, i **segmenti supportano anche dei flag** (anche se non vengono utilizzati molto):

- `SG_HIGHVM`: Solo core (non utilizzato)
- `SG_FVMLIB`: Non utilizzato
- `SG_NORELOC`: Il segmento non contiene relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Utilizzato, per esempio, da Finder per cifrare il segmento `__TEXT` text.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene l’entrypoint nell’**attributo entryoff**. Al caricamento, **dyld** aggiunge semplicemente questo valore alla **base (in memoria) del binary**, quindi esegue un **jump** a questa istruzione per avviare l’esecuzione del codice del binary.

**`LC_UNIXTHREAD`** contiene i valori che i registri devono avere all’avvio del main thread. Questo era già deprecato, ma **`dyld`** lo utilizza ancora. È possibile visualizzare i valori dei registri impostati in questo modo con:
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


Contiene informazioni sulla **code signature del file Macho-O**. Contiene solo un **offset** che **punta** al **signature blob**. Di solito si trova alla fine del file.\
Tuttavia, puoi trovare alcune informazioni su questa sezione in [**questo blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e in questi [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[3][4]</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Supporto per la cifratura dei binari. Tuttavia, naturalmente, se un attacker riesce a compromettere il processo, sarà in grado di eseguire il dump della memoria non cifrata.

### **`LC_LOAD_DYLINKER`**

Contiene il **percorso dell'eseguibile del dynamic linker** che mappa le shared libraries nello spazio degli indirizzi del processo. Il **valore è sempre impostato su `/usr/lib/dyld`**. È importante notare che in macOS il mapping delle dylib avviene in **user mode**, non in kernel mode.

### **`LC_IDENT`**

Obsoleto, ma quando è configurato per **generare** dump in caso di panic, viene creato un core dump Mach-O e la versione del kernel viene impostata nel comando `LC_IDENT`.

### **`LC_UUID`**

UUID casuale. Non è direttamente utile per molto, ma XNU lo memorizza nella cache insieme al resto delle informazioni sul processo. Può essere utilizzato nei crash report.

### **`LC_BUILD_VERSION`**

I binari moderni solitamente contengono questo comando per dichiarare la **piattaforma target**, la **versione minima del sistema operativo**, la **versione dell'SDK** e, facoltativamente, le **versioni degli strumenti** utilizzati per compilare quella slice. Dal punto di vista dell'offensive/reversing, è molto utile per identificare come è stato compilato un sample e individuare rapidamente universal binaries anomali, in cui una slice è stata compilata con un SDK o un deployment target differenti. I binari più vecchi possono invece utilizzare ancora `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Permette di indicare variabili d'ambiente a dyld prima dell'esecuzione del processo. Questo può essere molto pericoloso, poiché può consentire l'esecuzione di codice arbitrario all'interno del processo; per questo motivo, questo load command viene utilizzato solo nelle build di dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` e limita ulteriormente l'elaborazione alle variabili nella forma `DYLD_..._PATH` che specificano i percorsi di caricamento.

### **`LC_DYLD_EXPORTS_TRIE` e `LC_DYLD_CHAINED_FIXUPS`**

I toolchain recenti memorizzano frequentemente i metadati di export/bind/rebase in questi command invece di affidarsi esclusivamente ai più vecchi opcode `LC_DYLD_INFO[_ONLY]`. Entrambi sono elementi `linkedit_data_command` che puntano all'interno di **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: trie compatto contenente i simboli esportati dall'image.
- **`LC_DYLD_CHAINED_FIXUPS`**: catene di fixup per segmento utilizzate da dyld per applicare rebase e bind. Su Apple Silicon è anche il punto in cui si incontrano molti moderni fixup di puntatori autenticati.

Questi metadati sono molto utili per ricostruire import/export, capire perché una dipendenza caricata tramite `@rpath` è stata risolta in quel modo o determinare perché un tentativo di hook/rebinding è fallito su un target moderno `arm64e`. `dyld_info` può essere utilizzato anche con **percorsi di dylib presenti solo nella cache** che non esistono come file autonomi sul disco; questo è molto utile nelle versioni moderne di macOS, dove molte librerie di sistema risiedono esclusivamente nella shared cache.<sup>[2]</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Questo moderno load command è principalmente rilevante durante l'analisi di **kernel collections / file kernelcache**. Invece di rappresentare una singola immagine standalone, il Mach-O esterno agisce come container e ogni `LC_FILESET_ENTRY` punta a un Mach-O incorporato con un proprio **entry id** simile a un percorso, un indirizzo VM e un file offset. Se stai facendo reverse engineering di componenti kernel moderni di macOS/iOS, questo command è spesso il collegamento tra il container di primo livello e l'immagine effettiva che vuoi estrarre o disassemblare.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Per i workflow pratici di estrazione, consulta [quest'altra pagina sulle estensioni del kernel di macOS e sul kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Questo comando di caricamento descrive una dipendenza da una **libreria** **dinamica** che istruisce il **loader** (dyld) a **caricare e collegare tale libreria**. Esiste un comando di caricamento `LC_LOAD_DYLIB` **per ogni libreria** richiesta dal binario Mach-O.

- Questo comando di caricamento è una struttura di tipo **`dylib_command`** (che contiene una struct dylib, la quale descrive l'effettiva libreria dinamica dipendente):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t versione di compatibilità; / numero di versione di compatibilità della libreria /](<../../../images/image (486).png>)

Potresti ottenere queste informazioni anche dalla CLI con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Alcune potenziali librerie correlate al malware sono:

- **DiskArbitration**: Monitoraggio delle unità USB
- **AVFoundation:** Acquisizione di audio e video
- **CoreWLAN**: Scansioni WiFi.

> [!TIP]
> Un binario Mach-O può contenere uno o **più** **costruttori**, che verranno **eseguiti** **prima** dell'indirizzo specificato in **LC_MAIN**.\
> Gli offset di eventuali costruttori sono contenuti nella sezione **\_\_mod_init_func** del segmento **\_\_DATA_CONST**.

## **Dati Mach-O**

Al centro del file si trova la regione dei dati, composta da diversi segmenti definiti nella regione dei load commands. **All'interno di ogni segmento possono essere contenute diverse sezioni di dati**, ciascuna delle quali **contiene codice o dati** specifici di un tipo.

> [!TIP]
> I dati sono sostanzialmente la parte contenente tutte le **informazioni** caricate dai load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Questo include:

- **Tabella delle funzioni:** Contiene informazioni sulle funzioni del programma.
- **Tabella dei simboli**: Contiene informazioni sulla funzione esterna utilizzata dal binario
- Potrebbe contenere anche funzioni interne, nomi di variabili e altro.

Per verificarla è possibile utilizzare lo strumento [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oppure dalla cli:
```bash
size -m /bin/ls
```
## Sezioni comuni di Objective-C

Nel segmento `__TEXT` (r-x):

- `__objc_classname`: Nomi delle classi (stringhe)
- `__objc_methname`: Nomi dei metodi (stringhe)
- `__objc_methtype`: Tipi dei metodi (stringhe)

Nel segmento `__DATA` (rw-):

- `__objc_classlist`: Puntatori a tutte le classi Objective-C
- `__objc_nlclslist`: Puntatori alle classi Objective-C Non-Lazy
- `__objc_catlist`: Puntatori alle Categories
- `__objc_nlcatlist`: Puntatori alle Categories Non-Lazy
- `__objc_protolist`: Elenco dei protocolli
- `__objc_const`: Dati costanti
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Riferimenti

- [1] [Le slice Mach-O non sono così semplici come si potrebbe pensare](https://objective-see.org/blog/blog_0x80.html)
- [2] [Pagina man di dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Lettura dei propri Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
