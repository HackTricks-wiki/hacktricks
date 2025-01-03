# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I binari di Mac OS sono solitamente compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

Questi binari seguono la **struttura Mach-O** che è fondamentalmente composta da:

- Intestazione
- Comandi di caricamento
- Dati

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Cerca il file con: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC o FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* numero di strutture che seguono */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* specificatore cpu (int) */
cpu_subtype_t	cpusubtype;	/* specificatore macchina (int) */
uint32_t	offset;		/* offset del file a questo file oggetto */
uint32_t	size;		/* dimensione di questo file oggetto */
uint32_t	align;		/* allineamento come potenza di 2 */
};
</code></pre>

L'intestazione ha i byte **magic** seguiti dal **numero** di **architetture** che il file **contiene** (`nfat_arch`) e ogni architettura avrà una struttura `fat_arch`.

Controllalo con:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary con 2 architetture: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (per architettura x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (per architettura arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architettura x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architettura arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

o utilizzando lo strumento [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Come potresti pensare, di solito un universal binary compilato per 2 architetture **raddoppia la dimensione** di uno compilato per solo 1 arch.

## **Mach-O Header**

L'intestazione contiene informazioni di base sul file, come i byte magic per identificarlo come un file Mach-O e informazioni sull'architettura target. Puoi trovarlo in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Ci sono diversi tipi di file, puoi trovarli definiti nel [**codice sorgente per esempio qui**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). I più importanti sono:

- `MH_OBJECT`: File oggetto relocabile (prodotti intermedi della compilazione, non eseguibili ancora).
- `MH_EXECUTE`: File eseguibili.
- `MH_FVMLIB`: File di libreria VM fissa.
- `MH_CORE`: Dump di codice
- `MH_PRELOAD`: File eseguibile pre-caricato (non più supportato in XNU)
- `MH_DYLIB`: Librerie dinamiche
- `MH_DYLINKER`: Linker dinamico
- `MH_BUNDLE`: "File plugin". Generati utilizzando -bundle in gcc e caricati esplicitamente da `NSBundle` o `dlopen`.
- `MH_DYSM`: File `.dSym` companion (file con simboli per il debug).
- `MH_KEXT_BUNDLE`: Estensioni del kernel.
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

- `MH_NOUNDEFS`: Nessun riferimento non definito (completamente collegato)
- `MH_DYLDLINK`: Collegamento Dyld
- `MH_PREBOUND`: Riferimenti dinamici precollegati.
- `MH_SPLIT_SEGS`: Il file divide i segmenti r/o e r/w.
- `MH_WEAK_DEFINES`: Il binario ha simboli debolmente definiti
- `MH_BINDS_TO_WEAK`: Il binario utilizza simboli deboli
- `MH_ALLOW_STACK_EXECUTION`: Rende lo stack eseguibile
- `MH_NO_REEXPORTED_DYLIBS`: Libreria non comandi LC_REEXPORT
- `MH_PIE`: Eseguibile indipendente dalla posizione
- `MH_HAS_TLV_DESCRIPTORS`: C'è una sezione con variabili locali per thread
- `MH_NO_HEAP_EXECUTION`: Nessuna esecuzione per heap/pagine dati
- `MH_HAS_OBJC`: Il binario ha sezioni oBject-C
- `MH_SIM_SUPPORT`: Supporto per simulatori
- `MH_DYLIB_IN_CACHE`: Utilizzato su dylibs/frameworks nella cache delle librerie condivise.

## **Comandi di caricamento Mach-O**

Il **layout del file in memoria** è specificato qui, dettagliando la **posizione della tabella dei simboli**, il contesto del thread principale all'inizio dell'esecuzione e le **librerie condivise** richieste. Vengono fornite istruzioni al caricatore dinamico **(dyld)** sul processo di caricamento del binario in memoria.

Utilizza la struttura **load_command**, definita nel menzionato **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Ci sono circa **50 diversi tipi di comandi di caricamento** che il sistema gestisce in modo diverso. I più comuni sono: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` e `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Fondamentalmente, questo tipo di comando di caricamento definisce **come caricare il \_\_TEXT** (codice eseguibile) **e il \_\_DATA** (dati per il processo) **segmenti** secondo gli **offset indicati nella sezione Dati** quando il binario viene eseguito.

Questi comandi **definiscono segmenti** che sono **mappati** nello **spazio di memoria virtuale** di un processo quando viene eseguito.

Ci sono **diversi tipi** di segmenti, come il **\_\_TEXT** segmento, che contiene il codice eseguibile di un programma, e il **\_\_DATA** segmento, che contiene dati utilizzati dal processo. Questi **segmenti si trovano nella sezione dati** del file Mach-O.

**Ogni segmento** può essere ulteriormente **diviso** in più **sezioni**. La **struttura del comando di caricamento** contiene **informazioni** su **queste sezioni** all'interno del rispettivo segmento.

Nell'intestazione prima trovi l'**intestazione del segmento**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* includes sizeof section_64 structs */
char		segname[16];	/* nome del segmento */
uint64_t	vmaddr;		/* indirizzo di memoria di questo segmento */
uint64_t	vmsize;		/* dimensione della memoria di questo segmento */
uint64_t	fileoff;	/* offset del file di questo segmento */
uint64_t	filesize;	/* quantità da mappare dal file */
int32_t		maxprot;	/* protezione VM massima */
int32_t		initprot;	/* protezione VM iniziale */
<strong>	uint32_t	nsects;		/* numero di sezioni nel segmento */
</strong>	uint32_t	flags;		/* flag */
};
</code></pre>

Esempio di intestazione del segmento:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Questa intestazione definisce il **numero di sezioni i cui intestazioni appaiono dopo** di essa:
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

Se **aggiungi** l'**offset di sezione** (0x37DC) + l'**offset** dove **inizia l'arch**, in questo caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

È anche possibile ottenere **informazioni sugli header** dalla **linea di comando** con:
```bash
otool -lv /bin/ls
```
Segmenti comuni caricati da questo cmd:

- **`__PAGEZERO`:** Istruisce il kernel a **mappare** l'**indirizzo zero** in modo che **non possa essere letto, scritto o eseguito**. Le variabili maxprot e minprot nella struttura sono impostate a zero per indicare che non ci sono **diritti di lettura-scrittura-esecuzione su questa pagina**.
- Questa allocazione è importante per **mitigare le vulnerabilità di dereferenziazione di puntatori NULL**. Questo perché XNU applica una rigida pagina zero che garantisce che la prima pagina (solo la prima) della memoria sia inaccessibile (eccetto in i386). Un binario potrebbe soddisfare questi requisiti creando un piccolo \_\_PAGEZERO (utilizzando `-pagezero_size`) per coprire i primi 4k e rendendo il resto della memoria a 32 bit accessibile sia in modalità utente che in modalità kernel.
- **`__TEXT`**: Contiene **codice** **eseguibile** con permessi di **lettura** e **esecuzione** (non scrivibile)**.** Sezioni comuni di questo segmento:
- `__text`: Codice binario compilato
- `__const`: Dati costanti (solo lettura)
- `__[c/u/os_log]string`: Costanti di stringa C, Unicode o os logs
- `__stubs` e `__stubs_helper`: Coinvolti durante il processo di caricamento della libreria dinamica
- `__unwind_info`: Dati di unwind dello stack.
- Nota che tutto questo contenuto è firmato ma anche contrassegnato come eseguibile (creando più opzioni per lo sfruttamento di sezioni che non necessitano necessariamente di questo privilegio, come le sezioni dedicate alle stringhe).
- **`__DATA`**: Contiene dati che sono **leggibili** e **scrivibili** (non eseguibili)**.**
- `__got:` Tabella degli offset globali
- `__nl_symbol_ptr`: Puntatore simbolo non pigro (binding al caricamento)
- `__la_symbol_ptr`: Puntatore simbolo pigro (binding all'uso)
- `__const`: Dovrebbe essere dati di sola lettura (non realmente)
- `__cfstring`: Stringhe CoreFoundation
- `__data`: Variabili globali (che sono state inizializzate)
- `__bss`: Variabili statiche (che non sono state inizializzate)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, ecc): Informazioni utilizzate dal runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const non è garantito essere costante (permessi di scrittura), né lo sono altri puntatori e la GOT. Questa sezione rende `__const`, alcuni inizializzatori e la tabella GOT (una volta risolta) **solo lettura** utilizzando `mprotect`.
- **`__LINKEDIT`**: Contiene informazioni per il linker (dyld) come, simboli, stringhe e voci della tabella di rilocazione. È un contenitore generico per contenuti che non sono né in `__TEXT` né in `__DATA` e il suo contenuto è descritto in altri comandi di caricamento.
- Informazioni dyld: Rebase, opcodes di binding non pigro/pigro/debole e informazioni di esportazione
- Inizio delle funzioni: Tabella degli indirizzi di inizio delle funzioni
- Dati nel codice: Isole di dati in \_\_text
- Tabella dei simboli: Simboli nel binario
- Tabella dei simboli indiretti: Simboli puntatore/stub
- Tabella delle stringhe
- Firma del codice
- **`__OBJC`**: Contiene informazioni utilizzate dal runtime Objective-C. Anche se queste informazioni potrebbero essere trovate anche nel segmento \_\_DATA, all'interno di varie sezioni in \_\_objc\_\*.
- **`__RESTRICT`**: Un segmento senza contenuto con una singola sezione chiamata **`__restrict`** (anch'essa vuota) che garantisce che quando si esegue il binario, ignorerà le variabili ambientali DYLD.

Come è stato possibile vedere nel codice, **i segmenti supportano anche flag** (anche se non sono molto utilizzati):

- `SG_HIGHVM`: Solo core (non utilizzato)
- `SG_FVMLIB`: Non utilizzato
- `SG_NORELOC`: Il segmento non ha rilocazione
- `SG_PROTECTED_VERSION_1`: Crittografia. Utilizzato ad esempio da Finder per crittografare il segmento di testo `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene il punto di ingresso nell'**attributo entryoff.** Al momento del caricamento, **dyld** semplicemente **aggiunge** questo valore alla **base del binario** (in memoria), poi **salta** a questa istruzione per avviare l'esecuzione del codice del binario.

**`LC_UNIXTHREAD`** contiene i valori che il registro deve avere quando si avvia il thread principale. Questo era già deprecato ma **`dyld`** lo utilizza ancora. È possibile vedere i valori dei registri impostati da questo con:
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

Contiene informazioni sulla **firma del codice del file Macho-O**. Contiene solo un **offset** che **punta** al **blob della firma**. Questo si trova tipicamente alla fine del file.\
Tuttavia, puoi trovare alcune informazioni su questa sezione in [**questo post del blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e in questo [**gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Supporto per la crittografia binaria. Tuttavia, ovviamente, se un attaccante riesce a compromettere il processo, sarà in grado di scaricare la memoria non crittografata.

### **`LC_LOAD_DYLINKER`**

Contiene il **percorso all'eseguibile del linker dinamico** che mappa le librerie condivise nello spazio degli indirizzi del processo. Il **valore è sempre impostato su `/usr/lib/dyld`**. È importante notare che in macOS, il mapping delle dylib avviene in **modalità utente**, non in modalità kernel.

### **`LC_IDENT`**

Obsoleto, ma quando configurato per generare dump in caso di panico, viene creato un core dump Mach-O e la versione del kernel è impostata nel comando `LC_IDENT`.

### **`LC_UUID`**

UUID casuale. È utile per qualsiasi cosa direttamente, ma XNU lo memorizza nella cache con il resto delle informazioni sul processo. Può essere utilizzato nei rapporti di crash.

### **`LC_DYLD_ENVIRONMENT`**

Consente di indicare le variabili di ambiente al dyld prima che il processo venga eseguito. Questo può essere molto pericoloso poiché può consentire di eseguire codice arbitrario all'interno del processo, quindi questo comando di caricamento è utilizzato solo in dyld costruito con `#define SUPPORT_LC_DYLD_ENVIRONMENT` e restringe ulteriormente l'elaborazione solo alle variabili della forma `DYLD_..._PATH` specificando i percorsi di caricamento.

### **`LC_LOAD_DYLIB`**

Questo comando di caricamento descrive una dipendenza di **libreria** **dinamica** che **istruisce** il **loader** (dyld) a **caricare e collegare la suddetta libreria**. C'è un comando di caricamento `LC_LOAD_DYLIB` **per ogni libreria** di cui il binario Mach-O ha bisogno.

- Questo comando di caricamento è una struttura di tipo **`dylib_command`** (che contiene una struct dylib, che descrive la libreria dinamica dipendente effettiva):
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
Alcune librerie potenzialmente correlate al malware sono:

- **DiskArbitration**: Monitoraggio delle unità USB
- **AVFoundation:** Cattura audio e video
- **CoreWLAN**: Scansioni Wifi.

> [!NOTE]
> Un binario Mach-O può contenere uno o **più** **costruttori**, che verranno **eseguiti** **prima** dell'indirizzo specificato in **LC_MAIN**.\
> Gli offset di qualsiasi costruttore sono contenuti nella sezione **\_\_mod_init_func** del segmento **\_\_DATA_CONST**.

## **Dati Mach-O**

Al centro del file si trova la regione dati, che è composta da diversi segmenti come definiti nella regione dei comandi di caricamento. **Una varietà di sezioni dati può essere ospitata all'interno di ciascun segmento**, con ciascuna sezione **che contiene codice o dati** specifici per un tipo.

> [!TIP]
> I dati sono fondamentalmente la parte che contiene tutte le **informazioni** caricate dai comandi di caricamento **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Questo include:

- **Tabella delle funzioni:** Che contiene informazioni sulle funzioni del programma.
- **Tabella dei simboli**: Che contiene informazioni sulle funzioni esterne utilizzate dal binario
- Potrebbe anche contenere nomi di funzioni interne, variabili e altro ancora.

Per controllarlo puoi utilizzare lo strumento [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

O dalla cli:
```bash
size -m /bin/ls
```
## Sezioni Comuni di Objective-C

In `__TEXT` segment (r-x):

- `__objc_classname`: Nomi delle classi (stringhe)
- `__objc_methname`: Nomi dei metodi (stringhe)
- `__objc_methtype`: Tipi di metodi (stringhe)

In `__DATA` segment (rw-):

- `__objc_classlist`: Puntatori a tutte le classi Objective-C
- `__objc_nlclslist`: Puntatori a classi Objective-C Non-Lazy
- `__objc_catlist`: Puntatore a Categorie
- `__objc_nlcatlist`: Puntatore a Categorie Non-Lazy
- `__objc_protolist`: Elenco dei protocolli
- `__objc_const`: Dati costanti
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
