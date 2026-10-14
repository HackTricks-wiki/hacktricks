# Binari universali macOS e formato Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

macOS usa il formato eseguibile **Mach-O**. Un binario **universale**, o fat, contiene in un unico file più slice Mach-O specifiche per ciascuna architettura. Gli header open source `fat.h` e `loader.h` di Apple definiscono le strutture e le costanti descritte in questa pagina. <sup>[[5]](#references)</sup>

Un'immagine Mach-O è composta da:

- Header
- Load Commands
- Dati

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

L'header contiene i byte **magic**, seguiti dal **numero** di **architetture** contenute nel file (`nfat_arch`); ogni architettura avrà una struct `fat_arch`.

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

Come probabilmente immagini, di solito un binario universale compilato per 2 architetture **raddoppia le dimensioni** rispetto a uno compilato per una sola architettura.

> [!TIP]
> Quando analizzi malware o app sospette, non fermarti dopo che `file` ha segnalato l'architettura "migliore". Un binario universale può nascondere importazioni, load command o metadati del compilatore diversi in ciascuna slice; elencale quindi **tutte** prima di esaminarle una per una:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Gli SDK macOS più recenti espongono anche helper come `macho_for_each_slice()` e `macho_best_slice()` in `<mach-o/utils.h>`. Quest’ultimo è utile per emulare ciò che caricherebbero dyld/kernel, ma gli scanner dovrebbero comunque iterare ogni slice per evitare di non rilevare contenuti specifici di un’architettura.<sup>[[1]](#references)</sup>

## **Intestazione Mach-O**

L’intestazione contiene informazioni di base sul file, come i byte magici che lo identificano come file Mach-O e informazioni sull’architettura di destinazione. Puoi trovarla con: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

- `MH_OBJECT`: file oggetto rilocabile (prodotti intermedi della compilazione, non ancora eseguibili).
- `MH_EXECUTE`: file eseguibili.
- `MH_FVMLIB`: file di libreria VM fissa.
- `MH_CORE`: dump di codice
- `MH_PRELOAD`: file eseguibile precaricato (non più supportato in XNU)
- `MH_DYLIB`: librerie dinamiche
- `MH_DYLINKER`: linker dinamico
- `MH_BUNDLE`: "file plugin". Generati usando -bundle in gcc e caricati esplicitamente da `NSBundle` o `dlopen`.
- `MH_DYSM`: file `.dSym` associato (file con simboli per il debugging).
- `MH_KEXT_BUNDLE`: estensioni del kernel.

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

Il codice sorgente definisce anche diversi flag utili per caricare le librerie:

- `MH_NOUNDEFS`: Nessun riferimento non definito (collegato completamente)
- `MH_DYLDLINK`: Collegamento Dyld
- `MH_PREBOUND`: Riferimenti dinamici precollegati.
- `MH_SPLIT_SEGS`: Il file suddivide i segmenti in sola lettura e lettura/scrittura.
- `MH_WEAK_DEFINES`: Il binary contiene simboli definiti deboli
- `MH_BINDS_TO_WEAK`: Il binary usa simboli deboli
- `MH_ALLOW_STACK_EXECUTION`: Rende eseguibile lo stack
- `MH_NO_REEXPORTED_DYLIBS`: La libreria non usa comandi LC_REEXPORT
- `MH_PIE`: Eseguibile indipendente dalla posizione
- `MH_HAS_TLV_DESCRIPTORS`: È presente una sezione con variabili locali al thread
- `MH_NO_HEAP_EXECUTION`: Nessuna esecuzione per le pagine heap/data
- `MH_HAS_OBJC`: Il binary contiene sezioni Objective-C
- `MH_SIM_SUPPORT`: Supporto per il simulatore
- `MH_DYLIB_IN_CACHE`: Usato per dylib/framework nella cache delle librerie condivise.

## **Comandi di caricamento Mach-O**

Il **layout del file in memoria** è specificato qui e descrive la **posizione della tabella dei simboli**, il contesto del thread principale all'inizio dell'esecuzione e le **librerie condivise** richieste. Vengono fornite istruzioni al loader dinamico **(dyld)** sul processo di caricamento del binary in memoria.

Utilizza la struttura **load_command**, definita nel file **`loader.h`** menzionato:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Ci sono circa **50 tipi diversi di load command** che il sistema gestisce in modo diverso. I più comuni sono: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` e `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> In pratica, questo tipo di Load Command definisce **come caricare i segmenti \_\_TEXT** (codice eseguibile) **e \_\_DATA** (dati del processo) **in base agli offset indicati nella sezione Data** quando viene eseguito il binario.

Questi comandi **definiscono i segmenti** che vengono **mappati** nello **spazio di memoria virtuale** di un processo quando viene eseguito.

Esistono **diversi tipi** di segmenti, come il segmento **\_\_TEXT**, che contiene il codice eseguibile di un programma, e il segmento **\_\_DATA**, che contiene i dati utilizzati dal processo. Questi **segmenti si trovano nella sezione Data** del file Mach-O.

**Ogni segmento** può essere ulteriormente **suddiviso** in più **sezioni**. La **struttura del load command** contiene **informazioni** su **queste sezioni** all'interno del rispettivo segmento.

Nell'header si trova prima l'**header del segmento**:

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

Questo header definisce il **numero di sezioni, i cui header compaiono subito dopo**:

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

Esempio di **header di sezione**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Se si **somma** l'**offset della sezione** (0x37DC) all'**offset** in cui inizia l'**arch**, in questo caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

È anche possibile ottenere **informazioni sugli header** dalla **riga di comando** con:

```bash
otool -lv /bin/ls
```

Segmenti comuni caricati da questo comando:

- **`__PAGEZERO`:** Indica al kernel di **mappare** l’**indirizzo zero** in modo che **non possa essere letto, scritto o eseguito**. Le variabili maxprot e minprot nella struttura sono impostate a zero per indicare che **questa pagina non dispone di permessi di lettura-scrittura-esecuzione**.
  - Questa allocazione è importante per **mitigare le vulnerabilità di dereferenziazione di puntatori NULL**. XNU impone infatti una pagina zero rigida, che garantisce che la prima pagina di memoria (solo la prima) sia inaccessibile (tranne in i386). Un binario potrebbe soddisfare questo requisito creando una piccola \_\_PAGEZERO (usando `-pagezero_size`) che copra i primi 4k e lasciando il resto della memoria a 32 bit accessibile sia in modalità utente sia in modalità kernel.
- **`__TEXT`**: Contiene **codice** **eseguibile** con permessi di **lettura** ed **esecuzione** (senza permessi di scrittura)**.** Sezioni comuni di questo segmento:
  - `__text`: Codice binario compilato
  - `__const`: Dati costanti (sola lettura)
  - `__[c/u/os_log]string`: Costanti stringa C, Unicode o dei log os
  - `__stubs` e `__stubs_helper`: Coinvolte durante il processo di caricamento delle librerie dinamiche
  - `__unwind_info`: Dati per lo stack unwinding.
  - Nota che tutti questi contenuti sono firmati, ma anche contrassegnati come eseguibili (creando più possibilità di exploitation delle sezioni che non necessitano necessariamente di questo privilegio, come le sezioni dedicate alle stringhe).
- **`__DATA`**: Contiene dati **leggibili** e **scrivibili** (non eseguibili)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Puntatore a simbolo non lazy (collegato al caricamento)
  - `__la_symbol_ptr`: Puntatore a simbolo lazy (collegato all’uso)
  - `__const`: Dovrebbe contenere dati di sola lettura (in realtà non è così)
  - `__cfstring`: Stringhe CoreFoundation
  - `__data`: Variabili globali (inizializzate)
  - `__bss`: Variabili statiche (non inizializzate)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, ecc.): Informazioni usate dal runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const non è garantito che sia costante (permessi di scrittura), e lo stesso vale per gli altri puntatori e per la GOT. Questa sezione rende **di sola lettura** `__const`, alcuni inizializzatori e la tabella GOT (una volta risolta) usando `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Comuni nei binari recenti per Apple Silicon. Questi segmenti contengono puntatori che devono essere autenticati al caricamento o al momento dell’uso (ad esempio `__auth_got`). Se una tecnica di rebinding, hook o patching degli import controlla solo le sezioni legacy `__got` / `__la_symbol_ptr`, potrebbe non individuare i veri call site nei binari `arm64e` moderni. Per maggiori dettagli su queste sezioni, consulta [questa pagina](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contiene informazioni per il linker (dyld), come le voci delle tabelle dei simboli, delle stringhe e delle rilocazioni. È un contenitore generico per contenuti che non si trovano in `__TEXT` o `__DATA`; i suoi contenuti sono descritti in altri comandi di caricamento.
  - Informazioni dyld: Rebase, opcode di binding non-lazy/lazy/weak e informazioni di export
  - Inizio delle funzioni: Tabella degli indirizzi iniziali delle funzioni
  - Data In Code: Blocchi di dati in \_\_text
  - Tabella dei simboli: Simboli nel binario
  - Tabella dei simboli indiretti: Simboli di puntatori/stub
  - Tabella delle stringhe
  - Firma del codice
- **`__OBJC`**: Contiene informazioni usate dal runtime Objective-C. Queste informazioni potrebbero trovarsi anche nel segmento \_\_DATA, all’interno di varie sezioni \_\_objc\_\*.
- **`__RESTRICT`**: Un segmento senza contenuti, con un’unica sezione chiamata **`__restrict`** (anch’essa vuota), che garantisce che, durante l’esecuzione del binario, le variabili d’ambiente DYLD vengano ignorate.

Come si è potuto vedere nel codice, **i segmenti supportano anche dei flag** (anche se non vengono usati molto):

- `SG_HIGHVM`: Solo per il core (non usato)
- `SG_FVMLIB`: Non usato
- `SG_NORELOC`: Il segmento non ha rilocazioni
- `SG_PROTECTED_VERSION_1`: Crittografia. Usato, ad esempio, da Finder per crittografare il segmento `__TEXT` di testo.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene l’entrypoint nell’attributo **entryoff.** Al caricamento, **dyld** si limita ad **aggiungere** questo valore alla **base** (in memoria) del binario, quindi **salta** a questa istruzione per avviare l’esecuzione del codice del binario.

**`LC_UNIXTHREAD`** contiene i valori che i registri devono avere all’avvio del thread principale. È già deprecato, ma **`dyld`** lo usa ancora. È possibile visualizzare i valori impostati nei registri con:

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


Contiene informazioni sulla **code signature del file Mach-O**. Contiene solo un **offset** che **punta** al **signature blob**. Questo si trova in genere alla fine del file.\
Puoi trovare maggiori informazioni su questa sezione in [**questo blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e [**questo gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Supporto per la cifratura dei binary. Tuttavia, ovviamente, se un attacker riesce a compromettere il processo, potrà scaricare la memoria non cifrata.

### **`LC_LOAD_DYLINKER`**

Contiene il **percorso dell'eseguibile del dynamic linker**, che mappa le librerie condivise nello spazio degli indirizzi del processo. Il **valore è sempre impostato su `/usr/lib/dyld`**. È importante notare che in macOS il mapping dei dylib avviene in **user mode**, non in kernel mode.

### **`LC_IDENT`**

Obsoleto, ma quando è configurato per generare dump in caso di panic, viene creato un core dump Mach-O e la versione del kernel è impostata nel comando `LC_IDENT`.

### **`LC_UUID`**

UUID casuale. Non è utile per nulla direttamente, ma XNU lo mette in cache insieme alle altre informazioni sul processo. Può essere usato nei crash report.

### **`LC_BUILD_VERSION`**

I binary moderni di solito includono questo comando per dichiarare la **piattaforma target**, la **versione minima del sistema operativo**, la **versione dell'SDK** e, facoltativamente, le **versioni degli strumenti** usati per compilare quella slice. Dal punto di vista offensive/reversing, è molto utile per identificare come è stato compilato un sample e individuare rapidamente universal binaries anomali in cui una slice è stata compilata con un SDK o un deployment target diverso. I binary più vecchi possono ancora usare `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Consente di specificare variabili d'ambiente per dyld prima dell'esecuzione del processo. Può essere molto pericoloso, perché può consentire di eseguire codice arbitrario all'interno del processo. Per questo, questo comando di caricamento viene usato solo nelle build di dyld con `#define SUPPORT_LC_DYLD_ENVIRONMENT` e limita ulteriormente l'elaborazione alle variabili della forma `DYLD_..._PATH` che specificano percorsi di caricamento.

### **`LC_DYLD_EXPORTS_TRIE` e `LC_DYLD_CHAINED_FIXUPS`**

Le toolchain recenti memorizzano spesso i metadati di esportazione/binding/rebase in questi comandi, invece di affidarsi solo ai vecchi opcode `LC_DYLD_INFO[_ONLY]`. Entrambi sono voci `linkedit_data_command` che puntano a **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: trie compatto con i simboli esportati dall'immagine.
- **`LC_DYLD_CHAINED_FIXUPS`**: catene di fixup per segmento, usate da dyld per applicare rebase e binding. Su Apple Silicon è anche qui che troverai molti fixup moderni di puntatori autenticati.

Questi metadati sono molto utili per ricostruire import/export, capire perché una dipendenza caricata tramite `@rpath` è stata risolta in un certo modo o determinare perché un tentativo di hook/rebinding è fallito su un target `arm64e` moderno. `dyld_info` può essere usato anche con percorsi di dylib disponibili solo nella cache, che non esistono come file autonomi sul disco. È molto utile su macOS moderno, dove molte librerie di sistema si trovano solo nella cache condivisa.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Questo moderno comando di caricamento è rilevante soprattutto quando si esaminano **kernel collections / fileset in stile kernelcache**. Invece di rappresentare una singola immagine autonoma, il Mach-O esterno funge da contenitore e ogni `LC_FILESET_ENTRY` punta a un Mach-O incorporato, con un proprio **entry id** simile a un percorso, un indirizzo VM e un offset nel file. Se stai effettuando il reverse engineering dei moderni componenti kernel di macOS/iOS, questo comando è spesso il collegamento tra il contenitore di primo livello e l'immagine effettiva da estrarre o disassemblare.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Per i workflow pratici di estrazione, consulta [questa altra pagina sulle estensioni del kernel di macOS e il kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Questo load command descrive una dipendenza da una **libreria** **dinamica** che **indica** al **loader** (dyld) di **caricare e collegare tale libreria**. È presente un load command `LC_LOAD_DYLIB` **per ogni libreria** richiesta dal binario Mach-O.

- Questo load command è una struttura di tipo **`dylib_command`** (che contiene una struct dylib, la quale descrive la libreria dinamica effettivamente richiesta):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t versione di compatibilità; / numero della versione di compatibilità della libreria /](<../../../images/image (486).png>)

Puoi ottenere queste informazioni anche dalla CLI con:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Alcune librerie potenzialmente correlate al malware sono:

- **DiskArbitration**: Monitoraggio delle unità USB
- **AVFoundation:** Acquisizione di audio e video
- **CoreWLAN**: Scansioni Wi-Fi.

> [!TIP]
> Un binario Mach-O può contenere uno o **più** **costruttori**, che verranno **eseguiti** **prima** dell'indirizzo specificato in **LC_MAIN**.\
> Gli offset di qualsiasi costruttore sono memorizzati nella sezione **\_\_mod_init_func** del segmento **\_\_DATA_CONST**.

## **Dati Mach-O**

Al centro del file si trova l'area dati, composta da diversi segmenti definiti nell'area dei load commands. **Ogni segmento può contenere diverse sezioni di dati**, ciascuna delle quali **contiene codice o dati** specifici di un tipo.

> [!TIP]
> I dati sono fondamentalmente la parte che contiene tutte le **informazioni** caricate dai load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Questi includono:

- **Tabella delle funzioni:** contiene informazioni sulle funzioni del programma.
- **Tabella dei simboli**: contiene informazioni sulle funzioni esterne utilizzate dal binario
- Potrebbe contenere anche funzioni interne, nomi di variabili e altro.

Per controllarla, puoi usare lo strumento [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oppure dalla CLI:

```bash
size -m /bin/ls
```

### Dati aggiunti e overlay analizzati al contrario

Un loader può conservare la configurazione nei dati aggiunti anziché in una sezione Mach-O con nome. Un parser inverso si ancora quindi a un marker finale, legge una dimensione memorizzata immediatamente prima di esso e usa quel valore per individuare e decrittare il blob precedente. Un loader universal osservato usava questo layout per un URL di downloader crittografato con XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Quando esegui il reverse engineering di un binario sconosciuto, esamina i byte intorno ai marcatori di fine riconoscibili e traccia ogni calcolo delle dimensioni a ritroso prima di presumere che stringhe o configurazioni appartengano a una sezione dei load command. Il marcatore e la chiave XOR sono specifici del campione; la tecnica riutilizzabile consiste nell’usare un trailer auto-descrittivo.

## Sezioni comuni di Objective-C

Nel segmento `__TEXT` (r-x):

- `__objc_classname`: Nomi delle classi (stringhe)
- `__objc_methname`: Nomi dei metodi (stringhe)
- `__objc_methtype`: Tipi dei metodi (stringhe)

Nel segmento `__DATA` (rw-):

- `__objc_classlist`: Puntatori a tutte le classi Objective-C
- `__objc_nlclslist`: Puntatori alle classi Objective-C non lazy
- `__objc_catlist`: Puntatore alle categorie
- `__objc_nlcatlist`: Puntatore alle categorie non lazy
- `__objc_protolist`: Elenco dei protocolli
- `__objc_const`: Dati costanti
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Le slice Mach-O non sono così semplici come potresti pensare](https://objective-see.org/blog/blog_0x80.html)
- [2] [Pagina man di dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Leggere i propri entitlement](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - `fat.h` e `loader.h` di Mach-O](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Una nuova versione del malware MacSync per macOS prende di mira gli appassionati di criptovalute e gli sviluppatori](https://securelist.com/macsync-new-version/121383/)
