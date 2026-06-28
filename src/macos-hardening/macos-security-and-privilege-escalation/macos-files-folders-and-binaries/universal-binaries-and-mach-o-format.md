# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Τα Mac OS binaries συνήθως μεταγλωττίζονται ως **universal binaries**. Ένα **universal binary** μπορεί να **υποστηρίζει πολλαπλές αρχιτεκτονικές στο ίδιο αρχείο**.

Αυτά τα binaries ακολουθούν τη δομή **Mach-O**, η οποία βασικά αποτελείται από:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Αναζήτησε το αρχείο με: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Το header έχει τα **magic** bytes ακολουθούμενα από τον **αριθμό** των **archs** που **περιέχει** το αρχείο (`nfat_arch`) και κάθε arch θα έχει ένα `fat_arch` struct.

Έλεγξέ το με:

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

ή χρησιμοποιώντας το εργαλείο [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Όπως ίσως σκέφτεσαι, συνήθως ένα universal binary μεταγλωττισμένο για 2 αρχιτεκτονικές **διπλασιάζει το μέγεθος** ενός που έχει μεταγλωττιστεί μόνο για 1 arch.

> [!TIP]
> Όταν κάνεις triaging malware ή suspicious apps, μην σταματάς μόλις το `file` αναφέρει την "best" architecture. Ένα universal binary μπορεί να κρύβει διαφορετικά imports, load commands ή compiler metadata σε κάθε slice, οπότε κάνε πρώτα enumerate **όλα** τα slices και μετά εξέτασέ τα ανεξάρτητα:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Πρόσφατα macOS SDKs επίσης εκθέτουν helpers όπως `macho_for_each_slice()` και `macho_best_slice()` στο `<mach-o/utils.h>`. Το τελευταίο είναι χρήσιμο για να προσομοιώσεις τι θα φόρτωνε το dyld/kernel, αλλά οι scanners θα πρέπει παρ' όλα αυτά να κάνουν iterate σε κάθε slice για να μην χάσουν arch-specific content.

## **Mach-O Header**

Το header περιέχει βασικές πληροφορίες για το αρχείο, όπως magic bytes για να το αναγνωρίσουν ως Mach-O file και πληροφορίες για το target architecture. Μπορείς να το βρεις στο: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Τύποι Αρχείων Mach-O

Υπάρχουν διαφορετικοί τύποι αρχείων, μπορείτε να τους βρείτε ορισμένους στο [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Οι πιο σημαντικοί είναι:

- `MH_OBJECT`: Relocatable object file (ενδιάμεσα προϊόντα της μεταγλώττισης, όχι ακόμη executables).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (δεν υποστηρίζεται πλέον στο XNU)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Δημιουργούνται χρησιμοποιώντας -bundle στο gcc και φορτώνονται ρητά από `NSBundle` ή `dlopen`.
- `MH_DYSM`: Companion `.dSym` file (file with symbols for debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ή χρησιμοποιώντας [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Ο source code επίσης ορίζει αρκετά flags χρήσιμα για τη φόρτωση libraries:

- `MH_NOUNDEFS`: No undefined references (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: File splits r/o and r/w segments.
- `MH_WEAK_DEFINES`: Binary has weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary uses weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Make the stack executable
- `MH_NO_REEXPORTED_DYLIBS`: Library not LC_REEXPORT commands
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: There is a section with thread local variables
- `MH_NO_HEAP_EXECUTION`: No execution for heap/data pages
- `MH_HAS_OBJC`: Binary has oBject-C sections
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Used on dylibs/frameworks in shared library cache.

## **Mach-O Load commands**

Η **file's layout in memory** ορίζεται εδώ, με λεπτομέρειες για τη **θέση του symbol table**, το context του κύριου thread κατά την έναρξη εκτέλεσης, και τις απαιτούμενες **shared libraries**. Παρέχονται οδηγίες στον dynamic loader **(dyld)** για τη διαδικασία φόρτωσης του binary στη μνήμη.

Χρησιμοποιεί τη δομή **load_command**, που ορίζεται στο αναφερόμενο **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Υπάρχουν περίπου **50 διαφορετικοί τύποι load commands** που το σύστημα χειρίζεται διαφορετικά. Οι πιο συνηθισμένοι είναι: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, και `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Βασικά, αυτός ο τύπος Load Command ορίζει **πώς να φορτωθούν τα \_\_TEXT** (εκτελέσιμος κώδικας) **και \_\_DATA** (δεδομένα για το process) **segments** σύμφωνα με τα **offsets που υποδεικνύονται στην Data section** όταν το binary εκτελείται.

Αυτές οι εντολές **ορίζουν segments** που **χαρτογραφούνται** στον **virtual memory space** ενός process όταν εκτελείται.

Υπάρχουν **διαφορετικοί τύποι** segments, όπως το segment **\_\_TEXT**, που περιέχει τον εκτελέσιμο κώδικα ενός προγράμματος, και το segment **\_\_DATA**, που περιέχει δεδομένα που χρησιμοποιεί το process. Αυτά τα **segments βρίσκονται στην data section** του Mach-O αρχείου.

**Κάθε segment** μπορεί να **διαιρεθεί** περαιτέρω σε πολλαπλά **sections**. Η δομή του **load command** περιέχει **πληροφορίες** για **αυτά τα sections** μέσα στο αντίστοιχο segment.

Στο header πρώτα βρίσκεις το **segment header**:

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

Παράδειγμα του segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Αυτό το header ορίζει τον **αριθμό των sections των οποίων τα headers εμφανίζονται μετά από αυτό**:
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
Παράδειγμα **κεφαλίδας ενότητας**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Αν **προσθέσεις** το **offset της ενότητας** (0x37DC) + το **offset** όπου ξεκινά το **arch**, σε αυτήν την περίπτωση `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Είναι επίσης δυνατό να πάρεις **πληροφορίες κεφαλίδων** από τη **γραμμή εντολών** με:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Υποδεικνύει στον kernel να **χαρτογραφήσει** το **address zero** έτσι ώστε να **μην μπορεί να διαβαστεί, να γραφτεί ή να εκτελεστεί**. Οι μεταβλητές maxprot και minprot στη δομή ορίζονται σε zero για να δείξουν ότι **δεν υπάρχουν δικαιώματα read-write-execute σε αυτή τη σελίδα**.
- Αυτή η allocation είναι σημαντική για να **μετριάσει vulnerabilities NULL pointer dereference**. Αυτό συμβαίνει επειδή το XNU επιβάλλει ένα hard page zero που διασφαλίζει ότι η πρώτη σελίδα (μόνο η πρώτη) της memory είναι innaccesible (εκτός σε i386). Ένα binary θα μπορούσε να εκπληρώσει αυτές τις απαιτήσεις δημιουργώντας ένα μικρό \_\_PAGEZERO (χρησιμοποιώντας το `-pagezero_size`) ώστε να καλύπτει τα πρώτα 4k και έχοντας το υπόλοιπο της 32bit memory προσβάσιμο τόσο σε user όσο και σε kernel mode.
- **`__TEXT`**: Περιέχει **εκτελέσιμο** **code** με δικαιώματα **read** και **execute** (όχι writable)**.** Κοινά sections αυτού του segment:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
- `__unwind_info`: Stack unwind data.
- Σημειώστε ότι όλο αυτό το content είναι signed αλλά επίσης σημειωμένο ως executable (δημιουργώντας περισσότερες επιλογές για exploitation sections που δεν χρειάζονται απαραίτητα αυτό το privilege, όπως string dedicated sections).
- **`__DATA`**: Περιέχει data που είναι **readable** και **writable** (no executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Information used by the Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const is not guaranteed to be constant (write permissions), nor are other pointers and the GOT. This section makes `__const`, some initializers and the GOT table (once resolved) **read only** using `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Common in recent Apple Silicon binaries. These segments hold pointers that must be authenticated at load or use time (for example `__auth_got`). If a rebinding, hook or import-patching trick only checks the legacy `__got` / `__la_symbol_ptr` sections, it may miss the real call sites in modern `arm64e` binaries. For more details on these sections check [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Περιέχει πληροφορίες για τον linker (dyld) όπως, symbol, string, and relocation table entries. It' a generic container for contents that are neither in `__TEXT` or `__DATA` and its content is decribed in other load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Περιέχει πληροφορίες που χρησιμοποιούνται από το Objective-C runtime. Παρότι αυτές οι πληροφορίες μπορεί επίσης να βρίσκονται στο \_\_DATA segment, μέσα σε διάφορα \_\_objc\_\* sections.
- **`__RESTRICT`**: Ένα segment χωρίς content με ένα μόνο section που ονομάζεται **`__restrict`** (επίσης empty) το οποίο διασφαλίζει ότι κατά την εκτέλεση του binary, θα αγνοεί DYLD environmental variables.

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


Περιέχει πληροφορίες για το **code signature του αρχείου Macho-O**. Περιέχει μόνο ένα **offset** που **δείχνει** στο **signature blob**. Αυτό συνήθως βρίσκεται στο πολύ τέλος του αρχείου.\
Ωστόσο, μπορείς να βρεις κάποιες πληροφορίες για αυτό το section σε [**αυτό το blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) και σε αυτό το [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Υποστήριξη για binary encryption. Ωστόσο, φυσικά, αν ένας attacker καταφέρει να compromise το process, θα μπορεί να κάνει dump τη μνήμη unencrypted.

### **`LC_LOAD_DYLINKER`**

Περιέχει το **path προς το dynamic linker executable** που κάνει map τα shared libraries στο process address space. Η **τιμή είναι πάντα ορισμένη σε `/usr/lib/dyld`**. Είναι σημαντικό να σημειωθεί ότι στο macOS, το dylib mapping γίνεται σε **user mode**, όχι σε kernel mode.

### **`LC_IDENT`**

Παρωχημένο, αλλά όταν είναι ρυθμισμένο να generate dumps on panic, δημιουργείται ένα Mach-O core dump και η kernel version ορίζεται στην εντολή `LC_IDENT`.

### **`LC_UUID`**

Τυχαίο UUID. Δεν είναι ιδιαίτερα χρήσιμο άμεσα, αλλά το XNU το κάνει cache μαζί με τα υπόλοιπα process info. Μπορεί να χρησιμοποιηθεί σε crash reports.

### **`LC_BUILD_VERSION`**

Τα σύγχρονα binaries συνήθως περιέχουν αυτή την εντολή για να δηλώσουν το **target platform**, την **minimum OS version**, την **SDK version**, και προαιρετικά τις **tool versions** που χρησιμοποιήθηκαν για να χτιστεί αυτό το slice. Από offensive/reversing άποψη αυτό είναι πολύ χρήσιμο για να γίνει fingerprint το πώς χτίστηκε ένα sample και για να εντοπιστούν γρήγορα περίεργα universal binaries όπου ένα slice μεταγλωττίστηκε με διαφορετικό SDK ή deployment target. Παλαιότερα binaries μπορεί ακόμα να χρησιμοποιούν `LC_VERSION_MIN_*` αντί γι' αυτό.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Επιτρέπει να καθορίζονται environment variables στο dyld πριν εκτελεστεί η process. Αυτό μπορεί να είναι πολύ επικίνδυνο, καθώς μπορεί να επιτρέψει την εκτέλεση arbitrary code μέσα στη process, οπότε αυτό το load command χρησιμοποιείται μόνο στο dyld build με `#define SUPPORT_LC_DYLD_ENVIRONMENT` και επιπλέον περιορίζει το processing μόνο σε variables της μορφής `DYLD_..._PATH` που καθορίζουν load paths.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains συχνά αποθηκεύουν export/bind/rebase metadata σε αυτά τα commands αντί να βασίζονται μόνο στα παλαιότερα `LC_DYLD_INFO[_ONLY]` opcodes. Και τα δύο είναι `linkedit_data_command` entries που δείχνουν μέσα στο **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Συμπαγές trie με τα symbols που exportάρει το image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Per-segment fixup chains που χρησιμοποιεί το dyld για να εφαρμόσει rebases και binds. Στο Apple Silicon εδώ θα συναντήσεις επίσης πολλά modern authenticated pointer fixups.

Αυτό το metadata είναι πολύ χρήσιμο όταν ανακατασκευάζεις imports/exports, καταλαβαίνεις γιατί ένα `@rpath`-loaded dependency resolved με τον τρόπο που έγινε, ή όταν προσπαθείς να καταλάβεις γιατί ένα hook/rebinding attempt απέτυχε σε ένα modern `arm64e` target. Το `dyld_info` μπορεί επίσης να χρησιμοποιηθεί σε **cache-only dylib paths** που δεν υπάρχουν ως standalone files στο disk, κάτι πολύ χρήσιμο στο modern macOS όπου πολλές system libraries υπάρχουν μόνο στο shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Αυτή η σύγχρονη load command είναι κυρίως σχετική όταν επιθεωρείτε **kernel collections / kernelcache-style filesets**. Αντί να αναπαριστά ένα μόνο standalone image, το εξωτερικό Mach-O λειτουργεί ως container και κάθε `LC_FILESET_ENTRY` δείχνει σε ένα embedded Mach-O με το δικό του path-like **entry id**, VM address και file offset. Αν κάνετε reversing σύγχρονα macOS/iOS kernel components, αυτή η command είναι συχνά η γέφυρα ανάμεσα στο top-level container και το πραγματικό image που θέλετε να extract ή να disassemble.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Για πρακτικές ροές εξαγωγής, δες [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Αυτή η load command περιγράφει μια **dynamic** εξάρτηση **library** η οποία **δίνει εντολή** στον **loader** (dyld) να **φορτώσει και να κάνει link τη συγκεκριμένη library**. Υπάρχει μια `LC_LOAD_DYLIB` load command **για κάθε library** που απαιτεί το Mach-O binary.

- Αυτή η load command είναι μια δομή τύπου **`dylib_command`** (η οποία περιέχει ένα struct dylib, που περιγράφει την πραγματική εξαρτώμενη dynamic library):
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

Θα μπορούσες επίσης να πάρεις αυτήν την πληροφορία από το cli με:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Μερικές πιθανές libraries σχετικές με malware είναι:

- **DiskArbitration**: Παρακολούθηση USB drives
- **AVFoundation:** Σύλληψη audio και video
- **CoreWLAN**: Wifi scans.

> [!TIP]
> Ένα Mach-O binary μπορεί να περιέχει έναν ή **περισσότερους** **constructors**, οι οποίοι θα **εκτελεστούν** **πριν** από τη διεύθυνση που ορίζεται στο **LC_MAIN**.\
> Τα offsets οποιωνδήποτε constructors βρίσκονται στο section **\_\_mod_init_func** του segment **\_\_DATA_CONST**.

## **Mach-O Data**

Στον πυρήνα του file βρίσκεται το data region, το οποίο αποτελείται από several segments όπως ορίζονται στο load-commands region. **Μια ποικιλία από data sections μπορεί να φιλοξενηθεί μέσα σε κάθε segment**, με κάθε section να **περιέχει code ή data** συγκεκριμένα για έναν type.

> [!TIP]
> Τα data είναι βασικά το μέρος που περιέχει όλες τις **πληροφορίες** που φορτώνονται από τα load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Αυτό περιλαμβάνει:

- **Function table:** Που περιέχει πληροφορίες για τις program functions.
- **Symbol table**: Που περιέχει πληροφορίες για την external function που χρησιμοποιείται από το binary
- Μπορεί επίσης να περιέχει internal function, variable names καθώς και άλλα.

Για να το ελέγξεις μπορείς να χρησιμοποιήσεις το εργαλείο [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ή από το cli:
```bash
size -m /bin/ls
```
## Κοινά Sections του Objetive-C

Στο segment `__TEXT` (r-x):

- `__objc_classname`: Ονόματα κλάσεων (strings)
- `__objc_methname`: Ονόματα μεθόδων (strings)
- `__objc_methtype`: Τύποι μεθόδων (strings)

Στο segment `__DATA` (rw-):

- `__objc_classlist`: Pointers προς όλες τις Objetive-C κλάσεις
- `__objc_nlclslist`: Pointers προς Non-Lazy Objective-C κλάσεις
- `__objc_catlist`: Pointer προς Categories
- `__objc_nlcatlist`: Pointer προς Non-Lazy Categories
- `__objc_protolist`: Λίστα πρωτοκόλλων
- `__objc_const`: Constant data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
