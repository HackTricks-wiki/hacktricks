# macOS Universal binaries και Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Τα binaries του Mac OS συνήθως γίνονται compile ως **universal binaries**. Ένα **universal binary** μπορεί να **υποστηρίζει πολλαπλές αρχιτεκτονικές στο ίδιο αρχείο**.

Αυτά τα binaries ακολουθούν τη **Mach-O structure**, η οποία αποτελείται βασικά από:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Αναζητήστε το αρχείο με: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Το header περιέχει τα **magic** bytes, ακολουθούμενα από τον **αριθμό** των **archs** που **περιέχει** το αρχείο (`nfat_arch`), και κάθε arch θα διαθέτει ένα struct `fat_arch`.

Ελέγξτε το με:

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

Όπως πιθανώς σκέφτεστε, συνήθως ένα universal binary που έχει γίνει compile για 2 αρχιτεκτονικές **διπλασιάζει το μέγεθος** ενός binary που έχει γίνει compile μόνο για 1 arch.

> [!TIP]
> Κατά το triaging malware ή ύποπτων εφαρμογών, μην σταματάτε αφού το `file` αναφέρει την «καλύτερη» αρχιτεκτονική. Ένα universal binary μπορεί να κρύβει διαφορετικά imports, load commands ή compiler metadata σε κάθε slice, επομένως απαριθμήστε πρώτα **όλα** τα slices και στη συνέχεια εξετάστε τα ανεξάρτητα:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Τα πρόσφατα macOS SDKs εκθέτουν επίσης helpers όπως τα `macho_for_each_slice()` και `macho_best_slice()` στο `<mach-o/utils.h>`. Το δεύτερο είναι χρήσιμο για την προσομοίωση του τι θα φόρτωνε το dyld/kernel, όμως οι scanners θα πρέπει και πάλι να επαναλαμβάνουν τη διαδικασία για κάθε slice, ώστε να μην παραλείπουν περιεχόμενο που αφορά συγκεκριμένες αρχιτεκτονικές.<sup>[[1]](#references)</sup>

## **Κεφαλίδα Mach-O**

Η κεφαλίδα περιέχει βασικές πληροφορίες για το αρχείο, όπως magic bytes για την αναγνώρισή του ως αρχείο Mach-O και πληροφορίες σχετικά με την αρχιτεκτονική προορισμού. Μπορείτε να τη βρείτε με: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Τύποι αρχείων Mach-O

Υπάρχουν διαφορετικοί τύποι αρχείων, τους οποίους μπορείτε να βρείτε ορισμένους στον [**πηγαίο κώδικα, για παράδειγμα εδώ**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Οι σημαντικότεροι είναι:

- `MH_OBJECT`: Relocatable object file (ενδιάμεσα προϊόντα της μεταγλώττισης, δεν είναι ακόμη εκτελέσιμα).
- `MH_EXECUTE`: Εκτελέσιμα αρχεία.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (δεν υποστηρίζεται πλέον στο XNU)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Αρχεία plugin". Δημιουργούνται με χρήση του -bundle στο gcc και φορτώνονται ρητά από τα `NSBundle` ή `dlopen`.
- `MH_DYSM`: Συνοδευτικό αρχείο `.dSym` (αρχείο με symbols για debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ή χρησιμοποιώντας το [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Ο πηγαίος κώδικας ορίζει επίσης several flags χρήσιμα για τη φόρτωση libraries:

- `MH_NOUNDEFS`: Δεν υπάρχουν undefined references (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: Το αρχείο χωρίζει τα r/o και r/w segments.
- `MH_WEAK_DEFINES`: Το binary περιέχει weak defined symbols
- `MH_BINDS_TO_WEAK`: Το binary χρησιμοποιεί weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Κάνει το stack executable
- `MH_NO_REEXPORTED_DYLIBS`: Η library δεν περιέχει εντολές LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Υπάρχει section με thread local variables
- `MH_NO_HEAP_EXECUTION`: Δεν επιτρέπεται η εκτέλεση για heap/data pages
- `MH_HAS_OBJC`: Το binary περιέχει oBject-C sections
- `MH_SIM_SUPPORT`: Υποστήριξη Simulator
- `MH_DYLIB_IN_CACHE`: Χρησιμοποιείται σε dylibs/frameworks στο shared library cache.

## **Mach-O Load commands**

Η **διάταξη του αρχείου στη μνήμη** καθορίζεται εδώ, περιγράφοντας τη **θέση του symbol table**, το context του main thread κατά την έναρξη της εκτέλεσης και τις απαιτούμενες **shared libraries**. Παρέχονται οδηγίες στον dynamic loader **(dyld)** σχετικά με τη διαδικασία φόρτωσης του binary στη μνήμη.

Χρησιμοποιείται η δομή **load_command**, η οποία ορίζεται στο προαναφερθέν **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Υπάρχουν περίπου **50 διαφορετικοί τύποι load commands** τους οποίους το σύστημα διαχειρίζεται διαφορετικά. Οι πιο συνηθισμένοι είναι οι εξής: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` και `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Βασικά, αυτός ο τύπος Load Command καθορίζει **πώς θα φορτωθούν τα \_\_TEXT** (εκτελέσιμος κώδικας) **και \_\_DATA** (δεδομένα για τη διεργασία) **segments**, σύμφωνα με τα **offsets που υποδεικνύονται στο Data section**, όταν εκτελείται το binary.

Αυτές οι εντολές **καθορίζουν segments** που **αντιστοιχίζονται** στον **virtual memory space** μιας διεργασίας κατά την εκτέλεσή της.

Υπάρχουν **διαφορετικοί τύποι** segments, όπως το **\_\_TEXT** segment, το οποίο περιέχει τον εκτελέσιμο κώδικα ενός προγράμματος, και το **\_\_DATA** segment, το οποίο περιέχει δεδομένα που χρησιμοποιούνται από τη διεργασία. Αυτά τα **segments βρίσκονται στο data section** του αρχείου Mach-O.

**Κάθε segment** μπορεί να **διαιρεθεί περαιτέρω** σε πολλά **sections**. Η **δομή του load command** περιέχει **πληροφορίες** σχετικά με **αυτά τα sections** μέσα στο αντίστοιχο segment.

Στην αρχή του header βρίσκετε το **segment header**:

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

Παράδειγμα segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Αυτό το header καθορίζει **τον αριθμό των sections των οποίων τα headers εμφανίζονται μετά από αυτό**:
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
Παράδειγμα **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Αν **προσθέσετε** το **section offset** (0x37DC) + το **offset** όπου ξεκινά το **arch**, σε αυτήν την περίπτωση `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Είναι επίσης δυνατό να λάβετε **πληροφορίες για τα headers** από τη **γραμμή εντολών** με:
```bash
otool -lv /bin/ls
```
Common segments που φορτώνονται από αυτό το cmd:

- **`__PAGEZERO`:** Δίνει εντολή στον kernel να **map** τη **διεύθυνση μηδέν**, ώστε να μην μπορεί να γίνει **read**, **write** ή **execute** σε αυτήν. Οι μεταβλητές maxprot και minprot στη δομή ορίζονται σε μηδέν, υποδεικνύοντας ότι **δεν υπάρχουν δικαιώματα read-write-execute σε αυτή τη σελίδα**.
- Αυτή η εκχώρηση είναι σημαντική για τον **μετριασμό NULL pointer dereference vulnerabilities**. Αυτό συμβαίνει επειδή το XNU επιβάλλει ένα hard page zero, το οποίο διασφαλίζει ότι η πρώτη σελίδα (μόνο η πρώτη) της μνήμης είναι μη προσβάσιμη (εκτός από το i386). Ένα binary μπορεί να εκπληρώσει αυτή την απαίτηση δημιουργώντας ένα μικρό \_\_PAGEZERO (χρησιμοποιώντας το `-pagezero_size`) ώστε να καλύπτει τα πρώτα 4k και να έχει την υπόλοιπη 32bit μνήμη προσβάσιμη τόσο σε user όσο και σε kernel mode.
- **`__TEXT`**: Περιέχει **executable** **code** με δικαιώματα **read** και **execute** (χωρίς writable)**.** Κοινά sections αυτού του segment:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode ή os logs string constants
- `__stubs` και `__stubs_helper`: Συμμετέχουν κατά τη διαδικασία dynamic library loading
- `__unwind_info`: Stack unwind data.
- Σημειώστε ότι όλο αυτό το περιεχόμενο είναι signed, αλλά επίσης marked as executable (δημιουργώντας περισσότερες επιλογές για exploitation sections που δεν χρειάζονται απαραίτητα αυτό το privilege, όπως τα string dedicated sections).
- **`__DATA`**: Περιέχει data που είναι **readable** και **writable** (χωρίς executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Θα έπρεπε να είναι read-only data (στην πραγματικότητα όχι)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (που έχουν initialized)
- `__bss`: Static variables (που δεν έχουν initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, κ.λπ.): Πληροφορίες που χρησιμοποιούνται από το Objective-C runtime
- **`__DATA_CONST`**: Το \_\_DATA.\_\_const δεν είναι εγγυημένα constant (write permissions), όπως δεν είναι και άλλα pointers και το GOT. Αυτό το section καθιστά τα `__const`, ορισμένους initializers και το GOT table (μετά την επίλυση) **read only** χρησιμοποιώντας το `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Συνηθίζονται σε πρόσφατα Apple Silicon binaries. Αυτά τα segments περιέχουν pointers που πρέπει να authenticated κατά το load ή κατά τη χρήση (για παράδειγμα το `__auth_got`). Αν ένα rebinding, hook ή import-patching trick ελέγχει μόνο τα legacy `__got` / `__la_symbol_ptr` sections, μπορεί να παραλείψει τα πραγματικά call sites σε σύγχρονα `arm64e` binaries. Για περισσότερες λεπτομέρειες σχετικά με αυτά τα sections δείτε [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Περιέχει πληροφορίες για τον linker (dyld), όπως entries των symbol, string και relocation tables. Είναι ένα generic container για περιεχόμενο που δεν βρίσκεται ούτε στο `__TEXT` ούτε στο `__DATA`, και το περιεχόμενό του περιγράφεται σε άλλα load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes και export info
- Functions starts: Πίνακας με start addresses των functions
- Data In Code: Data islands στο \_\_text
- SYmbol Table: Symbols στο binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Περιέχει πληροφορίες που χρησιμοποιούνται από το Objective-C runtime. Ωστόσο, αυτές οι πληροφορίες μπορεί επίσης να βρίσκονται στο \_\_DATA segment, μέσα σε διάφορα \_\_objc\_\* sections.
- **`__RESTRICT`**: Ένα segment χωρίς περιεχόμενο, με ένα μόνο section που ονομάζεται **`__restrict`** (επίσης κενό), το οποίο διασφαλίζει ότι κατά την εκτέλεση του binary θα αγνοούνται οι DYLD environmental variables.

Όπως ήταν δυνατό να φανεί στον κώδικα, τα **segments υποστηρίζουν επίσης flags** (παρότι δεν χρησιμοποιούνται ιδιαίτερα):

- `SG_HIGHVM`: Core only (δεν χρησιμοποιείται)
- `SG_FVMLIB`: Δεν χρησιμοποιείται
- `SG_NORELOC`: Το segment δεν έχει relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Χρησιμοποιείται, για παράδειγμα, από το Finder για την κρυπτογράφηση του `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

Το **`LC_MAIN`** περιέχει το entrypoint στο **entryoff attribute.** Κατά το load time, το **dyld** απλώς **προσθέτει** αυτή την τιμή στη (in-memory) **base του binary** και στη συνέχεια κάνει **jump** σε αυτή την instruction για να ξεκινήσει η εκτέλεση του code του binary.

Το **`LC_UNIXTHREAD`** περιέχει τις τιμές που πρέπει να έχουν τα registers κατά την εκκίνηση του main thread. Αυτό έχει ήδη deprecated, αλλά το **`dyld`** εξακολουθεί να το χρησιμοποιεί. Είναι δυνατό να δούμε τις τιμές των registers που ορίζονται με αυτό χρησιμοποιώντας:
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


Περιέχει πληροφορίες σχετικά με το **code signature του αρχείου Macho-O**. Περιέχει μόνο ένα **offset** που **δείχνει** στο **signature blob**. Αυτό βρίσκεται συνήθως ακριβώς στο τέλος του αρχείου.\
Ωστόσο, μπορείτε να βρείτε ορισμένες πληροφορίες σχετικά με αυτό το section σε [**αυτή την ανάρτηση ιστολογίου**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) και σε αυτά τα [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Υποστήριξη για binary encryption. Ωστόσο, φυσικά, αν ένας attacker καταφέρει να παραβιάσει το process, θα μπορεί να κάνει dump τη μνήμη χωρίς encryption.

### **`LC_LOAD_DYLINKER`**

Περιέχει το **path προς το dynamic linker executable** που αντιστοιχίζει shared libraries στον address space του process. Η **τιμή ορίζεται πάντα σε `/usr/lib/dyld`**. Είναι σημαντικό να σημειωθεί ότι στο macOS, το dylib mapping πραγματοποιείται σε **user mode** και όχι σε kernel mode.

### **`LC_IDENT`**

Παρωχημένο, αλλά όταν έχει ρυθμιστεί η δημιουργία dumps σε περίπτωση panic, δημιουργείται ένα Mach-O core dump και η έκδοση του kernel ορίζεται στην εντολή `LC_IDENT`.

### **`LC_UUID`**

Τυχαίο UUID. Δεν είναι άμεσα χρήσιμο για κάτι, αλλά το XNU το αποθηκεύει προσωρινά μαζί με τις υπόλοιπες πληροφορίες του process. Μπορεί να χρησιμοποιηθεί σε crash reports.

### **`LC_BUILD_VERSION`**

Τα σύγχρονα binaries συνήθως περιέχουν αυτή την εντολή για να δηλώσουν την **target platform**, την **ελάχιστη έκδοση του OS**, την **έκδοση του SDK** και, προαιρετικά, τις **εκδόσεις των tools** που χρησιμοποιήθηκαν για το build αυτού του slice. Από offensive/reversing perspective, αυτό είναι πολύ χρήσιμο για το fingerprinting του τρόπου με τον οποίο δημιουργήθηκε ένα sample και για τον γρήγορο εντοπισμό περίεργων universal binaries, όπου ένα slice έγινε compile με διαφορετικό SDK ή deployment target. Παλαιότερα binaries μπορεί να χρησιμοποιούν ακόμη το `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Επιτρέπει τον καθορισμό μεταβλητών περιβάλλοντος για το dyld πριν από την εκτέλεση της διεργασίας. Αυτό μπορεί να είναι πολύ επικίνδυνο, καθώς μπορεί να επιτρέψει την εκτέλεση arbitrary code μέσα στη διεργασία. Για αυτό, αυτό το load command χρησιμοποιείται μόνο σε builds του dyld με `#define SUPPORT_LC_DYLD_ENVIRONMENT` και περιορίζει περαιτέρω την επεξεργασία μόνο σε μεταβλητές της μορφής `DYLD_..._PATH` που καθορίζουν load paths.

### **`LC_DYLD_EXPORTS_TRIE` και `LC_DYLD_CHAINED_FIXUPS`**

Τα σύγχρονα toolchains αποθηκεύουν συχνά metadata για export/bind/rebase σε αυτά τα commands, αντί να βασίζονται αποκλειστικά στα παλαιότερα opcodes `LC_DYLD_INFO[_ONLY]`. Και τα δύο είναι entries τύπου `linkedit_data_command` που δείχνουν μέσα στο **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Compact trie με τα symbols που εξάγονται από το image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Αλυσίδες fixup ανά segment, τις οποίες χρησιμοποιεί το dyld για την εφαρμογή rebases και binds. Στο Apple Silicon, εδώ θα συναντήσετε επίσης πολλά σύγχρονα authenticated pointer fixups.

Αυτά τα metadata είναι ιδιαίτερα χρήσιμα κατά την ανακατασκευή imports/exports, την κατανόηση του λόγου για τον οποίο έγινε resolve μια dependency που φορτώθηκε μέσω `@rpath` με τον συγκεκριμένο τρόπο ή τη διερεύνηση του λόγου για τον οποίο απέτυχε μια προσπάθεια hook/rebinding σε έναν σύγχρονο στόχο `arm64e`. Το `dyld_info` μπορεί επίσης να χρησιμοποιηθεί σε **cache-only dylib paths** που δεν υπάρχουν ως standalone αρχεία στον δίσκο, κάτι ιδιαίτερα χρήσιμο στο σύγχρονο macOS, όπου πολλές system libraries βρίσκονται μόνο στο shared cache.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Αυτή η σύγχρονη εντολή φόρτωσης είναι κυρίως σημαντική κατά την επιθεώρηση **kernel collections / kernelcache-style filesets**. Αντί να αναπαριστά ένα μεμονωμένο standalone image, το εξωτερικό Mach-O λειτουργεί ως container και κάθε `LC_FILESET_ENTRY` παραπέμπει σε ένα ενσωματωμένο Mach-O με το δικό του path-like **entry id**, VM address και file offset. Αν κάνετε reverse engineering σε σύγχρονα macOS/iOS kernel components, αυτή η εντολή αποτελεί συχνά τη γέφυρα μεταξύ του top-level container και του πραγματικού image που θέλετε να εξαγάγετε ή να κάνετε disassemble.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Για πρακτικές ροές εργασίας εξαγωγής, δείτε [αυτήν τη σελίδα σχετικά με τα macOS kernel extensions και το kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Αυτή η εντολή φόρτωσης περιγράφει μια εξάρτηση από **dynamic** **library**, η οποία δίνει εντολή στον **loader** (dyld) να **φορτώσει και να συνδέσει τη συγκεκριμένη library**. Υπάρχει μία εντολή φόρτωσης `LC_LOAD_DYLIB` **για κάθε library** που απαιτεί το Mach-O δυαδικό αρχείο.

- Αυτή η εντολή φόρτωσης είναι μια δομή τύπου **`dylib_command`** (η οποία περιέχει μια δομή dylib που περιγράφει την πραγματική εξαρτώμενη dynamic library):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / αριθμός έκδοσης συμβατότητας της library /](<../../../images/image (486).png>)

Μπορείτε επίσης να λάβετε αυτές τις πληροφορίες από το cli με:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Ορισμένες πιθανές βιβλιοθήκες που σχετίζονται με malware είναι:

- **DiskArbitration**: Παρακολούθηση μονάδων USB
- **AVFoundation:** Καταγραφή ήχου και βίντεο
- **CoreWLAN**: Σαρώσεις WiFi.

> [!TIP]
> Ένα Mach-O binary μπορεί να περιέχει **έναν** ή **περισσότερους** **constructors**, οι οποίοι θα **εκτελεστούν** **πριν** από τη διεύθυνση που καθορίζεται στο **LC_MAIN**.\
> Τα offsets οποιωνδήποτε constructors αποθηκεύονται στο section **\_\_mod_init_func** του segment **\_\_DATA_CONST**.

## **Mach-O Data**

Στον πυρήνα του αρχείου βρίσκεται η περιοχή δεδομένων, η οποία αποτελείται από αρκετά segments, όπως ορίζονται στην περιοχή των load commands. **Σε κάθε segment μπορούν να φιλοξενούνται διάφορα data sections**, με κάθε section να **περιέχει κώδικα ή δεδομένα** συγκεκριμένου τύπου.

> [!TIP]
> Τα δεδομένα αποτελούν ουσιαστικά το τμήμα που περιέχει όλες τις **πληροφορίες** οι οποίες φορτώνονται από τα load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Αυτό περιλαμβάνει:

- **Πίνακας συναρτήσεων:** Περιέχει πληροφορίες σχετικά με τις συναρτήσεις του προγράμματος.
- **Πίνακας συμβόλων**: Περιέχει πληροφορίες σχετικά με την external function που χρησιμοποιείται από το binary
- Θα μπορούσε επίσης να περιέχει ονόματα internal functions, μεταβλητών και άλλα.

Για να το ελέγξετε, μπορείτε να χρησιμοποιήσετε το εργαλείο [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ή από το cli:
```bash
size -m /bin/ls
```
## Συνηθισμένα Sections του Objective-C

Στο segment `__TEXT` (r-x):

- `__objc_classname`: Ονόματα κλάσεων (strings)
- `__objc_methname`: Ονόματα μεθόδων (strings)
- `__objc_methtype`: Τύποι μεθόδων (strings)

Στο segment `__DATA` (rw-):

- `__objc_classlist`: Pointers προς όλες τις κλάσεις Objective-C
- `__objc_nlclslist`: Pointers προς Non-Lazy κλάσεις Objective-C
- `__objc_catlist`: Pointer προς Categories
- `__objc_nlcatlist`: Pointer προς Non-Lazy Categories
- `__objc_protolist`: Λίστα Protocols
- `__objc_const`: Constant data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

## References

- [1] [Τα Mach-O slices δεν είναι τόσο απλά όσο ίσως νομίζετε](https://objective-see.org/blog/blog_0x80.html)
- [2] [Σελίδα man του dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Reading Your Own Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
