# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Τα binaries του Mac OS συνήθως μεταγλωττίζονται ως **universal binaries**. Ένα **universal binary** μπορεί να **υποστηρίξει πολλαπλές αρχιτεκτονικές στο ίδιο αρχείο**.

Αυτά τα binaries ακολουθούν τη **Mach-O δομή** η οποία βασικά αποτελείται από:

- Κεφαλίδα
- Εντολές Φόρτωσης (Load Commands)
- Δεδομένα

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Search for the file with: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Η κεφαλίδα περιέχει τα **magic** bytes ακολουθούμενα από τον **αριθμό** των **αρχιτεκτονικών** που το αρχείο **περιέχει** (`nfat_arch`) και κάθε αρχιτεκτονική θα έχει μια δομή `fat_arch`.

Check it with:

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

Όπως ίσως σκέφτεστε, συνήθως ένα universal binary που έχει μεταγλωττιστεί για 2 αρχιτεκτονικές **διπλασιάζει το μέγεθος** σε σχέση με ένα που έχει μεταγλωττιστεί για μόνον 1 αρχιτεκτονική.

## **Mach-O Header**

Η κεφαλίδα περιέχει βασικές πληροφορίες για το αρχείο, όπως τα magic bytes που το προσδιορίζουν ως Mach-O αρχείο και πληροφορίες σχετικά με την στοχευόμενη αρχιτεκτονική. Μπορείτε να τη βρείτε με: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O File Types

Υπάρχουν διάφοροι τύποι αρχείων· μπορείτε να τους βρείτε ορισμένους στον [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Οι πιο σημαντικοί είναι:

- `MH_OBJECT`: Αρχείο αντικειμένου με δυνατότητα επανατοποθέτησης (ενδιάμεσα προϊόντα της μεταγλώττισης — όχι ακόμη εκτελέσιμα).
- `MH_EXECUTE`: Εκτελέσιμα αρχεία.
- `MH_FVMLIB`: Αρχείο βιβλιοθήκης για Fixed VM.
- `MH_CORE`: Αρχεία dump κώδικα.
- `MH_PRELOAD`: Προφορτωμένο εκτελέσιμο αρχείο (πλέον δεν υποστηρίζεται στο XNU)
- `MH_DYLIB`: Δυναμικές βιβλιοθήκες
- `MH_DYLINKER`: Δυναμικός linker
- `MH_BUNDLE`: "Plugin files". Παράγονται χρησιμοποιώντας -bundle στο gcc και φορτώνονται ρητά από `NSBundle` ή `dlopen`.
- `MH_DYSM`: Συνοδευτικό `.dSym` αρχείο (αρχείο με σύμβολα για αποσφαλμάτωση).
- `MH_KEXT_BUNDLE`: Επεκτάσεις πυρήνα.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ή χρησιμοποιώντας [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Σημαίες Mach-O**

Ο πηγαίος κώδικας ορίζει επίσης αρκετές σημαίες χρήσιμες για τη φόρτωση βιβλιοθηκών:

- `MH_NOUNDEFS`: Καμία μη ορισμένη αναφορά (πλήρως συνδεδεμένο)
- `MH_DYLDLINK`: Σύνδεση dyld
- `MH_PREBOUND`: Οι δυναμικές αναφορές είναι προδεσμευμένες
- `MH_SPLIT_SEGS`: Το αρχείο χωρίζει τμήματα r/o και r/w
- `MH_WEAK_DEFINES`: Το δυαδικό έχει αδύναμα ορισμένα σύμβολα
- `MH_BINDS_TO_WEAK`: Το δυαδικό χρησιμοποιεί αδύναμα σύμβολα
- `MH_ALLOW_STACK_EXECUTION`: Κάνει την στοίβα εκτελέσιμη
- `MH_NO_REEXPORTED_DYLIBS`: Η βιβλιοθήκη δεν έχει εντολές LC_REEXPORT
- `MH_PIE`: Θέση-ανεξάρτητο εκτελέσιμο
- `MH_HAS_TLV_DESCRIPTORS`: Υπάρχει ενότητα με thread-local μεταβλητές
- `MH_NO_HEAP_EXECUTION`: Απαγορεύεται η εκτέλεση για σελίδες heap/data
- `MH_HAS_OBJC`: Το δυαδικό έχει τμήματα Objective-C
- `MH_SIM_SUPPORT`: Υποστήριξη προσομοιωτή
- `MH_DYLIB_IN_CACHE`: Χρησιμοποιείται σε dylibs/frameworks στην cache κοινής βιβλιοθήκης

## **Εντολές φόρτωσης Mach-O**

Η διάταξη του αρχείου στη μνήμη καθορίζεται εδώ, περιγράφοντας λεπτομερώς τη θέση του πίνακα συμβόλων, το πλαίσιο του κύριου νήματος κατά την έναρξη εκτέλεσης, και τις απαιτούμενες shared libraries. Παρέχονται οδηγίες στον dynamic loader **(dyld)** σχετικά με τη διαδικασία φόρτωσης του δυαδικού στη μνήμη.

Χρησιμοποιεί τη δομή **load_command**, ορισμένη στο προαναφερθέν **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Υπάρχουν περίπου **50 διαφορετικοί τύποι εντολών φόρτωσης** που το σύστημα χειρίζεται διαφορετικά. Οι πιο συνηθισμένοι είναι: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, και `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Βασικά, αυτός ο τύπος εντολής φόρτωσης ορίζει **πώς να φορτωθούν τα \_\_TEXT** (εκτελέσιμος κώδικας) **και \_\_DATA** (δεδομένα για τη διεργασία) **τμήματα** σύμφωνα με τις **μετατοπίσεις που υποδεικνύονται στην ενότητα δεδομένων** όταν το binary εκτελείται.

Αυτές οι εντολές **ορίζουν τμήματα** που **χαρτογραφούνται** στον **εικονικό χώρο μνήμης** μιας διεργασίας όταν αυτή εκτελείται.

Υπάρχουν **διάφοροι τύποι** τμημάτων, όπως το τμήμα **\_\_TEXT**, που περιέχει τον εκτελέσιμο κώδικα ενός προγράμματος, και το τμήμα **\_\_DATA**, που περιέχει δεδομένα που χρησιμοποιούνται από τη διεργασία. Αυτά τα **τμήματα βρίσκονται στην ενότητα δεδομένων** του αρχείου Mach-O.

**Κάθε τμήμα** μπορεί να διαιρεθεί περαιτέρω σε πολλαπλές **sections**. Η **δομή της εντολής φόρτωσης** περιέχει **πληροφορίες** για **αυτές τις sections** μέσα στο αντίστοιχο τμήμα.

Στην κεφαλίδα πρώτα θα βρείτε την **κεφαλίδα τμήματος**:

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

Παράδειγμα κεφαλίδας τμήματος:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Αυτή η κεφαλίδα ορίζει τον **αριθμό των sections των οποίων οι κεφαλίδες εμφανίζονται μετά** από αυτή:
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
<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Παράδειγμα **επικεφαλίδας τμήματος**:

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Εάν **προσθέσετε** την **μετατόπιση τμήματος** (0x37DC) + την **μετατόπιση** όπου **η arch ξεκινά**, σε αυτή την περίπτωση `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Είναι επίσης δυνατό να λάβετε πληροφορίες **κεφαλίδων** από τη **γραμμή εντολών** με:
```bash
otool -lv /bin/ls
```
Κοινά τμήματα που φορτώνονται από αυτήν την εντολή:

- **`__PAGEZERO`:** Δίνει οδηγία στον kernel να **χαρτογραφήσει** τη **διεύθυνση μηδέν** ώστε **να μην μπορεί να διαβαστεί, να γραφτεί ή να εκτελεστεί**. Οι μεταβλητές maxprot και minprot στη δομή τίθενται στο μηδέν για να υποδείξουν ότι **δεν υπάρχουν δικαιώματα ανάγνωσης-εγγραφής-εκτέλεσης σε αυτή τη σελίδα**.
- Αυτή η κατανομή είναι σημαντική για να **μειώσει τις ευπάθειες NULL pointer dereference**. Αυτό συμβαίνει επειδή το XNU επιβάλλει μια σκληρή σελίδα μηδέν που εξασφαλίζει ότι η πρώτη σελίδα (μόνο η πρώτη) της μνήμης είναι μη προσβάσιμη (εκτός σε i386). Ένα binary μπορεί να ικανοποιήσει αυτή την απαίτηση δημιουργώντας ένα μικρό __PAGEZERO (χρησιμοποιώντας την επιλογή `-pagezero_size`) για να καλύψει τα πρώτα 4k και να έχει το υπόλοιπο της 32bit μνήμης προσβάσιμο τόσο σε user όσο και σε kernel mode.
- **`__TEXT`**: Περιέχει **εκτελέσιμο** **κώδικα** με δικαιώματα **ανάγνωσης** και **εκτέλεσης** (χωρίς εγγραφή). Κοινές ενότητες αυτού του segment:
- `__text`: Συνταγμένος κώδικας του binary
- `__const`: Σταθερά δεδομένα (μόνο ανάγνωση)
- `__[c/u/os_log]string`: Σταθερές συμβολοσειρές C, Unicode ή os log
- `__stubs` και `__stubs_helper`: Εμπλέκονται στη διαδικασία δυναμικής φόρτωσης βιβλιοθηκών
- `__unwind_info`: Δεδομένα αποκατάστασης στοίβας (stack unwind)
- Σημειώστε ότι όλο αυτό το περιεχόμενο είναι υπογεγραμμένο αλλά επίσης επισημασμένο ως εκτελέσιμο (δημιουργώντας περισσότερες επιλογές για εκμετάλλευση τμημάτων που δεν χρειάζονται απαραίτητα αυτό το προνόμιο, όπως τμήματα αφιερωμένα σε συμβολοσειρές).
- **`__DATA`**: Περιέχει δεδομένα που είναι **αναγνώσιμα** και **εγγράψιμα** (χωρίς εκτέλεση).
- `__got`: Global Offset Table
- `__nl_symbol_ptr`: Non-lazy (bind at load) pointer συμβόλων
- `__la_symbol_ptr`: Lazy (bind on use) pointer συμβόλων
- `__const`: Θα έπρεπε να είναι δεδομένα μόνο ανάγνωσης (δεν είναι πάντα)
- `__cfstring`: CoreFoundation συμβολοσειρές
- `__data`: Παγκόσμιες μεταβλητές (που έχουν αρχικοποιηθεί)
- `__bss`: Στατικές μεταβλητές (που δεν έχουν αρχικοποιηθεί)
- `__objc_*` (__objc_classlist, __objc_protolist, κ.λπ.): Πληροφορίες που χρησιμοποιούνται από το Objective-C runtime
- **`__DATA_CONST`**: Το __DATA.__const δεν είναι εγγυημένο ότι είναι σταθερό (έχει δικαιώματα εγγραφής), ούτε και άλλοι pointers και το GOT. Αυτό το τμήμα καθιστά το `__const`, μερικούς αρχικοποιητές και τον πίνακα GOT (μόλις επιλυθεί) **μόνο για ανάγνωση** χρησιμοποιώντας `mprotect`.
- **`__LINKEDIT`**: Περιέχει πληροφορίες για τον linker (dyld) όπως εγγραφές πινάκων συμβόλων, συμβολοσειρών και relocation. Είναι ένας γενικός κοντέινερ για περιεχόμενο που δεν ανήκει στο `__TEXT` ή το `__DATA` και το περιεχόμενό του περιγράφεται σε άλλες load commands.
- dyld πληροφορίες: Rebase, Non-lazy/lazy/weak binding opcodes και export info
- Functions starts: Πίνακας διευθύνσεων εκκίνησης συναρτήσεων
- Data In Code: Νησίδες δεδομένων μέσα στο `__text`
- Πίνακας Συμβόλων: Σύμβολα μέσα στο binary
- Έμμεσος Πίνακας Συμβόλων: Pointer/stub σύμβολα
- Πίνακας Συμβολοσειρών
- Υπογραφή Κώδικα
- **`__OBJC`**: Περιέχει πληροφορίες που χρησιμοποιούνται από το Objective-C runtime. Παρόλο που αυτές οι πληροφορίες μπορεί επίσης να βρεθούν στο τμήμα `__DATA`, μέσα σε διάφορα `__objc_*` sections.
- **`__RESTRICT`**: Ένα segment χωρίς περιεχόμενο με μία ενότητα που ονομάζεται **`__restrict`** (επίσης κενή) που εξασφαλίζει ότι κατά την εκτέλεση του binary θα αγνοεί τις περιβαλλοντικές μεταβλητές του DYLD.

Όπως φαίνεται στον κώδικα, **τα segments υποστηρίζουν επίσης flags** (αν και δεν χρησιμοποιούνται πολύ):

- `SG_HIGHVM`: Core only (όχι χρησιμοποιούμενο)
- `SG_FVMLIB`: Όχι χρησιμοποιούμενο
- `SG_NORELOC`: Το segment δεν έχει relocation
- `SG_PROTECTED_VERSION_1`: Κρυπτογράφηση. Χρησιμοποιείται για παράδειγμα από το Finder για να κρυπτογραφήσει το `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** περιέχει το entrypoint στο **entryoff attribute.** Κατά το φόρτωμα, ο **dyld** απλώς **προσθέτει** αυτή την τιμή στη (στη μνήμη) **βάση του binary**, και στη συνέχεια **πηδάει** σε αυτή την εντολή για να ξεκινήσει η εκτέλεση του κώδικα του binary.

**`LC_UNIXTHREAD`** περιέχει τις τιμές που πρέπει να έχουν οι καταχωρητές κατά την εκκίνηση του main thread. Αυτό έχει ήδη αποσυρθεί αλλά ο **`dyld`** εξακολουθεί να το χρησιμοποιεί. Είναι δυνατόν να δείτε τις τιμές των καταχωρητών που θέτει αυτό με:
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


Περιέχει πληροφορίες για την **υπογραφή κώδικα του Mach-O αρχείου**. Περιλαμβάνει μόνο ένα **offset** που **δείχνει** στο **signature blob**. Αυτό βρίσκεται τυπικά στο τέλος του αρχείου.\
Ωστόσο, μπορείτε να βρείτε κάποιες πληροφορίες για αυτή την ενότητα στο [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) και αυτό το [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Υποστήριξη για κρυπτογράφηση του binary. Ωστόσο, φυσικά, αν ένας επιτιθέμενος καταφέρει να συμβιβάσει τη διεργασία, θα μπορεί να dump τη μνήμη μη κρυπτογραφημένη.

### **`LC_LOAD_DYLINKER`**

Περιέχει την **διαδρομή προς το εκτελέσιμο του dynamic linker** που χαρτογραφεί τις shared libraries στον address space της διεργασίας. Η **τιμή είναι πάντα ορισμένη σε `/usr/lib/dyld`**. Είναι σημαντικό να σημειωθεί ότι στο macOS, το mapping των dylib γίνεται σε **λειτουργία χρήστη**, όχι σε λειτουργία πυρήνα.

### **`LC_IDENT`**

Παρωχημένο, αλλά όταν ρυθμιστεί να δημιουργεί dumps σε panic, δημιουργείται ένα Mach-O core dump και η έκδοση του πυρήνα ορίζεται στην εντολή `LC_IDENT`.

### **`LC_UUID`**

Τυχαίο UUID. Δεν είναι ιδιαίτερα χρήσιμο από μόνο του, αλλά το XNU το αποθηκεύει στην cache μαζί με τις υπόλοιπες πληροφορίες της διεργασίας. Μπορεί να χρησιμοποιηθεί σε crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Επιτρέπει τον καθορισμό μεταβλητών περιβάλλοντος για το dyld πριν εκτελεστεί η διεργασία. Αυτό μπορεί να είναι πολύ επικίνδυνο καθώς μπορεί να επιτρέψει την εκτέλεση αυθαίρετου κώδικα μέσα στη διεργασία, γι' αυτό αυτή η load command χρησιμοποιείται μόνο σε dyld build με `#define SUPPORT_LC_DYLD_ENVIRONMENT` και επιπλέον περιορίζει την επεξεργασία μόνο σε μεταβλητές της μορφής `DYLD_..._PATH` που καθορίζουν load paths.

### **`LC_LOAD_DYLIB`**

Αυτή η εντολή φόρτωσης περιγράφει μια εξάρτηση από δυναμική βιβλιοθήκη που **εντοπίζει** τον **loader** (dyld) να **φορτώσει και να συνδέσει τη συγκεκριμένη βιβλιοθήκη**. Υπάρχει μια εντολή `LC_LOAD_DYLIB` **για κάθε βιβλιοθήκη** που απαιτεί το Mach-O binary.

- Αυτή η εντολή φόρτωσης είναι μια δομή τύπου **`dylib_command`** (η οποία περιέχει μια struct dylib, περιγράφοντας την πραγματική εξαρτώμενη δυναμική βιβλιοθήκη):
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

Μπορείτε επίσης να λάβετε αυτές τις πληροφορίες από το cli με:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: Παρακολούθηση συσκευών USB
- **AVFoundation:** Καταγραφή ήχου και βίντεο
- **CoreWLAN**: Σάρωση Wi‑Fi.

> [!TIP]
> Ένα αρχείο Mach-O μπορεί να περιέχει έναν ή **περισσότερους** **constructors**, οι οποίοι θα **εκτελεστούν** **πριν** από τη διεύθυνση που καθορίζεται στο **LC_MAIN**.\
> Οι offsets οποιωνδήποτε constructors κρατούνται στην ενότητα **\_\_mod_init_func** του segment **\_\_DATA_CONST**.

## **Mach-O Data**

Στον πυρήνα του αρχείου βρίσκεται η περιοχή δεδομένων, η οποία αποτελείται από διάφορα τμήματα όπως ορίζονται στην περιοχή load-commands. **Μια ποικιλία ενοτήτων δεδομένων μπορεί να φιλοξενηθεί μέσα σε κάθε τμήμα**, με κάθε ενότητα **να περιέχει κώδικα ή δεδομένα** ειδικά για έναν τύπο.

> [!TIP]
> Τα δεδομένα είναι ουσιαστικά το τμήμα που περιέχει όλες τις **πληροφορίες** που φορτώνονται από τις load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Που περιέχει πληροφορίες για τις συναρτήσεις του προγράμματος.
- **Symbol table**: Που περιέχει πληροφορίες για τις εξωτερικές συναρτήσεις που χρησιμοποιεί το binary
- Μπορεί επίσης να περιέχει εσωτερικές συναρτήσεις, ονόματα μεταβλητών και άλλα.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

Στο τμήμα `__TEXT` (r-x):

- `__objc_classname`: Ονόματα κλάσεων (συμβολοσειρές)
- `__objc_methname`: Ονόματα μεθόδων (συμβολοσειρές)
- `__objc_methtype`: Τύποι μεθόδων (συμβολοσειρές)

Στο τμήμα `__DATA` (rw-):

- `__objc_classlist`: Δείκτες προς όλες τις κλάσεις Objetive-C
- `__objc_nlclslist`: Δείκτες προς Non-Lazy κλάσεις Objective-C
- `__objc_catlist`: Δείκτης σε Categories
- `__objc_nlcatlist`: Δείκτης σε Non-Lazy Categories
- `__objc_protolist`: Λίστα πρωτοκόλλων
- `__objc_const`: Σταθερά δεδομένα
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
