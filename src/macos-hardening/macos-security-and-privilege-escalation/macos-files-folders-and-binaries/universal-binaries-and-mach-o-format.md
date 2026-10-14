# Universal binaries του macOS και μορφή Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το macOS χρησιμοποιεί τη μορφή εκτελέσιμων **Mach-O**. Ένα **universal**, ή fat, binary περιέχει πολλά Mach-O slices, το καθένα για διαφορετική αρχιτεκτονική, σε ένα αρχείο. Οι κεφαλίδες `fat.h` και `loader.h` του ανοιχτού κώδικα της Apple ορίζουν τις δομές και τις σταθερές που περιγράφονται σε αυτήν τη σελίδα. <sup>[[5]](#references)</sup>

Μια εικόνα Mach-O αποτελείται από:

- Κεφαλίδα
- Load Commands
- Δεδομένα

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Κεφαλίδα Fat

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

Η κεφαλίδα περιλαμβάνει τα bytes **magic**, ακολουθούμενα από τον **αριθμό** των **archs** που **περιέχει** το αρχείο (`nfat_arch`), και κάθε arch έχει μια δομή `fat_arch`.

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

Όπως ίσως υποψιάζεστε, ένα universal binary που έχει μεταγλωττιστεί για 2 αρχιτεκτονικές έχει συνήθως **διπλάσιο μέγεθος** από ένα που έχει μεταγλωττιστεί για μία μόνο αρχιτεκτονική.

> [!TIP]
> Κατά την αρχική ανάλυση malware ή ύποπτων εφαρμογών, μην σταματάτε όταν το `file` αναφέρει την «καλύτερη» αρχιτεκτονική. Ένα universal binary μπορεί να κρύβει διαφορετικά imports, load commands ή μεταδεδομένα compiler σε κάθε slice, επομένως πρώτα απαριθμήστε **όλα** τα slices και έπειτα εξετάστε τα ξεχωριστά:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Οι πρόσφατες εκδόσεις του macOS SDK παρέχουν επίσης βοηθητικές συναρτήσεις όπως οι `macho_for_each_slice()` και `macho_best_slice()` στο `<mach-o/utils.h>`. Η δεύτερη είναι χρήσιμη για την προσομοίωση του slice που θα φόρτωναν τα dyld/kernel, αλλά οι scanners πρέπει και πάλι να εξετάζουν κάθε slice, ώστε να μην παραλείπουν περιεχόμενο ειδικό για κάποια αρχιτεκτονική.<sup>[[1]](#references)</sup>

## **Κεφαλίδα Mach-O**

Η κεφαλίδα περιέχει βασικές πληροφορίες για το αρχείο, όπως magic bytes για την αναγνώρισή του ως αρχείου Mach-O και πληροφορίες για την αρχιτεκτονική-στόχο. Μπορείτε να τη βρείτε με την εντολή: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Υπάρχουν διαφορετικοί τύποι αρχείων, οι οποίοι ορίζονται, για παράδειγμα, στον [**πηγαίο κώδικα εδώ**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Οι σημαντικότεροι είναι:

- `MH_OBJECT`: Αρχείο αντικειμένου με δυνατότητα ανατοποθέτησης (ενδιάμεσο προϊόν της μεταγλώττισης, όχι ακόμη εκτελέσιμο).
- `MH_EXECUTE`: Εκτελέσιμα αρχεία.
- `MH_FVMLIB`: Αρχείο βιβλιοθήκης σταθερής εικονικής μνήμης.
- `MH_CORE`: Αρχεία core dump.
- `MH_PRELOAD`: Προφορτωμένο εκτελέσιμο αρχείο (δεν υποστηρίζεται πλέον στο XNU).
- `MH_DYLIB`: Δυναμικές βιβλιοθήκες.
- `MH_DYLINKER`: Δυναμικός linker.
- `MH_BUNDLE`: «Αρχεία plugin». Δημιουργούνται με τη χρήση του -bundle στο gcc και φορτώνονται ρητά από το `NSBundle` ή το `dlopen`.
- `MH_DYSM`: Συνοδευτικό αρχείο `.dSym` (αρχείο με σύμβολα για debugging).
- `MH_KEXT_BUNDLE`: Επεκτάσεις πυρήνα.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Ή χρησιμοποιώντας το [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Σημαίες Mach-O**

Ο πηγαίος κώδικας ορίζει επίσης αρκετές σημαίες χρήσιμες για τη φόρτωση βιβλιοθηκών:

- `MH_NOUNDEFS`: Δεν υπάρχουν μη ορισμένες αναφορές (πλήρως συνδεδεμένο)
- `MH_DYLDLINK`: Σύνδεση Dyld
- `MH_PREBOUND`: Οι δυναμικές αναφορές είναι προκαθορισμένα συνδεδεμένες.
- `MH_SPLIT_SEGS`: Το αρχείο χωρίζει τα τμήματα r/o και r/w.
- `MH_WEAK_DEFINES`: Το binary έχει ασθενώς ορισμένα σύμβολα
- `MH_BINDS_TO_WEAK`: Το binary χρησιμοποιεί ασθενή σύμβολα
- `MH_ALLOW_STACK_EXECUTION`: Κάνει τη στοίβα εκτελέσιμη
- `MH_NO_REEXPORTED_DYLIBS`: Η βιβλιοθήκη δεν έχει εντολές LC_REEXPORT
- `MH_PIE`: Εκτελέσιμο ανεξάρτητο από τη θέση
- `MH_HAS_TLV_DESCRIPTORS`: Υπάρχει μια ενότητα με τοπικές μεταβλητές νημάτων
- `MH_NO_HEAP_EXECUTION`: Δεν επιτρέπεται η εκτέλεση για σελίδες heap/data
- `MH_HAS_OBJC`: Το binary έχει ενότητες oBject-C
- `MH_SIM_SUPPORT`: Υποστήριξη προσομοιωτή
- `MH_DYLIB_IN_CACHE`: Χρησιμοποιείται σε dylibs/frameworks στην κοινόχρηστη library cache.

## **Εντολές φόρτωσης Mach-O**

Η **διάταξη του αρχείου στη μνήμη** καθορίζεται εδώ, με λεπτομέρειες για τη **θέση του πίνακα συμβόλων**, το περιβάλλον του κύριου νήματος κατά την έναρξη της εκτέλεσης και τις απαιτούμενες **κοινόχρηστες βιβλιοθήκες**. Παρέχονται οδηγίες στον dynamic loader **(dyld)** σχετικά με τη διαδικασία φόρτωσης του binary στη μνήμη.

Χρησιμοποιείται η δομή **load_command**, η οποία ορίζεται στο προαναφερθέν **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Υπάρχουν περίπου **50 διαφορετικοί τύποι load commands**, τους οποίους το σύστημα χειρίζεται με διαφορετικό τρόπο. Οι πιο συνηθισμένοι είναι: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` και `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Βασικά, αυτός ο τύπος Load Command ορίζει **πώς θα φορτωθούν τα τμήματα \_\_TEXT** (εκτελέσιμος κώδικας) **και \_\_DATA** (δεδομένα για τη διεργασία), **σύμφωνα με τα offsets που υποδεικνύονται στην ενότητα Data**, κατά την εκτέλεση του binary.

Αυτές οι εντολές **ορίζουν τμήματα**, τα οποία **χαρτογραφούνται** στον **χώρο εικονικής μνήμης** μιας διεργασίας κατά την εκτέλεσή της.

Υπάρχουν **διαφορετικοί τύποι** τμημάτων, όπως το τμήμα **\_\_TEXT**, το οποίο περιέχει τον εκτελέσιμο κώδικα ενός προγράμματος, και το τμήμα **\_\_DATA**, το οποίο περιέχει δεδομένα που χρησιμοποιούνται από τη διεργασία. Αυτά τα **τμήματα βρίσκονται στην ενότητα δεδομένων** του αρχείου Mach-O.

**Κάθε τμήμα** μπορεί να **διαιρεθεί** περαιτέρω σε πολλαπλές **ενότητες**. Η **δομή της load command** περιέχει **πληροφορίες** για **αυτές τις ενότητες** μέσα στο αντίστοιχο τμήμα.

Στην αρχή της κεφαλίδας βρίσκεται η **κεφαλίδα του τμήματος**:

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

Αυτή η κεφαλίδα ορίζει **τον αριθμό των ενοτήτων, οι κεφαλίδες των οποίων εμφανίζονται μετά από αυτήν**:

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

Αν **προσθέσετε** το **offset της ενότητας** (0x37DC) στο **offset** όπου ξεκινά η **arch**, σε αυτήν την περίπτωση `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Μπορείτε επίσης να λάβετε **πληροφορίες κεφαλίδας** από τη **γραμμή εντολών** με:

```bash
otool -lv /bin/ls
```

Common segments που φορτώνονται από αυτό το cmd:

- **`__PAGEZERO`:** Δίνει εντολή στον kernel να κάνει **map** τη **διεύθυνση μηδέν**, ώστε να **μην είναι δυνατή η ανάγνωση, η εγγραφή ή η εκτέλεση** σε αυτήν. Οι μεταβλητές maxprot και minprot στη δομή ορίζονται σε μηδέν, υποδεικνύοντας ότι **αυτή η σελίδα δεν έχει δικαιώματα ανάγνωσης-εγγραφής-εκτέλεσης**.
  - Αυτή η εκχώρηση είναι σημαντική για τον **μετριασμό ευπαθειών NULL pointer dereference**. Αυτό συμβαίνει επειδή το XNU επιβάλλει μια προστατευμένη σελίδα μηδέν, διασφαλίζοντας ότι η πρώτη σελίδα μνήμης (και μόνο η πρώτη) είναι απροσπέλαστη (εκτός από το i386). Ένα binary θα μπορούσε να ικανοποιήσει αυτή την απαίτηση δημιουργώντας ένα μικρό \_\_PAGEZERO (χρησιμοποιώντας το `-pagezero_size`) που καλύπτει τα πρώτα 4k και αφήνοντας το υπόλοιπο της μνήμης 32bit προσβάσιμο τόσο σε user όσο και σε kernel mode.
- **`__TEXT`**: Περιέχει **εκτελέσιμο** **κώδικα** με δικαιώματα **ανάγνωσης** και **εκτέλεσης** (χωρίς εγγραφή)**.** Συνήθεις ενότητες αυτού του segment:
  - `__text`: Μεταγλωττισμένος κώδικας binary
  - `__const`: Σταθερά δεδομένα (μόνο για ανάγνωση)
  - `__[c/u/os_log]string`: Σταθερές συμβολοσειρές C, Unicode ή os logs
  - `__stubs` και `__stubs_helper`: Συμμετέχουν κατά τη διαδικασία φόρτωσης δυναμικών βιβλιοθηκών
  - `__unwind_info`: Δεδομένα stack unwind.
  - Σημειώστε ότι όλο αυτό το περιεχόμενο είναι υπογεγραμμένο, αλλά έχει επίσης επισημανθεί ως εκτελέσιμο (δημιουργώντας περισσότερες δυνατότητες για εκμετάλλευση ενοτήτων που δεν χρειάζονται απαραίτητα αυτό το δικαίωμα, όπως οι ενότητες που προορίζονται για συμβολοσειρές).
- **`__DATA`**: Περιέχει δεδομένα που είναι **αναγνώσιμα** και **εγγράψιμα** (όχι εκτελέσιμα)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Δείκτης συμβόλου Non lazy (bind κατά τη φόρτωση)
  - `__la_symbol_ptr`: Δείκτης συμβόλου Lazy (bind κατά τη χρήση)
  - `__const`: Θα έπρεπε να περιέχει δεδομένα μόνο για ανάγνωση (όχι στην πράξη)
  - `__cfstring`: Συμβολοσειρές CoreFoundation
  - `__data`: Καθολικές μεταβλητές (που έχουν αρχικοποιηθεί)
  - `__bss`: Στατικές μεταβλητές (που δεν έχουν αρχικοποιηθεί)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, κ.λπ.): Πληροφορίες που χρησιμοποιούνται από το runtime Objective-C
- **`__DATA_CONST`**: Το \_\_DATA.\_\_const δεν είναι εγγυημένα σταθερό (δικαιώματα εγγραφής), ούτε είναι σταθεροί άλλοι δείκτες και το GOT. Αυτή η ενότητα καθιστά τα `__const`, ορισμένους initializers και τον πίνακα GOT (αφού επιλυθεί) **μόνο για ανάγνωση**, χρησιμοποιώντας το `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Συνηθισμένα σε πρόσφατα binaries Apple Silicon. Αυτά τα segments περιέχουν δείκτες που πρέπει να πιστοποιούνται κατά τη φόρτωση ή κατά τη χρήση (για παράδειγμα, `__auth_got`). Αν ένα τέχνασμα rebinding, hook ή import-patching ελέγχει μόνο τις παλαιότερες ενότητες `__got` / `__la_symbol_ptr`, μπορεί να μην εντοπίσει τα πραγματικά σημεία κλήσης σε σύγχρονα binaries `arm64e`. Για περισσότερες λεπτομέρειες σχετικά με αυτές τις ενότητες, δείτε [αυτή τη σελίδα](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Περιέχει πληροφορίες για τον linker (dyld), όπως εγγραφές στους πίνακες συμβόλων, συμβολοσειρών και relocations. Είναι ένα γενικό container για περιεχόμενο που δεν βρίσκεται στα `__TEXT` ή `__DATA` και το περιεχόμενό του περιγράφεται σε άλλες load commands.
  - Πληροφορίες dyld: Rebase, opcodes σύνδεσης Non-lazy/lazy/weak και πληροφορίες export
  - Αρχές συναρτήσεων: Πίνακας διευθύνσεων έναρξης συναρτήσεων
  - Data In Code: Περιοχές δεδομένων στο \_\_text
  - Πίνακας συμβόλων: Σύμβολα στο binary
  - Πίνακας έμμεσων συμβόλων: Σύμβολα δεικτών/stub
  - Πίνακας συμβολοσειρών
  - Υπογραφή κώδικα
- **`__OBJC`**: Περιέχει πληροφορίες που χρησιμοποιούνται από το runtime Objective-C. Ωστόσο, αυτές οι πληροφορίες μπορεί επίσης να βρίσκονται στο segment \_\_DATA, μέσα σε διάφορες ενότητες \_\_objc\_\*.
- **`__RESTRICT`**: Ένα segment χωρίς περιεχόμενο, με μία μόνο ενότητα που ονομάζεται **`__restrict`** (επίσης κενή), η οποία διασφαλίζει ότι κατά την εκτέλεση του binary θα αγνοούνται οι μεταβλητές περιβάλλοντος DYLD.

Όπως φάνηκε στον κώδικα, τα **segments υποστηρίζουν επίσης flags** (αν και δεν χρησιμοποιούνται πολύ):

- `SG_HIGHVM`: Μόνο για Core (δεν χρησιμοποιείται)
- `SG_FVMLIB`: Δεν χρησιμοποιείται
- `SG_NORELOC`: Το segment δεν έχει relocation
- `SG_PROTECTED_VERSION_1`: Κρυπτογράφηση. Χρησιμοποιείται, για παράδειγμα, από το Finder για την κρυπτογράφηση του segment κειμένου `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

Το **`LC_MAIN`** περιέχει το entrypoint στο **attribute entryoff.** Κατά τη φόρτωση, το **dyld** απλώς **προσθέτει** αυτή την τιμή στη (στη μνήμη) **βάση του binary** και στη συνέχεια **μεταβαίνει** σε αυτή την εντολή για να ξεκινήσει την εκτέλεση του κώδικα του binary.

Το **`LC_UNIXTHREAD`** περιέχει τις τιμές που πρέπει να έχουν οι καταχωρητές κατά την εκκίνηση του κύριου thread. Αυτό είχε ήδη καταργηθεί, αλλά το **`dyld`** εξακολουθεί να το χρησιμοποιεί. Μπορείτε να δείτε τις τιμές των καταχωρητών που ορίζονται με αυτόν τον τρόπο χρησιμοποιώντας:

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


Περιέχει πληροφορίες για την **υπογραφή κώδικα του αρχείου Macho-O**. Περιέχει μόνο ένα **offset** που **δείχνει** στο **signature blob**. Συνήθως βρίσκεται στο τέλος του αρχείου.\
Μπορείτε να βρείτε περισσότερες πληροφορίες για αυτήν την ενότητα σε [**αυτήν την ανάρτηση ιστολογίου**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) και σε [**αυτό το gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Υποστήριξη για κρυπτογράφηση binary. Ωστόσο, φυσικά, αν ένας attacker καταφέρει να παραβιάσει τη διεργασία, θα μπορεί να κάνει dump τη μνήμη χωρίς κρυπτογράφηση.

### **`LC_LOAD_DYLINKER`**

Περιέχει τη **διαδρομή προς το εκτελέσιμο dynamic linker**, το οποίο αντιστοιχίζει shared libraries στον χώρο διευθύνσεων της διεργασίας. Η **τιμή ορίζεται πάντα σε `/usr/lib/dyld`**. Είναι σημαντικό να σημειωθεί ότι στο macOS, η αντιστοίχιση dylib γίνεται σε **user mode**, όχι σε kernel mode.

### **`LC_IDENT`**

Έχει καταργηθεί, αλλά όταν έχει ρυθμιστεί η δημιουργία dumps σε περίπτωση panic, δημιουργείται ένα Mach-O core dump και η έκδοση του kernel ορίζεται στην εντολή `LC_IDENT`.

### **`LC_UUID`**

Τυχαίο UUID. Δεν είναι άμεσα χρήσιμο για κάτι, αλλά το XNU το αποθηκεύει στην cache μαζί με τα υπόλοιπα στοιχεία της διεργασίας. Μπορεί να χρησιμοποιηθεί σε αναφορές crash.

### **`LC_BUILD_VERSION`**

Τα σύγχρονα binaries συνήθως περιλαμβάνουν αυτήν την εντολή για να δηλώσουν την **πλατφόρμα-στόχο**, την **ελάχιστη έκδοση OS**, την **έκδοση SDK** και, προαιρετικά, τις **εκδόσεις των εργαλείων** που χρησιμοποιήθηκαν για τη δημιουργία αυτού του slice. Από την οπτική του offensive/reversing, αυτό είναι πολύ χρήσιμο για να προσδιορίσετε πώς δημιουργήθηκε ένα δείγμα και να εντοπίσετε γρήγορα ασυνήθιστα universal binaries, όπου ένα slice μεταγλωττίστηκε με διαφορετικό SDK ή deployment target. Τα παλαιότερα binaries μπορεί να χρησιμοποιούν ακόμη το `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Επιτρέπει τον ορισμό μεταβλητών περιβάλλοντος για το dyld πριν από την εκτέλεση της διεργασίας. Αυτό μπορεί να είναι πολύ επικίνδυνο, καθώς μπορεί να επιτρέψει την εκτέλεση αυθαίρετου κώδικα μέσα στη διεργασία. Γι’ αυτό, αυτή η load command χρησιμοποιείται μόνο σε build του dyld με `#define SUPPORT_LC_DYLD_ENVIRONMENT` και περιορίζει περαιτέρω την επεξεργασία μόνο σε μεταβλητές της μορφής `DYLD_..._PATH` που καθορίζουν διαδρομές φόρτωσης.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Οι σύγχρονες toolchains αποθηκεύουν συχνά τα metadata των export/bind/rebase σε αυτές τις commands, αντί να βασίζονται μόνο στα παλαιότερα opcodes `LC_DYLD_INFO[_ONLY]`. Και οι δύο είναι καταχωρίσεις `linkedit_data_command` που δείχνουν σε δεδομένα μέσα στο **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Συμπαγές trie με τα symbols που εξάγει το image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Αλυσίδες fixup ανά segment, τις οποίες χρησιμοποιεί το dyld για να εφαρμόσει rebases και binds. Σε Apple Silicon, εδώ θα συναντήσετε επίσης πολλά σύγχρονα authenticated pointer fixups.

Αυτά τα metadata είναι πολύ χρήσιμα για την ανακατασκευή imports/exports, την κατανόηση του τρόπου με τον οποίο επιλύθηκε μια εξάρτηση που φορτώθηκε μέσω `@rpath` ή τη διερεύνηση του λόγου για τον οποίο απέτυχε μια απόπειρα hook/rebinding σε σύγχρονο στόχο `arm64e`. Το `dyld_info` μπορεί επίσης να χρησιμοποιηθεί με **διαδρομές dylib που υπάρχουν μόνο στο cache**, οι οποίες δεν υπάρχουν ως αυτόνομα αρχεία στον δίσκο. Αυτό είναι πολύ χρήσιμο σε σύγχρονο macOS, όπου πολλές βιβλιοθήκες συστήματος υπάρχουν μόνο στο shared cache.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Αυτή η σύγχρονη εντολή φόρτωσης έχει κυρίως σημασία κατά την επιθεώρηση **kernel collections / αρχείων τύπου kernelcache**. Αντί να αναπαριστά μία αυτόνομη εικόνα, το εξωτερικό Mach-O λειτουργεί ως container και κάθε `LC_FILESET_ENTRY` δείχνει σε ένα ενσωματωμένο Mach-O με δικό του **entry id** τύπου διαδρομής, διεύθυνση VM και offset αρχείου. Αν κάνετε reverse engineering σύγχρονων στοιχείων πυρήνα macOS/iOS, αυτή η εντολή συχνά γεφυρώνει το container ανώτατου επιπέδου με την πραγματική εικόνα που θέλετε να εξαγάγετε ή να αποσυναρμολογήσετε.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Για πρακτικές ροές εργασίας εξαγωγής, δείτε [αυτήν τη σελίδα σχετικά με τα macOS kernel extensions και το kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Αυτή η εντολή φόρτωσης περιγράφει μια εξάρτηση από **dynamic** **library**, η οποία **δίνει εντολή** στον **loader** (dyld) να **φορτώσει και να συνδέσει την εν λόγω library**. Υπάρχει μία εντολή φόρτωσης `LC_LOAD_DYLIB` **για κάθε library** που απαιτεί το Mach-O binary.

- Αυτή η εντολή φόρτωσης είναι μια δομή τύπου **`dylib_command`** (η οποία περιέχει ένα struct dylib, που περιγράφει την πραγματική εξαρτώμενη dynamic library):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t αριθμός έκδοσης συμβατότητας; / αριθμός έκδοσης συμβατότητας της βιβλιοθήκης /](<../../../images/image (486).png>)

Μπορείτε επίσης να λάβετε αυτές τις πληροφορίες από το CLI με:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Ορισμένες βιβλιοθήκες που ενδέχεται να σχετίζονται με malware είναι:

- **DiskArbitration**: Παρακολούθηση μονάδων USB
- **AVFoundation:** Καταγραφή ήχου και βίντεο
- **CoreWLAN**: Σαρώσεις Wi-Fi.

> [!TIP]
> Ένα Mach-O binary μπορεί να περιέχει έναν ή **περισσότερους** **constructors**, οι οποίοι θα **εκτελεστούν** **πριν από** τη διεύθυνση που καθορίζεται στο **LC_MAIN**.\
> Τα offsets οποιωνδήποτε constructors βρίσκονται στην ενότητα **\_\_mod_init_func** του segment **\_\_DATA_CONST**.

## **Δεδομένα Mach-O**

Στον πυρήνα του αρχείου βρίσκεται η περιοχή δεδομένων, η οποία αποτελείται από αρκετά segments, όπως ορίζονται στην περιοχή των load commands. **Σε κάθε segment μπορούν να περιέχονται διάφορες ενότητες δεδομένων**, καθεμία από τις οποίες **περιέχει κώδικα ή δεδομένα** ειδικά για έναν τύπο.

> [!TIP]
> Τα δεδομένα είναι ουσιαστικά το τμήμα που περιέχει όλες τις **πληροφορίες** που φορτώνονται από τα load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Περιλαμβάνονται:

- **Πίνακας συναρτήσεων:** Περιέχει πληροφορίες σχετικά με τις συναρτήσεις του προγράμματος.
- **Πίνακας συμβόλων**: Περιέχει πληροφορίες σχετικά με τις εξωτερικές συναρτήσεις που χρησιμοποιεί το binary.
- Θα μπορούσε επίσης να περιέχει εσωτερικές συναρτήσεις, ονόματα μεταβλητών και άλλα.

Για να το ελέγξετε, μπορείτε να χρησιμοποιήσετε το εργαλείο [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ή από το cli:

```bash
size -m /bin/ls
```

### Προσαρτημένα δεδομένα και reverse-parsed επικαλύψεις

Ένας loader μπορεί να διατηρεί ρυθμίσεις σε προσαρτημένα δεδομένα αντί σε μια επώνυμη ενότητα Mach-O. Ένας reverse parser αγκυρώνεται έπειτα σε έναν δείκτη trailer, διαβάζει ένα μέγεθος που είναι αποθηκευμένο ακριβώς πριν από αυτόν και χρησιμοποιεί αυτήν την τιμή για να εντοπίσει και να αποκρυπτογραφήσει το προηγούμενο blob. Ένας universal loader που παρατηρήθηκε χρησιμοποιούσε αυτήν τη διάταξη για ένα URL downloader κρυπτογραφημένο με XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Όταν κάνετε reverse engineering σε ένα άγνωστο binary, εξετάστε τα bytes γύρω από αναγνωρίσιμα τελικά markers και ιχνηλατήστε κάθε υπολογισμό μεγέθους προς τα πίσω, προτού υποθέσετε ότι τα strings ή οι ρυθμίσεις παραμέτρων πρέπει να ανήκουν σε μια ενότητα load-command. Το marker και το XOR key αφορούν μόνο το συγκεκριμένο δείγμα· η τεχνική που μπορεί να επαναχρησιμοποιηθεί είναι το self-describing trailer.

## Συνήθεις ενότητες Objective-C

Στο segment `__TEXT` (r-x):

- `__objc_classname`: Ονόματα κλάσεων (strings)
- `__objc_methname`: Ονόματα μεθόδων (strings)
- `__objc_methtype`: Τύποι μεθόδων (strings)

Στο segment `__DATA` (rw-):

- `__objc_classlist`: Pointers προς όλες τις κλάσεις Objective-C
- `__objc_nlclslist`: Pointers προς τις Non-Lazy κλάσεις Objective-C
- `__objc_catlist`: Pointer προς τις Categories
- `__objc_nlcatlist`: Pointers προς τις Non-Lazy Categories
- `__objc_protolist`: Λίστα Protocols
- `__objc_const`: Σταθερά δεδομένα
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Τα Mach-O slices δεν είναι τόσο απλά όσο νομίζετε](https://objective-see.org/blog/blog_0x80.html)
- [2] [Σελίδα man του dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Διαβάζοντας τα δικά σας Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` και `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Νέα έκδοση του MacSync macOS stealer στοχεύει λάτρεις των κρυπτονομισμάτων και developers](https://securelist.com/macsync-new-version/121383/)
