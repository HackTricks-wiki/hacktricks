# macOS Universal binaries & Μορφή Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το macOS χρησιμοποιεί τη μορφή εκτελέσιμων **Mach-O**. Ένα **universal** ή fat binary περιέχει πολλαπλά Mach-O slices, ένα για κάθε αρχιτεκτονική, σε ένα αρχείο. Οι κεφαλίδες ανοιχτού κώδικα `fat.h` και `loader.h` της Apple ορίζουν τις δομές και τις σταθερές που περιγράφονται σε αυτήν τη σελίδα. <sup>[[5]](#references)</sup>

Μια εικόνα Mach-O αποτελείται από:

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

Το header περιέχει τα bytes **magic**, ακολουθούμενα από τον **αριθμό** των **archs** που **περιέχει** το αρχείο (`nfat_arch`), και κάθε arch έχει μια δομή `fat_arch`.

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

ή με το εργαλείο [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Όπως ίσως σκέφτεστε, ένα universal binary που έχει συνήθως μεταγλωττιστεί για 2 αρχιτεκτονικές έχει **διπλάσιο μέγεθος** από ένα που έχει μεταγλωττιστεί μόνο για 1 arch.

> [!TIP]
> Κατά την αρχική εξέταση malware ή ύποπτων εφαρμογών, μην αρκεστείτε στο αποτέλεσμα της `file` που αναφέρει την «καλύτερη» αρχιτεκτονική. Ένα universal binary μπορεί να κρύβει διαφορετικά imports, load commands ή metadata μεταγλωττιστή σε κάθε slice, επομένως απαριθμήστε πρώτα **όλα** τα slices και, στη συνέχεια, εξετάστε τα ανεξάρτητα:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Τα πρόσφατα macOS SDK εκθέτουν επίσης τα `macho_for_each_slice()` και `macho_best_slice()` στο `<mach-o/utils.h>`. Σε Apple Silicon, πριν από το macOS 15, η `macho_best_slice()` μπορούσε να επιστρέψει λανθασμένα `EBADARCH` για ένα εκτελέσιμο `arm64` τρίτου μέρους· το API διορθώθηκε στο macOS 15. Χρησιμοποιήστε τα `macho_for_each_slice()` ή `lipo -archs` για να καταγράψετε όλα τα slices, αντί να θεωρήσετε ότι μια αποτυχημένη αναζήτηση best-slice αποδεικνύει πως κανένα slice δεν μπορεί να εκτελεστεί.<sup>[[1]](#references)[[7]](#references)</sup>

### Σύγκριση code signatures μεταξύ slices

Κάθε αρχιτεκτονική σε ένα universal binary έχει το δικό της CodeDirectory και CDHash. Κατά τον έλεγχο ενός υπογεγραμμένου εκτελέσιμου ή privileged helper, εξετάστε την **υπογραφή κάθε slice**. Ένα διαφορετικό CDHash είναι φυσιολογικό· συγκρίνετε την ταυτότητα υπογραφής, τα CodeDirectory flags και τα entitlements.<sup>[[8]](#references)</sup>

Για policies που αντιστοιχίζουν ένα CDHash, κάθε hash προσδιορίζει μόνο μία διαδρομή εκτέλεσης συγκεκριμένης αρχιτεκτονικής. Η Apple συνιστά την απαρίθμηση των slices και τη χρήση του `codesign --arch` για τον έλεγχο καθενός.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

Για τη δομή της υπογραφής και τις λεπτομέρειες επικύρωσης, δείτε το [macOS Code Signing](../macos-security-protections/macos-code-signing.md).

## **Κεφαλίδα Mach-O**

Η κεφαλίδα περιέχει βασικές πληροφορίες για το αρχείο, όπως magic bytes για την αναγνώρισή του ως αρχείο Mach-O και πληροφορίες σχετικά με την αρχιτεκτονική-στόχο. Μπορείτε να τη βρείτε με την εντολή: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Υπάρχουν διαφορετικοί τύποι αρχείων, οι οποίοι ορίζονται στον [**πηγαίο κώδικα, για παράδειγμα εδώ**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Οι σημαντικότεροι είναι:

- `MH_OBJECT`: Αρχείο μεταγλωττίσιμου αντικειμένου (ενδιάμεσα προϊόντα της μεταγλώττισης, δεν είναι ακόμη εκτελέσιμα).
- `MH_EXECUTE`: Εκτελέσιμα αρχεία.
- `MH_FVMLIB`: Αρχείο βιβλιοθήκης σταθερής VM.
- `MH_CORE`: Dump μνήμης.
- `MH_PRELOAD`: Προφορτωμένο εκτελέσιμο αρχείο (δεν υποστηρίζεται πλέον στο XNU).
- `MH_DYLIB`: Δυναμικές βιβλιοθήκες.
- `MH_DYLINKER`: Δυναμικός linker.
- `MH_BUNDLE`: «Αρχεία plugin». Δημιουργούνται με τη χρήση του `-bundle` στο gcc και φορτώνονται ρητά από τα `NSBundle` ή `dlopen`.
- `MH_DSYM`: Συνοδευτικό αρχείο `.dSYM` (αρχείο με σύμβολα για αποσφαλμάτωση).
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

Ο πηγαίος κώδικας ορίζει επίσης διάφορες σημαίες χρήσιμες για τη φόρτωση βιβλιοθηκών:

- `MH_NOUNDEFS`: Δεν υπάρχουν μη επιλυμένες αναφορές (πλήρως συνδεδεμένο)
- `MH_DYLDLINK`: Σύνδεση dyld
- `MH_PREBOUND`: Οι δυναμικές αναφορές είναι προκαθορισμένα συνδεδεμένες.
- `MH_SPLIT_SEGS`: Το αρχείο διαχωρίζει τα τμήματα μόνο για ανάγνωση και ανάγνωση/εγγραφή.
- `MH_WEAK_DEFINES`: Το binary περιέχει σύμβολα με weak ορισμούς
- `MH_BINDS_TO_WEAK`: Το binary χρησιμοποιεί weak σύμβολα
- `MH_ALLOW_STACK_EXECUTION`: Κάνει τη στοίβα εκτελέσιμη
- `MH_NO_REEXPORTED_DYLIBS`: Η βιβλιοθήκη δεν περιέχει εντολές LC_REEXPORT
- `MH_PIE`: Εκτελέσιμο ανεξάρτητο από τη θέση
- `MH_HAS_TLV_DESCRIPTORS`: Υπάρχει ενότητα με τοπικές μεταβλητές νήματος
- `MH_NO_HEAP_EXECUTION`: Δεν επιτρέπεται η εκτέλεση σε σελίδες heap/data
- `MH_HAS_OBJC`: Το binary περιέχει ενότητες oBject-C
- `MH_SIM_SUPPORT`: Υποστήριξη προσομοιωτή
- `MH_DYLIB_IN_CACHE`: Χρησιμοποιείται σε dylibs/frameworks στην κοινόχρηστη cache βιβλιοθηκών.

## **Εντολές φόρτωσης Mach-O**

Η **διάταξη του αρχείου στη μνήμη** καθορίζεται εδώ, με λεπτομέρειες για τη **θέση του πίνακα συμβόλων**, το πλαίσιο του κύριου νήματος κατά την έναρξη της εκτέλεσης και τις απαιτούμενες **κοινόχρηστες βιβλιοθήκες**. Παρέχονται οδηγίες στον dynamic loader **(dyld)** για τη διαδικασία φόρτωσης του binary στη μνήμη.

Χρησιμοποιεί τη δομή **load_command**, η οποία ορίζεται στο προαναφερθέν **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Υπάρχουν περίπου **50 διαφορετικοί τύποι εντολών φόρτωσης** τους οποίους το σύστημα χειρίζεται διαφορετικά. Οι πιο συνηθισμένοι είναι: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` και `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Βασικά, αυτός ο τύπος εντολής φόρτωσης ορίζει **πώς φορτώνονται τα τμήματα \_\_TEXT** (εκτελέσιμος κώδικας) **και \_\_DATA** (δεδομένα της διεργασίας), **σύμφωνα με τα offsets που υποδεικνύονται στην ενότητα Data**, κατά την εκτέλεση του binary.

Αυτές οι εντολές **ορίζουν τμήματα** που **αντιστοιχίζονται** στον **εικονικό χώρο μνήμης** μιας διεργασίας κατά την εκτέλεσή της.

Υπάρχουν **διαφορετικοί τύποι** τμημάτων, όπως το τμήμα **\_\_TEXT**, το οποίο περιέχει τον εκτελέσιμο κώδικα ενός προγράμματος, και το τμήμα **\_\_DATA**, το οποίο περιέχει δεδομένα που χρησιμοποιεί η διεργασία. Αυτά τα **τμήματα βρίσκονται στην ενότητα δεδομένων** του αρχείου Mach-O.

**Κάθε τμήμα** μπορεί να **διαιρεθεί** περαιτέρω σε πολλαπλές **ενότητες**. Η **δομή της εντολής φόρτωσης** περιέχει **πληροφορίες** σχετικά με **αυτές τις ενότητες** μέσα στο αντίστοιχο τμήμα.

Στην κεφαλίδα, πρώτα βρίσκετε την **κεφαλίδα τμήματος**:

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

Αυτή η κεφαλίδα ορίζει **τον αριθμό των ενοτήτων των οποίων οι κεφαλίδες εμφανίζονται μετά από αυτήν**:

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

Παράδειγμα **επικεφαλίδας ενότητας**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Αν **προσθέσετε** τη **μετατόπιση ενότητας** (0x37DC) στη **μετατόπιση** όπου ξεκινά η **αρχιτεκτονική**, σε αυτή την περίπτωση `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Μπορείτε επίσης να λάβετε **πληροφορίες κεφαλίδων** από τη **γραμμή εντολών** με:

```bash
otool -lv /bin/ls
```

Common segments που φορτώνονται από αυτή την εντολή:

- **`__PAGEZERO`:** Δίνει εντολή στον kernel να **χαρτογραφήσει** τη **διεύθυνση μηδέν**, ώστε να **μην είναι δυνατή η ανάγνωση, η εγγραφή ή η εκτέλεση** σε αυτήν. Οι μεταβλητές maxprot και minprot στη δομή ορίζονται σε μηδέν, υποδεικνύοντας ότι **δεν υπάρχουν δικαιώματα ανάγνωσης-εγγραφής-εκτέλεσης σε αυτήν τη σελίδα**.
  - Αυτή η εκχώρηση είναι σημαντική για τον **περιορισμό των ευπαθειών αποαναφοράς NULL pointer**. Αυτό συμβαίνει επειδή το XNU επιβάλλει ένα αυστηρό page zero, το οποίο διασφαλίζει ότι η πρώτη σελίδα (και μόνο η πρώτη) της μνήμης είναι μη προσβάσιμη (εκτός από το i386). Ένα binary θα μπορούσε να ικανοποιήσει αυτή την απαίτηση δημιουργώντας ένα μικρό \_\_PAGEZERO (χρησιμοποιώντας το `-pagezero_size`) που καλύπτει τα πρώτα 4k, ενώ η υπόλοιπη μνήμη 32 bit παραμένει προσβάσιμη τόσο σε user όσο και σε kernel mode.
- **`__TEXT`**: Περιέχει **εκτελέσιμο** **κώδικα** με δικαιώματα **ανάγνωσης** και **εκτέλεσης** (χωρίς δικαίωμα εγγραφής)**.** Συνήθεις ενότητες αυτού του segment:
  - `__text`: Μεταγλωττισμένος δυαδικός κώδικας
  - `__const`: Σταθερά δεδομένα (μόνο για ανάγνωση)
  - `__[c/u/os_log]string`: Συμβολοσειρές σταθερών C, Unicode ή os log
  - `__stubs` και `__stubs_helper`: Συμμετέχουν στη διαδικασία φόρτωσης της dynamic library
  - `__unwind_info`: Δεδομένα αποτύλιξης της στοίβας.
  - Σημειώστε ότι όλο αυτό το περιεχόμενο είναι υπογεγραμμένο, αλλά επισημαίνεται επίσης ως εκτελέσιμο (δημιουργώντας περισσότερες δυνατότητες εκμετάλλευσης ενοτήτων που δεν χρειάζονται απαραίτητα αυτό το δικαίωμα, όπως οι αποκλειστικές ενότητες συμβολοσειρών).
- **`__DATA`**: Περιέχει δεδομένα που είναι **αναγνώσιμα** και **εγγράψιμα** (όχι εκτελέσιμα)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Δείκτης συμβόλου non-lazy (δέσμευση κατά τη φόρτωση)
  - `__la_symbol_ptr`: Δείκτης συμβόλου lazy (δέσμευση κατά τη χρήση)
  - `__const`: Θα έπρεπε να περιέχει δεδομένα μόνο για ανάγνωση (όχι στην πράξη)
  - `__cfstring`: Συμβολοσειρές CoreFoundation
  - `__data`: Καθολικές μεταβλητές (που έχουν αρχικοποιηθεί)
  - `__bss`: Στατικές μεταβλητές (που δεν έχουν αρχικοποιηθεί)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist κ.λπ.): Πληροφορίες που χρησιμοποιούνται από το Objective-C runtime
- **`__DATA_CONST`**: Δεν είναι εγγυημένο ότι το \_\_DATA.\_\_const είναι σταθερό (έχει δικαιώματα εγγραφής), ούτε και οι άλλοι δείκτες και το GOT. Αυτό το section καθιστά τα `__const`, ορισμένους initializers και τον πίνακα GOT (αφού επιλυθεί) **μόνο για ανάγνωση**, χρησιμοποιώντας το `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Συνηθισμένα σε πρόσφατα binary Apple Silicon. Αυτά τα segments περιέχουν δείκτες που πρέπει να πιστοποιηθούν κατά τη φόρτωση ή τη χρήση (για παράδειγμα, `__auth_got`). Αν ένα τέχνασμα rebinding, hook ή import-patching ελέγχει μόνο τα παλαιότερα sections `__got` / `__la_symbol_ptr`, μπορεί να παραβλέψει τα πραγματικά σημεία κλήσης σε σύγχρονα binary `arm64e`. Για περισσότερες λεπτομέρειες σχετικά με αυτά τα sections, δείτε [αυτή τη σελίδα](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Περιέχει πληροφορίες για τον linker (dyld), όπως καταχωρίσεις στους πίνακες συμβόλων, συμβολοσειρών και μετεγκατάστασης. Είναι ένα γενικό δοχείο για περιεχόμενο που δεν βρίσκεται ούτε στο `__TEXT` ούτε στο `__DATA`, και το περιεχόμενό του περιγράφεται σε άλλες εντολές φόρτωσης.
  - Πληροφορίες dyld: opcodes Rebase, Non-lazy/lazy/weak binding και πληροφορίες export
  - Αρχές συναρτήσεων: Πίνακας διευθύνσεων έναρξης συναρτήσεων
  - Data In Code: Νησίδες δεδομένων στο \_\_text
  - Πίνακας συμβόλων: Σύμβολα στο binary
  - Πίνακας έμμεσων συμβόλων: Σύμβολα δεικτών/stub
  - Πίνακας συμβολοσειρών
  - Code Signature
- **`__OBJC`**: Περιέχει πληροφορίες που χρησιμοποιούνται από το Objective-C runtime. Ωστόσο, αυτές οι πληροφορίες μπορεί να βρίσκονται και στο segment \_\_DATA, μέσα σε διάφορα sections \_\_objc\_\*.
- **`__RESTRICT`**: Ένα segment χωρίς περιεχόμενο, το οποίο περιέχει ένα μόνο section με όνομα **`__restrict`** (επίσης κενό), που διασφαλίζει ότι κατά την εκτέλεση του binary θα αγνοούνται οι μεταβλητές περιβάλλοντος DYLD.

Όπως ήταν δυνατό να φανεί στον κώδικα, τα **segments υποστηρίζουν επίσης flags** (αν και δεν χρησιμοποιούνται πολύ):

- `SG_HIGHVM`: Μόνο για Core (δεν χρησιμοποιείται)
- `SG_FVMLIB`: Δεν χρησιμοποιείται
- `SG_NORELOC`: Το segment δεν έχει μετεγκατάσταση
- `SG_PROTECTED_VERSION_1`: Κρυπτογράφηση. Χρησιμοποιείται, για παράδειγμα, από το Finder για την κρυπτογράφηση του segment κειμένου `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

Το **`LC_MAIN`** περιέχει το entry point στο **χαρακτηριστικό entryoff.** Κατά τη φόρτωση, το **dyld** απλώς **προσθέτει** αυτή την τιμή στη (μνήμη) **βάση του binary** και, στη συνέχεια, **μεταβαίνει** σε αυτή την εντολή για να ξεκινήσει την εκτέλεση του κώδικα του binary.

Το **`LC_UNIXTHREAD`** περιέχει τις τιμές που πρέπει να έχουν οι καταχωρητές κατά την εκκίνηση του κύριου thread. Αυτό έχει ήδη καταργηθεί, αλλά το **`dyld`** εξακολουθεί να το χρησιμοποιεί. Μπορείτε να δείτε τις τιμές των καταχωρητών που ορίζονται με αυτόν τον τρόπο χρησιμοποιώντας:

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
Μπορείτε να βρείτε περισσότερες πληροφορίες για αυτήν την ενότητα σε [**αυτήν την ανάρτηση ιστολογίου**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) και [**αυτό το gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Υποστήριξη για κρυπτογράφηση δυαδικών αρχείων. Ωστόσο, φυσικά, αν ένας attacker καταφέρει να παραβιάσει τη διεργασία, θα μπορεί να κάνει dump τη μνήμη χωρίς κρυπτογράφηση.

### **`LC_LOAD_DYLINKER`**

Περιέχει τη **διαδρομή προς το εκτελέσιμο αρχείο του dynamic linker**, το οποίο αντιστοιχίζει τις κοινόχρηστες βιβλιοθήκες στον χώρο διευθύνσεων της διεργασίας. Η **τιμή ορίζεται πάντα σε `/usr/lib/dyld`**. Είναι σημαντικό να σημειωθεί ότι στο macOS, η αντιστοίχιση dylib γίνεται σε **user mode**, όχι σε kernel mode.

### **`LC_IDENT`**

Έχει καταργηθεί, αλλά όταν έχει ρυθμιστεί η δημιουργία dumps κατά το panic, δημιουργείται ένα Mach-O core dump και η έκδοση του kernel ορίζεται στην εντολή `LC_IDENT`.

### **`LC_UUID`**

Τυχαίο UUID. Είναι χρήσιμο για οτιδήποτε άμεσα, αλλά το XNU το αποθηκεύει στην cache μαζί με τις υπόλοιπες πληροφορίες της διεργασίας. Μπορεί να χρησιμοποιηθεί σε αναφορές σφαλμάτων.

### **`LC_BUILD_VERSION`**

Τα σύγχρονα binaries συνήθως περιλαμβάνουν αυτήν την εντολή για να δηλώσουν την **πλατφόρμα-στόχο**, την **ελάχιστη έκδοση του OS**, την **έκδοση του SDK** και, προαιρετικά, τις **εκδόσεις των εργαλείων** που χρησιμοποιήθηκαν για τη δημιουργία αυτού του slice. Από την οπτική της offensive ανάλυσης/reversing, αυτό είναι πολύ χρήσιμο για να εντοπίσετε πώς δημιουργήθηκε ένα δείγμα και να εντοπίσετε γρήγορα περίεργα universal binaries, στα οποία ένα slice έχει μεταγλωττιστεί με διαφορετικό SDK ή deployment target. Τα παλαιότερα binaries μπορεί να χρησιμοποιούν ακόμα `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Επιτρέπει τον καθορισμό μεταβλητών περιβάλλοντος για το dyld πριν από την εκτέλεση της διεργασίας. Αυτό μπορεί να είναι πολύ επικίνδυνο, καθώς μπορεί να επιτρέψει την εκτέλεση αυθαίρετου κώδικα μέσα στη διεργασία. Για αυτόν τον λόγο, αυτή η εντολή φόρτωσης χρησιμοποιείται μόνο σε build του dyld με `#define SUPPORT_LC_DYLD_ENVIRONMENT` και περιορίζει περαιτέρω την επεξεργασία μόνο σε μεταβλητές της μορφής `DYLD_..._PATH` που καθορίζουν διαδρομές φόρτωσης.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Οι πρόσφατες toolchains αποθηκεύουν συχνά τα metadata για exports/bind/rebase σε αυτές τις εντολές, αντί να βασίζονται αποκλειστικά στους παλαιότερους opcodes `LC_DYLD_INFO[_ONLY]`. Και οι δύο είναι εγγραφές `linkedit_data_command` που δείχνουν σε δεδομένα μέσα στο **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Συμπαγές trie με τα σύμβολα που εξάγει το image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Αλυσίδες fixup ανά segment, τις οποίες χρησιμοποιεί το dyld για να εφαρμόσει rebases και binds. Στο Apple Silicon, εδώ θα συναντήσετε επίσης πολλά σύγχρονα authenticated pointer fixups.

Αυτά τα metadata είναι πολύ χρήσιμα για την ανακατασκευή των imports/exports, την κατανόηση του λόγου για τον οποίο επιλύθηκε με συγκεκριμένο τρόπο μια εξάρτηση που φορτώθηκε μέσω `@rpath` ή τη διερεύνηση του λόγου για τον οποίο απέτυχε μια προσπάθεια hook/rebinding σε έναν σύγχρονο στόχο `arm64e`. Το `dyld_info` μπορεί επίσης να χρησιμοποιηθεί σε **διαδρομές dylib που υπάρχουν μόνο στην cache** και δεν αντιστοιχούν σε αυτόνομα αρχεία στον δίσκο. Αυτό είναι πολύ χρήσιμο στο σύγχρονο macOS, όπου πολλές βιβλιοθήκες συστήματος βρίσκονται μόνο στην shared cache.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Αυτή η σύγχρονη εντολή φόρτωσης είναι κυρίως σχετική κατά την επιθεώρηση **kernel collections / kernelcache-style filesets**. Αντί να αναπαριστά ένα μεμονωμένο, αυτόνομο image, το εξωτερικό Mach-O λειτουργεί ως container και κάθε `LC_FILESET_ENTRY` δείχνει σε ένα ενσωματωμένο Mach-O με δικό του path-like **entry id**, διεύθυνση VM και file offset. Αν κάνετε reverse engineering σύγχρονων στοιχείων kernel του macOS/iOS, αυτή η εντολή είναι συχνά ο σύνδεσμος ανάμεσα στο container ανώτατου επιπέδου και στο πραγματικό image που θέλετε να εξαγάγετε ή να αποσυναρμολογήσετε.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Για πρακτικές ροές εργασίας εξαγωγής, δείτε [αυτήν τη σελίδα σχετικά με τα macOS kernel extensions και το kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Αυτή η εντολή φόρτωσης περιγράφει μια εξάρτηση από **δυναμική** **βιβλιοθήκη**, η οποία **δίνει εντολή** στον **loader** (dyld) να **φορτώσει και να συνδέσει τη συγκεκριμένη βιβλιοθήκη**. Υπάρχει μία εντολή φόρτωσης `LC_LOAD_DYLIB` **για κάθε βιβλιοθήκη** που απαιτεί το Mach-O binary.

- Αυτή η εντολή φόρτωσης είναι μια δομή τύπου **`dylib_command`** (η οποία περιέχει μια δομή dylib που περιγράφει την πραγματική εξαρτώμενη δυναμική βιβλιοθήκη):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t αριθμός έκδοσης συμβατότητας της βιβλιοθήκης](<../../../images/image (486).png>)

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
- **CoreWLAN**: Σάρωση δικτύων Wi-Fi.

> [!TIP]
> Ένα binary Mach-O μπορεί να περιέχει έναν ή **περισσότερους** **constructors**, οι οποίοι θα **εκτελεστούν** **πριν** από τη διεύθυνση που καθορίζεται στο **LC_MAIN**.\
> Τα offsets των constructors αποθηκεύονται στο section **\_\_mod_init_func** του segment **\_\_DATA_CONST**.

## **Δεδομένα Mach-O**

Στον πυρήνα του αρχείου βρίσκεται η περιοχή δεδομένων, η οποία αποτελείται από διάφορα segments, όπως ορίζονται στην περιοχή των load commands. **Κάθε segment μπορεί να περιέχει ποικίλα sections δεδομένων**, με κάθε section να **περιέχει κώδικα ή δεδομένα** ειδικά για έναν τύπο.

> [!TIP]
> Τα δεδομένα είναι ουσιαστικά το τμήμα που περιέχει όλες τις **πληροφορίες** που φορτώνονται από τα load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Σε αυτά περιλαμβάνονται:

- **Πίνακας συναρτήσεων:** Περιέχει πληροφορίες σχετικά με τις συναρτήσεις του προγράμματος.
- **Πίνακας συμβόλων**: Περιέχει πληροφορίες σχετικά με τις εξωτερικές συναρτήσεις που χρησιμοποιεί το binary.
- Μπορεί επίσης να περιέχει εσωτερικές συναρτήσεις, ονόματα μεταβλητών και άλλα.

Για να το ελέγξετε, μπορείτε να χρησιμοποιήσετε το εργαλείο [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ή από το cli:

```bash
size -m /bin/ls
```

### Προσαρτημένα δεδομένα και overlays που αναλύονται αντίστροφα

Ένας loader μπορεί να διατηρεί τη διαμόρφωση σε προσαρτημένα δεδομένα αντί σε μια ονομασμένη ενότητα Mach-O. Στη συνέχεια, ένας reverse parser εντοπίζει έναν δείκτη στο τέλος του αρχείου, διαβάζει ένα μέγεθος που είναι αποθηκευμένο ακριβώς πριν από αυτόν και χρησιμοποιεί αυτήν την τιμή για να εντοπίσει και να αποκρυπτογραφήσει το προηγούμενο blob. Ένας universal loader που παρατηρήθηκε χρησιμοποιούσε αυτήν τη διάταξη για ένα URL downloader κρυπτογραφημένο με XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Κατά την αντίστροφη ανάλυση ενός άγνωστου binary, εξετάστε τα bytes γύρω από αναγνωρίσιμους δείκτες τέλους και ανιχνεύστε κάθε υπολογισμό μεγέθους προς τα πίσω, πριν υποθέσετε ότι τα strings ή οι ρυθμίσεις παραμέτρων ανήκουν σε κάποια ενότητα load-command. Ο δείκτης και το κλειδί XOR αφορούν το συγκεκριμένο δείγμα· η επαναχρησιμοποιήσιμη τεχνική είναι το αυτοπεριγραφόμενο trailer.

## Κοινές ενότητες Objective-C

Στο τμήμα `__TEXT` (r-x):

- `__objc_classname`: Ονόματα κλάσεων (strings)
- `__objc_methname`: Ονόματα μεθόδων (strings)
- `__objc_methtype`: Τύποι μεθόδων (strings)

Στο τμήμα `__DATA` (rw-):

- `__objc_classlist`: Δείκτες προς όλες τις κλάσεις Objective-C
- `__objc_nlclslist`: Δείκτες προς τις Non-Lazy κλάσεις Objective-C
- `__objc_catlist`: Δείκτες προς Categories
- `__objc_nlcatlist`: Δείκτες προς Non-Lazy Categories
- `__objc_protolist`: Λίστα Protocols
- `__objc_const`: Δεδομένα σταθερών
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Δείτε επίσης: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Τα Mach-O slices δεν είναι τόσο απλά όσο ίσως νομίζετε](https://objective-see.org/blog/blog_0x80.html)
- [2] [Σελίδα man του dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Ανάγνωση των δικών σας entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` και `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Νέα έκδοση του macOS stealer MacSync στοχεύει λάτρεις των crypto και developers](https://securelist.com/macsync-new-version/121383/)
- [7] [Η τέχνη του Mac Malware, Τόμος 2 — Ανάλυση Binaries](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Μέσα στο Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Επιτρέποντας και αποκλείοντας apps και binaries](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
