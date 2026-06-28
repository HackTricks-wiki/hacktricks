# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS binaries se obično kompajliraju kao **universal binaries**. **universal binary** može da **podržava više arhitektura u istoj datoteci**.

Ovi binaries prate **Mach-O structure** koja se u osnovi sastoji od:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Pretraži datoteku pomoću: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header ima **magic** bajtove praćene **brojem** **archs** koje datoteka **sadrži** (`nfat_arch`) i svaka arch će imati `fat_arch` struct.

Proveri pomoću:

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

ili koristeći [Mach-O View](https://sourceforge.net/projects/machoview/) alat:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Kao što možda misliš, univerzalni binary kompajliran za 2 arhitekture obično **udvostručuje veličinu** u odnosu na onaj kompajliran za samo 1 arch.

> [!TIP]
> When triaging malware or suspicious apps, don't stop after `file` reports the "best" architecture. A universal binary can hide different imports, load commands or compiler metadata in each slice, so enumerate **all** the slices first and then inspect them independently:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Nedavni macOS SDK-ovi takođe izlažu pomoćne funkcije kao što su `macho_for_each_slice()` i `macho_best_slice()` u `<mach-o/utils.h>`. Potonja je korisna da se emulira šta bi `dyld`/kernel učitao, ali skeneri bi i dalje trebalo da iteriraju kroz svaki slice kako ne bi propustili sadržaj specifičan za arhitekturu.

## **Mach-O Header**

Header sadrži osnovne informacije o fajlu, kao što su magic bytes za identifikaciju da je to Mach-O fajl i informacije o ciljnoj arhitekturi. Možete ga pronaći u: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O Tipovi Fajlova

Postoje različiti tipovi fajlova, možete ih pronaći definisane u [**source code na primer ovde**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najvažniji su:

- `MH_OBJECT`: Relokabilni object fajl (međuprodukti kompajliranja, još nisu executables).
- `MH_EXECUTE`: Izvršni fajlovi.
- `MH_FVMLIB`: Fajl fiksne VM biblioteke.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Prethodno učitani izvršni fajl (više nije podržan u XNU)
- `MH_DYLIB`: Dinamičke biblioteke
- `MH_DYLINKER`: Dinamički linker
- `MH_BUNDLE`: "Plugin fajlovi". Generisani korišćenjem -bundle u gcc i eksplicitno učitani preko `NSBundle` ili `dlopen`.
- `MH_DYSM`: Prateći `.dSym` fajl (fajl sa simbolima za debugging).
- `MH_KEXT_BUNDLE`: Kernel ekstenzije.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ili koristeći [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Izvorni kod takođe definiše nekoliko flagova korisnih za učitavanje biblioteka:

- `MH_NOUNDEFS`: Nema nedefinisanih referenci (potpuno linkovano)
- `MH_DYLDLINK`: Dyld linkovanje
- `MH_PREBOUND`: Dinamičke reference su prethodno boundovane.
- `MH_SPLIT_SEGS`: Datoteka deli r/o i r/w segmente.
- `MH_WEAK_DEFINES`: Binary ima slabo definisane simbole
- `MH_BINDS_TO_WEAK`: Binary koristi slabe simbole
- `MH_ALLOW_STACK_EXECUTION`: Čini stack izvršnim
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nema LC_REEXPORT komande
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Postoji sekcija sa thread local variables
- `MH_NO_HEAP_EXECUTION`: Nema izvršavanja za heap/data stranice
- `MH_HAS_OBJC`: Binary ima oBject-C sekcije
- `MH_SIM_SUPPORT`: Podrška za simulator
- `MH_DYLIB_IN_CACHE`: Koristi se na dylibs/frameworks u shared library cache.

## **Mach-O Load commands**

**Raspored datoteke u memoriji** je ovde specificiran, sa detaljima o **lokaciji symbol table**, kontekstu glavnog thread-a pri početku izvršavanja i potrebnim **shared libraries**. Uputstva se prosleđuju dinamičkom loader-u **(dyld)** o procesu učitavanja binarnog fajla u memoriju.

Koristi se struktura **load_command**, definisana u pomenutom **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Postoji oko **50 različitih tipova load commands** koje sistem obrađuje na različite načine. Najčešći su: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> U suštini, ovaj tip Load Command definiše **kako da se učitaju segmenti \_\_TEXT** (izvršni kod) **i \_\_DATA** (podaci za proces) **u skladu sa offsetima navedenim u Data sekciji** kada se binarni fajl izvrši.

Ove komande **definišu segmente** koji se **mapiraju** u **virtuelni memorijski prostor** procesa kada se izvršava.

Postoje **različiti tipovi** segmenata, kao što je segment **\_\_TEXT**, koji sadrži izvršni kod programa, i segment **\_\_DATA**, koji sadrži podatke koje koristi proces. Ovi **segmenti se nalaze u data sekciji** Mach-O fajla.

**Svaki segment** može dalje da se **podeli** na više **sekcija**. **Struktura load command-a** sadrži **informacije** o **tim sekcijama** unutar odgovarajućeg segmenta.

U headeru prvo nalaziš **segment header**:

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

Primer segment header-a:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Ovaj header definiše **broj sekcija čiji se headeri pojavljuju posle** njega:
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
Primer **zaglavlja sekcije**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Ako **dodate** **pomak sekcije** (0x37DC) + **pomak** gde **arch počinje**, u ovom slučaju `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Takođe je moguće dobiti **informacije o zaglavljima** iz **command line** sa:
```bash
otool -lv /bin/ls
```
Uobičajeni segmenti učitani ovim cmd:

- **`__PAGEZERO`:** Naređuje kernelu da **mapira** **adresu nula** tako da **ne može da se čita, upisuje niti izvršava**. Promenljive maxprot i minprot u strukturi su postavljene na nulu da bi označile da na ovoj stranici **nema read-write-execute prava**.
- Ovo alociranje je važno da bi se **ublažile NULL pointer dereference ranjivosti**. To je zato što XNU nameće hard page zero koji obezbeđuje da je prva stranica (samo prva) memorije nedostupna (osim u i386). Binarni fajl može da ispuni ovaj uslov tako što napravi mali \_\_PAGEZERO (koristeći `-pagezero_size`) da pokrije prvih 4k i da ostatak 32bit memorije bude dostupan i u user i u kernel modu.
- **`__TEXT`**: Sadrži **izvršni** **code** sa dozvolama za **read** i **execute** (nema writable)**.** Uobičajene sekcije ovog segmenta:
- `__text`: Kompajlirani binary code
- `__const`: Konstantni podaci (read only)
- `__[c/u/os_log]string`: C, Unicode ili os logs string konstante
- `__stubs` and `__stubs_helper`: Uključeni tokom procesa učitavanja dynamic library
- `__unwind_info`: Podaci za stack unwind.
- Imajte na umu da je sav ovaj sadržaj potpisan, ali i označen kao izvršan (što stvara više opcija za exploitation sekcija kojima ta privilegija ne mora nužno da bude potrebna, kao što su sekcije namenjene stringovima).
- **`__DATA`**: Sadrži podatke koji su **readable** i **writable** (nema executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Trebalo bi da budu read-only podaci (ne baš)
- `__cfstring`: CoreFoundation strings
- `__data`: Globalne promenljive (koje su inicijalizovane)
- `__bss`: Statičke promenljive (koje nisu inicijalizovane)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informacije koje koristi Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const nije garantovano konstantan (write permissions), niti su ostali pokazivači i GOT. Ovaj segment čini `__const`, neke initializers i GOT tabelu (jednom kada se resolve-uje) **read only** pomoću `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Uobičajeno u novijim Apple Silicon binary fajlovima. Ovi segmenti sadrže pokazivače koji moraju da budu authenticated pri load ili use time (na primer `__auth_got`). Ako rebinding, hook ili import-patching trik proverava samo legacy `__got` / `__la_symbol_ptr` sekcije, može da propusti stvarne call sites u modernim `arm64e` binary fajlovima. Za više detalja o ovim sekcijama pogledajte [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Sadrži informacije za linker (dyld) kao što su symbol, string i relocation table entries. To je generički container za sadržaj koji nije u `__TEXT` ili `__DATA`, a njegov sadržaj je opisan u drugim load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes i export info
- Functions starts: Tabela početnih adresa funkcija
- Data In Code: Data islands u \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Sadrži informacije koje koristi Objective-C runtime. Iako se ove informacije mogu naći i u \_\_DATA segmentu, unutar raznih \_\_objc\_\* sekcija.
- **`__RESTRICT`**: Segment bez sadržaja sa jednom sekcijom pod nazivom **`__restrict`** (takođe praznom) koji obezbeđuje da će, pri pokretanju binary fajla, DYLD environmental variables biti ignorisane.

Kao što se moglo videti u code, **segments takođe podržavaju flags** (iako se ne koriste mnogo):

- `SG_HIGHVM`: Samo core (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Koristi se, na primer, od strane Finder-a za encryption text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** sadrži entrypoint u **entryoff attribute.** Pri load time, **dyld** jednostavno **dodaje** ovu vrednost na (u memoriji) **base of the binary**, a zatim **skače** na ovu instrukciju da bi započeo izvršavanje binary koda.

**`LC_UNIXTHREAD`** sadrži vrednosti koje registry mora da ima pri pokretanju main thread-a. Ovo je već deprecated, ali **`dyld`** ga i dalje koristi. Moguće je videti vrednosti registry-ja postavljene ovim sa:
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


Sadrži informacije o **code signature Macho-O fajla**. Sadrži samo **offset** koji **pokazuje** na **signature blob**. Ovo se tipično nalazi na samom kraju fajla.\
Međutim, neke informacije o ovom odeljku možeš naći u [**ovom blog postu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i u ovim [**gistovima**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Podrška za enkripciju binarnih fajlova. Međutim, naravno, ako napadač uspe da kompromituje proces, moći će da izvadi memoriju nešifrovanu.

### **`LC_LOAD_DYLINKER`**

Sadrži **putanju do izvršnog fajla dinamičkog linkera** koji mapira deljene biblioteke u adresni prostor procesa. **Vrednost je uvek postavljena na `/usr/lib/dyld`**. Važno je napomenuti da se u macOS-u mapiranje dylib-ova dešava u **user mode**, a ne u kernel mode.

### **`LC_IDENT`**

Zastareo, ali kada je podešen da generiše dump-ove pri panic-u, kreira se Mach-O core dump i verzija kernela se postavlja u `LC_IDENT` komandi.

### **`LC_UUID`**

Nasumični UUID. Nije direktno koristan ni za šta, ali XNU ga kešira zajedno sa ostalim informacijama o procesu. Može se koristiti u crash report-ovima.

### **`LC_BUILD_VERSION`**

Moderni binarni fajlovi obično sadrže ovu komandu da bi deklarisali **target platformu**, **minimalnu OS verziju**, **SDK verziju** i, opciono, **tool verzije** korišćene za build tog slice-a. Iz offensive/reversing perspektive, ovo je veoma korisno za fingerprinting kako je sample napravljen i za brzo uočavanje čudnih universal binaries gde je jedan slice kompajliran sa drugačijim SDK-om ili deployment target-om. Stariji binarni fajlovi i dalje mogu da koriste `LC_VERSION_MIN_*` umesto toga.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Omogućava da se naznače environment variables za dyld pre nego što se proces izvrši. Ovo može biti veoma opasno jer može omogućiti izvršavanje proizvoljnog koda unutar procesa, pa se ovaj load command koristi samo u dyld build-u sa `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatno ograničava obradu samo na varijable u formatu `DYLD_..._PATH` koje specificiraju load paths.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Noviji toolchains često čuvaju export/bind/rebase metadata u ovim komandama umesto da se oslanjaju samo na starije `LC_DYLD_INFO[_ONLY]` opcodes. Oba su `linkedit_data_command` unosi koji pokazuju u **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktni trie sa simbolima koje image eksportuje.
- **`LC_DYLD_CHAINED_FIXUPS`**: Chains fixup-a po segmentima koje dyld koristi za primenu rebases i binds. Na Apple Silicon-u ćete ovde takođe nailaziti na mnoge moderne authenticated pointer fixups.

Ova metadata je vrlo korisna pri rekonstruisanju imports/exports, razumevanju zašto je `@rpath`-loaded dependency rešena na određeni način, ili otkrivanju zašto je hook/rebinding pokušaj propao na modernom `arm64e` targetu. `dyld_info` se takođe može koristiti nad **cache-only dylib paths** koji ne postoje kao samostalni fajlovi na disku, što je veoma korisno na modernom macOS-u gde mnoge sistemske biblioteke postoje samo u shared cache-u.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Ova moderna load komanda je uglavnom relevantna kada se ispituju **kernel collections / kernelcache-style filesets**. Umesto da predstavlja jednu samostalnu sliku, spoljašnji Mach-O deluje kao kontejner i svaki `LC_FILESET_ENTRY` pokazuje na ugrađeni Mach-O sa svojim path-like **entry id**, VM adresom i file offsetom. Ako reverzujete moderne macOS/iOS kernel komponente, ova komanda je često most između kontejnera na najvišem nivou i stvarne slike koju želite da izvučete ili disasemblirate.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Za praktične workflow-ove ekstrakcije, pogledajte [ovu drugu stranicu o macOS kernel extensions i kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ova load komanda opisuje zavisnost od **dinamičke** **biblioteke** koja **upućuje** **loader** (dyld) da **učita i poveže tu biblioteku**. Postoji `LC_LOAD_DYLIB` load komanda **za svaku biblioteku** koja je potrebna Mach-O binarnoj datoteci.

- Ova load komanda je struktura tipa **`dylib_command`** (koja sadrži struct dylib, koja opisuje stvarnu zavisnu dinamičku biblioteku):
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

Ove informacije možete takođe dobiti iz cli sa:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Neke potencijalne biblioteke povezane sa malware-om su:

- **DiskArbitration**: Nadgledanje USB diskova
- **AVFoundation:** Snimanje zvuka i videa
- **CoreWLAN**: Wifi skeniranja.

> [!TIP]
> Mach-O binary može da sadrži jedan ili **više** **konstruktora**, koji će biti **izvršeni** **pre** adrese navedene u **LC_MAIN**.\
> Offseti bilo kog konstruktora se nalaze u sekciji **\_\_mod_init_func** segmenta **\_\_DATA_CONST**.

## **Mach-O Data**

U jezgru fajla nalazi se data region, koji je sastavljen od nekoliko segmenata, kao što je definisano u load-commands regionu. **Različite data sekcije mogu biti smeštene unutar svakog segmenta**, pri čemu svaka sekcija **sadrži code ili data** specifične za određeni tip.

> [!TIP]
> Data je u osnovi deo koji sadrži sve **informacije** koje se učitavaju pomoću load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Ovo uključuje:

- **Function table:** Koja sadrži informacije o programskim funkcijama.
- **Symbol table**: Koja sadrži informacije o eksternim funkcijama koje binary koristi
- Može takođe da sadrži i interne funkcije, imena varijabli i još mnogo toga.

Da biste to proverili, možete koristiti alat [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ili iz cli:
```bash
size -m /bin/ls
```
## Uobičajeni Objective-C sekciji

U `__TEXT` segmentu (r-x):

- `__objc_classname`: Imena klasa (stringovi)
- `__objc_methname`: Imena metoda (stringovi)
- `__objc_methtype`: Tipovi metoda (stringovi)

U `__DATA` segmentu (rw-):

- `__objc_classlist`: Pokazivači na sve Objective-C klase
- `__objc_nlclslist`: Pokazivači na Non-Lazy Objective-C klase
- `__objc_catlist`: Pokazivač na Categories
- `__objc_nlcatlist`: Pokazivač na Non-Lazy Categories
- `__objc_protolist`: Lista protokola
- `__objc_const`: Konstantni podaci
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Reference

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
