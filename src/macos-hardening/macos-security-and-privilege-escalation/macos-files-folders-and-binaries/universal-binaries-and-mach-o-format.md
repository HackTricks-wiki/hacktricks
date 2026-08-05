# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Binarne datoteke za Mac OS se obično kompajliraju kao **universal binaries**. **Universal binary** može da **podržava više arhitektura u istoj datoteci**.

Ove binarne datoteke prate **Mach-O strukturu**, koja se u osnovi sastoji od:

- Zaglavlja
- Load Commands
- Podataka

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Pretražite sistem za datoteku pomoću: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Zaglavlje sadrži **magic** bajtove, nakon kojih slede **broj** **arhitektura** koje datoteka **sadrži** (`nfat_arch`), a svaka arhitektura ima `fat_arch` strukturu.

Proverite pomoću:

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

ili pomoću alata [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Kao što možda pretpostavljate, universal binary kompajliran za 2 arhitekture obično ima **dvostruko veću veličinu** od onog koji je kompajliran samo za 1 arhitekturu.

> [!TIP]
> Prilikom triage-a malware-a ili sumnjivih aplikacija, nemojte stati nakon što `file` prijavi „najbolju” arhitekturu. Universal binary može sakriti različite import-e, load commands ili metadata kompajlera u svakom slice-u, zato prvo izlistajte **sve** slice-ove, a zatim ih nezavisno analizirajte:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Noviji macOS SDK-ovi takođe izlažu pomoćne funkcije kao što su `macho_for_each_slice()` i `macho_best_slice()` u `<mach-o/utils.h>`. Ova druga je korisna za emulaciju onoga što bi dyld/kernel učitao, ali skeneri i dalje treba da iteriraju kroz svaki slice kako bi izbegli propuštanje sadržaja specifičnog za određenu arhitekturu.<sup>[[1]](#references)</sup>

## **Mach-O zaglavlje**

Zaglavlje sadrži osnovne informacije o fajlu, kao što su magic bytes za identifikaciju fajla kao Mach-O fajla i informacije o ciljnoj arhitekturi. Možete ga pronaći pomoću: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Tipovi Mach-O datoteka

Postoje različiti tipovi datoteka; definisane su u [**izvornom kodu, na primer ovde**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najvažniji su:

- `MH_OBJECT`: Relocatable object file (međurezultati kompilacije, još nisu izvršne datoteke).
- `MH_EXECUTE`: Izvršne datoteke.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Ispisi memorije.
- `MH_PRELOAD`: Preloaded executable file (više nije podržan u XNU).
- `MH_DYLIB`: Dinamičke biblioteke.
- `MH_DYLINKER`: Dinamički linker.
- `MH_BUNDLE`: "Plugin files". Generišu se pomoću opcije -bundle u gcc-u i eksplicitno učitavaju pomoću `NSBundle` ili `dlopen`.
- `MH_DYSM`: Prateća `.dSym` datoteka (datoteka sa simbolima za debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
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

Izvorni kod takođe definiše nekoliko korisnih flags za učitavanje biblioteka:

- `MH_NOUNDEFS`: Nema nedefinisanih referenci (potpuno povezan)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dinamičke reference su unapred povezane.
- `MH_SPLIT_SEGS`: Fajl deli r/o i r/w segmente.
- `MH_WEAK_DEFINES`: Binary ima weak definisane simbole
- `MH_BINDS_TO_WEAK`: Binary koristi weak simbole
- `MH_ALLOW_STACK_EXECUTION`: Omogućava izvršavanje stack-a
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nema LC_REEXPORT komande
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Postoji sekcija sa thread local promenljivama
- `MH_NO_HEAP_EXECUTION`: Nema izvršavanja za heap/data stranice
- `MH_HAS_OBJC`: Binary ima oBject-C sekcije
- `MH_SIM_SUPPORT`: Podrška za simulator
- `MH_DYLIB_IN_CACHE`: Koristi se za dylib-ove/framework-e u shared library cache-u.

## **Mach-O Load commands**

**Raspored fajla u memoriji** naveden je ovde, uključujući detalje o **lokaciji tabele simbola**, kontekstu glavne niti na početku izvršavanja i potrebnim **shared libraries**. Dynamic loader-u **(dyld)** daju se instrukcije o procesu učitavanja binary-ja u memoriju.

Ovo koristi strukturu **load_command**, definisanu u pomenutom **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Postoji oko **50 različitih tipova load commands** kojima sistem rukuje na različite načine. Najčešći su: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> U osnovi, ovaj tip Load Command-a definiše **kako se učitavaju \_\_TEXT** (izvršni kod) **i \_\_DATA** (podaci za proces) **segmenti** u skladu sa **offsetima navedenim u Data sekciji** prilikom izvršavanja binarnog fajla.

Ove komande **definišu segmente** koji se **mapiraju** u **virtuelni memorijski prostor** procesa kada se on izvršava.

Postoje **različiti tipovi** segmenata, kao što je segment **\_\_TEXT**, koji sadrži izvršni kod programa, i segment **\_\_DATA**, koji sadrži podatke koje proces koristi. Ovi **segmenti se nalaze u data sekciji** Mach-O fajla.

**Svaki segment** se dalje može **podeliti** na više **sekcija**. **Struktura load command-a** sadrži **informacije** o **ovim sekcijama** unutar odgovarajućeg segmenta.

U zaglavlju se najpre nalazi **zaglavlje segmenta**:

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

Primer zaglavlja segmenta:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Ovo zaglavlje definiše **broj sekcija čija se zaglavlja pojavljuju nakon** njega:
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

Ako **dodate** **offset sekcije** (0x37DC) + **offset** na kojem arhitektura počinje, u ovom slučaju `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Takođe je moguće dobiti **informacije o zaglavljima** iz **komandne linije** pomoću:
```bash
otool -lv /bin/ls
```
Uobičajeni segmenti koje učitava ova cmd:

- **`__PAGEZERO`:** Instruira kernel da **mapira** **nultu adresu** tako da se sa nje **ne može čitati, u nju upisivati niti se sa nje može izvršavati**. Promenljive maxprot i minprot u strukturi postavljene su na nulu kako bi označile da na ovoj stranici **ne postoje read-write-execute prava**.
- Ova alokacija je važna za **ublažavanje NULL pointer dereference vulnerabilities**. To je zato što XNU primenjuje hard page zero, koji obezbeđuje da prva stranica (samo prva) memorije bude nedostupna (osim na i386). Binary bi mogao da ispuni ovaj zahtev kreiranjem malog \_\_PAGEZERO (pomoću `-pagezero_size`) koji pokriva prvih 4k i omogućavanjem pristupa ostatku 32-bitne memorije i u user i u kernel modu.
- **`__TEXT`**: Sadrži **izvršivi** **code** sa **read** i **execute** permisijama (bez writable)**.** Uobičajene sekcije ovog segmenta:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode ili os logs string constants
- `__stubs` i `__stubs_helper`: Učestvuju tokom procesa učitavanja dynamic library
- `__unwind_info`: Stack unwind data.
- Imajte na umu da je sav ovaj sadržaj potpisan, ali i označen kao executable (što stvara više opcija za exploitation sekcija kojima ova privilegija nije nužno potrebna, kao što su sekcije namenjene stringovima).
- **`__DATA`**: Sadrži podatke koji su **readable** i **writable** (nisu executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Trebalo bi da sadrži read-only data (ali zapravo ne)
- `__cfstring`: CoreFoundation strings
- `__data`: Globalne promenljive (koje su inicijalizovane)
- `__bss`: Static promenljive (koje nisu inicijalizovane)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, itd.): Informacije koje koristi Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const nije garantovano konstantan (write permissions), kao ni drugi pointeri i GOT. Ova sekcija čini `__const`, neke initializers i GOT table (nakon razrešavanja) **read only** pomoću `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Uobičajeni u novijim Apple Silicon binaries. Ovi segmenti sadrže pointere koji moraju biti authenticated prilikom load ili use vremena (na primer `__auth_got`). Ako rebinding, hook ili import-patching trik proverava samo legacy `__got` / `__la_symbol_ptr` sekcije, može propustiti stvarna call sites u modernim `arm64e` binaries. Za više detalja o ovim sekcijama pogledajte [ovu stranicu](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Sadrži informacije za linker (dyld), kao što su entries u symbol, string i relocation tabelama. To je generički container za sadržaj koji nije u `__TEXT` ili `__DATA`, a njegov sadržaj je opisan u drugim load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes i export info
- Functions starts: Tabela početnih adresa funkcija
- Data In Code: Data islands u \_\_text
- SYmbol Table: Simboli u binary
- Indirect Symbol Table: Pointer/stub simboli
- String Table
- Code Signature
- **`__OBJC`**: Sadrži informacije koje koristi Objective-C runtime. Iako se ove informacije mogu pronaći i u \_\_DATA segmentu, unutar različitih \_\_objc\_\* sekcija.
- **`__RESTRICT`**: Segment bez sadržaja sa jednom sekcijom pod nazivom **`__restrict`** (takođe praznom), koji obezbeđuje da se prilikom pokretanja binary-ja ignorišu DYLD environmental variables.

Kao što je bilo moguće videti u code-u, **segmenti takođe podržavaju flags** (iako se ne koriste često):

- `SG_HIGHVM`: Samo Core (ne koristi se)
- `SG_FVMLIB`: Ne koristi se
- `SG_NORELOC`: Segment nema relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Koristi ga, na primer, Finder za encryption text `__TEXT` segmenta.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** sadrži entrypoint u **entryoff atributu.** Prilikom load-a, **dyld** jednostavno **dodaje** ovu vrednost (in-memory) **base-u binary-ja**, a zatim **skače** na ovu instrukciju kako bi započeo izvršavanje code-a binary-ja.

**`LC_UNIXTHREAD`** sadrži vrednosti koje registri moraju imati prilikom pokretanja main thread-a. Ovo je već deprecated, ali ga **`dyld`** i dalje koristi. Vrednosti registara postavljene na ovaj način moguće je videti pomoću:
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


Sadrži informacije o **code signature Mach-O fajla**. Sadrži samo **offset** koji **pokazuje** na **signature blob**. Ovo se obično nalazi na samom kraju fajla.\
Međutim, neke informacije o ovoj sekciji možete pronaći u [**ovom blog postu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i ovom [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Podrška za enkripciju binary fajlova. Međutim, naravno, ako napadač uspe da kompromituje proces, moći će da dump-uje memoriju u dekriptovanom obliku.

### **`LC_LOAD_DYLINKER`**

Sadrži **putanju do izvršnog fajla dynamic linker-a** koji mapira shared libraries u adresni prostor procesa. **Vrednost je uvek postavljena na `/usr/lib/dyld`**. Važno je napomenuti da se u macOS-u mapiranje dylib fajlova obavlja u **user mode**, a ne u **kernel mode**.

### **`LC_IDENT`**

Zastareo je, ali kada je podešeno generisanje dump-ova prilikom panic-a, kreira se Mach-O core dump, a verzija kernela se postavlja u komandu `LC_IDENT`.

### **`LC_UUID`**

Nasumični UUID. Sam po sebi nije direktno naročito koristan, ali ga XNU kešira zajedno sa ostatkom informacija o procesu. Može se koristiti u crash report-ovima.

### **`LC_BUILD_VERSION`**

Moderni binary fajlovi obično sadrže ovu komandu za deklarisanje **ciljne platforme**, **minimalne verzije OS-a**, **SDK verzije** i, opciono, **verzija tool-ova** korišćenih za build tog slice-a. Iz offensive/reversing perspektive, ovo je veoma korisno za fingerprinting načina na koji je sample izgrađen i za brzo uočavanje neobičnih universal binary fajlova kod kojih je jedan slice kompajliran pomoću drugačijeg SDK-a ili deployment target-a. Stariji binary fajlovi umesto toga mogu koristiti `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Omogućava navođenje environment varijabli za dyld pre nego što se proces izvrši. Ovo može biti veoma opasno jer može omogućiti izvršavanje proizvoljnog koda unutar procesa, pa se ova load command koristi samo u dyld buildovima sa `#define SUPPORT_LC_DYLD_ENVIRONMENT`, a obrada se dodatno ograničava samo na varijable oblika `DYLD_..._PATH` koje navode load paths.

### **`LC_DYLD_EXPORTS_TRIE` i `LC_DYLD_CHAINED_FIXUPS`**

Noviji toolchain-i često čuvaju export/bind/rebase metadata u ovim komandama umesto da se oslanjaju samo na starije `LC_DYLD_INFO[_ONLY]` opcode-ove. Obe su `linkedit_data_command` stavke koje pokazuju unutar **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktno stablo sa simbolima koje image export-uje.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup lanci po segmentima koje dyld koristi za primenu rebases i binds. Na Apple Silicon-u se ovde takođe susreću mnogi moderni authenticated pointer fixup-ovi.

Ovi metadata podaci su veoma korisni pri rekonstrukciji imports/exports, razumevanju zašto je dependency učitan pomoću `@rpath` razrešen na određeni način ili utvrđivanju razloga zbog kog hook/rebinding pokušaj nije uspeo na modernom `arm64e` targetu. `dyld_info` se takođe može koristiti nad **cache-only dylib paths** koji ne postoje kao standalone fajlovi na disku, što je veoma korisno na modernom macOS-u gde mnoge system libraries postoje samo u shared cache-u.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Ova moderna load command je uglavnom relevantna pri analizi **kernel collections / kernelcache-style filesets**. Umesto da predstavlja jednu samostalnu image datoteku, spoljašnji Mach-O se ponaša kao container, a svaki `LC_FILESET_ENTRY` pokazuje na ugrađeni Mach-O sa sopstvenim path-like **entry id**, VM adresom i offsetom u datoteci. Ako radite reverse engineering modernih macOS/iOS kernel komponenti, ova komanda je često veza između kontejnera najvišeg nivoa i stvarne image datoteke koju želite da izdvojite ili disasemblirate.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Za praktične workflows ekstrakcije, pogledajte [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ova load command opisuje **dinamičku** zavisnost od **biblioteke** koja nalaže **loader-u** (dyld) da **učita i poveže navedenu biblioteku**. Postoji jedna `LC_LOAD_DYLIB` load command **za svaku biblioteku** koja je potrebna Mach-O binary-ju.

- Ova load command je struktura tipa **`dylib_command`** (koja sadrži struct dylib, koji opisuje stvarnu zavisnu dinamičku biblioteku):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t verzija kompatibilnosti; / broj verzije kompatibilnosti biblioteke /](<../../../images/image (486).png>)

Ove informacije možete dobiti i iz CLI-ja pomoću:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Neke potencijalne biblioteke povezane sa malware-om su:

- **DiskArbitration**: Nadgledanje USB diskova
- **AVFoundation:** Snimanje audio i video sadržaja
- **CoreWLAN**: WiFi skeniranja.

> [!TIP]
> Mach-O binary može da sadrži jedan ili **više** **konstruktora**, koji će biti **izvršeni** **pre** adrese navedene u **LC_MAIN**.\
> Offset-i svih konstruktora čuvaju se u odeljku **\_\_mod_init_func** segmenta **\_\_DATA_CONST**.

## **Mach-O podaci**

U osnovi fajla nalazi se region sa podacima, koji se sastoji od nekoliko segmenata definisanih u regionu load commands. **Unutar svakog segmenta mogu se nalaziti različiti odeljci sa podacima**, pri čemu svaki odeljak **sadrži code ili podatke** specifične za određeni tip.

> [!TIP]
> Podaci su u osnovi deo koji sadrži sve **informacije** koje učitavaju load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Ovo uključuje:

- **Tabela funkcija:** Sadrži informacije o funkcijama programa.
- **Tabela simbola**: Sadrži informacije o eksternoj funkciji koju binary koristi.
- Takođe može sadržati interne funkcije, nazive promenljivih i još mnogo toga.

Da biste to proverili, možete koristiti alat [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ili iz cli-ja:
```bash
size -m /bin/ls
```
## Uobičajene Objective-C sekcije

U segmentu `__TEXT` (r-x):

- `__objc_classname`: Imena klasa (stringovi)
- `__objc_methname`: Imena metoda (stringovi)
- `__objc_methtype`: Tipovi metoda (stringovi)

U segmentu `__DATA` (rw-):

- `__objc_classlist`: Pokazivači na sve Objective-C klase
- `__objc_nlclslist`: Pokazivači na Non-Lazy Objective-C klase
- `__objc_catlist`: Pokazivač na kategorije
- `__objc_nlcatlist`: Pokazivač na Non-Lazy kategorije
- `__objc_protolist`: Lista protokola
- `__objc_const`: Konstantni podaci
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Reference

- [1] [Mach-O slice-ovi nisu tako jednostavni kao što možda mislite](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man stranica](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Čitanje sopstvenih entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
