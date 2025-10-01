# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS binarni fajlovi obično su kompajlirani kao **universal binaries**. **Universal binary** može **podržavati više arhitektura u istom fajlu**.

Ovi binarni fajlovi prate **Mach-O strukturu** koja se u suštini sastoji od:

- Zaglavlje
- Load Commands
- Podaci

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Potražite fajl sa: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Zaglavlje ima **magic** bajtove praćene brojem **arhitektura** koje fajl **sadrži** (`nfat_arch`) i svaka arhitektura će imati `fat_arch` strukturu.

Proverite to sa:

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

Kao što verovatno mislite, univerzalni binarni fajl kompajliran za 2 arhitekture obično je dvostruko veći od onog kompajliranog samo za 1 arhitekturu.

## **Mach-O Header**

Zaglavlje sadrži osnovne informacije o fajlu, kao što su magic bajtovi koji ga identifikuju kao Mach-O fajl i informacije o cilјnoj arhitekturi. Možete ga pronaći u: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O tipovi datoteka

Postoje različiti tipovi datoteka, možete ih pronaći definisane u [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najvažniji su:

- `MH_OBJECT`: Relokabilni objekt fajl (međuproizvodi kompajliranja, još nisu izvršni).
- `MH_EXECUTE`: Izvršni fajlovi.
- `MH_FVMLIB`: Fajl fiksne VM biblioteke.
- `MH_CORE`: Dump-ovi koda.
- `MH_PRELOAD`: Prethodno učitani izvršni fajl (više nije podržan u XNU).
- `MH_DYLIB`: Dinamičke biblioteke.
- `MH_DYLINKER`: Dinamički linker.
- `MH_BUNDLE`: "Plugin files". Generisani korišćenjem -bundle u gcc i eksplicitno učitavani putem `NSBundle` ili `dlopen`.
- `MH_DYSM`: Prateći `.dSym` fajl (fajl sa simbolima za otklanjanje grešaka).
- `MH_KEXT_BUNDLE`: Ekstenzije kernela.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ili koristeći [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O zastavke**

The source code also defines several flags useful for loading libraries:

- `MH_NOUNDEFS`: Bez nedefinisanih referenci (potpuno povezano)
- `MH_DYLDLINK`: Linkovanje preko dyld-a
- `MH_PREBOUND`: Dinamičke reference unapred vezane.
- `MH_SPLIT_SEGS`: Fajl razdvaja r/o i r/w segmente.
- `MH_WEAK_DEFINES`: Binar ima slabe definicije simbola
- `MH_BINDS_TO_WEAK`: Binar koristi slabe simbole
- `MH_ALLOW_STACK_EXECUTION`: Dozvoli izvršavanje na steku
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nema LC_REEXPORT komande
- `MH_PIE`: Poziciono nezavisan izvršni fajl
- `MH_HAS_TLV_DESCRIPTORS`: Postoji sekcija sa promenljivim lokalnim za niti
- `MH_NO_HEAP_EXECUTION`: Nije dozvoljeno izvršavanje na heap/data stranicama
- `MH_HAS_OBJC`: Binar ima Objective-C sekcije
- `MH_SIM_SUPPORT`: Podrška za simulator
- `MH_DYLIB_IN_CACHE`: Koristi se za dylibs/frameworks u kešu deljenih biblioteka.

## **Mach-O komande za učitavanje**

Ovde se određuje raspored fajla u memoriji, detaljno navodeći lokaciju tabele simbola, kontekst glavne niti pri pokretanju i potrebne deljene biblioteke. Daju se instrukcije dinamičkom učitaču (dyld) o procesu učitavanja binarnog fajla u memoriju.

Koristi se struktura `load_command`, definisana u pomenutom `loader.h`:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Postoji otprilike **50 different types of load commands** koje sistem obrađuje na različite načine. Najčešći su: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Suštinski, ovaj tip Load Command definiše **how to load the \_\_TEXT** (izvršni kod) **and \_\_DATA** (podatke procesa) **segments** u skladu sa **offsets indicated in the Data section** kada se binar izvršava.

Ove komande **definišu segmente** koji se **mapiraju** u **virtuelni adresni prostor** procesa kada se izvrše.

Postoje **različiti tipovi** segmenata, kao što je **\_\_TEXT** segment, koji sadrži izvršni kod programa, i **\_\_DATA** segment, koji sadrži podatke korišćene od strane procesa. Ovi **segmenti se nalaze u data section** Mach-O fajla.

**Svaki segment** može biti dalje **podeljen** na više **sekcija**. Struktura load command-a sadrži **informacije** o **ovim sekcijama** unutar odgovarajućeg segmenta.

U hederu prvo nalazite **segment header**:

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

Example of segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Ovaj heder definiše **broj sekcija čiji se hederi nalaze posle njega**:
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
Primer **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Ako **sabereš** **section offset** (0x37DC) + **offset** gde **arch** počinje, u ovom slučaju `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Takođe je moguće dobiti **headers information** iz **command line** pomoću:
```bash
otool -lv /bin/ls
```
Uobičajeni segmenti učitani ovim cmd-om:

- **`__PAGEZERO`:** Naređuje kernelu da **mapira** **adresu nula** tako da ona **ne može biti čitana, pisana ili izvršavana**. The maxprot and minprot variables in the structure are set to zero to indicate there are **no read-write-execute rights on this page**.
- This allocation is important to **mitigate NULL pointer dereference vulnerabilities**. This is because XNU enforces a hard page zero that ensures the first page (only the first) of memory is innaccesible (except in i386). A binary could fulfil this requirements by crafting a small \_\_PAGEZERO (using the `-pagezero_size`) to cover the first 4k and having the rest of 32bit memory accessible in both user and kernel mode.
- **`__TEXT`**: Sadrži **izvršni** **kod** sa dozvolama za **čitanje** i **izvršavanje** (bez dozvole za pisanje)**.** Uobičajene sekcije ovog segmenta:
- `__text`: Kompajlirani binarni kod
- `__const`: Konstantni podaci (samo za čitanje)
- `__[c/u/os_log]string`: C, Unicode ili os_log string konstante
- `__stubs` and `__stubs_helper`: Uključeni u proces učitavanja dinamičkih biblioteka
- `__unwind_info`: Podaci za povratak steka (unwind).
- Note that all this content is signed but also marked as executable (creating more options for exploitation of sections that doesn't necessarily need this privilege, like string dedicated sections).
- **`__DATA`**: Sadrži podatke koji su **čitljivi** i **pisivi** (bez izvršnih prava)**.**
- `__got:` Globalna tabela pomaka (GOT)
- `__nl_symbol_ptr`: Non-lazy (poveži pri učitavanju) pokazivač simbola
- `__la_symbol_ptr`: Lazy (poveži pri upotrebi) pokazivač simbola
- `__const`: Trebalo bi da bude samo-za-čitanje podatak (nije u potpunosti tako)
- `__cfstring`: CoreFoundation stringovi
- `__data`: Globalne promenljive (koje su inicijalizovane)
- `__bss`: Statičke promenljive (koje nisu inicijalizovane)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informacije koje koristi Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const is not guaranteed to be constant (write permissions), nor are other pointers and the GOT. This section makes `__const`, some initializers and the GOT table (once resolved) **read only** using `mprotect`.
- **`__LINKEDIT`**: Sadrži informacije za linker (dyld) kao što su unosi u tabeli simbola, stringova i relokacija. To je generički kontejner za sadržaje koji nisu ni u `__TEXT` ili `__DATA` i njegov sadržaj je opisan u drugim load komandama.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Tabela početnih adresa funkcija
- Data In Code: Data islands in \_\_text
- SYmbol Table: Simboli u binarnom fajlu
- Indirect Symbol Table: Pokazivački / stub simboli
- String Table
- Code Signature
- **`__OBJC`**: Sadrži informacije koje koristi Objective-C runtime. Ipak, ove informacije se takođe mogu naći u segmentu \_\_DATA, unutar različitih \_\_objc\_\* sekcija.
- **`__RESTRICT`**: Segment bez sadržaja sa jednom sekcijom zvanom **`__restrict`** (takođe praznom) koji osigurava da će pri pokretanju binarnog fajla ignorisati DYLD promenljive okruženja.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** sadrži ulaznu tačku u atributu **entryoff.** Pri učitavanju, **dyld** jednostavno **dodaje** ovu vrednost na (u-memoriji) **baznu adresu binarnog fajla**, pa zatim **skače** na tu instrukciju da započne izvršavanje koda binarnog fajla.

**`LC_UNIXTHREAD`** sadrži vrednosti koje registri moraju imati pri pokretanju glavne niti. Ovo je već zastarelo, ali **`dyld`** ga i dalje koristi. Vrednosti registara postavljene ovim možete videti pomoću:
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


Sadrži informacije o **code signature of the Macho-O file**. Sadrži samo **offset** koji **pokazuje** na **signature blob**. Ovo se obično nalazi na samom kraju fajla.\
Međutim, možete naći neke informacije o ovom odeljku u [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i ovom [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Podrška za enkapsulaciju binarnog fajla (binary encryption). Ipak, naravno, ako napadač uspe da kompromituje proces, biće u mogućnosti da dump-uje memoriju nekriptovanu.

### **`LC_LOAD_DYLINKER`**

Sadrži **putanju do dynamic linker executable** koji mapira shared libraries u adresni prostor procesa. Vrednost je uvek postavljena na `/usr/lib/dyld`. Važno je napomenuti da na macOS-u, dylib mapping događa u user mode, a ne u kernel mode.

### **`LC_IDENT`**

Zastarelo, ali kada je konfigurisano da generiše dump-ove na panic, kreira se Mach-O core dump i verzija kernela se postavlja u `LC_IDENT` komandu.

### **`LC_UUID`**

Nasumični UUID. Sam po sebi nije direktno koristan za mnogo toga, ali XNU ga kešira zajedno sa ostatkom informacija o procesu. Može se koristiti u crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Omogućava navođenje environment variables za dyld pre nego što se proces izvrši. Ovo može biti vrlo opasno jer može omogućiti izvršavanje proizvoljnog koda unutar procesa, pa se ovaj load command koristi samo u dyld build sa `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatno ograničava obradu samo na varijable oblika `DYLD_..._PATH` koje specifikuju load paths.

### **`LC_LOAD_DYLIB`**

Ovaj load command opisuje zavisnost od **dynamic** **library** koja **instructs** the **loader** (dyld) da **load and link said library**. Postoji po jedan `LC_LOAD_DYLIB` load command **za svaku biblioteku** koju Mach-O binarni fajl zahteva.

- Ovaj load command je struktura tipa **`dylib_command`** (koja sadrži struct dylib, opisuje stvarnu dependent dynamic library):
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

Možete takođe dobiti ove informacije iz cli pomoću:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: Praćenje USB diskova
- **AVFoundation:** Snimanje zvuka i videa
- **CoreWLAN**: Skeniranje Wifi mreža.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

U srcu fajla nalazi se data region, koji se sastoji od više segmenata definisanih u delu load-commands. **U okviru svakog segmenta može biti smešten različit skup data sekcija**, pri čemu svaka sekcija **sadrži kod ili podatke** specifične za taj tip.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Koji sadrži informacije o funkcijama programa.
- **Symbol table**: Koji sadrži informacije o eksternim funkcijama koje koristi binary
- Može takođe sadržati interne funkcije, nazive promenljivih i još mnogo toga.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C Uobičajene sekcije

U `__TEXT` segmentu (r-x):

- `__objc_classname`: Imena klasa (stringovi)
- `__objc_methname`: Imena metoda (stringovi)
- `__objc_methtype`: Tipovi metoda (stringovi)

U `__DATA` segmentu (rw-):

- `__objc_classlist`: Pokazivači na sve Objetive-C klase
- `__objc_nlclslist`: Pokazivači na Non-Lazy Objective-C klase
- `__objc_catlist`: Pokazivač na Categories
- `__objc_nlcatlist`: Pokazivač na Non-Lazy Categories
- `__objc_protolist`: Lista protokola
- `__objc_const`: Konstantni podaci
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
