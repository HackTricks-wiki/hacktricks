# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

macOS koristi izvršni format **Mach-O**. **Universal**, odnosno fat, binary sadrži više Mach-O isečaka specifičnih za arhitekturu u jednoj datoteci. Apple-ova open-source zaglavlja `fat.h` i `loader.h` definišu strukture i konstante opisane na ovoj stranici. <sup>[[5]](#references)</sup>

Mach-O slika se sastoji od:

- Zaglavlja
- Load Commands
- Podataka

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat zaglavlje

Potražite datoteku pomoću: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Zaglavlje sadrži bajtove **magic**, zatim **broj** **arhitektura** koje datoteka **sadrži** (`nfat_arch`), a svaka arhitektura ima `fat_arch` strukturu.

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

Kao što možda pretpostavljate, universal binary kompajliran za 2 arhitekture obično je **dvostruko veći** od onog kompajliranog samo za 1 arhitekturu.

> [!TIP]
> Kada analizirate malware ili sumnjive aplikacije, nemojte stati nakon što `file` prikaže „najbolju” arhitekturu. Universal binary može da krije različite importe, load commands ili metapodatke kompajlera u svakom isečku, zato prvo izlistajte **sve** isečke, a zatim ih zasebno pregledajte:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Noviji macOS SDK-ovi takođe pružaju pomoćne funkcije kao što su `macho_for_each_slice()` i `macho_best_slice()` u `<mach-o/utils.h>`. Ova druga je korisna za simuliranje onoga što bi dyld/kernel učitao, ali skeneri bi i dalje trebalo da iteriraju kroz svaki slice kako ne bi propustili sadržaj specifičan za određenu arhitekturu.<sup>[[1]](#references)</sup>

## **Mach-O zaglavlje**

Zaglavlje sadrži osnovne informacije o datoteci, kao što su magic bajtovi za identifikaciju datoteke kao Mach-O i informacije o ciljnoj arhitekturi. Možete ga pronaći pomoću: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

### Tipovi Mach-O fajlova

Postoje različiti tipovi fajlova; definisani su, na primer, u [**izvornom kodu ovde**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najvažniji su:

- `MH_OBJECT`: Relokativni objektni fajl (međuproizvod kompilacije, još nije izvršni fajl).
- `MH_EXECUTE`: Izvršni fajlovi.
- `MH_FVMLIB`: Fajl biblioteke sa fiksnim VM-om.
- `MH_CORE`: Dumpovi koda.
- `MH_PRELOAD`: Unapred učitani izvršni fajl (više nije podržan u XNU).
- `MH_DYLIB`: Dinamičke biblioteke.
- `MH_DYLINKER`: Dinamički linker.
- `MH_BUNDLE`: „Fajlovi dodataka“. Generišu se pomoću `-bundle` u gcc-u i izričito učitavaju pomoću `NSBundle` ili `dlopen`.
- `MH_DYSM`: Prateći `.dSym` fajl (fajl sa simbolima za otklanjanje grešaka).
- `MH_KEXT_BUNDLE`: Proširenja kernela.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Ili pomoću [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Izvorni kod takođe definiše nekoliko zastavica korisnih za učitavanje biblioteka:

- `MH_NOUNDEFS`: Nema nedefinisanih referenci (potpuno povezan)
- `MH_DYLDLINK`: Dyld povezivanje
- `MH_PREBOUND`: Dinamičke reference su unapred povezane.
- `MH_SPLIT_SEGS`: Fajl deli segmente samo za čitanje i čitanje/pisanje.
- `MH_WEAK_DEFINES`: Binarni fajl ima slabo definisane simbole
- `MH_BINDS_TO_WEAK`: Binarni fajl koristi slabe simbole
- `MH_ALLOW_STACK_EXECUTION`: Omogućava izvršavanje steka
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nema LC_REEXPORT komande
- `MH_PIE`: Pozicijski nezavisan izvršni fajl
- `MH_HAS_TLV_DESCRIPTORS`: Postoji odeljak sa lokalnim promenljivama niti
- `MH_NO_HEAP_EXECUTION`: Nema izvršavanja na stranicama hipa/podataka
- `MH_HAS_OBJC`: Binarni fajl ima Objective-C odeljke
- `MH_SIM_SUPPORT`: Podrška za simulator
- `MH_DYLIB_IN_CACHE`: Koristi se za dylib biblioteke/okvire u kešu deljene biblioteke.

## **Mach-O Load commands**

**Raspored fajla u memoriji** definiše se ovde, uz navođenje **lokacije tabele simbola**, konteksta glavne niti na početku izvršavanja i potrebnih **deljenih biblioteka**. Dinamičkom učitavaču **(dyld)** daju se uputstva o procesu učitavanja binarnog fajla u memoriju.

Koristi se struktura **load_command**, definisana u pomenutom fajlu **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Postoji oko **50 različitih tipova load komandi** koje sistem obrađuje na različite načine. Najčešće su: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> U suštini, ovaj tip load komande definiše **kako se učitavaju segmenti \_\_TEXT** (izvršni kod) **i \_\_DATA** (podaci za proces), **prema offsetima navedenim u odeljku Data**, prilikom izvršavanja binarne datoteke.

Ove komande **definišu segmente** koji se **mapiraju** u **virtuelni memorijski prostor** procesa prilikom njegovog izvršavanja.

Postoje **različiti tipovi** segmenata, kao što je segment **\_\_TEXT**, koji sadrži izvršni kod programa, i segment **\_\_DATA**, koji sadrži podatke koje proces koristi. Ovi **segmenti se nalaze u odeljku data** Mach-O datoteke.

**Svaki segment** se dalje može **podeliti** na više **odeljaka**. **Struktura load komande** sadrži **informacije** o **tim odeljcima** unutar odgovarajućeg segmenta.

U zaglavlju se prvo nalazi **zaglavlje segmenta**:

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

Ovo zaglavlje definiše **broj odeljaka čija se zaglavlja nalaze iza njega**:

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

Ako **pomeraju sekcije** (0x37DC) dodate **pomeraj** na kom **počinje arhitektura**, u ovom slučaju `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Informacije o **zaglavlju** moguće je dobiti i iz **komandne linije** pomoću:

```bash
otool -lv /bin/ls
```

Common segmenti koje učitava ovaj cmd:

- **`__PAGEZERO`:** Daje instrukciju kernelu da **mapira** **nultu adresu** tako da se iz nje **ne može čitati, u nju pisati niti se ona može izvršavati**. Promenljive maxprot i minprot u strukturi postavljene su na nulu kako bi označile da **na ovoj stranici nema prava za čitanje, pisanje ni izvršavanje**.
  - Ova alokacija je važna za **ublažavanje ranjivosti dereferenciranja NULL pokazivača**. XNU nameće tvrdu nultu stranicu koja osigurava da je prva stranica memorije (samo prva) nedostupna (osim u i386). Binarni fajl može ispuniti ovaj zahtev tako što napravi mali \_\_PAGEZERO (koristeći `-pagezero_size`) koji pokriva prvih 4k, a ostatak 32-bitne memorije ostavi dostupnim i u korisničkom i u kernel režimu.
- **`__TEXT`**: Sadrži **izvršni** **kod** sa dozvolama za **čitanje** i **izvršavanje** (bez dozvole za pisanje)**.** Uobičajene sekcije ovog segmenta:
  - `__text`: Kompajlirani binarni kod
  - `__const`: Konstantni podaci (samo za čitanje)
  - `__[c/u/os_log]string`: C, Unicode ili os log string konstante
  - `__stubs` i `__stubs_helper`: Učestvuju u procesu učitavanja dinamičkih biblioteka
  - `__unwind_info`: Podaci za odmotavanje steka.
  - Imajte na umu da je sav ovaj sadržaj potpisan, ali i označen kao izvršni (što stvara više mogućnosti za eksploataciju sekcija kojima ova privilegija nije nužno potrebna, poput sekcija namenjenih samo stringovima).
- **`__DATA`**: Sadrži podatke koji su **čitljivi** i **upisivi** (nisu izvršni)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Pokazivač na simbol koji nije lenj (povezivanje pri učitavanju)
  - `__la_symbol_ptr`: Lenji pokazivač na simbol (povezivanje pri korišćenju)
  - `__const`: Trebalo bi da sadrži podatke samo za čitanje (ali ne nužno)
  - `__cfstring`: CoreFoundation stringovi
  - `__data`: Globalne promenljive (koje su inicijalizovane)
  - `__bss`: Statičke promenljive (koje nisu inicijalizovane)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, itd.): Informacije koje koristi Objective-C runtime
- **`__DATA_CONST`**: Nije garantovano da je \_\_DATA.\_\_const konstantna (dozvole za pisanje), a isto važi i za druge pokazivače i GOT. Ova sekcija koristi `mprotect` da postavi `__const`, neke inicijalizatore i GOT tabelu (nakon razrešavanja) kao **samo za čitanje**.
- **`__AUTH` / `__AUTH_CONST`**: Česti su u novijim binarnim fajlovima za Apple Silicon. Ovi segmenti sadrže pokazivače koje je potrebno autentifikovati pri učitavanju ili korišćenju (na primer `__auth_got`). Ako rebinding, hook ili trik za patchovanje importa proverava samo nasleđene sekcije `__got` / `__la_symbol_ptr`, može propustiti stvarna mesta poziva u modernim binarnim fajlovima `arm64e`. Više detalja o ovim sekcijama potražite na [ovoj stranici](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Sadrži informacije za linker (dyld), kao što su stavke u tabelama simbola, stringova i relokacija. To je generički kontejner za sadržaj koji nije ni u `__TEXT` ni u `__DATA`, a njegov sadržaj opisuju druge load komande.
  - Informacije za dyld: opcodes za rebase, lenjo/nelенjo/slabo povezivanje i informacije o eksportu
  - Početci funkcija: Tabela početnih adresa funkcija
  - Data In Code: Segmenti podataka u \_\_text
  - Tabela simbola: Simboli u binarnom fajlu
  - Tabela indirektnih simbola: Simboli pokazivača/stubova
  - Tabela stringova
  - Potpis koda
- **`__OBJC`**: Sadrži informacije koje koristi Objective-C runtime. Međutim, te informacije mogu se naći i u segmentu \_\_DATA, u raznim sekcijama \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez sadržaja, sa jednom sekcijom pod nazivom **`__restrict`** (takođe praznom), koji osigurava da će binarni fajl pri pokretanju ignorisati DYLD promenljive okruženja.

Kao što se moglo videti u kodu, **segmenti podržavaju i zastavice** (mada se ne koriste često):

- `SG_HIGHVM`: Samo Core (ne koristi se)
- `SG_FVMLIB`: Ne koristi se
- `SG_NORELOC`: Segment nema relokacije
- `SG_PROTECTED_VERSION_1`: Šifrovanje. Finder ga, na primer, koristi za šifrovanje segmenta `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** sadrži ulaznu tačku u atributu **entryoff**. Pri učitavanju, **dyld** jednostavno **dodaje** ovu vrednost (memorijskoj) **osnovnoj adresi binarnog fajla**, a zatim **skače** na ovu instrukciju da bi započeo izvršavanje koda binarnog fajla.

**`LC_UNIXTHREAD`** sadrži vrednosti koje registri moraju imati pri pokretanju glavne niti. Ovo je već zastarelo, ali **`dyld`** ga i dalje koristi. Vrednosti registara postavljene na ovaj način mogu se videti pomoću:

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


Sadrži informacije o **code signature Macho-O datoteke**. Sadrži samo **offset** koji **pokazuje** na **signature blob**. Obično se nalazi sasvim na kraju datoteke.\
Više informacija o ovom odeljku možete pronaći u [**ovom blog postu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i [**ovom gist-u**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Podrška za enkripciju binarnih datoteka. Međutim, naravno, ako napadač uspe da kompromituje proces, moći će da preuzme memoriju bez enkripcije.

### **`LC_LOAD_DYLINKER`**

Sadrži **putanju do izvršne datoteke dinamičkog linkera** koji mapira shared libraries u adresni prostor procesa. **Vrednost je uvek postavljena na `/usr/lib/dyld`**. Važno je napomenuti da se u macOS-u mapiranje dylib datoteka odvija u **user mode**, a ne u kernel mode.

### **`LC_IDENT`**

Zastareo je, ali kada je podešen da generiše dumpove pri panici, kreira se Mach-O core dump, a verzija kernela se postavlja u komandu `LC_IDENT`.

### **`LC_UUID`**

Nasumični UUID. Koristan je za bilo šta direktno, ali XNU ga kešira zajedno sa ostalim informacijama o procesu. Može se koristiti u izveštajima o padu sistema.

### **`LC_BUILD_VERSION`**

Moderne binarne datoteke obično sadrže ovu komandu da bi navele **ciljnu platformu**, **minimalnu verziju OS-a**, **verziju SDK-a** i, opciono, **verzije alata** korišćenih za izgradnju tog slice-a. Iz perspektive offensive/reversing rada, ovo je veoma korisno za utvrđivanje načina na koji je uzorak izgrađen i brzo uočavanje neobičnih universal binaries datoteka kod kojih je jedan slice kompajliran drugim SDK-om ili sa drugačijim deployment target-om. Starije binarne datoteke mogu umesto toga koristiti `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Omogućava navođenje promenljivih okruženja za dyld pre izvršavanja procesa. Ovo može biti veoma opasno jer može omogućiti izvršavanje proizvoljnog koda unutar procesa, pa se ovaj load command koristi samo u dyld verzijama izgrađenim sa `#define SUPPORT_LC_DYLD_ENVIRONMENT`, a obrada je dodatno ograničena samo na promenljive oblika `DYLD_..._PATH` koje navode putanje za učitavanje.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Noviji toolchain-i često čuvaju metapodatke za export/bind/rebase u ovim komandama, umesto da se oslanjaju isključivo na starije `LC_DYLD_INFO[_ONLY]` opcode-ove. Obe su stavke `linkedit_data_command` koje ukazuju na **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktno trie stablo sa simbolima koje image eksportuje.
- **`LC_DYLD_CHAINED_FIXUPS`**: Lanci fixup-ova po segmentima koje dyld koristi za primenu rebases i binds. Na Apple Silicon-u ovde ćete naići i na mnoge savremene fixup-ove za autentifikovane pokazivače.

Ovi metapodaci su veoma korisni pri rekonstrukciji imports/exports, razumevanju zašto je zavisnost učitana preko `@rpath` razrešena na određeni način ili utvrđivanju zašto hook/rebinding pokušaj nije uspeo na modernom `arm64e` cilju. `dyld_info` se može koristiti i nad putanjama do dylib-ova koji postoje samo u cache-u, a ne kao samostalni fajlovi na disku. To je veoma korisno na modernom macOS-u, gde mnoge sistemske biblioteke postoje samo u shared cache-u.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Ova moderna load komanda uglavnom je relevantna pri analizi **kernel kolekcija / datoteka u kernelcache stilu**. Umesto da predstavlja jednu samostalnu sliku, spoljašnji Mach-O služi kao kontejner, a svaki `LC_FILESET_ENTRY` upućuje na ugrađeni Mach-O sa sopstvenim **ID-jem unosa** nalik putanji, VM adresom i pomakom u datoteci. Ako vršite reverzno inženjerstvo modernih macOS/iOS kernel komponenti, ova komanda je često veza između kontejnera najvišeg nivoa i stvarne slike koju želite da izdvojite ili disasemblirate.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Za praktične postupke izdvajanja pogledajte [ovu drugu stranicu o macOS kernel extensions i kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ova naredba za učitavanje opisuje zavisnost od **dinamičke** **biblioteke** i **upućuje** **loader** (dyld) da **učita i poveže navedenu biblioteku**. U Mach-O binarnom fajlu postoji naredba za učitavanje `LC_LOAD_DYLIB` **za svaku biblioteku** koju taj fajl zahteva.

- Ova naredba za učitavanje je struktura tipa **`dylib_command`** (koja sadrži strukturu dylib koja opisuje konkretnu zavisnu dinamičku biblioteku):

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

Ove informacije možete dobiti i pomoću CLI-ja:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Some potencijalno malware biblioteke su:

- **DiskArbitration**: Nadgledanje USB diskova
- **AVFoundation:** Snimanje zvuka i videa
- **CoreWLAN**: Skeniranje Wi-Fi mreža.

> [!TIP]
> Mach-O binarni fajl može da sadrži jedan ili **više** **konstruktora**, koji će biti **izvršeni** **pre** adrese navedene u **LC_MAIN**.\
> Offseti svih konstruktora nalaze se u sekciji **\_\_mod_init_func** segmenta **\_\_DATA_CONST**.

## **Mach-O podaci**

U središtu fajla nalazi se oblast sa podacima, sastavljena od nekoliko segmenata, kako je definisano u oblasti load-commands. **Svaki segment može da sadrži različite sekcije sa podacima**, pri čemu svaka sekcija **sadrži kod ili podatke** specifične za određeni tip.

> [!TIP]
> Podaci su u osnovi deo koji sadrži sve **informacije** koje učitavaju load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Ovo obuhvata:

- **Tabela funkcija:** Sadrži informacije o funkcijama programa.
- **Tabela simbola**: Sadrži informacije o eksternim funkcijama koje binarni fajl koristi.
- Može da sadrži i interne funkcije, nazive promenljivih i još mnogo toga.

Da biste to proverili, možete da koristite alat [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ili iz CLI-ja:

```bash
size -m /bin/ls
```

### Dodati podaci i obrnuto parsirani preklopi

Loader može da čuva konfiguraciju u dodacima podataka, umesto u imenovanoj Mach-O sekciji. Obrnuti parser se zatim oslanja na oznaku na kraju, čita veličinu sačuvanu neposredno ispred nje i koristi tu vrednost da pronađe i dešifruje prethodni blob. Jedan uočeni universal loader koristio je ovaj raspored za XOR-šifrovani URL downloader-a:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Pri reverziranju nepoznatog binarnog fajla, pregledajte bajtove oko prepoznatljivih završnih markera i ispratite svaki proračun veličine unazad pre nego što pretpostavite da stringovi ili konfiguracija moraju pripadati sekciji load-command. Marker i XOR ključ specifični su za uzorak; tehnika koja se može ponovo upotrebiti jeste samop opisni završni zapis (trailer).

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

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O sliceovi nisu baš tako jednostavni kao što možda mislite](https://objective-see.org/blog/blog_0x80.html)
- [2] [man stranica za dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Čitanje sopstvenih entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` i `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Nova verzija MacSync macOS kradljivca cilja entuzijaste kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
