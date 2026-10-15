# macOS univerzalni binarni fajlovi i Mach-O format

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

macOS koristi izvršni format **Mach-O**. **Univerzalni**, odnosno fat, binarni fajl sadrži više Mach-O isečaka specifičnih za arhitekturu u jednoj datoteci. Apple-ova open-source zaglavlja `fat.h` i `loader.h` definišu strukture i konstante opisane na ovoj stranici. <sup>[[5]](#references)</sup>

Mach-O slika se sastoji od:

- Zaglavlja
- Komandi za učitavanje
- Podataka

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat zaglavlje

Pronađite datoteku pomoću: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Zaglavlje sadrži bajtove **magic**, zatim **broj** **arhitektura** koje datoteka **sadrži** (`nfat_arch`), a svaka arhitektura ima strukturu `fat_arch`.

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

Kao što možda pretpostavljate, univerzalni binarni fajl kompajliran za 2 arhitekture obično je **dvostruko veći** od onog kompajliranog samo za 1 arhitekturu.

> [!TIP]
> Kada analizirate malware ili sumnjive aplikacije, nemojte stati nakon što `file` prijavi „najbolju“ arhitekturu. Univerzalni binarni fajl može da sakrije različite imports, load commands ili compiler metadata u svakom isečku, zato prvo navedite **sve** isečke, pa ih zatim analizirajte pojedinačno:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Noviji macOS SDK-ovi takođe izlažu pomoćne funkcije kao što su `macho_for_each_slice()` i `macho_best_slice()` u `<mach-o/utils.h>`. Potonja je korisna za oponašanje onoga što bi učitali dyld/kernel, ali skeneri bi ipak trebalo da iteriraju kroz svaki slice kako ne bi propustili sadržaj specifičan za određenu arhitekturu.<sup>[[1]](#references)</sup>

## **Mach-O zaglavlje**

Zaglavlje sadrži osnovne informacije o fajlu, kao što su magični bajtovi za prepoznavanje da je u pitanju Mach-O fajl i informacije o ciljnoj arhitekturi. Možete ga pronaći pomoću: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Postoje različiti tipovi datoteka; možete ih pronaći definisane u [**izvornom kodu, na primer ovde**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najvažniji su:

- `MH_OBJECT`: Relokabilna objektna datoteka (međuproizvod kompilacije, još uvek nije izvršna datoteka).
- `MH_EXECUTE`: Izvršne datoteke.
- `MH_FVMLIB`: Datoteka biblioteke fiksne VM memorije.
- `MH_CORE`: Dumpovi koda
- `MH_PRELOAD`: Unapred učitana izvršna datoteka (više nije podržana u XNU)
- `MH_DYLIB`: Dinamičke biblioteke
- `MH_DYLINKER`: Dinamički linker
- `MH_BUNDLE`: „Datoteke dodataka“. Generišu se pomoću `-bundle` u gcc-u i eksplicitno učitavaju pomoću `NSBundle` ili `dlopen`.
- `MH_DYSM`: Prateća `.dSym` datoteka (datoteka sa simbolima za debagovanje).
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

- `MH_NOUNDEFS`: Nema nedefinisanih referenci (potpuno povezano)
- `MH_DYLDLINK`: Dyld povezivanje
- `MH_PREBOUND`: Dinamičke reference su unapred povezane.
- `MH_SPLIT_SEGS`: Datoteka deli segmente samo za čitanje i za čitanje i pisanje.
- `MH_WEAK_DEFINES`: Binarna datoteka ima slabe definisane simbole
- `MH_BINDS_TO_WEAK`: Binarna datoteka koristi slabe simbole
- `MH_ALLOW_STACK_EXECUTION`: Omogućava izvršavanje steka
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nema LC_REEXPORT komande
- `MH_PIE`: Pozicijski nezavisna izvršna datoteka
- `MH_HAS_TLV_DESCRIPTORS`: Postoji odeljak sa lokalnim promenljivama niti
- `MH_NO_HEAP_EXECUTION`: Nema izvršavanja na stranicama hipa/podataka
- `MH_HAS_OBJC`: Binarna datoteka ima Objective-C odeljke
- `MH_SIM_SUPPORT`: Podrška za simulator
- `MH_DYLIB_IN_CACHE`: Koristi se za dylib/framework datoteke u kešu deljenih biblioteka.

## **Mach-O Load commands**

**Raspored datoteke u memoriji** naveden je ovde, uz detalje o **lokaciji tabele simbola**, kontekstu glavne niti na početku izvršavanja i potrebnim **deljenim bibliotekama**. Dinamičkom učitavaču **(dyld)** daju se uputstva o procesu učitavanja binarne datoteke u memoriju.

Koristi se struktura **load_command**, definisana u pomenutoj datoteci **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Postoji oko **50 različitih tipova load komandi** koje sistem obrađuje na različite načine. Najčešće su: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> U suštini, ovaj tip Load Command definiše **kako da se učitaju segmenti \_\_TEXT** (izvršni kod) **i \_\_DATA** (podaci za proces), u skladu sa **offsetima navedenim u odeljku Data** prilikom izvršavanja binarne datoteke.

Ove komande **definišu segmente** koji se **mapiraju** u **prostor virtuelne memorije** procesa prilikom njegovog izvršavanja.

Postoje **različiti tipovi** segmenata, kao što je segment **\_\_TEXT**, koji sadrži izvršni kod programa, i segment **\_\_DATA**, koji sadrži podatke koje koristi proces. Ovi **segmenti se nalaze u odeljku data** Mach-O datoteke.

**Svaki segment** može se dalje **podeliti** na više **odeljaka**. **Struktura load komande** sadrži **informacije** o **ovim odeljcima** u okviru odgovarajućeg segmenta.

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

Primer **zaglavlja odeljka**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Ako **saberete** **pomeraj odeljka** (0x37DC) i **pomeraj** na kom počinje **arhitektura**, u ovom slučaju `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Takođe je moguće dobiti informacije o **zaglavlju** iz **komandne linije** pomoću:

```bash
otool -lv /bin/ls
```

Common segmenti koje učitava ova komanda:

- **`__PAGEZERO`:** Upućuje kernel da **mapira** **nultu adresu** tako da se sa nje **ne može čitati, u nju pisati niti se sa nje može izvršavati kod**. Promenljive maxprot i minprot u strukturi postavljene su na nulu, što označava da **na ovoj stranici nema prava za čitanje, pisanje ni izvršavanje**.
  - Ova alokacija je važna za **ublažavanje ranjivosti NULL pointer dereference**. Razlog je to što XNU nameće zaštićenu nultu stranicu, čime obezbeđuje da prva stranica memorije (i samo prva) bude nedostupna (osim na i386). Binarna datoteka može da ispuni ovaj zahtev tako što će napraviti malu oblast \_\_PAGEZERO (pomoću `-pagezero_size`) koja pokriva prvih 4k, a ostatak 32-bitne memorije ostaviti dostupnim i u korisničkom i u kernel režimu.
- **`__TEXT`**: Sadrži **izvršivi** **kod** sa dozvolama za **čitanje** i **izvršavanje** (bez dozvole za pisanje)**.** Uobičajeni odeljci ovog segmenta:
  - `__text`: Kompajlirani binarni kod
  - `__const`: Konstantni podaci (samo za čitanje)
  - `__[c/u/os_log]string`: String konstante u C-u, Unicode formatu ili os logovima
  - `__stubs` i `__stubs_helper`: Učestvuju u procesu učitavanja dinamičkih biblioteka
  - `__unwind_info`: Podaci za razmotavanje steka.
  - Imajte na umu da je sav ovaj sadržaj potpisan, ali i označen kao izvršiv (što stvara dodatne mogućnosti za eksploataciju odeljaka kojima ova privilegija nije nužno potrebna, kao što su odeljci namenjeni stringovima).
- **`__DATA`**: Sadrži podatke koji su **čitljivi** i **zapisivi** (nisu izvršivi)**.**
  - `__got:` Globalna tabela pomeraja
  - `__nl_symbol_ptr`: Pokazivač na simbol koji nije lenjo vezan (vezuje se pri učitavanju)
  - `__la_symbol_ptr`: Lenjo vezan pokazivač na simbol (vezuje se pri upotrebi)
  - `__const`: Trebalo bi da sadrži podatke samo za čitanje (ali zapravo ne)
  - `__cfstring`: CoreFoundation stringovi
  - `__data`: Globalne promenljive (koje su inicijalizovane)
  - `__bss`: Statičke promenljive (koje nisu inicijalizovane)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist itd.): Informacije koje koristi Objective-C runtime
- **`__DATA_CONST`**: Za \_\_DATA.\_\_const nije garantovano da je konstantan (dozvole za pisanje), kao ni za druge pokazivače i GOT. Ovaj odeljak pomoću `mprotect` postavlja `__const`, neke inicijalizatore i GOT tabelu (nakon razrešavanja) kao **samo za čitanje**.
- **`__AUTH` / `__AUTH_CONST`**: Uobičajeni su u novijim binarnim datotekama za Apple Silicon. Ovi segmenti sadrže pokazivače koji moraju da budu autentifikovani pri učitavanju ili upotrebi (na primer `__auth_got`). Ako trik za rebinding, hook ili patchovanje importa proverava samo zastarele odeljke `__got` / `__la_symbol_ptr`, može da propusti stvarna mesta poziva u savremenim `arm64e` binarnim datotekama. Više informacija o ovim odeljcima potražite na [ovoj stranici](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Sadrži informacije za linker (dyld), kao što su unosi u tabelama simbola, stringova i relokacija. To je generički kontejner za sadržaj koji nije u `__TEXT` ni u `__DATA`, a njegov sadržaj opisuju druge load komande.
  - Informacije za dyld: opcodes za rebase, lenjo/ne-lenjo/slabo vezivanje i informacije o izvozu
  - Počeci funkcija: Tabela početnih adresa funkcija
  - Podaci u kodu: Podaci umetnuti u \_\_text
  - Tabela simbola: Simboli u binarnoj datoteci
  - Tabela indirektnih simbola: Simboli pokazivača/stubova
  - Tabela stringova
  - Potpis koda
- **`__OBJC`**: Sadrži informacije koje koristi Objective-C runtime. Međutim, ove informacije mogu se naći i u segmentu \_\_DATA, u raznim odeljcima \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez sadržaja, sa jednim odeljkom pod nazivom **`__restrict`** (takođe praznim), koji obezbeđuje da binarna datoteka pri pokretanju ignoriše DYLD promenljive okruženja.

Kao što se moglo videti u kodu, **segmenti podržavaju i zastavice** (mada se ne koriste mnogo):

- `SG_HIGHVM`: Samo za core (ne koristi se)
- `SG_FVMLIB`: Ne koristi se
- `SG_NORELOC`: Segment nema relokacije
- `SG_PROTECTED_VERSION_1`: Šifrovanje. Na primer, Finder ga koristi za šifrovanje segmenta `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** sadrži ulaznu tačku u atributu **entryoff**. Pri učitavanju, **dyld** jednostavno **dodaje** ovu vrednost (u memoriji) **osnovnoj adresi binarne datoteke**, a zatim **skače** na ovu instrukciju da bi započeo izvršavanje koda binarne datoteke.

**`LC_UNIXTHREAD`** sadrži vrednosti koje registri moraju da imaju pri pokretanju glavne niti. Ovo je već zastarelo, ali **`dyld`** ga i dalje koristi. Vrednosti koje su ovim postupkom postavljene u registre mogu se videti pomoću:

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


Sadrži informacije o **code signature-u Macho-O datoteke**. Sadrži samo **offset** koji **pokazuje** na **signature blob**. Obično se nalazi na samom kraju datoteke.\
Više informacija o ovom odeljku možete pronaći u [**ovom blog postu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i [**ovom gist-u**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Podrška za šifrovanje binarnih datoteka. Međutim, naravno, ako napadač uspe da kompromituje proces, moći će da izdumpuje memoriju u nešifrovanom obliku.

### **`LC_LOAD_DYLINKER`**

Sadrži **putanju do izvršne datoteke dynamic linker-a** koja mapira shared libraries u adresni prostor procesa. **Vrednost je uvek postavljena na `/usr/lib/dyld`**. Važno je napomenuti da se u macOS-u mapiranje dylib-a odvija u **user mode-u**, a ne u kernel mode-u.

### **`LC_IDENT`**

Zastareo je, ali kada je podešen da generiše dump-ove pri panic-u, kreira se Mach-O core dump, a verzija kernela se postavlja u komandu `LC_IDENT`.

### **`LC_UUID`**

Nasumični UUID. Sam po sebi nije naročito koristan, ali ga XNU kešira zajedno sa ostalim informacijama o procesu. Može se koristiti u crash report-ovima.

### **`LC_BUILD_VERSION`**

Savremeni binarni fajlovi obično sadrže ovu komandu za navođenje **ciljne platforme**, **minimalne verzije OS-a**, **SDK verzije** i, po želji, **verzija alata** korišćenih za izgradnju tog slice-a. Iz ugla ofanzivne analize i reverse engineering-a, ovo je veoma korisno za utvrđivanje načina na koji je uzorak napravljen i za brzo uočavanje neobičnih universal binaries fajlova kod kojih je jedan slice kompajliran sa drugim SDK-om ili deployment target-om. Stariji binarni fajlovi možda i dalje koriste `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Omogućava navođenje promenljivih okruženja za dyld pre izvršavanja procesa. Ovo može biti veoma opasno jer može omogućiti izvršavanje proizvoljnog koda unutar procesa, pa se ova load komanda koristi samo u dyld buildovima sa `#define SUPPORT_LC_DYLD_ENVIRONMENT`, a obrada se dodatno ograničava samo na promenljive oblika `DYLD_..._PATH` koje navode putanje za učitavanje.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Noviji toolchain-ovi često čuvaju metapodatke o izvozu, povezivanju i relokaciji u ovim komandama, umesto da se oslanjaju isključivo na starije `LC_DYLD_INFO[_ONLY]` opcode-ove. Obe su stavke `linkedit_data_command` koje upućuju na **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktno trie stablo sa simbolima koje image izvozi.
- **`LC_DYLD_CHAINED_FIXUPS`**: Lanci fixup-ova po segmentima koje dyld koristi za primenu relokacija i povezivanja. Na Apple Silicon-u ovde ćete naići i na mnoge savremene fixup-ove autentifikovanih pokazivača.

Ovi metapodaci su veoma korisni pri rekonstrukciji importa/eksporta, razumevanju zašto je zavisnost učitana preko `@rpath` razrešena na određeni način ili utvrđivanju zašto pokušaj hook-ovanja/rebinding-a nije uspeo na savremenom `arm64e` cilju. `dyld_info` se može koristiti i nad putanjama dylib-ova koji postoje samo u cache-u i ne postoje kao samostalne datoteke na disku. Ovo je veoma korisno na savremenom macOS-u, gde mnoge sistemske biblioteke postoje samo u shared cache-у.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Ova moderna load komanda uglavnom je relevantna prilikom analize **kernel collections / kernelcache-style filesets**. Umesto da predstavlja jednu samostalnu sliku, spoljašnji Mach-O služi kao kontejner, a svaki `LC_FILESET_ENTRY` upućuje na ugrađeni Mach-O sa sopstvenim identifikatorom nalik putanji (**entry id**), VM adresom i pomakom u datoteci. Ako vršite reverzni inženjering modernih macOS/iOS kernel komponenti, ova komanda je često veza između kontejnera najvišeg nivoa i stvarne slike koju želite da izdvojite ili disasemblirate.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Za praktične tokove rada za izdvajanje, pogledajte [ovu drugu stranicu o macOS kernel extensions i kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ova komanda za učitavanje opisuje zavisnost od **dinamičke** **biblioteke** i **nalaže** **učitavaču** (dyld) da **učita i poveže tu biblioteku**. U Mach-O binarnoj datoteci postoji po jedna komanda za učitavanje `LC_LOAD_DYLIB` **za svaku biblioteku** koju ta datoteka zahteva.

- Ova komanda za učitavanje je struktura tipa **`dylib_command`** (koja sadrži strukturu dylib koja opisuje konkretnu zavisnu dinamičku biblioteku):

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

Neke potencijalno zlonamerne biblioteke su:

- **DiskArbitration**: Nadgledanje USB diskova
- **AVFoundation:** Snimanje zvuka i videa
- **CoreWLAN**: Wi-Fi skeniranja.

> [!TIP]
> Mach-O binarna datoteka može da sadrži jedan ili **više** **konstruktora**, koji će biti **izvršeni** **pre** adrese navedene u **LC_MAIN**.\
> Pomaci svih konstruktora nalaze se u odeljku **\_\_mod_init_func** segmenta **\_\_DATA_CONST**.

## **Mach-O podaci**

U središtu datoteke nalazi se oblast sa podacima, koja se sastoji od nekoliko segmenata definisanih u oblasti load komandi. **Svaki segment može da sadrži različite odeljke sa podacima**, a svaki odeljak **sadrži kod ili podatke** specifične za određeni tip.

> [!TIP]
> Podaci su u suštini deo koji sadrži sve **informacije** koje učitavaju load komande **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

To obuhvata:

- **Tabela funkcija:** Sadrži informacije o funkcijama programa.
- **Tabela simbola**: Sadrži informacije o spoljnim funkcijama koje binarna datoteka koristi.
- Može da sadrži i nazive internih funkcija i promenljivih, kao i još toga.

Da biste to proverili, možete da koristite alat [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ili iz CLI-ja:

```bash
size -m /bin/ls
```

### Dodati podaci i overlay-ji parsirani unazad

Loader može da čuva konfiguraciju u dodatim podacima umesto u imenovanoj Mach-O sekciji. Parser koji parsira unazad zatim se oslanja na oznaku na kraju, čita veličinu zapisanu neposredno pre nje i koristi tu vrednost da pronađe i dešifruje prethodni blob. Jedan uočeni universal loader koristio je ovaj raspored za XOR-šifrovani URL downloader-a:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Pri reverziranju nepoznatog binarnog fajla pregledajte bajtove oko prepoznatljivih završnih markera i pratite svaki proračun veličine unazad pre nego što pretpostavite da stringovi ili konfiguracija moraju pripadati odeljku load-command. Marker i XOR ključ specifični su za uzorak; ponovo upotrebljiva tehnika jeste samop opisni trailer.

## Uobičajeni Objective-C odeljci

U segmentu `__TEXT` (r-x):

- `__objc_classname`: Imena klasa (stringovi)
- `__objc_methname`: Imena metoda (stringovi)
- `__objc_methtype`: Tipovi metoda (stringovi)

U segmentu `__DATA` (rw-):

- `__objc_classlist`: Pokazivači na sve Objective-C klase
- `__objc_nlclslist`: Pokazivači na Non-Lazy Objective-C klase
- `__objc_catlist`: Pokazivači na kategorije
- `__objc_nlcatlist`: Pokazivači na Non-Lazy kategorije
- `__objc_protolist`: Lista protokola
- `__objc_const`: Konstantni podaci
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Pogledajte i: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O slice-ovi nisu baš toliko jednostavni kao što možda mislite](https://objective-see.org/blog/blog_0x80.html)
- [2] [Priručnik za dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Čitanje sopstvenih entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` i `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Nova verzija MacSync macOS kradljivca cilja entuzijaste kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
