# macOS Universal binarni fajlovi i Mach-O format

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

macOS koristi izvršni format **Mach-O**. **Universal**, odnosno fat, binarni fajl sadrži više Mach-O isečaka specifičnih za arhitekturu u jednoj datoteci. Apple-ova open-source zaglavlja `fat.h` i `loader.h` definišu strukture i konstante opisane na ovoj stranici. <sup>[[5]](#references)</sup>

Mach-O slika sastoji se od:

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

Kao što verovatno pretpostavljate, universal binarni fajl kompajliran za 2 arhitekture obično je **dvostruko veći** od fajla kompajliranog za samo 1 arhitekturu.

> [!TIP]
> Kada analizirate malware ili sumnjive aplikacije, nemojte stati nakon što `file` prikaže „najbolju” arhitekturu. Universal binarni fajl može da sadrži različite importe, load commands ili metapodatke kompajlera u svakom isečku, zato prvo izlistajte **sve** isečke, a zatim ih pregledajte zasebno:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Noviji macOS SDK-ovi takođe izlažu `macho_for_each_slice()` i `macho_best_slice()` u `<mach-o/utils.h>`. Na Apple Silicon-u, `macho_best_slice()` je pre macOS 15 mogao pogrešno da vrati `EBADARCH` za izvršiv binarni fajl treće strane `arm64`; API je ispravljen u macOS 15. Koristite `macho_for_each_slice()` ili `lipo -archs` da biste popisali svaki slice, umesto da neuspešan izbor najboljeg slice-a smatrate dokazom da nijedan slice ne može da se izvrši.<sup>[[1]](#references)[[7]](#references)</sup>

### Uporedite code signature potpise među slice-ovima

Svaka arhitektura u universal binary-ju ima sopstveni CodeDirectory i CDHash. Prilikom provere potpisanog izvršnog fajla ili privilegovanog pomoćnog programa, pregledajte **potpis svakog slice-a**. Različit CDHash je uobičajen; umesto toga uporedite potpisni identitet, oznake CodeDirectory-ja i entitlements.<sup>[[8]](#references)</sup>

Za pravila koja se podudaraju sa CDHash-om, jedan hash identifikuje samo jedan put izvršavanja specifičan za arhitekturu. Apple preporučuje popisivanje slice-ova i korišćenje `codesign --arch` za pregled svakog od njih.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

Za strukturu potpisa i detalje validacije pogledajte [macOS Code Signing](../macos-security-protections/macos-code-signing.md).

## **Mach-O zaglavlje**

Zaglavlje sadrži osnovne informacije o datoteci, kao što su magic bytes za prepoznavanje datoteke kao Mach-O i informacije o ciljnoj arhitekturi. Možete ga pronaći u: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Postoje različiti tipovi datoteka; možete ih pronaći definisane u [**izvornom kodu, na primer ovde**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najvažniji su:

- `MH_OBJECT`: Relokabilna objektna datoteka (međuproizvod kompilacije, još uvek nije izvršna datoteka).
- `MH_EXECUTE`: Izvršne datoteke.
- `MH_FVMLIB`: Datoteka fiksne VM biblioteke.
- `MH_CORE`: Ispisi memorije.
- `MH_PRELOAD`: Unapred učitana izvršna datoteka (više nije podržana u XNU).
- `MH_DYLIB`: Dinamičke biblioteke.
- `MH_DYLINKER`: Dinamički linker.
- `MH_BUNDLE`: „Plugin datoteke“. Generišu se pomoću -bundle u gcc-u i eksplicitno učitavaju pomoću `NSBundle` ili `dlopen`.
- `MH_DSYM`: Prateća `.dSYM` datoteka (datoteka sa simbolima za otklanjanje grešaka).
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

## **Mach-O zastavice**

Izvorni kod takođe definiše nekoliko zastavica korisnih za učitavanje biblioteka:

- `MH_NOUNDEFS`: Nema nedefinisanih referenci (potpuno povezano)
- `MH_DYLDLINK`: Povezivanje pomoću Dyld-a
- `MH_PREBOUND`: Dinamičke reference su unapred povezane.
- `MH_SPLIT_SEGS`: Datoteka razdvaja segmente samo za čitanje i za čitanje i pisanje.
- `MH_WEAK_DEFINES`: Binarna datoteka ima slabe definisane simbole
- `MH_BINDS_TO_WEAK`: Binarna datoteka koristi slabe simbole
- `MH_ALLOW_STACK_EXECUTION`: Omogućava izvršavanje steka
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nema LC_REEXPORT komande
- `MH_PIE`: Izvršna datoteka nezavisna od pozicije
- `MH_HAS_TLV_DESCRIPTORS`: Postoji odeljak sa lokalnim promenljivama niti
- `MH_NO_HEAP_EXECUTION`: Nema izvršavanja stranica hipa/podataka
- `MH_HAS_OBJC`: Binarna datoteka ima Objective-C odeljke
- `MH_SIM_SUPPORT`: Podrška za simulator
- `MH_DYLIB_IN_CACHE`: Koristi se za dylib biblioteke/okvire u kešu deljenih biblioteka.

## **Mach-O komande za učitavanje**

**Raspored datoteke u memoriji** naveden je ovde, sa detaljima o **lokaciji tabele simbola**, kontekstu glavne niti na početku izvršavanja i potrebnim **deljenim bibliotekama**. Dinamičkom učitavaču **(dyld)** daju se uputstva za učitavanje binarne datoteke u memoriju.

Koristi strukturu **load_command**, definisanu u pomenutom fajlu **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Postoji oko **50 različitih tipova naredbi za učitavanje** koje sistem obrađuje na različite načine. Najčešće su: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> U suštini, ovaj tip naredbe za učitavanje definiše **kako učitati segmente \_\_TEXT** (izvršni kod) **i \_\_DATA** (podaci za proces) **u skladu sa pomerajima navedenim u odeljku Data** prilikom izvršavanja binarne datoteke.

Ove naredbe **definišu segmente** koji se **mapiraju** u **prostor virtuelne memorije** procesa prilikom njegovog izvršavanja.

Postoje **različiti tipovi** segmenata, kao što je segment **\_\_TEXT**, koji sadrži izvršni kod programa, i segment **\_\_DATA**, koji sadrži podatke koje koristi proces. Ovi **segmenti se nalaze u odeljku podataka** Mach-O datoteke.

Svaki **segment** se može dalje **podeliti** na više **odeljaka**. **Struktura naredbe za učitavanje** sadrži **informacije** o **tim odeljcima** unutar odgovarajućeg segmenta.

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

Ako **dodate** **offset sekcije** (0x37DC) na **offset** na kom **počinje arhitektura**, u ovom slučaju `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Informacije o **zaglavlju** možete da dobijete i iz **komandne linije** pomoću:

```bash
otool -lv /bin/ls
```

Common segmenti koje učitava ova komanda:

- **`__PAGEZERO`:** Daje kernelu instrukciju da **mapira** **nultu adresu** tako da se iz nje **ne može čitati, u nju pisati niti se sa nje može izvršavati kod**. Promenljive maxprot i minprot u strukturi postavljene su na nulu, što znači da na ovoj stranici **nema dozvola za čitanje, pisanje ni izvršavanje**.
  - Ova alokacija je važna za **ublažavanje ranjivosti dereferenciranja NULL pokazivača**. To je zato što XNU nameće strogo zaštićenu nultu stranicu, čime se obezbeđuje da prva stranica memorije (i samo prva) bude nedostupna (osim na i386). Binarni fajl mogao bi da ispuni ovaj zahtev tako što bi napravio mali \_\_PAGEZERO (pomoću opcije `-pagezero_size`) koji pokriva prvih 4k, dok bi ostatak 32-bitne memorije bio dostupan i u korisničkom i u kernel režimu.
- **`__TEXT`**: Sadrži **izvršivi** **kod** sa dozvolama za **čitanje** i **izvršavanje** (bez dozvole za pisanje)**.** Uobičajeni odeljci ovog segmenta:
  - `__text`: Kompajlirani binarni kod
  - `__const`: Konstantni podaci (samo za čitanje)
  - `__[c/u/os_log]string`: C, Unicode ili os log string konstante
  - `__stubs` and `__stubs_helper`: Koriste se tokom procesa učitavanja dinamičkih biblioteka
  - `__unwind_info`: Podaci za odmotavanje steka.
  - Imajte na umu da je sav ovaj sadržaj potpisan, ali je takođe označen kao izvršiv (što pruža više mogućnosti za eksploataciju odeljaka kojima ova privilegija nije nužno potrebna, poput odeljaka namenjenih stringovima).
- **`__DATA`**: Sadrži podatke koji se mogu **čitati** i **menjati** (nisu izvršivi)**.**
  - `__got:` Globalna tabela pomeraja
  - `__nl_symbol_ptr`: Pokazivač na simbol koji nije lenjo povezan (povezuje se pri učitavanju)
  - `__la_symbol_ptr`: Pokazivač na simbol koji se lenjo povezuje (povezuje se pri upotrebi)
  - `__const`: Trebalo bi da sadrži podatke samo za čitanje (ali zapravo nije tako)
  - `__cfstring`: CoreFoundation stringovi
  - `__data`: Globalne promenljive (koje su inicijalizovane)
  - `__bss`: Statičke promenljive (koje nisu inicijalizovane)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, itd.): Informacije koje koristi Objective-C runtime
- **`__DATA_CONST`**: Za \_\_DATA.\_\_const nije garantovano da je konstantan (ima dozvole za pisanje), a isto važi i za druge pokazivače i GOT. Ovaj odeljak pomoću `mprotect` postavlja `__const`, neke inicijalizatore i GOT tabelu (kada se razreše) na **samo za čitanje**.
- **`__AUTH` / `__AUTH_CONST`**: Česti su u novijim binarnim fajlovima za Apple Silicon. Ovi segmenti sadrže pokazivače koji moraju biti autentifikovani pri učitavanju ili upotrebi (na primer, `__auth_got`). Ako trik za rebinding, hook ili izmenu importovanih simbola proverava samo zastarele odeljke `__got` / `__la_symbol_ptr`, može da propusti stvarne pozive u modernim binarnim fajlovima `arm64e`. Više detalja o ovim odeljcima potražite na [ovoj stranici](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Sadrži informacije za linker (dyld), kao što su stavke u tabelama simbola, stringova i relokacija. To je generički kontejner za sadržaj koji nije ni u `__TEXT` ni u `__DATA`, a njegov sadržaj je opisan u drugim load command-ovima.
  - Informacije za dyld: opcodes za rebase, non-lazy/lazy/weak binding i informacije o export-ima
  - Početne adrese funkcija: Tabela početnih adresa funkcija
  - Podaci u kodu: Odeljci sa podacima unutar \_\_text
  - Tabela simbola: Simboli u binarnom fajlu
  - Tabela indirektnih simbola: Simboli pokazivača/stub-a
  - Tabela stringova
  - Potpis koda
- **`__OBJC`**: Sadrži informacije koje koristi Objective-C runtime. Međutim, ove informacije mogu se naći i u segmentu \_\_DATA, unutar različitih odeljaka \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez sadržaja, sa jednim odeljkom pod nazivom **`__restrict`** (takođe praznim), koji obezbeđuje da se pri pokretanju binarnog fajla ignorišu DYLD promenljive okruženja.

Kao što se moglo videti u kodu, **segmenti podržavaju i zastavice** (mada se ne koriste često):

- `SG_HIGHVM`: Samo za jezgro (ne koristi se)
- `SG_FVMLIB`: Ne koristi se
- `SG_NORELOC`: Segment nema relokacije
- `SG_PROTECTED_VERSION_1`: Šifrovanje. Na primer, Finder ga koristi za šifrovanje tekstualnog segmenta `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** sadrži ulaznu tačku u atributu **entryoff.** Prilikom učitavanja, **dyld** jednostavno **dodaje** ovu vrednost osnovnoj adresi binarnog fajla (u memoriji), a zatim **skače** na ovu instrukciju da bi započeo izvršavanje koda binarnog fajla.

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


Sadrži informacije o **code signature Macho-O datoteke**. Sadrži samo **offset** koji **pokazuje** na **signature blob**. On se obično nalazi na samom kraju datoteke.\
Više informacija o ovom odeljku možete pronaći u [**ovom blog postu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i [**ovom gistu**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Podrška za binary encryption. Međutim, naravno, ako napadač uspe da kompromituje proces, moći će da dump-uje memoriju u dekriptovanom obliku.

### **`LC_LOAD_DYLINKER`**

Sadrži **putanju do izvršne datoteke dynamic linker-a** koja mapira shared libraries u adresni prostor procesa. **Vrednost je uvek postavljena na `/usr/lib/dyld`**. Važno je napomenuti da se u macOS-u mapiranje dylib-ova odvija u **user mode-u**, a ne u kernel mode-u.

### **`LC_IDENT`**

Zastareo je, ali kada je podešen da generiše dump-ove pri panic-u, kreira se Mach-O core dump i verzija kernela se postavlja u komandu `LC_IDENT`.

### **`LC_UUID`**

Nasumični UUID. Koristan je za bilo šta direktno, ali ga XNU kešira zajedno sa ostatkom informacija o procesu. Može se koristiti u crash report-ovima.

### **`LC_BUILD_VERSION`**

Moderni binary-ji obično sadrže ovu komandu za deklarisanje **ciljne platforme**, **minimalne verzije OS-a**, **verzije SDK-a** i, opciono, **verzija alata** korišćenih za izgradnju tog slice-a. Iz ofanzivnog/reversing ugla, ovo je veoma korisno za utvrđivanje kako je uzorak izgrađen i za brzo uočavanje neobičnih universal binary-ja kod kojih je jedan slice kompajliran uz drugačiji SDK ili deployment target. Stariji binary-ji umesto toga mogu i dalje koristiti `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Omogućava navođenje promenljivih okruženja za dyld pre izvršavanja procesa. Ovo može biti veoma opasno jer može omogućiti izvršavanje proizvoljnog koda unutar procesa, pa se ova load komanda koristi samo u dyld build-u sa `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatno ograničava obradu na promenljive oblika `DYLD_..._PATH` koje navode putanje za učitavanje.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Noviji toolchain-ovi često čuvaju metapodatke o export/bind/rebase operacijama u ovim komandama umesto da se oslanjaju isključivo na starije `LC_DYLD_INFO[_ONLY]` opcodes. Obe su stavke tipa `linkedit_data_command` koje upućuju na **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktno trie stablo sa simbolima koje image exportuje.
- **`LC_DYLD_CHAINED_FIXUPS`**: Lanci fixup-a za svaki segment koje dyld koristi za primenu rebases i binds. Na Apple Silicon-u ćete ovde naići i na mnoge moderne authenticated pointer fixups.

Ovi metapodaci su veoma korisni za rekonstrukciju import-a/export-a, razumevanje zašto je zavisnost učitana putem `@rpath` razrešena na određeni način ili utvrđivanje zašto hook/rebinding pokušaj nije uspeo na modernom `arm64e` target-u. `dyld_info` se može koristiti i nad **cache-only dylib putanjama** koje ne postoje kao samostalne datoteke na disku, što je veoma korisno na modernom macOS-u gde mnoge sistemske biblioteke postoje samo u shared cache-u.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Ova moderna load komanda je uglavnom relevantna pri pregledu **kernel kolekcija / fileset datoteka u stilu kernelcache-a**. Umesto da predstavlja jednu samostalnu sliku, spoljašnji Mach-O služi kao kontejner, a svaki `LC_FILESET_ENTRY` pokazuje na ugrađeni Mach-O sa sopstvenim identifikatorom unosa nalik putanji, VM adresom i pomakom u datoteci. Ako vršite reverzni inženjering modernih komponenti macOS/iOS kernela, ova komanda je često veza između kontejnera najvišeg nivoa i stvarne slike koju želite da izdvojite ili disasemblirate.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Za praktične tokove rada pri izdvajanju, pogledajte [ovu drugu stranicu o macOS kernel extensions i kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ova load komanda opisuje zavisnost od **dinamičke** **biblioteke** koja **nalaže** **loader-u** (dyld) da **učita i poveže navedenu biblioteku**. Postoji load komanda `LC_LOAD_DYLIB` **za svaku biblioteku** koju Mach-O binarna datoteka zahteva.

- Ova load komanda je struktura tipa **`dylib_command`** (koja sadrži strukturu dylib koja opisuje konkretnu zavisnu dinamičku biblioteku):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t kompatibilna verzija; / broj kompatibilne verzije biblioteke /](<../../../images/image (486).png>)

Ove informacije možete dobiti i pomoću CLI-ja:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Neke potencijalno povezane sa malware-om biblioteke su:

- **DiskArbitration**: Nadgledanje USB diskova
- **AVFoundation:** Snimanje zvuka i videa
- **CoreWLAN**: Wi-Fi skeniranja.

> [!TIP]
> Mach-O binary može da sadrži jedan ili **više** **konstruktora**, koji će biti **izvršeni** **pre** adrese navedene u **LC_MAIN**.\
> Offseti svih konstruktora čuvaju se u sekciji **\_\_mod_init_func** segmenta **\_\_DATA_CONST**.

## **Mach-O podaci**

U središtu fajla nalazi se oblast sa podacima, koja se sastoji od nekoliko segmenata definisanih u oblasti load-commands. **Svaki segment može da sadrži različite sekcije podataka**, pri čemu svaka sekcija **sadrži kod ili podatke** specifične za određeni tip.

> [!TIP]
> Podaci su u suštini deo koji sadrži sve **informacije** učitane load commands-ima **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Ovo obuhvata:

- **Tabela funkcija:** Sadrži informacije o funkcijama programa.
- **Tabela simbola**: Sadrži informacije o eksternim funkcijama koje binary koristi.
- Može da sadrži i interne funkcije, imena promenljivih i još toga.

Da biste ovo proverili, možete da koristite alatku [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ili iz CLI-ja:

```bash
size -m /bin/ls
```

### Dodati podaci i overlay-i parsirani unazad

Loader može da čuva konfiguraciju u dodatim podacima umesto u imenovanom Mach-O odeljku. Reverse parser se zatim oslanja na oznaku na kraju, čita veličinu sačuvanu neposredno pre nje i koristi tu vrednost da pronađe i dešifruje prethodni blob. Jedan zabeleženi univerzalni loader koristio je ovaj raspored za URL downloader-a šifrovan XOR-om:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Prilikom reverse engineering-a nepoznatog binarnog fajla, pregledajte bajtove oko prepoznatljivih završnih markera i pratite svako izračunavanje veličine unazad pre nego što pretpostavite da stringovi ili konfiguracija moraju pripadati sekciji load command-a. Marker i XOR ključ specifični su za uzorak; ponovo upotrebljiva tehnika je samoopisni završni blok.

## Uobičajene Objective-C sekcije

U segmentu `__TEXT` (r-x):

- `__objc_classname`: Imena klasa (stringovi)
- `__objc_methname`: Imena metoda (stringovi)
- `__objc_methtype`: Tipovi metoda (stringovi)

U segmentu `__DATA` (rw-):

- `__objc_classlist`: Pokazivači na sve Objective-C klase
- `__objc_nlclslist`: Pokazivači na Non-Lazy Objective-C klase
- `__objc_catlist`: Pokazivači na Categories
- `__objc_nlcatlist`: Pokazivači na Non-Lazy Categories
- `__objc_protolist`: Lista protokola
- `__objc_const`: Konstantni podaci
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Pogledajte i: [Reflektivno učitavanje Mach-O fajlova](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O slices nisu tako jednostavni kao što možda mislite](https://objective-see.org/blog/blog_0x80.html)
- [2] [Stranica priručnika za dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Čitanje sopstvenih entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source — Mach-O `fat.h` i `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist — Nova verzija macOS kradljivca MacSync cilja entuzijaste za kriptovalute i programere](https://securelist.com/macsync-new-version/121383/)
- [7] [Umetnost Mac malvera, tom 2 — Parsiranje binarnih fajlova](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Unutar potpisivanja koda: heševi](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Dozvoljavanje i odbijanje aplikacija i binarnih fajlova](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
